//! TCP / Network protocol runner — ported from Nuclei `pkg/protocols/network`.
//!
//! Sends a sequence of binary or text payloads over a raw TCP (or TLS) connection
//! and matches the response using the template's matchers and extractors.
//!
//! # Template usage
//!
//! ```yaml
//! id: ssh-version-detect
//! info:
//!   name: SSH Version Detection
//!   severity: info
//! tcp:
//!   - inputs:
//!       - read: 1024
//!     matchers:
//!       - type: regex
//!         patterns: ["^SSH-2\\.0-"]
//!         part: data
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::finding::{EvidenceSource, PatternFinding};
use crate::generator::apply_payload;
use crate::runner::{evaluate_template_with_response, ResponseData};
use crate::template::{InputEncoding, PatternTemplate, TcpInput};

// ── Public API ────────────────────────────────────────────────────────────────

/// Default read buffer size — matches Nuclei default.
const DEFAULT_READ_SIZE: usize = 1024;

/// Run a TCP/Network template against a target.
///
/// For each configured input in the TCP request definition:
/// 1. Write the payload (text or hex) to the socket.
/// 2. Optionally read a specified number of bytes.
///
/// After all inputs are processed, read any remaining data (up to `read_size`
/// or `DEFAULT_READ_SIZE` bytes), then evaluate matchers/extractors.
pub async fn run_tcp(
    template: &PatternTemplate,
    target_ip: IpAddr,
    port: u16,
    variables: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<Vec<PatternFinding>> {
    let tcp_req = match &template.tcp_request {
        Some(r) => r,
        None => {
            tracing::warn!(template_id = %template.id, "tcp_request missing — skipping");
            return Ok(vec![]);
        }
    };

    let addr = format!("{target_ip}:{port}");
    let conn_timeout = Duration::from_millis(timeout_ms);

    // Connect with timeout
    let stream = timeout(conn_timeout, TcpStream::connect(&addr))
        .await
        .context("TCP connect timeout")?
        .with_context(|| format!("TCP connect to {addr}"))?;

    let resp = run_tcp_exchange(stream, tcp_req.inputs.as_slice(), variables, timeout_ms).await?;

    Ok(evaluate_template_with_response(
        template,
        &resp,
        target_ip,
        port,
        EvidenceSource::TcpProbe,
    ))
}

// ── Internal exchange ─────────────────────────────────────────────────────────

async fn run_tcp_exchange(
    mut stream: TcpStream,
    inputs: &[TcpInput],
    variables: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<ResponseData> {
    let io_timeout = Duration::from_millis(timeout_ms);
    let mut all_sent = Vec::<u8>::new();
    let mut all_recv = Vec::<u8>::new();

    for input in inputs {
        // Resolve variables in data
        let data_str = apply_payload(&input.data, variables);

        let payload_bytes: Vec<u8> = match input.encoding {
            InputEncoding::Text => data_str.into_bytes(),
            InputEncoding::Hex => hex::decode(&data_str)
                .with_context(|| format!("hex decode input: {:?}", input.data))?,
        };

        if !payload_bytes.is_empty() {
            timeout(io_timeout, stream.write_all(&payload_bytes))
                .await
                .context("TCP write timeout")?
                .context("TCP write")?;
            all_sent.extend_from_slice(&payload_bytes);
        }

        // Read response bytes for this input step
        let read_size = if input.read > 0 {
            input.read
        } else if payload_bytes.is_empty() {
            DEFAULT_READ_SIZE
        } else {
            0
        };

        if read_size > 0 {
            let mut buf = vec![0u8; read_size];
            let n = timeout(io_timeout, stream.read(&mut buf))
                .await
                .unwrap_or(Ok(0))
                .unwrap_or(0);
            all_recv.extend_from_slice(&buf[..n]);
        }
    }

    // Final read of any remaining banner/data
    let final_read = {
        let mut buf = vec![0u8; DEFAULT_READ_SIZE];
        timeout(io_timeout, stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        buf
    };
    all_recv.extend_from_slice(
        &final_read[..final_read
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0)],
    );

    let body = String::from_utf8_lossy(&all_recv).into_owned();
    let request_hex = hex::encode(&all_sent);

    let mut extra = HashMap::new();
    extra.insert("request".into(), request_hex);
    extra.insert("data".into(), body.clone());
    extra.insert(
        "raw".into(),
        format!("SENT:{}\nRECV:{}", String::from_utf8_lossy(&all_sent), body),
    );
    extra.insert("type".into(), "tcp".into());

    Ok(ResponseData {
        status: 0,
        headers: Default::default(),
        body,
        raw_bytes: Some(all_recv),
        extra,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_data_fields_populated() {
        let resp = ResponseData {
            status: 0,
            headers: Default::default(),
            body: "SSH-2.0-OpenSSH_8.4".into(),
            raw_bytes: Some(b"SSH-2.0-OpenSSH_8.4".to_vec()),
            extra: [
                ("type".to_string(), "tcp".to_string()),
                ("data".to_string(), "SSH-2.0-OpenSSH_8.4".to_string()),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(resp.extra.get("type").unwrap(), "tcp");
        assert!(resp.raw_bytes.is_some());
    }
}
