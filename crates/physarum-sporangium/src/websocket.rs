//! WebSocket protocol runner — ported from Nuclei `pkg/protocols/websocket`.
//!
//! Establishes a WebSocket (ws:// or wss://) connection and exchanges frames
//! defined in the template's input list. Collects all received frames and
//! exposes them for matching/extraction.
//!
//! # Template usage
//!
//! ```yaml
//! id: ws-echo-detect
//! info:
//!   name: WebSocket Echo Detection
//!   severity: info
//! websocket:
//!   - address: "ws://{{Hostname}}:{{Port}}/ws"
//!     inputs:
//!       - data: "ping"
//!         read: 1024
//!     matchers:
//!       - type: words
//!         words: ["pong"]
//!         part: ws_response
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::{connect_async_with_config, tungstenite::Message};

use crate::finding::{EvidenceSource, PatternFinding};
use crate::generator::apply_payload;
use crate::runner::{evaluate_template_with_response, ResponseData};
use crate::template::{PatternTemplate, WsInput};

// ── Public API ────────────────────────────────────────────────────────────────

/// Run a WebSocket template against a target.
///
/// The `address` field in the template's `websocket` section may contain
/// `{{Hostname}}`, `{{Port}}`, and other template variables.
pub async fn run_websocket(
    template: &PatternTemplate,
    target_ip: IpAddr,
    port: u16,
    variables: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<Vec<PatternFinding>> {
    let ws_req = match &template.websocket_request {
        Some(r) => r,
        None => {
            tracing::warn!(template_id = %template.id, "websocket_request missing — skipping");
            return Ok(vec![]);
        }
    };

    let mut vars = variables.clone();
    vars.entry("Hostname".into())
        .or_insert_with(|| target_ip.to_string());
    vars.entry("Port".into())
        .or_insert_with(|| port.to_string());

    let address = apply_payload(&ws_req.address, &vars);
    let tm = Duration::from_millis(timeout_ms);

    let resp = exchange_websocket(&address, ws_req.inputs.as_slice(), &vars, tm).await?;

    Ok(evaluate_template_with_response(
        template,
        &resp,
        target_ip,
        port,
        EvidenceSource::HttpProbe,
    ))
}

// ── WebSocket exchange ────────────────────────────────────────────────────────

async fn exchange_websocket(
    url: &str,
    inputs: &[WsInput],
    variables: &HashMap<String, String>,
    tm: Duration,
) -> Result<ResponseData> {
    let (mut ws_stream, upgrade_resp) = timeout(tm, connect_async_with_config(url, None, false))
        .await
        .context("WebSocket connect timeout")?
        .with_context(|| format!("WebSocket connect to {url}"))?;

    let status_code = upgrade_resp.status().as_u16();
    let response_headers: HashMap<String, String> = upgrade_resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let mut all_sent = Vec::<String>::new();
    let mut all_received = Vec::<String>::new();

    for input in inputs {
        let data = apply_payload(&input.data, variables);

        if !data.is_empty() {
            ws_stream
                .send(Message::Text(data.clone()))
                .await
                .context("WebSocket send")?;
            all_sent.push(data.clone());
        }

        if input.read > 0 {
            // Read up to `read` frames within the timeout
            let mut bytes_read = 0usize;
            while bytes_read < input.read {
                match timeout(Duration::from_millis(500), ws_stream.next()).await {
                    Ok(Some(Ok(Message::Text(text)))) => {
                        bytes_read += text.len();
                        all_received.push(text);
                    }
                    Ok(Some(Ok(Message::Binary(bin)))) => {
                        bytes_read += bin.len();
                        all_received.push(String::from_utf8_lossy(&bin).into_owned());
                    }
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
                    _ => break,
                }
            }
        }
    }

    let response_text = all_received.join("\n");
    let request_text = all_sent.join("\n");

    let mut extra: HashMap<String, String> = HashMap::new();
    extra.insert("response".into(), response_text.clone());
    extra.insert("request".into(), request_text);
    extra.insert("status_code".into(), status_code.to_string());
    extra.insert("type".into(), "websocket".into());
    for (k, v) in &response_headers {
        extra.insert(format!("header_{}", k.replace('-', "_")), v.clone());
    }

    Ok(ResponseData {
        status: status_code,
        headers: response_headers,
        body: response_text,
        raw_bytes: None,
        extra,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_data_has_ws_type() {
        let mut extra = HashMap::new();
        extra.insert("type".into(), "websocket".into());
        let resp = ResponseData {
            status: 101,
            headers: Default::default(),
            body: "pong".into(),
            raw_bytes: None,
            extra,
        };
        assert_eq!(resp.extra.get("type").unwrap(), "websocket");
    }
}
