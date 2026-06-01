//! DNS protocol runner — ported from Nuclei `pkg/protocols/dns`.
//!
//! Sends DNS queries of any record type and populates a `ResponseData` with
//! all response sections so matchers/extractors can operate on them.
//!
//! # Template usage
//!
//! ```yaml
//! id: dns-mx-detect
//! info:
//!   name: MX Record Detection
//!   severity: info
//! dns:
//!   - name: "{{FQDN}}"
//!     type: MX
//!     matchers:
//!       - type: words
//!         words: ["mail."]
//!         part: dns_answer
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::proto::udp::UdpClientStream;
use tokio::net::UdpSocket;

use crate::finding::{EvidenceSource, PatternFinding};
use crate::generator::apply_payload;
use crate::runner::{evaluate_template_with_response, ResponseData};
use crate::template::{DnsRecordType, PatternTemplate};

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_RESOLVER: &str = "8.8.8.8:53";
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

// ── Public API ────────────────────────────────────────────────────────────────

/// Run a DNS template against a target domain.
///
/// `target` is the domain name to query (e.g. `"example.com"`).
/// `variables` may contain `{{FQDN}}` and other template placeholders.
pub async fn run_dns(
    template: &PatternTemplate,
    target: &str,
    variables: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<Vec<PatternFinding>> {
    let dns_req = match &template.dns_request {
        Some(r) => r,
        None => {
            tracing::warn!(template_id = %template.id, "dns_request missing — skipping");
            return Ok(vec![]);
        }
    };

    // Resolve {{FQDN}} and other variables in the name field
    let mut vars = variables.clone();
    vars.entry("FQDN".into())
        .or_insert_with(|| target.to_string());
    vars.entry("Hostname".into())
        .or_insert_with(|| target.to_string());
    let query_name = apply_payload(&dns_req.name, &vars);

    // Choose resolver
    let resolver_addr: SocketAddr = dns_req
        .resolvers
        .first()
        .map(|r| r.as_str())
        .unwrap_or(DEFAULT_RESOLVER)
        .parse()
        .unwrap_or_else(|_| DEFAULT_RESOLVER.parse().unwrap());

    let record_type = record_type_from_template(dns_req.record_type);
    let tm = Duration::from_millis(timeout_ms.max(DEFAULT_TIMEOUT_MS));

    let resp = query_dns(&query_name, record_type, resolver_addr, dns_req.retries, tm).await?;

    // Use 0.0.0.0 as placeholder IP since DNS doesn't target a specific IP
    let target_ip: IpAddr = "0.0.0.0".parse().unwrap();
    Ok(evaluate_template_with_response(
        template,
        &resp,
        target_ip,
        53,
        EvidenceSource::Static,
    ))
}

// ── DNS query execution ───────────────────────────────────────────────────────

async fn query_dns(
    name: &str,
    record_type: RecordType,
    resolver: SocketAddr,
    retries: u8,
    tm: Duration,
) -> Result<ResponseData> {
    let name = Name::from_str(name).with_context(|| format!("parse DNS name {:?}", name))?;

    let mut last_err = None;
    for attempt in 0..=retries {
        match do_query(name.clone(), record_type, resolver, tm).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::debug!(attempt, err = %e, "DNS query attempt failed");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DNS query failed (0 attempts)")))
}

async fn do_query(
    name: Name,
    record_type: RecordType,
    resolver: SocketAddr,
    tm: Duration,
) -> Result<ResponseData> {
    let stream = UdpClientStream::<UdpSocket>::with_timeout(resolver, tm);
    let (mut client, bg) = AsyncClient::connect(stream)
        .await
        .context("DNS client connect")?;
    tokio::spawn(bg);

    let response = client
        .query(name.clone(), DNSClass::IN, record_type)
        .await
        .context("DNS query")?;

    let rcode = u16::from(response.response_code()) as i32;
    let query_text = format!("{} {}", name, record_type);

    // Format each response section
    let answer = format_records(response.answers());
    let ns = format_records(response.name_servers());
    let extra_section = format_records(response.additionals());
    let raw = format!(
        "RCODE: {}\nQUESTION: {}\nANSWER:\n{}\nNS:\n{}\nADDITIONAL:\n{}",
        rcode, query_text, answer, ns, extra_section
    );

    // Collect per-type record values for DSL context
    let mut extra: HashMap<String, String> = HashMap::new();
    extra.insert("rcode".into(), rcode.to_string());
    extra.insert("question".into(), query_text.clone());
    extra.insert("answer".into(), answer.clone());
    extra.insert("ns".into(), ns.clone());
    extra.insert("extra".into(), extra_section.clone());
    extra.insert("raw".into(), raw.clone());
    extra.insert("type".into(), "dns".into());

    // Per-record-type fields (a, aaaa, mx, txt, cname, etc.)
    for record in response.answers() {
        if let Some(rdata) = record.data() {
            let type_key = record_type_key(rdata);
            let value = rdata_to_string(rdata);
            extra
                .entry(type_key)
                .and_modify(|existing| {
                    existing.push('\n');
                    existing.push_str(&value);
                })
                .or_insert(value);
        }
    }

    Ok(ResponseData {
        status: rcode as u16,
        headers: Default::default(),
        body: answer,
        raw_bytes: None,
        extra,
    })
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn format_records(records: &[hickory_client::proto::rr::Record]) -> String {
    records
        .iter()
        .map(|r| {
            format!(
                "{} {} IN {} {}",
                r.name(),
                r.ttl(),
                r.record_type(),
                r.data().map(rdata_to_string).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn rdata_to_string(rdata: &RData) -> String {
    match rdata {
        RData::A(addr) => addr.to_string(),
        RData::AAAA(addr) => addr.to_string(),
        RData::CNAME(name) => name.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
        RData::TXT(txt) => txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        RData::NS(ns) => ns.to_string(),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname(),
            soa.rname(),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum()
        ),
        RData::PTR(ptr) => ptr.to_string(),
        _ => format!("{rdata:?}"),
    }
}

fn record_type_key(rdata: &RData) -> String {
    match rdata {
        RData::A(_) => "a",
        RData::AAAA(_) => "aaaa",
        RData::CNAME(_) => "cname",
        RData::MX(_) => "mx",
        RData::TXT(_) => "txt",
        RData::NS(_) => "ns",
        RData::SOA(_) => "soa",
        RData::PTR(_) => "ptr",
        _ => "other",
    }
    .to_string()
}

fn record_type_from_template(rt: DnsRecordType) -> RecordType {
    match rt {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::AAAA => RecordType::AAAA,
        DnsRecordType::CNAME => RecordType::CNAME,
        DnsRecordType::MX => RecordType::MX,
        DnsRecordType::TXT => RecordType::TXT,
        DnsRecordType::NS => RecordType::NS,
        DnsRecordType::SOA => RecordType::SOA,
        DnsRecordType::PTR => RecordType::PTR,
        DnsRecordType::DS => RecordType::DS,
        DnsRecordType::ANY => RecordType::ANY,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_mapping() {
        assert_eq!(record_type_from_template(DnsRecordType::A), RecordType::A);
        assert_eq!(record_type_from_template(DnsRecordType::MX), RecordType::MX);
        assert_eq!(
            record_type_from_template(DnsRecordType::TXT),
            RecordType::TXT
        );
    }
}
