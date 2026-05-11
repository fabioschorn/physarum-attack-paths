use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AgentId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Outbound,
    Inbound,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEvent {
    ConnectEstablished,
    AcceptEstablished,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowProtocol {
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowObservation {
    pub agent_id: AgentId,
    pub observed_at: DateTime<Utc>,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: FlowProtocol,
    pub direction: FlowDirection,
    pub event: FlowEvent,
    pub pid: u32,
    pub comm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowObservationAck {
    pub accepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FlowObservation {
        FlowObservation {
            agent_id: "agent-b".to_string(),
            observed_at: DateTime::from_timestamp(0, 0).unwrap(),
            source_ip: "10.50.20.10".to_string(),
            source_port: 53124,
            destination_ip: "10.50.30.10".to_string(),
            destination_port: 9002,
            protocol: FlowProtocol::Tcp,
            direction: FlowDirection::Outbound,
            event: FlowEvent::ConnectEstablished,
            pid: 1234,
            comm: "physarum-agent".to_string(),
        }
    }

    #[test]
    fn round_trips_via_json() {
        let obs = sample();
        let json = serde_json::to_string(&obs).unwrap();
        let back: FlowObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, obs.agent_id);
        assert_eq!(back.source_port, obs.source_port);
        assert_eq!(back.destination_port, obs.destination_port);
        assert_eq!(back.pid, obs.pid);
        assert_eq!(back.comm, obs.comm);
    }

    #[test]
    fn direction_serializes_snake_case() {
        let v = serde_json::to_value(FlowDirection::Outbound).unwrap();
        assert_eq!(v, "outbound");
        let v = serde_json::to_value(FlowDirection::Inbound).unwrap();
        assert_eq!(v, "inbound");
    }

    #[test]
    fn event_serializes_snake_case() {
        let v = serde_json::to_value(FlowEvent::ConnectEstablished).unwrap();
        assert_eq!(v, "connect_established");
        let v = serde_json::to_value(FlowEvent::AcceptEstablished).unwrap();
        assert_eq!(v, "accept_established");
        let v = serde_json::to_value(FlowEvent::Close).unwrap();
        assert_eq!(v, "close");
    }

    #[test]
    fn protocol_serializes_snake_case() {
        let v = serde_json::to_value(FlowProtocol::Tcp).unwrap();
        assert_eq!(v, "tcp");
    }

    #[test]
    fn invalid_direction_rejected() {
        let err = serde_json::from_str::<FlowDirection>("\"lateral\"");
        assert!(err.is_err());
    }

    #[test]
    fn invalid_event_rejected() {
        let err = serde_json::from_str::<FlowEvent>("\"connect_failed\"");
        assert!(err.is_err());
    }

    #[test]
    fn all_fields_present_in_json() {
        let obs = sample();
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        for field in &[
            "agent_id",
            "observed_at",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "direction",
            "event",
            "pid",
            "comm",
        ] {
            assert!(v.get(field).is_some(), "missing field: {field}");
        }
    }
}
