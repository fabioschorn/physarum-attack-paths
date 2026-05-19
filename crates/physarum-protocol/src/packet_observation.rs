use crate::AgentId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketProtocol {
    Icmp,
}

/// ICMP message type with named variants for the two probe-relevant types.
///
/// `Other(u8)` carries the raw type code for all other ICMP messages.
/// Gate L.3 only seeds discovery from `EchoRequest`; remaining types are
/// stored as-is for observability without blocking the ingestion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    Other(u8),
}

impl IcmpType {
    pub fn from_u8(raw: u8) -> Self {
        match raw {
            8 => Self::EchoRequest,
            0 => Self::EchoReply,
            v => Self::Other(v),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::EchoRequest => 8,
            Self::EchoReply => 0,
            Self::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

/// Packet-level metadata observation produced by the tc ingress eBPF classifier.
///
/// No payload bytes, pcap data, or headers beyond what is needed for
/// provenance are stored — identical privacy boundary as `FlowObservation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketObservation {
    pub agent_id: AgentId,
    pub observed_at: DateTime<Utc>,
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: PacketProtocol,
    pub icmp_type: IcmpType,
    pub icmp_code: u8,
    pub direction: PacketDirection,
    pub interface_name: String,
    pub packet_size: Option<u16>,
    pub ttl: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketObservationAck {
    pub accepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample() -> PacketObservation {
        PacketObservation {
            agent_id: "agent-b".to_string(),
            observed_at: Utc::now(),
            source_ip: "10.50.20.20".to_string(),
            destination_ip: "10.50.20.10".to_string(),
            protocol: PacketProtocol::Icmp,
            icmp_type: IcmpType::EchoRequest,
            icmp_code: 0,
            direction: PacketDirection::Inbound,
            interface_name: "eth0".to_string(),
            packet_size: Some(64),
            ttl: Some(64),
        }
    }

    #[test]
    fn packet_observation_round_trips_via_json() {
        let obs = sample();
        let json = serde_json::to_string(&obs).unwrap();
        let back: PacketObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, obs.agent_id);
        assert_eq!(back.source_ip, obs.source_ip);
        assert_eq!(back.destination_ip, obs.destination_ip);
        assert_eq!(back.icmp_type, obs.icmp_type);
        assert_eq!(back.icmp_code, obs.icmp_code);
        assert_eq!(back.direction, obs.direction);
        assert_eq!(back.interface_name, obs.interface_name);
        assert_eq!(back.packet_size, Some(64));
        assert_eq!(back.ttl, Some(64));
    }

    #[test]
    fn optional_fields_can_be_none() {
        let mut obs = sample();
        obs.packet_size = None;
        obs.ttl = None;
        let json = serde_json::to_string(&obs).unwrap();
        let back: PacketObservation = serde_json::from_str(&json).unwrap();
        assert!(back.packet_size.is_none());
        assert!(back.ttl.is_none());
    }

    #[test]
    fn icmp_type_serializes_as_snake_case() {
        let v = serde_json::to_value(IcmpType::EchoRequest).unwrap();
        assert_eq!(v, "echo_request");

        let v = serde_json::to_value(IcmpType::EchoReply).unwrap();
        assert_eq!(v, "echo_reply");
    }

    #[test]
    fn icmp_other_type_serializes_correctly() {
        let v = serde_json::to_value(IcmpType::Other(3)).unwrap();
        // serde represents tuple variant as {"other": 3}
        assert_eq!(v["other"], 3);

        let back: IcmpType = serde_json::from_value(v).unwrap();
        assert_eq!(back, IcmpType::Other(3));
    }

    #[test]
    fn icmp_type_from_u8_maps_known_types() {
        assert_eq!(IcmpType::from_u8(8), IcmpType::EchoRequest);
        assert_eq!(IcmpType::from_u8(0), IcmpType::EchoReply);
        assert_eq!(IcmpType::from_u8(3), IcmpType::Other(3));
        assert_eq!(IcmpType::from_u8(11), IcmpType::Other(11));
    }

    #[test]
    fn icmp_type_as_u8_round_trips() {
        assert_eq!(IcmpType::EchoRequest.as_u8(), 8);
        assert_eq!(IcmpType::EchoReply.as_u8(), 0);
        assert_eq!(IcmpType::Other(11).as_u8(), 11);
    }

    #[test]
    fn direction_serializes_as_snake_case() {
        let v = serde_json::to_value(PacketDirection::Inbound).unwrap();
        assert_eq!(v, "inbound");

        let v = serde_json::to_value(PacketDirection::Outbound).unwrap();
        assert_eq!(v, "outbound");
    }

    #[test]
    fn protocol_serializes_as_snake_case() {
        let v = serde_json::to_value(PacketProtocol::Icmp).unwrap();
        assert_eq!(v, "icmp");
    }

    #[test]
    fn ack_round_trips() {
        let ack = PacketObservationAck { accepted: true };
        let json = serde_json::to_string(&ack).unwrap();
        let back: PacketObservationAck = serde_json::from_str(&json).unwrap();
        assert!(back.accepted);
    }

    #[test]
    fn all_fields_present_in_json() {
        let obs = sample();
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        for field in &[
            "agent_id",
            "observed_at",
            "source_ip",
            "destination_ip",
            "protocol",
            "icmp_type",
            "icmp_code",
            "direction",
            "interface_name",
            "packet_size",
            "ttl",
        ] {
            assert!(v.get(field).is_some(), "missing field: {field}");
        }
    }
}
