use chrono::Utc;
use physarum_protocol::{IcmpType, PacketDirection, PacketObservation, PacketProtocol};
use std::net::Ipv4Addr;

/// Raw ICMP event captured by the eBPF tc ingress classifier and transferred via ring buffer.
///
/// Must match the layout of `IcmpEvent` in `physarum-packet-observer-ebpf/src/main.rs`.
/// IcmpEvent: 4 + 4 + 1 + 1 + 2 = 12 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IcmpEvent {
    /// Source IPv4 address bytes in network byte order.
    pub src_addr: [u8; 4],
    /// Destination IPv4 address bytes in network byte order.
    pub dst_addr: [u8; 4],
    /// Raw ICMP type byte (8 = echo_request, 0 = echo_reply, etc.).
    pub icmp_type: u8,
    /// Raw ICMP code byte.
    pub icmp_code: u8,
    pub _pad: [u8; 2],
}

/// Convert a raw kernel `IcmpEvent` to a `PacketObservation` ready for the coordinator.
///
/// `interface` comes from userspace config — the tc program is attached to a specific
/// interface and we record that name for provenance.
pub fn map(event: &IcmpEvent, agent_id: &str, interface: &str) -> PacketObservation {
    let icmp_type = IcmpType::from_u8(event.icmp_type);
    PacketObservation {
        agent_id: agent_id.to_string(),
        observed_at: Utc::now(),
        source_ip: Ipv4Addr::from(event.src_addr).to_string(),
        destination_ip: Ipv4Addr::from(event.dst_addr).to_string(),
        protocol: PacketProtocol::Icmp,
        icmp_type,
        icmp_code: event.icmp_code,
        // tc ingress sees inbound packets — all events from this classifier are inbound.
        direction: PacketDirection::Inbound,
        interface_name: interface.to_string(),
        packet_size: None,
        ttl: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_protocol::{IcmpType, PacketDirection, PacketProtocol};

    fn make_event(src: [u8; 4], dst: [u8; 4], icmp_type: u8, icmp_code: u8) -> IcmpEvent {
        IcmpEvent {
            src_addr: src,
            dst_addr: dst,
            icmp_type,
            icmp_code,
            _pad: [0; 2],
        }
    }

    #[test]
    fn echo_request_maps_to_inbound_icmp_echo_request() {
        let event = make_event([10, 50, 20, 20], [10, 50, 20, 10], 8, 0);
        let obs = map(&event, "agent-b", "eth0");
        assert_eq!(obs.icmp_type, IcmpType::EchoRequest);
        assert_eq!(obs.direction, PacketDirection::Inbound);
        assert_eq!(obs.protocol, PacketProtocol::Icmp);
    }

    #[test]
    fn echo_reply_maps_correctly() {
        let event = make_event([10, 50, 20, 10], [10, 50, 20, 20], 0, 0);
        let obs = map(&event, "agent-b", "eth0");
        assert_eq!(obs.icmp_type, IcmpType::EchoReply);
        assert_eq!(obs.direction, PacketDirection::Inbound);
    }

    #[test]
    fn other_icmp_type_preserved() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 11, 0);
        let obs = map(&event, "a", "eth0");
        assert_eq!(obs.icmp_type, IcmpType::Other(11));
    }

    #[test]
    fn ip_bytes_convert_to_dotted_notation() {
        let event = make_event([10, 50, 20, 20], [10, 50, 20, 10], 8, 0);
        let obs = map(&event, "agent-b", "eth0");
        assert_eq!(obs.source_ip, "10.50.20.20");
        assert_eq!(obs.destination_ip, "10.50.20.10");
    }

    #[test]
    fn agent_id_and_interface_come_from_parameters() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 8, 0);
        let obs = map(&event, "agent-x", "ens5");
        assert_eq!(obs.agent_id, "agent-x");
        assert_eq!(obs.interface_name, "ens5");
    }

    #[test]
    fn icmp_code_is_preserved() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 8, 7);
        let obs = map(&event, "a", "eth0");
        assert_eq!(obs.icmp_code, 7);
    }

    #[test]
    fn optional_fields_are_none() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 8, 0);
        let obs = map(&event, "a", "eth0");
        assert!(obs.packet_size.is_none());
        assert!(obs.ttl.is_none());
    }

    #[test]
    fn icmp_event_layout_size_matches_expected_abi() {
        // IcmpEvent: 4 + 4 + 1 + 1 + 2 = 12 bytes.
        // If this assertion fails, the eBPF ↔ userspace ABI has drifted — update both together.
        assert_eq!(core::mem::size_of::<IcmpEvent>(), 12);
    }

    #[test]
    fn mapped_observation_serializes_to_expected_json_shape() {
        let event = make_event([10, 50, 20, 20], [10, 50, 20, 10], 8, 0);
        let obs = map(&event, "agent-b", "eth0");
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        assert_eq!(v["agent_id"], "agent-b");
        assert_eq!(v["source_ip"], "10.50.20.20");
        assert_eq!(v["destination_ip"], "10.50.20.10");
        assert_eq!(v["protocol"], "icmp");
        assert_eq!(v["icmp_type"], "echo_request");
        assert_eq!(v["icmp_code"], 0);
        assert_eq!(v["direction"], "inbound");
        assert_eq!(v["interface_name"], "eth0");
    }
}
