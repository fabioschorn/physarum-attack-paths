use chrono::Utc;
use physarum_protocol::{FlowDirection, FlowEvent, FlowObservation, FlowProtocol};
use std::net::Ipv4Addr;

/// Raw TCP event captured by the eBPF tracepoint and transferred via ring buffer.
///
/// Must match the layout of `TcpEvent` in `physarum-ebpf-observer-ebpf/src/main.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TcpEvent {
    /// Source IPv4 address bytes in network byte order (as received from the kernel).
    pub src_addr: [u8; 4],
    /// Destination IPv4 address bytes in network byte order.
    pub dst_addr: [u8; 4],
    /// Source port in host byte order (already converted by the kernel tracepoint).
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// PID of the process that owns the socket at state-change time.
    pub pid: u32,
    /// Process name (comm): up to 15 printable chars plus a null terminator.
    pub comm: [u8; 16],
    /// 0 = connect_established, 1 = accept_established, 2 = close.
    pub event_type: u8,
    pub _pad: [u8; 3],
}

/// Convert a raw kernel `TcpEvent` to a `FlowObservation` ready for the coordinator.
pub fn map(event: &TcpEvent, agent_id: &str) -> FlowObservation {
    FlowObservation {
        agent_id: agent_id.to_string(),
        observed_at: Utc::now(),
        source_ip: Ipv4Addr::from(event.src_addr).to_string(),
        source_port: event.src_port,
        destination_ip: Ipv4Addr::from(event.dst_addr).to_string(),
        destination_port: event.dst_port,
        protocol: FlowProtocol::Tcp,
        direction: match event.event_type {
            0 => FlowDirection::Outbound,
            1 => FlowDirection::Inbound,
            _ => FlowDirection::Unknown,
        },
        event: match event.event_type {
            0 => FlowEvent::ConnectEstablished,
            1 => FlowEvent::AcceptEstablished,
            _ => FlowEvent::Close,
        },
        pid: event.pid,
        comm: comm_to_string(&event.comm),
    }
}

/// Decode a null-terminated comm byte array into a UTF-8 string.
pub fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_protocol::{FlowDirection, FlowEvent, FlowProtocol};

    fn make_event(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        pid: u32,
        comm: &str,
        event_type: u8,
    ) -> TcpEvent {
        let mut comm_bytes = [0u8; 16];
        let src_bytes = comm.as_bytes();
        let n = src_bytes.len().min(15);
        comm_bytes[..n].copy_from_slice(&src_bytes[..n]);
        TcpEvent {
            src_addr: src,
            dst_addr: dst,
            src_port: sport,
            dst_port: dport,
            pid,
            comm: comm_bytes,
            event_type,
            _pad: [0; 3],
        }
    }

    #[test]
    fn connect_established_maps_to_outbound() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 55000, 9002, 42, "agent", 0);
        let obs = map(&event, "agent-b");
        assert_eq!(obs.event, FlowEvent::ConnectEstablished);
        assert_eq!(obs.direction, FlowDirection::Outbound);
        assert_eq!(obs.protocol, FlowProtocol::Tcp);
    }

    #[test]
    fn accept_established_maps_to_inbound() {
        let event = make_event([10, 0, 0, 2], [10, 0, 0, 1], 9002, 55000, 99, "agent", 1);
        let obs = map(&event, "agent-c");
        assert_eq!(obs.event, FlowEvent::AcceptEstablished);
        assert_eq!(obs.direction, FlowDirection::Inbound);
    }

    #[test]
    fn close_maps_to_unknown_direction_and_close_event() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 55000, 9002, 42, "agent", 2);
        let obs = map(&event, "agent-b");
        assert_eq!(obs.event, FlowEvent::Close);
        assert_eq!(obs.direction, FlowDirection::Unknown);
    }

    #[test]
    fn ip_bytes_convert_to_dotted_notation() {
        let event = make_event(
            [192, 168, 1, 10],
            [10, 50, 30, 20],
            44000,
            8080,
            1,
            "proc",
            0,
        );
        let obs = map(&event, "a");
        assert_eq!(obs.source_ip, "192.168.1.10");
        assert_eq!(obs.destination_ip, "10.50.30.20");
    }

    #[test]
    fn ports_are_preserved_without_byte_swap() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 53124, 9002, 1, "x", 0);
        let obs = map(&event, "a");
        assert_eq!(obs.source_port, 53124);
        assert_eq!(obs.destination_port, 9002);
    }

    #[test]
    fn pid_and_comm_are_preserved() {
        let event = make_event(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            4242,
            "physarum-agent",
            0,
        );
        let obs = map(&event, "a");
        assert_eq!(obs.pid, 4242);
        assert_eq!(obs.comm, "physarum-agent");
    }

    #[test]
    fn comm_null_terminator_is_stripped() {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"curl");
        assert_eq!(comm_to_string(&comm), "curl");
    }

    #[test]
    fn agent_id_comes_from_parameter_not_event() {
        let event = make_event([10, 0, 0, 1], [10, 0, 0, 2], 100, 200, 1, "x", 0);
        let obs = map(&event, "agent-x-007");
        assert_eq!(obs.agent_id, "agent-x-007");
    }

    #[test]
    fn mapped_observation_serializes_to_expected_json_shape() {
        let event = make_event(
            [10, 50, 20, 10],
            [10, 50, 30, 10],
            53124,
            9002,
            1234,
            "physarum-agent",
            0,
        );
        let obs = map(&event, "agent-b");
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        assert_eq!(v["agent_id"], "agent-b");
        assert_eq!(v["source_ip"], "10.50.20.10");
        assert_eq!(v["destination_ip"], "10.50.30.10");
        assert_eq!(v["source_port"], 53124);
        assert_eq!(v["destination_port"], 9002);
        assert_eq!(v["direction"], "outbound");
        assert_eq!(v["event"], "connect_established");
        assert_eq!(v["protocol"], "tcp");
        assert_eq!(v["pid"], 1234);
        assert_eq!(v["comm"], "physarum-agent");
    }
}
