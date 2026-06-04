use std::net::IpAddr;

use keli_net_core::{
    parse_tun_packet_flow, RouteDestination, RouteTarget, TunIpVersion, TunPacketError,
    TunTransportProtocol,
};

#[test]
fn parses_ipv4_udp_packet_to_route_destination_and_dns_candidate() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &[0xd4, 0x31, 0x00, 0x35, 0, 8, 0, 0],
    );

    let flow = parse_tun_packet_flow(&packet).expect("parse IPv4 UDP TUN packet");

    assert_eq!(flow.ip_version, TunIpVersion::Ipv4);
    assert_eq!(flow.protocol, TunTransportProtocol::Udp);
    assert_eq!(
        flow.source_ip,
        "10.7.0.2".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(
        flow.destination_ip,
        "8.8.8.8".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(flow.source_port, Some(54321));
    assert_eq!(flow.destination_port, Some(53));
    assert_eq!(
        flow.route_destination(),
        RouteDestination::new(RouteTarget::Ip("8.8.8.8".parse().expect("valid IP")), 53)
    );
    assert!(flow.is_dns_hijack_candidate());
}

#[test]
fn parses_ipv6_tcp_packet_to_socket_addresses() {
    let packet = ipv6_packet(
        6,
        "fd00::2",
        "2606:4700:4700::1111",
        &[
            0xc0, 0x00, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0x00, 0, 0, 0, 0,
        ],
    );

    let flow = parse_tun_packet_flow(&packet).expect("parse IPv6 TCP TUN packet");

    assert_eq!(flow.ip_version, TunIpVersion::Ipv6);
    assert_eq!(flow.protocol, TunTransportProtocol::Tcp);
    assert_eq!(flow.source_port, Some(49152));
    assert_eq!(flow.destination_port, Some(443));
    assert_eq!(
        flow.destination_socket_addr()
            .expect("destination socket address")
            .to_string(),
        "[2606:4700:4700::1111]:443"
    );
    assert!(!flow.is_dns_hijack_candidate());
}

#[test]
fn parses_non_tcp_udp_packet_without_ports() {
    let packet = ipv4_packet(1, "10.7.0.2", "10.7.0.1", &[8, 0, 0, 0]);

    let flow = parse_tun_packet_flow(&packet).expect("parse IPv4 ICMP TUN packet");

    assert_eq!(flow.protocol, TunTransportProtocol::Icmp);
    assert_eq!(flow.source_port, None);
    assert_eq!(flow.destination_port, None);
    assert_eq!(
        flow.route_destination(),
        RouteDestination::new(RouteTarget::Ip("10.7.0.1".parse().expect("valid IP")), 0)
    );
}

#[test]
fn rejects_truncated_transport_header() {
    let packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &[0xd4, 0x31, 0x00]);

    let error = parse_tun_packet_flow(&packet).expect_err("truncated UDP header should fail");

    assert_eq!(
        error,
        TunPacketError::TransportHeaderTooShort {
            protocol: TunTransportProtocol::Udp,
            required_len: 4,
            available_len: 3
        }
    );
}

#[test]
fn rejects_truncated_ipv6_packet() {
    let mut packet = ipv6_packet(17, "fd00::2", "fd00::1", &[0, 1, 0, 2, 0, 8, 0, 0]);
    packet.truncate(42);

    let error = parse_tun_packet_flow(&packet).expect_err("truncated IPv6 packet should fail");

    assert_eq!(
        error,
        TunPacketError::Ipv6PacketTruncated {
            total_length: 48,
            packet_len: 42
        }
    );
}

fn ipv4_packet(protocol: u8, source: &str, destination: &str, payload: &[u8]) -> Vec<u8> {
    let source: [u8; 4] = source
        .parse::<std::net::Ipv4Addr>()
        .expect("valid source IPv4")
        .octets();
    let destination: [u8; 4] = destination
        .parse::<std::net::Ipv4Addr>()
        .expect("valid destination IPv4")
        .octets();
    let total_length = 20 + payload.len();
    let mut packet = vec![0; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..].copy_from_slice(payload);
    packet
}

fn ipv6_packet(protocol: u8, source: &str, destination: &str, payload: &[u8]) -> Vec<u8> {
    let source = source
        .parse::<std::net::Ipv6Addr>()
        .expect("valid source IPv6")
        .octets();
    let destination = destination
        .parse::<std::net::Ipv6Addr>()
        .expect("valid destination IPv6")
        .octets();
    let total_length = 40 + payload.len();
    let mut packet = vec![0; total_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = protocol;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
    packet[40..].copy_from_slice(payload);
    packet
}
