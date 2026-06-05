use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use keli_net_core::{
    build_dns_error_response, build_dns_response, build_tun_dns_hijack_response,
    build_tun_dns_response_packet, build_tun_tcp_ack_response_packet,
    build_tun_tcp_fin_ack_response_packet, build_tun_tcp_payload_response_packet,
    build_tun_tcp_reset_response_packet, build_tun_tcp_response_packet,
    build_tun_tcp_syn_ack_response_packet, decide_tun_packet_route, parse_tun_packet_flow,
    parse_tun_tcp_segment, parse_tun_udp_payload, plan_tun_dns_hijack, plan_tun_packet_relay,
    process_tun_device_packet_with_tcp_session_relay, process_tun_packet,
    process_tun_tcp_session_segment, prune_idle_tun_tcp_sessions, relay_tun_direct_udp_packet,
    relay_tun_udp_packet, run_tun_packet_loop, run_tun_packet_loop_summary,
    run_tun_packet_loop_with_relays_summary, run_tun_packet_loop_with_tcp_session_relay_summary,
    run_tun_packet_loop_with_tcp_session_relay_summary_with_idle_timeout,
    run_tun_packet_loop_with_udp_relay_summary, DnsCache, DnsEngine, DnsError,
    DnsLocalResolutionPolicy, DnsQuestionType, DnsResolver, OutboundRegistry, OutboundTarget,
    RegistryTunTcpSessionRelay, RegistryTunUdpRelay, RouteAction, RouteDestination, RouteEngine,
    RouteIpCidr, RouteMatcher, RouteRule, RouteTarget, TunIpVersion, TunPacketDevice,
    TunPacketError, TunPacketLoopEvent, TunPacketLoopSummary, TunPacketProcessAction,
    TunPacketRelayAction, TunPacketRelayPlan, TunTcpFlags, TunTcpServerRead, TunTcpSessionKey,
    TunTcpSessionPhase, TunTcpSessionRecord, TunTcpSessionRelay, TunTcpSessionStep,
    TunTcpSessionTable, TunTransportProtocol, TunUdpRelay, TunUdpRelayError, UdpRelayResponse,
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
fn parses_ipv4_udp_payload_using_udp_length() {
    let mut datagram = udp_datagram(54321, 53, b"keli");
    datagram.extend_from_slice(b"padding");
    let packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &datagram);

    let udp = parse_tun_udp_payload(&packet).expect("parse TUN UDP payload");

    assert_eq!(udp.flow.source_port, Some(54321));
    assert_eq!(udp.flow.destination_port, Some(53));
    assert_eq!(udp.payload, b"keli");
}

#[test]
fn parses_ipv4_tcp_segment_flags_sequence_window_and_payload() {
    let packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(
            49152,
            443,
            0x0102_0304,
            0xa0b0_c0d0,
            0x0018,
            0x4000,
            &[1, 1, 0, 0],
            b"GET /",
        ),
    );

    let segment = parse_tun_tcp_segment(&packet).expect("parse TUN TCP segment");

    assert_eq!(segment.flow.ip_version, TunIpVersion::Ipv4);
    assert_eq!(segment.flow.source_port, Some(49152));
    assert_eq!(segment.flow.destination_port, Some(443));
    assert_eq!(segment.sequence_number, 0x0102_0304);
    assert_eq!(segment.acknowledgment_number, 0xa0b0_c0d0);
    assert_eq!(segment.header_len, 24);
    assert_eq!(segment.flags.bits(), 0x0018);
    assert!(segment.flags.ack());
    assert!(segment.flags.psh());
    assert!(!segment.flags.syn());
    assert!(!segment.flags.fin());
    assert_eq!(segment.window_size, 0x4000);
    assert_eq!(segment.payload, b"GET /");
}

#[test]
fn parses_ipv6_tcp_syn_segment_after_extension_header() {
    let mut payload = vec![6, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&tcp_segment(49152, 443, 1, 0, 0x0002, 0x2000, &[], b""));
    let packet = ipv6_packet(60, "fd00::2", "2606:4700:4700::1111", &payload);

    let segment = parse_tun_tcp_segment(&packet).expect("parse extended IPv6 TCP segment");

    assert_eq!(segment.flow.ip_version, TunIpVersion::Ipv6);
    assert_eq!(segment.flow.protocol, TunTransportProtocol::Tcp);
    assert_eq!(segment.header_len, 20);
    assert_eq!(segment.sequence_number, 1);
    assert!(segment.flags.syn());
    assert!(!segment.flags.ack());
    assert!(segment.payload.is_empty());
}

#[test]
fn rejects_non_tcp_packet_for_tcp_segment_parser() {
    let packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, b"keli"));

    let error = parse_tun_tcp_segment(&packet).expect_err("UDP packet is not a TCP segment");

    assert_eq!(
        error,
        TunPacketError::ExpectedTcpSegment {
            protocol: TunTransportProtocol::Udp
        }
    );
}

#[test]
fn rejects_truncated_tcp_segment_header() {
    let packet = ipv4_packet(6, "10.7.0.2", "93.184.216.34", &[0xc0, 0x00, 0x01, 0xbb]);

    let error = parse_tun_tcp_segment(&packet).expect_err("truncated TCP segment should fail");

    assert_eq!(
        error,
        TunPacketError::TransportHeaderTooShort {
            protocol: TunTransportProtocol::Tcp,
            required_len: 20,
            available_len: 4
        }
    );
}

#[test]
fn rejects_tcp_data_offset_smaller_than_minimum_header() {
    let mut segment = tcp_segment(49152, 443, 1, 0, 0x0002, 0x2000, &[], b"");
    segment[12] = 0x40;
    let packet = ipv4_packet(6, "10.7.0.2", "93.184.216.34", &segment);

    let error = parse_tun_tcp_segment(&packet).expect_err("invalid TCP data offset should fail");

    assert_eq!(
        error,
        TunPacketError::TcpDataOffsetTooSmall { data_offset: 16 }
    );
}

#[test]
fn rejects_tcp_data_offset_larger_than_transport_payload() {
    let mut segment = tcp_segment(49152, 443, 1, 0, 0x0002, 0x2000, &[1, 1, 0, 0], b"");
    segment.truncate(20);
    let packet = ipv4_packet(6, "10.7.0.2", "93.184.216.34", &segment);

    let error = parse_tun_tcp_segment(&packet).expect_err("truncated TCP options should fail");

    assert_eq!(
        error,
        TunPacketError::TcpSegmentTruncated {
            header_len: 24,
            available_len: 20
        }
    );
}

#[test]
fn builds_ipv4_tun_tcp_response_packet_with_swapped_flow_and_checksum() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet = build_tun_tcp_response_packet(
        &request_segment.flow,
        1000,
        request_segment.sequence_number + 1,
        TunTcpFlags::from_bits(0x0012),
        0x2000,
        b"",
    )
    .expect("build TCP response packet");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse response TCP segment");

    assert_eq!(
        response.flow.source_ip,
        "93.184.216.34".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(
        response.flow.destination_ip,
        "10.7.0.2".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1000);
    assert_eq!(response.acknowledgment_number, 11);
    assert_eq!(response.header_len, 20);
    assert_eq!(response.flags.bits(), 0x0012);
    assert!(response.flags.syn());
    assert!(response.flags.ack());
    assert!(response.payload.is_empty());
    assert_ne!(&response_packet[10..12], &[0, 0]);
    assert_ne!(&response_packet[36..38], &[0, 0]);
}

#[test]
fn builds_ipv6_tun_tcp_response_packet_with_payload_and_checksum() {
    let request = ipv6_packet(
        6,
        "fd00::2",
        "2606:4700:4700::1111",
        &tcp_segment(54000, 443, 50, 200, 0x0018, 0x4000, &[], b"ping"),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet = build_tun_tcp_response_packet(
        &request_segment.flow,
        500,
        request_segment.sequence_number + request_segment.payload.len() as u32,
        TunTcpFlags::from_bits(0x0018),
        0x3000,
        b"ok",
    )
    .expect("build IPv6 TCP response packet");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse IPv6 response segment");

    assert_eq!(
        response.flow.source_ip,
        "2606:4700:4700::1111".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(
        response.flow.destination_ip,
        "fd00::2".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(54000));
    assert_eq!(response.sequence_number, 500);
    assert_eq!(response.acknowledgment_number, 54);
    assert_eq!(response.flags.bits(), 0x0018);
    assert!(response.flags.ack());
    assert!(response.flags.psh());
    assert_eq!(response.window_size, 0x3000);
    assert_eq!(response.payload, b"ok");
    assert_ne!(&response_packet[56..58], &[0, 0]);
}

#[test]
fn rejects_non_tcp_flow_for_tcp_response_packet() {
    let packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, b"keli"));
    let flow = parse_tun_packet_flow(&packet).expect("parse UDP flow");

    let error =
        build_tun_tcp_response_packet(&flow, 1, 1, TunTcpFlags::from_bits(0x0010), 0x2000, b"")
            .expect_err("UDP flow cannot build TCP response");

    assert_eq!(
        error,
        TunPacketError::ExpectedTcpSegment {
            protocol: TunTransportProtocol::Udp
        }
    );
}

#[test]
fn rejects_oversized_ipv4_tun_tcp_response_payload() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");
    let max_payload_len = u16::MAX as usize - 20 - 20;
    let payload = vec![0; max_payload_len + 1];

    let error = build_tun_tcp_response_packet(
        &segment.flow,
        1,
        11,
        TunTcpFlags::from_bits(0x0012),
        0x2000,
        &payload,
    )
    .expect_err("oversized TCP response payload should fail");

    assert_eq!(
        error,
        TunPacketError::TcpResponsePayloadTooLarge {
            ip_version: TunIpVersion::Ipv4,
            payload_len: payload.len(),
            max_payload_len
        }
    );
}

#[test]
fn builds_tun_tcp_reset_response_packet_with_ack_for_syn_payload_and_fin() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 100, 0, 0x0003, 0x4000, &[], b"x"),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet =
        build_tun_tcp_reset_response_packet(&request_segment).expect("build TCP RST response");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse TCP RST response");

    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 0);
    assert_eq!(response.acknowledgment_number, 103);
    assert_eq!(response.flags.bits(), 0x0014);
    assert!(response.flags.rst());
    assert!(response.flags.ack());
    assert_eq!(response.window_size, 0);
    assert!(response.payload.is_empty());
}

#[test]
fn builds_tun_tcp_syn_ack_response_packet_for_initial_syn() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet = build_tun_tcp_syn_ack_response_packet(&request_segment, 1000, 0x2000)
        .expect("build TCP SYN-ACK response");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse TCP SYN-ACK response");

    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1000);
    assert_eq!(response.acknowledgment_number, 11);
    assert_eq!(response.flags.bits(), 0x0012);
    assert!(response.flags.syn());
    assert!(response.flags.ack());
    assert_eq!(response.window_size, 0x2000);
    assert!(response.payload.is_empty());
}

#[test]
fn rejects_non_initial_syn_for_tun_tcp_syn_ack_response() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 1001, 0x0012, 0x4000, &[], b""),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let error = build_tun_tcp_syn_ack_response_packet(&request_segment, 1000, 0x2000)
        .expect_err("SYN-ACK segment is not an initial client SYN");

    assert_eq!(
        error,
        TunPacketError::ExpectedTcpSynSegment {
            flags: TunTcpFlags::from_bits(0x0012)
        }
    );
}

#[test]
fn starts_tun_tcp_session_from_syn_and_establishes_on_matching_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let mut sessions = TunTcpSessionTable::new();

    let response = sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");

    assert_eq!(sessions.len(), 1);
    assert_eq!(response.session.client_initial_sequence_number, 10);
    assert_eq!(response.session.client_next_sequence_number, 11);
    assert_eq!(response.session.server_initial_sequence_number, 1000);
    assert_eq!(response.session.server_next_sequence_number, 1001);
    assert_eq!(response.session.phase, TunTcpSessionPhase::SynReceived);
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    assert_eq!(
        sessions
            .get(&key)
            .expect("session record")
            .server_next_sequence_number,
        1001
    );
    let syn_ack = parse_tun_tcp_segment(&response.packet).expect("parse SYN-ACK packet");
    assert!(syn_ack.flags.syn());
    assert!(syn_ack.flags.ack());
    assert_eq!(syn_ack.sequence_number, 1000);
    assert_eq!(syn_ack.acknowledgment_number, 11);

    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    let established = sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");

    assert_eq!(established.phase, TunTcpSessionPhase::Established);
    assert_eq!(
        sessions.get(&key).expect("established session").phase,
        TunTcpSessionPhase::Established
    );
}

#[test]
fn accepts_established_tun_tcp_client_payload_and_acknowledges_it() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");

    let frame = sessions
        .accept_client_payload(&data)
        .expect("accept TCP client payload")
        .expect("payload frame");

    assert_eq!(frame.sequence_number, 11);
    assert_eq!(frame.acknowledgment_number, 16);
    assert_eq!(frame.payload, b"GET /");
    assert_eq!(
        frame.session.client_next_sequence_number, 16,
        "session should advance by payload length"
    );
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        16
    );
    let response = parse_tun_tcp_segment(&frame.ack_packet).expect("parse payload ACK packet");
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(response.flags.bits(), 0x0010);
    assert!(response.flags.ack());
    assert!(response.payload.is_empty());
}

#[test]
fn acknowledges_duplicate_tun_tcp_client_payload_without_advancing_session() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");
    sessions
        .accept_client_payload(&data)
        .expect("accept TCP client payload")
        .expect("payload frame");

    let duplicate = sessions
        .acknowledge_duplicate_client_payload(&data)
        .expect("ack duplicate TCP client payload")
        .expect("duplicate payload ACK");

    assert_eq!(duplicate.sequence_number, 11);
    assert_eq!(duplicate.acknowledgment_number, 16);
    assert_eq!(duplicate.payload, b"GET /");
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        16,
        "duplicate payload must not advance the client cursor"
    );
    let response =
        parse_tun_tcp_segment(&duplicate.ack_packet).expect("parse duplicate payload ACK packet");
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 16);
    assert!(response.flags.ack());
    assert!(response.payload.is_empty());
}

#[test]
fn accepts_partially_overlapping_tun_tcp_client_payload_suffix_only() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let first_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"hello"),
    );
    let first = parse_tun_tcp_segment(&first_packet).expect("parse first TCP data segment");
    sessions
        .accept_client_payload(&first)
        .expect("accept first TCP client payload")
        .expect("first payload frame");
    let overlapping_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 13, 1001, 0x0018, 0x4000, &[], b"llo world"),
    );
    let overlapping =
        parse_tun_tcp_segment(&overlapping_packet).expect("parse overlapping TCP segment");

    let frame = sessions
        .accept_overlapping_client_payload(&overlapping)
        .expect("accept overlapping TCP client payload")
        .expect("overlapping payload frame");

    assert_eq!(frame.sequence_number, 16);
    assert_eq!(frame.acknowledgment_number, 22);
    assert_eq!(frame.payload, b" world");
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        22,
        "overlapping payload should advance by the new suffix only"
    );
    let response =
        parse_tun_tcp_segment(&frame.ack_packet).expect("parse overlapping payload ACK packet");
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 22);
    assert!(response.flags.ack());
    assert!(response.payload.is_empty());
}

#[test]
fn acknowledges_out_of_order_tun_tcp_client_payload_without_advancing_session() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let out_of_order_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1001, 0x0018, 0x4000, &[], b"late"),
    );
    let out_of_order =
        parse_tun_tcp_segment(&out_of_order_packet).expect("parse out-of-order TCP segment");

    let ack = sessions
        .acknowledge_out_of_order_client_payload(&out_of_order)
        .expect("ack out-of-order TCP client payload")
        .expect("out-of-order payload ACK");

    assert_eq!(ack.sequence_number, 16);
    assert_eq!(ack.acknowledgment_number, 11);
    assert_eq!(ack.payload, b"late");
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        11,
        "out-of-order payload must not advance the client cursor"
    );
    let response =
        parse_tun_tcp_segment(&ack.ack_packet).expect("parse out-of-order payload ACK packet");
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 11);
    assert!(response.flags.ack());
    assert!(response.payload.is_empty());
}

#[test]
fn ignores_tun_tcp_client_payload_before_established_or_out_of_order() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let early_data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"early"),
    );
    let early_data =
        parse_tun_tcp_segment(&early_data_packet).expect("parse early TCP data segment");

    assert!(sessions
        .accept_client_payload(&early_data)
        .expect("try early TCP payload")
        .is_none());
    assert_eq!(
        sessions.get(&key).expect("stored session").phase,
        TunTcpSessionPhase::SynReceived
    );
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        11
    );

    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let out_of_order_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 12, 1001, 0x0018, 0x4000, &[], b"late"),
    );
    let out_of_order =
        parse_tun_tcp_segment(&out_of_order_packet).expect("parse out-of-order TCP segment");

    assert!(sessions
        .accept_client_payload(&out_of_order)
        .expect("try out-of-order TCP payload")
        .is_none());
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        11
    );
}

#[test]
fn builds_tun_tcp_ack_response_packet_with_swapped_flow() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet =
        build_tun_tcp_ack_response_packet(&request_segment.flow, 1001, 16, 0x2000)
            .expect("build TCP ACK response");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse TCP ACK response");

    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(response.flags.bits(), 0x0010);
    assert_eq!(response.window_size, 0x2000);
    assert!(response.payload.is_empty());
}

#[test]
fn sends_tun_tcp_server_payload_and_advances_server_sequence() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");
    sessions
        .accept_client_payload(&data)
        .expect("accept TCP client payload")
        .expect("payload frame");

    let frame = sessions
        .send_server_payload(&syn.flow, b"HTTP/1.1")
        .expect("send TCP server payload")
        .expect("server payload frame");

    assert_eq!(frame.sequence_number, 1001);
    assert_eq!(frame.acknowledgment_number, 16);
    assert_eq!(frame.payload, b"HTTP/1.1");
    assert_eq!(
        frame.session.server_next_sequence_number, 1009,
        "server sequence should advance by payload length"
    );
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .server_next_sequence_number,
        1009
    );
    let response = parse_tun_tcp_segment(&frame.packet).expect("parse server payload packet");
    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(response.flags.bits(), 0x0018);
    assert!(response.flags.psh());
    assert!(response.flags.ack());
    assert_eq!(response.window_size, 0x2000);
    assert_eq!(response.payload, b"HTTP/1.1");
}

#[test]
fn accepts_tun_tcp_client_payload_with_stale_known_server_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");
    let first_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let first = parse_tun_tcp_segment(&first_packet).expect("parse first TCP data segment");
    sessions
        .accept_client_payload(&first)
        .expect("accept first TCP client payload")
        .expect("first payload frame");
    sessions
        .send_server_payload(&syn.flow, b"HTTP/1.1")
        .expect("send TCP server payload")
        .expect("server payload frame");
    let invalid_ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1000, 0x0018, 0x4000, &[], b"bad"),
    );
    let invalid_ack =
        parse_tun_tcp_segment(&invalid_ack_packet).expect("parse invalid ACK TCP segment");
    assert!(sessions
        .accept_client_payload(&invalid_ack)
        .expect("try client payload with unknown server ACK")
        .is_none());

    let stale_ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1001, 0x0018, 0x4000, &[], b"more"),
    );
    let stale_ack = parse_tun_tcp_segment(&stale_ack_packet).expect("parse stale ACK TCP segment");

    let frame = sessions
        .accept_client_payload(&stale_ack)
        .expect("accept client payload with stale server ACK")
        .expect("payload frame");

    assert_eq!(frame.sequence_number, 16);
    assert_eq!(frame.acknowledgment_number, 20);
    assert_eq!(frame.payload, b"more");
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .client_next_sequence_number,
        20
    );
    let response =
        parse_tun_tcp_segment(&frame.ack_packet).expect("parse stale payload ACK packet");
    assert_eq!(response.sequence_number, 1009);
    assert_eq!(response.acknowledgment_number, 20);
    assert!(response.flags.ack());
    assert!(response.payload.is_empty());
}

#[test]
fn ignores_tun_tcp_server_payload_before_established_or_empty_payload() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let key = TunTcpSessionKey::from_flow(&syn.flow).expect("session key");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");

    assert!(sessions
        .send_server_payload(&syn.flow, b"early")
        .expect("try early server payload")
        .is_none());
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .server_next_sequence_number,
        1001
    );

    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    sessions
        .apply_ack(&ack)
        .expect("apply session ACK")
        .expect("session established");

    assert!(sessions
        .send_server_payload(&syn.flow, b"")
        .expect("try empty server payload")
        .is_none());
    assert_eq!(
        sessions
            .get(&key)
            .expect("stored session")
            .server_next_sequence_number,
        1001
    );
}

#[test]
fn builds_tun_tcp_payload_response_packet_with_swapped_flow() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet =
        build_tun_tcp_payload_response_packet(&request_segment.flow, 1001, 16, 0x2000, b"HTTP/1.1")
            .expect("build TCP payload response");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse TCP payload response");

    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(response.flags.bits(), 0x0018);
    assert_eq!(response.window_size, 0x2000);
    assert_eq!(response.payload, b"HTTP/1.1");
}

#[test]
fn builds_tun_tcp_fin_ack_response_packet_with_swapped_flow() {
    let request = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1009, 0x0010, 0x4000, &[], b""),
    );
    let request_segment = parse_tun_tcp_segment(&request).expect("parse request TCP segment");

    let response_packet =
        build_tun_tcp_fin_ack_response_packet(&request_segment.flow, 1009, 16, 0x2000)
            .expect("build TCP FIN-ACK response");
    let response = parse_tun_tcp_segment(&response_packet).expect("parse TCP FIN-ACK response");

    assert_eq!(response.flow.source_port, Some(443));
    assert_eq!(response.flow.destination_port, Some(49152));
    assert_eq!(response.sequence_number, 1009);
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(response.flags.bits(), 0x0011);
    assert!(response.flags.fin());
    assert!(response.flags.ack());
    assert_eq!(response.window_size, 0x2000);
    assert!(response.payload.is_empty());
}

#[test]
fn processes_tun_tcp_session_steps_with_relay_callbacks_and_response_packets() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");
    let out_of_order_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1001, 0x0018, 0x4000, &[], b"late"),
    );
    let out_of_order =
        parse_tun_tcp_segment(&out_of_order_packet).expect("parse out-of-order TCP segment");
    let overlapping_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 14, 1009, 0x0018, 0x4000, &[], b" /more"),
    );
    let overlapping =
        parse_tun_tcp_segment(&overlapping_packet).expect("parse overlapping TCP segment");
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::with_server_payloads(vec![b"HTTP/1.1".to_vec()]);

    let syn_step = process_tun_tcp_session_segment(&mut sessions, &syn, &mut relay, 1000, 0x2000)
        .expect("process SYN step");
    let TunTcpSessionStep::SynAck { response } = syn_step else {
        panic!("expected SYN-ACK step");
    };
    assert_eq!(response.session.phase, TunTcpSessionPhase::SynReceived);
    let syn_ack = parse_tun_tcp_segment(&response.packet).expect("parse SYN-ACK packet");
    assert_eq!(syn_ack.sequence_number, 1000);
    assert_eq!(syn_ack.acknowledgment_number, 11);
    assert!(relay.established_sessions.is_empty());

    let ack_step = process_tun_tcp_session_segment(&mut sessions, &ack, &mut relay, 1000, 0x2000)
        .expect("process ACK step");
    let TunTcpSessionStep::Established { session } = ack_step else {
        panic!("expected established step");
    };
    assert_eq!(session.phase, TunTcpSessionPhase::Established);
    assert_eq!(relay.established_sessions.len(), 1);
    assert_eq!(
        relay.established_sessions[0].server_next_sequence_number,
        1001
    );

    let out_of_order_step =
        process_tun_tcp_session_segment(&mut sessions, &out_of_order, &mut relay, 1000, 0x2000)
            .expect("process out-of-order data step");
    assert_eq!(out_of_order_step.response_packets().len(), 1);
    let TunTcpSessionStep::OutOfOrderClientPayload { ack } = out_of_order_step else {
        panic!("expected out-of-order client payload step");
    };
    assert_eq!(ack.sequence_number, 16);
    assert_eq!(ack.acknowledgment_number, 11);
    assert_eq!(ack.payload, b"late");
    assert!(
        relay.client_payloads.is_empty(),
        "out-of-order payload must not be written to the relay"
    );
    let out_of_order_ack =
        parse_tun_tcp_segment(&ack.ack_packet).expect("parse out-of-order payload ACK");
    assert_eq!(out_of_order_ack.sequence_number, 1001);
    assert_eq!(out_of_order_ack.acknowledgment_number, 11);
    assert!(out_of_order_ack.flags.ack());
    assert!(out_of_order_ack.payload.is_empty());

    let data_step = process_tun_tcp_session_segment(&mut sessions, &data, &mut relay, 1000, 0x2000)
        .expect("process data step");
    assert_eq!(data_step.response_packets().len(), 2);
    let TunTcpSessionStep::ClientPayload {
        frame,
        server_response,
        server_close,
    } = data_step
    else {
        panic!("expected client payload step");
    };
    assert_eq!(frame.payload, b"GET /");
    assert_eq!(relay.client_payloads, vec![b"GET /".to_vec()]);
    assert!(server_close.is_none());
    let server_response = server_response.expect("server response packet");
    assert_eq!(server_response.payload, b"HTTP/1.1");
    let server_packet =
        parse_tun_tcp_segment(&server_response.packet).expect("parse server response packet");
    assert_eq!(server_packet.sequence_number, 1001);
    assert_eq!(server_packet.acknowledgment_number, 16);
    assert_eq!(server_packet.payload, b"HTTP/1.1");
    assert!(server_packet.flags.psh());
    assert!(server_packet.flags.ack());

    let duplicate_step =
        process_tun_tcp_session_segment(&mut sessions, &data, &mut relay, 1000, 0x2000)
            .expect("process duplicate data step");
    assert_eq!(duplicate_step.response_packets().len(), 1);
    let TunTcpSessionStep::DuplicateClientPayload { ack } = duplicate_step else {
        panic!("expected duplicate client payload step");
    };
    assert_eq!(ack.sequence_number, 11);
    assert_eq!(ack.acknowledgment_number, 16);
    assert_eq!(ack.payload, b"GET /");
    assert_eq!(
        relay.client_payloads,
        vec![b"GET /".to_vec()],
        "duplicate payload must not be written to the relay again"
    );
    let duplicate_ack =
        parse_tun_tcp_segment(&ack.ack_packet).expect("parse duplicate payload ACK");
    assert_eq!(duplicate_ack.sequence_number, 1009);
    assert_eq!(duplicate_ack.acknowledgment_number, 16);
    assert!(duplicate_ack.flags.ack());
    assert!(duplicate_ack.payload.is_empty());

    let overlapping_step =
        process_tun_tcp_session_segment(&mut sessions, &overlapping, &mut relay, 1000, 0x2000)
            .expect("process overlapping data step");
    assert_eq!(overlapping_step.response_packets().len(), 1);
    let TunTcpSessionStep::OverlappingClientPayload {
        frame,
        server_response,
        server_close,
    } = overlapping_step
    else {
        panic!("expected overlapping client payload step");
    };
    assert_eq!(frame.sequence_number, 16);
    assert_eq!(frame.acknowledgment_number, 20);
    assert_eq!(frame.payload, b"more");
    assert!(server_response.is_none());
    assert!(server_close.is_none());
    assert_eq!(
        relay.client_payloads,
        vec![b"GET /".to_vec(), b"more".to_vec()],
        "overlapping payload should only write the new suffix to the relay"
    );
    let overlapping_ack =
        parse_tun_tcp_segment(&frame.ack_packet).expect("parse overlapping payload ACK");
    assert_eq!(overlapping_ack.sequence_number, 1009);
    assert_eq!(overlapping_ack.acknowledgment_number, 20);
    assert!(overlapping_ack.flags.ack());
    assert!(overlapping_ack.payload.is_empty());
}

#[test]
fn polls_tun_tcp_server_payload_on_followup_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");
    let followup_ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1009, 0x0010, 0x4000, &[], b""),
    );
    let followup_ack =
        parse_tun_tcp_segment(&followup_ack_packet).expect("parse follow-up ACK segment");
    let mut sessions = TunTcpSessionTable::new();
    let mut relay =
        FakeTunTcpSessionRelay::with_server_payloads(vec![b"HTTP/1.1".to_vec(), b" body".to_vec()]);

    process_tun_tcp_session_segment(&mut sessions, &syn, &mut relay, 1000, 0x2000)
        .expect("process SYN step");
    process_tun_tcp_session_segment(&mut sessions, &ack, &mut relay, 1000, 0x2000)
        .expect("process ACK step");
    process_tun_tcp_session_segment(&mut sessions, &data, &mut relay, 1000, 0x2000)
        .expect("process data step");

    let server_step =
        process_tun_tcp_session_segment(&mut sessions, &followup_ack, &mut relay, 1000, 0x2000)
            .expect("process follow-up ACK step");

    assert_eq!(server_step.response_packets().len(), 1);
    let TunTcpSessionStep::ServerPayload { response } = server_step else {
        panic!("expected server payload step");
    };
    assert_eq!(response.sequence_number, 1009);
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(response.payload, b" body");
    let packet = parse_tun_tcp_segment(&response.packet).expect("parse server payload packet");
    assert_eq!(packet.sequence_number, 1009);
    assert_eq!(packet.acknowledgment_number, 16);
    assert_eq!(packet.payload, b" body");
}

#[test]
fn closes_tun_tcp_session_on_server_eof_and_builds_fin_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::with_server_reads(vec![TunTcpServerRead::Closed]);

    process_tun_tcp_session_segment(&mut sessions, &syn, &mut relay, 1000, 0x2000)
        .expect("process SYN step");
    process_tun_tcp_session_segment(&mut sessions, &ack, &mut relay, 1000, 0x2000)
        .expect("process ACK step");
    let data_step = process_tun_tcp_session_segment(&mut sessions, &data, &mut relay, 1000, 0x2000)
        .expect("process data step");

    assert_eq!(data_step.response_packets().len(), 2);
    let TunTcpSessionStep::ClientPayload {
        frame,
        server_response,
        server_close,
    } = data_step
    else {
        panic!("expected client payload step");
    };
    assert_eq!(frame.payload, b"GET /");
    assert!(server_response.is_none());
    let server_close = server_close.expect("server FIN packet");
    assert_eq!(server_close.sequence_number, 1001);
    assert_eq!(server_close.acknowledgment_number, 16);
    let fin = parse_tun_tcp_segment(&server_close.packet).expect("parse server FIN packet");
    assert_eq!(fin.sequence_number, 1001);
    assert_eq!(fin.acknowledgment_number, 16);
    assert!(fin.flags.fin());
    assert!(fin.flags.ack());
    assert!(fin.payload.is_empty());
    assert!(sessions.is_empty());
    assert_eq!(relay.closed_sessions.len(), 1);
}

#[test]
fn polls_tun_tcp_server_eof_on_followup_ack_and_builds_fin_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
    );
    let ack = parse_tun_tcp_segment(&ack_packet).expect("parse ACK segment");
    let data_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
    );
    let data = parse_tun_tcp_segment(&data_packet).expect("parse TCP data segment");
    let followup_ack_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 16, 1009, 0x0010, 0x4000, &[], b""),
    );
    let followup_ack =
        parse_tun_tcp_segment(&followup_ack_packet).expect("parse follow-up ACK segment");
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::with_server_reads(vec![
        TunTcpServerRead::Payload(b"HTTP/1.1".to_vec()),
        TunTcpServerRead::Closed,
    ]);

    process_tun_tcp_session_segment(&mut sessions, &syn, &mut relay, 1000, 0x2000)
        .expect("process SYN step");
    process_tun_tcp_session_segment(&mut sessions, &ack, &mut relay, 1000, 0x2000)
        .expect("process ACK step");
    process_tun_tcp_session_segment(&mut sessions, &data, &mut relay, 1000, 0x2000)
        .expect("process data step");

    let server_step =
        process_tun_tcp_session_segment(&mut sessions, &followup_ack, &mut relay, 1000, 0x2000)
            .expect("process follow-up ACK step");

    assert_eq!(server_step.response_packets().len(), 1);
    let TunTcpSessionStep::ServerClosed { response } = server_step else {
        panic!("expected server closed step");
    };
    assert_eq!(response.sequence_number, 1009);
    assert_eq!(response.acknowledgment_number, 16);
    let fin = parse_tun_tcp_segment(&response.packet).expect("parse server FIN packet");
    assert_eq!(fin.sequence_number, 1009);
    assert_eq!(fin.acknowledgment_number, 16);
    assert!(fin.flags.fin());
    assert!(fin.flags.ack());
    assert!(sessions.is_empty());
    assert_eq!(relay.closed_sessions.len(), 1);
}

#[test]
fn closes_tun_tcp_session_step_and_notifies_relay() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::default();
    process_tun_tcp_session_segment(&mut sessions, &syn, &mut relay, 1000, 0x2000)
        .expect("process SYN step");
    let rst_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0014, 0x4000, &[], b""),
    );
    let rst = parse_tun_tcp_segment(&rst_packet).expect("parse RST segment");

    let close_step = process_tun_tcp_session_segment(&mut sessions, &rst, &mut relay, 1000, 0x2000)
        .expect("process close step");

    let TunTcpSessionStep::Closed { session, response } = close_step else {
        panic!("expected closed step");
    };
    assert_eq!(session.phase, TunTcpSessionPhase::SynReceived);
    assert!(response.is_none());
    assert!(sessions.is_empty());
    assert_eq!(relay.closed_sessions.len(), 1);
}

#[test]
fn removes_tun_tcp_session_on_rst_without_close_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let rst_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0014, 0x4000, &[], b""),
    );
    let rst = parse_tun_tcp_segment(&rst_packet).expect("parse RST segment");

    let removed = sessions
        .remove_on_close(&rst)
        .expect("remove closed session")
        .expect("removed session");

    let (removed, response) = removed;
    assert_eq!(removed.phase, TunTcpSessionPhase::SynReceived);
    assert!(response.is_none());
    assert!(sessions.is_empty());
}

#[test]
fn removes_tun_tcp_session_on_fin_and_builds_close_ack() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let fin_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 11, 1001, 0x0011, 0x4000, &[], b""),
    );
    let fin = parse_tun_tcp_segment(&fin_packet).expect("parse FIN segment");

    let (removed, response) = sessions
        .remove_on_close(&fin)
        .expect("remove closed session")
        .expect("removed session");

    assert_eq!(removed.phase, TunTcpSessionPhase::SynReceived);
    let response = response.expect("FIN close ACK");
    assert_eq!(response.sequence_number, 1001);
    assert_eq!(response.acknowledgment_number, 12);
    let packet = parse_tun_tcp_segment(&response.packet).expect("parse FIN ACK");
    assert_eq!(packet.flow.source_port, Some(443));
    assert_eq!(packet.flow.destination_port, Some(49152));
    assert_eq!(packet.sequence_number, 1001);
    assert_eq!(packet.acknowledgment_number, 12);
    assert_eq!(packet.flags.bits(), 0x0010);
    assert!(packet.flags.ack());
    assert!(!packet.flags.fin());
    assert!(packet.payload.is_empty());
    assert!(sessions.is_empty());
}

#[test]
fn prunes_idle_tun_tcp_sessions_and_closes_relay_state() {
    let syn_packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let syn = parse_tun_tcp_segment(&syn_packet).expect("parse SYN segment");
    let mut sessions = TunTcpSessionTable::new();
    sessions
        .start_from_syn(&syn, 1000, 0x2000)
        .expect("start TUN TCP session");
    let mut relay = FakeTunTcpSessionRelay::default();

    let report = prune_idle_tun_tcp_sessions(
        &mut sessions,
        &mut relay,
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(5),
    );

    assert_eq!(report.pruned_sessions, 1);
    assert_eq!(report.close_errors, 0);
    assert!(report.last_close_error.is_none());
    assert!(sessions.is_empty());
    assert_eq!(relay.closed_sessions.len(), 1);
}

#[test]
fn process_tun_packet_writes_tcp_reset_for_blocked_tcp_route() {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-web".to_string(),
        matcher: RouteMatcher::PortExact(443),
        action: RouteAction::Block,
    });
    let packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let action =
        process_tun_packet(&packet, &routes, true, &mut dns, 30).expect("process blocked TCP");

    let TunPacketProcessAction::WriteTcpReset { response } = action else {
        panic!("expected TCP reset write action");
    };
    assert_eq!(response.plan.relay_action, TunPacketRelayAction::Drop);
    assert_eq!(
        response.plan.route.matched_rule,
        Some("block-web".to_string())
    );
    assert_eq!(response.sequence_number, 0);
    assert_eq!(response.acknowledgment_number, 11);
    let reset = parse_tun_tcp_segment(&response.packet).expect("parse reset packet");
    assert_eq!(reset.flow.source_port, Some(443));
    assert_eq!(reset.flow.destination_port, Some(49152));
    assert!(reset.flags.rst());
    assert!(reset.flags.ack());
}

#[test]
fn process_tun_packet_drops_blocked_tcp_rst_without_reset_loop() {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-web".to_string(),
        matcher: RouteMatcher::PortExact(443),
        action: RouteAction::Block,
    });
    let packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0004, 0x4000, &[], b""),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let action =
        process_tun_packet(&packet, &routes, true, &mut dns, 30).expect("process blocked TCP RST");

    let TunPacketProcessAction::Relay(plan) = action else {
        panic!("expected blocked RST to remain a drop plan");
    };
    assert_eq!(plan.relay_action, TunPacketRelayAction::Drop);
}

#[test]
fn tun_dns_hijack_plan_parses_query_and_swaps_response_endpoints() {
    let query = dns_query(0x1234, "Example.COM", 1);
    let packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, &query));

    let plan = plan_tun_dns_hijack(&packet).expect("plan TUN DNS hijack");

    assert_eq!(plan.question.id, 0x1234);
    assert_eq!(plan.question.name, "example.com");
    assert_eq!(plan.question.question_type, DnsQuestionType::A);
    assert_eq!(plan.response_source.to_string(), "8.8.8.8:53");
    assert_eq!(plan.response_destination.to_string(), "10.7.0.2:54321");
}

#[test]
fn tun_dns_hijack_plan_rejects_non_dns_udp_destination() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"keli"),
    );

    let error = plan_tun_dns_hijack(&packet).expect_err("non-DNS UDP should not hijack");

    assert_eq!(
        error,
        TunPacketError::NotDnsHijackCandidate {
            destination_port: Some(443)
        }
    );
}

#[test]
fn builds_ipv4_tun_dns_response_packet_with_swapped_flow() {
    let query = dns_query(0x1234, "example.com", 1);
    let packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, &query));
    let plan = plan_tun_dns_hijack(&packet).expect("plan TUN DNS hijack");
    let response_payload = build_dns_response(
        &plan.question,
        &[IpAddr::V4("203.0.113.7".parse().expect("valid IP"))],
        60,
    );

    let response_packet =
        build_tun_dns_response_packet(&plan, &response_payload).expect("build TUN DNS response");
    let response = parse_tun_udp_payload(&response_packet).expect("parse response packet");

    assert_eq!(
        response.flow.source_ip,
        "8.8.8.8".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(
        response.flow.destination_ip,
        "10.7.0.2".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(response.flow.source_port, Some(53));
    assert_eq!(response.flow.destination_port, Some(54321));
    assert_eq!(response.payload, response_payload.as_slice());
    assert_ne!(&response_packet[10..12], &[0, 0]);
    assert_ne!(&response_packet[26..28], &[0, 0]);
}

#[test]
fn builds_ipv6_tun_dns_response_packet_with_udp_checksum() {
    let query = dns_query(0x9876, "example.com", 28);
    let packet = ipv6_packet(
        17,
        "fd00::2",
        "2001:4860:4860::8888",
        &udp_datagram(54000, 53, &query),
    );
    let plan = plan_tun_dns_hijack(&packet).expect("plan IPv6 TUN DNS hijack");
    let response_payload = build_dns_error_response(&plan.question, 3);

    let response_packet =
        build_tun_dns_response_packet(&plan, &response_payload).expect("build IPv6 DNS response");
    let response = parse_tun_udp_payload(&response_packet).expect("parse IPv6 response packet");

    assert_eq!(
        response.flow.source_ip,
        "2001:4860:4860::8888".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(
        response.flow.destination_ip,
        "fd00::2".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(response.flow.source_port, Some(53));
    assert_eq!(response.flow.destination_port, Some(54000));
    assert_eq!(response.payload, response_payload.as_slice());
    assert_ne!(&response_packet[46..48], &[0, 0]);
}

#[test]
fn builds_tun_dns_hijack_response_packet_from_dns_engine() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &udp_datagram(54321, 53, &dns_query(0x1234, "example.com", 1)),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let response =
        build_tun_dns_hijack_response(&packet, &mut dns, 30).expect("build DNS response");
    let udp = parse_tun_udp_payload(&response.packet).expect("parse response packet");

    assert_eq!(response.rcode, 0);
    assert_eq!(response.plan.question.name, "example.com");
    assert_eq!(udp.payload, response.dns_payload.as_slice());
    assert!(udp
        .payload
        .windows(4)
        .any(|window| window == [203, 0, 113, 7]));
}

#[test]
fn tun_dns_hijack_response_returns_notimp_for_unsupported_question_type() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &udp_datagram(54321, 53, &dns_query(0x9876, "example.com", 16)),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let response =
        build_tun_dns_hijack_response(&packet, &mut dns, 30).expect("build DNS response");
    let udp = parse_tun_udp_payload(&response.packet).expect("parse response packet");

    assert_eq!(response.rcode, 4);
    assert_eq!(dns_rcode(udp.payload), 4);
}

#[test]
fn tun_dns_hijack_response_returns_nxdomain_when_local_resolution_is_blocked() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &udp_datagram(54321, 53, &dns_query(0x5678, "blocked.example", 1)),
    );
    let mut dns = DnsEngine::with_policy(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::PreventPublicLeak,
    );

    let response =
        build_tun_dns_hijack_response(&packet, &mut dns, 30).expect("build blocked DNS response");
    let udp = parse_tun_udp_payload(&response.packet).expect("parse blocked response packet");

    assert_eq!(response.rcode, 3);
    assert_eq!(dns_rcode(udp.payload), 3);
}

#[test]
fn process_tun_packet_writes_dns_hijack_response_packet() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &udp_datagram(54321, 53, &dns_query(0x1234, "example.com", 1)),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let action = process_tun_packet(&packet, &routes, true, &mut dns, 30)
        .expect("process DNS hijack packet");

    let TunPacketProcessAction::WritePacket { response } = action else {
        panic!("expected DNS response write action");
    };
    assert_eq!(response.rcode, 0);
    assert!(parse_tun_udp_payload(&response.packet)
        .expect("parse response packet")
        .payload
        .windows(4)
        .any(|window| window == [203, 0, 113, 7]));
}

#[test]
fn process_tun_packet_returns_relay_plan_for_direct_udp() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"keli"),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let action = process_tun_packet(&packet, &routes, true, &mut dns, 30)
        .expect("process direct UDP packet");

    assert_eq!(
        action,
        TunPacketProcessAction::Relay(TunPacketRelayPlan {
            route: decide_tun_packet_route(&packet, &routes, true).expect("route packet"),
            relay_action: TunPacketRelayAction::DirectUdp {
                target: OutboundTarget::new("1.1.1.1", 443)
            }
        })
    );
}

#[test]
fn relays_tun_direct_udp_packet_and_wraps_response() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"ping"),
    );
    let plan = plan_tun_packet_relay(&packet, &routes, true).expect("plan direct UDP packet");
    let mut relay = FakeTunUdpRelay::ok("1.1.1.1:443", b"pong");

    let response =
        relay_tun_direct_udp_packet(&packet, plan.clone(), &mut relay).expect("relay TUN UDP");

    assert_eq!(response.plan, plan);
    assert_eq!(
        relay.calls,
        vec![(OutboundTarget::new("1.1.1.1", 443), b"ping".to_vec())]
    );
    assert_eq!(response.relay_payload, b"pong");
    let udp = parse_tun_udp_payload(&response.packet).expect("parse relay response");
    assert_eq!(
        udp.flow.source_ip,
        "1.1.1.1".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(
        udp.flow.destination_ip,
        "10.7.0.2".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(udp.flow.source_port, Some(443));
    assert_eq!(udp.flow.destination_port, Some(54321));
    assert_eq!(udp.payload, b"pong");
}

#[test]
fn relays_tun_outbound_udp_packet_with_tag_and_wraps_response() {
    let routes = RouteEngine::new(RouteAction::Outbound("edge".to_string()));
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"ping"),
    );
    let plan = plan_tun_packet_relay(&packet, &routes, true).expect("plan outbound UDP packet");
    let mut relay = FakeTunUdpRelay::ok("1.1.1.1:443", b"pong");

    let response =
        relay_tun_udp_packet(&packet, plan.clone(), &mut relay).expect("relay outbound TUN UDP");

    assert_eq!(response.plan, plan);
    assert!(relay.calls.is_empty());
    assert_eq!(
        relay.outbound_calls,
        vec![(
            "edge".to_string(),
            OutboundTarget::new("1.1.1.1", 443),
            b"ping".to_vec()
        )]
    );
    let udp = parse_tun_udp_payload(&response.packet).expect("parse relay response");
    assert_eq!(
        udp.flow.source_ip,
        "1.1.1.1".parse::<IpAddr>().expect("valid IP")
    );
    assert_eq!(udp.flow.source_port, Some(443));
    assert_eq!(udp.payload, b"pong");
}

#[test]
fn tun_packet_loop_with_udp_relay_writes_direct_udp_response() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"ping"),
    );
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![packet]);
    let mut relay = FakeTunUdpRelay::ok("1.1.1.1:443", b"pong");

    let summary = run_tun_packet_loop_with_udp_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        1,
        &mut relay,
    )
    .expect("run TUN loop with UDP relay");

    assert_eq!(summary.processed_packets(), 1);
    assert_eq!(summary.udp_relay_responses_written, 1);
    assert_eq!(summary.relay_packets, 0);
    assert_eq!(summary.tcp_relay_plans, 0);
    assert_eq!(summary.udp_relay_plans, 0);
    assert_eq!(summary.udp_relay_errors, 0);
    assert_eq!(
        relay.calls,
        vec![(OutboundTarget::new("1.1.1.1", 443), b"ping".to_vec())]
    );
    assert_eq!(device.writes.len(), 1);
    assert_eq!(
        parse_tun_udp_payload(&device.writes[0])
            .expect("parse written response")
            .payload,
        b"pong"
    );
}

#[test]
fn tun_packet_loop_with_udp_relay_writes_outbound_udp_response() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"ping"),
    );
    let routes = RouteEngine::new(RouteAction::Outbound("edge".to_string()));
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![packet]);
    let mut relay = FakeTunUdpRelay::ok("1.1.1.1:443", b"pong");

    let summary = run_tun_packet_loop_with_udp_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        1,
        &mut relay,
    )
    .expect("run TUN loop with tagged UDP relay");

    assert_eq!(summary.processed_packets(), 1);
    assert_eq!(summary.udp_relay_responses_written, 1);
    assert!(relay.calls.is_empty());
    assert_eq!(
        relay.outbound_calls,
        vec![(
            "edge".to_string(),
            OutboundTarget::new("1.1.1.1", 443),
            b"ping".to_vec()
        )]
    );
    assert_eq!(device.writes.len(), 1);
    assert_eq!(
        parse_tun_udp_payload(&device.writes[0])
            .expect("parse written response")
            .payload,
        b"pong"
    );
}

#[test]
fn registry_tun_udp_relay_relays_direct_udp_datagram() {
    let (port, server) = spawn_udp_echo_server(b"ping", b"pong");
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "127.0.0.1",
        &udp_datagram(54321, port, b"ping"),
    );
    let routes = RouteEngine::new(RouteAction::Direct);
    let plan = plan_tun_packet_relay(&packet, &routes, false).expect("plan direct UDP packet");
    let registry = OutboundRegistry::new();
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay = RegistryTunUdpRelay::new(&registry, &mut dns, Duration::from_secs(1));

    let response = relay_tun_udp_packet(&packet, plan, &mut relay)
        .expect("registry relay should execute direct UDP");

    assert_eq!(response.relay_source.port(), port);
    assert_eq!(
        parse_tun_udp_payload(&response.packet)
            .expect("parse relay response")
            .payload,
        b"pong"
    );
    server.join().expect("udp echo server");
}

#[test]
fn tun_packet_loop_with_registry_udp_relay_writes_tagged_outbound_response() {
    let (port, server) = spawn_udp_echo_server(b"ping", b"pong");
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "127.0.0.1",
        &udp_datagram(54321, port, b"ping"),
    );
    let routes = RouteEngine::new(RouteAction::Outbound("edge".to_string()));
    let mut registry = OutboundRegistry::new();
    registry.add_direct("edge");
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay = RegistryTunUdpRelay::new(&registry, &mut dns, Duration::from_secs(1));
    let mut dns_for_hijack = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![packet]);

    let summary = run_tun_packet_loop_with_udp_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns_for_hijack,
        30,
        1,
        &mut relay,
    )
    .expect("run TUN loop with registry UDP relay");

    assert_eq!(summary.processed_packets(), 1);
    assert_eq!(summary.udp_relay_responses_written, 1);
    assert_eq!(device.writes.len(), 1);
    assert_eq!(
        parse_tun_udp_payload(&device.writes[0])
            .expect("parse written response")
            .payload,
        b"pong"
    );
    server.join().expect("udp echo server");
}

#[test]
fn tun_packet_loop_with_registry_relays_executes_direct_udp_and_tcp_sessions() {
    let (udp_port, udp_server) = spawn_udp_echo_server(b"ping", b"pong");
    let (tcp_port, tcp_server) = spawn_tcp_response_server(b"GET /", b"HTTP/1.1");
    let mut packets = vec![ipv4_packet(
        17,
        "10.7.0.2",
        "127.0.0.1",
        &udp_datagram(54321, udp_port, b"ping"),
    )];
    packets.extend(tcp_session_packets(
        "127.0.0.1",
        tcp_port,
        1000,
        b"GET /",
        b"HTTP/1.1".len(),
    ));
    let routes = RouteEngine::new(RouteAction::Direct);
    let registry = OutboundRegistry::new();
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut udp_relay_dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut tcp_relay_dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut udp_relay =
        RegistryTunUdpRelay::new(&registry, &mut udp_relay_dns, Duration::from_secs(1));
    let mut tcp_relay =
        RegistryTunTcpSessionRelay::new(&registry, &mut tcp_relay_dns, Duration::from_secs(1));
    let mut sessions = TunTcpSessionTable::new();
    let mut device = FakeTunPacketDevice::new(packets);

    let summary = run_tun_packet_loop_with_relays_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        5,
        &mut udp_relay,
        &mut sessions,
        &mut tcp_relay,
        1000,
        0x2000,
    )
    .expect("run TUN loop with registry relays");

    assert_eq!(summary.processed_packets(), 5);
    assert_eq!(summary.udp_relay_responses_written, 1);
    assert_eq!(summary.tcp_session_events, 4);
    assert_eq!(summary.tcp_session_packets_written, 3);
    assert_eq!(summary.udp_relay_errors, 0);
    assert_eq!(summary.tcp_session_errors, 0);
    assert_eq!(device.writes.len(), 4);
    assert_eq!(
        parse_tun_udp_payload(&device.writes[0])
            .expect("parse UDP response")
            .payload,
        b"pong"
    );
    let server_payload =
        parse_tun_tcp_segment(&device.writes[3]).expect("parse TCP server payload packet");
    assert_eq!(server_payload.payload, b"HTTP/1.1");
    assert!(tcp_relay.is_empty());
    assert!(sessions.is_empty());
    udp_server.join().expect("udp echo server");
    tcp_server.join().expect("tcp response server");
}

#[test]
fn registry_tun_tcp_session_relay_relays_tagged_direct_outbound_tcp_stream_payload() {
    let (tcp_port, tcp_server) = spawn_tcp_response_server(b"GET /", b"HTTP/1.1");
    let packets = tcp_session_packets("127.0.0.1", tcp_port, 1000, b"GET /", b"HTTP/1.1".len());
    let routes = RouteEngine::new(RouteAction::Outbound("edge".to_string()));
    let mut registry = OutboundRegistry::new();
    registry.add_direct("edge");
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay_dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay =
        RegistryTunTcpSessionRelay::new(&registry, &mut relay_dns, Duration::from_secs(1));
    let mut sessions = TunTcpSessionTable::new();
    let mut device = FakeTunPacketDevice::new(packets);

    let summary = run_tun_packet_loop_with_tcp_session_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        4,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
    )
    .expect("run TUN loop with registry TCP session relay");

    assert_eq!(summary.processed_packets(), 4);
    assert_eq!(summary.tcp_session_events, 4);
    assert_eq!(summary.tcp_session_packets_written, 3);
    assert_eq!(summary.tcp_session_errors, 0);
    assert_eq!(device.writes.len(), 3);
    let server_payload =
        parse_tun_tcp_segment(&device.writes[2]).expect("parse TCP server payload packet");
    assert_eq!(server_payload.payload, b"HTTP/1.1");
    assert!(relay.is_empty());
    assert!(sessions.is_empty());
    tcp_server.join().expect("tcp response server");
}

#[test]
fn registry_tun_tcp_session_relay_polls_followup_server_payload_after_ack() {
    let first_chunk = b"HTTP/1.1";
    let second_chunk = b" body";
    let server_response = b"HTTP/1.1 body";
    let (tcp_port, tcp_server) = spawn_tcp_response_server(b"GET /", server_response);
    let mut packets = tcp_session_packets(
        "127.0.0.1",
        tcp_port,
        1000,
        b"GET /",
        first_chunk.len() + second_chunk.len(),
    );
    let rst = packets.pop().expect("RST packet");
    packets.push(ipv4_packet(
        6,
        "10.7.0.2",
        "127.0.0.1",
        &tcp_segment(
            49152,
            tcp_port,
            16,
            1001 + first_chunk.len() as u32,
            0x0010,
            0x4000,
            &[],
            b"",
        ),
    ));
    packets.push(rst);
    let routes = RouteEngine::new(RouteAction::Outbound("edge".to_string()));
    let mut registry = OutboundRegistry::new();
    registry.add_direct("edge");
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay_dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay =
        RegistryTunTcpSessionRelay::new(&registry, &mut relay_dns, Duration::from_secs(1))
            .with_read_buffer_size(first_chunk.len());
    let mut sessions = TunTcpSessionTable::new();
    let mut device = FakeTunPacketDevice::new(packets);

    let summary = run_tun_packet_loop_with_tcp_session_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        5,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
    )
    .expect("run TUN loop with split registry TCP response");

    assert_eq!(summary.processed_packets(), 5);
    assert_eq!(summary.tcp_session_events, 5);
    assert_eq!(summary.tcp_session_packets_written, 4);
    assert_eq!(summary.tcp_session_errors, 0);
    assert_eq!(device.writes.len(), 4);
    let first_payload =
        parse_tun_tcp_segment(&device.writes[2]).expect("parse first server payload packet");
    assert_eq!(first_payload.sequence_number, 1001);
    assert_eq!(first_payload.acknowledgment_number, 16);
    assert_eq!(first_payload.payload, first_chunk);
    let second_payload =
        parse_tun_tcp_segment(&device.writes[3]).expect("parse second server payload packet");
    assert_eq!(
        second_payload.sequence_number,
        1001 + first_chunk.len() as u32
    );
    assert_eq!(second_payload.acknowledgment_number, 16);
    assert_eq!(second_payload.payload, second_chunk);
    assert!(relay.is_empty());
    assert!(sessions.is_empty());
    tcp_server.join().expect("tcp response server");
}

#[test]
fn registry_tun_tcp_session_relay_reports_server_eof_as_fin_ack() {
    let server_response = b"HTTP/1.1";
    let (tcp_port, tcp_server) = spawn_tcp_response_server(b"GET /", server_response);
    let packets = vec![
        ipv4_packet(
            6,
            "10.7.0.2",
            "127.0.0.1",
            &tcp_segment(49152, tcp_port, 10, 0, 0x0002, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "127.0.0.1",
            &tcp_segment(49152, tcp_port, 11, 1001, 0x0010, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "127.0.0.1",
            &tcp_segment(49152, tcp_port, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "127.0.0.1",
            &tcp_segment(
                49152,
                tcp_port,
                16,
                1001 + server_response.len() as u32,
                0x0010,
                0x4000,
                &[],
                b"",
            ),
        ),
    ];
    let routes = RouteEngine::new(RouteAction::Outbound("edge".to_string()));
    let mut registry = OutboundRegistry::new();
    registry.add_direct("edge");
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay_dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("127.0.0.1".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut relay =
        RegistryTunTcpSessionRelay::new(&registry, &mut relay_dns, Duration::from_secs(1));
    let mut sessions = TunTcpSessionTable::new();
    let mut device = FakeTunPacketDevice::new(packets);

    for _ in 0..3 {
        let event = process_tun_device_packet_with_tcp_session_relay(
            &mut device,
            &routes,
            true,
            &mut dns,
            30,
            &mut sessions,
            &mut relay,
            1000,
            0x2000,
        )
        .expect("process registry TCP session packet");
        assert!(matches!(event, TunPacketLoopEvent::TcpSession { .. }));
    }
    tcp_server.join().expect("tcp response server");

    let event = process_tun_device_packet_with_tcp_session_relay(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
    )
    .expect("process registry TCP EOF poll packet");

    let TunPacketLoopEvent::TcpSession {
        step,
        packets_written,
        ..
    } = event
    else {
        panic!("expected TCP session event");
    };
    assert_eq!(packets_written, 1);
    let TunTcpSessionStep::ServerClosed { response } = step else {
        panic!("expected server closed step");
    };
    assert_eq!(
        response.sequence_number,
        1001 + server_response.len() as u32
    );
    assert_eq!(response.acknowledgment_number, 16);
    assert_eq!(device.writes.len(), 4);
    let fin = parse_tun_tcp_segment(&device.writes[3]).expect("parse server FIN packet");
    assert_eq!(fin.sequence_number, 1001 + server_response.len() as u32);
    assert_eq!(fin.acknowledgment_number, 16);
    assert!(fin.flags.fin());
    assert!(fin.flags.ack());
    assert!(fin.payload.is_empty());
    assert!(relay.is_empty());
    assert!(sessions.is_empty());
}

#[test]
fn tun_packet_loop_with_udp_relay_records_relay_error_and_continues() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"ping"),
    );
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![packet]);
    let mut relay = FakeTunUdpRelay::err("relay down");

    let summary = run_tun_packet_loop_with_udp_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        2,
        &mut relay,
    )
    .expect("run TUN loop with UDP relay error");

    assert_eq!(summary.processed_packets(), 1);
    assert_eq!(summary.idle_events, 1);
    assert_eq!(summary.udp_relay_responses_written, 0);
    assert_eq!(summary.udp_relay_errors, 1);
    assert!(matches!(
        summary.last_udp_relay_error,
        Some(TunUdpRelayError::Relay(error)) if error == "relay down"
    ));
    assert!(device.writes.is_empty());
}

#[test]
fn process_tun_packet_returns_drop_plan_for_blocked_route() {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-lan".to_string(),
        matcher: RouteMatcher::IpCidr(
            RouteIpCidr::new("10.0.0.0".parse().expect("valid IP"), 8).expect("valid CIDR"),
        ),
        action: RouteAction::Block,
    });
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "10.1.2.3",
        &udp_datagram(54321, 443, b"keli"),
    );
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );

    let action =
        process_tun_packet(&packet, &routes, true, &mut dns, 30).expect("process blocked packet");

    let TunPacketProcessAction::Relay(plan) = action else {
        panic!("expected relay plan action");
    };
    assert_eq!(plan.relay_action, TunPacketRelayAction::Drop);
    assert_eq!(plan.route.matched_rule, Some("block-lan".to_string()));
}

#[test]
fn tun_packet_loop_writes_dns_response_to_device() {
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &udp_datagram(54321, 53, &dns_query(0x1234, "example.com", 1)),
    );
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![packet]);

    let events =
        run_tun_packet_loop(&mut device, &routes, true, &mut dns, 30, 1).expect("run TUN loop");

    assert_eq!(events.len(), 1);
    let TunPacketLoopEvent::WrotePacket { response } = &events[0] else {
        panic!("expected write packet event");
    };
    assert_eq!(response.rcode, 0);
    assert_eq!(device.writes.len(), 1);
    assert_eq!(device.writes[0], response.packet);
    assert!(parse_tun_udp_payload(&device.writes[0])
        .expect("parse written response")
        .payload
        .windows(4)
        .any(|window| window == [203, 0, 113, 7]));
}

#[test]
fn tun_packet_loop_writes_tcp_reset_for_blocked_tcp_to_device() {
    let packet = ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    );
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-web".to_string(),
        matcher: RouteMatcher::PortExact(443),
        action: RouteAction::Block,
    });
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![packet]);

    let summary = run_tun_packet_loop_summary(&mut device, &routes, true, &mut dns, 30, 1)
        .expect("run TUN loop");

    assert_eq!(summary.processed_packets(), 1);
    assert_eq!(summary.tcp_resets_written, 1);
    assert_eq!(summary.dropped_packets, 0);
    assert_eq!(device.writes.len(), 1);
    let reset = parse_tun_tcp_segment(&device.writes[0]).expect("parse written TCP reset");
    assert_eq!(reset.flow.source_port, Some(443));
    assert_eq!(reset.flow.destination_port, Some(49152));
    assert_eq!(reset.acknowledgment_number, 11);
    assert!(reset.flags.rst());
    assert!(reset.flags.ack());
}

#[test]
fn tun_packet_loop_with_tcp_session_relay_writes_session_response_packets() {
    let packets = vec![
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 16, 1001, 0x0018, 0x4000, &[], b"late"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 14, 1009, 0x0018, 0x4000, &[], b" /more"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 20, 1009, 0x0011, 0x4000, &[], b""),
        ),
    ];
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(packets);
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::with_server_payloads(vec![b"HTTP/1.1".to_vec()]);

    let summary = run_tun_packet_loop_with_tcp_session_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        7,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
    )
    .expect("run TUN loop with TCP session relay");

    assert_eq!(summary.processed_packets(), 7);
    assert_eq!(summary.tcp_session_events, 7);
    assert_eq!(summary.tcp_session_packets_written, 7);
    assert_eq!(summary.tcp_session_errors, 0);
    assert_eq!(device.writes.len(), 7);
    let syn_ack = parse_tun_tcp_segment(&device.writes[0]).expect("parse SYN-ACK");
    assert_eq!(syn_ack.sequence_number, 1000);
    assert_eq!(syn_ack.acknowledgment_number, 11);
    assert!(syn_ack.flags.syn());
    assert!(syn_ack.flags.ack());
    let out_of_order_ack =
        parse_tun_tcp_segment(&device.writes[1]).expect("parse out-of-order payload ACK packet");
    assert_eq!(out_of_order_ack.sequence_number, 1001);
    assert_eq!(out_of_order_ack.acknowledgment_number, 11);
    assert!(out_of_order_ack.flags.ack());
    assert!(out_of_order_ack.payload.is_empty());
    let client_ack = parse_tun_tcp_segment(&device.writes[2]).expect("parse client payload ACK");
    assert_eq!(client_ack.sequence_number, 1001);
    assert_eq!(client_ack.acknowledgment_number, 16);
    assert!(client_ack.payload.is_empty());
    let server_payload =
        parse_tun_tcp_segment(&device.writes[3]).expect("parse server payload packet");
    assert_eq!(server_payload.sequence_number, 1001);
    assert_eq!(server_payload.acknowledgment_number, 16);
    assert_eq!(server_payload.payload, b"HTTP/1.1");
    let duplicate_ack =
        parse_tun_tcp_segment(&device.writes[4]).expect("parse duplicate payload ACK packet");
    assert_eq!(duplicate_ack.sequence_number, 1009);
    assert_eq!(duplicate_ack.acknowledgment_number, 16);
    assert!(duplicate_ack.flags.ack());
    assert!(duplicate_ack.payload.is_empty());
    let overlapping_ack =
        parse_tun_tcp_segment(&device.writes[5]).expect("parse overlapping payload ACK packet");
    assert_eq!(overlapping_ack.sequence_number, 1009);
    assert_eq!(overlapping_ack.acknowledgment_number, 20);
    assert!(overlapping_ack.flags.ack());
    assert!(overlapping_ack.payload.is_empty());
    let close_ack = parse_tun_tcp_segment(&device.writes[6]).expect("parse close ACK packet");
    assert_eq!(close_ack.sequence_number, 1009);
    assert_eq!(close_ack.acknowledgment_number, 21);
    assert!(close_ack.flags.ack());
    assert!(!close_ack.flags.fin());
    assert!(close_ack.payload.is_empty());
    assert_eq!(relay.established_sessions.len(), 1);
    assert_eq!(
        relay.client_payloads,
        vec![b"GET /".to_vec(), b"more".to_vec()]
    );
    assert_eq!(relay.closed_sessions.len(), 1);
    assert!(sessions.is_empty());
}

#[test]
fn tun_packet_loop_accepts_client_payload_with_stale_server_ack() {
    let packets = vec![
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 16, 1001, 0x0018, 0x4000, &[], b"more"),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 20, 1009, 0x0011, 0x4000, &[], b""),
        ),
    ];
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(packets);
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::with_server_payloads(vec![b"HTTP/1.1".to_vec()]);

    let summary = run_tun_packet_loop_with_tcp_session_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        5,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
    )
    .expect("run TUN loop with stale server ACK TCP session relay");

    assert_eq!(summary.processed_packets(), 5);
    assert_eq!(summary.tcp_session_events, 5);
    assert_eq!(summary.tcp_session_packets_written, 5);
    assert_eq!(summary.tcp_session_errors, 0);
    assert_eq!(device.writes.len(), 5);
    let first_payload_ack =
        parse_tun_tcp_segment(&device.writes[1]).expect("parse first client payload ACK");
    assert_eq!(first_payload_ack.sequence_number, 1001);
    assert_eq!(first_payload_ack.acknowledgment_number, 16);
    let server_payload =
        parse_tun_tcp_segment(&device.writes[2]).expect("parse server payload packet");
    assert_eq!(server_payload.sequence_number, 1001);
    assert_eq!(server_payload.acknowledgment_number, 16);
    assert_eq!(server_payload.payload, b"HTTP/1.1");
    let stale_payload_ack =
        parse_tun_tcp_segment(&device.writes[3]).expect("parse stale server ACK payload ACK");
    assert_eq!(stale_payload_ack.sequence_number, 1009);
    assert_eq!(stale_payload_ack.acknowledgment_number, 20);
    assert!(stale_payload_ack.flags.ack());
    assert!(stale_payload_ack.payload.is_empty());
    let close_ack = parse_tun_tcp_segment(&device.writes[4]).expect("parse close ACK packet");
    assert_eq!(close_ack.sequence_number, 1009);
    assert_eq!(close_ack.acknowledgment_number, 21);
    assert_eq!(
        relay.client_payloads,
        vec![b"GET /".to_vec(), b"more".to_vec()]
    );
    assert_eq!(relay.closed_sessions.len(), 1);
    assert!(sessions.is_empty());
}

#[test]
fn tun_packet_loop_prunes_idle_tcp_sessions_before_next_read() {
    let packets = vec![ipv4_packet(
        6,
        "10.7.0.2",
        "93.184.216.34",
        &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
    )];
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(packets);
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::default();

    let summary = run_tun_packet_loop_with_tcp_session_relay_summary_with_idle_timeout(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        2,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
        Duration::ZERO,
    )
    .expect("run TUN loop with TCP session idle cleanup");

    assert_eq!(summary.processed_packets(), 1);
    assert_eq!(summary.idle_events, 1);
    assert_eq!(summary.tcp_session_events, 1);
    assert_eq!(summary.tcp_session_packets_written, 1);
    assert_eq!(summary.tcp_sessions_pruned, 1);
    assert_eq!(summary.tcp_session_errors, 0);
    assert_eq!(device.writes.len(), 1);
    assert_eq!(relay.closed_sessions.len(), 1);
    assert!(sessions.is_empty());
}

#[test]
fn tun_packet_loop_with_tcp_session_relay_records_relay_error_and_continues_summary() {
    let packets = vec![
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 10, 0, 0x0002, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0010, 0x4000, &[], b""),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            "93.184.216.34",
            &tcp_segment(49152, 443, 11, 1001, 0x0018, 0x4000, &[], b"GET /"),
        ),
    ];
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(packets);
    let mut sessions = TunTcpSessionTable::new();
    let mut relay = FakeTunTcpSessionRelay::with_client_payload_error("relay failed");

    let summary = run_tun_packet_loop_with_tcp_session_relay_summary(
        &mut device,
        &routes,
        true,
        &mut dns,
        30,
        3,
        &mut sessions,
        &mut relay,
        1000,
        0x2000,
    )
    .expect("run TUN loop with TCP session relay error");

    assert_eq!(summary.processed_packets(), 3);
    assert_eq!(summary.tcp_session_events, 2);
    assert_eq!(summary.tcp_session_packets_written, 1);
    assert_eq!(summary.tcp_session_errors, 1);
    assert_eq!(
        summary.last_tcp_session_error,
        Some(keli_net_core::TunTcpSessionError::Relay(
            "relay failed".to_string()
        ))
    );
    assert_eq!(device.writes.len(), 1);
    assert!(relay.client_payloads.is_empty());
}

#[test]
fn tun_packet_loop_reports_relay_and_drop_without_writing() {
    let direct_packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &udp_datagram(54321, 443, b"keli"),
    );
    let blocked_packet = ipv4_packet(
        17,
        "10.7.0.2",
        "10.1.2.3",
        &udp_datagram(54321, 443, b"keli"),
    );
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-lan".to_string(),
        matcher: RouteMatcher::IpCidr(
            RouteIpCidr::new("10.0.0.0".parse().expect("valid IP"), 8).expect("valid CIDR"),
        ),
        action: RouteAction::Block,
    });
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![direct_packet, blocked_packet]);

    let events =
        run_tun_packet_loop(&mut device, &routes, true, &mut dns, 30, 2).expect("run TUN loop");

    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], TunPacketLoopEvent::Relay(_)));
    assert!(matches!(events[1], TunPacketLoopEvent::Drop(_)));
    assert!(device.writes.is_empty());
}

#[test]
fn tun_packet_loop_keeps_processing_after_packet_error() {
    let mut fragmented = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, b"keli"));
    fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    let dns_packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &udp_datagram(54322, 53, &dns_query(0x5678, "example.com", 1)),
    );
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(vec![fragmented, dns_packet]);

    let events =
        run_tun_packet_loop(&mut device, &routes, true, &mut dns, 30, 2).expect("run TUN loop");

    assert!(matches!(
        events[0],
        TunPacketLoopEvent::PacketError(TunPacketError::Ipv4FragmentedPacket { .. })
    ));
    assert!(matches!(events[1], TunPacketLoopEvent::WrotePacket { .. }));
    assert_eq!(device.writes.len(), 1);
}

#[test]
fn tun_packet_loop_summary_counts_event_outcomes() {
    let build_packets = || {
        let mut fragmented =
            ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, b"keli"));
        fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        vec![
            fragmented,
            ipv4_packet(
                17,
                "10.7.0.2",
                "8.8.8.8",
                &udp_datagram(54322, 53, &dns_query(0x5678, "example.com", 1)),
            ),
            ipv4_packet(
                17,
                "10.7.0.2",
                "1.1.1.1",
                &udp_datagram(54323, 443, b"keli"),
            ),
            ipv4_packet(6, "10.7.0.2", "1.1.1.3", &[0xc0, 0x01, 0x01, 0xbb]),
            ipv4_packet(
                17,
                "10.7.0.2",
                "10.1.2.3",
                &udp_datagram(54324, 443, b"keli"),
            ),
            ipv4_packet(1, "10.7.0.2", "1.1.1.2", &[8, 0, 0, 0]),
        ]
    };
    let build_routes = || {
        let mut routes = RouteEngine::new(RouteAction::Direct);
        routes.add_rule(RouteRule {
            name: "block-lan".to_string(),
            matcher: RouteMatcher::IpCidr(
                RouteIpCidr::new("10.0.0.0".parse().expect("valid IP"), 8).expect("valid CIDR"),
            ),
            action: RouteAction::Block,
        });
        routes
    };
    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(build_packets());
    let routes = build_routes();

    let events =
        run_tun_packet_loop(&mut device, &routes, true, &mut dns, 30, 7).expect("run TUN loop");
    let summary = TunPacketLoopSummary::from_events(&events);

    assert_eq!(events.len(), 7);
    assert_eq!(summary.processed_packets(), 6);
    assert_eq!(summary.idle_events, 1);
    assert_eq!(summary.dns_responses_written, 1);
    assert_eq!(summary.relay_packets, 2);
    assert_eq!(summary.tcp_relay_plans, 1);
    assert_eq!(summary.udp_relay_plans, 1);
    assert_eq!(summary.dropped_packets, 1);
    assert_eq!(summary.unsupported_packets, 1);
    assert_eq!(summary.packet_errors, 1);
    assert!(matches!(
        summary.last_packet_error,
        Some(TunPacketError::Ipv4FragmentedPacket { .. })
    ));

    let mut dns = DnsEngine::new(
        StaticResolver::new(vec![IpAddr::V4("203.0.113.7".parse().expect("valid IP"))]),
        DnsCache::new(Duration::from_secs(60)),
    );
    let mut device = FakeTunPacketDevice::new(build_packets());
    let routes = build_routes();

    let summary_from_runner =
        run_tun_packet_loop_summary(&mut device, &routes, true, &mut dns, 30, 7)
            .expect("run TUN summary loop");

    assert_eq!(summary_from_runner, summary);
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

#[test]
fn parses_ipv6_hop_by_hop_extension_header_to_udp_socket_addresses() {
    let mut payload = vec![17, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&udp_datagram(54321, 53, b"keli"));
    let packet = ipv6_packet(0, "fd00::2", "fd00::1", &payload);

    let flow = parse_tun_packet_flow(&packet).expect("parse IPv6 extension header packet");

    assert_eq!(flow.ip_version, TunIpVersion::Ipv6);
    assert_eq!(flow.protocol, TunTransportProtocol::Udp);
    assert_eq!(flow.source_port, Some(54321));
    assert_eq!(flow.destination_port, Some(53));
    assert!(flow.is_dns_hijack_candidate());
}

#[test]
fn parses_chained_ipv6_option_extension_headers_to_tcp_socket_addresses() {
    let mut payload = vec![60, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&[
        0xc0, 0x00, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0x00, 0, 0, 0, 0,
    ]);
    let packet = ipv6_packet(0, "fd00::2", "2606:4700:4700::1111", &payload);

    let flow = parse_tun_packet_flow(&packet).expect("parse chained IPv6 extension headers");

    assert_eq!(flow.ip_version, TunIpVersion::Ipv6);
    assert_eq!(flow.protocol, TunTransportProtocol::Tcp);
    assert_eq!(flow.source_port, Some(49152));
    assert_eq!(flow.destination_port, Some(443));
}

#[test]
fn rejects_truncated_ipv6_extension_header() {
    let packet = ipv6_packet(0, "fd00::2", "fd00::1", &[17]);

    let error = parse_tun_packet_flow(&packet).expect_err("truncated IPv6 extension header");

    assert_eq!(
        error,
        TunPacketError::Ipv6ExtensionHeaderTruncated {
            next_header: 0,
            required_len: 2,
            available_len: 1
        }
    );
}

#[test]
fn rejects_oversized_ipv6_extension_header() {
    let packet = ipv6_packet(60, "fd00::2", "fd00::1", &[17, 1, 0, 0, 0, 0, 0, 0]);

    let error = parse_tun_packet_flow(&packet).expect_err("oversized IPv6 extension header");

    assert_eq!(
        error,
        TunPacketError::Ipv6ExtensionHeaderTruncated {
            next_header: 60,
            required_len: 16,
            available_len: 8
        }
    );
}

#[test]
fn rejects_ipv6_fragment_extension_header_until_reassembly_exists() {
    let packet = ipv6_packet(44, "fd00::2", "fd00::1", &[17, 0, 0, 0, 0, 0, 0, 0]);

    let error = parse_tun_packet_flow(&packet).expect_err("IPv6 fragment header should fail");

    assert_eq!(
        error,
        TunPacketError::Ipv6ExtensionHeaderUnsupported { next_header: 44 }
    );
}

#[test]
fn rejects_ipv4_more_fragments_packet() {
    let mut packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, b"keli"));
    packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

    let error = parse_tun_packet_flow(&packet).expect_err("fragmented packet should fail");

    assert_eq!(
        error,
        TunPacketError::Ipv4FragmentedPacket {
            fragment_offset: 0,
            more_fragments: true
        }
    );
}

#[test]
fn rejects_ipv4_nonzero_fragment_offset_packet() {
    let mut packet = ipv4_packet(17, "10.7.0.2", "8.8.8.8", &udp_datagram(54321, 53, b"keli"));
    packet[6..8].copy_from_slice(&1u16.to_be_bytes());

    let error = parse_tun_packet_flow(&packet).expect_err("fragment offset should fail");

    assert_eq!(
        error,
        TunPacketError::Ipv4FragmentedPacket {
            fragment_offset: 1,
            more_fragments: false
        }
    );
}

#[test]
fn tun_dns_hijack_decision_overrides_default_route() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &[0xd4, 0x31, 0x00, 0x35, 0, 8, 0, 0],
    );

    let decision =
        decide_tun_packet_route(&packet, &routes, true).expect("decide TUN packet route");

    assert_eq!(decision.action, RouteAction::HijackDns);
    assert_eq!(decision.matched_rule, None);
    assert!(decision.dns_hijacked);
    assert!(decision.flow.is_dns_hijack_candidate());
}

#[test]
fn tun_cidr_rule_blocks_matching_destination() {
    let mut routes = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
    routes.add_rule(RouteRule {
        name: "block-lan".to_string(),
        matcher: RouteMatcher::IpCidr(
            RouteIpCidr::new("10.0.0.1".parse().expect("valid IP"), 8).expect("valid CIDR"),
        ),
        action: RouteAction::Block,
    });
    let packet = ipv4_packet(6, "10.7.0.2", "10.9.8.7", &[0xd4, 0x31, 0x01, 0xbb]);

    let decision =
        decide_tun_packet_route(&packet, &routes, false).expect("decide TUN packet route");

    assert_eq!(decision.action, RouteAction::Block);
    assert_eq!(decision.matched_rule, Some("block-lan".to_string()));
    assert!(!decision.dns_hijacked);
}

#[test]
fn tun_port_rule_uses_destination_port() {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "proxy-https".to_string(),
        matcher: RouteMatcher::PortExact(443),
        action: RouteAction::Outbound("proxy".to_string()),
    });
    let packet = ipv6_packet(
        6,
        "fd00::2",
        "2606:4700:4700::1111",
        &[
            0xc0, 0x00, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0x00, 0, 0, 0, 0,
        ],
    );

    let decision =
        decide_tun_packet_route(&packet, &routes, false).expect("decide TUN packet route");

    assert_eq!(decision.action, RouteAction::Outbound("proxy".to_string()));
    assert_eq!(decision.matched_rule, Some("proxy-https".to_string()));
}

#[test]
fn tun_direct_udp_route_builds_direct_udp_relay_plan() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "1.1.1.1",
        &[0xd4, 0x31, 0x01, 0xbb, 0, 8, 0, 0],
    );

    let plan = plan_tun_packet_relay(&packet, &routes, false).expect("plan TUN relay");

    assert_eq!(
        plan.relay_action,
        TunPacketRelayAction::DirectUdp {
            target: OutboundTarget::new("1.1.1.1", 443)
        }
    );
}

#[test]
fn tun_outbound_tcp_route_builds_tagged_tcp_relay_plan() {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "proxy-https".to_string(),
        matcher: RouteMatcher::PortExact(443),
        action: RouteAction::Outbound("proxy".to_string()),
    });
    let packet = ipv4_packet(6, "10.7.0.2", "93.184.216.34", &[0xd4, 0x31, 0x01, 0xbb]);

    let plan = plan_tun_packet_relay(&packet, &routes, false).expect("plan TUN relay");

    assert_eq!(
        plan.relay_action,
        TunPacketRelayAction::OutboundTcp {
            tag: "proxy".to_string(),
            target: OutboundTarget::new("93.184.216.34", 443)
        }
    );
    assert_eq!(plan.route.matched_rule, Some("proxy-https".to_string()));
}

#[test]
fn tun_block_route_builds_drop_plan() {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-lan".to_string(),
        matcher: RouteMatcher::IpCidr(
            RouteIpCidr::new("10.0.0.0".parse().expect("valid IP"), 8).expect("valid CIDR"),
        ),
        action: RouteAction::Block,
    });
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "10.1.2.3",
        &[0xd4, 0x31, 0x01, 0xbb, 0, 8, 0, 0],
    );

    let plan = plan_tun_packet_relay(&packet, &routes, false).expect("plan TUN relay");

    assert_eq!(plan.relay_action, TunPacketRelayAction::Drop);
}

#[test]
fn tun_dns_hijack_route_builds_hijack_plan() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(
        17,
        "10.7.0.2",
        "8.8.8.8",
        &[0xd4, 0x31, 0x00, 0x35, 0, 8, 0, 0],
    );

    let plan = plan_tun_packet_relay(&packet, &routes, true).expect("plan TUN relay");

    assert_eq!(plan.relay_action, TunPacketRelayAction::HijackDns);
    assert!(plan.route.dns_hijacked);
}

#[test]
fn tun_icmp_route_builds_unsupported_transport_plan() {
    let routes = RouteEngine::new(RouteAction::Direct);
    let packet = ipv4_packet(1, "10.7.0.2", "10.7.0.1", &[8, 0, 0, 0]);

    let plan = plan_tun_packet_relay(&packet, &routes, false).expect("plan TUN relay");

    assert_eq!(
        plan.relay_action,
        TunPacketRelayAction::UnsupportedTransport {
            protocol: TunTransportProtocol::Icmp
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

fn udp_datagram(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut datagram = Vec::with_capacity(length);
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&(length as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

fn tcp_segment(
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: u16,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0, "TCP options must be 32-bit aligned");
    let header_len = 20 + options.len();
    let data_offset = (header_len / 4) as u8;
    let mut segment = vec![0; header_len + payload.len()];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgment_number.to_be_bytes());
    segment[12] = (data_offset << 4) | (((flags >> 8) & 0x01) as u8);
    segment[13] = flags as u8;
    segment[14..16].copy_from_slice(&window_size.to_be_bytes());
    segment[20..header_len].copy_from_slice(options);
    segment[header_len..].copy_from_slice(payload);
    segment
}

fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn dns_rcode(payload: &[u8]) -> u8 {
    payload[3] & 0x0f
}

fn spawn_udp_echo_server(
    expected_request: &'static [u8],
    response: &'static [u8],
) -> (u16, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP echo server");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set UDP echo server timeout");
    let port = socket.local_addr().expect("UDP echo server address").port();
    let server = thread::spawn(move || {
        let mut request = [0; 1500];
        let (size, peer) = socket.recv_from(&mut request).expect("read UDP request");
        assert_eq!(&request[..size], expected_request);
        socket.send_to(response, peer).expect("write UDP response");
    });
    (port, server)
}

fn spawn_tcp_response_server(
    expected_request: &'static [u8],
    response: &'static [u8],
) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP response server");
    let port = listener
        .local_addr()
        .expect("TCP response server address")
        .port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TCP request");
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set TCP response server read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("set TCP response server write timeout");
        let mut request = vec![0; expected_request.len()];
        stream
            .read_exact(&mut request)
            .expect("read TCP request payload");
        assert_eq!(request, expected_request);
        stream
            .write_all(response)
            .expect("write TCP response payload");
    });
    (port, server)
}

fn tcp_session_packets(
    destination: &str,
    destination_port: u16,
    server_initial_sequence_number: u32,
    client_payload: &[u8],
    server_payload_len: usize,
) -> Vec<Vec<u8>> {
    let client_initial_sequence_number = 10;
    let client_payload_sequence_number = client_initial_sequence_number + 1;
    let server_acknowledgment_number = server_initial_sequence_number + 1;
    vec![
        ipv4_packet(
            6,
            "10.7.0.2",
            destination,
            &tcp_segment(
                49152,
                destination_port,
                client_initial_sequence_number,
                0,
                0x0002,
                0x4000,
                &[],
                b"",
            ),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            destination,
            &tcp_segment(
                49152,
                destination_port,
                client_payload_sequence_number,
                server_acknowledgment_number,
                0x0010,
                0x4000,
                &[],
                b"",
            ),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            destination,
            &tcp_segment(
                49152,
                destination_port,
                client_payload_sequence_number,
                server_acknowledgment_number,
                0x0018,
                0x4000,
                &[],
                client_payload,
            ),
        ),
        ipv4_packet(
            6,
            "10.7.0.2",
            destination,
            &tcp_segment(
                49152,
                destination_port,
                client_payload_sequence_number + client_payload.len() as u32,
                server_acknowledgment_number + server_payload_len as u32,
                0x0014,
                0x4000,
                &[],
                b"",
            ),
        ),
    ]
}

#[derive(Clone)]
struct StaticResolver {
    ips: Vec<IpAddr>,
}

impl StaticResolver {
    fn new(ips: Vec<IpAddr>) -> Self {
        Self { ips }
    }
}

impl DnsResolver for StaticResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DnsError> {
        Ok(self.ips.clone())
    }
}

struct FakeTunPacketDevice {
    reads: std::collections::VecDeque<Vec<u8>>,
    writes: Vec<Vec<u8>>,
}

impl FakeTunPacketDevice {
    fn new(reads: Vec<Vec<u8>>) -> Self {
        Self {
            reads: reads.into(),
            writes: Vec::new(),
        }
    }
}

impl TunPacketDevice for FakeTunPacketDevice {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.reads.pop_front())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        self.writes.push(packet.to_vec());
        Ok(())
    }
}

#[derive(Default)]
struct FakeTunTcpSessionRelay {
    established_sessions: Vec<TunTcpSessionRecord>,
    client_payloads: Vec<Vec<u8>>,
    server_reads: std::collections::VecDeque<TunTcpServerRead>,
    closed_sessions: Vec<TunTcpSessionRecord>,
    client_payload_error: Option<String>,
}

impl FakeTunTcpSessionRelay {
    fn with_server_payloads(payloads: Vec<Vec<u8>>) -> Self {
        let reads = payloads
            .into_iter()
            .map(TunTcpServerRead::Payload)
            .collect::<Vec<_>>();
        Self::with_server_reads(reads)
    }

    fn with_server_reads(reads: Vec<TunTcpServerRead>) -> Self {
        Self {
            server_reads: reads.into(),
            ..Self::default()
        }
    }

    fn with_client_payload_error(error: &str) -> Self {
        Self {
            client_payload_error: Some(error.to_string()),
            ..Self::default()
        }
    }

    fn pop_server_read(&mut self) -> TunTcpServerRead {
        self.server_reads
            .pop_front()
            .unwrap_or(TunTcpServerRead::NoPayload)
    }
}

impl TunTcpSessionRelay for FakeTunTcpSessionRelay {
    fn establish_session(&mut self, session: &TunTcpSessionRecord) -> Result<(), String> {
        self.established_sessions.push(session.clone());
        Ok(())
    }

    fn write_client_payload(
        &mut self,
        frame: &keli_net_core::TunTcpClientPayloadFrame,
    ) -> Result<(), String> {
        if let Some(error) = &self.client_payload_error {
            return Err(error.clone());
        }
        self.client_payloads.push(frame.payload.clone());
        Ok(())
    }

    fn read_server_payload(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<Option<Vec<u8>>, String> {
        match self.read_server_event(session)? {
            TunTcpServerRead::Payload(payload) => Ok(Some(payload)),
            TunTcpServerRead::NoPayload | TunTcpServerRead::Closed => Ok(None),
        }
    }

    fn read_server_event(
        &mut self,
        _session: &TunTcpSessionRecord,
    ) -> Result<TunTcpServerRead, String> {
        Ok(self.pop_server_read())
    }

    fn poll_server_event(
        &mut self,
        _session: &TunTcpSessionRecord,
    ) -> Result<TunTcpServerRead, String> {
        Ok(self.pop_server_read())
    }

    fn close_session(&mut self, session: &TunTcpSessionRecord) -> Result<(), String> {
        self.closed_sessions.push(session.clone());
        Ok(())
    }
}

struct FakeTunUdpRelay {
    response: Result<UdpRelayResponse, String>,
    calls: Vec<(OutboundTarget, Vec<u8>)>,
    outbound_calls: Vec<(String, OutboundTarget, Vec<u8>)>,
}

impl FakeTunUdpRelay {
    fn ok(source: &str, payload: &[u8]) -> Self {
        Self {
            response: Ok(UdpRelayResponse {
                source: source.parse::<SocketAddr>().expect("valid relay source"),
                payload: payload.to_vec(),
            }),
            calls: Vec::new(),
            outbound_calls: Vec::new(),
        }
    }

    fn err(error: &str) -> Self {
        Self {
            response: Err(error.to_string()),
            calls: Vec::new(),
            outbound_calls: Vec::new(),
        }
    }
}

impl TunUdpRelay for FakeTunUdpRelay {
    fn relay_udp_datagram(
        &mut self,
        target: &OutboundTarget,
        payload: &[u8],
    ) -> Result<UdpRelayResponse, String> {
        self.calls.push((target.clone(), payload.to_vec()));
        self.response.clone()
    }

    fn relay_outbound_udp_datagram(
        &mut self,
        tag: &str,
        target: &OutboundTarget,
        payload: &[u8],
    ) -> Result<UdpRelayResponse, String> {
        self.outbound_calls
            .push((tag.to_string(), target.clone(), payload.to_vec()));
        self.response.clone()
    }
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
