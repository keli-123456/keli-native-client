use std::net::IpAddr;
use std::time::Duration;

use keli_net_core::{
    build_dns_error_response, build_dns_response, build_tun_dns_hijack_response,
    build_tun_dns_response_packet, decide_tun_packet_route, parse_tun_packet_flow,
    parse_tun_udp_payload, plan_tun_dns_hijack, plan_tun_packet_relay, process_tun_packet,
    run_tun_packet_loop, DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy, DnsQuestionType,
    DnsResolver, OutboundTarget, RouteAction, RouteDestination, RouteEngine, RouteIpCidr,
    RouteMatcher, RouteRule, RouteTarget, TunIpVersion, TunPacketDevice, TunPacketError,
    TunPacketLoopEvent, TunPacketProcessAction, TunPacketRelayAction, TunPacketRelayPlan,
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
fn rejects_ipv6_hop_by_hop_extension_header() {
    let packet = ipv6_packet(0, "fd00::2", "fd00::1", &[17, 0, 0, 0, 0, 0, 0, 0]);

    let error = parse_tun_packet_flow(&packet).expect_err("IPv6 extension header should fail");

    assert_eq!(
        error,
        TunPacketError::Ipv6ExtensionHeaderUnsupported { next_header: 0 }
    );
}

#[test]
fn rejects_ipv6_destination_options_extension_header() {
    let packet = ipv6_packet(60, "fd00::2", "fd00::1", &[17, 0, 0, 0, 0, 0, 0, 0]);

    let error = parse_tun_packet_flow(&packet).expect_err("IPv6 extension header should fail");

    assert_eq!(
        error,
        TunPacketError::Ipv6ExtensionHeaderUnsupported { next_header: 60 }
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
