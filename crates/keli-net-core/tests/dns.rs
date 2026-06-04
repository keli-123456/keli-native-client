use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keli_net_core::{
    build_dns_error_response, build_dns_response, parse_dns_query, DnsAddressFamilyPolicy,
    DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy, DnsQuestionType, DnsResolver,
};

#[test]
fn ip_literal_resolves_without_calling_upstream() {
    let resolver = CountingResolver::new(vec![]);
    let mut engine = DnsEngine::new(resolver.clone(), DnsCache::new(Duration::from_secs(60)));

    let result = engine.resolve("127.0.0.1", 443).expect("IP literal");

    assert_eq!(result[0].ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(result[0].port, 443);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn domain_resolution_is_cached_until_ttl_expires() {
    let resolver = CountingResolver::new(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]);
    let mut engine = DnsEngine::new(resolver.clone(), DnsCache::new(Duration::from_secs(60)));

    let first = engine.resolve("example.com", 443).expect("first resolve");
    let second = engine.resolve("example.com", 443).expect("second resolve");

    assert_eq!(first, second);
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn expired_cache_entry_is_resolved_again() {
    let resolver = CountingResolver::new(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))]);
    let mut cache = DnsCache::new(Duration::from_millis(1));
    cache.insert_for_test(
        "example.com",
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))],
        Instant::now() - Duration::from_secs(1),
    );
    let mut engine = DnsEngine::new(resolver.clone(), cache);

    let result = engine
        .resolve("example.com", 443)
        .expect("resolve after expiry");

    assert_eq!(result[0].ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)));
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn empty_upstream_result_is_an_error() {
    let resolver = CountingResolver::new(vec![]);
    let mut engine = DnsEngine::new(resolver, DnsCache::new(Duration::from_secs(60)));

    let error = engine
        .resolve("example.com", 443)
        .expect_err("empty result");

    assert_eq!(error, DnsError::NoRecords("example.com".to_string()));
}

#[test]
fn prevent_public_leak_blocks_system_resolution_for_domains() {
    let resolver = CountingResolver::new(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3))]);
    let mut engine = DnsEngine::with_policy(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::PreventPublicLeak,
    );

    let error = engine
        .resolve("Example.COM.", 443)
        .expect_err("public domain should be blocked");

    assert_eq!(
        error,
        DnsError::LocalResolutionBlocked {
            host: "example.com".to_string(),
            policy: DnsLocalResolutionPolicy::PreventPublicLeak,
        }
    );
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn prevent_public_leak_still_allows_ip_literals() {
    let resolver = CountingResolver::new(vec![]);
    let mut engine = DnsEngine::with_policy(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::PreventPublicLeak,
    );

    let result = engine.resolve("203.0.113.9", 443).expect("IP literal");

    assert_eq!(result[0].ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    assert_eq!(result[0].port, 443);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn prevent_public_leak_resolves_localhost_without_upstream() {
    let resolver = CountingResolver::new(vec![]);
    let mut engine = DnsEngine::with_policy(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::PreventPublicLeak,
    );

    let result = engine.resolve("LOCALHOST.", 8080).expect("localhost");

    assert_eq!(result[0].ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(result[0].port, 8080);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn ipv4_only_policy_filters_upstream_ipv6_records() {
    let resolver = CountingResolver::new(vec![
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
    ]);
    let mut engine = DnsEngine::with_policies(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::AllowSystem,
        DnsAddressFamilyPolicy::Ipv4Only,
    );

    let result = engine.resolve("example.com", 443).expect("resolve IPv4");

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)));
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn ipv6_only_policy_filters_upstream_ipv4_records() {
    let resolver = CountingResolver::new(vec![
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]);
    let mut engine = DnsEngine::with_policies(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::AllowSystem,
        DnsAddressFamilyPolicy::Ipv6Only,
    );

    let result = engine.resolve("example.com", 443).expect("resolve IPv6");

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn address_family_policy_reports_when_all_records_are_filtered() {
    let resolver = CountingResolver::new(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6))]);
    let mut engine = DnsEngine::with_policies(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::AllowSystem,
        DnsAddressFamilyPolicy::Ipv6Only,
    );

    let error = engine
        .resolve("example.com", 443)
        .expect_err("IPv4-only records should be filtered");

    assert_eq!(
        error,
        DnsError::AddressFamilyFiltered {
            host: "example.com".to_string(),
            policy: DnsAddressFamilyPolicy::Ipv6Only,
        }
    );
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn address_family_policy_filters_ip_literals() {
    let resolver = CountingResolver::new(vec![]);
    let mut engine = DnsEngine::with_policies(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::AllowSystem,
        DnsAddressFamilyPolicy::Ipv6Only,
    );

    let error = engine
        .resolve("203.0.113.7", 443)
        .expect_err("IPv4 literal should be filtered");

    assert_eq!(
        error,
        DnsError::AddressFamilyFiltered {
            host: "203.0.113.7".to_string(),
            policy: DnsAddressFamilyPolicy::Ipv6Only,
        }
    );
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn prevent_public_leak_respects_ipv6_only_localhost_policy() {
    let resolver = CountingResolver::new(vec![]);
    let mut engine = DnsEngine::with_policies(
        resolver.clone(),
        DnsCache::new(Duration::from_secs(60)),
        DnsLocalResolutionPolicy::PreventPublicLeak,
        DnsAddressFamilyPolicy::Ipv6Only,
    );

    let result = engine.resolve("localhost", 8080).expect("localhost");

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(result[0].port, 8080);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn parses_dns_a_query_and_builds_ipv4_response() {
    let query = dns_query(0x1234, "example.com", 1);

    let question = parse_dns_query(&query).expect("parse DNS query");

    assert_eq!(question.id, 0x1234);
    assert_eq!(question.name, "example.com");
    assert_eq!(question.question_type, DnsQuestionType::A);

    let response = build_dns_response(
        &question,
        &[
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        60,
    );

    assert_eq!(&response[0..2], &0x1234u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
    assert!(response.windows(4).any(|window| window == [203, 0, 113, 7]));
    assert!(!response
        .windows(16)
        .any(|window| window == Ipv6Addr::LOCALHOST.octets()));
}

#[test]
fn builds_dns_error_response_with_requested_rcode() {
    let query = dns_query(0x9876, "example.com", 28);
    let question = parse_dns_query(&query).expect("parse DNS query");

    let response = build_dns_error_response(&question, 3);

    assert_eq!(&response[0..2], &0x9876u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 3);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
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

#[derive(Clone)]
struct CountingResolver {
    ips: Vec<IpAddr>,
    calls: Arc<Mutex<usize>>,
}

impl CountingResolver {
    fn new(ips: Vec<IpAddr>) -> Self {
        Self {
            ips,
            calls: Arc::new(Mutex::new(0)),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls lock")
    }
}

impl DnsResolver for CountingResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        assert_eq!(host, "example.com");
        *self.calls.lock().expect("calls lock") += 1;
        Ok(self.ips.clone())
    }
}
