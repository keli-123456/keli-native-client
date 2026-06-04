use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keli_net_core::{
    DnsAddressFamilyPolicy, DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy, DnsResolver,
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
