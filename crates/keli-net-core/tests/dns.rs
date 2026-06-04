use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keli_net_core::{DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy, DnsResolver};

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
