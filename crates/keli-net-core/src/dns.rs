use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsLocalResolutionPolicy {
    AllowSystem,
    PreventPublicLeak,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    ResolveFailed {
        host: String,
        detail: String,
    },
    NoRecords(String),
    LocalResolutionBlocked {
        host: String,
        policy: DnsLocalResolutionPolicy,
    },
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolveFailed { host, detail } => write!(f, "failed to resolve {host}: {detail}"),
            Self::NoRecords(host) => write!(f, "DNS returned no records for {host}"),
            Self::LocalResolutionBlocked { host, policy } => {
                write!(f, "local DNS resolution for {host} blocked by {policy:?}")
            }
        }
    }
}

impl std::error::Error for DnsError {}

pub trait DnsResolver: Clone {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        (host, 0)
            .to_socket_addrs()
            .map_err(|error| DnsError::ResolveFailed {
                host: host.to_string(),
                detail: error.to_string(),
            })
            .map(|addresses| {
                let mut ips = Vec::new();
                for address in addresses {
                    let ip = address.ip();
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                ips
            })
    }
}

#[derive(Debug, Clone)]
pub struct DnsCache {
    ttl: Duration,
    entries: HashMap<String, DnsCacheEntry>,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    fn get(&self, host: &str, now: Instant) -> Option<Vec<IpAddr>> {
        self.entries.get(&normalize_host(host)).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.ips.clone())
            } else {
                None
            }
        })
    }

    fn insert(&mut self, host: &str, ips: Vec<IpAddr>, now: Instant) {
        self.entries.insert(
            normalize_host(host),
            DnsCacheEntry {
                ips,
                expires_at: now + self.ttl,
            },
        );
    }

    pub fn insert_for_test(&mut self, host: &str, ips: Vec<IpAddr>, expires_at: Instant) {
        self.entries
            .insert(normalize_host(host), DnsCacheEntry { ips, expires_at });
    }
}

#[derive(Debug, Clone)]
pub struct DnsEngine<R> {
    resolver: R,
    cache: DnsCache,
    policy: DnsLocalResolutionPolicy,
}

impl<R: DnsResolver> DnsEngine<R> {
    pub fn new(resolver: R, cache: DnsCache) -> Self {
        Self::with_policy(resolver, cache, DnsLocalResolutionPolicy::AllowSystem)
    }

    pub fn with_policy(resolver: R, cache: DnsCache, policy: DnsLocalResolutionPolicy) -> Self {
        Self {
            resolver,
            cache,
            policy,
        }
    }

    pub fn resolve(&mut self, host: &str, port: u16) -> Result<Vec<ResolvedAddress>, DnsError> {
        let normalized_host = normalize_host(host);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ResolvedAddress { ip, port }]);
        }
        if self.policy == DnsLocalResolutionPolicy::PreventPublicLeak {
            if normalized_host == "localhost" {
                return Ok(vec![ResolvedAddress {
                    ip: IpAddr::from([127, 0, 0, 1]),
                    port,
                }]);
            }
            return Err(DnsError::LocalResolutionBlocked {
                host: normalized_host,
                policy: self.policy,
            });
        }

        let now = Instant::now();
        let ips = match self.cache.get(&normalized_host, now) {
            Some(ips) => ips,
            None => {
                let ips = self.resolver.resolve(&normalized_host)?;
                if ips.is_empty() {
                    return Err(DnsError::NoRecords(normalized_host));
                }
                self.cache.insert(&normalized_host, ips.clone(), now);
                ips
            }
        };

        Ok(ips
            .into_iter()
            .map(|ip| ResolvedAddress { ip, port })
            .collect())
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}
