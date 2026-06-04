use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsAddressFamilyPolicy {
    DualStack,
    Ipv4Only,
    Ipv6Only,
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
    AddressFamilyFiltered {
        host: String,
        policy: DnsAddressFamilyPolicy,
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
            Self::AddressFamilyFiltered { host, policy } => {
                write!(f, "DNS records for {host} were filtered by {policy:?}")
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
    address_family_policy: DnsAddressFamilyPolicy,
}

impl<R: DnsResolver> DnsEngine<R> {
    pub fn new(resolver: R, cache: DnsCache) -> Self {
        Self::with_policy(resolver, cache, DnsLocalResolutionPolicy::AllowSystem)
    }

    pub fn with_policy(resolver: R, cache: DnsCache, policy: DnsLocalResolutionPolicy) -> Self {
        Self::with_policies(resolver, cache, policy, DnsAddressFamilyPolicy::DualStack)
    }

    pub fn with_policies(
        resolver: R,
        cache: DnsCache,
        policy: DnsLocalResolutionPolicy,
        address_family_policy: DnsAddressFamilyPolicy,
    ) -> Self {
        Self {
            resolver,
            cache,
            policy,
            address_family_policy,
        }
    }

    pub fn resolve(&mut self, host: &str, port: u16) -> Result<Vec<ResolvedAddress>, DnsError> {
        let normalized_host = normalize_host(host);
        if let Ok(ip) = normalized_host.parse::<IpAddr>() {
            if !address_family_matches(ip, self.address_family_policy) {
                return Err(DnsError::AddressFamilyFiltered {
                    host: normalized_host,
                    policy: self.address_family_policy,
                });
            }
            return Ok(vec![ResolvedAddress { ip, port }]);
        }
        if self.policy == DnsLocalResolutionPolicy::PreventPublicLeak {
            if normalized_host == "localhost" {
                return Ok(localhost_ips(self.address_family_policy)
                    .into_iter()
                    .map(|ip| ResolvedAddress { ip, port })
                    .collect());
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
        let ips: Vec<IpAddr> = ips
            .into_iter()
            .filter(|ip| address_family_matches(*ip, self.address_family_policy))
            .collect();
        if ips.is_empty() {
            return Err(DnsError::AddressFamilyFiltered {
                host: normalized_host,
                policy: self.address_family_policy,
            });
        }

        Ok(ips
            .into_iter()
            .map(|ip| ResolvedAddress { ip, port })
            .collect())
    }
}

fn address_family_matches(ip: IpAddr, policy: DnsAddressFamilyPolicy) -> bool {
    match policy {
        DnsAddressFamilyPolicy::DualStack => true,
        DnsAddressFamilyPolicy::Ipv4Only => ip.is_ipv4(),
        DnsAddressFamilyPolicy::Ipv6Only => ip.is_ipv6(),
    }
}

fn localhost_ips(policy: DnsAddressFamilyPolicy) -> Vec<IpAddr> {
    match policy {
        DnsAddressFamilyPolicy::DualStack => vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        DnsAddressFamilyPolicy::Ipv4Only => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        DnsAddressFamilyPolicy::Ipv6Only => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}
