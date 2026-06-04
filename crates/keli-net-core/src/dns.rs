use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQuestionType {
    A,
    Aaaa,
    Unsupported(u16),
}

impl DnsQuestionType {
    fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            28 => Self::Aaaa,
            other => Self::Unsupported(other),
        }
    }

    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Unsupported(code) => code,
        }
    }

    pub fn matches_ip(self, ip: IpAddr) -> bool {
        match self {
            Self::A => ip.is_ipv4(),
            Self::Aaaa => ip.is_ipv6(),
            Self::Unsupported(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsWireQuestion {
    pub id: u16,
    pub name: String,
    pub question_type: DnsQuestionType,
    raw_question: Vec<u8>,
    recursion_desired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsWireError {
    PacketTooShort,
    ResponsePacket,
    UnsupportedOpcode(u16),
    QuestionCount(u16),
    LabelOutOfBounds,
    CompressedQuestionName,
    InvalidLabel,
    QuestionTooShort,
    UnsupportedClass(u16),
}

impl fmt::Display for DnsWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "DNS packet is too short"),
            Self::ResponsePacket => write!(f, "DNS packet is already a response"),
            Self::UnsupportedOpcode(opcode) => write!(f, "unsupported DNS opcode: {opcode}"),
            Self::QuestionCount(count) => write!(f, "unsupported DNS question count: {count}"),
            Self::LabelOutOfBounds => write!(f, "DNS question label is out of bounds"),
            Self::CompressedQuestionName => {
                write!(f, "compressed DNS question names are unsupported")
            }
            Self::InvalidLabel => write!(f, "DNS question label is invalid"),
            Self::QuestionTooShort => write!(f, "DNS question is too short"),
            Self::UnsupportedClass(class) => write!(f, "unsupported DNS question class: {class}"),
        }
    }
}

impl std::error::Error for DnsWireError {}

pub fn parse_dns_query(packet: &[u8]) -> Result<DnsWireQuestion, DnsWireError> {
    if packet.len() < 12 {
        return Err(DnsWireError::PacketTooShort);
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return Err(DnsWireError::ResponsePacket);
    }
    let opcode = (flags >> 11) & 0x0f;
    if opcode != 0 {
        return Err(DnsWireError::UnsupportedOpcode(opcode));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
        return Err(DnsWireError::QuestionCount(qdcount));
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let Some(&label_len) = packet.get(offset) else {
            return Err(DnsWireError::LabelOutOfBounds);
        };
        offset += 1;
        if label_len == 0 {
            break;
        }
        if label_len & 0xc0 != 0 {
            return Err(DnsWireError::CompressedQuestionName);
        }
        let label_len = label_len as usize;
        let label_end = offset + label_len;
        let Some(label) = packet.get(offset..label_end) else {
            return Err(DnsWireError::LabelOutOfBounds);
        };
        labels.push(
            str::from_utf8(label)
                .map_err(|_| DnsWireError::InvalidLabel)?
                .to_ascii_lowercase(),
        );
        offset = label_end;
    }

    let question_end = offset + 4;
    let Some(question_tail) = packet.get(offset..question_end) else {
        return Err(DnsWireError::QuestionTooShort);
    };
    let qtype = u16::from_be_bytes([question_tail[0], question_tail[1]]);
    let qclass = u16::from_be_bytes([question_tail[2], question_tail[3]]);
    if qclass != 1 {
        return Err(DnsWireError::UnsupportedClass(qclass));
    }

    Ok(DnsWireQuestion {
        id,
        name: labels.join("."),
        question_type: DnsQuestionType::from_code(qtype),
        raw_question: packet[12..question_end].to_vec(),
        recursion_desired: flags & 0x0100 != 0,
    })
}

pub fn build_dns_response(question: &DnsWireQuestion, ips: &[IpAddr], ttl_seconds: u32) -> Vec<u8> {
    let answers: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| question.question_type.matches_ip(*ip))
        .collect();
    let mut response = dns_response_header(question, 0, answers.len() as u16);
    response.extend_from_slice(&question.raw_question);
    for ip in answers {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&question.question_type.code().to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        match ip {
            IpAddr::V4(ip) => {
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&ip.octets());
            }
        }
    }
    response
}

pub fn build_dns_error_response(question: &DnsWireQuestion, rcode: u8) -> Vec<u8> {
    let mut response = dns_response_header(question, rcode & 0x0f, 0);
    response.extend_from_slice(&question.raw_question);
    response
}

fn dns_response_header(question: &DnsWireQuestion, rcode: u8, answer_count: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(12 + question.raw_question.len());
    response.extend_from_slice(&question.id.to_be_bytes());
    let mut flags = 0x8000 | 0x0080 | u16::from(rcode & 0x0f);
    if question.recursion_desired {
        flags |= 0x0100;
    }
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

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
