use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{error::Error, fmt};

use crate::{RouteDestination, RouteTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunIpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl TunTransportProtocol {
    pub fn from_ip_protocol_number(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    pub fn ip_protocol_number(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmpv6 => 58,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunPacketFlow {
    pub ip_version: TunIpVersion,
    pub protocol: TunTransportProtocol,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

impl TunPacketFlow {
    pub fn route_destination(&self) -> RouteDestination {
        RouteDestination::new(
            RouteTarget::Ip(self.destination_ip),
            self.destination_port.unwrap_or(0),
        )
    }

    pub fn source_socket_addr(&self) -> Option<SocketAddr> {
        self.source_port
            .map(|port| SocketAddr::new(self.source_ip, port))
    }

    pub fn destination_socket_addr(&self) -> Option<SocketAddr> {
        self.destination_port
            .map(|port| SocketAddr::new(self.destination_ip, port))
    }

    pub fn is_dns_hijack_candidate(&self) -> bool {
        self.protocol == TunTransportProtocol::Udp && self.destination_port == Some(53)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketError {
    PacketTooShort,
    UnsupportedIpVersion(u8),
    Ipv4HeaderTooShort {
        header_len: usize,
        packet_len: usize,
    },
    Ipv4TotalLengthTooShort {
        total_length: usize,
        header_len: usize,
    },
    Ipv4PacketTruncated {
        total_length: usize,
        packet_len: usize,
    },
    Ipv6PacketTruncated {
        total_length: usize,
        packet_len: usize,
    },
    TransportHeaderTooShort {
        protocol: TunTransportProtocol,
        required_len: usize,
        available_len: usize,
    },
}

impl fmt::Display for TunPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "TUN packet is too short"),
            Self::UnsupportedIpVersion(version) => {
                write!(f, "unsupported TUN packet IP version: {version}")
            }
            Self::Ipv4HeaderTooShort {
                header_len,
                packet_len,
            } => write!(
                f,
                "IPv4 header length {header_len} exceeds packet length {packet_len}"
            ),
            Self::Ipv4TotalLengthTooShort {
                total_length,
                header_len,
            } => write!(
                f,
                "IPv4 total length {total_length} is smaller than header length {header_len}"
            ),
            Self::Ipv4PacketTruncated {
                total_length,
                packet_len,
            } => write!(
                f,
                "IPv4 packet length {packet_len} is smaller than total length {total_length}"
            ),
            Self::Ipv6PacketTruncated {
                total_length,
                packet_len,
            } => write!(
                f,
                "IPv6 packet length {packet_len} is smaller than total length {total_length}"
            ),
            Self::TransportHeaderTooShort {
                protocol,
                required_len,
                available_len,
            } => write!(
                f,
                "transport header for {:?} is too short: required {required_len}, available {available_len}",
                protocol
            ),
        }
    }
}

impl Error for TunPacketError {}

pub fn parse_tun_packet_flow(packet: &[u8]) -> Result<TunPacketFlow, TunPacketError> {
    let first = *packet.first().ok_or(TunPacketError::PacketTooShort)?;
    match first >> 4 {
        4 => parse_ipv4_packet_flow(packet),
        6 => parse_ipv6_packet_flow(packet),
        version => Err(TunPacketError::UnsupportedIpVersion(version)),
    }
}

fn parse_ipv4_packet_flow(packet: &[u8]) -> Result<TunPacketFlow, TunPacketError> {
    if packet.len() < 20 {
        return Err(TunPacketError::PacketTooShort);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(TunPacketError::Ipv4HeaderTooShort {
            header_len,
            packet_len: packet.len(),
        });
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_len {
        return Err(TunPacketError::Ipv4TotalLengthTooShort {
            total_length,
            header_len,
        });
    }
    if total_length > packet.len() {
        return Err(TunPacketError::Ipv4PacketTruncated {
            total_length,
            packet_len: packet.len(),
        });
    }
    let protocol = TunTransportProtocol::from_ip_protocol_number(packet[9]);
    let source_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let payload = &packet[header_len..total_length];
    let (source_port, destination_port) = parse_transport_ports(protocol, payload)?;

    Ok(TunPacketFlow {
        ip_version: TunIpVersion::Ipv4,
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
    })
}

fn parse_ipv6_packet_flow(packet: &[u8]) -> Result<TunPacketFlow, TunPacketError> {
    if packet.len() < 40 {
        return Err(TunPacketError::PacketTooShort);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_length = 40 + payload_length;
    if total_length > packet.len() {
        return Err(TunPacketError::Ipv6PacketTruncated {
            total_length,
            packet_len: packet.len(),
        });
    }
    let protocol = TunTransportProtocol::from_ip_protocol_number(packet[6]);
    let source_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("IPv6 source slice length"),
    ));
    let destination_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("IPv6 destination slice length"),
    ));
    let payload = &packet[40..total_length];
    let (source_port, destination_port) = parse_transport_ports(protocol, payload)?;

    Ok(TunPacketFlow {
        ip_version: TunIpVersion::Ipv6,
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
    })
}

fn parse_transport_ports(
    protocol: TunTransportProtocol,
    payload: &[u8],
) -> Result<(Option<u16>, Option<u16>), TunPacketError> {
    match protocol {
        TunTransportProtocol::Tcp | TunTransportProtocol::Udp => {
            if payload.len() < 4 {
                return Err(TunPacketError::TransportHeaderTooShort {
                    protocol,
                    required_len: 4,
                    available_len: payload.len(),
                });
            }
            Ok((
                Some(u16::from_be_bytes([payload[0], payload[1]])),
                Some(u16::from_be_bytes([payload[2], payload[3]])),
            ))
        }
        _ => Ok((None, None)),
    }
}
