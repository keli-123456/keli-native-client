use std::fmt;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Handshake {
    pub methods: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Command {
    Connect,
    Bind,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    pub command: Socks5Command,
    pub address: Socks5Address,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5ReplyCode {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Socks5ReplyCode {
    fn as_byte(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::ConnectionNotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

#[derive(Debug)]
pub enum Socks5Error {
    Io(io::Error),
    UnsupportedVersion(u8),
    UnsupportedCommand(u8),
    UnsupportedAddressType(u8),
    EmptyMethodList,
    EmptyDomain,
    InvalidDomain,
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "SOCKS5 I/O error: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported SOCKS version: {version}")
            }
            Self::UnsupportedCommand(command) => write!(f, "unsupported SOCKS5 command: {command}"),
            Self::UnsupportedAddressType(address_type) => {
                write!(f, "unsupported SOCKS5 address type: {address_type}")
            }
            Self::EmptyMethodList => write!(f, "SOCKS5 handshake has no methods"),
            Self::EmptyDomain => write!(f, "SOCKS5 request has an empty domain"),
            Self::InvalidDomain => write!(f, "SOCKS5 request domain is not valid UTF-8"),
        }
    }
}

impl std::error::Error for Socks5Error {}

impl From<io::Error> for Socks5Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn parse_socks5_handshake(reader: &mut impl Read) -> Result<Socks5Handshake, Socks5Error> {
    let version = read_u8(reader)?;
    if version != 0x05 {
        return Err(Socks5Error::UnsupportedVersion(version));
    }

    let method_count = read_u8(reader)?;
    if method_count == 0 {
        return Err(Socks5Error::EmptyMethodList);
    }

    let mut methods = vec![0; method_count as usize];
    reader.read_exact(&mut methods)?;
    Ok(Socks5Handshake { methods })
}

pub fn parse_socks5_request(reader: &mut impl Read) -> Result<Socks5Request, Socks5Error> {
    let version = read_u8(reader)?;
    if version != 0x05 {
        return Err(Socks5Error::UnsupportedVersion(version));
    }

    let command = match read_u8(reader)? {
        0x01 => Socks5Command::Connect,
        0x02 => Socks5Command::Bind,
        0x03 => Socks5Command::UdpAssociate,
        other => return Err(Socks5Error::UnsupportedCommand(other)),
    };

    let reserved = read_u8(reader)?;
    if reserved != 0x00 {
        return Err(Socks5Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 reserved byte must be zero",
        )));
    }

    let address = match read_u8(reader)? {
        0x01 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes)?;
            Socks5Address::Ipv4(Ipv4Addr::from(bytes))
        }
        0x03 => {
            let length = read_u8(reader)? as usize;
            if length == 0 {
                return Err(Socks5Error::EmptyDomain);
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes)?;
            let domain = String::from_utf8(bytes).map_err(|_| Socks5Error::InvalidDomain)?;
            Socks5Address::Domain(domain)
        }
        0x04 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes)?;
            Socks5Address::Ipv6(Ipv6Addr::from(bytes))
        }
        other => return Err(Socks5Error::UnsupportedAddressType(other)),
    };

    let port = read_u16(reader)?;
    Ok(Socks5Request {
        command,
        address,
        port,
    })
}

pub fn socks5_no_auth_response() -> [u8; 2] {
    [0x05, 0x00]
}

pub fn socks5_reply(code: Socks5ReplyCode) -> [u8; 10] {
    [
        0x05,
        code.as_byte(),
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}

fn read_u8(reader: &mut impl Read) -> Result<u8, Socks5Error> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_u16(reader: &mut impl Read) -> Result<u16, Socks5Error> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}
