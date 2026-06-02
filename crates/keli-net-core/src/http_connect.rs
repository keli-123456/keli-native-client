use std::fmt;
use std::io::{self, Read};

const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectRequest {
    pub host: String,
    pub port: u16,
    pub http_version: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HttpConnectError {
    Io(String),
    HeaderTooLarge,
    InvalidUtf8,
    MissingRequestLine,
    InvalidRequestLine,
    UnsupportedMethod(String),
    MissingTargetPort,
    InvalidPort(String),
    EmptyHost,
}

impl fmt::Display for HttpConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "HTTP CONNECT I/O error: {error}"),
            Self::HeaderTooLarge => write!(f, "HTTP CONNECT header is too large"),
            Self::InvalidUtf8 => write!(f, "HTTP CONNECT header is not valid UTF-8"),
            Self::MissingRequestLine => write!(f, "HTTP CONNECT request line is missing"),
            Self::InvalidRequestLine => write!(f, "HTTP CONNECT request line is invalid"),
            Self::UnsupportedMethod(method) => write!(f, "unsupported HTTP proxy method: {method}"),
            Self::MissingTargetPort => write!(f, "HTTP CONNECT target must include a port"),
            Self::InvalidPort(port) => write!(f, "HTTP CONNECT target port is invalid: {port}"),
            Self::EmptyHost => write!(f, "HTTP CONNECT target host is empty"),
        }
    }
}

impl std::error::Error for HttpConnectError {}

pub fn parse_http_connect_request(
    reader: &mut impl Read,
) -> Result<HttpConnectRequest, HttpConnectError> {
    let header = read_header(reader)?;
    let header = std::str::from_utf8(&header).map_err(|_| HttpConnectError::InvalidUtf8)?;
    let request_line = header
        .lines()
        .next()
        .ok_or(HttpConnectError::MissingRequestLine)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpConnectError::InvalidRequestLine)?;
    let target = parts.next().ok_or(HttpConnectError::InvalidRequestLine)?;
    let http_version = parts.next().ok_or(HttpConnectError::InvalidRequestLine)?;
    if parts.next().is_some() {
        return Err(HttpConnectError::InvalidRequestLine);
    }
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(HttpConnectError::UnsupportedMethod(method.to_string()));
    }

    let (host, port) = parse_target(target)?;
    Ok(HttpConnectRequest {
        host,
        port,
        http_version: http_version.to_string(),
    })
}

pub fn http_connect_success_response() -> &'static [u8] {
    b"HTTP/1.1 200 Connection Established\r\n\r\n"
}

pub fn http_connect_bad_request_response() -> &'static [u8] {
    b"HTTP/1.1 400 Bad Request\r\n\r\n"
}

fn read_header(reader: &mut impl Read) -> Result<Vec<u8>, HttpConnectError> {
    let mut header = Vec::new();
    let mut byte = [0; 1];
    while header.len() < MAX_CONNECT_HEADER_BYTES {
        match reader.read_exact(&mut byte) {
            Ok(()) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    return Ok(header);
                }
            }
            Err(error) => return Err(HttpConnectError::Io(error.to_string())),
        }
    }
    Err(HttpConnectError::HeaderTooLarge)
}

fn parse_target(target: &str) -> Result<(String, u16), HttpConnectError> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or(HttpConnectError::MissingTargetPort)?;
        let port = rest
            .strip_prefix(':')
            .ok_or(HttpConnectError::MissingTargetPort)?;
        (host, port)
    } else {
        target
            .rsplit_once(':')
            .ok_or(HttpConnectError::MissingTargetPort)?
    };

    if host.trim().is_empty() {
        return Err(HttpConnectError::EmptyHost);
    }

    let port = port
        .parse::<u16>()
        .map_err(|_| HttpConnectError::InvalidPort(port.to_string()))?;
    Ok((host.to_string(), port))
}

impl From<io::Error> for HttpConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
