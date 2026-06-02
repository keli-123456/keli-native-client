use std::fmt;
use std::io::Read;

const MAX_HTTP_PROXY_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProxyRequest {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub http_version: String,
    pub rewritten_header: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProxyError {
    Io(String),
    HeaderTooLarge,
    InvalidUtf8,
    MissingRequestLine,
    InvalidRequestLine,
    UnsupportedScheme(String),
    MissingHost,
    EmptyHost,
    InvalidPort(String),
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "HTTP proxy I/O error: {error}"),
            Self::HeaderTooLarge => write!(f, "HTTP proxy header is too large"),
            Self::InvalidUtf8 => write!(f, "HTTP proxy header is not valid UTF-8"),
            Self::MissingRequestLine => write!(f, "HTTP proxy request line is missing"),
            Self::InvalidRequestLine => write!(f, "HTTP proxy request line is invalid"),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "unsupported HTTP proxy URL scheme: {scheme}")
            }
            Self::MissingHost => write!(f, "HTTP proxy request is missing a host"),
            Self::EmptyHost => write!(f, "HTTP proxy target host is empty"),
            Self::InvalidPort(port) => write!(f, "HTTP proxy target port is invalid: {port}"),
        }
    }
}

impl std::error::Error for HttpProxyError {}

pub fn parse_http_proxy_request(
    reader: &mut impl Read,
) -> Result<HttpProxyRequest, HttpProxyError> {
    let header = read_header(reader)?;
    let header_text = std::str::from_utf8(&header).map_err(|_| HttpProxyError::InvalidUtf8)?;
    let request_line = header_text
        .lines()
        .next()
        .ok_or(HttpProxyError::MissingRequestLine)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpProxyError::InvalidRequestLine)?;
    let target = parts.next().ok_or(HttpProxyError::InvalidRequestLine)?;
    let http_version = parts.next().ok_or(HttpProxyError::InvalidRequestLine)?;
    if parts.next().is_some() {
        return Err(HttpProxyError::InvalidRequestLine);
    }

    let (host, port, path_and_query) = if let Some(rest) = target.strip_prefix("http://") {
        parse_absolute_http_target(rest)?
    } else if let Some(rest) = target.split_once("://") {
        return Err(HttpProxyError::UnsupportedScheme(rest.0.to_string()));
    } else {
        let host = find_host_header(header_text).ok_or(HttpProxyError::MissingHost)?;
        let (host, port) = parse_host_port(host, 80)?;
        (host, port, normalize_origin_path(target))
    };

    let rewritten_header = rewrite_header(header_text, method, &path_and_query, http_version);
    Ok(HttpProxyRequest {
        method: method.to_string(),
        host,
        port,
        path_and_query,
        http_version: http_version.to_string(),
        rewritten_header,
    })
}

pub fn http_proxy_bad_request_response() -> &'static [u8] {
    b"HTTP/1.1 400 Bad Request\r\n\r\n"
}

fn read_header(reader: &mut impl Read) -> Result<Vec<u8>, HttpProxyError> {
    let mut header = Vec::new();
    let mut byte = [0; 1];
    while header.len() < MAX_HTTP_PROXY_HEADER_BYTES {
        reader
            .read_exact(&mut byte)
            .map_err(|error| HttpProxyError::Io(error.to_string()))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(HttpProxyError::HeaderTooLarge)
}

fn parse_absolute_http_target(rest: &str) -> Result<(String, u16, String), HttpProxyError> {
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = parse_host_port(authority, 80)?;
    Ok((host, port, normalize_origin_path(path)))
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16), HttpProxyError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(HttpProxyError::EmptyHost);
    }

    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or(HttpProxyError::MissingHost)?;
        let port = rest.strip_prefix(':').unwrap_or("");
        (host, parse_port(port, default_port)?)
    } else if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            (value, default_port)
        } else {
            (host, parse_port(port, default_port)?)
        }
    } else {
        (value, default_port)
    };

    if host.trim().is_empty() {
        return Err(HttpProxyError::EmptyHost);
    }
    Ok((host.to_string(), port))
}

fn parse_port(value: &str, default_port: u16) -> Result<u16, HttpProxyError> {
    if value.is_empty() {
        return Ok(default_port);
    }
    value
        .parse::<u16>()
        .map_err(|_| HttpProxyError::InvalidPort(value.to_string()))
}

fn find_host_header(header_text: &str) -> Option<&str> {
    header_text.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn normalize_origin_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn rewrite_header(
    header_text: &str,
    method: &str,
    path_and_query: &str,
    http_version: &str,
) -> Vec<u8> {
    let mut lines = header_text.split("\r\n");
    let _ = lines.next();
    let mut rewritten = format!("{method} {path_and_query} {http_version}\r\n");
    for line in lines {
        if line.is_empty() {
            rewritten.push_str("\r\n");
            break;
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    rewritten.into_bytes()
}
