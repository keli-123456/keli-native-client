use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::panel::{
    normalize_api_prefix, normalize_base_url, parse_bootstrap_payload,
    parse_legacy_bootstrap_payload, parse_login_session, PanelBootstrapPayload, PanelHttpMethod,
    PanelRequest, PanelSession,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelApiError {
    pub kind: String,
    pub message: String,
}

impl PanelApiError {
    fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
        }
    }

    fn http_status(operation: &str, status: u16) -> Self {
        Self::new(
            "http-status",
            format!("{operation} failed with HTTP status {status}"),
        )
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PanelApiRequest {
    pub method: PanelHttpMethod,
    pub url: String,
    pub body: Option<Value>,
    pub authorization: Option<String>,
}

impl fmt::Debug for PanelApiRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanelApiRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body_present", &self.body.is_some())
            .field("authorization_redacted", &self.authorization.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelApiResponse {
    pub status: u16,
    body: String,
}

impl fmt::Debug for PanelApiResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanelApiResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl PanelApiResponse {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            body: serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string()),
        }
    }

    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    fn json_value(&self, operation: &str) -> Result<Value, PanelApiError> {
        serde_json::from_str(&self.body).map_err(|error| {
            PanelApiError::new(
                "json-parse",
                format!("{operation} response JSON parse failed: {error}"),
            )
        })
    }
}

pub trait PanelApiTransport {
    fn send(&self, request: PanelApiRequest) -> Result<PanelApiResponse, PanelApiError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelHttpTransport {
    timeout: Duration,
    max_bytes: usize,
}

impl Default for PanelHttpTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

impl PanelHttpTransport {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

impl PanelApiTransport for PanelHttpTransport {
    fn send(&self, request: PanelApiRequest) -> Result<PanelApiResponse, PanelApiError> {
        send_blocking_http_request(&request, self.timeout, self.max_bytes)
    }
}

pub struct PanelApiClient<'a, T: PanelApiTransport + ?Sized> {
    api_base: String,
    transport: &'a T,
}

impl<'a, T: PanelApiTransport + ?Sized> PanelApiClient<'a, T> {
    pub fn new(api_base: &str, transport: &'a T) -> Result<Self, PanelApiError> {
        let api_base = normalize_base_url(api_base).ok_or_else(|| {
            PanelApiError::new(
                "endpoint",
                format!("invalid panel API base URL: {api_base}"),
            )
        })?;
        Ok(Self {
            api_base,
            transport,
        })
    }

    pub fn login(&self, email: &str, password: &str) -> Result<PanelSession, PanelApiError> {
        let response = self.send_request(None, PanelRequest::login(email, password))?;
        require_success("login", &response)?;
        let value = response.json_value("login")?;
        parse_login_session(&value, &self.api_base, "/api/v1")
            .filter(|session| !session.token_is_empty())
            .ok_or_else(|| PanelApiError::new("auth", "login response did not include auth data"))
    }

    pub fn bootstrap(
        &self,
        session: &PanelSession,
    ) -> Result<PanelBootstrapPayload, PanelApiError> {
        let response = self.send_request(Some(session), PanelRequest::bootstrap())?;
        if response.is_success() {
            if let Ok(value) = response.json_value("bootstrap") {
                if let Some(payload) = parse_bootstrap_payload(&value) {
                    return Ok(payload);
                }
            }
        }
        self.legacy_bootstrap(session)
    }

    pub fn sing_box_config_for_server(
        &self,
        session: &PanelSession,
        server_id: i64,
        platform: &str,
        core_version: Option<&str>,
    ) -> Result<String, PanelApiError> {
        let response = self.send_request(
            Some(session),
            PanelRequest::sing_box_config_for_server(server_id, platform, core_version),
        )?;
        require_success("config", &response)?;
        Ok(response.body().to_string())
    }

    fn legacy_bootstrap(
        &self,
        session: &PanelSession,
    ) -> Result<PanelBootstrapPayload, PanelApiError> {
        let info = self.send_json_request(session, PanelRequest::user_info(), "user-info")?;
        let subscribe =
            self.send_json_request(session, PanelRequest::user_subscribe(), "user-subscribe")?;
        let servers = self.send_json_request(session, PanelRequest::servers(), "servers")?;
        parse_legacy_bootstrap_payload(&info, &subscribe, &servers)
            .ok_or_else(|| PanelApiError::new("bootstrap", "legacy bootstrap payload is invalid"))
    }

    fn send_json_request(
        &self,
        session: &PanelSession,
        request: PanelRequest,
        operation: &str,
    ) -> Result<Value, PanelApiError> {
        let response = self.send_request(Some(session), request)?;
        require_success(operation, &response)?;
        response.json_value(operation)
    }

    fn send_request(
        &self,
        session: Option<&PanelSession>,
        request: PanelRequest,
    ) -> Result<PanelApiResponse, PanelApiError> {
        let api_base = session
            .filter(|_| request.authenticated)
            .map(|session| session.api_base.as_str())
            .unwrap_or(self.api_base.as_str());
        let api_prefix = session
            .filter(|_| request.authenticated)
            .map(|session| session.api_prefix.as_str())
            .unwrap_or(request.api_prefix.as_str());
        let authorization = session
            .filter(|_| request.authenticated)
            .map(PanelSession::authorization_header);
        let url = build_url(api_base, api_prefix, &request.path, &request.query)?;
        self.transport.send(PanelApiRequest {
            method: request.method,
            url,
            body: request.body,
            authorization,
        })
    }
}

fn require_success(operation: &str, response: &PanelApiResponse) -> Result<(), PanelApiError> {
    if response.is_success() {
        Ok(())
    } else {
        Err(PanelApiError::http_status(operation, response.status))
    }
}

fn build_url(
    api_base: &str,
    api_prefix: &str,
    path: &str,
    query: &[(String, String)],
) -> Result<String, PanelApiError> {
    let mut url = Url::parse(api_base).map_err(|error| {
        PanelApiError::new("endpoint", format!("invalid panel API base URL: {error}"))
    })?;
    let base_path = url.path().trim_matches('/');
    let api_prefix = normalize_api_prefix(api_prefix);
    let api_prefix = api_prefix.trim_matches('/');
    let path = path.trim_matches('/');
    let full_path = [base_path, api_prefix, path]
        .into_iter()
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    url.set_path(&format!("/{full_path}"));
    url.set_query(None);
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

fn send_blocking_http_request(
    request: &PanelApiRequest,
    timeout: Duration,
    max_bytes: usize,
) -> Result<PanelApiResponse, PanelApiError> {
    let url = Url::parse(&request.url)
        .map_err(|error| PanelApiError::new("endpoint", format!("invalid request URL: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| PanelApiError::new("endpoint", "request URL has no host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| PanelApiError::new("endpoint", "request URL has no port"))?;
    let mut tcp = connect_tcp(&host, port, timeout)?;
    tcp.set_read_timeout(Some(timeout)).map_err(|error| {
        PanelApiError::new("network", format!("set read timeout failed: {error}"))
    })?;
    tcp.set_write_timeout(Some(timeout)).map_err(|error| {
        PanelApiError::new("network", format!("set write timeout failed: {error}"))
    })?;

    match url.scheme() {
        "http" => write_and_read_http(&mut tcp, request, &url, max_bytes),
        "https" => {
            let server_name = ServerName::try_from(host.clone()).map_err(|error| {
                PanelApiError::new("tls", format!("invalid TLS server name: {error}"))
            })?;
            let connection =
                ClientConnection::new(tls_client_config()?, server_name).map_err(|error| {
                    PanelApiError::new("tls", format!("TLS connect failed: {error}"))
                })?;
            let mut tls = StreamOwned::new(connection, tcp);
            write_and_read_http(&mut tls, request, &url, max_bytes)
        }
        scheme => Err(PanelApiError::new(
            "endpoint",
            format!("unsupported request URL scheme: {scheme}"),
        )),
    }
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, PanelApiError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| PanelApiError::new("network", format!("resolve failed: {error}")))?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(PanelApiError::new(
        "network",
        format!(
            "connect failed: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no resolved addresses".to_string())
        ),
    ))
}

fn tls_client_config() -> Result<Arc<ClientConfig>, PanelApiError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| PanelApiError::new("tls", format!("TLS versions failed: {error}")))?;
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

fn write_and_read_http<S: Read + Write>(
    stream: &mut S,
    request: &PanelApiRequest,
    url: &Url,
    max_bytes: usize,
) -> Result<PanelApiResponse, PanelApiError> {
    let request_bytes = http_request_bytes(request, url)?;
    stream
        .write_all(&request_bytes)
        .map_err(|error| PanelApiError::new("network", format!("write request failed: {error}")))?;
    stream
        .flush()
        .map_err(|error| PanelApiError::new("network", format!("flush request failed: {error}")))?;
    let response_bytes = read_limited_response(stream, max_bytes)?;
    parse_http_response(&response_bytes)
}

fn http_request_bytes(request: &PanelApiRequest, url: &Url) -> Result<Vec<u8>, PanelApiError> {
    let method = match request.method {
        PanelHttpMethod::Get => "GET",
        PanelHttpMethod::Post => "POST",
    };
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => {
            if url.path().is_empty() {
                "/".to_string()
            } else {
                url.path().to_string()
            }
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| PanelApiError::new("endpoint", "request URL has no host"))?;
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let body = match request.body.as_ref() {
        Some(body) => serde_json::to_string(body).map_err(|error| {
            PanelApiError::new(
                "json-encode",
                format!("request JSON encode failed: {error}"),
            )
        })?,
        None => String::new(),
    };
    let mut headers = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: keli-native-client/{}\r\nAccept: application/json, text/plain, */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Some(authorization) = request.authorization.as_ref() {
        headers.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    if request.body.is_some() {
        headers.push_str("Content-Type: application/json\r\n");
        headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    headers.push_str("\r\n");
    let mut bytes = headers.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    Ok(bytes)
}

fn read_limited_response<S: Read>(
    stream: &mut S,
    max_bytes: usize,
) -> Result<Vec<u8>, PanelApiError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream.read(&mut buffer).map_err(|error| {
            PanelApiError::new("network", format!("read response failed: {error}"))
        })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > max_bytes.saturating_add(64 * 1024) {
            return Err(PanelApiError::new(
                "body-too-large",
                format!("response exceeded {max_bytes} bytes"),
            ));
        }
    }
    Ok(bytes)
}

fn parse_http_response(bytes: &[u8]) -> Result<PanelApiResponse, PanelApiError> {
    let header_end = find_header_end(bytes)
        .ok_or_else(|| PanelApiError::new("http", "response header is incomplete"))?;
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| PanelApiError::new("http", "response status is invalid"))?;
    let mut body = bytes[header_end + 4..].to_vec();
    if header_value(&headers, "transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        body = decode_chunked_body(&body)?;
    } else if let Some(content_length) =
        header_value(&headers, "content-length").and_then(|value| value.parse::<usize>().ok())
    {
        body.truncate(content_length.min(body.len()));
    }
    let body = String::from_utf8(body).map_err(|error| {
        PanelApiError::new("utf8", format!("response body UTF-8 failed: {error}"))
    })?;
    Ok(PanelApiResponse::text(status, body))
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn decode_chunked_body(bytes: &[u8]) -> Result<Vec<u8>, PanelApiError> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = find_crlf(&bytes[cursor..])
            .ok_or_else(|| PanelApiError::new("http", "chunk size is incomplete"))?
            + cursor;
        let size_line = std::str::from_utf8(&bytes[cursor..line_end]).map_err(|error| {
            PanelApiError::new("utf8", format!("chunk size UTF-8 failed: {error}"))
        })?;
        let size_text = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| PanelApiError::new("http", format!("chunk size invalid: {error}")))?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        let chunk_end = cursor.saturating_add(size);
        if chunk_end > bytes.len() {
            return Err(PanelApiError::new("http", "chunk body is incomplete"));
        }
        decoded.extend_from_slice(&bytes[cursor..chunk_end]);
        cursor = chunk_end.saturating_add(2);
        if cursor > bytes.len() {
            return Err(PanelApiError::new("http", "chunk delimiter is incomplete"));
        }
    }
    Ok(decoded)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}
