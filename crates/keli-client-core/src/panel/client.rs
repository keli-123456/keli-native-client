use std::fmt;

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

pub struct PanelApiClient<'a, T: PanelApiTransport + ?Sized> {
    api_base: String,
    transport: &'a T,
}

impl<'a, T: PanelApiTransport + ?Sized> PanelApiClient<'a, T> {
    pub fn new(api_base: &str, transport: &'a T) -> Result<Self, PanelApiError> {
        let api_base = normalize_base_url(api_base).ok_or_else(|| {
            PanelApiError::new("endpoint", format!("invalid panel API base URL: {api_base}"))
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
