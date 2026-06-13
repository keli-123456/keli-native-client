use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::panel::{normalize_api_prefix, normalize_base_url};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelSession {
    pub api_base: String,
    pub api_prefix: String,
    token: String,
    pub email: Option<String>,
}

impl fmt::Debug for PanelSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanelSession")
            .field("api_base", &self.api_base)
            .field("api_prefix", &self.api_prefix)
            .field("token_redacted", &true)
            .field("email", &self.email)
            .finish()
    }
}

impl PanelSession {
    pub fn new(
        api_base: impl AsRef<str>,
        api_prefix: impl AsRef<str>,
        token: impl Into<String>,
        email: Option<String>,
    ) -> Self {
        let api_base = normalize_base_url(api_base.as_ref()).unwrap_or_else(|| {
            api_base
                .as_ref()
                .trim()
                .trim_end_matches('/')
                .to_string()
        });
        Self {
            api_base,
            api_prefix: normalize_api_prefix(api_prefix.as_ref()),
            token: token.into(),
            email,
        }
    }

    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub fn token_is_empty(&self) -> bool {
        self.token.trim().is_empty()
    }
}

pub fn parse_login_session(
    value: &Value,
    api_base: &str,
    api_prefix: &str,
) -> Option<PanelSession> {
    let data = value.get("data").unwrap_or(value);
    let token = string_value(data, "auth_data").or_else(|| string_value(data, "token"))?;
    let email = data
        .get("user")
        .and_then(|user| string_value(user, "email"))
        .or_else(|| string_value(data, "email"));
    Some(PanelSession::new(api_base, api_prefix, token, email))
}

fn string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
}
