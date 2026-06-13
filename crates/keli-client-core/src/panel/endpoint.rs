use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelEndpointCandidate {
    pub base_url: String,
    pub api_prefix: String,
    pub source: String,
}

impl PanelEndpointCandidate {
    pub fn key(&self) -> String {
        format!("{}|{}", self.base_url.to_lowercase(), self.api_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelEndpointConfig {
    pub api_base: String,
    pub api_prefix: String,
    pub backup_api_bases: Vec<String>,
    pub bootstrap_urls: Vec<String>,
    pub panel_host: Option<String>,
    pub source: String,
    pub updated_at: SystemTime,
    pub ttl: Duration,
    pub signature: Option<String>,
}

impl PanelEndpointConfig {
    pub fn from_discovery_json(value: &Value, now: SystemTime) -> Option<Self> {
        let api_base = normalize_base_url(string_value(value, "api_base")?)?;
        let api_prefix =
            normalize_api_prefix(string_value(value, "api_prefix").unwrap_or("/api/v1"));
        let backup_api_bases = string_list(value.get("backup_api_bases"))
            .into_iter()
            .filter_map(|item| normalize_base_url(&item))
            .collect();
        let bootstrap_urls = string_list(value.get("bootstrap_urls"))
            .into_iter()
            .filter(|item| Url::parse(item).is_ok())
            .collect();
        let panel_host = string_value(value, "panel_host")
            .map(str::to_lowercase)
            .filter(|item| !item.is_empty());
        let source = string_value(value, "source")
            .unwrap_or("well-known")
            .to_string();
        let ttl_seconds = value
            .get("ttl")
            .and_then(Value::as_u64)
            .unwrap_or(3600)
            .max(60);
        let signature = string_value(value, "signature")
            .map(str::to_string)
            .filter(|item| !item.is_empty());

        Some(Self {
            api_base,
            api_prefix,
            backup_api_bases,
            bootstrap_urls,
            panel_host,
            source,
            updated_at: now,
            ttl: Duration::from_secs(ttl_seconds),
            signature,
        })
    }

    pub fn primary_candidate(&self) -> PanelEndpointCandidate {
        PanelEndpointCandidate {
            base_url: self.api_base.clone(),
            api_prefix: self.api_prefix.clone(),
            source: self.source.clone(),
        }
    }

    pub fn backup_candidates(&self) -> Vec<PanelEndpointCandidate> {
        self.backup_api_bases
            .iter()
            .map(|base_url| PanelEndpointCandidate {
                base_url: base_url.clone(),
                api_prefix: self.api_prefix.clone(),
                source: format!("{} backup", self.source),
            })
            .collect()
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        match self.updated_at.checked_add(self.ttl) {
            Some(expires_at) => now >= expires_at,
            None => true,
        }
    }
}

pub fn normalize_base_url(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.contains("://") {
        return None;
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&with_scheme).ok()?;
    match parsed.scheme() {
        "http" | "https" => Some(with_scheme),
        _ => None,
    }
}

pub fn normalize_api_prefix(value: &str) -> String {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/api/v1".to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(items)) => items
            .split(|ch: char| ch == ',' || ch.is_whitespace())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}
