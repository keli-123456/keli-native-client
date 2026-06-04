use std::fmt;
use std::io;
use std::time::Duration;

use crate::{OutboundTarget, RelayStats, RouteAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionErrorKind {
    DnsResolveFailed,
    TcpConnectTimeout,
    TcpConnectionRefused,
    FirstByteTimeout,
    IdleTimeout,
    RouteBlocked,
    UnsupportedOutbound,
    RelayIo,
    ProtocolError,
}

impl ConnectionErrorKind {
    pub fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut => Self::TcpConnectTimeout,
            io::ErrorKind::ConnectionRefused => Self::TcpConnectionRefused,
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NotFound => Self::DnsResolveFailed,
            io::ErrorKind::Unsupported => Self::UnsupportedOutbound,
            io::ErrorKind::InvalidData => Self::ProtocolError,
            _ => Self::RelayIo,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsResolveFailed => "dns_resolve_failed",
            Self::TcpConnectTimeout => "tcp_connect_timeout",
            Self::TcpConnectionRefused => "tcp_connection_refused",
            Self::FirstByteTimeout => "first_byte_timeout",
            Self::IdleTimeout => "idle_timeout",
            Self::RouteBlocked => "route_blocked",
            Self::UnsupportedOutbound => "unsupported_outbound",
            Self::RelayIo => "relay_io",
            Self::ProtocolError => "protocol_error",
        }
    }
}

impl fmt::Display for ConnectionErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionReport {
    pub inbound: String,
    pub target: OutboundTarget,
    pub route_action: RouteAction,
    pub connect_ms: Option<u128>,
    pub first_byte_ms: Option<u128>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub error_kind: Option<ConnectionErrorKind>,
    pub error_detail: Option<String>,
}

impl ConnectionReport {
    pub fn new(
        inbound: impl Into<String>,
        target: OutboundTarget,
        route_action: RouteAction,
    ) -> Self {
        Self {
            inbound: inbound.into(),
            target,
            route_action,
            connect_ms: None,
            first_byte_ms: None,
            upload_bytes: 0,
            download_bytes: 0,
            error_kind: None,
            error_detail: None,
        }
    }

    pub fn record_connect_duration(&mut self, duration: Duration) {
        self.connect_ms = Some(duration.as_millis());
    }

    pub fn record_first_byte_duration(&mut self, duration: Duration) {
        self.first_byte_ms = Some(duration.as_millis());
    }

    pub fn record_relay_stats(&mut self, stats: RelayStats) {
        self.upload_bytes = stats.client_to_remote_bytes;
        self.download_bytes = stats.remote_to_client_bytes;
        if let Some(duration) = stats.remote_first_byte_after {
            self.record_first_byte_duration(duration);
        }
    }

    pub fn record_error(&mut self, error_kind: ConnectionErrorKind) {
        self.error_kind = Some(error_kind);
    }

    pub fn record_error_detail(
        &mut self,
        error_kind: ConnectionErrorKind,
        detail: impl Into<String>,
    ) {
        self.record_error(error_kind);
        let detail = detail.into();
        if !detail.trim().is_empty() {
            self.error_detail = Some(detail);
        }
    }

    pub fn summary_line(&self) -> String {
        format!(
            "connection finished inbound={} target={}:{} route={:?} connect_ms={} first_byte_ms={} upload_bytes={} download_bytes={} error_kind={} error_detail={}",
            self.inbound,
            self.target.host,
            self.target.port,
            self.route_action,
            optional_ms(self.connect_ms),
            optional_ms(self.first_byte_ms),
            self.upload_bytes,
            self.download_bytes,
            self.error_kind.map(ConnectionErrorKind::as_str).unwrap_or("none"),
            optional_detail(self.error_detail.as_deref())
        )
    }
}

fn optional_ms(value: Option<u128>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn optional_detail(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "none".to_string();
    };
    let sanitized = value.split_whitespace().collect::<Vec<_>>().join("_");
    if sanitized.is_empty() {
        "none".to_string()
    } else {
        sanitized
    }
}
