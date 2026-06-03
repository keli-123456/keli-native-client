use std::time::SystemTime;

use keli_protocol::parse_subscription_outbound_profiles;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionPhase {
    Idle,
    Resolving,
    Connecting,
    HandshakingTls,
    HandshakingProxy,
    Relaying,
    Recovering,
    Failed(ClientErrorKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientErrorKind {
    CoreNotStarted,
    DnsTimeout,
    TcpConnectTimeout,
    TlsHandshakeFailed,
    WebSocketUpgradeFailed,
    ProxyAuthFailed,
    RelayStalled,
    TunPermissionMissing,
    SystemProxyLoop,
    RouteNoOutbound,
    NoSupportedOutbounds,
    OutboundNotFound(String),
    ConfigInvalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub phase: ConnectionPhase,
    pub target: Option<String>,
    pub note: Option<String>,
    pub at: SystemTime,
}

impl ConnectionEvent {
    pub fn new(phase: ConnectionPhase) -> Self {
        Self {
            phase,
            target: None,
            note: None,
            at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionState {
    phase: ConnectionPhase,
    events: Vec<ConnectionEvent>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            events: vec![ConnectionEvent::new(ConnectionPhase::Idle)],
        }
    }
}

impl SessionState {
    pub fn phase(&self) -> &ConnectionPhase {
        &self.phase
    }

    pub fn events(&self) -> &[ConnectionEvent] {
        &self.events
    }

    pub fn transition(&mut self, phase: ConnectionPhase) {
        self.phase = phase.clone();
        self.events.push(ConnectionEvent::new(phase));
    }

    pub fn fail(&mut self, error: ClientErrorKind) {
        self.transition(ConnectionPhase::Failed(error));
    }

    pub fn prepare_connection_plan(
        &mut self,
        config_text: &str,
        preferred_outbound: Option<&str>,
        listen: impl Into<String>,
    ) -> Result<ConnectionPlan, ClientErrorKind> {
        match build_connection_plan(config_text, preferred_outbound, listen) {
            Ok(plan) => {
                self.events.push(ConnectionEvent {
                    phase: self.phase.clone(),
                    target: Some(plan.selected_outbound.clone()),
                    note: Some("connection plan ready".to_string()),
                    at: SystemTime::now(),
                });
                Ok(plan)
            }
            Err(error) => {
                self.fail(error.clone());
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionPreflightReport {
    supported_tags: Vec<String>,
    skipped: Vec<SkippedProfileSummary>,
    default_outbound: Option<String>,
}

impl SubscriptionPreflightReport {
    pub fn supported_count(&self) -> usize {
        self.supported_tags.len()
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    pub fn is_usable(&self) -> bool {
        !self.supported_tags.is_empty()
    }

    pub fn supported_tags(&self) -> &[String] {
        &self.supported_tags
    }

    pub fn skipped(&self) -> &[SkippedProfileSummary] {
        &self.skipped
    }

    pub fn default_outbound(&self) -> Option<&str> {
        self.default_outbound.as_deref()
    }

    pub fn select_outbound(&self, preferred: Option<&str>) -> Result<String, ClientErrorKind> {
        match preferred {
            Some(tag) if self.supported_tags.iter().any(|supported| supported == tag) => {
                Ok(tag.to_string())
            }
            Some(tag) => Err(ClientErrorKind::OutboundNotFound(tag.to_string())),
            None => self
                .default_outbound
                .clone()
                .ok_or_else(|| ClientErrorKind::NoSupportedOutbounds),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedProfileSummary {
    pub name: String,
    pub reason: String,
}

pub fn preflight_subscription_config(
    config_text: &str,
) -> Result<SubscriptionPreflightReport, ClientErrorKind> {
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| ClientErrorKind::ConfigInvalid(error.to_string()))?;
    let supported_tags: Vec<String> = parsed
        .profiles
        .iter()
        .map(|profile| profile.tag.clone())
        .collect();
    let default_outbound = supported_tags.first().cloned();
    let skipped = parsed
        .skipped
        .into_iter()
        .map(|skipped| SkippedProfileSummary {
            name: skipped.name,
            reason: skipped.reason,
        })
        .collect();
    Ok(SubscriptionPreflightReport {
        supported_tags,
        skipped,
        default_outbound,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPlan {
    selected_outbound: String,
    listen: String,
    preflight: SubscriptionPreflightReport,
}

impl ConnectionPlan {
    pub fn selected_outbound(&self) -> &str {
        &self.selected_outbound
    }

    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn preflight(&self) -> &SubscriptionPreflightReport {
        &self.preflight
    }
}

pub fn build_connection_plan(
    config_text: &str,
    preferred_outbound: Option<&str>,
    listen: impl Into<String>,
) -> Result<ConnectionPlan, ClientErrorKind> {
    let preflight = preflight_subscription_config(config_text)?;
    let selected_outbound = preflight.select_outbound(preferred_outbound)?;
    Ok(ConnectionPlan {
        selected_outbound,
        listen: listen.into(),
        preflight,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_tracks_successful_relay_path() {
        let mut session = SessionState::default();

        session.transition(ConnectionPhase::Resolving);
        session.transition(ConnectionPhase::Connecting);
        session.transition(ConnectionPhase::HandshakingTls);
        session.transition(ConnectionPhase::HandshakingProxy);
        session.transition(ConnectionPhase::Relaying);

        assert_eq!(session.phase(), &ConnectionPhase::Relaying);
        assert_eq!(session.events().len(), 6);
    }

    #[test]
    fn session_keeps_specific_failure_reason() {
        let mut session = SessionState::default();

        session.transition(ConnectionPhase::Resolving);
        session.fail(ClientErrorKind::DnsTimeout);

        assert_eq!(
            session.phase(),
            &ConnectionPhase::Failed(ClientErrorKind::DnsTimeout)
        );
    }

    #[test]
    fn preflight_reports_supported_skipped_default_and_usable_state() {
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: VMESS-OLD
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;

        let report = preflight_subscription_config(config).expect("preflight");

        assert!(report.is_usable());
        assert_eq!(report.supported_count(), 1);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.default_outbound(), Some("SS-READY"));
        assert_eq!(report.supported_tags(), &["SS-READY".to_string()]);
        assert_eq!(report.skipped()[0].name, "VMESS-OLD");
        assert_eq!(report.skipped()[0].reason, "unsupported protocol: vmess");
    }

    #[test]
    fn preflight_selects_default_or_reports_missing_outbound() {
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        let report = preflight_subscription_config(config).expect("preflight");

        assert_eq!(report.select_outbound(None).expect("default"), "SS-READY");
        assert_eq!(
            report
                .select_outbound(Some("SS-READY"))
                .expect("explicit outbound"),
            "SS-READY"
        );
        assert_eq!(
            report
                .select_outbound(Some("MISSING"))
                .expect_err("missing"),
            ClientErrorKind::OutboundNotFound("MISSING".to_string())
        );
    }

    #[test]
    fn preflight_reports_no_supported_outbounds_as_typed_error() {
        let config = r#"
proxies:
  - name: VMESS-OLD
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;
        let report = preflight_subscription_config(config).expect("preflight");

        assert_eq!(
            report.select_outbound(None).expect_err("no outbound"),
            ClientErrorKind::NoSupportedOutbounds
        );
    }

    #[test]
    fn connection_plan_selects_outbound_and_preserves_local_listen() {
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;

        let plan = build_connection_plan(config, Some("SS-READY"), "127.0.0.1:7890")
            .expect("connection plan");

        assert_eq!(plan.selected_outbound(), "SS-READY");
        assert_eq!(plan.listen(), "127.0.0.1:7890");
        assert_eq!(plan.preflight().supported_count(), 1);
    }

    #[test]
    fn connection_plan_rejects_unknown_selected_outbound_before_starting_core() {
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;

        assert_eq!(
            build_connection_plan(config, Some("MISSING"), "127.0.0.1:7890")
                .expect_err("unknown outbound"),
            ClientErrorKind::OutboundNotFound("MISSING".to_string())
        );
    }

    #[test]
    fn session_prepare_connection_plan_records_selected_outbound() {
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        let mut session = SessionState::default();

        let plan = session
            .prepare_connection_plan(config, Some("SS-READY"), "127.0.0.1:7890")
            .expect("prepare plan");

        assert_eq!(plan.selected_outbound(), "SS-READY");
        assert_eq!(session.phase(), &ConnectionPhase::Idle);
        assert_eq!(
            session.events().last().expect("event").target.as_deref(),
            Some("SS-READY")
        );
        assert_eq!(
            session.events().last().expect("event").note.as_deref(),
            Some("connection plan ready")
        );
    }

    #[test]
    fn session_prepare_connection_plan_records_config_failure() {
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        let mut session = SessionState::default();

        let error = session
            .prepare_connection_plan(config, Some("MISSING"), "127.0.0.1:7890")
            .expect_err("prepare should fail");

        assert_eq!(
            error,
            ClientErrorKind::OutboundNotFound("MISSING".to_string())
        );
        assert_eq!(session.phase(), &ConnectionPhase::Failed(error));
    }
}
