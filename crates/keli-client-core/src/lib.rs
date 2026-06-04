use std::time::SystemTime;

use keli_protocol::{
    parse_subscription_outbound_profiles, OutboundProfile, ProxyProtocol, SecurityKind,
    TransportKind,
};

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
    PanelTrafficRestricted {
        account_state: String,
        risk_control: String,
    },
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
    supported: Vec<SubscriptionNodeCapability>,
    skipped: Vec<SkippedProfileSummary>,
    default_outbound: Option<String>,
}

impl SubscriptionPreflightReport {
    pub fn supported_count(&self) -> usize {
        self.supported.len()
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

    pub fn supported(&self) -> &[SubscriptionNodeCapability] {
        &self.supported
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
pub struct SubscriptionNodeCapability {
    pub tag: String,
    pub protocol: String,
    pub transport: String,
    pub security: String,
    pub tls_skip_verify: Option<bool>,
    pub udp_supported: bool,
}

impl SubscriptionNodeCapability {
    fn from_profile(profile: &OutboundProfile) -> Self {
        Self {
            tag: profile.tag.clone(),
            protocol: format!("{:?}", profile.protocol),
            transport: transport_label(&profile.transport).to_string(),
            security: security_label(&profile.security).to_string(),
            tls_skip_verify: tls_skip_verify(&profile.security),
            udp_supported: profile_supports_udp(profile),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedProfileSummary {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelAccountState {
    Unknown,
    Active,
    Limited,
    Expired,
    Disabled,
}

impl PanelAccountState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Active => "active",
            Self::Limited => "limited",
            Self::Expired => "expired",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelRiskControlState {
    Unknown,
    Clear,
    Warning,
    Restricted,
    Blocked,
}

impl PanelRiskControlState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Clear => "clear",
            Self::Warning => "warning",
            Self::Restricted => "restricted",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelUserState {
    pub account_state: PanelAccountState,
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub expires_at: Option<SystemTime>,
}

impl PanelUserState {
    pub fn traffic_used_per_mille(&self) -> Option<u16> {
        let (Some(used), Some(total)) = (self.used_bytes, self.total_bytes) else {
            return None;
        };
        if total == 0 {
            return None;
        }
        let per_mille = (u128::from(used) * 1000) / u128::from(total);
        Some(per_mille.min(u128::from(u16::MAX)) as u16)
    }

    pub fn quota_exhausted(&self) -> bool {
        matches!(
            (self.used_bytes, self.total_bytes),
            (Some(used), Some(total)) if total > 0 && used >= total
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelState {
    pub user: PanelUserState,
    pub risk_control: PanelRiskControlState,
    pub updated_at: SystemTime,
    pub support_note: Option<String>,
}

impl PanelState {
    pub fn new(user: PanelUserState, risk_control: PanelRiskControlState) -> Self {
        Self {
            user,
            risk_control,
            updated_at: SystemTime::now(),
            support_note: None,
        }
    }

    pub fn with_support_note(mut self, support_note: impl Into<String>) -> Self {
        self.support_note = Some(support_note.into());
        self
    }

    pub fn should_restrict_traffic(&self) -> bool {
        matches!(
            self.user.account_state,
            PanelAccountState::Expired | PanelAccountState::Disabled
        ) || self.user.quota_exhausted()
            || matches!(
                self.risk_control,
                PanelRiskControlState::Restricted | PanelRiskControlState::Blocked
            )
    }

    pub fn traffic_restriction_error(&self) -> Option<ClientErrorKind> {
        self.should_restrict_traffic()
            .then(|| ClientErrorKind::PanelTrafficRestricted {
                account_state: self.user.account_state.label().to_string(),
                risk_control: self.risk_control.label().to_string(),
            })
    }
}

pub fn preflight_subscription_config(
    config_text: &str,
) -> Result<SubscriptionPreflightReport, ClientErrorKind> {
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| ClientErrorKind::ConfigInvalid(error.to_string()))?;
    let supported: Vec<SubscriptionNodeCapability> = parsed
        .profiles
        .iter()
        .map(SubscriptionNodeCapability::from_profile)
        .collect();
    let supported_tags: Vec<String> = supported
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
        supported,
        skipped,
        default_outbound,
    })
}

fn profile_supports_udp(profile: &OutboundProfile) -> bool {
    !matches!(profile.protocol, ProxyProtocol::Http | ProxyProtocol::Naive)
}

fn transport_label(transport: &TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "tcp",
        TransportKind::WebSocket { .. } => "ws",
        TransportKind::HttpUpgrade { .. } => "httpupgrade",
        TransportKind::Http2 { .. } => "h2",
        TransportKind::Grpc { .. } => "grpc",
        TransportKind::Quic { .. } => "quic",
    }
}

fn security_label(security: &SecurityKind) -> &'static str {
    match security {
        SecurityKind::None => "none",
        SecurityKind::Tls { .. } => "tls",
    }
}

fn tls_skip_verify(security: &SecurityKind) -> Option<bool> {
    match security {
        SecurityKind::None => None,
        SecurityKind::Tls { skip_verify, .. } => Some(*skip_verify),
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    config_text: String,
    preferred_outbound: Option<String>,
    listen: String,
}

impl RuntimeConfig {
    pub fn new(
        config_text: impl Into<String>,
        preferred_outbound: Option<impl Into<String>>,
        listen: impl Into<String>,
    ) -> Self {
        Self {
            config_text: config_text.into(),
            preferred_outbound: preferred_outbound.map(Into::into),
            listen: listen.into(),
        }
    }

    pub fn config_text(&self) -> &str {
        &self.config_text
    }

    pub fn preferred_outbound(&self) -> Option<&str> {
        self.preferred_outbound.as_deref()
    }

    pub fn listen(&self) -> &str {
        &self.listen
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStatus {
    Stopped,
    Starting,
    Running {
        generation: u64,
        selected_outbound: String,
        listen: String,
    },
    Reloading {
        generation: u64,
    },
    Stopping {
        generation: u64,
    },
    Failed(ClientErrorKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub status: RuntimeStatus,
    pub note: Option<String>,
    pub at: SystemTime,
}

impl RuntimeEvent {
    pub fn new(status: RuntimeStatus, note: Option<impl Into<String>>) -> Self {
        Self {
            status,
            note: note.map(Into::into),
            at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientRuntime {
    status: RuntimeStatus,
    active_plan: Option<ConnectionPlan>,
    active_config: Option<RuntimeConfig>,
    generation: u64,
    events: Vec<RuntimeEvent>,
}

impl Default for ClientRuntime {
    fn default() -> Self {
        Self {
            status: RuntimeStatus::Stopped,
            active_plan: None,
            active_config: None,
            generation: 0,
            events: vec![RuntimeEvent::new(
                RuntimeStatus::Stopped,
                Some("runtime initialized"),
            )],
        }
    }
}

impl ClientRuntime {
    pub fn status(&self) -> &RuntimeStatus {
        &self.status
    }

    pub fn active_plan(&self) -> Option<&ConnectionPlan> {
        self.active_plan.as_ref()
    }

    pub fn active_config(&self) -> Option<&RuntimeConfig> {
        self.active_config.as_ref()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn events(&self) -> &[RuntimeEvent] {
        &self.events
    }

    pub fn start(&mut self, config: RuntimeConfig) -> Result<&ConnectionPlan, ClientErrorKind> {
        self.record(RuntimeStatus::Starting, Some("runtime starting"));
        let plan = match build_connection_plan(
            config.config_text(),
            config.preferred_outbound(),
            config.listen(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.fail(error.clone());
                return Err(error);
            }
        };

        self.generation += 1;
        self.status = RuntimeStatus::Running {
            generation: self.generation,
            selected_outbound: plan.selected_outbound().to_string(),
            listen: plan.listen().to_string(),
        };
        self.active_plan = Some(plan);
        self.active_config = Some(config);
        self.events.push(RuntimeEvent::new(
            self.status.clone(),
            Some("runtime running"),
        ));
        Ok(self.active_plan.as_ref().expect("runtime plan is set"))
    }

    pub fn reload(&mut self, config: RuntimeConfig) -> Result<&ConnectionPlan, ClientErrorKind> {
        let previous_status = self.status.clone();
        let previous_plan = self.active_plan.clone();
        let previous_config = self.active_config.clone();
        self.record(
            RuntimeStatus::Reloading {
                generation: self.generation,
            },
            Some("runtime reloading"),
        );

        match build_connection_plan(
            config.config_text(),
            config.preferred_outbound(),
            config.listen(),
        ) {
            Ok(plan) => {
                self.generation += 1;
                self.status = RuntimeStatus::Running {
                    generation: self.generation,
                    selected_outbound: plan.selected_outbound().to_string(),
                    listen: plan.listen().to_string(),
                };
                self.active_plan = Some(plan);
                self.active_config = Some(config);
                self.events.push(RuntimeEvent::new(
                    self.status.clone(),
                    Some("runtime reload applied"),
                ));
                Ok(self.active_plan.as_ref().expect("runtime plan is set"))
            }
            Err(error) => {
                self.status = previous_status;
                self.active_plan = previous_plan;
                self.active_config = previous_config;
                self.events.push(RuntimeEvent::new(
                    RuntimeStatus::Failed(error.clone()),
                    Some("runtime reload rejected"),
                ));
                Err(error)
            }
        }
    }

    pub fn stop(&mut self) {
        if matches!(self.status, RuntimeStatus::Stopped) {
            return;
        }
        self.record(
            RuntimeStatus::Stopping {
                generation: self.generation,
            },
            Some("runtime stopping"),
        );
        self.active_plan = None;
        self.active_config = None;
        self.status = RuntimeStatus::Stopped;
        self.events.push(RuntimeEvent::new(
            RuntimeStatus::Stopped,
            Some("runtime stopped"),
        ));
    }

    pub fn record_failure(&mut self, error: ClientErrorKind) {
        self.fail(error);
    }

    pub fn record_reload_rejected(&mut self, error: ClientErrorKind) {
        self.events.push(RuntimeEvent::new(
            RuntimeStatus::Failed(error),
            Some("runtime reload rejected"),
        ));
    }

    pub fn record_control_rejected(&mut self, error: ClientErrorKind, note: impl Into<String>) {
        self.events
            .push(RuntimeEvent::new(RuntimeStatus::Failed(error), Some(note)));
    }

    pub fn record_status_note(&mut self, note: impl Into<String>) {
        self.events
            .push(RuntimeEvent::new(self.status.clone(), Some(note.into())));
    }

    fn fail(&mut self, error: ClientErrorKind) {
        self.active_plan = None;
        self.active_config = None;
        self.status = RuntimeStatus::Failed(error.clone());
        self.events.push(RuntimeEvent::new(
            RuntimeStatus::Failed(error),
            Some("runtime failed"),
        ));
    }

    fn record(&mut self, status: RuntimeStatus, note: Option<&str>) {
        self.status = status.clone();
        self.events.push(RuntimeEvent::new(status, note));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ss_config(tag: &str) -> String {
        format!(
            r#"
proxies:
  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
        )
    }

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
    tls: true
    servername: private-sni.example.com
    network: ws
    ws-opts:
      path: /private-vmess-path
      headers:
        Host: private-host.example.com
"#;

        let report = preflight_subscription_config(config).expect("preflight");

        assert!(report.is_usable());
        assert_eq!(report.supported_count(), 2);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.default_outbound(), Some("SS-READY"));
        assert_eq!(
            report.supported_tags(),
            &["SS-READY".to_string(), "VMESS-OLD".to_string()]
        );
        assert_eq!(report.supported()[0].tag, "SS-READY");
        assert_eq!(report.supported()[0].protocol, "Shadowsocks");
        assert_eq!(report.supported()[0].transport, "tcp");
        assert_eq!(report.supported()[0].security, "none");
        assert_eq!(report.supported()[0].tls_skip_verify, None);
        assert!(report.supported()[0].udp_supported);
        assert_eq!(report.supported()[1].tag, "VMESS-OLD");
        assert_eq!(report.supported()[1].protocol, "Vmess");
        assert_eq!(report.supported()[1].transport, "ws");
        assert_eq!(report.supported()[1].security, "tls");
        assert_eq!(report.supported()[1].tls_skip_verify, Some(false));
        assert!(report.supported()[1].udp_supported);
        let debug = format!("{report:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("00112233-4455-6677-8899-aabbccddeeff"));
        assert!(!debug.contains("ss.example.com"));
        assert!(!debug.contains("vmess.example.com"));
        assert!(!debug.contains("private-sni.example.com"));
        assert!(!debug.contains("private-host.example.com"));
        assert!(!debug.contains("/private-vmess-path"));
    }

    #[test]
    fn panel_state_reports_quota_and_risk_restrictions() {
        let active_user = PanelUserState {
            account_state: PanelAccountState::Active,
            used_bytes: Some(250),
            total_bytes: Some(1000),
            expires_at: None,
        };
        assert_eq!(active_user.traffic_used_per_mille(), Some(250));
        assert!(!active_user.quota_exhausted());
        let warning = PanelState::new(active_user.clone(), PanelRiskControlState::Warning);
        assert_eq!(warning.user.account_state.label(), "active");
        assert_eq!(warning.risk_control.label(), "warning");
        assert!(!warning.should_restrict_traffic());

        let quota_limited = PanelState::new(
            PanelUserState {
                account_state: PanelAccountState::Limited,
                used_bytes: Some(1000),
                total_bytes: Some(1000),
                expires_at: None,
            },
            PanelRiskControlState::Clear,
        );
        assert!(quota_limited.user.quota_exhausted());
        assert!(quota_limited.should_restrict_traffic());
        assert_eq!(
            quota_limited.traffic_restriction_error(),
            Some(ClientErrorKind::PanelTrafficRestricted {
                account_state: "limited".to_string(),
                risk_control: "clear".to_string()
            })
        );

        let expired = PanelState::new(
            PanelUserState {
                account_state: PanelAccountState::Expired,
                used_bytes: None,
                total_bytes: None,
                expires_at: Some(SystemTime::UNIX_EPOCH),
            },
            PanelRiskControlState::Clear,
        );
        assert!(expired.should_restrict_traffic());

        let restricted = PanelState::new(active_user, PanelRiskControlState::Restricted)
            .with_support_note("risk-control restricted by panel");
        assert!(restricted.should_restrict_traffic());
        assert_eq!(
            restricted.traffic_restriction_error(),
            Some(ClientErrorKind::PanelTrafficRestricted {
                account_state: "active".to_string(),
                risk_control: "restricted".to_string()
            })
        );
        assert_eq!(
            restricted.support_note.as_deref(),
            Some("risk-control restricted by panel")
        );
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

        assert_eq!(report.select_outbound(None).expect("default"), "VMESS-OLD");
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

    #[test]
    fn runtime_start_builds_plan_and_enters_running_state() {
        let mut runtime = ClientRuntime::default();

        let plan = runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("SS-READY"),
                "127.0.0.1:7890",
            ))
            .expect("runtime start");

        assert_eq!(plan.selected_outbound(), "SS-READY");
        assert_eq!(
            runtime.status(),
            &RuntimeStatus::Running {
                generation: 1,
                selected_outbound: "SS-READY".to_string(),
                listen: "127.0.0.1:7890".to_string(),
            }
        );
        assert_eq!(runtime.generation(), 1);
    }

    #[test]
    fn runtime_start_failure_records_typed_error() {
        let mut runtime = ClientRuntime::default();

        let error = runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("MISSING"),
                "127.0.0.1:7890",
            ))
            .expect_err("runtime should reject unknown outbound");

        assert_eq!(
            error,
            ClientErrorKind::OutboundNotFound("MISSING".to_string())
        );
        assert_eq!(runtime.status(), &RuntimeStatus::Failed(error));
        assert!(runtime.active_plan().is_none());
    }

    #[test]
    fn runtime_reload_applies_new_valid_plan() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-A"),
                Some("SS-A"),
                "127.0.0.1:7890",
            ))
            .expect("runtime start");

        let plan = runtime
            .reload(RuntimeConfig::new(
                ss_config("SS-B"),
                Some("SS-B"),
                "127.0.0.1:7891",
            ))
            .expect("runtime reload");

        assert_eq!(plan.selected_outbound(), "SS-B");
        assert_eq!(runtime.generation(), 2);
        assert_eq!(
            runtime.status(),
            &RuntimeStatus::Running {
                generation: 2,
                selected_outbound: "SS-B".to_string(),
                listen: "127.0.0.1:7891".to_string(),
            }
        );
    }

    #[test]
    fn runtime_reload_rejects_invalid_config_without_dropping_active_plan() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-A"),
                Some("SS-A"),
                "127.0.0.1:7890",
            ))
            .expect("runtime start");

        let error = runtime
            .reload(RuntimeConfig::new(
                ss_config("SS-B"),
                Some("MISSING"),
                "127.0.0.1:7891",
            ))
            .expect_err("runtime reload should reject unknown outbound");

        assert_eq!(
            error,
            ClientErrorKind::OutboundNotFound("MISSING".to_string())
        );
        assert_eq!(runtime.generation(), 1);
        assert_eq!(
            runtime.active_plan().map(ConnectionPlan::selected_outbound),
            Some("SS-A")
        );
        assert_eq!(
            runtime.status(),
            &RuntimeStatus::Running {
                generation: 1,
                selected_outbound: "SS-A".to_string(),
                listen: "127.0.0.1:7890".to_string(),
            }
        );
        assert!(runtime
            .events()
            .iter()
            .any(|event| matches!(event.status, RuntimeStatus::Failed(_))));
    }

    #[test]
    fn runtime_can_record_reload_rejection_without_dropping_active_plan() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("SS-READY"),
                "127.0.0.1:7890",
            ))
            .expect("runtime start");
        let generation = runtime.generation();

        runtime.record_reload_rejected(ClientErrorKind::ConfigInvalid(
            "registry build failed".to_string(),
        ));

        assert_eq!(runtime.generation(), generation);
        assert_eq!(
            runtime.status(),
            &RuntimeStatus::Running {
                generation,
                selected_outbound: "SS-READY".to_string(),
                listen: "127.0.0.1:7890".to_string()
            }
        );
        assert_eq!(
            runtime.active_plan().unwrap().selected_outbound(),
            "SS-READY"
        );
        assert!(runtime
            .events()
            .last()
            .is_some_and(|event| matches!(event.status, RuntimeStatus::Failed(_))));
    }

    #[test]
    fn runtime_can_record_status_note_without_changing_status() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("SS-READY"),
                "127.0.0.1:7890",
            ))
            .expect("runtime start");
        let status = runtime.status().clone();
        let generation = runtime.generation();

        runtime.record_status_note("node health recorded: SS-READY=healthy");

        assert_eq!(runtime.status(), &status);
        assert_eq!(runtime.generation(), generation);
        assert_eq!(
            runtime.events().last().expect("event").note.as_deref(),
            Some("node health recorded: SS-READY=healthy")
        );
        assert_eq!(runtime.events().last().expect("event").status, status);
    }

    #[test]
    fn runtime_stop_clears_active_plan() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("SS-READY"),
                "127.0.0.1:7890",
            ))
            .expect("runtime start");

        runtime.stop();

        assert_eq!(runtime.status(), &RuntimeStatus::Stopped);
        assert!(runtime.active_plan().is_none());
        assert!(runtime.active_config().is_none());
    }
}
