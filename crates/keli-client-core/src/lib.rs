use std::time::SystemTime;

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
}
