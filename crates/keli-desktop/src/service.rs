use keli_client_core::{
    preflight_subscription_config, ClientErrorKind, ClientRuntime, RuntimeConfig,
};
use serde::{Deserialize, Serialize};

use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::DesktopSubscriptionSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopRuntimeCommand {
    ImportSubscription,
    SelectNode,
    Start,
    Reload,
    Stop,
}

#[derive(Debug)]
pub struct DesktopRuntimeService {
    runtime: ClientRuntime,
    subscription_config: Option<String>,
    selected_outbound: Option<String>,
    traffic_mode: DesktopTrafficMode,
    listen: String,
}

impl Default for DesktopRuntimeService {
    fn default() -> Self {
        Self {
            runtime: ClientRuntime::default(),
            subscription_config: None,
            selected_outbound: None,
            traffic_mode: DesktopTrafficMode::SystemProxy,
            listen: "127.0.0.1:7890".to_string(),
        }
    }
}

impl DesktopRuntimeService {
    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, ClientErrorKind> {
        let config_text = config_text.into();
        let report = preflight_subscription_config(&config_text)?;
        let selected = report.default_outbound().map(str::to_string);
        self.subscription_config = Some(config_text);
        self.selected_outbound = selected.clone();
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            selected.as_deref(),
            selected.as_deref(),
        ))
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, ClientErrorKind> {
        let outbound_tag = outbound_tag.into();
        let config_text = self
            .subscription_config
            .as_deref()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        let report = preflight_subscription_config(config_text)?;
        report.select_outbound(Some(&outbound_tag))?;
        self.selected_outbound = Some(outbound_tag.clone());
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            Some(&outbound_tag),
            Some(&outbound_tag),
        ))
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.traffic_mode = traffic_mode;
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, ClientErrorKind> {
        let config_text = self
            .subscription_config
            .clone()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        self.runtime.start(RuntimeConfig::new(
            config_text,
            self.selected_outbound.clone(),
            self.listen.clone(),
        ))?;
        Ok(self.status())
    }

    pub fn stop(&mut self) -> DesktopStatusSnapshot {
        self.runtime.stop();
        self.status()
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot::from_client_runtime(&self.runtime, self.traffic_mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::DesktopRunState;

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
    fn import_subscription_exposes_desktop_summary() {
        let mut service = DesktopRuntimeService::default();

        let summary = service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        assert!(summary.usable);
        assert_eq!(summary.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(summary.nodes[0].tag, "SS-READY");
        assert!(summary.nodes[0].selected);
    }

    #[test]
    fn select_node_rejects_missing_outbound_without_changing_runtime() {
        let mut service = DesktopRuntimeService::default();
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        let error = service.select_node("MISSING").expect_err("missing node");

        assert_eq!(
            error,
            ClientErrorKind::OutboundNotFound("MISSING".to_string())
        );
        assert_eq!(service.status().run_state, DesktopRunState::Stopped);
    }

    #[test]
    fn start_and_stop_use_selected_subscription_node() {
        let mut service = DesktopRuntimeService::default();
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::Tun);

        let running = service.start().expect("start service");

        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(running.selected_outbound.as_deref(), Some("SS-READY"));

        let stopped = service.stop();

        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::Tun);
    }
}
