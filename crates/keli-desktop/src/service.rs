use std::time::Duration;

use keli_cli::write_support_bundle_report;
use keli_client_core::{plan_subscription_update, preflight_subscription_config, ClientErrorKind};
use keli_platform::{
    NativeTunDeviceController, SystemProxyController, TunDeviceConfig, TunPacketIoController,
};
use serde::{Deserialize, Serialize};

use crate::managed::{DesktopManagedCoreService, DesktopManagedStartOptions};
use crate::persistence::DesktopPersistedSubscription;
use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::{
    DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
    DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
    DesktopSubscriptionUrlUpdateSummary,
};
use crate::support::{build_desktop_support_bundle_export, DesktopSupportBundleExport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopRuntimeCommand {
    ImportSubscription,
    SelectNode,
    Start,
    Reload,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopRuntimeError {
    Client(ClientErrorKind),
    Managed(String),
}

impl From<ClientErrorKind> for DesktopRuntimeError {
    fn from(error: ClientErrorKind) -> Self {
        Self::Client(error)
    }
}

impl From<String> for DesktopRuntimeError {
    fn from(error: String) -> Self {
        Self::Managed(error)
    }
}

pub struct DesktopRuntimeService<
    'a,
    C: SystemProxyController + ?Sized,
    T: TunPacketIoController + ?Sized = NativeTunDeviceController,
> {
    core: DesktopManagedCoreService<'a, C>,
    tun_controller: Option<&'a T>,
    subscription_config: Option<String>,
    selected_outbound: Option<String>,
    traffic_mode: DesktopTrafficMode,
    listen: String,
}

impl<'a, C: SystemProxyController + ?Sized>
    DesktopRuntimeService<'a, C, NativeTunDeviceController>
{
    pub fn new(controller: &'a C) -> Self {
        Self {
            core: DesktopManagedCoreService::new(controller),
            tun_controller: None,
            subscription_config: None,
            selected_outbound: None,
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
            listen: "127.0.0.1:7890".to_string(),
        }
    }
}

impl<'a, C, T> DesktopRuntimeService<'a, C, T>
where
    C: SystemProxyController + ?Sized,
    T: TunPacketIoController + ?Sized,
    T::PacketIo: Send + 'static,
{
    pub fn new_with_tun_controller(controller: &'a C, tun_controller: &'a T) -> Self {
        Self {
            core: DesktopManagedCoreService::new(controller),
            tun_controller: Some(tun_controller),
            subscription_config: None,
            selected_outbound: None,
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
            listen: "127.0.0.1:7890".to_string(),
        }
    }

    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopRuntimeError> {
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

    pub fn import_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopRuntimeError> {
        if self.core.is_running() {
            return Err(DesktopRuntimeError::Managed(
                "desktop subscription URL import requires stopped core".to_string(),
            ));
        }
        let fetched =
            DesktopManagedCoreService::<C>::fetch_subscription_url_config(url, timeout, max_bytes);
        let (fetch, config_text) = fetched.into_parts();
        let fetch_summary = DesktopSubscriptionUrlFetchSummary::from_managed(&fetch);
        let Some(config_text) = config_text else {
            return Ok(DesktopSubscriptionUrlImportSummary::fetch_error(
                fetch_summary,
            ));
        };
        let subscription = self.import_subscription_config(config_text)?;
        Ok(DesktopSubscriptionUrlImportSummary {
            fetch: fetch_summary,
            subscription: Some(subscription),
            error: None,
        })
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopRuntimeError> {
        let outbound_tag = outbound_tag.into();
        let config_text = self
            .subscription_config
            .clone()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        let report = preflight_subscription_config(&config_text)?;
        report.select_outbound(Some(&outbound_tag))?;
        if self.core.is_running() {
            self.core
                .reload_from_subscription_config(&config_text, Some(outbound_tag.clone()))?;
        }
        self.selected_outbound = Some(outbound_tag.clone());
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            Some(&outbound_tag),
            Some(&outbound_tag),
        ))
    }

    pub fn update_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionUpdateSummary, DesktopRuntimeError> {
        let config_text = config_text.into();
        if self.core.is_running() {
            let outcome = self
                .core
                .reload_subscription_config_with_update_plan(&config_text)?;
            let planned_selected = outcome.report.planned_selected_outbound.clone();
            let subscription = if let Some(subscription) = outcome.status.subscription.as_ref() {
                DesktopSubscriptionSummary::from_managed(subscription)
            } else {
                let preflight = preflight_subscription_config(&config_text)?;
                DesktopSubscriptionSummary::from_preflight(
                    &preflight,
                    planned_selected.as_deref(),
                    planned_selected.as_deref(),
                )
            };
            if outcome.applied {
                self.subscription_config = Some(config_text);
                self.selected_outbound = outcome.status.selected_outbound.clone();
            }
            return Ok(DesktopSubscriptionUpdateSummary::from_report(
                &outcome.report,
                outcome.applied,
                outcome.error,
                subscription,
            ));
        }

        let preflight = preflight_subscription_config(&config_text)?;
        let report = plan_subscription_update(
            self.subscription_config.as_deref(),
            &config_text,
            self.selected_outbound.as_deref(),
        )?;
        let selected = report.planned_selected_outbound.clone();
        let subscription = DesktopSubscriptionSummary::from_preflight(
            &preflight,
            selected.as_deref(),
            selected.as_deref(),
        );
        self.subscription_config = Some(config_text);
        self.selected_outbound = selected;
        Ok(DesktopSubscriptionUpdateSummary::from_report(
            &report,
            true,
            None,
            subscription,
        ))
    }

    pub fn update_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopRuntimeError> {
        if !self.core.is_running() {
            return Err(DesktopRuntimeError::Managed(
                "desktop subscription URL update requires running core".to_string(),
            ));
        }
        let result = self
            .core
            .reload_subscription_url_with_update_plan_and_config_text(url, timeout, max_bytes)?;
        let (outcome, fetched_config_text, applied_config_text) = result.into_parts();
        let update = match (outcome.update.as_ref(), fetched_config_text.as_deref()) {
            (Some(report), Some(config_text)) => {
                let planned_selected = report.planned_selected_outbound.clone();
                let subscription = if let Some(subscription) = outcome.status.subscription.as_ref()
                {
                    DesktopSubscriptionSummary::from_managed(subscription)
                } else {
                    let preflight = preflight_subscription_config(config_text)?;
                    DesktopSubscriptionSummary::from_preflight(
                        &preflight,
                        planned_selected.as_deref(),
                        planned_selected.as_deref(),
                    )
                };
                Some(DesktopSubscriptionUpdateSummary::from_report(
                    report,
                    outcome.applied,
                    outcome.error.clone(),
                    subscription,
                ))
            }
            _ => None,
        };
        if outcome.applied {
            if let Some(config_text) = applied_config_text {
                self.subscription_config = Some(config_text);
            }
            self.selected_outbound = outcome.status.selected_outbound.clone();
        }
        Ok(DesktopSubscriptionUrlUpdateSummary::from_managed(
            &outcome,
            update,
            self.traffic_mode,
        ))
    }

    pub fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription> {
        self.subscription_config
            .as_ref()
            .map(|config_text| DesktopPersistedSubscription {
                config_text: config_text.clone(),
                selected_outbound: self.selected_outbound.clone(),
            })
    }

    pub fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopRuntimeError> {
        let mut core_bundle_bytes = Vec::new();
        write_support_bundle_report(self.subscription_config.as_deref(), &mut core_bundle_bytes)?;
        let core_support_bundle: serde_json::Value = serde_json::from_slice(&core_bundle_bytes)
            .map_err(|error| {
                DesktopRuntimeError::Managed(format!("support bundle JSON parse failed: {error}"))
            })?;
        let desktop_status = self.status();
        build_desktop_support_bundle_export(
            core_support_bundle,
            &desktop_status,
            self.core.managed_status_json(),
        )
        .map_err(DesktopRuntimeError::Managed)
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.traffic_mode = traffic_mode;
    }

    pub fn set_listen(&mut self, listen: impl Into<String>) {
        self.listen = listen.into();
    }

    pub fn is_running(&self) -> bool {
        self.core.is_running()
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopRuntimeError> {
        let config_text = self
            .subscription_config
            .clone()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        if self.traffic_mode == DesktopTrafficMode::Tun {
            let tun_controller = self.tun_controller.ok_or_else(|| {
                DesktopRuntimeError::Managed(
                    "desktop TUN mode requires a TUN controller".to_string(),
                )
            })?;
            let options = DesktopManagedStartOptions::tun_mode(
                config_text,
                self.selected_outbound.clone(),
                default_desktop_tun_device_config()?,
            )
            .with_listen(self.listen.clone());
            return Ok(self
                .core
                .start_with_tun_controller(options, tun_controller)?);
        }
        let options = if self.traffic_mode == DesktopTrafficMode::SystemProxy {
            DesktopManagedStartOptions::system_proxy_mode(
                config_text,
                self.selected_outbound.clone(),
            )
        } else {
            DesktopManagedStartOptions::mixed_inbound_only(
                config_text,
                self.selected_outbound.clone(),
            )
        }
        .with_listen(self.listen.clone());
        Ok(self.core.start(options)?)
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopRuntimeError> {
        if self.core.is_running() {
            self.core.stop()?;
        }
        Ok(self.status())
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        let mut status = self.core.status();
        status.traffic_mode = self.traffic_mode;
        status
    }
}

fn default_desktop_tun_device_config() -> Result<TunDeviceConfig, DesktopRuntimeError> {
    TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .map_err(|error| DesktopRuntimeError::Managed(format!("build default TUN config: {error}")))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::status::DesktopRunState;
    use keli_platform::{
        SystemProxyConfig, SystemProxyController, SystemProxyError, SystemProxySnapshot,
        TunDeviceConfig, TunDeviceController, TunDeviceError, TunDeviceSnapshot, TunPacketIo,
        TunPacketIoController,
    };

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

    fn ss_config_with_tags(tags: &[&str]) -> String {
        let mut config = String::from("proxies:\n");
        for tag in tags {
            config.push_str(&format!(
                r#"  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
            ));
        }
        config
    }

    fn unusable_config() -> &'static str {
        r#"
proxies:
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#
    }

    fn spawn_subscription_http_server(
        status_code: u16,
        reason: &str,
        body: String,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind subscription HTTP server");
        let port = listener
            .local_addr()
            .expect("subscription server addr")
            .port();
        let url = format!("http://127.0.0.1:{port}/panel/private/sub?token=super-secret-token");
        let reason = reason.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept subscription fetch");
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while stream.read(&mut byte).expect("read subscription request") != 0 {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).expect("subscription request utf8");
            let response = format!(
                "HTTP/1.1 {status_code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write subscription response");
            request.lines().next().unwrap_or_default().to_string()
        });
        (url, handle)
    }

    #[derive(Debug)]
    struct FakeSystemProxyController {
        snapshot: SystemProxySnapshot,
        applied: RefCell<Vec<SystemProxyConfig>>,
        restored: RefCell<Vec<SystemProxySnapshot>>,
    }

    impl FakeSystemProxyController {
        fn new() -> Self {
            Self {
                snapshot: SystemProxySnapshot::default(),
                applied: RefCell::new(Vec::new()),
                restored: RefCell::new(Vec::new()),
            }
        }
    }

    impl SystemProxyController for FakeSystemProxyController {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            Ok(self.snapshot.clone())
        }

        fn apply(
            &self,
            config: &SystemProxyConfig,
        ) -> Result<SystemProxySnapshot, SystemProxyError> {
            self.applied.borrow_mut().push(config.clone());
            Ok(self.snapshot.clone())
        }

        fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            self.restored.borrow_mut().push(snapshot.clone());
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeTunDeviceController {
        starts: RefCell<Vec<TunDeviceConfig>>,
        opens: RefCell<Vec<TunDeviceConfig>>,
        stops: RefCell<usize>,
        running: RefCell<Option<TunDeviceConfig>>,
    }

    #[derive(Debug, Default)]
    struct FakeTunPacketIo;

    impl FakeTunDeviceController {
        fn stopped_snapshot() -> TunDeviceSnapshot {
            TunDeviceSnapshot {
                supported: true,
                lifecycle_available: true,
                packet_io_available: true,
                running: false,
                interface_name: None,
                address_cidr: None,
                mtu: None,
                dns_hijack: None,
            }
        }
    }

    impl TunDeviceController for FakeTunDeviceController {
        fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
            Ok(self
                .running
                .borrow()
                .as_ref()
                .map(TunDeviceSnapshot::running)
                .unwrap_or_else(Self::stopped_snapshot))
        }

        fn start(&self, config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
            self.starts.borrow_mut().push(config.clone());
            self.running.borrow_mut().replace(config.clone());
            Ok(TunDeviceSnapshot::running(config))
        }

        fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
            *self.stops.borrow_mut() += 1;
            self.running.borrow_mut().take();
            Ok(Self::stopped_snapshot())
        }
    }

    impl TunPacketIo for FakeTunPacketIo {
        fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError> {
            Ok(None)
        }

        fn write_packet(&mut self, _packet: &[u8]) -> Result<(), TunDeviceError> {
            Ok(())
        }
    }

    impl TunPacketIoController for FakeTunDeviceController {
        type PacketIo = FakeTunPacketIo;

        fn open_packet_io(
            &self,
            config: &TunDeviceConfig,
        ) -> Result<Self::PacketIo, TunDeviceError> {
            self.opens.borrow_mut().push(config.clone());
            Ok(FakeTunPacketIo)
        }
    }

    #[test]
    fn import_subscription_exposes_desktop_summary() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);

        let summary = service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        assert!(summary.usable);
        assert_eq!(summary.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(summary.nodes[0].tag, "SS-READY");
        assert!(summary.nodes[0].selected);
    }

    #[test]
    fn import_subscription_url_fetches_config_and_redacts_source() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        let (url, request_thread) =
            spawn_subscription_http_server(200, "OK", ss_config("SS-READY"));

        let imported = service
            .import_subscription_url(&url, Duration::from_secs(2), 4096)
            .expect("import subscription URL");
        let request_line = request_thread.join().expect("subscription request");

        assert_eq!(
            request_line,
            "GET /panel/private/sub?token=super-secret-token HTTP/1.1"
        );
        assert!(imported.fetch.ok);
        assert_eq!(imported.fetch.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(imported.fetch.path_present, Some(true));
        assert_eq!(imported.fetch.query_present, Some(true));
        assert_eq!(
            imported
                .subscription
                .as_ref()
                .and_then(|summary| summary.selected_outbound.as_deref()),
            Some("SS-READY")
        );
        assert!(!format!("{imported:?}").contains("super-secret-token"));
    }

    #[test]
    fn support_bundle_export_embeds_runtime_status_and_redacts_profile() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        service
            .import_subscription_config(config)
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let export = service
            .export_support_bundle()
            .expect("export support bundle");
        let bundle: serde_json::Value =
            serde_json::from_slice(&export.bytes).expect("support bundle JSON");
        let serialized = String::from_utf8(export.bytes.clone()).expect("support bundle UTF-8");

        assert_eq!(export.format, "json");
        assert_eq!(export.byte_count, export.bytes.len());
        assert_eq!(bundle["kind"], "keli_desktop_support_bundle");
        assert_eq!(bundle["desktop_status"]["run_state"], "running");
        assert_eq!(bundle["desktop_status"]["selected_outbound"], "SS-READY");
        assert_eq!(
            bundle["managed_runtime_status"]["selected_outbound"],
            "SS-READY"
        );
        assert_eq!(bundle["core_support_bundle"]["kind"], "keli_support_bundle");
        assert_eq!(bundle["core_support_bundle"]["profile"]["status"], "ok");
        assert_eq!(
            bundle["core_support_bundle"]["redaction"]["profile_config_text"],
            "omitted"
        );
        assert!(!serialized.contains("password: secret"));
        assert!(!serialized.contains("ss.example.com"));

        service.stop().expect("stop service");
    }

    #[test]
    fn select_node_rejects_missing_outbound_without_changing_runtime() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        let error = service.select_node("MISSING").expect_err("missing node");

        assert_eq!(
            error,
            DesktopRuntimeError::Client(ClientErrorKind::OutboundNotFound("MISSING".to_string()))
        );
        assert_eq!(service.status().run_state, DesktopRunState::Stopped);
    }

    #[test]
    fn start_and_stop_use_real_managed_core() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");

        let running = service.start().expect("start service");

        assert!(service.is_running());
        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
        assert_eq!(running.selected_outbound.as_deref(), Some("SS-READY"));

        let stopped = service.stop().expect("stop service");

        assert!(!service.is_running());
        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
    }

    #[test]
    fn running_node_selection_reloads_real_managed_core() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-READY", "SS-NEXT"]))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let summary = service.select_node("SS-NEXT").expect("select node");

        assert_eq!(summary.selected_outbound.as_deref(), Some("SS-NEXT"));
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-NEXT")
        );
        assert_eq!(service.status().run_state, DesktopRunState::Running);

        service.stop().expect("stop service");
    }

    #[test]
    fn running_subscription_update_preserves_selected_outbound() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-OLD", "SS-STAY"]))
            .expect("import subscription");
        service.select_node("SS-STAY").expect("select node");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let update = service
            .update_subscription_config(ss_config_with_tags(&["SS-STAY", "SS-NEW"]))
            .expect("update subscription");

        assert!(update.applied);
        assert_eq!(update.error, None);
        assert_eq!(update.reason, "selected-outbound-preserved");
        assert_eq!(update.current_selected_outbound.as_deref(), Some("SS-STAY"));
        assert_eq!(update.planned_selected_outbound.as_deref(), Some("SS-STAY"));
        assert!(update.selected_outbound_preserved);
        assert!(!update.selected_outbound_changed);
        assert_eq!(update.added_tags, vec!["SS-NEW".to_string()]);
        assert_eq!(update.removed_tags, vec!["SS-OLD".to_string()]);
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-STAY")
        );

        service.stop().expect("stop service");
    }

    #[test]
    fn running_subscription_update_falls_back_to_new_default() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-A", "SS-B"]))
            .expect("import subscription");
        service.select_node("SS-B").expect("select node");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let update = service
            .update_subscription_config(ss_config_with_tags(&["SS-C", "SS-D"]))
            .expect("update subscription");

        assert!(update.applied);
        assert_eq!(update.reason, "selected-outbound-missing-use-default");
        assert_eq!(update.current_selected_outbound.as_deref(), Some("SS-B"));
        assert_eq!(update.planned_selected_outbound.as_deref(), Some("SS-C"));
        assert!(!update.selected_outbound_preserved);
        assert!(update.selected_outbound_changed);
        assert_eq!(service.status().selected_outbound.as_deref(), Some("SS-C"));

        service.stop().expect("stop service");
    }

    #[test]
    fn running_subscription_url_update_syncs_config_for_next_node_selection() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-OLD", "SS-STAY"]))
            .expect("import subscription");
        service.select_node("SS-STAY").expect("select node");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");
        let (url, request_thread) =
            spawn_subscription_http_server(200, "OK", ss_config_with_tags(&["SS-STAY", "SS-NEW"]));

        let update = service
            .update_subscription_url(&url, Duration::from_secs(2), 4096)
            .expect("update subscription URL");
        request_thread.join().expect("subscription request");

        assert!(update.applied);
        assert_eq!(update.error, None);
        assert_eq!(update.fetch.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            update
                .update
                .as_ref()
                .map(|summary| summary.reason.as_str()),
            Some("selected-outbound-preserved")
        );

        service.select_node("SS-NEW").expect("select new node");

        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-NEW")
        );
        service.stop().expect("stop service");
    }

    #[test]
    fn failed_subscription_url_update_keeps_runtime_and_old_config() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");
        let (url, request_thread) =
            spawn_subscription_http_server(500, "Panel Error", "panel failed".to_string());

        let update = service
            .update_subscription_url(&url, Duration::from_secs(2), 4096)
            .expect("update subscription URL");
        request_thread.join().expect("subscription request");

        assert!(!update.applied);
        assert_eq!(
            update.error.as_deref(),
            Some("subscription URL fetch failed: http-status")
        );
        assert_eq!(update.fetch.error_kind.as_deref(), Some("http-status"));
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-READY")
        );
        assert_eq!(service.status().run_state, DesktopRunState::Running);

        service.stop().expect("stop service");
    }

    #[test]
    fn unusable_running_subscription_update_keeps_runtime() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let update = service
            .update_subscription_config(unusable_config())
            .expect("update subscription");

        assert!(!update.applied);
        assert_eq!(
            update.error.as_deref(),
            Some("subscription update rejected: no supported outbounds")
        );
        assert_eq!(update.reason, "no-supported-outbounds");
        assert_eq!(update.new_supported_count, 0);
        assert_eq!(update.new_skipped_count, 1);
        assert_eq!(update.planned_selected_outbound, None);
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-READY")
        );
        assert_eq!(service.status().run_state, DesktopRunState::Running);

        service.stop().expect("stop service");
    }

    #[test]
    fn system_proxy_mode_applies_and_restores_proxy() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::SystemProxy);
        service.set_listen("127.0.0.1:0");

        let running = service.start().expect("start service");

        assert_eq!(running.traffic_mode, DesktopTrafficMode::SystemProxy);
        assert_eq!(platform_controller.applied.borrow().len(), 1);

        service.stop().expect("stop service");

        assert_eq!(platform_controller.restored.borrow().len(), 1);
    }

    #[test]
    fn tun_mode_start_uses_managed_tun_controller() {
        let platform_controller = FakeSystemProxyController::new();
        let tun_controller = FakeTunDeviceController::default();
        let mut service =
            DesktopRuntimeService::new_with_tun_controller(&platform_controller, &tun_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::Tun);
        service.set_listen("127.0.0.1:0");

        let running = service.start().expect("start TUN service");

        assert_eq!(running.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(tun_controller.starts.borrow().len(), 1);
        assert_eq!(tun_controller.opens.borrow().len(), 1);

        let stopped = service.stop().expect("stop TUN service");

        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(*tun_controller.stops.borrow(), 1);
    }

    #[test]
    fn tun_mode_start_requires_tun_controller_when_not_supplied() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::Tun);

        let error = service.start().expect_err("tun mode blocked");

        assert_eq!(
            error,
            DesktopRuntimeError::Managed("desktop TUN mode requires a TUN controller".to_string())
        );
        assert_eq!(service.status().run_state, DesktopRunState::Stopped);
    }
}
