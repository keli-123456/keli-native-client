use std::fs;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::thread;
use std::time::{Duration, Instant};

use keli_client_core::{
    build_connection_plan, ClientErrorKind, ClientRuntime, ConnectionPhase, RuntimeConfig,
    RuntimeEvent, RuntimeStatus,
};
use keli_net_core::{
    encode_socks5_udp_datagram, http_connect_bad_request_response, http_connect_success_response,
    http_proxy_bad_request_response, parse_http_connect_request, parse_http_proxy_request,
    parse_socks5_handshake, parse_socks5_request, parse_socks5_udp_datagram,
    relay_owned_bidirectional_with_options, socks5_no_auth_response, socks5_reply,
    ConnectionErrorKind, ConnectionReport, DirectTcpConnector, DirectUdpConnector, LocalInbound,
    OutboundConnection, OutboundRegistry, OutboundTarget, RelayOptions, RouteAction, RouteEngine,
    Socks5Address, Socks5Command, Socks5ReplyCode,
};
use keli_platform::{
    NativeSystemProxyController, PlatformCapabilities, SystemProxyConfig, SystemProxyController,
    SystemProxySnapshot, SystemProxyStatus,
};
use keli_protocol::{
    detect_subscription_input_format, parse_mihomo_outbound_profiles,
    parse_subscription_outbound_profiles, Endpoint, OutboundProfile, ParsedOutboundProfiles,
    ProxyProtocol, SecurityKind, SkippedOutboundProfile, TransportKind,
};

const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_RELAY_POLL_INTERVAL: Duration = Duration::from_millis(200);
const MANAGED_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const SUPPORTED_OUTBOUNDS: &str =
    "direct,socks5-tcp,http-connect,trojan-tcp,trojan-ws,trojan-httpupgrade,trojan-grpc,trojan-h2,trojan-quic,vless-tcp,vless-ws,vless-httpupgrade,vless-grpc,vless-h2,vless-quic,vmess-tcp,vmess-ws,vmess-httpupgrade,vmess-grpc,vmess-h2,vmess-quic,shadowsocks-tcp,anytls-tls-tcp,naive-h2-tcp,naive-h3-quic,mieru-tcp,hy2-quic,tuic-quic";
const SUPPORTED_UDP_OUTBOUNDS: &str =
    "direct,socks5-udp,trojan-tcp-udp,trojan-tls-tcp-udp,trojan-ws-udp,trojan-tls-ws-udp,trojan-httpupgrade-udp,trojan-tls-httpupgrade-udp,trojan-grpc-udp,trojan-tls-grpc-udp,trojan-h2-udp,trojan-tls-h2-udp,trojan-quic-udp,vless-tcp-udp,vless-tls-tcp-udp,vless-ws-udp,vless-tls-ws-udp,vless-httpupgrade-udp,vless-tls-httpupgrade-udp,vless-grpc-udp,vless-tls-grpc-udp,vless-h2-udp,vless-tls-h2-udp,vless-quic-udp,vmess-tcp-aead-udp,vmess-tls-tcp-aead-udp,vmess-ws-aead-udp,vmess-tls-ws-aead-udp,vmess-httpupgrade-aead-udp,vmess-tls-httpupgrade-aead-udp,vmess-grpc-aead-udp,vmess-tls-grpc-aead-udp,vmess-h2-aead-udp,vmess-tls-h2-aead-udp,vmess-quic-aead-udp,shadowsocks-aead,anytls-tls-tcp-uot-udp,mieru-tcp-udp,hy2-quic,tuic-quic";
const SUPPORTED_PROTOCOL_CAPABILITIES: &str =
    "trojan=tcp,udp;vless=tcp,udp;vmess=tcp,udp;shadowsocks=tcp,udp;anytls=tcp,udp;naive=tcp;mieru=tcp,udp;hy2=tcp,udp;tuic=tcp,udp;socks=tcp,udp;http=tcp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Doctor,
    Version,
    ListenMixed {
        listen: String,
        once: bool,
        block_domains: Vec<String>,
        profile_config: Option<String>,
        outbound_tag: Option<String>,
        system_proxy: bool,
        system_proxy_bypass: Vec<String>,
        first_byte_timeout: Duration,
        idle_timeout: Duration,
    },
    ProbeOutbound {
        profile_config: String,
        outbound_tag: Option<String>,
        target: String,
        payload: Option<String>,
        expect: Option<String>,
        udp: bool,
        output: ProbeOutputFormat,
        first_byte_timeout: Duration,
    },
    SmokeMixed {
        profile_config: String,
        outbound_tag: Option<String>,
        target: String,
        payload: Option<String>,
        expect: Option<String>,
        inbound: SmokeInboundKind,
        output: ProbeOutputFormat,
        first_byte_timeout: Duration,
    },
    ProfileCheck {
        profile_config: String,
        output: ProbeOutputFormat,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmokeInboundKind {
    Socks5,
    HttpConnect,
}

impl SmokeInboundKind {
    fn label(self) -> &'static str {
        match self {
            Self::Socks5 => "mixed-socks5-smoke",
            Self::HttpConnect => "mixed-http-connect-smoke",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MixedProxyRuntime {
    pub routes: RouteEngine,
    pub relay_options: RelayOptions,
    pub outbounds: OutboundRegistry,
}

impl MixedProxyRuntime {
    pub fn with_routes(routes: RouteEngine) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds: OutboundRegistry::new(),
        }
    }

    pub fn with_routes_and_outbounds(routes: RouteEngine, outbounds: OutboundRegistry) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds,
        }
    }
}

impl Default for MixedProxyRuntime {
    fn default() -> Self {
        Self::with_routes(RouteEngine::new(RouteAction::Direct))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMixedOptions {
    pub listen: String,
    pub block_domains: Vec<String>,
    pub outbound_tag: Option<String>,
    pub relay_options: RelayOptions,
    pub system_proxy: bool,
    pub system_proxy_bypass: Vec<String>,
}

impl Default for ManagedMixedOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7890".to_string(),
            block_domains: Vec::new(),
            outbound_tag: None,
            relay_options: default_relay_options(),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ManagedSystemProxyGuard<'a, C: SystemProxyController + ?Sized> {
    controller: &'a C,
    snapshot: Option<SystemProxySnapshot>,
    config: SystemProxyConfig,
}

impl<'a, C: SystemProxyController + ?Sized> ManagedSystemProxyGuard<'a, C> {
    pub fn config(&self) -> &SystemProxyConfig {
        &self.config
    }

    pub fn restore(mut self) -> Result<(), String> {
        let Some(snapshot) = self.snapshot.take() else {
            return Ok(());
        };
        self.controller
            .restore(&snapshot)
            .map_err(|error| format!("restore system proxy: {error}"))
    }
}

#[derive(Debug)]
pub struct ManagedMixedSession<'a, C: SystemProxyController + ?Sized> {
    state: ClientRuntime,
    listener: Option<TcpListener>,
    listen_addr: SocketAddr,
    runtime: MixedProxyRuntime,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    system_proxy_guard: Option<ManagedSystemProxyGuard<'a, C>>,
}

#[derive(Debug)]
pub struct ManagedMixedHandle<'a, C: SystemProxyController + ?Sized> {
    state: ClientRuntime,
    listen_addr: SocketAddr,
    selected_outbound: Option<String>,
    runtime: Arc<RwLock<MixedProxyRuntime>>,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
    system_proxy_guard: Option<ManagedSystemProxyGuard<'a, C>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMixedStatusSnapshot {
    pub status: RuntimeStatus,
    pub listen_addr: Option<SocketAddr>,
    pub selected_outbound: Option<String>,
    pub generation: u64,
    pub event_count: usize,
    pub recent_events: Vec<RuntimeEvent>,
    pub last_error: Option<ClientErrorKind>,
    pub system_proxy: Option<SystemProxyConfig>,
}

impl ManagedMixedStatusSnapshot {
    fn stopped() -> Self {
        Self {
            status: RuntimeStatus::Stopped,
            listen_addr: None,
            selected_outbound: None,
            generation: 0,
            event_count: 0,
            recent_events: Vec::new(),
            last_error: None,
            system_proxy: None,
        }
    }

    pub fn system_proxy_enabled(&self) -> bool {
        self.system_proxy.is_some()
    }
}

#[derive(Debug)]
pub struct ManagedMixedController<'a, C: SystemProxyController + ?Sized> {
    controller: &'a C,
    handle: Option<ManagedMixedHandle<'a, C>>,
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedController<'a, C> {
    pub fn new(controller: &'a C) -> Self {
        Self {
            controller,
            handle: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }

    pub fn status(&self) -> ManagedMixedStatusSnapshot {
        self.handle
            .as_ref()
            .map(ManagedMixedStatusSnapshot::from_handle)
            .unwrap_or_else(ManagedMixedStatusSnapshot::stopped)
    }

    pub fn start_from_subscription_config_text(
        &mut self,
        config_text: &str,
        options: ManagedMixedOptions,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        if self.handle.is_some() {
            return Err("managed mixed core is already running".to_string());
        }

        let session = ManagedMixedSession::start_from_subscription_config_text(
            config_text,
            options,
            self.controller,
        )?;
        self.handle = Some(session.spawn_background()?);
        Ok(self.status())
    }

    pub fn reload_from_subscription_config_text(
        &mut self,
        config_text: &str,
        outbound_tag: Option<String>,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.reload_from_subscription_config_text(config_text, outbound_tag)?;
        }
        Ok(self.status())
    }

    pub fn stop(&mut self) -> Result<ClientRuntime, String> {
        let handle = self
            .handle
            .take()
            .ok_or_else(|| "managed mixed core is not running".to_string())?;
        handle.stop()
    }
}

impl ManagedMixedStatusSnapshot {
    fn from_handle<C: SystemProxyController + ?Sized>(handle: &ManagedMixedHandle<'_, C>) -> Self {
        let recent_events: Vec<RuntimeEvent> =
            handle.events().iter().rev().take(5).cloned().collect();
        let last_error = handle
            .events()
            .iter()
            .rev()
            .find_map(|event| match &event.status {
                RuntimeStatus::Failed(error) => Some(error.clone()),
                _ => None,
            });
        Self {
            status: handle.status().clone(),
            listen_addr: Some(handle.listen_addr()),
            selected_outbound: handle.selected_outbound().map(str::to_string),
            generation: handle.generation(),
            event_count: handle.events().len(),
            recent_events,
            last_error,
            system_proxy: handle.system_proxy_config().cloned(),
        }
    }
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedHandle<'a, C> {
    pub fn status(&self) -> &RuntimeStatus {
        self.state.status()
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn selected_outbound(&self) -> Option<&str> {
        self.selected_outbound.as_deref()
    }

    pub fn generation(&self) -> u64 {
        self.state.generation()
    }

    pub fn events(&self) -> &[RuntimeEvent] {
        self.state.events()
    }

    pub fn system_proxy_config(&self) -> Option<&SystemProxyConfig> {
        self.system_proxy_guard
            .as_ref()
            .map(ManagedSystemProxyGuard::config)
    }

    pub fn reload_from_subscription_config_text(
        &mut self,
        config_text: &str,
        outbound_tag: Option<String>,
    ) -> Result<(), String> {
        let listen = self.listen_addr.to_string();
        let config = RuntimeConfig::new(config_text, outbound_tag.clone(), listen.clone());
        let plan = match build_connection_plan(config_text, outbound_tag.as_deref(), listen.clone())
        {
            Ok(plan) => plan,
            Err(error) => {
                let _ = self.state.reload(config);
                return Err(format!("runtime reload failed: {error:?}"));
            }
        };
        let selected_outbound = plan.selected_outbound().to_string();
        let next_runtime = match mixed_runtime_from_subscription_config_text(
            config_text,
            self.block_domains.clone(),
            self.relay_options,
            Some(selected_outbound.clone()),
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.state
                    .record_reload_rejected(ClientErrorKind::ConfigInvalid(error.clone()));
                return Err(format!("runtime reload failed: {error}"));
            }
        };

        {
            let mut runtime = self
                .runtime
                .write()
                .map_err(|_| "managed mixed runtime lock poisoned".to_string())?;
            *runtime = next_runtime;
        }

        self.state
            .reload(config)
            .map_err(|error| format!("runtime reload failed: {error:?}"))?;
        self.selected_outbound = Some(selected_outbound);
        Ok(())
    }

    pub fn stop(mut self) -> Result<ClientRuntime, String> {
        self.stop.store(true, Ordering::SeqCst);
        let serve_result = self
            .thread
            .take()
            .map(|thread| {
                thread
                    .join()
                    .map_err(|_| "managed mixed listener thread panicked".to_string())
                    .and_then(|result| {
                        result.map_err(|error| format!("managed mixed listener failed: {error}"))
                    })
            })
            .unwrap_or(Ok(()));
        let restore_result = self
            .system_proxy_guard
            .take()
            .map(ManagedSystemProxyGuard::restore)
            .unwrap_or(Ok(()));
        self.state.stop();

        match (serve_result, restore_result) {
            (Ok(()), Ok(())) => Ok(self.state),
            (Err(serve_error), Ok(())) => Err(serve_error),
            (Ok(()), Err(restore_error)) => Err(restore_error),
            (Err(serve_error), Err(restore_error)) => {
                Err(format!("{serve_error}; {restore_error}"))
            }
        }
    }
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedSession<'a, C> {
    pub fn start_from_subscription_config_text(
        config_text: &str,
        options: ManagedMixedOptions,
        controller: &'a C,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(&options.listen)
            .map_err(|error| format!("listen-mixed bind failed on {}: {error}", options.listen))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|error| format!("read mixed listener address: {error}"))?;
        let listen = listen_addr.to_string();
        let block_domains = options.block_domains;
        let relay_options = options.relay_options;
        let mut state = ClientRuntime::default();
        let selected_outbound = match state.start(RuntimeConfig::new(
            config_text,
            options.outbound_tag.clone(),
            listen,
        )) {
            Ok(plan) => plan.selected_outbound().to_string(),
            Err(error) => return Err(format!("runtime start failed: {error:?}")),
        };
        let runtime = match mixed_runtime_from_subscription_config_text(
            config_text,
            block_domains.clone(),
            relay_options,
            Some(selected_outbound),
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                state.record_failure(ClientErrorKind::ConfigInvalid(error.clone()));
                return Err(error);
            }
        };
        let system_proxy_guard = if options.system_proxy {
            match apply_system_proxy_for_listener(
                controller,
                &listener,
                options.system_proxy_bypass,
            ) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    state.record_failure(ClientErrorKind::SystemProxyLoop);
                    return Err(error);
                }
            }
        } else {
            None
        };

        println!("mixed inbound listening on {listen_addr}");
        Ok(Self {
            state,
            listener: Some(listener),
            listen_addr,
            runtime,
            block_domains,
            relay_options,
            system_proxy_guard,
        })
    }

    pub fn status(&self) -> &RuntimeStatus {
        self.state.status()
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn selected_outbound(&self) -> Option<&str> {
        match self.state.status() {
            RuntimeStatus::Running {
                selected_outbound, ..
            } => Some(selected_outbound.as_str()),
            _ => None,
        }
    }

    pub fn serve(mut self, once: bool) -> Result<ClientRuntime, String> {
        let listener = self
            .listener
            .take()
            .expect("managed mixed listener is present");
        let serve_result = serve_mixed_listener(listener, once, &self.runtime);
        let stop_result = self.stop();

        match (serve_result, stop_result) {
            (Ok(()), Ok(state)) => Ok(state),
            (Err(serve_error), Ok(_)) => Err(format!("listen-mixed failed: {serve_error}")),
            (Ok(()), Err(restore_error)) => Err(restore_error),
            (Err(serve_error), Err(restore_error)) => Err(format!(
                "listen-mixed failed: {serve_error}; {restore_error}"
            )),
        }
    }

    pub fn spawn_background(mut self) -> Result<ManagedMixedHandle<'a, C>, String> {
        let listener = self
            .listener
            .take()
            .expect("managed mixed listener is present");
        let selected_outbound = self.selected_outbound().map(str::to_string);
        let runtime = Arc::new(RwLock::new(self.runtime));
        let thread_runtime = Arc::clone(&runtime);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            serve_mixed_listener_until(listener, thread_runtime, thread_stop)
        });

        Ok(ManagedMixedHandle {
            state: self.state,
            listen_addr: self.listen_addr,
            selected_outbound,
            runtime,
            block_domains: self.block_domains,
            relay_options: self.relay_options,
            stop,
            thread: Some(thread),
            system_proxy_guard: self.system_proxy_guard,
        })
    }

    pub fn stop(mut self) -> Result<ClientRuntime, String> {
        let restore_result = self
            .system_proxy_guard
            .take()
            .map(ManagedSystemProxyGuard::restore)
            .unwrap_or(Ok(()));
        self.state.stop();
        restore_result.map(|_| self.state)
    }
}

pub fn parse_cli_command(
    args: impl IntoIterator<Item = impl Into<String>>,
) -> Result<CliCommand, String> {
    let mut args = args.into_iter().map(Into::into);
    match args.next().as_deref() {
        None | Some("doctor") => Ok(CliCommand::Doctor),
        Some("version") => Ok(CliCommand::Version),
        Some("listen-mixed") => parse_listen_mixed(args),
        Some("probe-outbound") => parse_probe_outbound(args),
        Some("smoke-mixed") => parse_smoke_mixed(args),
        Some("profile-check") => parse_profile_check(args),
        Some(other) => Err(format!("unknown command: {other}")),
    }
}

pub fn run(command: CliCommand) -> Result<(), String> {
    match command {
        CliCommand::Doctor => {
            print_doctor();
            Ok(())
        }
        CliCommand::Version => {
            println!("keli-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::ListenMixed {
            listen,
            once,
            block_domains,
            profile_config,
            outbound_tag,
            system_proxy,
            system_proxy_bypass,
            first_byte_timeout,
            idle_timeout,
        } => {
            let relay_options = RelayOptions {
                first_byte_timeout: Some(first_byte_timeout),
                idle_timeout: Some(idle_timeout),
            };
            let controller = NativeSystemProxyController::new();

            if let Some(path) = profile_config {
                let config_text = fs::read_to_string(&path)
                    .map_err(|error| format!("read profile config {path}: {error}"))?;
                let session = ManagedMixedSession::start_from_subscription_config_text(
                    &config_text,
                    ManagedMixedOptions {
                        listen,
                        block_domains,
                        outbound_tag,
                        relay_options,
                        system_proxy,
                        system_proxy_bypass,
                    },
                    &controller,
                )?;
                return session.serve(once).map(|_| ());
            }

            let runtime = mixed_runtime_from_cli(block_domains, relay_options);
            if system_proxy {
                listen_mixed_with_system_proxy_controller(
                    &listen,
                    once,
                    &runtime,
                    &controller,
                    system_proxy_bypass,
                )
            } else {
                listen_mixed(&listen, once, &runtime)
                    .map_err(|error| format!("listen-mixed failed on {listen}: {error}"))
            }
        }
        CliCommand::ProbeOutbound {
            profile_config,
            outbound_tag,
            target,
            payload,
            expect,
            udp,
            output,
            first_byte_timeout,
        } => {
            let config_text = fs::read_to_string(&profile_config)
                .map_err(|error| format!("read profile config {profile_config}: {error}"))?;
            let mut stdout = io::stdout();
            probe_outbound_from_subscription_config_text_with_format(
                &config_text,
                outbound_tag,
                &target,
                payload.as_deref().unwrap_or("").as_bytes(),
                expect.as_deref().map(str::as_bytes),
                udp,
                first_byte_timeout,
                output,
                &mut stdout,
            )
        }
        CliCommand::SmokeMixed {
            profile_config,
            outbound_tag,
            target,
            payload,
            expect,
            inbound,
            output,
            first_byte_timeout,
        } => {
            let config_text = fs::read_to_string(&profile_config)
                .map_err(|error| format!("read profile config {profile_config}: {error}"))?;
            let mut stdout = io::stdout();
            write_smoke_mixed_report_from_subscription_config_text(
                &config_text,
                outbound_tag,
                &target,
                payload.as_deref().unwrap_or("").as_bytes(),
                expect.as_deref().unwrap_or("").as_bytes(),
                inbound,
                first_byte_timeout,
                output,
                &mut stdout,
            )
        }
        CliCommand::ProfileCheck {
            profile_config,
            output,
        } => {
            let config_text = fs::read_to_string(&profile_config)
                .map_err(|error| format!("read profile config {profile_config}: {error}"))?;
            let mut stdout = io::stdout();
            write_profile_check_report_from_subscription_config_text(
                &config_text,
                output,
                &mut stdout,
            )
        }
    }
}

pub fn print_usage(mut writer: impl Write) -> io::Result<()> {
    writeln!(
        writer,
        "usage: keli-cli [doctor|version|listen-mixed|probe-outbound|smoke-mixed|profile-check]"
    )?;
    writeln!(
        writer,
        "       keli-cli listen-mixed [--listen 127.0.0.1:7890] [--once] [--profile-config subscription.yaml] [--outbound-tag proxy] [--first-byte-timeout-ms 30000] [--idle-timeout-ms 300000]"
    )?;
    writeln!(
        writer,
        "       keli-cli listen-mixed --system-proxy [--system-proxy-bypass localhost] [--system-proxy-bypass <local>]"
    )?;
    writeln!(
        writer,
        "       keli-cli probe-outbound --profile-config subscription.yaml [--outbound-tag proxy] --target example.com:443 [--payload ping] [--expect pong] [--udp] [--format text|json] [--first-byte-timeout-ms 30000]"
    )?;
    writeln!(
        writer,
        "       keli-cli smoke-mixed --profile-config subscription.yaml [--outbound-tag proxy] --target example.com:443 [--inbound socks5|http-connect] [--payload ping] [--expect pong] [--format text|json] [--first-byte-timeout-ms 30000]"
    )?;
    writeln!(
        writer,
        "       keli-cli profile-check --profile-config subscription.yaml [--format text|json]"
    )
}

fn parse_listen_mixed(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut listen = "127.0.0.1:7890".to_string();
    let mut once = false;
    let mut block_domains = Vec::new();
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut system_proxy = false;
    let mut system_proxy_bypass = Vec::new();
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut idle_timeout = DEFAULT_IDLE_TIMEOUT;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .ok_or_else(|| "--listen requires an address".to_string())?;
            }
            "--once" => once = true,
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            "--idle-timeout-ms" => {
                idle_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--idle-timeout-ms requires a value".to_string())?,
                    "--idle-timeout-ms",
                )?;
            }
            "--block-domain" => {
                block_domains.push(
                    args.next()
                        .ok_or_else(|| "--block-domain requires a domain".to_string())?,
                );
            }
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            "--system-proxy" => system_proxy = true,
            "--system-proxy-bypass" => {
                system_proxy_bypass.push(
                    args.next()
                        .ok_or_else(|| "--system-proxy-bypass requires a value".to_string())?,
                );
            }
            other => return Err(format!("unknown listen-mixed option: {other}")),
        }
    }

    Ok(CliCommand::ListenMixed {
        listen,
        once,
        block_domains,
        profile_config,
        outbound_tag,
        system_proxy,
        system_proxy_bypass,
        first_byte_timeout,
        idle_timeout,
    })
}

fn parse_probe_outbound(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut target = None;
    let mut payload = None;
    let mut expect = None;
    let mut udp = false;
    let mut output = ProbeOutputFormat::Text;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            "--target" => {
                target = Some(
                    args.next()
                        .ok_or_else(|| "--target requires host:port".to_string())?,
                );
            }
            "--payload" => {
                payload = Some(
                    args.next()
                        .ok_or_else(|| "--payload requires a value".to_string())?,
                );
            }
            "--expect" => {
                expect = Some(
                    args.next()
                        .ok_or_else(|| "--expect requires a value".to_string())?,
                );
            }
            "--udp" => udp = true,
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            other => return Err(format!("unknown probe-outbound option: {other}")),
        }
    }

    Ok(CliCommand::ProbeOutbound {
        profile_config: profile_config
            .ok_or_else(|| "probe-outbound requires --profile-config".to_string())?,
        outbound_tag,
        target: target.ok_or_else(|| "probe-outbound requires --target".to_string())?,
        payload,
        expect,
        udp,
        output,
        first_byte_timeout,
    })
}

fn parse_smoke_mixed(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut target = None;
    let mut payload = None;
    let mut expect = None;
    let mut inbound = SmokeInboundKind::Socks5;
    let mut output = ProbeOutputFormat::Text;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            "--target" => {
                target = Some(
                    args.next()
                        .ok_or_else(|| "--target requires host:port".to_string())?,
                );
            }
            "--payload" => {
                payload = Some(
                    args.next()
                        .ok_or_else(|| "--payload requires a value".to_string())?,
                );
            }
            "--expect" => {
                expect = Some(
                    args.next()
                        .ok_or_else(|| "--expect requires a value".to_string())?,
                );
            }
            "--inbound" => {
                inbound = parse_smoke_inbound_kind(
                    args.next()
                        .ok_or_else(|| "--inbound requires socks5 or http-connect".to_string())?,
                )?;
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            other => return Err(format!("unknown smoke-mixed option: {other}")),
        }
    }

    Ok(CliCommand::SmokeMixed {
        profile_config: profile_config
            .ok_or_else(|| "smoke-mixed requires --profile-config".to_string())?,
        outbound_tag,
        target: target.ok_or_else(|| "smoke-mixed requires --target".to_string())?,
        payload,
        expect,
        inbound,
        output,
        first_byte_timeout,
    })
}

fn parse_smoke_inbound_kind(value: String) -> Result<SmokeInboundKind, String> {
    match value.as_str() {
        "socks5" => Ok(SmokeInboundKind::Socks5),
        "http-connect" => Ok(SmokeInboundKind::HttpConnect),
        other => Err(format!("unknown smoke-mixed inbound: {other}")),
    }
}

fn parse_probe_output_format(value: String) -> Result<ProbeOutputFormat, String> {
    match value.as_str() {
        "text" => Ok(ProbeOutputFormat::Text),
        "json" => Ok(ProbeOutputFormat::Json),
        other => Err(format!("unknown probe-outbound format: {other}")),
    }
}

fn parse_profile_check(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut output = ProbeOutputFormat::Text;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            other => return Err(format!("unknown profile-check option: {other}")),
        }
    }

    Ok(CliCommand::ProfileCheck {
        profile_config: profile_config
            .ok_or_else(|| "profile-check requires --profile-config".to_string())?,
        output,
    })
}

fn print_doctor() {
    let mut stdout = io::stdout();
    write_doctor_report(&mut stdout).expect("write doctor report");
}

pub fn write_doctor_report(mut writer: impl Write) -> io::Result<()> {
    let capabilities = PlatformCapabilities::detect();
    let system_proxy_status = SystemProxyStatus::detect();
    let inbound = LocalInbound::Mixed {
        listen: "127.0.0.1".to_string(),
        port: 7890,
    };
    let route_engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
    let profile = OutboundProfile {
        tag: "trojan-ws".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("example.com", 443),
        transport: TransportKind::WebSocket {
            path: "/answer".to_string(),
            host: Some("example.com".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("example.com".to_string()),
            skip_verify: false,
        },
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    };

    writeln!(writer, "keli-native-client doctor")?;
    writeln!(writer, "version={}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "platform={:?}", capabilities.platform)?;
    writeln!(writer, "system_proxy={}", capabilities.system_proxy)?;
    writeln!(
        writer,
        "system_proxy_state={} server={} error={}",
        system_proxy_status
            .enabled
            .map(|enabled| if enabled { "enabled" } else { "disabled" })
            .unwrap_or(if system_proxy_status.supported {
                "unknown"
            } else {
                "unsupported"
            }),
        system_proxy_status.server.as_deref().unwrap_or("-"),
        system_proxy_status.error.as_deref().unwrap_or("-")
    )?;
    writeln!(writer, "tun={}", capabilities.tun)?;
    writeln!(writer, "secure_storage={}", capabilities.secure_storage)?;
    writeln!(writer, "inbound={inbound:?}")?;
    writeln!(writer, "route_default={route_engine:?}")?;
    writeln!(writer, "dns_engine=system_resolver cache_ttl=60s")?;
    writeln!(writer, "supported_outbounds={SUPPORTED_OUTBOUNDS}")?;
    writeln!(writer, "supported_udp_outbounds={SUPPORTED_UDP_OUTBOUNDS}")?;
    writeln!(
        writer,
        "protocol_capabilities={SUPPORTED_PROTOCOL_CAPABILITIES}"
    )?;
    writeln!(
        writer,
        "sample_profile_valid={}",
        profile.validate().is_ok()
    )?;
    writeln!(writer, "initial_phase={:?}", ConnectionPhase::Idle)?;
    Ok(())
}

fn listen_mixed(listen: &str, once: bool, runtime: &MixedProxyRuntime) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    println!("mixed inbound listening on {}", listener.local_addr()?);

    serve_mixed_listener(listener, once, runtime)
}

fn serve_mixed_listener(
    listener: TcpListener,
    once: bool,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = handle_mixed_connection_with_routes(&mut stream, runtime) {
            eprintln!("mixed inbound failed: {error}");
        }
        if once {
            break;
        }
    }

    Ok(())
}

fn serve_mixed_listener_until(
    listener: TcpListener,
    runtime: Arc<RwLock<MixedProxyRuntime>>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let runtime = runtime
                    .read()
                    .map_err(|_| io::Error::other("mixed runtime lock poisoned"))?
                    .clone();
                if let Err(error) = handle_mixed_connection_with_routes(&mut stream, &runtime) {
                    eprintln!("mixed inbound failed: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(MANAGED_ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn listen_mixed_with_system_proxy_controller<C: SystemProxyController + ?Sized>(
    listen: &str,
    once: bool,
    runtime: &MixedProxyRuntime,
    controller: &C,
    bypass: Vec<String>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .map_err(|error| format!("listen-mixed bind failed on {listen}: {error}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| format!("read mixed listener address: {error}"))?;
    println!("mixed inbound listening on {listen_addr}");
    let guard = apply_system_proxy_for_listener(controller, &listener, bypass)?;
    let serve_result = serve_mixed_listener(listener, once, runtime);
    let restore_result = guard.restore();

    match (serve_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(serve_error), Ok(())) => Err(format!("listen-mixed failed: {serve_error}")),
        (Ok(()), Err(restore_error)) => Err(restore_error),
        (Err(serve_error), Err(restore_error)) => Err(format!(
            "listen-mixed failed: {serve_error}; {restore_error}"
        )),
    }
}

pub fn apply_system_proxy_for_listener<'a, C: SystemProxyController + ?Sized>(
    controller: &'a C,
    listener: &TcpListener,
    bypass: Vec<String>,
) -> Result<ManagedSystemProxyGuard<'a, C>, String> {
    let local_addr = listener
        .local_addr()
        .map_err(|error| format!("read mixed listener address: {error}"))?;
    let server = system_proxy_server_for_listener(local_addr);
    let config = SystemProxyConfig::new(server)
        .map_err(|error| format!("build system proxy config: {error}"))?
        .with_bypass(bypass);
    let snapshot = controller
        .apply(&config)
        .map_err(|error| format!("apply system proxy: {error}"))?;
    Ok(ManagedSystemProxyGuard {
        controller,
        snapshot: Some(snapshot),
        config,
    })
}

fn system_proxy_server_for_listener(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port()).to_string()
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port()).to_string()
        }
        _ => addr.to_string(),
    }
}

pub fn handle_socks5_connection(stream: &mut TcpStream) -> io::Result<()> {
    handle_socks5_connection_with_routes(stream, &MixedProxyRuntime::default())
}

pub fn handle_socks5_connection_with_routes(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let handshake = parse_socks5_handshake(stream).map_err(to_io_error)?;
    if !handshake.methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff])?;
        return Ok(());
    }

    stream.write_all(&socks5_no_auth_response())?;
    let request = parse_socks5_request(stream).map_err(to_io_error)?;
    println!(
        "socks5 request command={:?} address={:?} port={}",
        request.command, request.address, request.port
    );

    match request.command {
        Socks5Command::Connect => {}
        Socks5Command::UdpAssociate => {
            return handle_socks5_udp_associate(stream, runtime);
        }
        Socks5Command::Bind => {
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Ok(());
        }
    }

    let target = OutboundTarget::from_socks5_request(&request);
    let mut report = ConnectionReport::new("socks5", target.clone(), RouteAction::Direct);
    let remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::ConnectionNotAllowed))?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::HostUnreachable))?;
            return Err(error);
        }
    };

    stream.write_all(&socks5_reply(Socks5ReplyCode::Succeeded))?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

fn handle_socks5_udp_associate(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let relay = UdpSocket::bind("127.0.0.1:0")?;
    let first_byte_timeout = runtime
        .relay_options
        .first_byte_timeout
        .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT);
    let idle_timeout = runtime
        .relay_options
        .idle_timeout
        .unwrap_or(DEFAULT_IDLE_TIMEOUT);
    relay.set_read_timeout(Some(UDP_RELAY_POLL_INTERVAL))?;
    let outbound = UdpSocket::bind("0.0.0.0:0")?;
    outbound.set_read_timeout(Some(first_byte_timeout))?;

    let bound_addr = relay.local_addr()?;
    stream.write_all(&socks5_success_reply_for_bound_addr(bound_addr))?;
    stream.set_nonblocking(true)?;
    let session_result = relay_socks5_udp_session(
        stream,
        runtime,
        &relay,
        &outbound,
        first_byte_timeout,
        idle_timeout,
    );
    stream.set_nonblocking(false).ok();
    session_result
}

fn relay_socks5_udp_session(
    stream: &TcpStream,
    runtime: &MixedProxyRuntime,
    relay: &UdpSocket,
    outbound: &UdpSocket,
    first_byte_timeout: Duration,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut request_buffer = [0; 65_535];
    let started = Instant::now();
    let mut last_activity = started;
    let mut received_datagram = false;

    loop {
        if socks5_udp_control_is_closed(stream)? {
            return Ok(());
        }

        match relay.recv_from(&mut request_buffer) {
            Ok((request_size, client_udp_addr)) => {
                received_datagram = true;
                relay_socks5_udp_datagram(
                    runtime,
                    relay,
                    outbound,
                    &request_buffer[..request_size],
                    client_udp_addr,
                    first_byte_timeout,
                )?;
                last_activity = Instant::now();
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if socks5_udp_control_is_closed(stream)? {
                    return Ok(());
                }
                let timeout = if received_datagram {
                    idle_timeout
                } else {
                    first_byte_timeout
                };
                let reference = if received_datagram {
                    last_activity
                } else {
                    started
                };
                if reference.elapsed() >= timeout {
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn relay_socks5_udp_datagram(
    runtime: &MixedProxyRuntime,
    relay: &UdpSocket,
    outbound: &UdpSocket,
    request: &[u8],
    client_udp_addr: SocketAddr,
    response_timeout: Duration,
) -> io::Result<()> {
    let datagram = parse_socks5_udp_datagram(request).map_err(to_io_error)?;
    let target = outbound_target_from_socks5_udp(&datagram.address, datagram.port);
    let mut report = ConnectionReport::new("socks5-udp", target.clone(), RouteAction::Direct);

    match runtime.routes.decide(&target.route_target()).action {
        RouteAction::Direct => {}
        RouteAction::Block => {
            report.route_action = RouteAction::Block;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            return Ok(());
        }
        RouteAction::Outbound(tag) => {
            report.route_action = RouteAction::Outbound(tag.clone());
            let started = Instant::now();
            let response = match runtime.outbounds.relay_udp_datagram(
                &tag,
                &target,
                &datagram.payload,
                response_timeout,
            ) {
                Ok(response) => response,
                Err(error) => {
                    report.record_error(ConnectionErrorKind::from_io(&error));
                    println!("{}", report.summary_line());
                    return Ok(());
                }
            };
            report.upload_bytes = datagram.payload.len() as u64;
            report.record_first_byte_duration(started.elapsed());
            report.download_bytes = response.payload.len() as u64;
            send_socks5_udp_response(relay, client_udp_addr, response.source, &response.payload)?;
            println!("{}", report.summary_line());
            return Ok(());
        }
        RouteAction::HijackDns => {
            report.route_action = RouteAction::HijackDns;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            return Ok(());
        }
    }

    let remote_addr = match resolve_udp_socket_addr(&target) {
        Ok(remote_addr) => remote_addr,
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            return Ok(());
        }
    };
    let started = Instant::now();
    if let Err(error) = outbound.send_to(&datagram.payload, remote_addr) {
        report.record_error(ConnectionErrorKind::from_io(&error));
        println!("{}", report.summary_line());
        return Ok(());
    }
    report.upload_bytes = datagram.payload.len() as u64;

    let mut response_buffer = [0; 65_535];
    let (response_size, response_from) = match outbound.recv_from(&mut response_buffer) {
        Ok(response) => response,
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            return Ok(());
        }
    };
    report.record_first_byte_duration(started.elapsed());
    report.download_bytes = response_size as u64;

    send_socks5_udp_response(
        relay,
        client_udp_addr,
        response_from,
        &response_buffer[..response_size],
    )?;
    println!("{}", report.summary_line());
    Ok(())
}

fn send_socks5_udp_response(
    relay: &UdpSocket,
    client_udp_addr: SocketAddr,
    response_from: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let response_address = socks5_address_from_ip(response_from.ip());
    let response = encode_socks5_udp_datagram(&response_address, response_from.port(), payload)
        .map_err(to_io_error)?;
    relay.send_to(&response, client_udp_addr)?;
    Ok(())
}

fn socks5_udp_control_is_closed(stream: &TcpStream) -> io::Result<bool> {
    let mut buffer = [0; 1];
    match stream.peek(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::TimedOut =>
        {
            Ok(false)
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(true),
        Err(error) => Err(error),
    }
}

fn socks5_success_reply_for_bound_addr(bound_addr: SocketAddr) -> Vec<u8> {
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[0x05, 0x00, 0x00]);
    match bound_addr.ip() {
        IpAddr::V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound_addr.port().to_be_bytes());
    reply
}

fn outbound_target_from_socks5_udp(address: &Socks5Address, port: u16) -> OutboundTarget {
    let host = match address {
        Socks5Address::Ipv4(ip) => ip.to_string(),
        Socks5Address::Domain(domain) => domain.clone(),
        Socks5Address::Ipv6(ip) => ip.to_string(),
    };
    OutboundTarget::new(host, port)
}

fn resolve_udp_socket_addr(target: &OutboundTarget) -> io::Result<SocketAddr> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, target.port));
    }

    (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address resolved for {}:{}", target.host, target.port),
            )
        })
}

fn socks5_address_from_ip(ip: IpAddr) -> Socks5Address {
    match ip {
        IpAddr::V4(ip) => Socks5Address::Ipv4(ip),
        IpAddr::V6(ip) => Socks5Address::Ipv6(ip),
    }
}

pub fn handle_mixed_connection(stream: &mut TcpStream) -> io::Result<()> {
    handle_mixed_connection_with_routes(stream, &MixedProxyRuntime::default())
}

pub fn handle_mixed_connection_with_routes(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let mut first = [0; 1];
    stream.peek(&mut first)?;
    match first[0] {
        0x05 => handle_socks5_connection_with_routes(stream, runtime),
        b'C' | b'c' => handle_http_connect_connection(stream, runtime),
        b'D' | b'd' | b'G' | b'g' | b'H' | b'h' | b'O' | b'o' | b'P' | b'p' | b'T' | b't' => {
            handle_http_proxy_connection(stream, runtime)
        }
        _ => {
            stream.write_all(http_connect_bad_request_response())?;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mixed inbound received an unsupported protocol",
            ))
        }
    }
}

fn handle_http_connect_connection(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let request = match parse_http_connect_request(stream) {
        Ok(remote) => remote,
        Err(error) => {
            stream.write_all(http_connect_bad_request_response())?;
            return Err(to_io_error(error));
        }
    };
    println!(
        "http connect request address={} port={}",
        request.host, request.port
    );

    let target = OutboundTarget::new(request.host, request.port);
    let mut report = ConnectionReport::new("http-connect", target.clone(), RouteAction::Direct);
    let remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(http_connect_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(http_connect_bad_request_response())?;
            return Err(error);
        }
    };

    stream.write_all(http_connect_success_response())?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

fn handle_http_proxy_connection(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let request = match parse_http_proxy_request(stream) {
        Ok(request) => request,
        Err(error) => {
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(to_io_error(error));
        }
    };
    println!(
        "http proxy request method={} address={} port={} path={}",
        request.method, request.host, request.port, request.path_and_query
    );

    let target = OutboundTarget::new(request.host, request.port);
    let mut report = ConnectionReport::new("http-proxy", target.clone(), RouteAction::Direct);
    let mut remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(error);
        }
    };

    remote.write_all(&request.rewritten_header)?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

enum RouteConnect {
    Direct {
        stream: OutboundConnection,
        route_action: RouteAction,
        connect_duration: Duration,
    },
    Blocked {
        route_action: RouteAction,
    },
    UnsupportedOutbound {
        tag: String,
        route_action: RouteAction,
    },
}

fn connect_by_route(
    target: &OutboundTarget,
    runtime: &MixedProxyRuntime,
) -> io::Result<RouteConnect> {
    let decision = runtime.routes.decide(&target.route_target());
    match decision.action {
        RouteAction::Direct => {
            let started = Instant::now();
            DirectTcpConnector::connect(target, Duration::from_secs(10)).map(|stream| {
                RouteConnect::Direct {
                    stream: OutboundConnection::Tcp(stream),
                    route_action: RouteAction::Direct,
                    connect_duration: started.elapsed(),
                }
            })
        }
        RouteAction::Block => Ok(RouteConnect::Blocked {
            route_action: RouteAction::Block,
        }),
        RouteAction::Outbound(tag) => {
            let started = Instant::now();
            match runtime
                .outbounds
                .connect(&tag, target, Duration::from_secs(10))
            {
                Ok(stream) => Ok(RouteConnect::Direct {
                    stream,
                    route_action: RouteAction::Outbound(tag),
                    connect_duration: started.elapsed(),
                }),
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    Ok(RouteConnect::UnsupportedOutbound {
                        route_action: RouteAction::Outbound(tag.clone()),
                        tag,
                    })
                }
                Err(error) => Err(error),
            }
        }
        RouteAction::HijackDns => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hijack-dns route action is not valid for TCP proxy relay",
        )),
    }
}

pub fn mixed_runtime_from_mihomo_config_text(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let parsed = parse_mihomo_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    mixed_runtime_from_parsed_profiles(parsed, block_domains, relay_options, outbound_tag)
}

pub fn mixed_runtime_from_subscription_config_text(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    mixed_runtime_from_parsed_profiles(parsed, block_domains, relay_options, outbound_tag)
}

pub fn probe_outbound_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: Option<&[u8]>,
    udp: bool,
    first_byte_timeout: Duration,
    mut writer: impl Write,
) -> Result<(), String> {
    probe_outbound_from_subscription_config_text_with_format(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        udp,
        first_byte_timeout,
        ProbeOutputFormat::Text,
        &mut writer,
    )
}

pub fn smoke_mixed_socks5_connect_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    first_byte_timeout: Duration,
) -> Result<ConnectionReport, String> {
    smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        SmokeInboundKind::Socks5,
        first_byte_timeout,
    )
}

pub fn smoke_mixed_http_connect_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    first_byte_timeout: Duration,
) -> Result<ConnectionReport, String> {
    smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        SmokeInboundKind::HttpConnect,
        first_byte_timeout,
    )
}

pub fn smoke_mixed_connect_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
) -> Result<ConnectionReport, String> {
    let target = parse_probe_target(target)?;
    let plan = build_connection_plan(config_text, outbound_tag.as_deref(), "127.0.0.1:0")
        .map_err(|error| format!("connection plan failed: {error:?}"))?;
    let selected_outbound = plan.selected_outbound().to_string();
    let relay_options = RelayOptions {
        first_byte_timeout: Some(first_byte_timeout),
        idle_timeout: Some(first_byte_timeout),
    };
    let runtime = mixed_runtime_from_subscription_config_text(
        config_text,
        Vec::new(),
        relay_options,
        Some(selected_outbound.clone()),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind smoke listener: {error}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| format!("read smoke listener addr: {error}"))?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        handle_mixed_connection_with_routes(&mut stream, &runtime)
    });

    let mut client = TcpStream::connect(listen_addr)
        .map_err(|error| format!("connect smoke listener {listen_addr}: {error}"))?;
    client
        .set_read_timeout(Some(first_byte_timeout))
        .map_err(|error| format!("set smoke read timeout: {error}"))?;
    client
        .set_write_timeout(Some(first_byte_timeout))
        .map_err(|error| format!("set smoke write timeout: {error}"))?;

    write_smoke_connect(&mut client, &target, inbound)?;
    let started = Instant::now();
    if !payload.is_empty() {
        client
            .write_all(payload)
            .map_err(|error| format!("write smoke payload: {error}"))?;
    }
    if !expect.is_empty() {
        let mut received = vec![0; expect.len()];
        client
            .read_exact(&mut received)
            .map_err(|error| format!("read smoke response: {error}"))?;
        if received != expect {
            client.shutdown(Shutdown::Both).ok();
            return Err(format!(
                "smoke response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(expect),
                String::from_utf8_lossy(&received)
            ));
        }
    }
    client.shutdown(Shutdown::Both).ok();
    server
        .join()
        .map_err(|_| "mixed smoke worker panicked".to_string())?
        .map_err(|error| format!("mixed smoke relay failed: {error}"))?;

    let mut report = ConnectionReport::new(
        inbound.label(),
        target,
        RouteAction::Outbound(selected_outbound),
    );
    if !expect.is_empty() {
        report.record_first_byte_duration(started.elapsed());
    }
    report.upload_bytes = payload.len() as u64;
    report.download_bytes = expect.len() as u64;
    Ok(report)
}

pub fn write_smoke_mixed_report_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        inbound,
        first_byte_timeout,
    )?;
    write_smoke_result(&mut writer, "ok", &report, output)
}

pub fn write_smoke_mixed_socks5_report_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    first_byte_timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        SmokeInboundKind::Socks5,
        first_byte_timeout,
    )?;
    write_smoke_result(&mut writer, "ok", &report, output)
}

pub fn probe_outbound_from_subscription_config_text_with_format(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: Option<&[u8]>,
    udp: bool,
    first_byte_timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let relay_options = RelayOptions {
        first_byte_timeout: Some(first_byte_timeout),
        idle_timeout: Some(first_byte_timeout),
    };
    let runtime = mixed_runtime_from_subscription_config_text(
        config_text,
        Vec::new(),
        relay_options,
        outbound_tag,
    )?;
    let target = parse_probe_target(target)?;
    if udp {
        return probe_udp_outbound(
            &runtime,
            target,
            payload,
            expect,
            first_byte_timeout,
            output,
            writer,
        );
    }
    let mut report = ConnectionReport::new("probe-outbound", target.clone(), RouteAction::Direct);
    let mut remote = match connect_by_route(&target, &runtime) {
        Ok(RouteConnect::Direct {
            stream,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            stream
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err("probe route blocked".to_string());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            let detail = format!("outbound route is not implemented: {tag}");
            report.record_error_detail(ConnectionErrorKind::UnsupportedOutbound, detail.clone());
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(detail);
        }
        Err(error) => {
            report.record_error_detail(ConnectionErrorKind::from_io(&error), error.to_string());
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!("probe connect failed: {error}"));
        }
    };

    if !payload.is_empty() {
        remote
            .write_all(payload)
            .map_err(|error| probe_io_error(error, &mut report, &mut writer, output))?;
        report.upload_bytes = payload.len() as u64;
    }

    if let Some(expected) = expect {
        let started = Instant::now();
        let mut received = vec![0; expected.len()];
        remote
            .read_exact(&mut received)
            .map_err(|error| probe_io_error(error, &mut report, &mut writer, output))?;
        report.record_first_byte_duration(started.elapsed());
        report.download_bytes = received.len() as u64;
        if received != expected {
            report.record_error(ConnectionErrorKind::ProtocolError);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!(
                "probe response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&received)
            ));
        }
    }

    write_probe_result(&mut writer, "ok", &report, output)
}

fn write_smoke_connect(
    client: &mut TcpStream,
    target: &OutboundTarget,
    inbound: SmokeInboundKind,
) -> Result<(), String> {
    match inbound {
        SmokeInboundKind::Socks5 => write_socks5_smoke_connect(client, target),
        SmokeInboundKind::HttpConnect => write_http_connect_smoke_connect(client, target),
    }
}

fn write_socks5_smoke_connect(
    client: &mut TcpStream,
    target: &OutboundTarget,
) -> Result<(), String> {
    client
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|error| format!("write smoke socks5 hello: {error}"))?;
    let mut hello = [0; 2];
    client
        .read_exact(&mut hello)
        .map_err(|error| format!("read smoke socks5 hello response: {error}"))?;
    if hello != [0x05, 0x00] {
        return Err(format!("unexpected smoke socks5 hello response: {hello:?}"));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host = target.host.as_bytes();
            if host.len() > u8::MAX as usize {
                return Err(format!("smoke target host is too long: {}", target.host));
            }
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host);
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    client
        .write_all(&request)
        .map_err(|error| format!("write smoke socks5 connect: {error}"))?;
    let mut response = [0; 10];
    client
        .read_exact(&mut response)
        .map_err(|error| format!("read smoke socks5 connect response: {error}"))?;
    if response[1] != 0x00 {
        return Err(format!("smoke socks5 connect failed: {response:?}"));
    }
    Ok(())
}

fn write_http_connect_smoke_connect(
    client: &mut TcpStream,
    target: &OutboundTarget,
) -> Result<(), String> {
    let authority = format!("{}:{}", target.host, target.port);
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client
        .write_all(request.as_bytes())
        .map_err(|error| format!("write smoke http connect: {error}"))?;

    let mut response = Vec::new();
    let mut byte = [0; 1];
    while response.len() < 1024 {
        client
            .read_exact(&mut byte)
            .map_err(|error| format!("read smoke http connect response: {error}"))?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err("smoke http connect response header is too large".to_string());
    }
    if !response.starts_with(b"HTTP/1.1 200 ") {
        return Err(format!(
            "smoke http connect failed: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    Ok(())
}

fn parse_probe_target(target: &str) -> Result<OutboundTarget, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("probe target is empty".to_string());
    }
    if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid probe target: {target}"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("invalid probe target: {target}"))?
            .parse::<u16>()
            .map_err(|_| format!("invalid probe target port: {target}"))?;
        return Ok(OutboundTarget::new(host, port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("probe target requires host:port: {target}"))?;
    if host.is_empty() {
        return Err(format!("probe target host is empty: {target}"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid probe target port: {target}"))?;
    Ok(OutboundTarget::new(host, port))
}

fn probe_udp_outbound(
    runtime: &MixedProxyRuntime,
    target: OutboundTarget,
    payload: &[u8],
    expect: Option<&[u8]>,
    timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let mut report = ConnectionReport::new("probe-udp", target.clone(), RouteAction::Direct);
    let started = Instant::now();
    let response = match runtime.routes.decide(&target.route_target()).action {
        RouteAction::Direct => DirectUdpConnector::relay_datagram(&target, payload, timeout),
        RouteAction::Block => {
            report.route_action = RouteAction::Block;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err("probe route blocked".to_string());
        }
        RouteAction::Outbound(tag) => {
            report.route_action = RouteAction::Outbound(tag.clone());
            runtime
                .outbounds
                .relay_udp_datagram(&tag, &target, payload, timeout)
        }
        RouteAction::HijackDns => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hijack-dns route action is not valid for UDP probe",
        )),
    };

    let response = match response {
        Ok(response) => response,
        Err(error) => {
            report.record_error_detail(ConnectionErrorKind::from_io(&error), error.to_string());
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!("probe UDP relay failed: {error}"));
        }
    };
    report.record_first_byte_duration(started.elapsed());
    report.upload_bytes = payload.len() as u64;
    report.download_bytes = response.payload.len() as u64;

    if let Some(expected) = expect {
        if response.payload != expected {
            report.record_error(ConnectionErrorKind::ProtocolError);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!(
                "probe UDP response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&response.payload)
            ));
        }
    }

    write_probe_result(&mut writer, "ok", &report, output)
}

fn probe_io_error(
    error: io::Error,
    report: &mut ConnectionReport,
    writer: &mut impl Write,
    output: ProbeOutputFormat,
) -> String {
    report.record_error_detail(ConnectionErrorKind::from_io(&error), error.to_string());
    let _ = write_probe_result(writer, "error", report, output);
    format!("probe relay failed: {error}")
}

fn write_probe_result(
    writer: &mut impl Write,
    status: &str,
    report: &ConnectionReport,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            writeln!(writer, "probe status={status} {}", report.summary_line())
                .map_err(|error| error.to_string())
        }
        ProbeOutputFormat::Json => {
            let (route, outbound_tag) = probe_route_fields(&report.route_action);
            let value = serde_json::json!({
                "status": status,
                "inbound": report.inbound.as_str(),
                "target": format!("{}:{}", report.target.host, report.target.port),
                "target_host": report.target.host.as_str(),
                "target_port": report.target.port,
                "route": route,
                "outbound_tag": outbound_tag,
                "connect_ms": report.connect_ms,
                "first_byte_ms": report.first_byte_ms,
                "upload_bytes": report.upload_bytes,
                "download_bytes": report.download_bytes,
                "error_kind": report.error_kind.map(ConnectionErrorKind::as_str),
                "error_detail": report.error_detail.as_deref(),
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
}

fn write_smoke_result(
    writer: &mut impl Write,
    status: &str,
    report: &ConnectionReport,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            writeln!(writer, "smoke status={status} {}", report.summary_line())
                .map_err(|error| error.to_string())
        }
        ProbeOutputFormat::Json => {
            let (route, outbound_tag) = probe_route_fields(&report.route_action);
            let value = serde_json::json!({
                "status": status,
                "inbound": report.inbound.as_str(),
                "target": format!("{}:{}", report.target.host, report.target.port),
                "target_host": report.target.host.as_str(),
                "target_port": report.target.port,
                "route": route,
                "outbound_tag": outbound_tag,
                "connect_ms": report.connect_ms,
                "first_byte_ms": report.first_byte_ms,
                "upload_bytes": report.upload_bytes,
                "download_bytes": report.download_bytes,
                "error_kind": report.error_kind.map(ConnectionErrorKind::as_str),
                "error_detail": report.error_detail.as_deref(),
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
}

fn probe_route_fields(route_action: &RouteAction) -> (&'static str, Option<&str>) {
    match route_action {
        RouteAction::Direct => ("direct", None),
        RouteAction::Block => ("block", None),
        RouteAction::HijackDns => ("hijack_dns", None),
        RouteAction::Outbound(tag) => ("outbound", Some(tag.as_str())),
    }
}

pub fn write_profile_check_report_from_subscription_config_text(
    config_text: &str,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let source_format = detect_subscription_input_format(config_text);
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    let parsed = profiles_with_registry_supported_outbounds(parsed);
    let default_outbound = parsed.profiles.first().map(|profile| profile.tag.as_str());
    let status = if parsed.profiles.is_empty() {
        "error"
    } else {
        "ok"
    };

    write_profile_check_report(
        &mut writer,
        status,
        source_format.as_str(),
        &parsed,
        default_outbound,
        None,
        output,
    )?;

    if parsed.profiles.is_empty() {
        return Err("profile config did not contain supported outbounds".to_string());
    }
    Ok(())
}

fn profiles_with_registry_supported_outbounds(
    parsed: ParsedOutboundProfiles,
) -> ParsedOutboundProfiles {
    let mut profiles = Vec::new();
    let mut skipped = parsed.skipped;
    for profile in parsed.profiles {
        match OutboundRegistry::from_profiles([profile.clone()]) {
            Ok(_) => profiles.push(profile),
            Err(error) => skipped.push(SkippedOutboundProfile {
                name: profile.tag,
                reason: format!("registry unsupported: {error}"),
            }),
        }
    }
    ParsedOutboundProfiles { profiles, skipped }
}

fn write_profile_check_report(
    writer: &mut impl Write,
    status: &str,
    source_format: &str,
    parsed: &keli_protocol::ParsedOutboundProfiles,
    default_outbound: Option<&str>,
    registry_error: Option<&str>,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            let udp_supported_tags = udp_supported_tags(&parsed.profiles);
            let protocol_capabilities = protocol_capability_reports(&parsed.profiles);
            let skipped_summary = skipped_summary_reports(&parsed.skipped);
            writeln!(
                writer,
                "profile status={status} source_format={source_format} supported={} skipped={} default_outbound={} registry_error={} udp_supported={} protocol_capabilities={}",
                parsed.profiles.len(),
                parsed.skipped.len(),
                default_outbound.unwrap_or("-"),
                registry_error.unwrap_or("-"),
                udp_supported_tags.len(),
                protocol_capabilities.len()
            )
            .map_err(|error| error.to_string())?;
            for capability in &protocol_capabilities {
                writeln!(
                    writer,
                    "profile capability protocol={} tcp_relay_supported={} udp_supported={} tags={}",
                    capability.protocol,
                    capability.tcp_relay_supported,
                    capability.udp_supported,
                    capability.tags.join(",")
                )
                .map_err(|error| error.to_string())?;
            }
            for summary in &skipped_summary {
                writeln!(
                    writer,
                    "profile skipped_summary count={} names={} reason={}",
                    summary.names.len(),
                    summary.names.join(","),
                    summary.reason
                )
                .map_err(|error| error.to_string())?;
            }
            for skipped in &parsed.skipped {
                writeln!(
                    writer,
                    "profile skipped name={} reason={}",
                    skipped.name, skipped.reason
                )
                .map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        ProbeOutputFormat::Json => {
            let supported_tags: Vec<&str> = parsed
                .profiles
                .iter()
                .map(|profile| profile.tag.as_str())
                .collect();
            let udp_supported_tags = udp_supported_tags(&parsed.profiles);
            let supported: Vec<_> = parsed
                .profiles
                .iter()
                .map(|profile| {
                    serde_json::json!({
                        "tag": profile.tag.as_str(),
                        "protocol": format!("{:?}", profile.protocol),
                        "transport": format!("{:?}", profile.transport),
                        "security": format!("{:?}", profile.security),
                        "server": profile.endpoint.host.as_str(),
                        "port": profile.endpoint.port,
                        "udp_supported": profile_supports_udp(profile),
                    })
                })
                .collect();
            let skipped: Vec<_> = parsed
                .skipped
                .iter()
                .map(|skipped| {
                    serde_json::json!({
                        "name": skipped.name.as_str(),
                        "reason": skipped.reason.as_str(),
                    })
                })
                .collect();
            let skipped_summary = skipped_summary_reports(&parsed.skipped);
            let skipped_summary_json: Vec<_> = skipped_summary
                .iter()
                .map(|summary| {
                    serde_json::json!({
                        "reason": summary.reason,
                        "count": summary.names.len(),
                        "names": summary.names,
                    })
                })
                .collect();
            let protocol_capabilities = protocol_capability_reports(&parsed.profiles);
            let protocol_capabilities_json: Vec<_> = protocol_capabilities
                .iter()
                .map(|capability| {
                    serde_json::json!({
                        "protocol": capability.protocol,
                        "tcp_relay_supported": capability.tcp_relay_supported,
                        "udp_supported": capability.udp_supported,
                        "tags": capability.tags,
                    })
                })
                .collect();
            let value = serde_json::json!({
                "status": status,
                "source_format": source_format,
                "supported_count": parsed.profiles.len(),
                "skipped_count": parsed.skipped.len(),
                "skipped_summary_count": skipped_summary.len(),
                "skipped_summary": skipped_summary_json,
                "default_outbound": default_outbound,
                "registry_error": registry_error,
                "supported_tags": supported_tags,
                "udp_supported_count": udp_supported_tags.len(),
                "udp_supported_tags": udp_supported_tags,
                "protocol_capability_count": protocol_capabilities.len(),
                "protocol_capabilities": protocol_capabilities_json,
                "supported": supported,
                "skipped": skipped,
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtocolCapabilityReport {
    protocol: String,
    tcp_relay_supported: bool,
    udp_supported: bool,
    tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkippedSummaryReport {
    reason: String,
    names: Vec<String>,
}

fn skipped_summary_reports(skipped: &[SkippedOutboundProfile]) -> Vec<SkippedSummaryReport> {
    let mut summaries = Vec::<SkippedSummaryReport>::new();
    for skipped in skipped {
        if let Some(summary) = summaries
            .iter_mut()
            .find(|summary| summary.reason == skipped.reason)
        {
            summary.names.push(skipped.name.clone());
            continue;
        }
        summaries.push(SkippedSummaryReport {
            reason: skipped.reason.clone(),
            names: vec![skipped.name.clone()],
        });
    }
    summaries
}

fn udp_supported_tags(profiles: &[OutboundProfile]) -> Vec<&str> {
    profiles
        .iter()
        .filter(|profile| profile_supports_udp(profile))
        .map(|profile| profile.tag.as_str())
        .collect()
}

fn profile_supports_udp(profile: &OutboundProfile) -> bool {
    !matches!(profile.protocol, ProxyProtocol::Http | ProxyProtocol::Naive)
}

fn protocol_capability_reports(profiles: &[OutboundProfile]) -> Vec<ProtocolCapabilityReport> {
    let mut capabilities = Vec::<ProtocolCapabilityReport>::new();
    for profile in profiles {
        let protocol = format!("{:?}", profile.protocol);
        if let Some(capability) = capabilities
            .iter_mut()
            .find(|capability| capability.protocol == protocol)
        {
            capability.tags.push(profile.tag.clone());
            capability.udp_supported |= profile_supports_udp(profile);
            continue;
        }
        capabilities.push(ProtocolCapabilityReport {
            protocol,
            tcp_relay_supported: true,
            udp_supported: profile_supports_udp(profile),
            tags: vec![profile.tag.clone()],
        });
    }
    capabilities
}

fn mixed_runtime_from_parsed_profiles(
    parsed: keli_protocol::ParsedOutboundProfiles,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let available_tags: Vec<String> = parsed
        .profiles
        .iter()
        .map(|profile| profile.tag.clone())
        .collect();
    let selected_tag = match outbound_tag {
        Some(tag) => tag,
        None => available_tags
            .first()
            .cloned()
            .ok_or_else(|| "profile config did not contain supported outbounds".to_string())?,
    };
    if !available_tags.iter().any(|tag| tag == &selected_tag) {
        return Err(format!(
            "outbound tag not found: {selected_tag}; available: {}",
            available_tags.join(", ")
        ));
    }
    let outbounds = OutboundRegistry::from_profiles(parsed.profiles)
        .map_err(|error| format!("profile config contains unsupported outbound: {error}"))?;
    Ok(MixedProxyRuntime {
        routes: routes_from_cli(block_domains, RouteAction::Outbound(selected_tag)),
        relay_options,
        outbounds,
    })
}

fn mixed_runtime_from_cli(
    block_domains: Vec<String>,
    relay_options: RelayOptions,
) -> MixedProxyRuntime {
    MixedProxyRuntime {
        routes: routes_from_cli(block_domains, RouteAction::Direct),
        relay_options,
        outbounds: OutboundRegistry::new(),
    }
}

fn routes_from_cli(block_domains: Vec<String>, default_action: RouteAction) -> RouteEngine {
    let mut routes = RouteEngine::new(default_action);
    for domain in block_domains {
        routes.add_rule(keli_net_core::RouteRule {
            name: format!("block-domain:{domain}"),
            matcher: keli_net_core::RouteMatcher::DomainSuffix(domain),
            action: RouteAction::Block,
        });
    }
    routes
}

fn http_forbidden_response() -> &'static [u8] {
    b"HTTP/1.1 403 Forbidden\r\n\r\n"
}

fn relay_with_report(
    client: TcpStream,
    remote: OutboundConnection,
    report: &mut ConnectionReport,
    relay_options: RelayOptions,
) -> io::Result<()> {
    match relay_owned_bidirectional_with_options(client, remote, relay_options) {
        Ok(stats) => {
            report.record_relay_stats(stats);
            println!("{}", report.summary_line());
            Ok(())
        }
        Err(error) => {
            report.record_error(error.kind);
            println!("{}", report.summary_line());
            Err(io::Error::new(io::ErrorKind::Other, error))
        }
    }
}

fn default_relay_options() -> RelayOptions {
    RelayOptions {
        first_byte_timeout: Some(DEFAULT_FIRST_BYTE_TIMEOUT),
        idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
    }
}

fn parse_duration_ms(value: String, option: &str) -> Result<Duration, String> {
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("{option} requires a positive integer value"))?;
    if milliseconds == 0 {
        return Err(format!("{option} must be greater than 0"));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn to_io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
