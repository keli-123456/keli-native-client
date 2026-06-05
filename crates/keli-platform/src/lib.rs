use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformKind {
    Windows,
    Android,
    Macos,
    Linux,
    Unknown,
}

impl PlatformKind {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "android") {
            Self::Android
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMode {
    SystemProxy,
    Tun,
    MixedInboundOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub platform: PlatformKind,
    pub system_proxy: bool,
    pub tun: bool,
    pub secure_storage: bool,
    pub process_supervision: bool,
}

impl PlatformCapabilities {
    pub fn detect() -> Self {
        match PlatformKind::current() {
            PlatformKind::Windows => Self {
                platform: PlatformKind::Windows,
                system_proxy: true,
                tun: true,
                secure_storage: true,
                process_supervision: true,
            },
            PlatformKind::Android => Self {
                platform: PlatformKind::Android,
                system_proxy: false,
                tun: true,
                secure_storage: true,
                process_supervision: true,
            },
            platform => Self {
                platform,
                system_proxy: false,
                tun: false,
                secure_storage: false,
                process_supervision: false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyConfig {
    pub server: String,
    pub bypass: Vec<String>,
}

impl SystemProxyConfig {
    pub fn new(server: impl Into<String>) -> Result<Self, SystemProxyError> {
        let server = server.into();
        validate_proxy_server(&server)?;
        Ok(Self {
            server,
            bypass: Vec::new(),
        })
    }

    pub fn mixed_inbound(listen: &str, port: u16) -> Result<Self, SystemProxyError> {
        Self::new(format!("{listen}:{port}"))
    }

    pub fn with_bypass(mut self, bypass: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.bypass = bypass.into_iter().map(Into::into).collect();
        self
    }

    pub fn bypass_value(&self) -> Option<String> {
        if self.bypass.is_empty() {
            None
        } else {
            Some(self.bypass.join(";"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemProxySnapshot {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
}

impl SystemProxySnapshot {
    pub fn enabled(&self) -> bool {
        self.proxy_enable.unwrap_or(0) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyStatus {
    pub supported: bool,
    pub enabled: Option<bool>,
    pub server: Option<String>,
    pub error: Option<String>,
}

impl SystemProxyStatus {
    pub fn detect() -> Self {
        let controller = NativeSystemProxyController::new();
        match controller.snapshot() {
            Ok(snapshot) => Self {
                supported: true,
                enabled: Some(snapshot.enabled()),
                server: snapshot.proxy_server,
                error: None,
            },
            Err(SystemProxyError::UnsupportedPlatform(_)) => Self {
                supported: false,
                enabled: None,
                server: None,
                error: None,
            },
            Err(error) => Self {
                supported: true,
                enabled: None,
                server: None,
                error: Some(error.to_string()),
            },
        }
    }
}

pub trait SystemProxyController {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError>;
    fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxySnapshot, SystemProxyError>;
    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceConfig {
    pub interface_name: String,
    pub address_cidr: String,
    pub mtu: u16,
    pub dns_hijack: bool,
}

impl TunDeviceConfig {
    pub fn new(
        interface_name: impl Into<String>,
        address_cidr: impl Into<String>,
        mtu: u16,
    ) -> Result<Self, TunDeviceError> {
        let config = Self {
            interface_name: interface_name.into(),
            address_cidr: address_cidr.into(),
            mtu,
            dns_hijack: false,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_dns_hijack(mut self, dns_hijack: bool) -> Self {
        self.dns_hijack = dns_hijack;
        self
    }

    pub fn validate(&self) -> Result<(), TunDeviceError> {
        validate_tun_interface_name(&self.interface_name)?;
        validate_tun_address_cidr(&self.address_cidr)?;
        validate_tun_mtu(self.mtu)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceSnapshot {
    pub supported: bool,
    pub lifecycle_available: bool,
    pub packet_io_available: bool,
    pub running: bool,
    pub interface_name: Option<String>,
    pub address_cidr: Option<String>,
    pub mtu: Option<u16>,
    pub dns_hijack: Option<bool>,
}

impl TunDeviceSnapshot {
    fn unsupported() -> Self {
        Self {
            supported: false,
            lifecycle_available: false,
            packet_io_available: false,
            running: false,
            interface_name: None,
            address_cidr: None,
            mtu: None,
            dns_hijack: None,
        }
    }

    fn stopped_supported_without_backend() -> Self {
        Self {
            supported: true,
            lifecycle_available: false,
            packet_io_available: false,
            running: false,
            interface_name: None,
            address_cidr: None,
            mtu: None,
            dns_hijack: None,
        }
    }

    pub fn running(config: &TunDeviceConfig) -> Self {
        Self {
            supported: true,
            lifecycle_available: true,
            packet_io_available: true,
            running: true,
            interface_name: Some(config.interface_name.clone()),
            address_cidr: Some(config.address_cidr.clone()),
            mtu: Some(config.mtu),
            dns_hijack: Some(config.dns_hijack),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceStatus {
    pub supported: bool,
    pub lifecycle_available: bool,
    pub packet_io_available: bool,
    pub running: bool,
    pub interface_name: Option<String>,
    pub address_cidr: Option<String>,
    pub mtu: Option<u16>,
    pub dns_hijack: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunBackendStatus {
    pub platform: PlatformKind,
    pub backend: String,
    pub supported: bool,
    pub lifecycle_wired: bool,
    pub packet_io_wired: bool,
    pub route_takeover_wired: bool,
    pub driver_library_present: bool,
    pub driver_api_available: bool,
    pub driver_library_path: Option<String>,
    pub driver_api_error: Option<String>,
    pub install_required: bool,
    pub searched_paths: Vec<String>,
    pub reason: Option<String>,
}

impl TunBackendStatus {
    pub fn detect() -> Self {
        NativeTunDeviceController::new().backend_status()
    }

    pub fn backend_label(&self) -> &str {
        &self.backend
    }

    pub fn is_ready(&self) -> bool {
        self.supported
            && self.lifecycle_wired
            && self.packet_io_wired
            && self.route_takeover_wired
            && self.driver_api_available
            && !self.install_required
    }
}

impl TunDeviceStatus {
    pub fn detect() -> Self {
        let controller = NativeTunDeviceController::new();
        match controller.snapshot() {
            Ok(snapshot) => Self::from_snapshot(snapshot, None),
            Err(TunDeviceError::UnsupportedPlatform(_)) => {
                Self::from_snapshot(TunDeviceSnapshot::unsupported(), None)
            }
            Err(error) => Self::from_snapshot(TunDeviceSnapshot::unsupported(), Some(error)),
        }
    }

    fn from_snapshot(snapshot: TunDeviceSnapshot, error: Option<TunDeviceError>) -> Self {
        Self {
            supported: snapshot.supported,
            lifecycle_available: snapshot.lifecycle_available,
            packet_io_available: snapshot.packet_io_available,
            running: snapshot.running,
            interface_name: snapshot.interface_name,
            address_cidr: snapshot.address_cidr,
            mtu: snapshot.mtu,
            dns_hijack: snapshot.dns_hijack,
            error: error.map(|error| error.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunDeviceReadiness {
    Ready,
    AlreadyRunning,
    RunningConflict,
    LifecycleUnavailable,
    PacketIoUnavailable,
    Unsupported,
    InvalidConfig,
    SnapshotFailed,
}

impl TunDeviceReadiness {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::AlreadyRunning => "already-running",
            Self::RunningConflict => "running-conflict",
            Self::LifecycleUnavailable => "lifecycle-unavailable",
            Self::PacketIoUnavailable => "packet-io-unavailable",
            Self::Unsupported => "unsupported",
            Self::InvalidConfig => "invalid-config",
            Self::SnapshotFailed => "snapshot-failed",
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready | Self::AlreadyRunning)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDevicePreflight {
    pub config: TunDeviceConfig,
    pub status: TunDeviceStatus,
    pub readiness: TunDeviceReadiness,
    pub ready: bool,
    pub reason: Option<String>,
}

impl TunDevicePreflight {
    pub fn check<C: TunDeviceController + ?Sized>(controller: &C, config: TunDeviceConfig) -> Self {
        if let Err(error) = config.validate() {
            return Self::from_parts(
                config,
                TunDeviceStatus::from_snapshot(
                    TunDeviceSnapshot::unsupported(),
                    Some(error.clone()),
                ),
                TunDeviceReadiness::InvalidConfig,
                Some(error.to_string()),
            );
        }

        match controller.snapshot() {
            Ok(snapshot) => {
                let readiness = tun_readiness_from_snapshot(&snapshot, &config);
                let reason = tun_readiness_reason(&readiness, &snapshot, None);
                Self::from_parts(
                    config,
                    TunDeviceStatus::from_snapshot(snapshot, None),
                    readiness,
                    reason,
                )
            }
            Err(TunDeviceError::UnsupportedPlatform(platform)) => {
                let error = TunDeviceError::UnsupportedPlatform(platform);
                Self::from_parts(
                    config,
                    TunDeviceStatus::from_snapshot(TunDeviceSnapshot::unsupported(), None),
                    TunDeviceReadiness::Unsupported,
                    Some(error.to_string()),
                )
            }
            Err(error) => Self::from_parts(
                config,
                TunDeviceStatus::from_snapshot(
                    TunDeviceSnapshot::unsupported(),
                    Some(error.clone()),
                ),
                TunDeviceReadiness::SnapshotFailed,
                Some(error.to_string()),
            ),
        }
    }

    fn from_parts(
        config: TunDeviceConfig,
        status: TunDeviceStatus,
        readiness: TunDeviceReadiness,
        reason: Option<String>,
    ) -> Self {
        let ready = readiness.is_ready();
        Self {
            config,
            status,
            readiness,
            ready,
            reason,
        }
    }
}

pub trait TunDeviceController {
    fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError>;
    fn start(&self, config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError>;
    fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError>;
}

pub trait TunPacketIo {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunDeviceError>;
}

pub trait TunPacketIoController: TunDeviceController {
    type PacketIo: TunPacketIo;

    fn open_packet_io(&self, config: &TunDeviceConfig) -> Result<Self::PacketIo, TunDeviceError>;
}

#[derive(Debug, Clone)]
pub struct NativeTunDeviceController {
    platform: PlatformKind,
    state: Arc<Mutex<NativeTunControllerState>>,
}

#[derive(Debug, Default)]
struct NativeTunControllerState {
    active_config: Option<TunDeviceConfig>,
    #[cfg(windows)]
    windows_adapter: Option<Arc<windows_tun::WintunAdapter>>,
    #[cfg(windows)]
    windows_route_takeover: Option<WindowsTunRouteTakeoverState>,
}

#[derive(Debug)]
pub struct NativeTunPacketIo {
    platform: PlatformKind,
    #[cfg(windows)]
    windows_session: Option<windows_tun::WintunSession>,
}

impl NativeTunDeviceController {
    pub fn new() -> Self {
        Self {
            platform: PlatformKind::current(),
            state: Arc::new(Mutex::new(NativeTunControllerState::default())),
        }
    }

    pub fn for_platform(platform: PlatformKind) -> Self {
        Self {
            platform,
            state: Arc::new(Mutex::new(NativeTunControllerState::default())),
        }
    }

    pub fn backend_status(&self) -> TunBackendStatus {
        match self.platform {
            PlatformKind::Windows => windows_tun_backend_status(windows_tun_library_search_paths()),
            PlatformKind::Android => TunBackendStatus {
                platform: PlatformKind::Android,
                backend: "android-vpn-service".to_string(),
                supported: true,
                lifecycle_wired: false,
                packet_io_wired: false,
                route_takeover_wired: false,
                driver_library_present: false,
                driver_api_available: false,
                driver_library_path: None,
                driver_api_error: None,
                install_required: false,
                searched_paths: Vec::new(),
                reason: Some("Android VpnService bridge is not wired yet".to_string()),
            },
            ref platform => TunBackendStatus {
                platform: platform.clone(),
                backend: "unsupported".to_string(),
                supported: false,
                lifecycle_wired: false,
                packet_io_wired: false,
                route_takeover_wired: false,
                driver_library_present: false,
                driver_api_available: false,
                driver_library_path: None,
                driver_api_error: None,
                install_required: false,
                searched_paths: Vec::new(),
                reason: Some(format!("TUN backend is unsupported on {platform:?}")),
            },
        }
    }
}

impl Default for NativeTunDeviceController {
    fn default() -> Self {
        Self::new()
    }
}

impl TunPacketIo for NativeTunPacketIo {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError> {
        #[cfg(windows)]
        if let Some(session) = self.windows_session.as_mut() {
            return session.read_packet();
        }

        Err(TunDeviceError::LifecycleUnavailable(self.platform.clone()))
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunDeviceError> {
        #[cfg(windows)]
        if let Some(session) = self.windows_session.as_mut() {
            return session.write_packet(packet);
        }

        Err(TunDeviceError::LifecycleUnavailable(self.platform.clone()))
    }
}

impl TunPacketIoController for NativeTunDeviceController {
    type PacketIo = NativeTunPacketIo;

    fn open_packet_io(&self, config: &TunDeviceConfig) -> Result<Self::PacketIo, TunDeviceError> {
        config.validate()?;
        match self.platform {
            PlatformKind::Windows => {
                #[cfg(windows)]
                {
                    let adapter = {
                        let state = self.state.lock().map_err(|_| {
                            TunDeviceError::Io("TUN controller state lock poisoned".to_string())
                        })?;
                        let Some(active_config) = state.active_config.as_ref() else {
                            return Err(TunDeviceError::LifecycleUnavailable(
                                PlatformKind::Windows,
                            ));
                        };
                        if active_config != config {
                            return Err(TunDeviceError::Io(format!(
                                "active TUN config is {}, not {}",
                                active_config.interface_name, config.interface_name
                            )));
                        }
                        state.windows_adapter.as_ref().cloned().ok_or_else(|| {
                            TunDeviceError::LifecycleUnavailable(PlatformKind::Windows)
                        })?
                    };
                    let session = adapter.start_session()?;
                    Ok(NativeTunPacketIo {
                        platform: PlatformKind::Windows,
                        windows_session: Some(session),
                    })
                }
                #[cfg(not(windows))]
                {
                    Err(TunDeviceError::LifecycleUnavailable(PlatformKind::Windows))
                }
            }
            PlatformKind::Android => {
                Err(TunDeviceError::LifecycleUnavailable(PlatformKind::Android))
            }
            ref platform => Err(TunDeviceError::UnsupportedPlatform(platform.clone())),
        }
    }
}

impl TunDeviceController for NativeTunDeviceController {
    fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        match self.platform {
            PlatformKind::Windows => {
                if let Some(config) = self
                    .state
                    .lock()
                    .map_err(|_| {
                        TunDeviceError::Io("TUN controller state lock poisoned".to_string())
                    })?
                    .active_config
                    .clone()
                {
                    return Ok(TunDeviceSnapshot::running(&config));
                }
                Ok(windows_tun_stopped_snapshot())
            }
            PlatformKind::Android => Ok(TunDeviceSnapshot::stopped_supported_without_backend()),
            ref platform => Err(TunDeviceError::UnsupportedPlatform(platform.clone())),
        }
    }

    fn start(&self, config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
        config.validate()?;
        match self.platform {
            PlatformKind::Windows => {
                #[cfg(windows)]
                {
                    let adapter = windows_tun::WintunAdapter::open_or_create(config)?;
                    let route_takeover = windows_configure_tun_interface(config)?;
                    let mut state = self.state.lock().map_err(|_| {
                        TunDeviceError::Io("TUN controller state lock poisoned".to_string())
                    })?;
                    state.active_config = Some(config.clone());
                    state.windows_adapter = Some(Arc::new(adapter));
                    state.windows_route_takeover = Some(route_takeover);
                    Ok(TunDeviceSnapshot::running(config))
                }
                #[cfg(not(windows))]
                {
                    Err(TunDeviceError::LifecycleUnavailable(PlatformKind::Windows))
                }
            }
            PlatformKind::Android => {
                Err(TunDeviceError::LifecycleUnavailable(PlatformKind::Android))
            }
            ref platform => Err(TunDeviceError::UnsupportedPlatform(platform.clone())),
        }
    }

    fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        match self.platform {
            PlatformKind::Windows => {
                let (route_takeover, adapter) = {
                    let mut state = self.state.lock().map_err(|_| {
                        TunDeviceError::Io("TUN controller state lock poisoned".to_string())
                    })?;
                    state.active_config = None;
                    (
                        state.windows_route_takeover.take(),
                        state.windows_adapter.take(),
                    )
                };
                if let Some(route_takeover) = route_takeover {
                    route_takeover.restore()?;
                }
                drop(adapter);
                Ok(windows_tun_stopped_snapshot())
            }
            PlatformKind::Android => self.snapshot(),
            ref platform => Err(TunDeviceError::UnsupportedPlatform(platform.clone())),
        }
    }
}

fn windows_tun_backend_status(search_paths: Vec<PathBuf>) -> TunBackendStatus {
    let found_path = search_paths.iter().find(|path| path.is_file()).cloned();
    let driver_library_present = found_path.is_some();
    let driver_api_result = found_path
        .as_deref()
        .map(windows_tun_driver_api_available)
        .transpose();
    let (driver_api_available, driver_api_error) = match driver_api_result {
        Ok(Some(())) => (true, None),
        Ok(None) => (false, None),
        Err(error) => (false, Some(error)),
    };
    let install_required = !driver_library_present || !driver_api_available;
    TunBackendStatus {
        platform: PlatformKind::Windows,
        backend: "wintun".to_string(),
        supported: true,
        lifecycle_wired: true,
        packet_io_wired: true,
        route_takeover_wired: true,
        driver_library_present,
        driver_api_available,
        driver_library_path: found_path.map(|path| path.display().to_string()),
        driver_api_error: driver_api_error.clone(),
        install_required,
        searched_paths: search_paths
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
        reason: Some(if !driver_library_present {
            "Wintun library was not found; bundle a valid wintun.dll".to_string()
        } else if let Some(error) = driver_api_error {
            format!("Wintun library was found, but its API could not be loaded: {error}")
        } else {
            "Wintun lifecycle and packet I/O bridge is wired".to_string()
        }),
    }
}

fn windows_tun_stopped_snapshot() -> TunDeviceSnapshot {
    let backend = windows_tun_backend_status(windows_tun_library_search_paths());
    if backend.driver_api_available {
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
    } else {
        TunDeviceSnapshot::stopped_supported_without_backend()
    }
}

fn windows_tun_driver_api_available(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_tun::WintunLibrary::load_from_path(path)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("Wintun API can only be loaded on Windows".to_string())
    }
}

fn windows_tun_library_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = std::env::var_os("KELI_WINTUN_DLL") {
        paths.push(PathBuf::from(path));
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            paths.push(dir.join("wintun.dll"));
        }
    }
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        let system_root = PathBuf::from(system_root);
        paths.push(system_root.join("System32").join("wintun.dll"));
    }
    paths.push(PathBuf::from(r"C:\Windows\System32\wintun.dll"));
    dedup_paths(paths)
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::<PathBuf>::new();
    for path in paths {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    deduped
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsTunCommand {
    program: &'static str,
    args: Vec<String>,
}

impl WindowsTunCommand {
    fn new(program: &'static str, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program,
            args: args.into_iter().collect(),
        }
    }

    fn run(&self) -> Result<(), TunDeviceError> {
        run_tun_command_checked(self.program, &self.args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsTunRouteTakeoverState {
    restore_commands: Vec<WindowsTunCommand>,
}

impl WindowsTunRouteTakeoverState {
    fn restore(self) -> Result<(), TunDeviceError> {
        let mut errors = Vec::new();
        for command in self.restore_commands.into_iter().rev() {
            if let Err(error) = command.run() {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(TunDeviceError::Io(format!(
                "restore TUN routes: {}",
                errors.join("; ")
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsTunRouteTakeoverStep {
    add: WindowsTunCommand,
    remove: WindowsTunCommand,
}

fn windows_configure_tun_interface(
    config: &TunDeviceConfig,
) -> Result<WindowsTunRouteTakeoverState, TunDeviceError> {
    let (address, prefix) = parse_tun_address_cidr_parts(&config.address_cidr)?;
    match address {
        IpAddr::V4(address) => {
            let netmask = ipv4_prefix_to_netmask(prefix)?;
            WindowsTunCommand::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv4".to_string(),
                    "set".to_string(),
                    "address".to_string(),
                    format!("name={}", config.interface_name),
                    "static".to_string(),
                    address.to_string(),
                    netmask.to_string(),
                ],
            )
            .run()?;
            WindowsTunCommand::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv4".to_string(),
                    "set".to_string(),
                    "subinterface".to_string(),
                    config.interface_name.clone(),
                    format!("mtu={}", config.mtu),
                    "store=active".to_string(),
                ],
            )
            .run()?;
        }
        IpAddr::V6(address) => {
            WindowsTunCommand::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv6".to_string(),
                    "set".to_string(),
                    "address".to_string(),
                    format!("interface={}", config.interface_name),
                    format!("address={address}/{prefix}"),
                ],
            )
            .run()?;
            WindowsTunCommand::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv6".to_string(),
                    "set".to_string(),
                    "subinterface".to_string(),
                    config.interface_name.clone(),
                    format!("mtu={}", config.mtu),
                    "store=active".to_string(),
                ],
            )
            .run()?;
        }
    };
    apply_windows_tun_route_takeover(config)
}

fn apply_windows_tun_route_takeover(
    config: &TunDeviceConfig,
) -> Result<WindowsTunRouteTakeoverState, TunDeviceError> {
    let steps = windows_tun_route_takeover_steps(config)?;
    let mut restore_commands = Vec::new();
    for step in steps {
        if let Err(error) = step.add.run() {
            let state = WindowsTunRouteTakeoverState { restore_commands };
            let restore_error = state.restore().err().map(|error| error.to_string());
            return Err(match restore_error {
                Some(restore_error) => TunDeviceError::Io(format!("{error}; {restore_error}")),
                None => error,
            });
        }
        restore_commands.push(step.remove);
    }
    Ok(WindowsTunRouteTakeoverState { restore_commands })
}

fn windows_tun_route_takeover_steps(
    config: &TunDeviceConfig,
) -> Result<Vec<WindowsTunRouteTakeoverStep>, TunDeviceError> {
    let (address, _) = parse_tun_address_cidr_parts(&config.address_cidr)?;
    let prefixes = match address {
        IpAddr::V4(_) => vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()],
        IpAddr::V6(_) => vec!["::/1".to_string(), "8000::/1".to_string()],
    };
    Ok(prefixes
        .into_iter()
        .map(|prefix| windows_tun_route_takeover_step(&config.interface_name, address, prefix))
        .collect())
}

fn windows_tun_route_takeover_step(
    interface_name: &str,
    address: IpAddr,
    prefix: String,
) -> WindowsTunRouteTakeoverStep {
    let family = match address {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    };
    let mut add_args = vec![
        "interface".to_string(),
        family.to_string(),
        "add".to_string(),
        "route".to_string(),
        format!("prefix={prefix}"),
        format!("interface={interface_name}"),
        "metric=1".to_string(),
        "store=active".to_string(),
    ];
    if matches!(address, IpAddr::V4(_)) {
        add_args.insert(6, "nexthop=0.0.0.0".to_string());
    }
    let mut remove_args = vec![
        "interface".to_string(),
        family.to_string(),
        "delete".to_string(),
        "route".to_string(),
        format!("prefix={prefix}"),
        format!("interface={interface_name}"),
    ];
    if matches!(address, IpAddr::V4(_)) {
        remove_args.push("nexthop=0.0.0.0".to_string());
    }
    WindowsTunRouteTakeoverStep {
        add: WindowsTunCommand::new("netsh", add_args),
        remove: WindowsTunCommand::new("netsh", remove_args),
    }
}

fn parse_tun_address_cidr_parts(address_cidr: &str) -> Result<(IpAddr, u8), TunDeviceError> {
    let Some((address, prefix)) = address_cidr.split_once('/') else {
        return Err(TunDeviceError::InvalidAddressCidr(address_cidr.to_string()));
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| TunDeviceError::InvalidAddressCidr(address_cidr.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| TunDeviceError::InvalidAddressCidr(address_cidr.to_string()))?;
    Ok((address, prefix))
}

fn ipv4_prefix_to_netmask(prefix: u8) -> Result<std::net::Ipv4Addr, TunDeviceError> {
    if prefix > 32 {
        return Err(TunDeviceError::InvalidAddressCidr(format!("ipv4/{prefix}")));
    }
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(std::net::Ipv4Addr::from(bits))
}

fn run_tun_command_checked(program: &str, args: &[String]) -> Result<(), TunDeviceError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| TunDeviceError::Io(error.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(TunDeviceError::Io(format!(
            "{} exited with code {}: {}",
            program,
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(windows)]
mod windows_tun {
    use super::{
        windows_tun_library_search_paths, TunDeviceConfig, TunDeviceError, WINDOWS_TUNNEL_TYPE,
    };
    use std::ffi::{c_char, c_void, CString, OsStr};
    use std::fmt;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::Arc;

    const WINTUN_RING_CAPACITY: u32 = 0x200000;
    const WINTUN_MAX_IP_PACKET_SIZE: usize = 0xFFFF;
    const ERROR_NO_MORE_ITEMS: u32 = 259;

    type Bool = i32;
    type Dword = u32;
    type Byte = u8;
    type Handle = *mut c_void;
    type HModule = *mut c_void;
    type AdapterHandle = *mut c_void;
    type SessionHandle = *mut c_void;

    type WintunCreateAdapter =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> AdapterHandle;
    type WintunOpenAdapter = unsafe extern "system" fn(*const u16) -> AdapterHandle;
    type WintunCloseAdapter = unsafe extern "system" fn(AdapterHandle);
    type WintunGetRunningDriverVersion = unsafe extern "system" fn() -> Dword;
    type WintunStartSession = unsafe extern "system" fn(AdapterHandle, Dword) -> SessionHandle;
    type WintunEndSession = unsafe extern "system" fn(SessionHandle);
    type WintunGetReadWaitEvent = unsafe extern "system" fn(SessionHandle) -> Handle;
    type WintunReceivePacket = unsafe extern "system" fn(SessionHandle, *mut Dword) -> *mut Byte;
    type WintunReleaseReceivePacket = unsafe extern "system" fn(SessionHandle, *const Byte);
    type WintunAllocateSendPacket = unsafe extern "system" fn(SessionHandle, Dword) -> *mut Byte;
    type WintunSendPacket = unsafe extern "system" fn(SessionHandle, *const Byte);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(lpLibFileName: *const u16) -> HModule;
        fn FreeLibrary(hLibModule: HModule) -> Bool;
        fn GetProcAddress(hModule: HModule, lpProcName: *const c_char) -> *mut c_void;
        fn GetLastError() -> Dword;
    }

    #[derive(Clone)]
    pub struct WintunLibrary {
        inner: Arc<WintunLibraryInner>,
    }

    struct WintunLibraryInner {
        module: HModule,
        path: PathBuf,
        create_adapter: WintunCreateAdapter,
        open_adapter: WintunOpenAdapter,
        close_adapter: WintunCloseAdapter,
        _get_running_driver_version: WintunGetRunningDriverVersion,
        start_session: WintunStartSession,
        end_session: WintunEndSession,
        get_read_wait_event: WintunGetReadWaitEvent,
        receive_packet: WintunReceivePacket,
        release_receive_packet: WintunReleaseReceivePacket,
        allocate_send_packet: WintunAllocateSendPacket,
        send_packet: WintunSendPacket,
    }

    unsafe impl Send for WintunLibraryInner {}
    unsafe impl Sync for WintunLibraryInner {}

    impl WintunLibrary {
        pub fn load_from_path(path: &Path) -> Result<Self, TunDeviceError> {
            let wide_path = wide_os_str(path.as_os_str());
            let module = unsafe { LoadLibraryW(wide_path.as_ptr()) };
            if module.is_null() {
                return Err(TunDeviceError::Io(format!(
                    "load {} failed with Windows error {}",
                    path.display(),
                    last_error()
                )));
            }

            let inner = unsafe {
                match (|| -> Result<WintunLibraryInner, TunDeviceError> {
                    Ok(WintunLibraryInner {
                        module,
                        path: path.to_path_buf(),
                        create_adapter: resolve(module, "WintunCreateAdapter")?,
                        open_adapter: resolve(module, "WintunOpenAdapter")?,
                        close_adapter: resolve(module, "WintunCloseAdapter")?,
                        _get_running_driver_version: resolve(
                            module,
                            "WintunGetRunningDriverVersion",
                        )?,
                        start_session: resolve(module, "WintunStartSession")?,
                        end_session: resolve(module, "WintunEndSession")?,
                        get_read_wait_event: resolve(module, "WintunGetReadWaitEvent")?,
                        receive_packet: resolve(module, "WintunReceivePacket")?,
                        release_receive_packet: resolve(module, "WintunReleaseReceivePacket")?,
                        allocate_send_packet: resolve(module, "WintunAllocateSendPacket")?,
                        send_packet: resolve(module, "WintunSendPacket")?,
                    })
                })() {
                    Ok(inner) => inner,
                    Err(error) => {
                        FreeLibrary(module);
                        return Err(error);
                    }
                }
            };

            Ok(Self {
                inner: Arc::new(inner),
            })
        }

        fn load_first() -> Result<Self, TunDeviceError> {
            let paths = windows_tun_library_search_paths();
            let Some(path) = paths.iter().find(|path| path.is_file()) else {
                return Err(TunDeviceError::LifecycleUnavailable(
                    super::PlatformKind::Windows,
                ));
            };
            Self::load_from_path(path)
        }

        fn create_adapter(
            &self,
            config: &TunDeviceConfig,
        ) -> Result<AdapterHandle, TunDeviceError> {
            let name = wide_str(&config.interface_name);
            let tunnel_type = wide_str(WINDOWS_TUNNEL_TYPE);
            let adapter = unsafe {
                (self.inner.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), ptr::null())
            };
            if adapter.is_null() {
                Err(TunDeviceError::Io(format!(
                    "WintunCreateAdapter({}) failed with Windows error {}",
                    config.interface_name,
                    last_error()
                )))
            } else {
                Ok(adapter)
            }
        }

        fn open_adapter(&self, interface_name: &str) -> Result<AdapterHandle, TunDeviceError> {
            let name = wide_str(interface_name);
            let adapter = unsafe { (self.inner.open_adapter)(name.as_ptr()) };
            if adapter.is_null() {
                Err(TunDeviceError::Io(format!(
                    "WintunOpenAdapter({interface_name}) failed with Windows error {}",
                    last_error()
                )))
            } else {
                Ok(adapter)
            }
        }
    }

    impl fmt::Debug for WintunLibrary {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("WintunLibrary")
                .field("path", &self.inner.path)
                .finish_non_exhaustive()
        }
    }

    impl Drop for WintunLibraryInner {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }

    #[derive(Debug)]
    pub struct WintunAdapter {
        library: WintunLibrary,
        handle: AdapterHandle,
    }

    unsafe impl Send for WintunAdapter {}
    unsafe impl Sync for WintunAdapter {}

    impl WintunAdapter {
        pub fn open_or_create(config: &TunDeviceConfig) -> Result<Self, TunDeviceError> {
            let library = WintunLibrary::load_first()?;
            let handle = match library.open_adapter(&config.interface_name) {
                Ok(handle) => handle,
                Err(_) => library.create_adapter(config)?,
            };
            Ok(Self { library, handle })
        }

        pub fn start_session(self: &Arc<Self>) -> Result<WintunSession, TunDeviceError> {
            let session =
                unsafe { (self.library.inner.start_session)(self.handle, WINTUN_RING_CAPACITY) };
            if session.is_null() {
                return Err(TunDeviceError::Io(format!(
                    "WintunStartSession failed with Windows error {}",
                    last_error()
                )));
            }
            let read_wait_event = unsafe { (self.library.inner.get_read_wait_event)(session) };
            Ok(WintunSession {
                adapter: Arc::clone(self),
                session,
                read_wait_event,
            })
        }
    }

    impl Drop for WintunAdapter {
        fn drop(&mut self) {
            unsafe {
                (self.library.inner.close_adapter)(self.handle);
            }
        }
    }

    #[derive(Debug)]
    pub struct WintunSession {
        adapter: Arc<WintunAdapter>,
        session: SessionHandle,
        read_wait_event: Handle,
    }

    unsafe impl Send for WintunSession {}

    impl WintunSession {
        pub fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError> {
            let _ = self.read_wait_event;
            let mut packet_size: Dword = 0;
            let packet = unsafe {
                (self.adapter.library.inner.receive_packet)(self.session, &mut packet_size)
            };
            if packet.is_null() {
                let error = last_error();
                if error == ERROR_NO_MORE_ITEMS {
                    return Ok(None);
                }
                return Err(TunDeviceError::Io(format!(
                    "WintunReceivePacket failed with Windows error {error}"
                )));
            }
            let bytes = unsafe {
                std::slice::from_raw_parts(packet.cast_const(), packet_size as usize).to_vec()
            };
            unsafe {
                (self.adapter.library.inner.release_receive_packet)(self.session, packet);
            }
            Ok(Some(bytes))
        }

        pub fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunDeviceError> {
            if packet.len() > WINTUN_MAX_IP_PACKET_SIZE {
                return Err(TunDeviceError::Io(format!(
                    "Wintun packet is too large: {} bytes",
                    packet.len()
                )));
            }
            let out = unsafe {
                (self.adapter.library.inner.allocate_send_packet)(
                    self.session,
                    packet.len() as Dword,
                )
            };
            if out.is_null() {
                return Err(TunDeviceError::Io(format!(
                    "WintunAllocateSendPacket failed with Windows error {}",
                    last_error()
                )));
            }
            unsafe {
                ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len());
                (self.adapter.library.inner.send_packet)(self.session, out);
            }
            Ok(())
        }
    }

    impl Drop for WintunSession {
        fn drop(&mut self) {
            unsafe {
                (self.adapter.library.inner.end_session)(self.session);
            }
        }
    }

    unsafe fn resolve<T: Copy>(module: HModule, name: &str) -> Result<T, TunDeviceError> {
        let name = CString::new(name).expect("Wintun symbol names do not contain NUL bytes");
        let proc = unsafe { GetProcAddress(module, name.as_ptr()) };
        if proc.is_null() {
            Err(TunDeviceError::Io(format!(
                "resolve {} failed with Windows error {}",
                name.to_string_lossy(),
                last_error()
            )))
        } else {
            Ok(unsafe { std::mem::transmute_copy(&proc) })
        }
    }

    fn last_error() -> Dword {
        unsafe { GetLastError() }
    }

    fn wide_str(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn wide_os_str(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
}

const WINDOWS_TUNNEL_TYPE: &str = "Keli";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunDeviceError {
    UnsupportedPlatform(PlatformKind),
    LifecycleUnavailable(PlatformKind),
    InvalidInterfaceName(String),
    InvalidAddressCidr(String),
    InvalidMtu(u16),
    Io(String),
}

impl fmt::Display for TunDeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => write!(f, "TUN is unsupported on {platform:?}"),
            Self::LifecycleUnavailable(platform) => {
                write!(f, "TUN lifecycle backend is unavailable on {platform:?}")
            }
            Self::InvalidInterfaceName(name) => write!(f, "invalid TUN interface name: {name}"),
            Self::InvalidAddressCidr(address) => write!(f, "invalid TUN address CIDR: {address}"),
            Self::InvalidMtu(mtu) => write!(f, "invalid TUN MTU: {mtu}"),
            Self::Io(error) => write!(f, "TUN command failed: {error}"),
        }
    }
}

impl std::error::Error for TunDeviceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSystemProxyController {
    platform: PlatformKind,
}

impl NativeSystemProxyController {
    pub fn new() -> Self {
        Self {
            platform: PlatformKind::current(),
        }
    }

    pub fn for_platform(platform: PlatformKind) -> Self {
        Self { platform }
    }
}

impl Default for NativeSystemProxyController {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemProxyController for NativeSystemProxyController {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
        match self.platform {
            PlatformKind::Windows => windows_system_proxy_snapshot(),
            ref platform => Err(SystemProxyError::UnsupportedPlatform(platform.clone())),
        }
    }

    fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxySnapshot, SystemProxyError> {
        validate_proxy_server(&config.server)?;
        let snapshot = self.snapshot()?;
        match self.platform {
            PlatformKind::Windows => {
                windows_set_registry_dword("ProxyEnable", 1)?;
                windows_set_registry_string("ProxyServer", &config.server)?;
                if let Some(value) = config.bypass_value() {
                    windows_set_registry_string("ProxyOverride", &value)?;
                } else {
                    windows_delete_registry_value("ProxyOverride")?;
                }
                Ok(snapshot)
            }
            ref platform => Err(SystemProxyError::UnsupportedPlatform(platform.clone())),
        }
    }

    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
        match self.platform {
            PlatformKind::Windows => {
                restore_windows_dword("ProxyEnable", snapshot.proxy_enable)?;
                restore_windows_string("ProxyServer", snapshot.proxy_server.as_deref())?;
                restore_windows_string("ProxyOverride", snapshot.proxy_override.as_deref())
            }
            ref platform => Err(SystemProxyError::UnsupportedPlatform(platform.clone())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemProxyError {
    UnsupportedPlatform(PlatformKind),
    InvalidProxyServer(String),
    Io(String),
    CommandFailed {
        program: String,
        code: Option<i32>,
        stderr: String,
    },
}

impl fmt::Display for SystemProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(f, "system proxy is unsupported on {platform:?}")
            }
            Self::InvalidProxyServer(server) => {
                write!(f, "invalid system proxy server: {server}")
            }
            Self::Io(error) => write!(f, "system proxy command failed: {error}"),
            Self::CommandFailed {
                program,
                code,
                stderr,
            } => {
                write!(
                    f,
                    "{program} exited with code {}: {stderr}",
                    code.map_or_else(|| "unknown".to_string(), |code| code.to_string())
                )
            }
        }
    }
}

impl std::error::Error for SystemProxyError {}

const WINDOWS_INTERNET_SETTINGS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn validate_proxy_server(server: &str) -> Result<(), SystemProxyError> {
    let trimmed = server.trim();
    if trimmed.is_empty()
        || trimmed.contains(char::is_whitespace)
        || !trimmed.rsplit_once(':').is_some_and(|(host, port)| {
            !host.trim_matches(['[', ']']).is_empty()
                && port.parse::<u16>().is_ok_and(|port| port != 0)
        })
    {
        return Err(SystemProxyError::InvalidProxyServer(server.to_string()));
    }
    Ok(())
}

fn validate_tun_interface_name(name: &str) -> Result<(), TunDeviceError> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed.contains(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(':')
    {
        return Err(TunDeviceError::InvalidInterfaceName(name.to_string()));
    }
    Ok(())
}

fn validate_tun_address_cidr(address_cidr: &str) -> Result<(), TunDeviceError> {
    let Some((address, prefix)) = address_cidr.split_once('/') else {
        return Err(TunDeviceError::InvalidAddressCidr(address_cidr.to_string()));
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| TunDeviceError::InvalidAddressCidr(address_cidr.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| TunDeviceError::InvalidAddressCidr(address_cidr.to_string()))?;
    let max_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(TunDeviceError::InvalidAddressCidr(address_cidr.to_string()));
    }
    Ok(())
}

fn validate_tun_mtu(mtu: u16) -> Result<(), TunDeviceError> {
    if !(1280..=9000).contains(&mtu) {
        return Err(TunDeviceError::InvalidMtu(mtu));
    }
    Ok(())
}

fn tun_readiness_from_snapshot(
    snapshot: &TunDeviceSnapshot,
    config: &TunDeviceConfig,
) -> TunDeviceReadiness {
    if !snapshot.supported {
        return TunDeviceReadiness::Unsupported;
    }
    if !snapshot.lifecycle_available {
        return TunDeviceReadiness::LifecycleUnavailable;
    }
    if !snapshot.packet_io_available {
        return TunDeviceReadiness::PacketIoUnavailable;
    }
    if snapshot.running {
        if tun_snapshot_matches_config(snapshot, config) {
            TunDeviceReadiness::AlreadyRunning
        } else {
            TunDeviceReadiness::RunningConflict
        }
    } else {
        TunDeviceReadiness::Ready
    }
}

fn tun_snapshot_matches_config(snapshot: &TunDeviceSnapshot, config: &TunDeviceConfig) -> bool {
    snapshot.interface_name.as_deref() == Some(config.interface_name.as_str())
        && snapshot.address_cidr.as_deref() == Some(config.address_cidr.as_str())
        && snapshot.mtu == Some(config.mtu)
        && snapshot.dns_hijack == Some(config.dns_hijack)
}

fn tun_readiness_reason(
    readiness: &TunDeviceReadiness,
    snapshot: &TunDeviceSnapshot,
    error: Option<&TunDeviceError>,
) -> Option<String> {
    match readiness {
        TunDeviceReadiness::Ready => None,
        TunDeviceReadiness::AlreadyRunning => {
            Some("TUN device is already running with the requested config".to_string())
        }
        TunDeviceReadiness::RunningConflict => Some(format!(
            "TUN device is already running with interface={}, address={}, mtu={}, dns_hijack={}",
            snapshot.interface_name.as_deref().unwrap_or("-"),
            snapshot.address_cidr.as_deref().unwrap_or("-"),
            snapshot
                .mtu
                .map_or_else(|| "-".to_string(), |mtu| mtu.to_string()),
            snapshot
                .dns_hijack
                .map_or_else(|| "-".to_string(), |dns_hijack| dns_hijack.to_string())
        )),
        TunDeviceReadiness::LifecycleUnavailable => {
            Some("TUN lifecycle backend is unavailable".to_string())
        }
        TunDeviceReadiness::PacketIoUnavailable => {
            Some("TUN packet I/O backend is unavailable".to_string())
        }
        TunDeviceReadiness::Unsupported => Some("TUN is unsupported on this platform".to_string()),
        TunDeviceReadiness::InvalidConfig | TunDeviceReadiness::SnapshotFailed => {
            error.map(ToString::to_string)
        }
    }
}

fn windows_system_proxy_snapshot() -> Result<SystemProxySnapshot, SystemProxyError> {
    Ok(SystemProxySnapshot {
        proxy_enable: windows_query_registry_dword("ProxyEnable")?,
        proxy_server: windows_query_registry_string("ProxyServer")?,
        proxy_override: windows_query_registry_string("ProxyOverride")?,
    })
}

fn windows_query_registry_dword(name: &str) -> Result<Option<u32>, SystemProxyError> {
    let output = run_optional_registry_command(
        "reg",
        &["query", WINDOWS_INTERNET_SETTINGS_KEY, "/v", name],
    )?;
    Ok(parse_reg_value(&output, name).and_then(|value| parse_reg_dword(&value)))
}

fn windows_query_registry_string(name: &str) -> Result<Option<String>, SystemProxyError> {
    let output = run_optional_registry_command(
        "reg",
        &["query", WINDOWS_INTERNET_SETTINGS_KEY, "/v", name],
    )?;
    Ok(parse_reg_value(&output, name))
}

fn windows_set_registry_dword(name: &str, value: u32) -> Result<(), SystemProxyError> {
    run_command_checked(
        "reg",
        &[
            "add",
            WINDOWS_INTERNET_SETTINGS_KEY,
            "/v",
            name,
            "/t",
            "REG_DWORD",
            "/d",
            &value.to_string(),
            "/f",
        ],
    )
}

fn windows_set_registry_string(name: &str, value: &str) -> Result<(), SystemProxyError> {
    run_command_checked(
        "reg",
        &[
            "add",
            WINDOWS_INTERNET_SETTINGS_KEY,
            "/v",
            name,
            "/t",
            "REG_SZ",
            "/d",
            value,
            "/f",
        ],
    )
}

fn windows_delete_registry_value(name: &str) -> Result<(), SystemProxyError> {
    run_optional_registry_command(
        "reg",
        &["delete", WINDOWS_INTERNET_SETTINGS_KEY, "/v", name, "/f"],
    )
    .map(|_| ())
}

fn restore_windows_dword(name: &str, value: Option<u32>) -> Result<(), SystemProxyError> {
    match value {
        Some(value) => windows_set_registry_dword(name, value),
        None => windows_delete_registry_value(name),
    }
}

fn restore_windows_string(name: &str, value: Option<&str>) -> Result<(), SystemProxyError> {
    match value {
        Some(value) => windows_set_registry_string(name, value),
        None => windows_delete_registry_value(name),
    }
}

fn run_command(program: &str, args: &[&str]) -> Result<String, SystemProxyError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| SystemProxyError::Io(error.to_string()))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.code() == Some(1)
        && (stderr.contains("The system was unable to find")
            || stderr.contains("找不到")
            || stderr.contains("无法找到"))
    {
        return Ok(String::new());
    }
    Err(SystemProxyError::CommandFailed {
        program: program.to_string(),
        code: output.status.code(),
        stderr,
    })
}

fn run_command_checked(program: &str, args: &[&str]) -> Result<(), SystemProxyError> {
    run_command(program, args).map(|_| ())
}

fn run_optional_registry_command(program: &str, args: &[&str]) -> Result<String, SystemProxyError> {
    match run_command(program, args) {
        Ok(output) => Ok(output),
        Err(SystemProxyError::CommandFailed { code: Some(1), .. }) => Ok(String::new()),
        Err(error) => Err(error),
    }
}

fn parse_reg_value(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix(name)?.trim_start();
        let rest = rest.strip_prefix("REG_")?;
        let (_, value) = rest.split_once(char::is_whitespace)?;
        Some(value.trim().to_string())
    })
}

fn parse_reg_dword(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[derive(Debug)]
    struct StaticTunController {
        snapshot: Result<TunDeviceSnapshot, TunDeviceError>,
    }

    impl TunDeviceController for StaticTunController {
        fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
            self.snapshot.clone()
        }

        fn start(&self, _config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
            self.snapshot()
        }

        fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
            self.snapshot()
        }
    }

    #[test]
    fn detected_capabilities_match_known_platform_shape() {
        let capabilities = PlatformCapabilities::detect();

        match capabilities.platform {
            PlatformKind::Windows => {
                assert!(capabilities.system_proxy);
                assert!(capabilities.tun);
            }
            PlatformKind::Android => {
                assert!(!capabilities.system_proxy);
                assert!(capabilities.tun);
            }
            _ => {
                assert!(!capabilities.system_proxy);
            }
        }
    }

    #[test]
    fn system_proxy_config_validates_host_and_port() {
        let config = SystemProxyConfig::mixed_inbound("127.0.0.1", 7890)
            .expect("valid mixed inbound system proxy");

        assert_eq!(config.server, "127.0.0.1:7890");
        assert_eq!(
            SystemProxyConfig::new("127.0.0.1").expect_err("missing port"),
            SystemProxyError::InvalidProxyServer("127.0.0.1".to_string())
        );
        assert_eq!(
            SystemProxyConfig::new("127.0.0.1:0").expect_err("zero port"),
            SystemProxyError::InvalidProxyServer("127.0.0.1:0".to_string())
        );
    }

    #[test]
    fn system_proxy_config_formats_bypass_list() {
        let config = SystemProxyConfig::new("127.0.0.1:7890")
            .expect("valid proxy")
            .with_bypass(["localhost", "<local>"]);

        assert_eq!(config.bypass_value().as_deref(), Some("localhost;<local>"));
    }

    #[test]
    fn parses_windows_registry_values() {
        let output = r#"
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    127.0.0.1:7890
    ProxyOverride    REG_SZ    localhost;<local>
"#;

        assert_eq!(
            parse_reg_value(output, "ProxyEnable").as_deref(),
            Some("0x1")
        );
        assert_eq!(
            parse_reg_value(output, "ProxyServer").as_deref(),
            Some("127.0.0.1:7890")
        );
        assert_eq!(
            parse_reg_value(output, "ProxyOverride").as_deref(),
            Some("localhost;<local>")
        );
        assert_eq!(parse_reg_dword("0x1"), Some(1));
    }

    #[test]
    fn non_windows_system_proxy_controller_reports_unsupported() {
        let controller = NativeSystemProxyController::for_platform(PlatformKind::Linux);

        assert_eq!(
            controller.snapshot().expect_err("unsupported platform"),
            SystemProxyError::UnsupportedPlatform(PlatformKind::Linux)
        );
    }

    #[test]
    fn tun_device_config_validates_name_cidr_and_mtu() {
        let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
            .expect("valid TUN device config")
            .with_dns_hijack(true);

        assert_eq!(config.interface_name, "keli-tun0");
        assert_eq!(config.address_cidr, "10.7.0.1/24");
        assert_eq!(config.mtu, 1500);
        assert!(config.dns_hijack);
        assert_eq!(
            TunDeviceConfig::new("bad tun", "10.7.0.1/24", 1500).expect_err("spaces are invalid"),
            TunDeviceError::InvalidInterfaceName("bad tun".to_string())
        );
        assert_eq!(
            TunDeviceConfig::new("keli-tun0", "10.7.0.1", 1500).expect_err("missing CIDR prefix"),
            TunDeviceError::InvalidAddressCidr("10.7.0.1".to_string())
        );
        assert_eq!(
            TunDeviceConfig::new("keli-tun0", "10.7.0.1/33", 1500)
                .expect_err("invalid IPv4 prefix"),
            TunDeviceError::InvalidAddressCidr("10.7.0.1/33".to_string())
        );
        assert_eq!(
            TunDeviceConfig::new("keli-tun0", "fd00::1/129", 1500)
                .expect_err("invalid IPv6 prefix"),
            TunDeviceError::InvalidAddressCidr("fd00::1/129".to_string())
        );
        assert_eq!(
            TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 576).expect_err("MTU too small"),
            TunDeviceError::InvalidMtu(576)
        );
    }

    #[test]
    fn native_tun_controller_reports_supported_boundary_without_starting_device() {
        let windows = NativeTunDeviceController::for_platform(PlatformKind::Windows);
        let snapshot = windows.snapshot().expect("windows TUN status");

        assert!(snapshot.supported);
        assert!(!snapshot.running);
        assert_eq!(
            windows
                .open_packet_io(
                    &TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid config")
                )
                .expect_err("native packet I/O requires an active TUN adapter"),
            TunDeviceError::LifecycleUnavailable(PlatformKind::Windows)
        );

        let linux = NativeTunDeviceController::for_platform(PlatformKind::Linux);
        assert_eq!(
            linux.snapshot().expect_err("linux TUN unsupported"),
            TunDeviceError::UnsupportedPlatform(PlatformKind::Linux)
        );
    }

    #[test]
    fn windows_tun_backend_status_reports_missing_wintun_library() {
        let status =
            windows_tun_backend_status(vec![PathBuf::from(r"C:\definitely-missing\wintun.dll")]);

        assert_eq!(status.platform, PlatformKind::Windows);
        assert_eq!(status.backend, "wintun");
        assert!(status.supported);
        assert!(status.lifecycle_wired);
        assert!(status.packet_io_wired);
        assert!(status.route_takeover_wired);
        assert!(!status.driver_library_present);
        assert!(!status.driver_api_available);
        assert_eq!(status.driver_api_error, None);
        assert!(status.install_required);
        assert!(!status.is_ready());
        assert_eq!(status.driver_library_path, None);
        assert_eq!(status.searched_paths.len(), 1);
        assert!(status
            .reason
            .as_deref()
            .expect("reason")
            .contains("Wintun library was not found"));
    }

    #[test]
    fn windows_tun_backend_status_reports_detected_invalid_library_without_marking_ready() {
        let temp_dir =
            std::env::temp_dir().join(format!("keli-wintun-test-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let dll_path = temp_dir.join("wintun.dll");
        std::fs::write(&dll_path, b"placeholder").expect("write placeholder dll");

        let status = windows_tun_backend_status(vec![dll_path.clone()]);

        std::fs::remove_file(&dll_path).ok();
        std::fs::remove_dir(&temp_dir).ok();

        assert_eq!(status.platform, PlatformKind::Windows);
        assert_eq!(status.backend, "wintun");
        assert!(status.supported);
        assert!(status.driver_library_present);
        assert!(!status.driver_api_available);
        assert!(status.driver_api_error.is_some());
        assert!(status.install_required);
        assert!(!status.is_ready());
        assert_eq!(
            status.driver_library_path,
            Some(dll_path.display().to_string())
        );
        assert!(status.lifecycle_wired);
        assert!(status.packet_io_wired);
        assert!(status.route_takeover_wired);
        assert!(status
            .reason
            .as_deref()
            .expect("reason")
            .contains("API could not be loaded"));
    }

    #[test]
    fn windows_tun_route_takeover_steps_use_ipv4_split_default_routes() {
        let config =
            TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");

        let steps = windows_tun_route_takeover_steps(&config).expect("route takeover steps");

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].add.program, "netsh");
        assert_eq!(
            steps[0].add.args,
            strings(&[
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=0.0.0.0/1",
                "interface=keli-tun0",
                "nexthop=0.0.0.0",
                "metric=1",
                "store=active"
            ])
        );
        assert_eq!(
            steps[1].add.args,
            strings(&[
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=128.0.0.0/1",
                "interface=keli-tun0",
                "nexthop=0.0.0.0",
                "metric=1",
                "store=active"
            ])
        );
        assert_eq!(
            steps[0].remove.args,
            strings(&[
                "interface",
                "ipv4",
                "delete",
                "route",
                "prefix=0.0.0.0/1",
                "interface=keli-tun0",
                "nexthop=0.0.0.0"
            ])
        );
    }

    #[test]
    fn windows_tun_route_takeover_steps_use_ipv6_split_default_routes() {
        let config =
            TunDeviceConfig::new("keli-tun0", "fd00::1/64", 1500).expect("valid TUN config");

        let steps = windows_tun_route_takeover_steps(&config).expect("route takeover steps");

        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0].add.args,
            strings(&[
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=::/1",
                "interface=keli-tun0",
                "metric=1",
                "store=active"
            ])
        );
        assert_eq!(
            steps[1].add.args,
            strings(&[
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=8000::/1",
                "interface=keli-tun0",
                "metric=1",
                "store=active"
            ])
        );
        assert_eq!(
            steps[1].remove.args,
            strings(&[
                "interface",
                "ipv6",
                "delete",
                "route",
                "prefix=8000::/1",
                "interface=keli-tun0"
            ])
        );
    }

    #[test]
    fn tun_device_snapshot_reports_running_config() {
        let config = TunDeviceConfig::new("keli-tun0", "fd00::1/64", 1400)
            .expect("valid IPv6 TUN config")
            .with_dns_hijack(true);
        let snapshot = TunDeviceSnapshot::running(&config);

        assert!(snapshot.supported);
        assert!(snapshot.lifecycle_available);
        assert!(snapshot.packet_io_available);
        assert!(snapshot.running);
        assert_eq!(snapshot.interface_name.as_deref(), Some("keli-tun0"));
        assert_eq!(snapshot.address_cidr.as_deref(), Some("fd00::1/64"));
        assert_eq!(snapshot.mtu, Some(1400));
        assert_eq!(snapshot.dns_hijack, Some(true));
    }

    #[test]
    fn tun_preflight_reports_lifecycle_unavailable_boundary() {
        let config =
            TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
        let controller = StaticTunController {
            snapshot: Ok(TunDeviceSnapshot::stopped_supported_without_backend()),
        };

        let preflight = TunDevicePreflight::check(&controller, config);

        assert_eq!(
            preflight.readiness,
            TunDeviceReadiness::LifecycleUnavailable
        );
        assert!(!preflight.ready);
        assert!(preflight.status.supported);
        assert!(!preflight.status.lifecycle_available);
        assert!(!preflight.status.packet_io_available);
        assert_eq!(
            preflight.reason.as_deref(),
            Some("TUN lifecycle backend is unavailable")
        );
    }

    #[test]
    fn tun_preflight_reports_packet_io_unavailable_boundary() {
        let config =
            TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
        let controller = StaticTunController {
            snapshot: Ok(TunDeviceSnapshot {
                supported: true,
                lifecycle_available: true,
                packet_io_available: false,
                running: false,
                interface_name: None,
                address_cidr: None,
                mtu: None,
                dns_hijack: None,
            }),
        };

        let preflight = TunDevicePreflight::check(&controller, config);

        assert_eq!(preflight.readiness, TunDeviceReadiness::PacketIoUnavailable);
        assert!(!preflight.ready);
        assert!(preflight.status.supported);
        assert!(preflight.status.lifecycle_available);
        assert!(!preflight.status.packet_io_available);
        assert_eq!(
            preflight.reason.as_deref(),
            Some("TUN packet I/O backend is unavailable")
        );
    }

    #[test]
    fn tun_preflight_distinguishes_ready_running_and_conflict() {
        let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
            .expect("valid TUN config")
            .with_dns_hijack(true);
        let ready_controller = StaticTunController {
            snapshot: Ok(TunDeviceSnapshot {
                supported: true,
                lifecycle_available: true,
                packet_io_available: true,
                running: false,
                interface_name: None,
                address_cidr: None,
                mtu: None,
                dns_hijack: None,
            }),
        };

        let preflight = TunDevicePreflight::check(&ready_controller, config.clone());

        assert_eq!(preflight.readiness, TunDeviceReadiness::Ready);
        assert!(preflight.ready);
        assert_eq!(preflight.reason, None);

        let running_controller = StaticTunController {
            snapshot: Ok(TunDeviceSnapshot::running(&config)),
        };
        let preflight = TunDevicePreflight::check(&running_controller, config.clone());

        assert_eq!(preflight.readiness, TunDeviceReadiness::AlreadyRunning);
        assert!(preflight.ready);

        let conflicting_config =
            TunDeviceConfig::new("keli-other0", "10.8.0.1/24", 1500).expect("valid TUN config");
        let preflight = TunDevicePreflight::check(&running_controller, conflicting_config);

        assert_eq!(preflight.readiness, TunDeviceReadiness::RunningConflict);
        assert!(!preflight.ready);
        assert!(preflight
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("interface=keli-tun0")));
    }

    #[test]
    fn tun_preflight_revalidates_public_config_fields() {
        let config = TunDeviceConfig {
            interface_name: "bad tun".to_string(),
            address_cidr: "10.7.0.1/24".to_string(),
            mtu: 1500,
            dns_hijack: false,
        };
        let controller = StaticTunController {
            snapshot: Ok(TunDeviceSnapshot::running(
                &TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config"),
            )),
        };

        let preflight = TunDevicePreflight::check(&controller, config);

        assert_eq!(preflight.readiness, TunDeviceReadiness::InvalidConfig);
        assert!(!preflight.ready);
        assert!(preflight
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("invalid TUN interface name")));
    }
}
