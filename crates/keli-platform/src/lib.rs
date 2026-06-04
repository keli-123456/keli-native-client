use std::fmt;
use std::net::IpAddr;
use std::process::Command;

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
    pub running: bool,
    pub interface_name: Option<String>,
    pub address_cidr: Option<String>,
    pub mtu: Option<u16>,
    pub dns_hijack: Option<bool>,
    pub error: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTunDeviceController {
    platform: PlatformKind,
}

impl NativeTunDeviceController {
    pub fn new() -> Self {
        Self {
            platform: PlatformKind::current(),
        }
    }

    pub fn for_platform(platform: PlatformKind) -> Self {
        Self { platform }
    }
}

impl Default for NativeTunDeviceController {
    fn default() -> Self {
        Self::new()
    }
}

impl TunDeviceController for NativeTunDeviceController {
    fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        match self.platform {
            PlatformKind::Windows | PlatformKind::Android => {
                Ok(TunDeviceSnapshot::stopped_supported_without_backend())
            }
            ref platform => Err(TunDeviceError::UnsupportedPlatform(platform.clone())),
        }
    }

    fn start(&self, config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
        config.validate()?;
        match self.platform {
            PlatformKind::Windows | PlatformKind::Android => {
                Err(TunDeviceError::LifecycleUnavailable(self.platform.clone()))
            }
            ref platform => Err(TunDeviceError::UnsupportedPlatform(platform.clone())),
        }
    }

    fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        self.snapshot()
    }
}

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
    fn native_tun_controller_reports_lifecycle_boundary() {
        let windows = NativeTunDeviceController::for_platform(PlatformKind::Windows);
        let snapshot = windows.snapshot().expect("windows TUN status");

        assert!(snapshot.supported);
        assert!(!snapshot.lifecycle_available);
        assert!(!snapshot.running);
        assert_eq!(
            windows
                .start(
                    &TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid config")
                )
                .expect_err("native backend is not wired yet"),
            TunDeviceError::LifecycleUnavailable(PlatformKind::Windows)
        );

        let linux = NativeTunDeviceController::for_platform(PlatformKind::Linux);
        assert_eq!(
            linux.snapshot().expect_err("linux TUN unsupported"),
            TunDeviceError::UnsupportedPlatform(PlatformKind::Linux)
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
        let controller = NativeTunDeviceController::for_platform(PlatformKind::Windows);

        let preflight = TunDevicePreflight::check(&controller, config);

        assert_eq!(
            preflight.readiness,
            TunDeviceReadiness::LifecycleUnavailable
        );
        assert!(!preflight.ready);
        assert!(preflight.status.supported);
        assert!(!preflight.status.lifecycle_available);
        assert_eq!(
            preflight.reason.as_deref(),
            Some("TUN lifecycle backend is unavailable")
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
