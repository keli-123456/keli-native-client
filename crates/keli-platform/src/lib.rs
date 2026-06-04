use std::fmt;
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
}
