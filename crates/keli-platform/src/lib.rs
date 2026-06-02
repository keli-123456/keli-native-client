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
}
