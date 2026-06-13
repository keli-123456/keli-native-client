use std::io;
use std::path::{Path, PathBuf};

use keli_desktop::DesktopTrafficMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellSettings {
    pub traffic_mode: DesktopTrafficMode,
    pub start_with_windows: bool,
    pub launch_minimized: bool,
    pub auto_start_core: bool,
    pub mixed_port: u16,
    pub socks_port: u16,
    pub http_port: u16,
    pub dns_mode: String,
    pub tun_stack: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopShellSettingsSaveSummary {
    pub status: String,
    pub path: String,
    pub settings: DesktopShellSettings,
}

impl Default for DesktopShellSettings {
    fn default() -> Self {
        Self {
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
            start_with_windows: false,
            launch_minimized: true,
            auto_start_core: false,
            mixed_port: 7890,
            socks_port: 7891,
            http_port: 7892,
            dns_mode: "fake-ip".to_string(),
            tun_stack: "system".to_string(),
        }
    }
}

pub fn default_desktop_shell_settings_path() -> PathBuf {
    if let Some(app_data) = std::env::var_os("APPDATA") {
        return PathBuf::from(app_data)
            .join("Keli")
            .join("desktop-settings.json");
    }
    std::env::temp_dir()
        .join("keli")
        .join("desktop-settings.json")
}

pub fn read_desktop_shell_settings(path: impl AsRef<Path>) -> io::Result<DesktopShellSettings> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DesktopShellSettings::default()),
        Err(error) => Err(error),
    }
}

pub fn write_desktop_shell_settings(
    path: impl AsRef<Path>,
    settings: &DesktopShellSettings,
) -> io::Result<DesktopShellSettingsSaveSummary> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    std::fs::write(path, bytes)?;
    Ok(DesktopShellSettingsSaveSummary {
        status: "saved".to_string(),
        path: path.to_string_lossy().into_owned(),
        settings: settings.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use keli_desktop::DesktopTrafficMode;

    fn test_dir(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("keli-desktop-settings-{label}-{unique}"))
    }

    #[test]
    fn desktop_settings_round_trip_persists_form_values() {
        let dir = test_dir("round-trip");
        let path = dir.join("desktop-settings.json");
        let settings = DesktopShellSettings {
            traffic_mode: DesktopTrafficMode::Tun,
            start_with_windows: true,
            launch_minimized: false,
            auto_start_core: true,
            mixed_port: 17890,
            socks_port: 17891,
            http_port: 17892,
            dns_mode: "redir-host".to_string(),
            tun_stack: "gvisor".to_string(),
        };

        let summary = write_desktop_shell_settings(&path, &settings).expect("write settings");
        let restored = read_desktop_shell_settings(&path).expect("read settings");

        assert_eq!(summary.status, "saved");
        assert_eq!(summary.path, path.to_string_lossy());
        assert_eq!(summary.settings, settings);
        assert_eq!(restored, settings);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_settings_reader_uses_default_for_missing_or_invalid_json() {
        let dir = test_dir("invalid");
        let missing = dir.join("missing.json");
        let invalid = dir.join("invalid.json");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(&invalid, b"{not-json").expect("write invalid");

        assert_eq!(
            read_desktop_shell_settings(&missing).expect("read missing"),
            DesktopShellSettings::default()
        );
        assert_eq!(
            read_desktop_shell_settings(&invalid).expect("read invalid"),
            DesktopShellSettings::default()
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
