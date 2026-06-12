use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPersistedSubscription {
    pub config_text: String,
    pub selected_outbound: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSubscriptionStore {
    path: PathBuf,
}

impl DesktopSubscriptionStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn default_path() -> PathBuf {
        if let Some(app_data) = std::env::var_os("APPDATA") {
            return PathBuf::from(app_data)
                .join("Keli")
                .join("desktop-subscription.json");
        }
        std::env::temp_dir()
            .join("keli")
            .join("desktop-subscription.json")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<DesktopPersistedSubscription>, DesktopPersistenceError> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => Ok(Some(serde_json::from_str(&contents)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn save(
        &self,
        subscription: &DesktopPersistedSubscription,
    ) -> Result<(), DesktopPersistenceError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(subscription)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum DesktopPersistenceError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for DesktopPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
        }
    }
}

impl Error for DesktopPersistenceError {}

impl From<std::io::Error> for DesktopPersistenceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for DesktopPersistenceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn test_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("keli-desktop-subscription-{name}-{unique}.json"))
    }

    #[test]
    fn subscription_store_round_trips_config_and_selected_node() {
        let path = test_path("round-trip");
        let store = DesktopSubscriptionStore::new(&path);
        let persisted = DesktopPersistedSubscription {
            config_text: "proxies:\n  - name: SS-READY".to_string(),
            selected_outbound: Some("SS-READY".to_string()),
        };

        store.save(&persisted).expect("save persisted subscription");

        assert_eq!(
            store.load().expect("load persisted subscription"),
            Some(persisted)
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn subscription_store_missing_file_loads_empty() {
        let store = DesktopSubscriptionStore::new(test_path("missing"));

        assert_eq!(store.load().expect("load missing store"), None);
    }
}
