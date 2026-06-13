use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use keli_desktop::DesktopSupportBundleExport;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportBundleSaveSummary {
    pub status: String,
    pub path: String,
    pub directory: String,
    pub byte_count: usize,
}

pub fn default_support_export_dir() -> PathBuf {
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(user_profile)
            .join("Documents")
            .join("Keli")
            .join("Support");
    }
    std::env::temp_dir().join("keli").join("support")
}

pub fn write_support_bundle_export(
    export: &DesktopSupportBundleExport,
    directory: impl AsRef<Path>,
) -> io::Result<SupportBundleSaveSummary> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)?;
    let path = directory.join(support_bundle_file_name(&export.format));
    fs::write(&path, &export.bytes)?;
    Ok(SupportBundleSaveSummary {
        status: "saved".to_string(),
        path: path.to_string_lossy().into_owned(),
        directory: directory.to_string_lossy().into_owned(),
        byte_count: export.bytes.len(),
    })
}

fn support_bundle_file_name(format: &str) -> String {
    let extension = if format == "json" { "json" } else { "bin" };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("keli-support-{timestamp}.{extension}")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use keli_desktop::DesktopSupportBundleExport;

    fn export() -> DesktopSupportBundleExport {
        DesktopSupportBundleExport {
            format: "json".to_string(),
            byte_count: 18,
            bytes: br#"{"status":"ok"}"#.to_vec(),
        }
    }

    #[test]
    fn support_export_writer_creates_json_file_and_reports_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("keli-support-export-test-{unique}"));

        let summary = write_support_bundle_export(&export(), &dir).expect("write support bundle");

        assert!(summary.path.ends_with(".json"));
        assert_eq!(summary.directory, dir.to_string_lossy().as_ref());
        assert_eq!(summary.byte_count, 15);
        assert_eq!(
            fs::read_to_string(&summary.path).expect("read support bundle"),
            r#"{"status":"ok"}"#
        );

        let _ = fs::remove_dir_all(dir);
    }
}
