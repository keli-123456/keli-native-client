use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use keli_desktop::DesktopSupportBundleExport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleSaveSummary {
    pub status: String,
    pub path: String,
    pub directory: String,
    pub byte_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportExportStorageSummary {
    pub status: String,
    pub directory: String,
    pub file_count: usize,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportExportCleanupSummary {
    pub status: String,
    pub directory: String,
    pub deleted_count: usize,
    pub reclaimed_bytes: u64,
    pub remaining_count: usize,
    pub remaining_bytes: u64,
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

pub fn support_export_record_path(directory: impl AsRef<Path>) -> PathBuf {
    directory.as_ref().join("last-support-export.json")
}

pub fn read_last_support_bundle_export(
    directory: impl AsRef<Path>,
) -> io::Result<Option<SupportBundleSaveSummary>> {
    let path = support_export_record_path(directory);
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn write_support_bundle_export(
    export: &DesktopSupportBundleExport,
    directory: impl AsRef<Path>,
) -> io::Result<SupportBundleSaveSummary> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)?;
    let path = directory.join(support_bundle_file_name(&export.format));
    fs::write(&path, &export.bytes)?;
    let summary = SupportBundleSaveSummary {
        status: "saved".to_string(),
        path: path.to_string_lossy().into_owned(),
        directory: directory.to_string_lossy().into_owned(),
        byte_count: export.bytes.len(),
    };
    write_last_support_bundle_export(directory, &summary)?;
    Ok(summary)
}

fn write_last_support_bundle_export(
    directory: impl AsRef<Path>,
    summary: &SupportBundleSaveSummary,
) -> io::Result<()> {
    let path = support_export_record_path(directory);
    let bytes = serde_json::to_vec_pretty(summary)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    fs::write(path, bytes)
}

pub fn summarize_support_export_directory(
    directory: impl AsRef<Path>,
) -> io::Result<SupportExportStorageSummary> {
    let directory = directory.as_ref();
    let artifacts = support_export_artifacts(directory)?;
    Ok(SupportExportStorageSummary {
        status: "ready".to_string(),
        directory: directory.to_string_lossy().into_owned(),
        file_count: artifacts.len(),
        byte_count: artifacts.iter().map(|artifact| artifact.byte_count).sum(),
    })
}

pub fn clear_support_export_directory(
    directory: impl AsRef<Path>,
) -> io::Result<SupportExportCleanupSummary> {
    let directory = directory.as_ref();
    let artifacts = support_export_artifacts(directory)?;
    let mut deleted_count = 0;
    let mut reclaimed_bytes = 0;
    for artifact in artifacts {
        fs::remove_file(&artifact.path)?;
        deleted_count += 1;
        reclaimed_bytes += artifact.byte_count;
    }
    let remaining = summarize_support_export_directory(directory)?;
    Ok(SupportExportCleanupSummary {
        status: "cleared".to_string(),
        directory: directory.to_string_lossy().into_owned(),
        deleted_count,
        reclaimed_bytes,
        remaining_count: remaining.file_count,
        remaining_bytes: remaining.byte_count,
    })
}

fn support_export_artifacts(directory: &Path) -> io::Result<Vec<SupportExportArtifact>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || !is_support_export_artifact(&path) {
            continue;
        }
        let byte_count = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        artifacts.push(SupportExportArtifact { path, byte_count });
    }
    Ok(artifacts)
}

fn is_support_export_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "last-support-export.json" || name.starts_with("keli-support-")
}

struct SupportExportArtifact {
    path: PathBuf,
    byte_count: u64,
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

    #[test]
    fn support_export_writer_persists_last_export_record() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("keli-support-export-record-test-{unique}"));

        let summary = write_support_bundle_export(&export(), &dir).expect("write support bundle");
        let restored = read_last_support_bundle_export(&dir)
            .expect("read support record")
            .expect("support record");

        assert_eq!(restored, summary);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn support_export_record_reader_ignores_missing_record() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("keli-support-export-missing-record-test-{unique}"));

        let restored = read_last_support_bundle_export(&dir).expect("read missing support record");

        assert_eq!(restored, None);
    }

    #[test]
    fn support_export_record_reader_ignores_invalid_json() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("keli-support-export-invalid-record-test-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(support_export_record_path(&dir), b"{not-json").expect("write invalid record");

        let restored = read_last_support_bundle_export(&dir).expect("read invalid support record");

        assert_eq!(restored, None);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn support_export_directory_summary_counts_only_keli_artifacts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("keli-support-cleanup-summary-test-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(dir.join("keli-support-a.json"), b"12345").expect("write bundle");
        fs::write(support_export_record_path(&dir), b"{}").expect("write record");
        fs::write(dir.join("notes.txt"), b"keep").expect("write unrelated");

        let summary = summarize_support_export_directory(&dir).expect("summarize support dir");

        assert_eq!(summary.status, "ready");
        assert_eq!(summary.directory, dir.to_string_lossy());
        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.byte_count, 7);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn support_export_directory_summary_handles_missing_directory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("keli-support-cleanup-missing-test-{unique}"));

        let summary =
            summarize_support_export_directory(&dir).expect("summarize missing support dir");

        assert_eq!(summary.file_count, 0);
        assert_eq!(summary.byte_count, 0);
    }

    #[test]
    fn support_export_cleanup_deletes_only_keli_artifacts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("keli-support-cleanup-delete-test-{unique}"));
        fs::create_dir_all(&dir).expect("create dir");
        let bundle = dir.join("keli-support-a.json");
        let unrelated = dir.join("notes.txt");
        fs::write(&bundle, b"12345").expect("write bundle");
        fs::write(support_export_record_path(&dir), b"{}").expect("write record");
        fs::write(&unrelated, b"keep").expect("write unrelated");

        let summary = clear_support_export_directory(&dir).expect("clear support dir");

        assert_eq!(summary.status, "cleared");
        assert_eq!(summary.deleted_count, 2);
        assert_eq!(summary.reclaimed_bytes, 7);
        assert_eq!(summary.remaining_count, 0);
        assert_eq!(summary.remaining_bytes, 0);
        assert!(!bundle.exists());
        assert!(unrelated.exists());
        assert!(!support_export_record_path(&dir).exists());

        let _ = fs::remove_dir_all(dir);
    }
}
