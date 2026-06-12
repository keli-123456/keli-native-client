use serde::{Deserialize, Serialize};

use crate::status::DesktopStatusSnapshot;

pub const DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSupportBundleExport {
    pub format: String,
    pub byte_count: usize,
    pub bytes: Vec<u8>,
}

pub fn build_desktop_support_bundle_export(
    core_support_bundle: serde_json::Value,
    desktop_status: &DesktopStatusSnapshot,
    managed_runtime_status: serde_json::Value,
) -> Result<DesktopSupportBundleExport, String> {
    let value = serde_json::json!({
        "status": "ok",
        "kind": "keli_desktop_support_bundle",
        "schema_version": DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION,
        "desktop_status": desktop_status,
        "managed_runtime_status": managed_runtime_status,
        "core_support_bundle": core_support_bundle,
        "redaction": {
            "profile_config_text": "omitted",
            "credentials": "omitted",
            "server_endpoints": "omitted",
            "subscription_url": "scheme-host-port-flags-only"
        },
    });
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    Ok(DesktopSupportBundleExport {
        format: "json".to_string(),
        byte_count: bytes.len(),
        bytes,
    })
}
