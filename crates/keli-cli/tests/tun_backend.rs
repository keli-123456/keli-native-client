use std::path::PathBuf;

use keli_cli::{
    write_tun_backend_check_report, write_tun_backend_install_report,
    write_tun_backend_install_report_from_source, ProbeOutputFormat, TunBackendInstallSource,
};
use serde_json::Value;

#[test]
fn tun_backend_check_json_reports_native_backend_wiring_state() {
    let mut output = Vec::new();

    write_tun_backend_check_report(ProbeOutputFormat::Json, &mut output)
        .expect("write TUN backend check");

    let report: Value = serde_json::from_slice(&output).expect("TUN backend JSON");
    assert_eq!(report["kind"], "keli_tun_backend_check");
    assert_eq!(report["status"], "not-ready");
    assert_eq!(report["backend"]["platform"], "Windows");
    assert_eq!(report["backend"]["backend"], "wintun");
    assert_eq!(report["backend"]["supported"], true);
    assert_eq!(report["backend"]["lifecycle_wired"], true);
    assert_eq!(report["backend"]["packet_io_wired"], true);
    assert_eq!(report["backend"]["route_takeover_wired"], true);
    assert!(report["backend"]["driver_api_available"].is_boolean());
    assert_eq!(
        report["status"].as_str().expect("status") == "ready",
        report["backend"]["driver_api_available"]
            .as_bool()
            .expect("driver api bool")
    );
    assert!(report["backend"]["searched_paths"]
        .as_array()
        .expect("searched paths")
        .iter()
        .any(|path| path.as_str().expect("path").contains("wintun.dll")));
    assert!(report["backend"]["reason"]
        .as_str()
        .expect("reason")
        .contains("Wintun"));
    assert_eq!(
        report["install_plan"]["required"],
        report["backend"]["install_required"]
    );
    assert_eq!(
        report["install_plan"]["source_dir_argument"],
        "--source-dir"
    );
    assert_eq!(report["install_plan"]["source_file_argument"], "--source");
    assert!(report["install_plan"]["target_path"]
        .as_str()
        .expect("target path")
        .contains("wintun.dll"));
    assert!(report["install_plan"]["source_dir_candidates"]
        .as_array()
        .expect("source dir candidates")
        .iter()
        .any(|path| {
            let path = path.as_str().expect("candidate");
            path.contains("<wintun-package>") && path.contains("bin") && path.contains("wintun.dll")
        }));
    assert!(report["install_plan"]["commands"]["source_dir"]
        .as_str()
        .expect("source-dir command")
        .contains("--source-dir"));
}

#[test]
fn tun_backend_check_text_reports_install_or_wiring_detail() {
    let mut output = Vec::new();

    write_tun_backend_check_report(ProbeOutputFormat::Text, &mut output)
        .expect("write TUN backend text");

    let output = String::from_utf8(output).expect("TUN backend text");
    assert!(output.contains("tun_backend status=not-ready"));
    assert!(output.contains("platform=Windows"));
    assert!(output.contains("backend=wintun"));
    assert!(output.contains("driver_api_available="));
    assert!(output.contains("lifecycle_wired=true"));
    assert!(output.contains("packet_io_wired=true"));
    assert!(output.contains("route_takeover_wired=true"));
    assert!(output.contains("searched_path="));
    assert!(output.contains("install_plan required="));
    assert!(output.contains("install_source_dir_candidate="));
    assert!(output.contains("install_command_source_dir="));
}

#[test]
fn tun_backend_install_reports_missing_source_path() {
    let mut output = Vec::new();

    let error = write_tun_backend_install_report(
        PathBuf::from(r"C:\definitely-missing\wintun.dll"),
        None,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect_err("missing source should fail");

    assert!(error.contains("Wintun source DLL was not found"));
}

#[test]
fn tun_backend_install_reports_missing_source_dir() {
    let mut output = Vec::new();

    let error = write_tun_backend_install_report_from_source(
        TunBackendInstallSource::Directory(PathBuf::from(r"C:\definitely-missing\wintun")),
        None,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect_err("missing source directory should fail");

    assert!(error.contains("Wintun source directory was not found"));
}
