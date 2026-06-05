use keli_cli::{write_tun_backend_check_report, ProbeOutputFormat};
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
    assert_eq!(report["backend"]["lifecycle_wired"], false);
    assert_eq!(report["backend"]["packet_io_wired"], false);
    assert!(report["backend"]["searched_paths"]
        .as_array()
        .expect("searched paths")
        .iter()
        .any(|path| path.as_str().expect("path").contains("wintun.dll")));
    assert!(report["backend"]["reason"]
        .as_str()
        .expect("reason")
        .contains("bridge"));
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
    assert!(output.contains("lifecycle_wired=false"));
    assert!(output.contains("packet_io_wired=false"));
    assert!(output.contains("searched_path="));
}
