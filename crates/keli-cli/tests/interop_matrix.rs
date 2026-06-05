use keli_cli::{write_interop_matrix_report, ProbeOutputFormat, INTEROP_MATRIX_SCHEMA_VERSION};
use serde_json::Value;

#[test]
fn interop_matrix_json_reports_registry_validated_protocol_coverage() {
    let mut output = Vec::new();

    write_interop_matrix_report(ProbeOutputFormat::Json, &mut output)
        .expect("write interop matrix");

    let report: Value = serde_json::from_slice(&output).expect("interop matrix json");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["kind"], "keli_interop_matrix");
    assert_eq!(report["schema_version"], INTEROP_MATRIX_SCHEMA_VERSION);
    assert_eq!(report["summary"]["protocol_count"], 12);
    assert_eq!(report["summary"]["tcp_relay_supported_count"], 12);
    assert_eq!(report["summary"]["udp_relay_supported_count"], 10);
    assert_eq!(report["summary"]["profile_source_supported_count"], 11);
    assert_eq!(report["summary"]["validation_supported_count"], 12);
    assert_eq!(report["summary"]["registry_supported_count"], 12);
    assert_eq!(report["summary"]["sample_profile_count"], 27);
    assert_eq!(report["summary"]["registry_profile_count"], 27);

    let entries = report["entries"].as_array().expect("entries array");
    let trojan = entries
        .iter()
        .find(|entry| entry["protocol"] == "trojan")
        .expect("trojan entry");
    assert_eq!(trojan["tcp_relay_supported"], true);
    assert_eq!(trojan["udp_relay_supported"], true);
    assert_eq!(trojan["covered_transports"][0], "tcp");
    assert_eq!(trojan["covered_transports"][5], "quic");
    assert_eq!(trojan["profile_sources"][0], "mihomo-yaml");
    assert_eq!(trojan["profile_sources"][1], "share-link");
    assert_eq!(trojan["sample_profile_count"], 6);
    assert_eq!(trojan["validated_profile_count"], 6);
    assert_eq!(trojan["registry_profile_count"], 6);
    assert_eq!(trojan["validation_supported"], true);
    assert_eq!(trojan["registry_supported"], true);
    assert!(trojan["validation_error"].is_null());
    assert!(trojan["registry_error"].is_null());

    let naive = entries
        .iter()
        .find(|entry| entry["protocol"] == "naive")
        .expect("naive entry");
    assert_eq!(naive["tcp_relay_supported"], true);
    assert_eq!(naive["udp_relay_supported"], false);
    assert_eq!(naive["covered_transports"][0], "h2");
    assert_eq!(naive["covered_transports"][1], "h3");

    let direct = entries
        .iter()
        .find(|entry| entry["protocol"] == "direct")
        .expect("direct entry");
    assert_eq!(direct["profile_sources"][0], "built-in");
    assert_eq!(direct["sample_profile_count"], 0);
    assert_eq!(direct["registry_supported"], true);
}

#[test]
fn interop_matrix_text_reports_summary_and_protocol_rows() {
    let mut output = Vec::new();

    write_interop_matrix_report(ProbeOutputFormat::Text, &mut output)
        .expect("write text interop matrix");

    let output = String::from_utf8(output).expect("interop matrix utf8");
    assert!(output.contains(
        "interop status=ok schema_version=1 protocols=12 tcp_relay_supported=12 udp_relay_supported=10"
    ));
    assert!(output.contains(
        "interop protocol=trojan tcp_relay_supported=true udp_relay_supported=true transports=tcp,ws,httpupgrade,grpc,h2,quic profile_sources=mihomo-yaml,share-link sample_profiles=6 validation_supported=true validated_profiles=6 validation_error=- registry_supported=true registry_profiles=6 registry_error=-"
    ));
    assert!(output.contains(
        "interop protocol=http tcp_relay_supported=true udp_relay_supported=false transports=connect"
    ));
}
