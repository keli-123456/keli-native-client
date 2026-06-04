use keli_cli::{write_tun_preflight_report_with_controller, ProbeOutputFormat};
use keli_platform::{TunDeviceConfig, TunDeviceController, TunDeviceError, TunDeviceSnapshot};

#[derive(Debug)]
struct FakeTunDeviceController {
    snapshot: Result<TunDeviceSnapshot, TunDeviceError>,
}

impl TunDeviceController for FakeTunDeviceController {
    fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        self.snapshot.clone()
    }

    fn start(&self, _config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
        self.snapshot()
    }

    fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        self.snapshot()
    }
}

#[test]
fn tun_preflight_text_reports_lifecycle_unavailable() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .expect("valid TUN config")
        .with_dns_hijack(true);
    let controller = FakeTunDeviceController {
        snapshot: Ok(TunDeviceSnapshot {
            supported: true,
            lifecycle_available: false,
            running: false,
            interface_name: None,
            address_cidr: None,
            mtu: None,
            dns_hijack: None,
        }),
    };

    let mut output = Vec::new();
    write_tun_preflight_report_with_controller(
        &mut output,
        ProbeOutputFormat::Text,
        config,
        &controller,
    )
    .expect("write report");
    let output = String::from_utf8(output).expect("utf8 output");

    assert!(output.contains("keli-native-client tun-preflight"));
    assert!(output.contains("status=lifecycle-unavailable"));
    assert!(output.contains("ready=false"));
    assert!(
        output.contains("config interface=keli-tun0 address=10.7.0.1/24 mtu=1500 dns_hijack=true")
    );
    assert!(output.contains("device supported=true lifecycle_available=false state=stopped"));
}

#[test]
fn tun_preflight_json_reports_running_conflict() {
    let running_config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .expect("valid TUN config")
        .with_dns_hijack(true);
    let requested_config =
        TunDeviceConfig::new("keli-other0", "10.8.0.1/24", 1500).expect("valid TUN config");
    let controller = FakeTunDeviceController {
        snapshot: Ok(TunDeviceSnapshot::running(&running_config)),
    };

    let mut output = Vec::new();
    write_tun_preflight_report_with_controller(
        &mut output,
        ProbeOutputFormat::Json,
        requested_config,
        &controller,
    )
    .expect("write report");
    let report: serde_json::Value =
        serde_json::from_slice(&output).expect("parse TUN preflight report");

    assert_eq!(report["status"], "running-conflict");
    assert_eq!(report["ready"], false);
    assert_eq!(report["config"]["interface_name"], "keli-other0");
    assert_eq!(report["device"]["state"], "running");
    assert_eq!(report["device"]["interface_name"], "keli-tun0");
    assert!(report["reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("interface=keli-tun0")));
}
