use std::cell::RefCell;

use keli_cli::{
    apply_tun_device_for_config, run_with_optional_tun_device,
    write_tun_preflight_report_with_controller, ProbeOutputFormat,
};
use keli_platform::{TunDeviceConfig, TunDeviceController, TunDeviceError, TunDeviceSnapshot};

#[derive(Debug)]
struct FakeTunDeviceController {
    snapshot: RefCell<Result<TunDeviceSnapshot, TunDeviceError>>,
    start_result: RefCell<Result<TunDeviceSnapshot, TunDeviceError>>,
    stop_result: RefCell<Result<TunDeviceSnapshot, TunDeviceError>>,
    starts: RefCell<Vec<TunDeviceConfig>>,
    stops: RefCell<usize>,
}

impl FakeTunDeviceController {
    fn new(snapshot: TunDeviceSnapshot) -> Self {
        Self {
            snapshot: RefCell::new(Ok(snapshot.clone())),
            start_result: RefCell::new(Ok(snapshot.clone())),
            stop_result: RefCell::new(Ok(snapshot)),
            starts: RefCell::new(Vec::new()),
            stops: RefCell::new(0),
        }
    }

    fn with_start_result(self, start_result: TunDeviceSnapshot) -> Self {
        *self.start_result.borrow_mut() = Ok(start_result);
        self
    }

    fn with_stop_result(self, stop_result: TunDeviceSnapshot) -> Self {
        *self.stop_result.borrow_mut() = Ok(stop_result);
        self
    }
}

impl TunDeviceController for FakeTunDeviceController {
    fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        self.snapshot.borrow().clone()
    }

    fn start(&self, config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
        self.starts.borrow_mut().push(config.clone());
        self.start_result.borrow().clone()
    }

    fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
        *self.stops.borrow_mut() += 1;
        self.stop_result.borrow().clone()
    }
}

#[test]
fn tun_preflight_text_reports_lifecycle_unavailable() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .expect("valid TUN config")
        .with_dns_hijack(true);
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot {
        supported: true,
        lifecycle_available: false,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    });

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
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot::running(&running_config));

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

#[test]
fn managed_tun_guard_starts_and_stops_owned_device() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .expect("valid TUN config")
        .with_dns_hijack(true);
    let stopped_snapshot = TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    };
    let stop_snapshot = stopped_snapshot.clone();
    let controller = FakeTunDeviceController::new(stopped_snapshot)
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stop_snapshot);

    let guard = apply_tun_device_for_config(&controller, config.clone()).expect("start TUN guard");

    assert!(guard.owns_device());
    assert_eq!(guard.config(), &config);
    assert!(guard.snapshot().running);
    assert_eq!(controller.starts.borrow().as_slice(), &[config]);

    let snapshot = guard.stop().expect("stop TUN guard");

    assert!(!snapshot.running);
    assert_eq!(*controller.stops.borrow(), 1);
}

#[test]
fn managed_tun_guard_adopts_already_running_device_without_stop() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot::running(&config));

    let guard = apply_tun_device_for_config(&controller, config).expect("adopt TUN guard");

    assert!(!guard.owns_device());
    assert!(guard.snapshot().running);
    assert!(controller.starts.borrow().is_empty());

    let snapshot = guard.stop().expect("stop adopted TUN guard");

    assert!(snapshot.running);
    assert_eq!(*controller.stops.borrow(), 0);
}

#[test]
fn managed_tun_guard_rejects_running_conflict_before_start() {
    let running_config =
        TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
    let requested_config =
        TunDeviceConfig::new("keli-other0", "10.8.0.1/24", 1500).expect("valid TUN config");
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot::running(&running_config));

    let error = apply_tun_device_for_config(&controller, requested_config)
        .expect_err("conflicting TUN should be rejected");

    assert!(error.contains("status=running-conflict"));
    assert!(controller.starts.borrow().is_empty());
    assert_eq!(*controller.stops.borrow(), 0);
}

#[test]
fn managed_tun_guard_rejects_mismatched_start_snapshot() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
    let wrong_config =
        TunDeviceConfig::new("keli-other0", "10.8.0.1/24", 1500).expect("valid TUN config");
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    })
    .with_start_result(TunDeviceSnapshot::running(&wrong_config));

    let error = apply_tun_device_for_config(&controller, config)
        .expect_err("mismatched TUN snapshot should be rejected");

    assert!(error.contains("different running config"));
    assert_eq!(controller.starts.borrow().len(), 1);
    assert_eq!(*controller.stops.borrow(), 0);
}

#[test]
fn optional_tun_wrapper_stops_owned_device_after_success() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    })
    .with_start_result(TunDeviceSnapshot::running(&config))
    .with_stop_result(TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    });

    run_with_optional_tun_device(&controller, Some(config), || Ok(())).expect("run with TUN guard");

    assert_eq!(controller.starts.borrow().len(), 1);
    assert_eq!(*controller.stops.borrow(), 1);
}

#[test]
fn optional_tun_wrapper_stops_owned_device_after_run_failure() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config");
    let controller = FakeTunDeviceController::new(TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    })
    .with_start_result(TunDeviceSnapshot::running(&config))
    .with_stop_result(TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    });

    let error = run_with_optional_tun_device(&controller, Some(config), || {
        Err("mixed listener failed".to_string())
    })
    .expect_err("run failure should be preserved");

    assert_eq!(error, "mixed listener failed");
    assert_eq!(controller.starts.borrow().len(), 1);
    assert_eq!(*controller.stops.borrow(), 1);
}
