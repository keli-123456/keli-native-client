use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

use keli_cli::{
    apply_tun_device_for_config, run_managed_tun_packet_loop, run_with_optional_tun_device,
    write_tun_preflight_report_with_controller, PlatformTunPacketDevice, ProbeOutputFormat,
};
use keli_net_core::{
    DnsCache, DnsEngine, RouteAction, RouteEngine, SystemDnsResolver, TunPacketDevice,
};
use keli_platform::{
    TunDeviceConfig, TunDeviceController, TunDeviceError, TunDeviceSnapshot, TunPacketIo,
    TunPacketIoController,
};

#[derive(Debug)]
struct FakeTunDeviceController {
    snapshot: RefCell<Result<TunDeviceSnapshot, TunDeviceError>>,
    start_result: RefCell<Result<TunDeviceSnapshot, TunDeviceError>>,
    stop_result: RefCell<Result<TunDeviceSnapshot, TunDeviceError>>,
    packet_io_result: RefCell<Option<Result<FakeTunPacketIo, TunDeviceError>>>,
    starts: RefCell<Vec<TunDeviceConfig>>,
    opens: RefCell<Vec<TunDeviceConfig>>,
    stops: RefCell<usize>,
}

impl FakeTunDeviceController {
    fn new(snapshot: TunDeviceSnapshot) -> Self {
        Self {
            snapshot: RefCell::new(Ok(snapshot.clone())),
            start_result: RefCell::new(Ok(snapshot.clone())),
            stop_result: RefCell::new(Ok(snapshot)),
            packet_io_result: RefCell::new(Some(Ok(FakeTunPacketIo::default()))),
            starts: RefCell::new(Vec::new()),
            opens: RefCell::new(Vec::new()),
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

    fn with_packet_io(self, packet_io: FakeTunPacketIo) -> Self {
        *self.packet_io_result.borrow_mut() = Some(Ok(packet_io));
        self
    }

    fn with_packet_io_error(self, error: TunDeviceError) -> Self {
        *self.packet_io_result.borrow_mut() = Some(Err(error));
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

impl TunPacketIoController for FakeTunDeviceController {
    type PacketIo = FakeTunPacketIo;

    fn open_packet_io(&self, config: &TunDeviceConfig) -> Result<Self::PacketIo, TunDeviceError> {
        self.opens.borrow_mut().push(config.clone());
        self.packet_io_result
            .borrow_mut()
            .take()
            .unwrap_or_else(|| Err(TunDeviceError::Io("packet I/O already opened".to_string())))
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
        packet_io_available: false,
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
    assert!(output.contains(
        "device supported=true lifecycle_available=false packet_io_available=false state=stopped"
    ));
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
        packet_io_available: true,
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
        packet_io_available: true,
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
        packet_io_available: true,
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
        packet_io_available: true,
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
        packet_io_available: true,
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
        packet_io_available: true,
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

#[test]
fn managed_tun_packet_loop_runs_platform_io_and_stops_owned_device() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .expect("valid TUN config")
        .with_dns_hijack(true);
    let stopped_snapshot = TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        packet_io_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    };
    let controller = FakeTunDeviceController::new(stopped_snapshot.clone())
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stopped_snapshot)
        .with_packet_io(FakeTunPacketIo {
            reads: VecDeque::from(vec![vec![0]]),
            writes: Vec::new(),
        });
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));

    let report = run_managed_tun_packet_loop(&controller, config.clone(), &routes, &mut dns, 30, 2)
        .expect("run managed TUN packet loop");

    assert_eq!(controller.starts.borrow().as_slice(), &[config.clone()]);
    assert_eq!(controller.opens.borrow().as_slice(), &[config.clone()]);
    assert_eq!(*controller.stops.borrow(), 1);
    assert!(report.owns_device);
    assert_eq!(report.config, config);
    assert!(report.start_snapshot.running);
    assert!(!report.stop_snapshot.running);
    assert_eq!(report.summary.packet_errors, 1);
    assert_eq!(report.summary.idle_events, 1);
    assert_eq!(report.summary.processed_packets(), 1);
}

#[test]
fn managed_tun_packet_loop_stops_owned_device_after_packet_io_open_failure() {
    let config = TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
        .expect("valid TUN config")
        .with_dns_hijack(true);
    let stopped_snapshot = TunDeviceSnapshot {
        supported: true,
        lifecycle_available: true,
        packet_io_available: true,
        running: false,
        interface_name: None,
        address_cidr: None,
        mtu: None,
        dns_hijack: None,
    };
    let controller = FakeTunDeviceController::new(stopped_snapshot.clone())
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stopped_snapshot)
        .with_packet_io_error(TunDeviceError::Io("open failed".to_string()));
    let routes = RouteEngine::new(RouteAction::Direct);
    let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));

    let error = run_managed_tun_packet_loop(&controller, config.clone(), &routes, &mut dns, 30, 1)
        .expect_err("packet I/O open should fail");

    assert!(error.contains("open TUN packet I/O"));
    assert!(error.contains("open failed"));
    assert_eq!(controller.starts.borrow().as_slice(), &[config.clone()]);
    assert_eq!(controller.opens.borrow().as_slice(), &[config]);
    assert_eq!(*controller.stops.borrow(), 1);
}

#[test]
fn platform_tun_packet_device_adapts_packet_io_to_net_core_device() {
    let fake_io = FakeTunPacketIo {
        reads: VecDeque::from(vec![vec![1, 2, 3]]),
        writes: Vec::new(),
    };
    let mut device = PlatformTunPacketDevice::new(fake_io);

    assert_eq!(
        device.read_packet().expect("read packet"),
        Some(vec![1, 2, 3])
    );
    assert_eq!(device.read_packet().expect("read idle"), None);
    device.write_packet(&[4, 5, 6]).expect("write packet");

    let fake_io = device.into_inner();
    assert_eq!(fake_io.writes, vec![vec![4, 5, 6]]);
}

#[derive(Debug, Default)]
struct FakeTunPacketIo {
    reads: VecDeque<Vec<u8>>,
    writes: Vec<Vec<u8>>,
}

impl TunPacketIo for FakeTunPacketIo {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError> {
        Ok(self.reads.pop_front())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunDeviceError> {
        self.writes.push(packet.to_vec());
        Ok(())
    }
}
