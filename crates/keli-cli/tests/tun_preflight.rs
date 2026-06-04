use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::net::UdpSocket;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use keli_cli::{
    apply_tun_device_for_config, listen_mixed_with_optional_tun_controller,
    listen_mixed_with_optional_tun_controller_report, run_managed_tun_packet_loop,
    run_managed_tun_packet_loop_with_runtime, run_with_optional_tun_device,
    run_with_optional_tun_runtime_background, run_with_optional_tun_runtime_background_report,
    write_tun_preflight_report_with_controller, ManagedMixedOptions, ManagedMixedSession,
    MixedProxyRuntime, PlatformTunPacketDevice, ProbeOutputFormat,
};
use keli_net_core::{
    parse_tun_udp_payload, DnsCache, DnsEngine, OutboundRegistry, RelayOptions, RouteAction,
    RouteEngine, SystemDnsResolver, TunPacketDevice,
};
use keli_platform::{
    NativeSystemProxyController, TunDeviceConfig, TunDeviceController, TunDeviceError,
    TunDeviceSnapshot, TunPacketIo, TunPacketIoController,
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
            shared_reads: None,
            writes: Vec::new(),
            shared_writes: None,
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
fn managed_tun_packet_loop_with_runtime_relays_tagged_udp_via_registry() {
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
    let (udp_port, udp_server) = spawn_udp_echo_server(b"ping", b"pong");
    let writes = Arc::new(Mutex::new(Vec::new()));
    let controller = FakeTunDeviceController::new(stopped_snapshot.clone())
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stopped_snapshot)
        .with_packet_io(FakeTunPacketIo {
            reads: VecDeque::from(vec![ipv4_packet(
                17,
                "10.7.0.2",
                "127.0.0.1",
                &udp_datagram(54321, udp_port, b"ping"),
            )]),
            shared_reads: None,
            writes: Vec::new(),
            shared_writes: Some(Arc::clone(&writes)),
        });
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_direct("edge");
    let runtime = MixedProxyRuntime {
        routes: RouteEngine::new(RouteAction::Outbound("edge".to_string())),
        relay_options: RelayOptions {
            first_byte_timeout: Some(Duration::from_secs(1)),
            idle_timeout: Some(Duration::from_secs(1)),
        },
        outbounds,
        dns_options: Default::default(),
    };

    let report =
        run_managed_tun_packet_loop_with_runtime(&controller, config.clone(), &runtime, 30, 1)
            .expect("run managed TUN packet loop with runtime relay");

    assert_eq!(controller.starts.borrow().as_slice(), &[config.clone()]);
    assert_eq!(controller.opens.borrow().as_slice(), &[config]);
    assert_eq!(*controller.stops.borrow(), 1);
    assert_eq!(report.summary.processed_packets(), 1);
    assert_eq!(report.summary.udp_relay_responses_written, 1);
    let writes = writes.lock().expect("TUN writes lock");
    assert_eq!(writes.len(), 1);
    let response = parse_tun_udp_payload(&writes[0]).expect("parse TUN UDP response");
    assert_eq!(response.flow.source_port, Some(udp_port));
    assert_eq!(response.flow.destination_port, Some(54321));
    assert_eq!(response.payload, b"pong");
    udp_server.join().expect("UDP echo server");
}

#[test]
fn optional_background_tun_runtime_returns_summary_report() {
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
    let reads = Arc::new(Mutex::new(VecDeque::new()));
    let writes = Arc::new(Mutex::new(Vec::new()));
    let controller = FakeTunDeviceController::new(stopped_snapshot.clone())
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stopped_snapshot)
        .with_packet_io(FakeTunPacketIo {
            reads: VecDeque::new(),
            shared_reads: Some(Arc::clone(&reads)),
            writes: Vec::new(),
            shared_writes: Some(Arc::clone(&writes)),
        });
    let (udp_port, udp_server) = spawn_udp_echo_server(b"ping", b"pong");
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_direct("edge");
    let runtime = MixedProxyRuntime {
        routes: RouteEngine::new(RouteAction::Outbound("edge".to_string())),
        relay_options: RelayOptions {
            first_byte_timeout: Some(Duration::from_secs(1)),
            idle_timeout: Some(Duration::from_secs(1)),
        },
        outbounds,
        dns_options: Default::default(),
    };

    let (output, report) = run_with_optional_tun_runtime_background_report(
        &controller,
        Some(config.clone()),
        &runtime,
        30,
        usize::MAX,
        || {
            reads.lock().expect("TUN reads lock").push_back(ipv4_packet(
                17,
                "10.7.0.2",
                "127.0.0.1",
                &udp_datagram(54321, udp_port, b"ping"),
            ));
            wait_for_tun_writes(&writes, 1);
            Ok("mixed listener stopped")
        },
    )
    .expect("run background TUN runtime with report");

    assert_eq!(output, "mixed listener stopped");
    assert_eq!(controller.starts.borrow().as_slice(), &[config.clone()]);
    assert_eq!(controller.opens.borrow().as_slice(), &[config.clone()]);
    assert_eq!(*controller.stops.borrow(), 1);
    let report = report.expect("TUN report");
    assert!(report.owns_device);
    assert_eq!(report.config, config);
    assert!(report.start_snapshot.running);
    assert!(!report.stop_snapshot.running);
    assert_eq!(report.summary.processed_packets(), 1);
    assert_eq!(report.summary.udp_relay_responses_written, 1);
    let writes = writes.lock().expect("TUN writes lock");
    let response = parse_tun_udp_payload(&writes[0]).expect("parse TUN UDP response");
    assert_eq!(response.flow.source_port, Some(udp_port));
    assert_eq!(response.flow.destination_port, Some(54321));
    assert_eq!(response.payload, b"pong");
    udp_server.join().expect("UDP echo server");
}

#[test]
fn optional_background_tun_runtime_stops_owned_device_after_packet_io_open_failure() {
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
    let runtime = MixedProxyRuntime::default();
    let ran = Arc::new(AtomicBool::new(false));
    let closure_ran = Arc::clone(&ran);

    let error = run_with_optional_tun_runtime_background(
        &controller,
        Some(config.clone()),
        &runtime,
        30,
        1,
        || {
            closure_ran.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("packet I/O open should fail");

    assert!(error.contains("open TUN packet I/O"));
    assert!(error.contains("open failed"));
    assert_eq!(controller.starts.borrow().as_slice(), &[config.clone()]);
    assert_eq!(controller.opens.borrow().as_slice(), &[config]);
    assert_eq!(*controller.stops.borrow(), 1);
    assert!(!ran.load(Ordering::SeqCst));
}

#[test]
fn listen_mixed_with_optional_tun_controller_report_returns_tun_summary() {
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
    let (udp_port, udp_server) = spawn_udp_echo_server(b"ping", b"pong");
    let reads = Arc::new(Mutex::new(VecDeque::new()));
    let writes = Arc::new(Mutex::new(Vec::new()));
    let controller = FakeTunDeviceController::new(stopped_snapshot.clone())
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stopped_snapshot)
        .with_packet_io(FakeTunPacketIo {
            reads: VecDeque::new(),
            shared_reads: Some(Arc::clone(&reads)),
            writes: Vec::new(),
            shared_writes: Some(Arc::clone(&writes)),
        });
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_direct("edge");
    let runtime = MixedProxyRuntime {
        routes: RouteEngine::new(RouteAction::Outbound("edge".to_string())),
        relay_options: RelayOptions {
            first_byte_timeout: Some(Duration::from_secs(1)),
            idle_timeout: Some(Duration::from_secs(1)),
        },
        outbounds,
        dns_options: Default::default(),
    };
    let listen = free_local_addr();
    let thread_listen = listen.clone();
    let listener_thread = thread::spawn(move || {
        let system_proxy = NativeSystemProxyController::new();
        listen_mixed_with_optional_tun_controller_report(
            &thread_listen,
            true,
            &runtime,
            &system_proxy,
            false,
            Vec::new(),
            &controller,
            Some(config),
        )
        .expect("listen-mixed with optional TUN report")
    });

    let mut client = connect_with_retry(&listen);
    reads.lock().expect("TUN reads lock").push_back(ipv4_packet(
        17,
        "10.7.0.2",
        "127.0.0.1",
        &udp_datagram(54321, udp_port, b"ping"),
    ));
    wait_for_tun_writes(&writes, 1);
    client.write_all(&[0]).expect("write unsupported byte");

    let report = listener_thread
        .join()
        .expect("listener thread")
        .expect("TUN report");
    udp_server.join().expect("UDP echo server");
    assert_eq!(report.summary.processed_packets(), 1);
    assert_eq!(report.summary.udp_relay_responses_written, 1);
    let writes = writes.lock().expect("TUN writes lock");
    assert_eq!(writes.len(), 1);
    let response = parse_tun_udp_payload(&writes[0]).expect("parse TUN UDP response");
    assert_eq!(response.flow.source_port, Some(udp_port));
    assert_eq!(response.flow.destination_port, Some(54321));
    assert_eq!(response.payload, b"pong");
}

#[test]
fn listen_mixed_with_optional_tun_controller_runs_tun_loop_while_listener_serves() {
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
    let (udp_port, udp_server) = spawn_udp_echo_server(b"ping", b"pong");
    let reads = Arc::new(Mutex::new(VecDeque::new()));
    let writes = Arc::new(Mutex::new(Vec::new()));
    let controller = FakeTunDeviceController::new(stopped_snapshot.clone())
        .with_start_result(TunDeviceSnapshot::running(&config))
        .with_stop_result(stopped_snapshot)
        .with_packet_io(FakeTunPacketIo {
            reads: VecDeque::new(),
            shared_reads: Some(Arc::clone(&reads)),
            writes: Vec::new(),
            shared_writes: Some(Arc::clone(&writes)),
        });
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_direct("edge");
    let runtime = MixedProxyRuntime {
        routes: RouteEngine::new(RouteAction::Outbound("edge".to_string())),
        relay_options: RelayOptions {
            first_byte_timeout: Some(Duration::from_secs(1)),
            idle_timeout: Some(Duration::from_secs(1)),
        },
        outbounds,
        dns_options: Default::default(),
    };
    let listen = free_local_addr();
    let thread_listen = listen.clone();
    let listener_thread = thread::spawn(move || {
        let system_proxy = NativeSystemProxyController::new();
        listen_mixed_with_optional_tun_controller(
            &thread_listen,
            true,
            &runtime,
            &system_proxy,
            false,
            Vec::new(),
            &controller,
            Some(config),
        )
        .expect("listen-mixed with optional TUN");
    });

    let mut client = connect_with_retry(&listen);
    reads.lock().expect("TUN reads lock").push_back(ipv4_packet(
        17,
        "10.7.0.2",
        "127.0.0.1",
        &udp_datagram(54321, udp_port, b"ping"),
    ));
    wait_for_tun_writes(&writes, 1);
    client.write_all(&[0]).expect("write unsupported byte");

    listener_thread.join().expect("listener thread");
    udp_server.join().expect("UDP echo server");
    let writes = writes.lock().expect("TUN writes lock");
    assert_eq!(writes.len(), 1);
    let response = parse_tun_udp_payload(&writes[0]).expect("parse TUN UDP response");
    assert_eq!(response.flow.source_port, Some(udp_port));
    assert_eq!(response.flow.destination_port, Some(54321));
    assert_eq!(response.payload, b"pong");
}

#[test]
fn managed_mixed_session_records_tun_runtime_status_note_after_serve() {
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
            shared_reads: None,
            writes: Vec::new(),
            shared_writes: None,
        });
    let system_proxy = NativeSystemProxyController::new();
    let session = ManagedMixedSession::start_from_subscription_config_text(
        ss_profile_config(),
        ManagedMixedOptions {
            listen: free_local_addr(),
            ..ManagedMixedOptions::default()
        },
        &system_proxy,
    )
    .expect("start managed mixed session");
    let listen = session.listen_addr().to_string();
    let client_thread = thread::spawn(move || {
        let mut client = connect_with_retry(&listen);
        client.write_all(&[0]).expect("write unsupported byte");
    });

    let (state, report) = session
        .serve_with_optional_tun_controller_report(true, &controller, Some(config))
        .expect("serve managed mixed with TUN report");
    client_thread.join().expect("client thread");

    let report = report.expect("TUN report");
    assert_eq!(report.summary.packet_errors, 1);
    let note = state
        .events()
        .iter()
        .rev()
        .find_map(|event| event.note.as_deref())
        .expect("runtime note");
    assert!(note.contains("managed TUN runtime stopped"));
    assert!(note.contains("packet_errors=1"));
}

#[test]
fn platform_tun_packet_device_adapts_packet_io_to_net_core_device() {
    let fake_io = FakeTunPacketIo {
        reads: VecDeque::from(vec![vec![1, 2, 3]]),
        shared_reads: None,
        writes: Vec::new(),
        shared_writes: None,
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

fn spawn_udp_echo_server(
    expected_request: &'static [u8],
    response: &'static [u8],
) -> (u16, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP echo server");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set UDP echo server timeout");
    let port = socket.local_addr().expect("UDP echo server address").port();
    let server = thread::spawn(move || {
        let mut request = [0; 1500];
        let (size, peer) = socket.recv_from(&mut request).expect("read UDP request");
        assert_eq!(&request[..size], expected_request);
        socket.send_to(response, peer).expect("write UDP response");
    });
    (port, server)
}

fn free_local_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    listener.local_addr().expect("local addr").to_string()
}

fn ss_profile_config() -> &'static str {
    r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
}

fn connect_with_retry(addr: &str) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect to {addr}: {error}"),
        }
    }
}

fn wait_for_tun_writes(writes: &Arc<Mutex<Vec<Vec<u8>>>>, expected_len: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if writes.lock().expect("TUN writes lock").len() >= expected_len {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for TUN writes");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn ipv4_packet(protocol: u8, source: &str, destination: &str, payload: &[u8]) -> Vec<u8> {
    let source: [u8; 4] = source
        .parse::<std::net::Ipv4Addr>()
        .expect("valid source IPv4")
        .octets();
    let destination: [u8; 4] = destination
        .parse::<std::net::Ipv4Addr>()
        .expect("valid destination IPv4")
        .octets();
    let total_length = 20 + payload.len();
    let mut packet = vec![0; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..].copy_from_slice(payload);
    packet
}

fn udp_datagram(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut datagram = Vec::with_capacity(length);
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&(length as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

#[derive(Debug, Default)]
struct FakeTunPacketIo {
    reads: VecDeque<Vec<u8>>,
    shared_reads: Option<Arc<Mutex<VecDeque<Vec<u8>>>>>,
    writes: Vec<Vec<u8>>,
    shared_writes: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
}

impl TunPacketIo for FakeTunPacketIo {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError> {
        if let Some(packet) = self.reads.pop_front() {
            return Ok(Some(packet));
        }
        if let Some(shared_reads) = &self.shared_reads {
            return Ok(shared_reads.lock().expect("TUN reads lock").pop_front());
        }
        Ok(None)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunDeviceError> {
        self.writes.push(packet.to_vec());
        if let Some(shared_writes) = &self.shared_writes {
            shared_writes
                .lock()
                .expect("TUN writes lock")
                .push(packet.to_vec());
        }
        Ok(())
    }
}
