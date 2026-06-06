use std::path::PathBuf;
use std::time::Duration;

use keli_cli::{
    parse_cli_command, CliCommand, MixedDnsOptions, ProbeOutputFormat, SmokeInboundKind,
    DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
};
use keli_net_core::{
    DnsAddressFamilyPolicy, DnsLocalResolutionPolicy, DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
};
use keli_platform::TunDeviceConfig;

#[test]
fn defaults_to_doctor_text_command() {
    let command = parse_cli_command(std::iter::empty::<&str>()).expect("command should parse");

    assert_eq!(
        command,
        CliCommand::Doctor {
            output: ProbeOutputFormat::Text
        }
    );
}

#[test]
fn parses_doctor_json_command() {
    let command = parse_cli_command(["doctor", "--format", "json"]).expect("command should parse");

    assert_eq!(
        command,
        CliCommand::Doctor {
            output: ProbeOutputFormat::Json
        }
    );
}

#[test]
fn parses_interop_matrix_json_command() {
    let command =
        parse_cli_command(["interop-matrix", "--format", "json"]).expect("command should parse");

    assert_eq!(
        command,
        CliCommand::InteropMatrix {
            output: ProbeOutputFormat::Json
        }
    );
}

#[test]
fn parses_readiness_check_json_command() {
    let command = parse_cli_command([
        "readiness-check",
        "--format",
        "json",
        "--soak-connections",
        "2",
        "--first-byte-timeout-ms",
        "1500",
        "--max-connection-workers",
        "3",
        "--skip-soak",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ReadinessCheck {
            output: ProbeOutputFormat::Json,
            soak_connections: 2,
            first_byte_timeout: Duration::from_millis(1500),
            max_connection_workers: 3,
            skip_soak: true,
        }
    );
}

#[test]
fn parses_default_core_certify_json_command() {
    let command = parse_cli_command([
        "default-core-certify",
        "--format",
        "json",
        "--soak-connections",
        "2",
        "--first-byte-timeout-ms",
        "1500",
        "--max-connection-workers",
        "3",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::DefaultCoreCertify {
            output: ProbeOutputFormat::Json,
            soak_connections: 2,
            first_byte_timeout: Duration::from_millis(1500),
            max_connection_workers: 3,
        }
    );
}

#[test]
fn parses_tun_preflight_json_command() {
    let command = parse_cli_command([
        "tun-preflight",
        "--interface",
        "keli-main0",
        "--address",
        "10.9.0.1/24",
        "--mtu",
        "1400",
        "--dns-hijack",
        "--format",
        "json",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::TunPreflight {
            config: TunDeviceConfig::new("keli-main0", "10.9.0.1/24", 1400)
                .expect("valid TUN config")
                .with_dns_hijack(true),
            output: ProbeOutputFormat::Json,
        }
    );
}

#[test]
fn parses_tun_backend_check_json_command() {
    let command =
        parse_cli_command(["tun-backend-check", "--format", "json"]).expect("command should parse");

    assert_eq!(
        command,
        CliCommand::TunBackendCheck {
            output: ProbeOutputFormat::Json
        }
    );
}

#[test]
fn parses_tun_backend_install_json_command() {
    let command = parse_cli_command([
        "tun-backend-install",
        "--source",
        r"C:\wintun\bin\amd64\wintun.dll",
        "--target-dir",
        r"C:\keli\runtime",
        "--format",
        "json",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::TunBackendInstall {
            source: PathBuf::from(r"C:\wintun\bin\amd64\wintun.dll"),
            target_dir: Some(PathBuf::from(r"C:\keli\runtime")),
            output: ProbeOutputFormat::Json,
        }
    );
}

#[test]
fn parses_support_bundle_command() {
    let command = parse_cli_command(["support-bundle", "--profile-config", "subscription.yaml"])
        .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SupportBundle {
            profile_config: Some("subscription.yaml".to_string()),
            include_default_core_certification: false,
            certification_soak_connections: 3,
            certification_first_byte_timeout: Duration::from_secs(30),
            certification_max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        }
    );
}

#[test]
fn parses_support_bundle_with_certification_options() {
    let command = parse_cli_command([
        "support-bundle",
        "--include-certification",
        "--certification-soak-connections",
        "2",
        "--certification-first-byte-timeout-ms",
        "1500",
        "--certification-max-connection-workers",
        "3",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SupportBundle {
            profile_config: None,
            include_default_core_certification: true,
            certification_soak_connections: 2,
            certification_first_byte_timeout: Duration::from_millis(1500),
            certification_max_connection_workers: 3,
        }
    );
}

#[test]
fn parses_listen_mixed_once_command() {
    let command = parse_cli_command(["listen-mixed", "--listen", "127.0.0.1:7890", "--once"])
        .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: true,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn defaults_listen_mixed_to_local_port_7890() {
    let command = parse_cli_command(["listen-mixed"]).expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_block_domain_rules() {
    let command = parse_cli_command([
        "listen-mixed",
        "--block-domain",
        "example.com",
        "--block-domain",
        "internal.test",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: vec!["example.com".to_string(), "internal.test".to_string()],
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_block_cidr_and_port_rules() {
    let command = parse_cli_command([
        "listen-mixed",
        "--block-cidr",
        "10.1.2.3/8",
        "--block-port",
        "25",
        "--block-port",
        "1000-1002",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: vec![
                "cidr:10.0.0.0/8".to_string(),
                "port:25".to_string(),
                "port:1000-1002".to_string()
            ],
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn rejects_invalid_listen_mixed_block_port_range() {
    let error = parse_cli_command(["listen-mixed", "--block-port", "100-10"])
        .expect_err("invalid port range should fail");

    assert!(error.contains("invalid --block-port range"));
}

#[test]
fn parses_listen_mixed_relay_timeouts() {
    let command = parse_cli_command([
        "listen-mixed",
        "--first-byte-timeout-ms",
        "1500",
        "--idle-timeout-ms",
        "90000",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_millis(1500),
            idle_timeout: Duration::from_millis(90000),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_profile_config_and_outbound_tag() {
    let command = parse_cli_command([
        "listen-mixed",
        "--profile-config",
        "subscription.yaml",
        "--outbound-tag",
        "美国-TROJAN-54",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: Some("subscription.yaml".to_string()),
            outbound_tag: Some("美国-TROJAN-54".to_string()),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_system_proxy_options() {
    let command = parse_cli_command([
        "listen-mixed",
        "--system-proxy",
        "--system-proxy-bypass",
        "localhost",
        "--system-proxy-bypass",
        "<local>",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: true,
            system_proxy_bypass: vec!["localhost".to_string(), "<local>".to_string()],
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_tun_options() {
    let command = parse_cli_command([
        "listen-mixed",
        "--tun",
        "--tun-interface",
        "keli-main0",
        "--tun-address",
        "10.9.0.1/24",
        "--tun-mtu",
        "1400",
        "--tun-dns-hijack",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: Some(
                TunDeviceConfig::new("keli-main0", "10.9.0.1/24", 1400)
                    .expect("valid TUN config")
                    .with_dns_hijack(true)
            ),
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_tun_tcp_session_limit() {
    let command = parse_cli_command(["listen-mixed", "--tun-tcp-max-active-sessions", "17"])
        .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: Some(
                TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config")
            ),
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: 17,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn parses_listen_mixed_connection_worker_limit() {
    let command = parse_cli_command(["listen-mixed", "--max-connection-workers", "23"])
        .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: 23,
            dns_options: MixedDnsOptions::default(),
        }
    );
}

#[test]
fn rejects_invalid_listen_mixed_connection_worker_limit() {
    let error = parse_cli_command(["listen-mixed", "--max-connection-workers", "0"])
        .expect_err("zero worker limit should fail");

    assert!(error.contains("--max-connection-workers must be greater than 0"));
}

#[test]
fn parses_listen_mixed_dns_policy_options() {
    let command = parse_cli_command([
        "listen-mixed",
        "--dns-local-policy",
        "prevent-public-leak",
        "--dns-address-family",
        "ipv6-only",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ListenMixed {
            listen: "127.0.0.1:7890".to_string(),
            once: false,
            block_domains: Vec::new(),
            profile_config: None,
            outbound_tag: None,
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            dns_options: MixedDnsOptions {
                local_resolution_policy: DnsLocalResolutionPolicy::PreventPublicLeak,
                address_family_policy: DnsAddressFamilyPolicy::Ipv6Only,
                cache_ttl: Duration::from_secs(60),
            },
        }
    );
}

#[test]
fn parses_probe_outbound_command() {
    let command = parse_cli_command([
        "probe-outbound",
        "--profile-config",
        "subscription.yaml",
        "--outbound-tag",
        "SS-READY",
        "--target",
        "example.com:443",
        "--payload",
        "ping",
        "--expect",
        "pong",
        "--first-byte-timeout-ms",
        "1500",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ProbeOutbound {
            profile_config: "subscription.yaml".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            target: "example.com:443".to_string(),
            payload: Some("ping".to_string()),
            expect: Some("pong".to_string()),
            udp: false,
            output: ProbeOutputFormat::Text,
            first_byte_timeout: Duration::from_millis(1500),
        }
    );
}

#[test]
fn parses_subscription_fetch_json_command() {
    let command = parse_cli_command([
        "subscription-fetch",
        "--url",
        "https://panel.example/sub?token=secret",
        "--format",
        "json",
        "--timeout-ms",
        "1500",
        "--max-bytes",
        "4096",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SubscriptionFetch {
            url: "https://panel.example/sub?token=secret".to_string(),
            output: ProbeOutputFormat::Json,
            timeout: Duration::from_millis(1500),
            max_bytes: 4096,
        }
    );
}

#[test]
fn parses_subscription_update_json_command() {
    let command = parse_cli_command([
        "subscription-update",
        "--current-config",
        "active.yaml",
        "--new-config",
        "next.yaml",
        "--current-outbound",
        "SS-READY",
        "--format",
        "json",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SubscriptionUpdate {
            current_config: Some("active.yaml".to_string()),
            new_config: "next.yaml".to_string(),
            current_outbound: Some("SS-READY".to_string()),
            output: ProbeOutputFormat::Json,
        }
    );
}

#[test]
fn parses_probe_outbound_udp_command() {
    let command = parse_cli_command([
        "probe-outbound",
        "--profile-config",
        "subscription.yaml",
        "--outbound-tag",
        "SS-READY",
        "--target",
        "example.com:53",
        "--payload",
        "ping",
        "--expect",
        "pong",
        "--udp",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ProbeOutbound {
            profile_config: "subscription.yaml".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            target: "example.com:53".to_string(),
            payload: Some("ping".to_string()),
            expect: Some("pong".to_string()),
            udp: true,
            output: ProbeOutputFormat::Text,
            first_byte_timeout: Duration::from_secs(30),
        }
    );
}

#[test]
fn parses_probe_outbound_json_command() {
    let command = parse_cli_command([
        "probe-outbound",
        "--profile-config",
        "subscription.yaml",
        "--target",
        "example.com:443",
        "--format",
        "json",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ProbeOutbound {
            profile_config: "subscription.yaml".to_string(),
            outbound_tag: None,
            target: "example.com:443".to_string(),
            payload: None,
            expect: None,
            udp: false,
            output: ProbeOutputFormat::Json,
            first_byte_timeout: Duration::from_secs(30),
        }
    );
}

#[test]
fn parses_profile_check_json_command() {
    let command = parse_cli_command([
        "profile-check",
        "--profile-config",
        "subscription.yaml",
        "--format",
        "json",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::ProfileCheck {
            profile_config: "subscription.yaml".to_string(),
            output: ProbeOutputFormat::Json,
        }
    );
}

#[test]
fn parses_smoke_mixed_json_command() {
    let command = parse_cli_command([
        "smoke-mixed",
        "--profile-config",
        "subscription.yaml",
        "--outbound-tag",
        "SS-READY",
        "--target",
        "example.com:443",
        "--payload",
        "ping",
        "--expect",
        "pong",
        "--format",
        "json",
        "--first-byte-timeout-ms",
        "1500",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SmokeMixed {
            profile_config: "subscription.yaml".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            target: "example.com:443".to_string(),
            payload: Some("ping".to_string()),
            expect: Some("pong".to_string()),
            inbound: SmokeInboundKind::Socks5,
            output: ProbeOutputFormat::Json,
            first_byte_timeout: Duration::from_millis(1500),
        }
    );
}

#[test]
fn parses_smoke_mixed_http_connect_inbound_command() {
    let command = parse_cli_command([
        "smoke-mixed",
        "--profile-config",
        "subscription.yaml",
        "--target",
        "example.com:443",
        "--inbound",
        "http-connect",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SmokeMixed {
            profile_config: "subscription.yaml".to_string(),
            outbound_tag: None,
            target: "example.com:443".to_string(),
            payload: None,
            expect: None,
            inbound: SmokeInboundKind::HttpConnect,
            output: ProbeOutputFormat::Text,
            first_byte_timeout: Duration::from_secs(30),
        }
    );
}

#[test]
fn parses_soak_mixed_json_command() {
    let command = parse_cli_command([
        "soak-mixed",
        "--connections",
        "7",
        "--inbound",
        "http-connect",
        "--format",
        "json",
        "--first-byte-timeout-ms",
        "1500",
        "--max-connection-workers",
        "3",
        "--min-duration-ms",
        "250",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        CliCommand::SoakMixed {
            connections: 7,
            inbound: SmokeInboundKind::HttpConnect,
            output: ProbeOutputFormat::Json,
            first_byte_timeout: Duration::from_millis(1500),
            max_connection_workers: 3,
            min_duration: Duration::from_millis(250),
        }
    );
}
