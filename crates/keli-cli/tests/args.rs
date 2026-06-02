use std::time::Duration;

use keli_cli::{parse_cli_command, CliCommand};

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
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
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
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
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
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        }
    );
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
            first_byte_timeout: Duration::from_millis(1500),
            idle_timeout: Duration::from_millis(90000),
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
            first_byte_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        }
    );
}
