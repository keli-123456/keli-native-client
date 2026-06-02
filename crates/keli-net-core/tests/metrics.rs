use std::io;
use std::time::Duration;

use keli_net_core::{
    ConnectionErrorKind, ConnectionReport, OutboundTarget, RelayStats, RouteAction,
};

#[test]
fn connection_report_records_connect_and_relay_metrics() {
    let mut report = ConnectionReport::new(
        "socks5",
        OutboundTarget::new("example.com", 443),
        RouteAction::Direct,
    );

    report.record_connect_duration(Duration::from_millis(17));
    report.record_first_byte_duration(Duration::from_millis(31));
    report.record_relay_stats(RelayStats {
        client_to_remote_bytes: 12,
        remote_to_client_bytes: 34,
        remote_first_byte_after: Some(Duration::from_millis(29)),
    });

    assert_eq!(report.connect_ms, Some(17));
    assert_eq!(report.first_byte_ms, Some(29));
    assert_eq!(report.upload_bytes, 12);
    assert_eq!(report.download_bytes, 34);
    assert!(report.error_kind.is_none());
}

#[test]
fn connection_report_formats_single_line_summary() {
    let mut report = ConnectionReport::new(
        "http-connect",
        OutboundTarget::new("blocked.test", 443),
        RouteAction::Block,
    );
    report.record_error(ConnectionErrorKind::RouteBlocked);

    let line = report.summary_line();

    assert!(line.contains("inbound=http-connect"));
    assert!(line.contains("target=blocked.test:443"));
    assert!(line.contains("route=Block"));
    assert!(line.contains("error_kind=route_blocked"));
}

#[test]
fn classifies_common_io_errors() {
    assert_eq!(
        ConnectionErrorKind::from_io(&io::Error::new(io::ErrorKind::TimedOut, "timeout")),
        ConnectionErrorKind::TcpConnectTimeout
    );
    assert_eq!(
        ConnectionErrorKind::from_io(&io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        ConnectionErrorKind::TcpConnectionRefused
    );
    assert_eq!(
        ConnectionErrorKind::from_io(&io::Error::new(io::ErrorKind::AddrNotAvailable, "dns")),
        ConnectionErrorKind::DnsResolveFailed
    );
}
