use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use keli_cli::{write_subscription_fetch_report_from_url, ProbeOutputFormat};

#[test]
fn subscription_fetch_json_fetches_subscription_and_redacts_source() {
    let body = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
    let response = http_response(200, body);
    let (url, server) = spawn_http_subscription_server(response);
    let mut output = Vec::new();

    write_subscription_fetch_report_from_url(
        &url,
        ProbeOutputFormat::Json,
        Duration::from_secs(2),
        16 * 1024,
        &mut output,
    )
    .expect("subscription fetch report");

    server.join().expect("subscription server");
    let output = String::from_utf8(output).expect("utf8 output");
    let report: serde_json::Value = serde_json::from_str(&output).expect("json report");

    assert_eq!(report["status"], "ok");
    assert_eq!(report["kind"], "keli_subscription_fetch");
    assert_eq!(report["fetch"]["status"], "ok");
    assert_eq!(report["fetch"]["source"]["scheme"], "http");
    assert_eq!(report["fetch"]["source"]["host"], "127.0.0.1");
    assert_eq!(report["fetch"]["source"]["path_present"], true);
    assert_eq!(report["fetch"]["source"]["query_present"], true);
    assert_eq!(report["fetch"]["http_status"], 200);
    assert!(report["fetch"]["body_bytes"].as_u64().unwrap_or(0) > 0);
    assert_eq!(report["profile"]["status"], "ok");
    assert_eq!(report["profile"]["supported_count"], 1);
    assert_eq!(report["profile"]["default_outbound"], "SS-READY");
    assert_eq!(
        report["redaction"]["source_url"],
        "scheme-host-port-flags-only"
    );
    assert!(!output.contains("super-secret-token"));
    assert!(!output.contains("private-token-path"));
    assert!(!output.contains("ss.example.com"));
    assert!(!output.contains("secret"));
}

#[test]
fn subscription_fetch_json_reports_response_size_limit_without_leaking_url() {
    let response = http_response(200, "too large for tiny limit");
    let (url, server) = spawn_http_subscription_server(response);
    let mut output = Vec::new();

    write_subscription_fetch_report_from_url(
        &url,
        ProbeOutputFormat::Json,
        Duration::from_secs(2),
        16,
        &mut output,
    )
    .expect("subscription fetch report");

    server.join().expect("subscription server");
    let output = String::from_utf8(output).expect("utf8 output");
    let report: serde_json::Value = serde_json::from_str(&output).expect("json report");

    assert_eq!(report["status"], "error");
    assert_eq!(report["fetch"]["status"], "error");
    assert_eq!(report["fetch"]["error_kind"], "response-too-large");
    assert_eq!(report["fetch"]["source"]["query_present"], true);
    assert!(report["profile"].is_null());
    assert!(!output.contains("super-secret-token"));
    assert!(!output.contains("private-token-path"));
}

fn spawn_http_subscription_server(response: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind subscription server");
    let port = listener
        .local_addr()
        .expect("subscription server addr")
        .port();
    let url = format!("http://127.0.0.1:{port}/private-token-path/sub?token=super-secret-token");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept subscription fetch");
        let request = read_http_request(&mut stream);
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("GET /private-token-path/sub?token=super-secret-token "));
        stream
            .write_all(response.as_bytes())
            .expect("write subscription response");
    });
    (url, handle)
}

fn read_http_request(stream: &mut impl Read) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0; 512];
    loop {
        let size = stream.read(&mut buffer).expect("read subscription request");
        if size == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..size]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    request
}

fn http_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
