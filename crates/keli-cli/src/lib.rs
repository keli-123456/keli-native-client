use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use keli_client_core::ConnectionPhase;
use keli_net_core::{
    encode_socks5_udp_datagram, http_connect_bad_request_response, http_connect_success_response,
    http_proxy_bad_request_response, parse_http_connect_request, parse_http_proxy_request,
    parse_socks5_handshake, parse_socks5_request, parse_socks5_udp_datagram,
    relay_owned_bidirectional_with_options, socks5_no_auth_response, socks5_reply,
    ConnectionErrorKind, ConnectionReport, DirectTcpConnector, LocalInbound, OutboundConnection,
    OutboundRegistry, OutboundTarget, RelayOptions, RouteAction, RouteEngine, Socks5Address,
    Socks5Command, Socks5ReplyCode,
};
use keli_platform::PlatformCapabilities;
use keli_protocol::{
    parse_mihomo_outbound_profiles, parse_subscription_outbound_profiles, Endpoint,
    OutboundProfile, ProxyProtocol, SecurityKind, TransportKind,
};

const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SUPPORTED_OUTBOUNDS: &str =
    "direct,trojan-tcp,trojan-ws,vless-tcp,vless-ws,shadowsocks-tcp,anytls-tls-tcp,hy2-quic,tuic-quic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Doctor,
    Version,
    ListenMixed {
        listen: String,
        once: bool,
        block_domains: Vec<String>,
        profile_config: Option<String>,
        outbound_tag: Option<String>,
        first_byte_timeout: Duration,
        idle_timeout: Duration,
    },
}

#[derive(Debug, Clone)]
pub struct MixedProxyRuntime {
    pub routes: RouteEngine,
    pub relay_options: RelayOptions,
    pub outbounds: OutboundRegistry,
}

impl MixedProxyRuntime {
    pub fn with_routes(routes: RouteEngine) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds: OutboundRegistry::new(),
        }
    }

    pub fn with_routes_and_outbounds(routes: RouteEngine, outbounds: OutboundRegistry) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds,
        }
    }
}

impl Default for MixedProxyRuntime {
    fn default() -> Self {
        Self::with_routes(RouteEngine::new(RouteAction::Direct))
    }
}

pub fn parse_cli_command(
    args: impl IntoIterator<Item = impl Into<String>>,
) -> Result<CliCommand, String> {
    let mut args = args.into_iter().map(Into::into);
    match args.next().as_deref() {
        None | Some("doctor") => Ok(CliCommand::Doctor),
        Some("version") => Ok(CliCommand::Version),
        Some("listen-mixed") => parse_listen_mixed(args),
        Some(other) => Err(format!("unknown command: {other}")),
    }
}

pub fn run(command: CliCommand) -> Result<(), String> {
    match command {
        CliCommand::Doctor => {
            print_doctor();
            Ok(())
        }
        CliCommand::Version => {
            println!("keli-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::ListenMixed {
            listen,
            once,
            block_domains,
            profile_config,
            outbound_tag,
            first_byte_timeout,
            idle_timeout,
        } => {
            let relay_options = RelayOptions {
                first_byte_timeout: Some(first_byte_timeout),
                idle_timeout: Some(idle_timeout),
            };
            let runtime = match profile_config {
                Some(path) => mixed_runtime_from_mihomo_config_path(
                    &path,
                    block_domains,
                    relay_options,
                    outbound_tag,
                )?,
                None => mixed_runtime_from_cli(block_domains, relay_options),
            };
            listen_mixed(&listen, once, &runtime)
                .map_err(|error| format!("listen-mixed failed on {listen}: {error}"))
        }
    }
}

pub fn print_usage(mut writer: impl Write) -> io::Result<()> {
    writeln!(writer, "usage: keli-cli [doctor|version|listen-mixed]")?;
    writeln!(
        writer,
        "       keli-cli listen-mixed [--listen 127.0.0.1:7890] [--once] [--profile-config subscription.yaml] [--outbound-tag proxy] [--first-byte-timeout-ms 30000] [--idle-timeout-ms 300000]"
    )
}

fn parse_listen_mixed(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut listen = "127.0.0.1:7890".to_string();
    let mut once = false;
    let mut block_domains = Vec::new();
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut idle_timeout = DEFAULT_IDLE_TIMEOUT;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .ok_or_else(|| "--listen requires an address".to_string())?;
            }
            "--once" => once = true,
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            "--idle-timeout-ms" => {
                idle_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--idle-timeout-ms requires a value".to_string())?,
                    "--idle-timeout-ms",
                )?;
            }
            "--block-domain" => {
                block_domains.push(
                    args.next()
                        .ok_or_else(|| "--block-domain requires a domain".to_string())?,
                );
            }
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            other => return Err(format!("unknown listen-mixed option: {other}")),
        }
    }

    Ok(CliCommand::ListenMixed {
        listen,
        once,
        block_domains,
        profile_config,
        outbound_tag,
        first_byte_timeout,
        idle_timeout,
    })
}

fn print_doctor() {
    let mut stdout = io::stdout();
    write_doctor_report(&mut stdout).expect("write doctor report");
}

pub fn write_doctor_report(mut writer: impl Write) -> io::Result<()> {
    let capabilities = PlatformCapabilities::detect();
    let inbound = LocalInbound::Mixed {
        listen: "127.0.0.1".to_string(),
        port: 7890,
    };
    let route_engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
    let profile = OutboundProfile {
        tag: "trojan-ws".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("example.com", 443),
        transport: TransportKind::WebSocket {
            path: "/answer".to_string(),
            host: Some("example.com".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("example.com".to_string()),
            skip_verify: false,
        },
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    };

    writeln!(writer, "keli-native-client doctor")?;
    writeln!(writer, "version={}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "platform={:?}", capabilities.platform)?;
    writeln!(writer, "system_proxy={}", capabilities.system_proxy)?;
    writeln!(writer, "tun={}", capabilities.tun)?;
    writeln!(writer, "secure_storage={}", capabilities.secure_storage)?;
    writeln!(writer, "inbound={inbound:?}")?;
    writeln!(writer, "route_default={route_engine:?}")?;
    writeln!(writer, "dns_engine=system_resolver cache_ttl=60s")?;
    writeln!(writer, "supported_outbounds={SUPPORTED_OUTBOUNDS}")?;
    writeln!(
        writer,
        "sample_profile_valid={}",
        profile.validate().is_ok()
    )?;
    writeln!(writer, "initial_phase={:?}", ConnectionPhase::Idle)?;
    Ok(())
}

fn listen_mixed(listen: &str, once: bool, runtime: &MixedProxyRuntime) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    println!("mixed inbound listening on {listen}");

    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = handle_mixed_connection_with_routes(&mut stream, runtime) {
            eprintln!("mixed inbound failed: {error}");
        }
        if once {
            break;
        }
    }

    Ok(())
}

pub fn handle_socks5_connection(stream: &mut TcpStream) -> io::Result<()> {
    handle_socks5_connection_with_routes(stream, &MixedProxyRuntime::default())
}

pub fn handle_socks5_connection_with_routes(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let handshake = parse_socks5_handshake(stream).map_err(to_io_error)?;
    if !handshake.methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff])?;
        return Ok(());
    }

    stream.write_all(&socks5_no_auth_response())?;
    let request = parse_socks5_request(stream).map_err(to_io_error)?;
    println!(
        "socks5 request command={:?} address={:?} port={}",
        request.command, request.address, request.port
    );

    match request.command {
        Socks5Command::Connect => {}
        Socks5Command::UdpAssociate => {
            return handle_socks5_udp_associate(stream, runtime);
        }
        Socks5Command::Bind => {
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Ok(());
        }
    }

    let target = OutboundTarget::from_socks5_request(&request);
    let mut report = ConnectionReport::new("socks5", target.clone(), RouteAction::Direct);
    let remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::ConnectionNotAllowed))?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::HostUnreachable))?;
            return Err(error);
        }
    };

    stream.write_all(&socks5_reply(Socks5ReplyCode::Succeeded))?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

fn handle_socks5_udp_associate(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let relay = UdpSocket::bind("127.0.0.1:0")?;
    let timeout = runtime
        .relay_options
        .first_byte_timeout
        .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT);
    relay.set_read_timeout(Some(timeout))?;
    let outbound = UdpSocket::bind("0.0.0.0:0")?;
    outbound.set_read_timeout(Some(timeout))?;

    let bound_addr = relay.local_addr()?;
    stream.write_all(&socks5_success_reply_for_bound_addr(bound_addr))?;

    let mut request_buffer = [0; 65_535];
    let (request_size, client_udp_addr) = relay.recv_from(&mut request_buffer)?;
    let datagram =
        parse_socks5_udp_datagram(&request_buffer[..request_size]).map_err(to_io_error)?;
    let target = outbound_target_from_socks5_udp(&datagram.address, datagram.port);
    let mut report = ConnectionReport::new("socks5-udp", target.clone(), RouteAction::Direct);

    match runtime.routes.decide(&target.route_target()).action {
        RouteAction::Direct => {}
        RouteAction::Block => {
            report.route_action = RouteAction::Block;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            return Ok(());
        }
        RouteAction::Outbound(tag) => {
            report.route_action = RouteAction::Outbound(tag);
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            return Ok(());
        }
        RouteAction::HijackDns => {
            report.route_action = RouteAction::HijackDns;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            return Ok(());
        }
    }

    let remote_addr = resolve_udp_socket_addr(&target)?;
    let started = Instant::now();
    outbound.send_to(&datagram.payload, remote_addr)?;
    report.upload_bytes = datagram.payload.len() as u64;

    let mut response_buffer = [0; 65_535];
    let (response_size, response_from) = outbound.recv_from(&mut response_buffer)?;
    report.record_first_byte_duration(started.elapsed());
    report.download_bytes = response_size as u64;

    let response_address = socks5_address_from_ip(response_from.ip());
    let response = encode_socks5_udp_datagram(
        &response_address,
        response_from.port(),
        &response_buffer[..response_size],
    )
    .map_err(to_io_error)?;
    relay.send_to(&response, client_udp_addr)?;
    println!("{}", report.summary_line());
    Ok(())
}

fn socks5_success_reply_for_bound_addr(bound_addr: SocketAddr) -> Vec<u8> {
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[0x05, 0x00, 0x00]);
    match bound_addr.ip() {
        IpAddr::V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound_addr.port().to_be_bytes());
    reply
}

fn outbound_target_from_socks5_udp(address: &Socks5Address, port: u16) -> OutboundTarget {
    let host = match address {
        Socks5Address::Ipv4(ip) => ip.to_string(),
        Socks5Address::Domain(domain) => domain.clone(),
        Socks5Address::Ipv6(ip) => ip.to_string(),
    };
    OutboundTarget::new(host, port)
}

fn resolve_udp_socket_addr(target: &OutboundTarget) -> io::Result<SocketAddr> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, target.port));
    }

    (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address resolved for {}:{}", target.host, target.port),
            )
        })
}

fn socks5_address_from_ip(ip: IpAddr) -> Socks5Address {
    match ip {
        IpAddr::V4(ip) => Socks5Address::Ipv4(ip),
        IpAddr::V6(ip) => Socks5Address::Ipv6(ip),
    }
}

pub fn handle_mixed_connection(stream: &mut TcpStream) -> io::Result<()> {
    handle_mixed_connection_with_routes(stream, &MixedProxyRuntime::default())
}

pub fn handle_mixed_connection_with_routes(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let mut first = [0; 1];
    stream.peek(&mut first)?;
    match first[0] {
        0x05 => handle_socks5_connection_with_routes(stream, runtime),
        b'C' | b'c' => handle_http_connect_connection(stream, runtime),
        b'D' | b'd' | b'G' | b'g' | b'H' | b'h' | b'O' | b'o' | b'P' | b'p' | b'T' | b't' => {
            handle_http_proxy_connection(stream, runtime)
        }
        _ => {
            stream.write_all(http_connect_bad_request_response())?;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mixed inbound received an unsupported protocol",
            ))
        }
    }
}

fn handle_http_connect_connection(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let request = match parse_http_connect_request(stream) {
        Ok(remote) => remote,
        Err(error) => {
            stream.write_all(http_connect_bad_request_response())?;
            return Err(to_io_error(error));
        }
    };
    println!(
        "http connect request address={} port={}",
        request.host, request.port
    );

    let target = OutboundTarget::new(request.host, request.port);
    let mut report = ConnectionReport::new("http-connect", target.clone(), RouteAction::Direct);
    let remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(http_connect_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(http_connect_bad_request_response())?;
            return Err(error);
        }
    };

    stream.write_all(http_connect_success_response())?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

fn handle_http_proxy_connection(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let request = match parse_http_proxy_request(stream) {
        Ok(request) => request,
        Err(error) => {
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(to_io_error(error));
        }
    };
    println!(
        "http proxy request method={} address={} port={} path={}",
        request.method, request.host, request.port, request.path_and_query
    );

    let target = OutboundTarget::new(request.host, request.port);
    let mut report = ConnectionReport::new("http-proxy", target.clone(), RouteAction::Direct);
    let mut remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(error);
        }
    };

    remote.write_all(&request.rewritten_header)?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

enum RouteConnect {
    Direct {
        stream: OutboundConnection,
        route_action: RouteAction,
        connect_duration: Duration,
    },
    Blocked {
        route_action: RouteAction,
    },
    UnsupportedOutbound {
        tag: String,
        route_action: RouteAction,
    },
}

fn connect_by_route(
    target: &OutboundTarget,
    runtime: &MixedProxyRuntime,
) -> io::Result<RouteConnect> {
    let decision = runtime.routes.decide(&target.route_target());
    match decision.action {
        RouteAction::Direct => {
            let started = Instant::now();
            DirectTcpConnector::connect(target, Duration::from_secs(10)).map(|stream| {
                RouteConnect::Direct {
                    stream: OutboundConnection::Tcp(stream),
                    route_action: RouteAction::Direct,
                    connect_duration: started.elapsed(),
                }
            })
        }
        RouteAction::Block => Ok(RouteConnect::Blocked {
            route_action: RouteAction::Block,
        }),
        RouteAction::Outbound(tag) => {
            let started = Instant::now();
            match runtime
                .outbounds
                .connect(&tag, target, Duration::from_secs(10))
            {
                Ok(stream) => Ok(RouteConnect::Direct {
                    stream,
                    route_action: RouteAction::Outbound(tag),
                    connect_duration: started.elapsed(),
                }),
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    Ok(RouteConnect::UnsupportedOutbound {
                        route_action: RouteAction::Outbound(tag.clone()),
                        tag,
                    })
                }
                Err(error) => Err(error),
            }
        }
        RouteAction::HijackDns => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hijack-dns route action is not valid for TCP proxy relay",
        )),
    }
}

pub fn mixed_runtime_from_mihomo_config_text(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let parsed = parse_mihomo_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    mixed_runtime_from_parsed_profiles(parsed, block_domains, relay_options, outbound_tag)
}

pub fn mixed_runtime_from_subscription_config_text(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    mixed_runtime_from_parsed_profiles(parsed, block_domains, relay_options, outbound_tag)
}

fn mixed_runtime_from_parsed_profiles(
    parsed: keli_protocol::ParsedOutboundProfiles,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let available_tags: Vec<String> = parsed
        .profiles
        .iter()
        .map(|profile| profile.tag.clone())
        .collect();
    let selected_tag = match outbound_tag {
        Some(tag) => tag,
        None => available_tags
            .first()
            .cloned()
            .ok_or_else(|| "profile config did not contain supported outbounds".to_string())?,
    };
    if !available_tags.iter().any(|tag| tag == &selected_tag) {
        return Err(format!(
            "outbound tag not found: {selected_tag}; available: {}",
            available_tags.join(", ")
        ));
    }
    let outbounds = OutboundRegistry::from_profiles(parsed.profiles)
        .map_err(|error| format!("profile config contains unsupported outbound: {error}"))?;
    Ok(MixedProxyRuntime {
        routes: routes_from_cli(block_domains, RouteAction::Outbound(selected_tag)),
        relay_options,
        outbounds,
    })
}

fn mixed_runtime_from_mihomo_config_path(
    path: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    let config_text =
        fs::read_to_string(path).map_err(|error| format!("read profile config {path}: {error}"))?;
    mixed_runtime_from_subscription_config_text(
        &config_text,
        block_domains,
        relay_options,
        outbound_tag,
    )
}

fn mixed_runtime_from_cli(
    block_domains: Vec<String>,
    relay_options: RelayOptions,
) -> MixedProxyRuntime {
    MixedProxyRuntime {
        routes: routes_from_cli(block_domains, RouteAction::Direct),
        relay_options,
        outbounds: OutboundRegistry::new(),
    }
}

fn routes_from_cli(block_domains: Vec<String>, default_action: RouteAction) -> RouteEngine {
    let mut routes = RouteEngine::new(default_action);
    for domain in block_domains {
        routes.add_rule(keli_net_core::RouteRule {
            name: format!("block-domain:{domain}"),
            matcher: keli_net_core::RouteMatcher::DomainSuffix(domain),
            action: RouteAction::Block,
        });
    }
    routes
}

fn http_forbidden_response() -> &'static [u8] {
    b"HTTP/1.1 403 Forbidden\r\n\r\n"
}

fn relay_with_report(
    client: TcpStream,
    remote: OutboundConnection,
    report: &mut ConnectionReport,
    relay_options: RelayOptions,
) -> io::Result<()> {
    match relay_owned_bidirectional_with_options(client, remote, relay_options) {
        Ok(stats) => {
            report.record_relay_stats(stats);
            println!("{}", report.summary_line());
            Ok(())
        }
        Err(error) => {
            report.record_error(error.kind);
            println!("{}", report.summary_line());
            Err(io::Error::new(io::ErrorKind::Other, error))
        }
    }
}

fn default_relay_options() -> RelayOptions {
    RelayOptions {
        first_byte_timeout: Some(DEFAULT_FIRST_BYTE_TIMEOUT),
        idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
    }
}

fn parse_duration_ms(value: String, option: &str) -> Result<Duration, String> {
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("{option} requires a positive integer value"))?;
    if milliseconds == 0 {
        return Err(format!("{option} must be greater than 0"));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn to_io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
