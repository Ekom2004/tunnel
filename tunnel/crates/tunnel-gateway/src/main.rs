#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::{Args, Parser, ValueEnum};
use tun::AbstractDevice;
use tunnel_shared::{
    decode_key_32, now_unix_secs, read_json_line, write_json_line, AgentToGateway, ComponentKind,
    GatewayRuntimeState, GatewayToAgent, HealthState, HealthStatus, PacketPathTelemetry,
    RuntimeStatus, SocketEndpoint, TransportKind, TunnelConfig, TunnelPhase, UsageRecord,
    WireGuardConfig,
};

#[derive(Debug, Parser)]
#[command(name = "tunnel-gateway")]
#[command(about = "Phase 1 Tunnel gateway", long_about = None)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:7000")]
    bind: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    output_dir: Option<PathBuf>,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-state.json")]
    state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-status.json")]
    status_file: PathBuf,
    #[arg(long)]
    cleanup_only: bool,
    #[arg(long, default_value_t = 5)]
    status_interval_secs: u64,
    #[command(flatten)]
    tun: TunArgs,
}

#[derive(Debug, Args, Clone)]
struct TunArgs {
    #[arg(long)]
    tun: bool,
    #[arg(long)]
    tun_name: Option<String>,
    #[arg(long, default_value = "10.200.0.1")]
    tun_address: String,
    #[arg(long, default_value = "10.200.0.2")]
    tun_destination: String,
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: String,
    #[arg(long, default_value_t = 1500)]
    tun_mtu: u16,
    #[arg(long)]
    egress_interface: Option<String>,
    #[arg(long)]
    egress_gateway: Option<String>,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Skip)]
    forwarding_mode: SystemCommandMode,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Skip)]
    nat_mode: SystemCommandMode,
    #[arg(long, default_value = "/private/tmp")]
    pf_rules_dir: PathBuf,
    #[arg(long, default_value = "com.apple/tunnel")]
    pf_anchor_prefix: String,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum SystemCommandMode {
    Skip,
    Print,
    Apply,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TargetOs {
    Linux,
    Macos,
    Other,
}

fn current_target_os() -> TargetOs {
    #[cfg(target_os = "linux")]
    {
        return TargetOs::Linux;
    }

    #[cfg(target_os = "macos")]
    {
        return TargetOs::Macos;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        TargetOs::Other
    }
}

#[derive(Debug, Default)]
struct ByteCounters {
    ingress_bytes: AtomicU64,
    egress_bytes: AtomicU64,
    last_ingress_at_unix_secs: AtomicU64,
    last_egress_at_unix_secs: AtomicU64,
    tun_read_packets: AtomicU64,
    tun_read_bytes: AtomicU64,
    tun_write_packets: AtomicU64,
    tun_write_bytes: AtomicU64,
    udp_rx_packets: AtomicU64,
    udp_rx_bytes: AtomicU64,
    udp_tx_packets: AtomicU64,
    udp_tx_bytes: AtomicU64,
    wireguard_encapsulated_packets: AtomicU64,
    wireguard_decapsulated_packets: AtomicU64,
    last_packet_error: Mutex<Option<String>>,
}

#[derive(Debug, Clone, Copy)]
struct PeerStatus {
    endpoint: Option<SocketAddr>,
    last_activity_unix_secs: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.cleanup_only {
        return run_cleanup_only(&cli);
    }

    if let Some(config_path) = &cli.config {
        let config: TunnelConfig = serde_json::from_str(&fs::read_to_string(config_path)?)?;
        config.validate()?;
        if let Some(wireguard) = &config.wireguard {
            return run_wireguard_gateway(&cli, &config, wireguard);
        }
    }

    run_json_session_gateway(&cli)
}

fn run_cleanup_only(cli: &Cli) -> Result<()> {
    let state = load_gateway_state(&cli.state_file)?;

    if cli.tun.forwarding_mode != SystemCommandMode::Skip {
        let commands = build_forwarding_cleanup_commands(&state);
        execute_commands(
            cli.tun.forwarding_mode,
            "gateway forwarding cleanup",
            &commands,
        )?;
    } else {
        println!("gateway forwarding cleanup skipped: forwarding_mode is skip");
    }

    if cli.tun.nat_mode != SystemCommandMode::Skip {
        handle_nat_cleanup(cli.tun.nat_mode, &state)?;
    } else {
        println!("gateway nat cleanup skipped: nat_mode is skip");
    }

    if cli.tun.forwarding_mode == SystemCommandMode::Apply
        || cli.tun.nat_mode == SystemCommandMode::Apply
    {
        remove_gateway_state(&cli.state_file)?;
        remove_gateway_state(&cli.status_file)?;
    }

    emit_status(
        &cli.status_file,
        &RuntimeStatus {
            component: ComponentKind::Gateway,
            state: HealthState::Healthy,
            phase: TunnelPhase::Active,
            tenant_id: None,
            tunnel_id: None,
            transport: TransportKind::WireGuardUdp,
            tunnel_interface: Some(state.tunnel_interface),
            peer_endpoint: None,
            ingress_bytes: 0,
            egress_bytes: 0,
            last_ingress_at_unix_secs: None,
            last_egress_at_unix_secs: None,
            last_peer_activity_unix_secs: None,
            last_activity_unix_secs: None,
            packet_path: PacketPathTelemetry::default(),
            observed_at_unix_secs: now_unix_secs(),
            detail: String::from("gateway cleanup complete"),
        },
    )?;

    Ok(())
}

fn run_json_session_gateway(cli: &Cli) -> Result<()> {
    let listener = TcpListener::bind(&cli.bind)?;
    let status = HealthStatus {
        component: ComponentKind::Gateway,
        state: HealthState::Healthy,
        detail: format!("gateway listening on {}", cli.bind),
    };
    println!("{}", serde_json::to_string_pretty(&status)?);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(stream, cli) {
                    eprintln!("gateway connection failed: {error:#}");
                }
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }

    Ok(())
}

fn run_wireguard_gateway(
    cli: &Cli,
    config: &TunnelConfig,
    wireguard: &WireGuardConfig,
) -> Result<()> {
    let bind_addr = format!(
        "{}:{}",
        wireguard.local_bind_host, wireguard.local_bind_port
    );
    let socket = UdpSocket::bind(&bind_addr)?;
    let status = HealthStatus {
        component: ComponentKind::Gateway,
        state: HealthState::Healthy,
        detail: format!("wireguard gateway listening on {bind_addr}"),
    };
    println!("{}", serde_json::to_string_pretty(&status)?);

    let device = create_tun_device(
        &cli.tun,
        Some(&wireguard.local_tunnel_address),
        Some(&wireguard.peer_tunnel_address),
    )?;
    let interface_name = device.tun_name()?;
    println!("gateway wireguard tun ready: {interface_name}");
    let previous_forwarding = query_ip_forwarding_enabled().ok();
    handle_gateway_networking(
        &cli.tun,
        &interface_name,
        Some(&wireguard.local_tunnel_address),
    )?;
    save_gateway_state(
        &cli.state_file,
        &cli.tun,
        &interface_name,
        previous_forwarding,
    )?;

    let tunnel = Arc::new(Mutex::new(build_wireguard_tunnel(wireguard, 2)?));
    let peer = Arc::new(Mutex::new(PeerStatus {
        endpoint: resolve_optional_socket_endpoint(wireguard.peer_endpoint.as_ref())?,
        last_activity_unix_secs: now_unix_secs(),
    }));
    let counters = Arc::new(ByteCounters::default());
    let output_file = prepare_output_file(
        cli.output_dir.as_deref(),
        &config.tenant_id,
        &config.tunnel_id,
    )?;
    let output_file = Arc::new(Mutex::new(output_file));
    let (mut tun_reader, mut tun_writer) = device.split();

    spawn_status_thread(
        cli.status_interval_secs,
        wireguard_stale_after_secs(cli.status_interval_secs, wireguard),
        cli.status_file.clone(),
        RuntimeStatusContext {
            component: ComponentKind::Gateway,
            tenant_id: Some(config.tenant_id.clone()),
            tunnel_id: Some(config.tunnel_id.clone()),
            transport: TransportKind::WireGuardUdp,
            tunnel_interface: interface_name.clone(),
            detail: String::from("wireguard gateway running"),
            started_at_unix_secs: now_unix_secs(),
        },
        Arc::clone(&peer),
        Arc::clone(&counters),
    );

    {
        let socket = socket.try_clone()?;
        let tunnel = Arc::clone(&tunnel);
        let peer = Arc::clone(&peer);
        let output = Arc::clone(&output_file);
        let counters = Arc::clone(&counters);
        thread::spawn(move || {
            if let Err(error) = wireguard_udp_receiver_loop(
                socket,
                tunnel,
                peer,
                &mut tun_writer,
                Some(output),
                counters,
                "gateway",
            ) {
                eprintln!("gateway wireguard udp receiver stopped: {error:#}");
            }
        });
    }

    {
        let socket = socket.try_clone()?;
        let tunnel = Arc::clone(&tunnel);
        let peer = Arc::clone(&peer);
        let counters = Arc::clone(&counters);
        thread::spawn(move || {
            if let Err(error) = wireguard_timer_loop(socket, tunnel, peer, counters, "gateway") {
                eprintln!("gateway wireguard timer stopped: {error:#}");
            }
        });
    }

    wireguard_tun_sender_loop(
        &mut tun_reader,
        socket,
        tunnel,
        peer,
        counters,
        config.max_chunk_bytes.max(cli.tun.tun_mtu as usize + 256),
        "gateway",
    )
}

fn handle_client(stream: TcpStream, cli: &Cli) -> Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = BufReader::new(stream);

    let open_message = match read_json_line::<_, AgentToGateway>(&mut reader)? {
        Some(message) => message,
        None => return Ok(()),
    };

    let (tenant_id, tunnel_id) = match open_message {
        AgentToGateway::SessionOpen {
            tenant_id,
            tunnel_id,
        } => (tenant_id, tunnel_id),
        other => {
            send_gateway_message(
                &writer,
                &GatewayToAgent::Error {
                    detail: format!("expected session_open, received {other:?}"),
                },
            )?;
            return Ok(());
        }
    };

    let mut usage = UsageRecord {
        tenant_id: tenant_id.clone(),
        tunnel_id: tunnel_id.clone(),
        ingress_bytes: 0,
        egress_bytes: 0,
        observed_at_unix_secs: now_unix_secs(),
    };

    let mut output_file = prepare_output_file(cli.output_dir.as_deref(), &tenant_id, &tunnel_id)?;
    let mut tun_writer = None;

    if cli.tun.tun {
        let device = create_tun_device(&cli.tun, None, None)?;
        let interface_name = device.tun_name()?;
        println!("gateway tun ready: {interface_name}");
        let previous_forwarding = query_ip_forwarding_enabled().ok();
        handle_gateway_networking(&cli.tun, &interface_name, None)?;
        save_gateway_state(
            &cli.state_file,
            &cli.tun,
            &interface_name,
            previous_forwarding,
        )?;
        let (mut tun_reader, writer_half) = device.split();
        tun_writer = Some(writer_half);

        let writer_for_packets = Arc::clone(&writer);
        let max_packet_bytes = cli.tun.tun_mtu as usize + 256;
        thread::spawn(move || {
            if let Err(error) =
                forward_tun_packets_json(&mut tun_reader, writer_for_packets, max_packet_bytes)
            {
                eprintln!("gateway tun reader stopped: {error:#}");
            }
        });
    }

    send_gateway_message(
        &writer,
        &GatewayToAgent::Health {
            status: HealthStatus {
                component: ComponentKind::Tunnel,
                state: HealthState::Healthy,
                detail: String::from("session established"),
            },
        },
    )?;

    while let Some(message) = read_json_line::<_, AgentToGateway>(&mut reader)? {
        match message {
            AgentToGateway::SessionOpen { .. } => {
                send_gateway_message(
                    &writer,
                    &GatewayToAgent::Error {
                        detail: String::from("session already established"),
                    },
                )?;
                break;
            }
            AgentToGateway::Heartbeat { .. } => {
                send_gateway_message(
                    &writer,
                    &GatewayToAgent::Health {
                        status: HealthStatus {
                            component: ComponentKind::Tunnel,
                            state: HealthState::Healthy,
                            detail: String::from("heartbeat acknowledged"),
                        },
                    },
                )?;
            }
            AgentToGateway::Payload { sequence, bytes } => {
                usage.ingress_bytes += bytes.len() as u64;
                usage.egress_bytes += bytes.len() as u64;
                usage.observed_at_unix_secs = now_unix_secs();

                if let Some(file) = output_file.as_mut() {
                    file.write_all(&bytes)?;
                    file.flush()?;
                }

                if let Some(writer_half) = tun_writer.as_mut() {
                    writer_half.write_all(&bytes)?;
                    writer_half.flush()?;
                }

                send_gateway_message(
                    &writer,
                    &GatewayToAgent::Ack {
                        sequence,
                        usage: usage.clone(),
                    },
                )?;
            }
            AgentToGateway::SessionClose => {
                send_gateway_message(
                    &writer,
                    &GatewayToAgent::FinalUsage {
                        usage: usage.clone(),
                    },
                )?;
                break;
            }
        }
    }

    Ok(())
}

fn wireguard_tun_sender_loop(
    tun_reader: &mut impl Read,
    socket: UdpSocket,
    tunnel: Arc<Mutex<Tunn>>,
    peer: Arc<Mutex<PeerStatus>>,
    counters: Arc<ByteCounters>,
    max_packet_bytes: usize,
    label: &str,
) -> Result<()> {
    let mut buf = vec![0_u8; max_packet_bytes];

    loop {
        let amount = tun_reader.read(&mut buf)?;
        if amount == 0 {
            continue;
        }
        counters
            .egress_bytes
            .fetch_add(amount as u64, Ordering::Relaxed);
        counters.tun_read_packets.fetch_add(1, Ordering::Relaxed);
        counters
            .tun_read_bytes
            .fetch_add(amount as u64, Ordering::Relaxed);
        counters
            .last_egress_at_unix_secs
            .store(now_unix_secs(), Ordering::Relaxed);

        let mut network_buf = vec![0_u8; amount + 512];
        let result = {
            let mut guard = tunnel
                .lock()
                .map_err(|_| anyhow!("{label} wireguard lock poisoned"))?;
            guard.encapsulate(&buf[..amount], &mut network_buf)
        };

        send_wireguard_network_result(result, &socket, &peer, &counters, label)?;
    }
}

fn wireguard_udp_receiver_loop(
    socket: UdpSocket,
    tunnel: Arc<Mutex<Tunn>>,
    peer: Arc<Mutex<PeerStatus>>,
    tun_writer: &mut impl Write,
    output_file: Option<Arc<Mutex<Option<File>>>>,
    counters: Arc<ByteCounters>,
    label: &str,
) -> Result<()> {
    let mut datagram = vec![0_u8; 65535];
    let mut plaintext = vec![0_u8; 65535];

    loop {
        let (amount, src_addr) = socket.recv_from(&mut datagram)?;
        counters.udp_rx_packets.fetch_add(1, Ordering::Relaxed);
        counters
            .udp_rx_bytes
            .fetch_add(amount as u64, Ordering::Relaxed);
        {
            let mut peer_guard = peer
                .lock()
                .map_err(|_| anyhow!("{label} peer lock poisoned"))?;
            peer_guard.endpoint = Some(src_addr);
            peer_guard.last_activity_unix_secs = now_unix_secs();
        }

        let mut input = Some((src_addr.ip(), amount));

        loop {
            let result = {
                let mut guard = tunnel
                    .lock()
                    .map_err(|_| anyhow!("{label} wireguard lock poisoned"))?;
                if let Some((src_ip, len)) = input.take() {
                    guard.decapsulate(Some(src_ip), &datagram[..len], &mut plaintext)
                } else {
                    guard.decapsulate(None, &[], &mut plaintext)
                }
            };

            match result {
                TunnResult::WriteToNetwork(packet) => {
                    let _ = send_udp_packet(&socket, &peer, packet, &counters, label)?;
                    continue;
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    counters
                        .wireguard_decapsulated_packets
                        .fetch_add(1, Ordering::Relaxed);
                    counters
                        .ingress_bytes
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    counters
                        .last_ingress_at_unix_secs
                        .store(now_unix_secs(), Ordering::Relaxed);
                    if let Some(output_file) = &output_file {
                        let mut guard = output_file
                            .lock()
                            .map_err(|_| anyhow!("{label} output file lock poisoned"))?;
                        if let Some(file) = guard.as_mut() {
                            file.write_all(packet)?;
                            file.flush()?;
                        }
                    }
                    tun_writer.write_all(packet)?;
                    tun_writer.flush()?;
                    counters.tun_write_packets.fetch_add(1, Ordering::Relaxed);
                    counters
                        .tun_write_bytes
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(error) => {
                    record_packet_error(
                        &counters,
                        format!("wireguard decapsulate error: {error:?}"),
                    );
                    eprintln!("{label} wireguard decapsulate error: {error:?}");
                    break;
                }
            }
        }
    }
}

fn wireguard_timer_loop(
    socket: UdpSocket,
    tunnel: Arc<Mutex<Tunn>>,
    peer: Arc<Mutex<PeerStatus>>,
    counters: Arc<ByteCounters>,
    label: &str,
) -> Result<()> {
    loop {
        thread::sleep(Duration::from_secs(1));
        let mut buf = vec![0_u8; 65535];
        let result = {
            let mut guard = tunnel
                .lock()
                .map_err(|_| anyhow!("{label} wireguard lock poisoned"))?;
            guard.update_timers(&mut buf)
        };

        if let TunnResult::WriteToNetwork(packet) = result {
            let _ = send_udp_packet(&socket, &peer, packet, &counters, label)?;
        }
    }
}

fn send_wireguard_network_result(
    result: TunnResult<'_>,
    socket: &UdpSocket,
    peer: &Arc<Mutex<PeerStatus>>,
    counters: &Arc<ByteCounters>,
    label: &str,
) -> Result<()> {
    match result {
        TunnResult::WriteToNetwork(packet) => {
            counters
                .wireguard_encapsulated_packets
                .fetch_add(1, Ordering::Relaxed);
            let _ = send_udp_packet(socket, peer, packet, counters, label)?;
            Ok(())
        }
        TunnResult::Done => Ok(()),
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => Ok(()),
        TunnResult::Err(error) => {
            record_packet_error(counters, format!("wireguard encapsulate error: {error:?}"));
            Err(anyhow!("{label} wireguard encapsulate error: {error:?}"))
        }
    }
}

fn send_udp_packet(
    socket: &UdpSocket,
    peer: &Arc<Mutex<PeerStatus>>,
    packet: &[u8],
    counters: &Arc<ByteCounters>,
    label: &str,
) -> Result<bool> {
    let mut guard = peer
        .lock()
        .map_err(|_| anyhow!("{label} peer lock poisoned"))?;
    let Some(target) = guard.endpoint else {
        return Ok(false);
    };
    socket.send_to(packet, target)?;
    counters.udp_tx_packets.fetch_add(1, Ordering::Relaxed);
    counters
        .udp_tx_bytes
        .fetch_add(packet.len() as u64, Ordering::Relaxed);
    guard.last_activity_unix_secs = now_unix_secs();
    Ok(true)
}

fn build_wireguard_tunnel(wireguard: &WireGuardConfig, index: u32) -> Result<Tunn> {
    let private_key = StaticSecret::from(decode_key_32(&wireguard.private_key_base64)?);
    let peer_public_key = PublicKey::from(decode_key_32(&wireguard.peer_public_key_base64)?);
    let preshared_key = wireguard
        .preshared_key_base64
        .as_ref()
        .map(|key| decode_key_32(key))
        .transpose()?;

    Ok(Tunn::new(
        private_key,
        peer_public_key,
        preshared_key,
        wireguard.persistent_keepalive_secs,
        index,
        None,
    ))
}

fn resolve_optional_socket_endpoint(
    endpoint: Option<&SocketEndpoint>,
) -> Result<Option<SocketAddr>> {
    endpoint.map(resolve_socket_endpoint).transpose()
}

fn resolve_socket_endpoint(endpoint: &SocketEndpoint) -> Result<SocketAddr> {
    format!("{}:{}", endpoint.host, endpoint.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("could not resolve {}:{}", endpoint.host, endpoint.port))
}

#[derive(Debug, Clone)]
struct RuntimeStatusContext {
    component: ComponentKind,
    tenant_id: Option<String>,
    tunnel_id: Option<String>,
    transport: TransportKind,
    tunnel_interface: String,
    detail: String,
    started_at_unix_secs: u64,
}

fn spawn_status_thread(
    interval_secs: u64,
    stale_after_secs: u64,
    status_file: PathBuf,
    context: RuntimeStatusContext,
    peer: Arc<Mutex<PeerStatus>>,
    counters: Arc<ByteCounters>,
) {
    if interval_secs == 0 {
        return;
    }

    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(interval_secs));
        let now = now_unix_secs();
        let (peer_endpoint, last_peer_activity) = peer
            .lock()
            .ok()
            .map(|guard| {
                (
                    guard.endpoint.map(|addr| addr.to_string()),
                    guard.last_activity_unix_secs,
                )
            })
            .unwrap_or((None, 0));
        let last_ingress = counters.last_ingress_at_unix_secs.load(Ordering::Relaxed);
        let last_egress = counters.last_egress_at_unix_secs.load(Ordering::Relaxed);
        let last_activity = last_peer_activity.max(last_ingress).max(last_egress);
        let is_stale = last_activity != 0 && now.saturating_sub(last_activity) > stale_after_secs;
        let uptime = now.saturating_sub(context.started_at_unix_secs);
        let has_traffic = counters.ingress_bytes.load(Ordering::Relaxed) > 0
            || counters.egress_bytes.load(Ordering::Relaxed) > 0;
        let (state, phase, detail) = if peer_endpoint.is_none() {
            (
                HealthState::Degraded,
                TunnelPhase::Establishing,
                String::from("wireguard peer endpoint is not established"),
            )
        } else if !has_traffic && uptime <= interval_secs * 3 {
            (
                HealthState::Degraded,
                TunnelPhase::Recovering,
                format!(
                    "wireguard peer discovered; awaiting traffic {}s after start",
                    uptime
                ),
            )
        } else if is_stale {
            (
                HealthState::Degraded,
                TunnelPhase::Stale,
                format!(
                    "wireguard path is stale; last activity {}s ago",
                    now.saturating_sub(last_activity)
                ),
            )
        } else {
            (
                HealthState::Healthy,
                TunnelPhase::Active,
                context.detail.clone(),
            )
        };
        let status = RuntimeStatus {
            component: context.component.clone(),
            state,
            phase,
            tenant_id: context.tenant_id.clone(),
            tunnel_id: context.tunnel_id.clone(),
            transport: context.transport.clone(),
            tunnel_interface: Some(context.tunnel_interface.clone()),
            peer_endpoint,
            ingress_bytes: counters.ingress_bytes.load(Ordering::Relaxed),
            egress_bytes: counters.egress_bytes.load(Ordering::Relaxed),
            last_ingress_at_unix_secs: non_zero_u64(last_ingress),
            last_egress_at_unix_secs: non_zero_u64(last_egress),
            last_peer_activity_unix_secs: non_zero_u64(last_peer_activity),
            last_activity_unix_secs: non_zero_u64(last_activity),
            packet_path: packet_path_snapshot(&counters),
            observed_at_unix_secs: now_unix_secs(),
            detail,
        };

        if let Err(error) = emit_status(&status_file, &status) {
            eprintln!("gateway status render failed: {error}");
        }
    });
}

fn wireguard_stale_after_secs(interval_secs: u64, wireguard: &WireGuardConfig) -> u64 {
    let status_window = interval_secs.saturating_mul(3);
    let keepalive_window = wireguard
        .persistent_keepalive_secs
        .map(|secs| u64::from(secs).saturating_mul(2))
        .unwrap_or(30);
    status_window.max(keepalive_window)
}

fn packet_path_snapshot(counters: &ByteCounters) -> PacketPathTelemetry {
    PacketPathTelemetry {
        tun_read_packets: counters.tun_read_packets.load(Ordering::Relaxed),
        tun_read_bytes: counters.tun_read_bytes.load(Ordering::Relaxed),
        tun_write_packets: counters.tun_write_packets.load(Ordering::Relaxed),
        tun_write_bytes: counters.tun_write_bytes.load(Ordering::Relaxed),
        udp_rx_packets: counters.udp_rx_packets.load(Ordering::Relaxed),
        udp_rx_bytes: counters.udp_rx_bytes.load(Ordering::Relaxed),
        udp_tx_packets: counters.udp_tx_packets.load(Ordering::Relaxed),
        udp_tx_bytes: counters.udp_tx_bytes.load(Ordering::Relaxed),
        wireguard_encapsulated_packets: counters
            .wireguard_encapsulated_packets
            .load(Ordering::Relaxed),
        wireguard_decapsulated_packets: counters
            .wireguard_decapsulated_packets
            .load(Ordering::Relaxed),
        last_packet_error: counters
            .last_packet_error
            .lock()
            .ok()
            .and_then(|error| error.clone()),
    }
}

fn record_packet_error(counters: &ByteCounters, detail: String) {
    if let Ok(mut error) = counters.last_packet_error.lock() {
        *error = Some(detail);
    }
}

fn save_gateway_state(
    state_file: &PathBuf,
    tun_args: &TunArgs,
    interface_name: &str,
    forwarding_was_enabled: Option<bool>,
) -> Result<()> {
    let state = GatewayRuntimeState {
        tunnel_interface: interface_name.to_owned(),
        nat_anchor_name: build_nat_anchor_name(interface_name, tun_args),
        nat_rules_path: build_nat_rules_path(interface_name, tun_args),
        forwarding_was_enabled,
        egress_interface: tun_args.egress_interface.clone(),
    };
    fs::write(state_file, serde_json::to_string_pretty(&state)?)?;
    Ok(())
}

fn load_gateway_state(state_file: &PathBuf) -> Result<GatewayRuntimeState> {
    let state = fs::read_to_string(state_file).with_context(|| {
        format!(
            "failed to read gateway state file: {}",
            state_file.display()
        )
    })?;
    Ok(serde_json::from_str(&state)?)
}

fn remove_gateway_state(state_file: &PathBuf) -> Result<()> {
    if state_file.exists() {
        fs::remove_file(state_file).with_context(|| {
            format!(
                "failed to remove gateway state file: {}",
                state_file.display()
            )
        })?;
    }
    Ok(())
}

fn emit_status(status_file: &PathBuf, status: &RuntimeStatus) -> Result<()> {
    let rendered = serde_json::to_string_pretty(status)?;
    fs::write(status_file, &rendered)?;
    println!("{rendered}");
    Ok(())
}

fn non_zero_u64(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn forward_tun_packets_json(
    tun_reader: &mut impl Read,
    writer: Arc<Mutex<TcpStream>>,
    max_packet_bytes: usize,
) -> Result<()> {
    let mut sequence = 0_u64;
    let mut buf = vec![0_u8; max_packet_bytes];

    loop {
        let amount = tun_reader.read(&mut buf)?;
        if amount == 0 {
            continue;
        }

        send_gateway_message(
            &writer,
            &GatewayToAgent::Payload {
                sequence,
                bytes: buf[..amount].to_vec(),
            },
        )?;
        sequence += 1;
    }
}

fn send_gateway_message(writer: &Arc<Mutex<TcpStream>>, message: &GatewayToAgent) -> Result<()> {
    let mut guard = writer
        .lock()
        .map_err(|_| anyhow!("tcp writer lock poisoned"))?;
    write_json_line(&mut *guard, message)?;
    Ok(())
}

fn create_tun_device(
    tun_args: &TunArgs,
    local_address: Option<&str>,
    peer_address: Option<&str>,
) -> Result<tun::Device> {
    let mut config = tun::Configuration::default();
    config
        .address(parse_ip(local_address.unwrap_or(&tun_args.tun_address))?)
        .destination(parse_ip(peer_address.unwrap_or(&tun_args.tun_destination))?)
        .netmask(parse_ip(&tun_args.tun_netmask)?)
        .mtu(tun_args.tun_mtu)
        .up();

    if let Some(name) = &tun_args.tun_name {
        config.tun_name(name);
    }

    #[cfg(target_os = "linux")]
    config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });

    #[cfg(target_os = "macos")]
    config.platform_config(|platform| {
        platform.enable_routing(false);
    });

    let device = tun::create(&config)?;
    Ok(device)
}

fn parse_ip(value: &str) -> Result<IpAddr> {
    value
        .parse()
        .with_context(|| format!("invalid IP address: {value}"))
}

fn handle_gateway_networking(
    tun_args: &TunArgs,
    interface_name: &str,
    local_tunnel_address: Option<&str>,
) -> Result<()> {
    handle_forwarding(tun_args.forwarding_mode, interface_name)?;
    handle_nat(
        tun_args.nat_mode,
        interface_name,
        tun_args,
        local_tunnel_address,
    )
}

fn build_nat_anchor_name(interface_name: &str, tun_args: &TunArgs) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        return Some(format!("{}-{}", tun_args.pf_anchor_prefix, interface_name));
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = interface_name;
        let _ = tun_args;
        None
    }
}

fn build_nat_rules_path(interface_name: &str, tun_args: &TunArgs) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return Some(
            tun_args
                .pf_rules_dir
                .join(format!("tunnel-{interface_name}.pf.conf")),
        );
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = interface_name;
        let _ = tun_args;
        None
    }
}

fn handle_forwarding(mode: SystemCommandMode, interface_name: &str) -> Result<()> {
    if mode == SystemCommandMode::Skip {
        return Ok(());
    }

    let commands = build_forwarding_commands(interface_name);
    execute_commands(mode, "gateway forwarding", &commands)
}

fn handle_nat(
    mode: SystemCommandMode,
    interface_name: &str,
    tun_args: &TunArgs,
    local_tunnel_address: Option<&str>,
) -> Result<()> {
    if mode == SystemCommandMode::Skip {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        return handle_macos_nat(mode, interface_name, tun_args, local_tunnel_address);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = local_tunnel_address;
        let commands = build_nat_commands(interface_name, tun_args.egress_interface.as_deref())?;
        return execute_commands(mode, "gateway nat", &commands);
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn build_forwarding_cleanup_commands(state: &GatewayRuntimeState) -> Vec<Vec<String>> {
    build_forwarding_cleanup_commands_for_os(current_target_os(), state)
}

fn build_forwarding_cleanup_commands_for_os(
    target_os: TargetOs,
    state: &GatewayRuntimeState,
) -> Vec<Vec<String>> {
    match target_os {
        TargetOs::Linux => {
            let mut commands = vec![
                vec![
                    String::from("iptables"),
                    String::from("-D"),
                    String::from("FORWARD"),
                    String::from("-i"),
                    state.tunnel_interface.clone(),
                    String::from("-j"),
                    String::from("ACCEPT"),
                ],
                vec![
                    String::from("iptables"),
                    String::from("-D"),
                    String::from("FORWARD"),
                    String::from("-o"),
                    state.tunnel_interface.clone(),
                    String::from("-m"),
                    String::from("state"),
                    String::from("--state"),
                    String::from("RELATED,ESTABLISHED"),
                    String::from("-j"),
                    String::from("ACCEPT"),
                ],
            ];

            if matches!(state.forwarding_was_enabled, Some(false)) {
                commands.push(vec![
                    String::from("sysctl"),
                    String::from("-w"),
                    String::from("net.ipv4.ip_forward=0"),
                ]);
            }

            commands
        }
        TargetOs::Macos => {
            if matches!(state.forwarding_was_enabled, Some(false)) {
                vec![vec![
                    String::from("sysctl"),
                    String::from("-w"),
                    String::from("net.inet.ip.forwarding=0"),
                ]]
            } else {
                Vec::new()
            }
        }
        TargetOs::Other => Vec::new(),
    }
}

fn handle_nat_cleanup(mode: SystemCommandMode, state: &GatewayRuntimeState) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return handle_macos_nat_cleanup(mode, state);
    }

    #[cfg(target_os = "linux")]
    {
        let commands = build_nat_cleanup_commands(state)?;
        return execute_commands(mode, "gateway nat cleanup", &commands);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = mode;
        let _ = state;
        Ok(())
    }
}

fn build_forwarding_commands(interface_name: &str) -> Vec<Vec<String>> {
    build_forwarding_commands_for_os(current_target_os(), interface_name)
}

fn build_forwarding_commands_for_os(target_os: TargetOs, interface_name: &str) -> Vec<Vec<String>> {
    match target_os {
        TargetOs::Linux => vec![
            vec![
                String::from("sysctl"),
                String::from("-w"),
                String::from("net.ipv4.ip_forward=1"),
            ],
            vec![
                String::from("iptables"),
                String::from("-A"),
                String::from("FORWARD"),
                String::from("-i"),
                String::from(interface_name),
                String::from("-j"),
                String::from("ACCEPT"),
            ],
            vec![
                String::from("iptables"),
                String::from("-A"),
                String::from("FORWARD"),
                String::from("-o"),
                String::from(interface_name),
                String::from("-m"),
                String::from("state"),
                String::from("--state"),
                String::from("RELATED,ESTABLISHED"),
                String::from("-j"),
                String::from("ACCEPT"),
            ],
        ],
        TargetOs::Macos => {
            let _ = interface_name;
            vec![vec![
                String::from("sysctl"),
                String::from("-w"),
                String::from("net.inet.ip.forwarding=1"),
            ]]
        }
        TargetOs::Other => vec![vec![
            String::from("echo"),
            format!("manual forwarding enable required for {interface_name}"),
        ]],
    }
}

fn query_ip_forwarding_enabled() -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "net.ipv4.ip_forward"])
            .output()
            .context("failed to query net.ipv4.ip_forward")?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to query net.ipv4.ip_forward: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        return Ok(String::from_utf8_lossy(&output.stdout).trim() == "1");
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .context("failed to query net.inet.ip.forwarding")?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to query net.inet.ip.forwarding: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        return Ok(String::from_utf8_lossy(&output.stdout).trim() == "1");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(false)
    }
}

#[cfg(not(target_os = "macos"))]
fn build_nat_commands(
    interface_name: &str,
    egress_interface: Option<&str>,
) -> Result<Vec<Vec<String>>> {
    build_nat_commands_for_os(current_target_os(), interface_name, egress_interface)
}

#[allow(dead_code)]
fn build_nat_commands_for_os(
    target_os: TargetOs,
    interface_name: &str,
    egress_interface: Option<&str>,
) -> Result<Vec<Vec<String>>> {
    match target_os {
        TargetOs::Linux => {
            let egress_interface = egress_interface.ok_or_else(|| {
                anyhow!("--egress-interface is required when nat-mode is not skip")
            })?;
            Ok(vec![
                vec![
                    String::from("iptables"),
                    String::from("-t"),
                    String::from("nat"),
                    String::from("-A"),
                    String::from("POSTROUTING"),
                    String::from("-o"),
                    String::from(egress_interface),
                    String::from("-j"),
                    String::from("MASQUERADE"),
                ],
                vec![
                    String::from("iptables"),
                    String::from("-A"),
                    String::from("FORWARD"),
                    String::from("-i"),
                    String::from(interface_name),
                    String::from("-o"),
                    String::from(egress_interface),
                    String::from("-j"),
                    String::from("ACCEPT"),
                ],
            ])
        }
        TargetOs::Macos | TargetOs::Other => Ok(Vec::new()),
    }
}

#[allow(dead_code)]
#[cfg(target_os = "linux")]
fn build_nat_cleanup_commands(state: &GatewayRuntimeState) -> Result<Vec<Vec<String>>> {
    build_nat_cleanup_commands_for_os(TargetOs::Linux, state)
}

#[allow(dead_code)]
fn build_nat_cleanup_commands_for_os(
    target_os: TargetOs,
    state: &GatewayRuntimeState,
) -> Result<Vec<Vec<String>>> {
    match target_os {
        TargetOs::Linux => {
            let egress_interface = state
                .egress_interface
                .as_deref()
                .ok_or_else(|| anyhow!("gateway state missing egress interface"))?;
            Ok(vec![
                vec![
                    String::from("iptables"),
                    String::from("-t"),
                    String::from("nat"),
                    String::from("-D"),
                    String::from("POSTROUTING"),
                    String::from("-o"),
                    String::from(egress_interface),
                    String::from("-j"),
                    String::from("MASQUERADE"),
                ],
                vec![
                    String::from("iptables"),
                    String::from("-D"),
                    String::from("FORWARD"),
                    String::from("-i"),
                    state.tunnel_interface.clone(),
                    String::from("-o"),
                    String::from(egress_interface),
                    String::from("-j"),
                    String::from("ACCEPT"),
                ],
            ])
        }
        TargetOs::Macos | TargetOs::Other => Ok(Vec::new()),
    }
}

#[cfg(target_os = "macos")]
fn handle_macos_nat(
    mode: SystemCommandMode,
    interface_name: &str,
    tun_args: &TunArgs,
    local_tunnel_address: Option<&str>,
) -> Result<()> {
    let egress_interface = tun_args
        .egress_interface
        .as_deref()
        .ok_or_else(|| anyhow!("--egress-interface is required when nat-mode is not skip"))?;
    let egress_gateway = match tun_args.egress_gateway.as_deref() {
        Some(gateway) => Some(gateway.to_owned()),
        None => query_macos_default_gateway(egress_interface)?,
    };
    let subnet_source = local_tunnel_address.unwrap_or(&tun_args.tun_address);
    let subnet = ipv4_subnet(subnet_source, &tun_args.tun_netmask)?;
    let anchor_name = build_nat_anchor_name(interface_name, tun_args)
        .ok_or_else(|| anyhow!("macOS NAT anchor name is unavailable"))?;
    let rules_path = tun_args
        .pf_rules_dir
        .join(format!("tunnel-{interface_name}.pf.conf"));
    let rules = build_macos_pf_rules(
        interface_name,
        egress_interface,
        egress_gateway.as_deref(),
        &subnet,
    );

    match mode {
        SystemCommandMode::Skip => Ok(()),
        SystemCommandMode::Print => {
            println!("gateway nat anchor: {anchor_name}");
            println!("gateway nat rules path: {}", rules_path.display());
            println!("gateway nat rules:\n{rules}");
            println!("gateway nat command: pfctl -E");
            println!(
                "gateway nat command: pfctl -a {} -f {}",
                anchor_name,
                rules_path.display()
            );
            Ok(())
        }
        SystemCommandMode::Apply => {
            fs::create_dir_all(&tun_args.pf_rules_dir)?;
            fs::write(&rules_path, &rules)?;
            run_command("gateway nat", &["pfctl", "-E"])?;
            let rules_path_string = rules_path.to_string_lossy().into_owned();
            run_command(
                "gateway nat",
                &[
                    "pfctl",
                    "-a",
                    anchor_name.as_str(),
                    "-f",
                    &rules_path_string,
                ],
            )?;
            println!("gateway nat anchor: {anchor_name}");
            println!("gateway nat rules path: {}", rules_path.display());
            if let Some(gateway) = &egress_gateway {
                println!("gateway egress route-to: {egress_interface} {gateway}");
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
fn handle_macos_nat_cleanup(mode: SystemCommandMode, state: &GatewayRuntimeState) -> Result<()> {
    let anchor_name = state
        .nat_anchor_name
        .as_deref()
        .ok_or_else(|| anyhow!("gateway state missing nat anchor name"))?;
    let rules_path = state
        .nat_rules_path
        .as_ref()
        .ok_or_else(|| anyhow!("gateway state missing nat rules path"))?;

    match mode {
        SystemCommandMode::Skip => Ok(()),
        SystemCommandMode::Print => {
            println!("gateway nat cleanup command: pfctl -a {anchor_name} -F all");
            println!("gateway nat cleanup file removal: {}", rules_path.display());
            Ok(())
        }
        SystemCommandMode::Apply => {
            run_command(
                "gateway nat cleanup",
                &["pfctl", "-a", anchor_name, "-F", "all"],
            )?;
            if rules_path.exists() {
                fs::remove_file(rules_path).with_context(|| {
                    format!(
                        "failed to remove gateway nat rules file: {}",
                        rules_path.display()
                    )
                })?;
            }
            println!("gateway nat cleanup anchor: {anchor_name}");
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
fn query_macos_default_gateway(egress_interface: &str) -> Result<Option<String>> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("failed to query macOS default route")?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to query macOS default route\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let gateway = parse_route_get_field(&stdout, "gateway");
    let interface = parse_route_get_field(&stdout, "interface");

    if interface.as_deref() == Some(egress_interface) {
        return Ok(gateway);
    }

    Ok(None)
}

#[cfg(target_os = "macos")]
fn parse_route_get_field(output: &str, field: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key.trim() == field).then(|| value.trim().to_owned())
    })
}

#[cfg(target_os = "macos")]
fn build_macos_pf_rules(
    interface_name: &str,
    egress_interface: &str,
    egress_gateway: Option<&str>,
    subnet: &str,
) -> String {
    let route_to = egress_gateway
        .map(|gateway| format!(" route-to ({egress_interface} {gateway})"))
        .unwrap_or_default();

    format!(
        "nat on {egress_interface} from {subnet} to any -> ({egress_interface})\n\
pass out quick on {egress_interface} inet from {subnet} to any keep state\n\
pass in quick on {interface_name}{route_to} inet from {subnet} to any keep state\n\
pass out quick on {interface_name} inet from any to {subnet} keep state\n"
    )
}

fn run_command(label: &str, command: &[&str]) -> Result<()> {
    let rendered = command.join(" ");
    let mut process = Command::new(command[0]);
    if command.len() > 1 {
        process.args(&command[1..]);
    }
    let output = process
        .output()
        .with_context(|| format!("failed to execute {label} command: {rendered}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{label} command failed: {rendered}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

fn ipv4_subnet(address: &str, netmask: &str) -> Result<String> {
    let address: Ipv4Addr = address
        .parse()
        .with_context(|| format!("invalid IPv4 address: {address}"))?;
    let netmask: Ipv4Addr = netmask
        .parse()
        .with_context(|| format!("invalid IPv4 netmask: {netmask}"))?;

    let address_u32 = u32::from(address);
    let mask_u32 = u32::from(netmask);
    let network = Ipv4Addr::from(address_u32 & mask_u32);
    let prefix = mask_u32.count_ones();

    Ok(format!("{network}/{prefix}"))
}

fn execute_commands(mode: SystemCommandMode, label: &str, commands: &[Vec<String>]) -> Result<()> {
    for command in commands {
        let rendered = shell_join(command);
        match mode {
            SystemCommandMode::Skip => {}
            SystemCommandMode::Print => {
                println!("{label} command: {rendered}");
            }
            SystemCommandMode::Apply => {
                println!("{label} apply: {rendered}");
                let mut process = Command::new(&command[0]);
                if command.len() > 1 {
                    process.args(&command[1..]);
                }
                let output = process
                    .output()
                    .with_context(|| format!("failed to execute {label} command: {rendered}"))?;
                if !output.status.success() {
                    return Err(anyhow!(
                        "{label} command failed: {rendered}\nstdout: {}\nstderr: {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    ));
                }
            }
        }
    }

    Ok(())
}

fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| {
            if part.contains(' ') {
                format!("{part:?}")
            } else {
                part.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn prepare_output_file(
    output_dir: Option<&Path>,
    tenant_id: &str,
    tunnel_id: &str,
) -> Result<Option<File>> {
    let Some(output_dir) = output_dir else {
        return Ok(None);
    };

    fs::create_dir_all(output_dir)?;
    let path = output_dir.join(format!("{tenant_id}_{tunnel_id}_{}.bin", now_unix_secs()));
    Ok(Some(File::create(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_forwarding_commands_enable_ip_forwarding_and_forward_rules() {
        assert_eq!(
            build_forwarding_commands_for_os(TargetOs::Linux, "tun0"),
            vec![
                vec!["sysctl", "-w", "net.ipv4.ip_forward=1"],
                vec!["iptables", "-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT"],
                vec![
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-o",
                    "tun0",
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            ]
            .into_iter()
            .map(string_vec)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn linux_nat_commands_masquerade_and_cleanup_by_interface() -> Result<()> {
        assert_eq!(
            build_nat_commands_for_os(TargetOs::Linux, "tun0", Some("eth0"))?,
            vec![
                vec![
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    "eth0",
                    "-j",
                    "MASQUERADE",
                ],
                vec!["iptables", "-A", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT",],
            ]
            .into_iter()
            .map(string_vec)
            .collect::<Vec<_>>()
        );

        let state = GatewayRuntimeState {
            tunnel_interface: String::from("tun0"),
            nat_anchor_name: None,
            nat_rules_path: None,
            forwarding_was_enabled: Some(false),
            egress_interface: Some(String::from("eth0")),
        };
        assert_eq!(
            build_nat_cleanup_commands_for_os(TargetOs::Linux, &state)?,
            vec![
                vec![
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    "eth0",
                    "-j",
                    "MASQUERADE",
                ],
                vec!["iptables", "-D", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT",],
            ]
            .into_iter()
            .map(string_vec)
            .collect::<Vec<_>>()
        );

        Ok(())
    }

    #[test]
    fn macos_forwarding_commands_are_preserved() {
        assert_eq!(
            build_forwarding_commands_for_os(TargetOs::Macos, "utun6"),
            vec![string_vec(
                vec!["sysctl", "-w", "net.inet.ip.forwarding=1",]
            )]
        );
    }

    fn string_vec(parts: Vec<&str>) -> Vec<String> {
        parts.into_iter().map(String::from).collect()
    }
}
