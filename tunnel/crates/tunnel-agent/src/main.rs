#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufReader, IsTerminal, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::{Args, Parser, ValueEnum};
use tun::AbstractDevice;
use tunnel_shared::{
    decode_key_32, now_unix_secs, read_json_line, write_json_line, AgentToGateway, GatewayToAgent,
    SocketEndpoint, TunnelConfig, WireGuardConfig,
};

#[derive(Debug, Parser)]
#[command(name = "tunnel-agent")]
#[command(about = "Phase 1 Tunnel agent", long_about = None)]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    input: Option<PathBuf>,
    #[arg(long)]
    payload: Option<String>,
    #[command(flatten)]
    tun: TunArgs,
}

#[derive(Debug, Args, Clone)]
struct TunArgs {
    #[arg(long)]
    tun: bool,
    #[arg(long)]
    tun_name: Option<String>,
    #[arg(long, default_value = "10.200.0.2")]
    tun_address: String,
    #[arg(long, default_value = "10.200.0.1")]
    tun_destination: String,
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: String,
    #[arg(long, default_value_t = 1500)]
    tun_mtu: u16,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Skip)]
    route_mode: SystemCommandMode,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum SystemCommandMode {
    Skip,
    Print,
    Apply,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config: TunnelConfig = serde_json::from_str(&fs::read_to_string(&cli.config)?)?;
    config.validate()?;

    if let Some(wireguard) = &config.wireguard {
        return run_wireguard_mode(&config, &cli.tun, wireguard);
    }

    run_json_session_mode(&config, &cli)
}

fn run_json_session_mode(config: &TunnelConfig, cli: &Cli) -> Result<()> {
    let stream = TcpStream::connect((config.gateway.host.as_str(), config.gateway.port))?;
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = BufReader::new(stream);

    open_session(&writer, config)?;
    read_and_print_message(&mut reader)?;
    send_heartbeat(&writer)?;
    read_and_print_message(&mut reader)?;

    spawn_heartbeat_thread(Arc::clone(&writer), config.heartbeat_interval_secs);

    if cli.tun.tun {
        run_json_tun_mode(config, &cli.tun, writer, &mut reader)
    } else {
        run_payload_mode(config, cli, &writer, &mut reader)
    }
}

fn run_payload_mode(
    config: &TunnelConfig,
    cli: &Cli,
    writer: &Arc<Mutex<TcpStream>>,
    reader: &mut BufReader<TcpStream>,
) -> Result<()> {
    let payload = load_payload(cli)?;

    for (sequence, chunk) in payload.chunks(config.max_chunk_bytes).enumerate() {
        send_message(
            writer,
            &AgentToGateway::Payload {
                sequence: sequence as u64,
                bytes: chunk.to_vec(),
            },
        )?;

        read_and_print_message(reader)?;
    }

    close_session(writer)?;
    read_and_print_message(reader)?;
    Ok(())
}

fn run_json_tun_mode(
    config: &TunnelConfig,
    tun_args: &TunArgs,
    writer: Arc<Mutex<TcpStream>>,
    reader: &mut BufReader<TcpStream>,
) -> Result<()> {
    let device = create_tun_device(tun_args, None, None)?;
    let interface_name = device.tun_name()?;
    println!("agent tun ready: {interface_name}");

    handle_agent_routes(tun_args.route_mode, &interface_name, config)?;

    let (mut tun_reader, mut tun_writer) = device.split();
    let writer_for_packets = Arc::clone(&writer);
    let max_packet_bytes = config.max_chunk_bytes.max(2048);

    thread::spawn(move || {
        if let Err(error) =
            forward_tun_packets_json(&mut tun_reader, writer_for_packets, max_packet_bytes)
        {
            eprintln!("agent tun reader stopped: {error:#}");
        }
    });

    while let Some(message) = read_json_line::<_, GatewayToAgent>(reader)? {
        match message {
            GatewayToAgent::Health { status } => {
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            GatewayToAgent::Ack { sequence, usage } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GatewayToAgent::Ack { sequence, usage })?
                );
            }
            GatewayToAgent::Payload { sequence, bytes } => {
                tun_writer.write_all(&bytes)?;
                tun_writer.flush()?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GatewayToAgent::Payload { sequence, bytes })?
                );
            }
            GatewayToAgent::FinalUsage { usage } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GatewayToAgent::FinalUsage { usage })?
                );
                break;
            }
            GatewayToAgent::Error { detail } => {
                return Err(anyhow!(detail));
            }
        }
    }

    Ok(())
}

fn run_wireguard_mode(
    config: &TunnelConfig,
    tun_args: &TunArgs,
    wireguard: &WireGuardConfig,
) -> Result<()> {
    let device = create_tun_device(
        tun_args,
        Some(&wireguard.local_tunnel_address),
        Some(&wireguard.peer_tunnel_address),
    )?;
    let interface_name = device.tun_name()?;
    println!("agent wireguard tun ready: {interface_name}");

    handle_agent_routes(tun_args.route_mode, &interface_name, config)?;

    let peer_endpoint = resolve_socket_endpoint(
        wireguard
            .peer_endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("wireguard peer endpoint is required for the agent"))?,
    )?;
    let socket = UdpSocket::bind((
        wireguard.local_bind_host.as_str(),
        wireguard.local_bind_port,
    ))?;
    println!("agent wireguard udp bind: {}", socket.local_addr()?);

    let tunnel = Arc::new(Mutex::new(build_wireguard_tunnel(wireguard, 1)?));
    let peer = Arc::new(Mutex::new(Some(peer_endpoint)));
    let (mut tun_reader, mut tun_writer) = device.split();

    {
        let socket = socket.try_clone()?;
        let tunnel = Arc::clone(&tunnel);
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            if let Err(error) =
                wireguard_udp_receiver_loop(socket, tunnel, peer, &mut tun_writer, "agent")
            {
                eprintln!("agent wireguard udp receiver stopped: {error:#}");
            }
        });
    }

    {
        let socket = socket.try_clone()?;
        let tunnel = Arc::clone(&tunnel);
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            if let Err(error) = wireguard_timer_loop(socket, tunnel, peer, "agent") {
                eprintln!("agent wireguard timer stopped: {error:#}");
            }
        });
    }

    wireguard_tun_sender_loop(
        &mut tun_reader,
        socket,
        tunnel,
        peer,
        config.max_chunk_bytes.max(tun_args.tun_mtu as usize + 256),
        "agent",
    )
}

fn wireguard_tun_sender_loop(
    tun_reader: &mut impl Read,
    socket: UdpSocket,
    tunnel: Arc<Mutex<Tunn>>,
    peer: Arc<Mutex<Option<SocketAddr>>>,
    max_packet_bytes: usize,
    label: &str,
) -> Result<()> {
    let mut buf = vec![0_u8; max_packet_bytes];

    loop {
        let amount = tun_reader.read(&mut buf)?;
        if amount == 0 {
            continue;
        }

        let mut network_buf = vec![0_u8; amount + 512];
        let result = {
            let mut guard = tunnel
                .lock()
                .map_err(|_| anyhow!("{label} wireguard lock poisoned"))?;
            guard.encapsulate(&buf[..amount], &mut network_buf)
        };

        send_wireguard_network_result(result, &socket, &peer, label)?;
    }
}

fn wireguard_udp_receiver_loop(
    socket: UdpSocket,
    tunnel: Arc<Mutex<Tunn>>,
    peer: Arc<Mutex<Option<SocketAddr>>>,
    tun_writer: &mut impl Write,
    label: &str,
) -> Result<()> {
    let mut datagram = vec![0_u8; 65535];
    let mut plaintext = vec![0_u8; 65535];

    loop {
        let (amount, src_addr) = socket.recv_from(&mut datagram)?;
        {
            let mut peer_guard = peer
                .lock()
                .map_err(|_| anyhow!("{label} peer lock poisoned"))?;
            *peer_guard = Some(src_addr);
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
                    send_udp_packet(&socket, &peer, packet, label)?;
                    continue;
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tun_writer.write_all(packet)?;
                    tun_writer.flush()?;
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(error) => {
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
    peer: Arc<Mutex<Option<SocketAddr>>>,
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
            send_udp_packet(&socket, &peer, packet, label)?;
        }
    }
}

fn send_wireguard_network_result(
    result: TunnResult<'_>,
    socket: &UdpSocket,
    peer: &Arc<Mutex<Option<SocketAddr>>>,
    label: &str,
) -> Result<()> {
    match result {
        TunnResult::WriteToNetwork(packet) => send_udp_packet(socket, peer, packet, label),
        TunnResult::Done => Ok(()),
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => Ok(()),
        TunnResult::Err(error) => Err(anyhow!("{label} wireguard encapsulate error: {error:?}")),
    }
}

fn send_udp_packet(
    socket: &UdpSocket,
    peer: &Arc<Mutex<Option<SocketAddr>>>,
    packet: &[u8],
    label: &str,
) -> Result<()> {
    let target = *peer
        .lock()
        .map_err(|_| anyhow!("{label} peer lock poisoned"))?;
    let target = target.ok_or_else(|| anyhow!("{label} peer endpoint is unknown"))?;
    socket.send_to(packet, target)?;
    Ok(())
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

fn resolve_socket_endpoint(endpoint: &SocketEndpoint) -> Result<SocketAddr> {
    format!("{}:{}", endpoint.host, endpoint.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("could not resolve {}:{}", endpoint.host, endpoint.port))
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

        send_message(
            &writer,
            &AgentToGateway::Payload {
                sequence,
                bytes: buf[..amount].to_vec(),
            },
        )?;
        sequence += 1;
    }
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

fn handle_agent_routes(
    mode: SystemCommandMode,
    interface_name: &str,
    config: &TunnelConfig,
) -> Result<()> {
    if mode == SystemCommandMode::Skip {
        return Ok(());
    }

    let commands = build_agent_route_commands(interface_name, config);
    execute_commands(mode, "agent route", &commands)
}

fn build_agent_route_commands(interface_name: &str, config: &TunnelConfig) -> Vec<Vec<String>> {
    config
        .route_policy
        .destination_cidrs
        .iter()
        .map(|cidr| {
            #[cfg(target_os = "linux")]
            {
                vec![
                    String::from("ip"),
                    String::from("route"),
                    String::from("replace"),
                    cidr.clone(),
                    String::from("dev"),
                    String::from(interface_name),
                ]
            }

            #[cfg(target_os = "macos")]
            {
                vec![
                    String::from("route"),
                    String::from("-n"),
                    String::from("add"),
                    String::from("-net"),
                    cidr.clone(),
                    String::from("-interface"),
                    String::from(interface_name),
                ]
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                vec![
                    String::from("echo"),
                    format!("manual route required for {cidr} via {interface_name}"),
                ]
            }
        })
        .collect()
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

fn open_session(writer: &Arc<Mutex<TcpStream>>, config: &TunnelConfig) -> Result<()> {
    send_message(
        writer,
        &AgentToGateway::SessionOpen {
            tenant_id: config.tenant_id.clone(),
            tunnel_id: config.tunnel_id.clone(),
        },
    )
}

fn close_session(writer: &Arc<Mutex<TcpStream>>) -> Result<()> {
    send_message(writer, &AgentToGateway::SessionClose)
}

fn send_heartbeat(writer: &Arc<Mutex<TcpStream>>) -> Result<()> {
    send_message(
        writer,
        &AgentToGateway::Heartbeat {
            observed_at_unix_secs: now_unix_secs(),
        },
    )
}

fn spawn_heartbeat_thread(writer: Arc<Mutex<TcpStream>>, interval_secs: u64) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(interval_secs));
        if let Err(error) = send_heartbeat(&writer) {
            eprintln!("heartbeat stopped: {error:#}");
            break;
        }
    });
}

fn send_message(writer: &Arc<Mutex<TcpStream>>, message: &AgentToGateway) -> Result<()> {
    let mut guard = writer
        .lock()
        .map_err(|_| anyhow!("tcp writer lock poisoned"))?;
    write_json_line(&mut *guard, message)?;
    Ok(())
}

fn read_and_print_message(reader: &mut BufReader<TcpStream>) -> Result<()> {
    if let Some(message) = read_json_line::<_, GatewayToAgent>(reader)? {
        println!("{}", serde_json::to_string_pretty(&message)?);
    }
    Ok(())
}

fn load_payload(cli: &Cli) -> Result<Vec<u8>> {
    if let Some(input) = &cli.input {
        return Ok(fs::read(input)?);
    }

    if let Some(payload) = &cli.payload {
        return Ok(payload.as_bytes().to_vec());
    }

    if io::stdin().is_terminal() {
        return Ok(b"tunnel phase1 sample payload".to_vec());
    }

    let mut payload = Vec::new();
    io::copy(&mut io::stdin().lock(), &mut payload)?;
    Ok(payload)
}
