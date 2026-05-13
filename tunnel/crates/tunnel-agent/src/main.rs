#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufReader, IsTerminal, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser};
use tun::AbstractDevice;
use tunnel_shared::{
    now_unix_secs, read_json_line, write_json_line, AgentToGateway, GatewayToAgent, TunnelConfig,
};

#[derive(Debug, Parser)]
#[command(name = "tunnel-agent")]
#[command(about = "Phase 1 Gum Tunnel agent harness", long_about = None)]
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
    #[arg(long)]
    print_route_hints: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config: TunnelConfig = serde_json::from_str(&fs::read_to_string(&cli.config)?)?;
    config.validate()?;

    let stream = TcpStream::connect((config.gateway.host.as_str(), config.gateway.port))?;
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = BufReader::new(stream);

    open_session(&writer, &config)?;
    read_and_print_message(&mut reader)?;
    send_heartbeat(&writer)?;
    read_and_print_message(&mut reader)?;

    spawn_heartbeat_thread(Arc::clone(&writer), config.heartbeat_interval_secs);

    if cli.tun.tun {
        run_tun_mode(&config, &cli.tun, writer, &mut reader)
    } else {
        run_payload_mode(&config, &cli, &writer, &mut reader)
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

fn run_tun_mode(
    config: &TunnelConfig,
    tun_args: &TunArgs,
    writer: Arc<Mutex<TcpStream>>,
    reader: &mut BufReader<TcpStream>,
) -> Result<()> {
    let device = create_tun_device(tun_args)?;
    let interface_name = device.tun_name()?;
    println!("agent tun ready: {interface_name}");

    if tun_args.print_route_hints {
        print_route_hints(&interface_name, config);
    }

    let (mut tun_reader, mut tun_writer) = device.split();
    let writer_for_packets = Arc::clone(&writer);
    let max_packet_bytes = config.max_chunk_bytes.max(2048);

    thread::spawn(move || {
        if let Err(error) =
            forward_tun_packets(&mut tun_reader, writer_for_packets, max_packet_bytes)
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

fn forward_tun_packets(
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

fn create_tun_device(tun_args: &TunArgs) -> Result<tun::Device> {
    let mut config = tun::Configuration::default();
    config
        .address(parse_ip(&tun_args.tun_address)?)
        .destination(parse_ip(&tun_args.tun_destination)?)
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

    let device = tun::create(&config)?;
    Ok(device)
}

fn parse_ip(value: &str) -> Result<IpAddr> {
    value
        .parse()
        .with_context(|| format!("invalid IP address: {value}"))
}

fn print_route_hints(interface_name: &str, config: &TunnelConfig) {
    for cidr in &config.route_policy.destination_cidrs {
        #[cfg(target_os = "linux")]
        println!("route hint: sudo ip route add {cidr} dev {interface_name}");

        #[cfg(target_os = "macos")]
        println!("route hint: sudo route -n add -net {cidr} -interface {interface_name}");

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        println!("route hint: add route for {cidr} via interface {interface_name}");
    }
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
        return Ok(b"gum tunnel phase1 sample payload".to_vec());
    }

    let mut payload = Vec::new();
    io::copy(&mut io::stdin().lock(), &mut payload)?;
    Ok(payload)
}
