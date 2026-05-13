#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser};
use tun::AbstractDevice;
use tunnel_shared::{
    now_unix_secs, read_json_line, write_json_line, AgentToGateway, ComponentKind, GatewayToAgent,
    HealthState, HealthStatus, UsageRecord,
};

#[derive(Debug, Parser)]
#[command(name = "tunnel-gateway")]
#[command(about = "Phase 1 Gum Tunnel gateway harness", long_about = None)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:7000")]
    bind: String,
    #[arg(long)]
    output_dir: Option<PathBuf>,
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
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
                if let Err(error) = handle_client(stream, &cli) {
                    eprintln!("gateway connection failed: {error:#}");
                }
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }

    Ok(())
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
        let device = create_tun_device(&cli.tun)?;
        let interface_name = device.tun_name()?;
        println!("gateway tun ready: {interface_name}");
        let (mut tun_reader, writer_half) = device.split();
        tun_writer = Some(writer_half);

        let writer_for_packets = Arc::clone(&writer);
        let max_packet_bytes = cli.tun.tun_mtu as usize + 256;
        thread::spawn(move || {
            if let Err(error) =
                forward_tun_packets(&mut tun_reader, writer_for_packets, max_packet_bytes)
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
