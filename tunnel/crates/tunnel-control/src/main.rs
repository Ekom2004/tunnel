#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::{Parser, ValueEnum};
use rand::RngCore;
use tunnel_shared::{
    encode_key_32, GatewayEndpoint, RoutePolicy, SocketEndpoint, TrafficClass, TunnelConfig,
    WireGuardConfig, WireGuardRole,
};

#[derive(Debug, Parser)]
#[command(name = "tunnel-control")]
#[command(about = "Phase 1 Tunnel config issuer", long_about = None)]
struct Cli {
    #[arg(long, default_value = "example-tenant")]
    tenant: String,
    #[arg(long, default_value = "example-tunnel")]
    tunnel: String,
    #[arg(long, default_value = "127.0.0.1")]
    gateway_host: String,
    #[arg(long, default_value_t = 7000)]
    gateway_port: u16,
    #[arg(long, value_enum, default_value_t = TrafficClassArg::BulkExport)]
    traffic_class: TrafficClassArg,
    #[arg(long = "cidr", required = true)]
    destination_cidrs: Vec<String>,
    #[arg(long, default_value_t = 100)]
    routing_mark: u32,
    #[arg(long)]
    allow_full_tunnel: bool,
    #[arg(long, default_value_t = 5)]
    heartbeat_interval_secs: u64,
    #[arg(long, default_value_t = 4096)]
    max_chunk_bytes: usize,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    wireguard: bool,
    #[arg(long)]
    gateway_output: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0")]
    wireguard_agent_bind_host: String,
    #[arg(long, default_value_t = 0)]
    wireguard_agent_bind_port: u16,
    #[arg(long, default_value = "0.0.0.0")]
    wireguard_gateway_bind_host: String,
    #[arg(long)]
    wireguard_port: Option<u16>,
    #[arg(long, default_value = "10.201.0.2")]
    wireguard_agent_address: String,
    #[arg(long, default_value = "10.201.0.1")]
    wireguard_gateway_address: String,
    #[arg(long, default_value_t = 25)]
    wireguard_keepalive_secs: u16,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum TrafficClassArg {
    BulkExport,
    Backup,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let route_policy = RoutePolicy {
        traffic_class: match cli.traffic_class {
            TrafficClassArg::BulkExport => TrafficClass::BulkExport,
            TrafficClassArg::Backup => TrafficClass::Backup,
        },
        destination_cidrs: cli.destination_cidrs.clone(),
        routing_mark: cli.routing_mark,
        allow_full_tunnel: cli.allow_full_tunnel,
    };

    if cli.wireguard {
        return write_wireguard_pair(cli, route_policy);
    }

    let config = TunnelConfig {
        tenant_id: cli.tenant,
        tunnel_id: cli.tunnel,
        gateway: GatewayEndpoint {
            host: cli.gateway_host,
            port: cli.gateway_port,
        },
        route_policy,
        heartbeat_interval_secs: cli.heartbeat_interval_secs,
        max_chunk_bytes: cli.max_chunk_bytes,
        wireguard: None,
    };

    config.validate()?;
    let rendered = serde_json::to_string_pretty(&config)?;

    if let Some(output) = cli.output {
        fs::write(output, rendered)?;
    } else {
        println!("{rendered}");
    }

    Ok(())
}

fn write_wireguard_pair(cli: Cli, route_policy: RoutePolicy) -> Result<()> {
    let agent_output = cli
        .output
        .ok_or_else(|| anyhow!("--output is required when --wireguard is set"))?;
    let gateway_output = cli
        .gateway_output
        .ok_or_else(|| anyhow!("--gateway-output is required when --wireguard is set"))?;

    let wireguard_port = cli.wireguard_port.unwrap_or(cli.gateway_port);
    let (agent_private, agent_public) = generate_keypair();
    let (gateway_private, gateway_public) = generate_keypair();

    let agent_config = TunnelConfig {
        tenant_id: cli.tenant.clone(),
        tunnel_id: cli.tunnel.clone(),
        gateway: GatewayEndpoint {
            host: cli.gateway_host.clone(),
            port: cli.gateway_port,
        },
        route_policy: route_policy.clone(),
        heartbeat_interval_secs: cli.heartbeat_interval_secs,
        max_chunk_bytes: cli.max_chunk_bytes,
        wireguard: Some(WireGuardConfig {
            local_bind_host: cli.wireguard_agent_bind_host,
            local_bind_port: cli.wireguard_agent_bind_port,
            peer_endpoint: Some(SocketEndpoint {
                host: cli.gateway_host.clone(),
                port: wireguard_port,
            }),
            local_tunnel_address: cli.wireguard_agent_address.clone(),
            peer_tunnel_address: cli.wireguard_gateway_address.clone(),
            private_key_base64: encode_key_32(&agent_private),
            peer_public_key_base64: encode_key_32(&gateway_public),
            preshared_key_base64: None,
            persistent_keepalive_secs: Some(cli.wireguard_keepalive_secs),
            role: WireGuardRole::Agent,
        }),
    };

    let gateway_config = TunnelConfig {
        tenant_id: cli.tenant,
        tunnel_id: cli.tunnel,
        gateway: GatewayEndpoint {
            host: cli.gateway_host,
            port: cli.gateway_port,
        },
        route_policy,
        heartbeat_interval_secs: cli.heartbeat_interval_secs,
        max_chunk_bytes: cli.max_chunk_bytes,
        wireguard: Some(WireGuardConfig {
            local_bind_host: cli.wireguard_gateway_bind_host,
            local_bind_port: wireguard_port,
            peer_endpoint: None,
            local_tunnel_address: cli.wireguard_gateway_address,
            peer_tunnel_address: cli.wireguard_agent_address,
            private_key_base64: encode_key_32(&gateway_private),
            peer_public_key_base64: encode_key_32(&agent_public),
            preshared_key_base64: None,
            persistent_keepalive_secs: None,
            role: WireGuardRole::Gateway,
        }),
    };

    agent_config.validate()?;
    gateway_config.validate()?;

    fs::write(agent_output, serde_json::to_string_pretty(&agent_config)?)?;
    fs::write(
        gateway_output,
        serde_json::to_string_pretty(&gateway_config)?,
    )?;
    Ok(())
}

fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}
