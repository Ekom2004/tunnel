#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tunnel_shared::{GatewayEndpoint, RoutePolicy, TrafficClass, TunnelConfig};

#[derive(Debug, Parser)]
#[command(name = "tunnel-control")]
#[command(about = "Phase 1 Gum Tunnel config issuer", long_about = None)]
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
    #[arg(long, default_value_t = 5)]
    heartbeat_interval_secs: u64,
    #[arg(long, default_value_t = 4096)]
    max_chunk_bytes: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum TrafficClassArg {
    BulkExport,
    Backup,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = TunnelConfig {
        tenant_id: cli.tenant,
        tunnel_id: cli.tunnel,
        gateway: GatewayEndpoint {
            host: cli.gateway_host,
            port: cli.gateway_port,
        },
        route_policy: RoutePolicy {
            traffic_class: match cli.traffic_class {
                TrafficClassArg::BulkExport => TrafficClass::BulkExport,
                TrafficClassArg::Backup => TrafficClass::Backup,
            },
            destination_cidrs: cli.destination_cidrs,
            routing_mark: cli.routing_mark,
        },
        heartbeat_interval_secs: cli.heartbeat_interval_secs,
        max_chunk_bytes: cli.max_chunk_bytes,
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
