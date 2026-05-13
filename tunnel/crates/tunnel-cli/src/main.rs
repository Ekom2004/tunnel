#![forbid(unsafe_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "tunnel")]
#[command(about = "Gum Tunnel operator CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Login,
    TenantCreate {
        name: String,
    },
    AttachmentRegister {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        cloud_account: String,
        #[arg(long)]
        name: String,
    },
    AgentEnroll {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        token: String,
    },
    PolicyApply {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        profile: String,
    },
    Connect {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        attachment: String,
    },
    Status {
        #[arg(long)]
        tenant: Option<String>,
    },
    Usage {
        #[arg(long)]
        tenant: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("{cli:?}");
    Ok(())
}
