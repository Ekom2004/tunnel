#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tunnel_shared::{
    now_unix_secs, AgentRuntimeState, GatewayRuntimeState, HealthState, PacketPathTelemetry,
    RuntimeStatus, TunnelConfig, TunnelPhase,
};

#[derive(Debug, Parser)]
#[command(name = "tunnel")]
#[command(about = "Tunnel operator CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    Login,
    #[command(hide = true)]
    TenantCreate {
        name: String,
    },
    #[command(hide = true)]
    AttachmentRegister {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        cloud_account: String,
        #[arg(long)]
        name: String,
    },
    #[command(hide = true)]
    AgentEnroll {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        token: String,
    },
    #[command(hide = true)]
    PolicyApply {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        profile: String,
    },
    Connect(ConnectArgs),
    Status(StatusArgs),
    Disconnect(DisconnectArgs),
    #[command(hide = true)]
    Usage(StatusArgs),
    #[command(hide = true)]
    Restart(RestartArgs),
    #[command(hide = true)]
    Supervise(SupervisorArgs),
    Doctor(DoctorArgs),
    Logs(LogsArgs),
    #[command(hide = true)]
    Soak(SoakArgs),
    #[command(hide = true)]
    RepairTest(RepairTestArgs),
}

#[derive(Debug, Args, Clone)]
struct ConnectArgs {
    #[arg(value_name = "PROFILE")]
    profile: Option<String>,
    #[arg(long, hide = true)]
    tenant: Option<String>,
    #[arg(long, hide = true)]
    attachment: Option<String>,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-wg.json"
    )]
    gateway_config: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-agent-state.json"
    )]
    agent_state_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-agent-status.json"
    )]
    agent_status_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-state.json"
    )]
    gateway_state_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-status.json"
    )]
    gateway_status_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-agent.log")]
    agent_log_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-gateway.log")]
    gateway_log_file: PathBuf,
    #[arg(long, hide = true, default_value = "en0")]
    egress_interface: String,
    #[arg(long, hide = true, value_enum, default_value_t = SystemCommandMode::Apply)]
    route_mode: SystemCommandMode,
    #[arg(long, hide = true, value_enum, default_value_t = SystemCommandMode::Apply)]
    forwarding_mode: SystemCommandMode,
    #[arg(long, hide = true, value_enum, default_value_t = SystemCommandMode::Apply)]
    nat_mode: SystemCommandMode,
    #[arg(long, hide = true, default_value_t = 12)]
    ready_timeout_secs: u64,
    #[arg(long, hide = true)]
    oneshot: bool,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-supervisor.log"
    )]
    supervisor_log_file: PathBuf,
}

#[derive(Debug, Args, Clone)]
struct StatusArgs {
    #[arg(value_name = "PROFILE")]
    profile: Option<String>,
    #[arg(long, hide = true)]
    tenant: Option<String>,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-agent-state.json"
    )]
    agent_state_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-agent-status.json"
    )]
    agent_status_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-state.json"
    )]
    gateway_state_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-status.json"
    )]
    gateway_status_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
}

#[derive(Debug, Args, Clone)]
struct DisconnectArgs {
    #[arg(value_name = "PROFILE")]
    profile: Option<String>,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-agent-state.json"
    )]
    agent_state_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-agent-status.json"
    )]
    agent_status_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-state.json"
    )]
    gateway_state_file: PathBuf,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-gateway-status.json"
    )]
    gateway_status_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, hide = true, value_enum, default_value_t = SystemCommandMode::Apply)]
    route_mode: SystemCommandMode,
    #[arg(long, hide = true, value_enum, default_value_t = SystemCommandMode::Apply)]
    forwarding_mode: SystemCommandMode,
    #[arg(long, hide = true, value_enum, default_value_t = SystemCommandMode::Apply)]
    nat_mode: SystemCommandMode,
}

#[derive(Debug, Args, Clone)]
struct RestartArgs {
    #[arg(long)]
    component: ComponentSelection,
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
}

#[derive(Debug, Args, Clone)]
struct SupervisorArgs {
    #[command(flatten)]
    connect: ConnectArgs,
    #[arg(long, default_value_t = 2)]
    monitor_interval_secs: u64,
    #[arg(long, default_value_t = 15)]
    stale_after_secs: u64,
    #[arg(long, default_value_t = 3)]
    unhealthy_grace_samples: u32,
    #[arg(long, default_value_t = 5)]
    restart_cooldown_secs: u64,
    #[arg(long, default_value_t = 10)]
    max_restarts_per_component: u32,
    #[arg(long)]
    max_iterations: Option<u64>,
}

#[derive(Debug, Args, Clone)]
struct LogsArgs {
    #[arg(value_name = "PROFILE")]
    profile: Option<String>,
    #[arg(long, value_enum, default_value_t = LogComponent::Both)]
    component: LogComponent,
    #[arg(long, default_value_t = 100)]
    lines: usize,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, hide = true)]
    agent_log_file: Option<PathBuf>,
    #[arg(long, hide = true)]
    gateway_log_file: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
struct DoctorArgs {
    #[arg(value_name = "PROFILE")]
    profile: Option<String>,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, hide = true, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, default_value = "1.1.1.1")]
    target: String,
    #[arg(long, default_value_t = 2.0)]
    probe_timeout_secs: f64,
    #[arg(long, default_value_t = 15)]
    stale_after_secs: u64,
    #[arg(long, default_value_t = 15)]
    post_probe_settle_secs: u64,
}

#[derive(Debug, Args, Clone)]
struct SoakArgs {
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, default_value = "1.1.1.1")]
    target: String,
    #[arg(long, default_value_t = 30)]
    count: u32,
    #[arg(long, default_value_t = 1.0)]
    interval_secs: f64,
    #[arg(long, default_value_t = 2.0)]
    probe_timeout_secs: f64,
    #[arg(long)]
    bounce_agent_at: Option<u32>,
    #[arg(long)]
    bounce_gateway_at: Option<u32>,
}

#[derive(Debug, Args, Clone)]
struct RepairTestArgs {
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, default_value = "1.1.1.1")]
    target: String,
    #[arg(long, default_value_t = 2.0)]
    probe_timeout_secs: f64,
    #[arg(long, default_value_t = 45)]
    recovery_timeout_secs: u64,
    #[arg(long, default_value_t = 1.0)]
    poll_interval_secs: f64,
    #[arg(long, default_value_t = 10)]
    post_repair_probe_attempts: u32,
    #[arg(long, value_enum, default_value_t = RepairTestMode::Process)]
    mode: RepairTestMode,
    #[arg(long)]
    component: Option<ComponentSelection>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum SystemCommandMode {
    Skip,
    Print,
    Apply,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum ComponentSelection {
    Agent,
    Gateway,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum LogComponent {
    Agent,
    Gateway,
    Both,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum RepairTestMode {
    Process,
    State,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionManifest {
    tenant: String,
    attachment: String,
    agent_config: PathBuf,
    gateway_config: PathBuf,
    agent_state_file: PathBuf,
    agent_status_file: PathBuf,
    gateway_state_file: PathBuf,
    gateway_status_file: PathBuf,
    #[serde(default = "default_agent_log_file")]
    agent_log_file: PathBuf,
    #[serde(default = "default_gateway_log_file")]
    gateway_log_file: PathBuf,
    egress_interface: String,
    route_mode: SystemCommandMode,
    forwarding_mode: SystemCommandMode,
    nat_mode: SystemCommandMode,
    agent_pid: Option<u32>,
    gateway_pid: Option<u32>,
    #[serde(default)]
    supervised: bool,
    #[serde(default)]
    supervisor_pid: Option<u32>,
    #[serde(default = "default_supervisor_log_file")]
    supervisor_log_file: PathBuf,
}

#[derive(Debug, Serialize)]
struct SoakReport {
    target: String,
    probe_timeout_secs: f64,
    sent: u32,
    received: u32,
    packet_loss_percent: f64,
    min_rtt_ms: Option<f64>,
    avg_rtt_ms: Option<f64>,
    max_rtt_ms: Option<f64>,
    p50_rtt_ms: Option<f64>,
    p95_rtt_ms: Option<f64>,
    p99_rtt_ms: Option<f64>,
    mean_jitter_ms: Option<f64>,
    max_jitter_ms: Option<f64>,
    bounced_agent_at: Option<u32>,
    bounced_gateway_at: Option<u32>,
    agent_recovery_secs: Option<f64>,
    gateway_recovery_secs: Option<f64>,
    agent_phase_transitions: Vec<PhaseTransition>,
    gateway_phase_transitions: Vec<PhaseTransition>,
    agent_degraded_samples: u32,
    gateway_degraded_samples: u32,
    agent_stale_samples: u32,
    gateway_stale_samples: u32,
    agent_bytes_before: Option<ByteSnapshot>,
    agent_bytes_after: Option<ByteSnapshot>,
    gateway_bytes_before: Option<ByteSnapshot>,
    gateway_bytes_after: Option<ByteSnapshot>,
    agent_bytes_delta: Option<ByteDelta>,
    gateway_bytes_delta: Option<ByteDelta>,
    transport_active_but_probe_failed: bool,
    likely_failure_domain: FailureDomain,
    elapsed_secs: f64,
}

#[derive(Debug, Serialize)]
struct PhaseTransition {
    sequence: u32,
    from: Option<TunnelPhase>,
    to: TunnelPhase,
    observed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ByteSnapshot {
    ingress_bytes: u64,
    egress_bytes: u64,
    observed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ByteDelta {
    ingress_delta: i64,
    egress_delta: i64,
}

#[derive(Debug, Clone, Serialize)]
struct PacketPathDelta {
    tun_read_packets_delta: i64,
    tun_read_bytes_delta: i64,
    tun_write_packets_delta: i64,
    tun_write_bytes_delta: i64,
    udp_rx_packets_delta: i64,
    udp_rx_bytes_delta: i64,
    udp_tx_packets_delta: i64,
    udp_tx_bytes_delta: i64,
    wireguard_encapsulated_packets_delta: i64,
    wireguard_decapsulated_packets_delta: i64,
    last_packet_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureDomain {
    None,
    ProbeNeverEnteredTunnel,
    TransportOrPeerLiveness,
    GatewayEgressOrReturnPath,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    overall: DoctorState,
    target: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct RepairTestReport {
    overall: DoctorState,
    target: String,
    supervised: bool,
    supervisor_pid: Option<u32>,
    checks: Vec<RepairTestCheck>,
}

#[derive(Debug, Serialize)]
struct RepairTestCheck {
    component: String,
    state: DoctorState,
    old_pid: Option<u32>,
    new_pid: Option<u32>,
    recovery_secs: Option<f64>,
    probe_rtt_ms: Option<f64>,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct ProfileConfig {
    default: Option<String>,
    profiles: Vec<TunnelProfile>,
}

#[derive(Debug, Clone, Deserialize)]
struct TunnelProfile {
    name: String,
    tenant: String,
    attachment: String,
    agent_config: Option<PathBuf>,
    gateway_config: Option<PathBuf>,
    agent_state_file: Option<PathBuf>,
    agent_status_file: Option<PathBuf>,
    gateway_state_file: Option<PathBuf>,
    gateway_status_file: Option<PathBuf>,
    session_file: Option<PathBuf>,
    agent_log_file: Option<PathBuf>,
    gateway_log_file: Option<PathBuf>,
    supervisor_log_file: Option<PathBuf>,
    egress_interface: Option<String>,
    route_mode: Option<SystemCommandMode>,
    forwarding_mode: Option<SystemCommandMode>,
    nat_mode: Option<SystemCommandMode>,
    ready_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    state: DoctorState,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorState {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Default)]
struct StatusHistory {
    transitions: Vec<PhaseTransition>,
    last_phase: Option<TunnelPhase>,
    degraded_samples: u32,
    stale_samples: u32,
    recovery_started_at: Option<Instant>,
    recovered_after_secs: Option<f64>,
}

#[derive(Debug, Default)]
struct ComponentSupervisorState {
    unhealthy_samples: u32,
    restart_count: u32,
    last_restart: Option<Instant>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CommandKind::Login => println!("login flow not implemented yet"),
        CommandKind::TenantCreate { name } => println!("tenant create not implemented yet: {name}"),
        CommandKind::AttachmentRegister {
            provider,
            cloud_account,
            name,
        } => println!(
            "attachment register not implemented yet: provider={provider} cloud_account={cloud_account} name={name}"
        ),
        CommandKind::AgentEnroll { tenant, token } => {
            println!("agent enroll not implemented yet: tenant={tenant} token={token}")
        }
        CommandKind::PolicyApply { tenant, profile } => {
            println!("policy apply not implemented yet: tenant={tenant} profile={profile}")
        }
        CommandKind::Connect(args) => run_connect(args)?,
        CommandKind::Status(args) => run_status(args)?,
        CommandKind::Disconnect(args) => run_disconnect(args)?,
        CommandKind::Usage(args) => run_usage(args)?,
        CommandKind::Restart(args) => run_restart(args)?,
        CommandKind::Supervise(args) => run_supervisor(args)?,
        CommandKind::Doctor(args) => run_doctor(args)?,
        CommandKind::Logs(args) => run_logs(args)?,
        CommandKind::Soak(args) => run_soak(args)?,
        CommandKind::RepairTest(args) => run_repair_test(args)?,
    }

    Ok(())
}

fn resolve_connect_args(mut args: ConnectArgs) -> Result<ConnectArgs> {
    if args.tenant.is_some() && args.attachment.is_some() {
        return Ok(args);
    }

    if args.profile_file.exists() {
        let config = load_profile_config(&args.profile_file)?;
        let profile_name = args
            .profile
            .clone()
            .or_else(|| config.default.clone())
            .or_else(|| (config.profiles.len() == 1).then(|| config.profiles[0].name.clone()))
            .ok_or_else(|| {
                anyhow!(
                    "no profile selected and no default profile configured in {}",
                    args.profile_file.display()
                )
            })?;
        let profile = config
            .profiles
            .iter()
            .find(|profile| profile.name == profile_name)
            .ok_or_else(|| {
                anyhow!(
                    "profile {profile_name:?} not found in {}",
                    args.profile_file.display()
                )
            })?;
        apply_profile(&mut args, profile);
        return Ok(args);
    }

    if let Some(profile) = args.profile.clone() {
        args.tenant
            .get_or_insert_with(|| String::from("local-tenant"));
        args.attachment.get_or_insert(profile);
        return Ok(args);
    }

    bail!(
        "connect requires a profile, or hidden --tenant/--attachment values. Example: tunnel-cli connect local-dev"
    );
}

fn load_profile_config(path: &Path) -> Result<ProfileConfig> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn apply_profile(args: &mut ConnectArgs, profile: &TunnelProfile) {
    args.profile.get_or_insert_with(|| profile.name.clone());
    args.tenant.get_or_insert_with(|| profile.tenant.clone());
    args.attachment
        .get_or_insert_with(|| profile.attachment.clone());

    if let Some(value) = &profile.agent_config {
        args.agent_config = value.clone();
    }
    if let Some(value) = &profile.gateway_config {
        args.gateway_config = value.clone();
    }
    if let Some(value) = &profile.agent_state_file {
        args.agent_state_file = value.clone();
    }
    if let Some(value) = &profile.agent_status_file {
        args.agent_status_file = value.clone();
    }
    if let Some(value) = &profile.gateway_state_file {
        args.gateway_state_file = value.clone();
    }
    if let Some(value) = &profile.gateway_status_file {
        args.gateway_status_file = value.clone();
    }
    if let Some(value) = &profile.session_file {
        args.session_file = value.clone();
    }
    if let Some(value) = &profile.agent_log_file {
        args.agent_log_file = value.clone();
    }
    if let Some(value) = &profile.gateway_log_file {
        args.gateway_log_file = value.clone();
    }
    if let Some(value) = &profile.supervisor_log_file {
        args.supervisor_log_file = value.clone();
    }
    if let Some(value) = &profile.egress_interface {
        args.egress_interface = value.clone();
    }
    if let Some(value) = profile.route_mode {
        args.route_mode = value;
    }
    if let Some(value) = profile.forwarding_mode {
        args.forwarding_mode = value;
    }
    if let Some(value) = profile.nat_mode {
        args.nat_mode = value;
    }
    if let Some(value) = profile.ready_timeout_secs {
        args.ready_timeout_secs = value;
    }
}

fn required_connect_value<'a>(value: Option<&'a String>, label: &str) -> Result<&'a str> {
    value
        .map(String::as_str)
        .ok_or_else(|| anyhow!("resolved connect args missing {label}"))
}

fn resolve_status_args(mut args: StatusArgs) -> Result<StatusArgs> {
    if let Some(profile) = load_profile_for_command(args.profile.as_ref(), &args.profile_file)? {
        args.tenant.get_or_insert_with(|| profile.tenant.clone());
        apply_status_profile(&mut args, &profile);
    } else if let Some(profile_name) = args.profile.clone() {
        args.tenant
            .get_or_insert_with(|| String::from("local-tenant"));
        let _ = profile_name;
    }
    Ok(args)
}

fn resolve_disconnect_args(mut args: DisconnectArgs) -> Result<DisconnectArgs> {
    if let Some(profile) = load_profile_for_command(args.profile.as_ref(), &args.profile_file)? {
        apply_disconnect_profile(&mut args, &profile);
    }
    Ok(args)
}

fn resolve_logs_args(mut args: LogsArgs) -> Result<LogsArgs> {
    if let Some(profile) = load_profile_for_command(args.profile.as_ref(), &args.profile_file)? {
        args.session_file = profile
            .session_file
            .clone()
            .unwrap_or_else(|| args.session_file.clone());
        if args.agent_log_file.is_none() {
            args.agent_log_file = profile.agent_log_file.clone();
        }
        if args.gateway_log_file.is_none() {
            args.gateway_log_file = profile.gateway_log_file.clone();
        }
    }
    Ok(args)
}

fn resolve_doctor_args(mut args: DoctorArgs) -> Result<DoctorArgs> {
    if let Some(profile) = load_profile_for_command(args.profile.as_ref(), &args.profile_file)? {
        args.session_file = profile
            .session_file
            .clone()
            .unwrap_or_else(|| args.session_file.clone());
    }
    Ok(args)
}

fn load_profile_for_command(
    profile_name: Option<&String>,
    profile_file: &Path,
) -> Result<Option<TunnelProfile>> {
    if !profile_file.exists() {
        return Ok(None);
    }

    let config = load_profile_config(profile_file)?;
    let selected = profile_name
        .cloned()
        .or_else(|| config.default.clone())
        .or_else(|| (config.profiles.len() == 1).then(|| config.profiles[0].name.clone()));
    let Some(selected) = selected else {
        return Ok(None);
    };

    config
        .profiles
        .into_iter()
        .find(|profile| profile.name == selected)
        .map(Some)
        .ok_or_else(|| {
            anyhow!(
                "profile {selected:?} not found in {}",
                profile_file.display()
            )
        })
}

fn apply_status_profile(args: &mut StatusArgs, profile: &TunnelProfile) {
    if let Some(value) = &profile.agent_state_file {
        args.agent_state_file = value.clone();
    }
    if let Some(value) = &profile.agent_status_file {
        args.agent_status_file = value.clone();
    }
    if let Some(value) = &profile.gateway_state_file {
        args.gateway_state_file = value.clone();
    }
    if let Some(value) = &profile.gateway_status_file {
        args.gateway_status_file = value.clone();
    }
    if let Some(value) = &profile.session_file {
        args.session_file = value.clone();
    }
}

fn apply_disconnect_profile(args: &mut DisconnectArgs, profile: &TunnelProfile) {
    if let Some(value) = &profile.agent_config {
        args.agent_config = value.clone();
    }
    if let Some(value) = &profile.agent_state_file {
        args.agent_state_file = value.clone();
    }
    if let Some(value) = &profile.agent_status_file {
        args.agent_status_file = value.clone();
    }
    if let Some(value) = &profile.gateway_state_file {
        args.gateway_state_file = value.clone();
    }
    if let Some(value) = &profile.gateway_status_file {
        args.gateway_status_file = value.clone();
    }
    if let Some(value) = &profile.session_file {
        args.session_file = value.clone();
    }
    if let Some(value) = profile.route_mode {
        args.route_mode = value;
    }
    if let Some(value) = profile.forwarding_mode {
        args.forwarding_mode = value;
    }
    if let Some(value) = profile.nat_mode {
        args.nat_mode = value;
    }
}

fn run_connect(args: ConnectArgs) -> Result<()> {
    let args = resolve_connect_args(args)?;
    if args.oneshot {
        return run_connect_oneshot(args);
    }

    run_connect_supervised(args)
}

fn run_connect_supervised(args: ConnectArgs) -> Result<()> {
    preflight_connect_args(&args)?;

    if let Some(session) = read_optional_json::<SessionManifest>(&args.session_file)? {
        let supervisor_running = pid_is_running_optional(session.supervisor_pid)?;
        let agent_running = pid_is_running_optional(session.agent_pid)?;
        let gateway_running = pid_is_running_optional(session.gateway_pid)?;
        if supervisor_running && agent_running && gateway_running {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "tenant": session.tenant,
                    "attachment": session.attachment,
                    "supervised": true,
                    "supervisor_pid": session.supervisor_pid,
                    "agent_pid": session.agent_pid,
                    "gateway_pid": session.gateway_pid,
                    "agent_log_file": session.agent_log_file,
                    "gateway_log_file": session.gateway_log_file,
                    "supervisor_log_file": session.supervisor_log_file,
                    "ready": true,
                    "session_file": args.session_file,
                }))?
            );
            return Ok(());
        }
    }

    let (supervisor_pid, session) = spawn_supervisor_for_connect(&args)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "tenant": session.tenant,
            "attachment": session.attachment,
            "supervised": true,
            "supervisor_pid": session.supervisor_pid.or(Some(supervisor_pid)),
            "agent_pid": session.agent_pid,
            "gateway_pid": session.gateway_pid,
            "agent_log_file": session.agent_log_file,
            "gateway_log_file": session.gateway_log_file,
            "supervisor_log_file": session.supervisor_log_file,
            "ready": true,
            "session_file": args.session_file,
        }))?
    );

    Ok(())
}

fn spawn_supervisor_for_connect(args: &ConnectArgs) -> Result<(u32, SessionManifest)> {
    let supervisor_log_file = args.supervisor_log_file.clone();
    let (supervisor_stdout, supervisor_stderr) = log_stdio(&supervisor_log_file, true)?;
    let current_exe = env::current_exe().context("failed to resolve current executable")?;
    let mut supervisor = Command::new(&current_exe);
    supervisor
        .arg("supervise")
        .stdin(Stdio::null())
        .stdout(supervisor_stdout)
        .stderr(supervisor_stderr);
    append_connect_args(&mut supervisor, args);
    supervisor
        .arg("--supervisor-log-file")
        .arg(&supervisor_log_file);

    let child = supervisor
        .spawn()
        .with_context(|| format!("failed to spawn supervisor {}", current_exe.display()))?;
    let supervisor_pid = child.id();
    wait_for_supervised_connect_ready(args, supervisor_pid)?;

    Ok((supervisor_pid, load_manifest(&args.session_file)?))
}

fn run_connect_oneshot(args: ConnectArgs) -> Result<()> {
    preflight_connect_args(&args)?;
    reconcile_before_connect(&args)?;
    let tenant = required_connect_value(args.tenant.as_ref(), "tenant")?.to_owned();
    let attachment = required_connect_value(args.attachment.as_ref(), "attachment")?.to_owned();

    let gateway_bin = sibling_binary("tunnel-gateway")?;
    let agent_bin = sibling_binary("tunnel-agent")?;
    let (gateway_stdout, gateway_stderr) = log_stdio(&args.gateway_log_file, false)?;
    let (agent_stdout, agent_stderr) = log_stdio(&args.agent_log_file, false)?;

    let mut gateway = Command::new(&gateway_bin);
    gateway
        .arg("--config")
        .arg(&args.gateway_config)
        .arg("--tun")
        .arg("--forwarding-mode")
        .arg(mode_str(args.forwarding_mode))
        .arg("--nat-mode")
        .arg(mode_str(args.nat_mode))
        .arg("--egress-interface")
        .arg(&args.egress_interface)
        .arg("--state-file")
        .arg(&args.gateway_state_file)
        .arg("--status-file")
        .arg(&args.gateway_status_file)
        .stdin(Stdio::null())
        .stdout(gateway_stdout)
        .stderr(gateway_stderr);

    let mut gateway_child = gateway
        .spawn()
        .with_context(|| format!("failed to spawn {}", gateway_bin.display()))?;

    thread::sleep(Duration::from_millis(750));
    ensure_child_still_running(&mut gateway_child, "gateway", &args.gateway_log_file)?;

    let mut agent = Command::new(&agent_bin);
    agent
        .arg("--config")
        .arg(&args.agent_config)
        .arg("--tun")
        .arg("--route-mode")
        .arg(mode_str(args.route_mode))
        .arg("--state-file")
        .arg(&args.agent_state_file)
        .arg("--status-file")
        .arg(&args.agent_status_file)
        .stdin(Stdio::null())
        .stdout(agent_stdout)
        .stderr(agent_stderr);

    let mut agent_child = agent
        .spawn()
        .with_context(|| format!("failed to spawn {}", agent_bin.display()))?;

    thread::sleep(Duration::from_millis(750));
    if let Err(error) = ensure_child_still_running(&mut agent_child, "agent", &args.agent_log_file)
    {
        let _ = terminate_pid(Some(gateway_child.id()));
        return Err(error);
    }

    if let Err(error) = wait_for_connect_ready(&args) {
        let _ = terminate_pid(Some(agent_child.id()));
        let _ = terminate_pid(Some(gateway_child.id()));
        return Err(error);
    }

    let manifest = SessionManifest {
        tenant: tenant.clone(),
        attachment: attachment.clone(),
        agent_config: args.agent_config.clone(),
        gateway_config: args.gateway_config.clone(),
        agent_state_file: args.agent_state_file.clone(),
        agent_status_file: args.agent_status_file.clone(),
        gateway_state_file: args.gateway_state_file.clone(),
        gateway_status_file: args.gateway_status_file.clone(),
        agent_log_file: args.agent_log_file.clone(),
        gateway_log_file: args.gateway_log_file.clone(),
        egress_interface: args.egress_interface.clone(),
        route_mode: args.route_mode,
        forwarding_mode: args.forwarding_mode,
        nat_mode: args.nat_mode,
        agent_pid: Some(agent_child.id()),
        gateway_pid: Some(gateway_child.id()),
        supervised: false,
        supervisor_pid: None,
        supervisor_log_file: args.supervisor_log_file.clone(),
    };
    save_manifest(&args.session_file, &manifest)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "tenant": tenant,
            "attachment": attachment,
            "gateway_pid": gateway_child.id(),
            "agent_pid": agent_child.id(),
            "supervised": false,
            "supervisor_pid": null,
            "agent_log_file": args.agent_log_file,
            "gateway_log_file": args.gateway_log_file,
            "supervisor_log_file": args.supervisor_log_file,
            "agent_status_file": args.agent_status_file,
            "gateway_status_file": args.gateway_status_file,
            "ready": true,
            "session_file": args.session_file,
        }))?
    );

    Ok(())
}

fn run_status(args: StatusArgs) -> Result<()> {
    let args = resolve_status_args(args)?;
    let agent_status = read_optional_json::<RuntimeStatus>(&args.agent_status_file)?;
    let gateway_status = read_optional_json::<RuntimeStatus>(&args.gateway_status_file)?;
    let agent_state = read_optional_json::<AgentRuntimeState>(&args.agent_state_file)?;
    let gateway_state = read_optional_json::<GatewayRuntimeState>(&args.gateway_state_file)?;
    let session = read_optional_json::<SessionManifest>(&args.session_file)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "tenant_filter": args.tenant,
            "session": session,
            "agent_status": agent_status,
            "gateway_status": gateway_status,
            "agent_state": agent_state,
            "gateway_state": gateway_state,
        }))?
    );
    Ok(())
}

fn run_usage(args: StatusArgs) -> Result<()> {
    let args = resolve_status_args(args)?;
    let agent_status = read_optional_json::<RuntimeStatus>(&args.agent_status_file)?;
    let gateway_status = read_optional_json::<RuntimeStatus>(&args.gateway_status_file)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "tenant_filter": args.tenant,
            "agent_bytes": agent_status.as_ref().map(|status| serde_json::json!({
                "ingress_bytes": status.ingress_bytes,
                "egress_bytes": status.egress_bytes,
                "observed_at_unix_secs": status.observed_at_unix_secs,
            })),
            "gateway_bytes": gateway_status.as_ref().map(|status| serde_json::json!({
                "ingress_bytes": status.ingress_bytes,
                "egress_bytes": status.egress_bytes,
                "observed_at_unix_secs": status.observed_at_unix_secs,
            })),
        }))?
    );
    Ok(())
}

fn run_logs(args: LogsArgs) -> Result<()> {
    let args = resolve_logs_args(args)?;
    let session = read_optional_json::<SessionManifest>(&args.session_file)?;
    let agent_log_file = args
        .agent_log_file
        .or_else(|| {
            session
                .as_ref()
                .map(|session| session.agent_log_file.clone())
        })
        .unwrap_or_else(default_agent_log_file);
    let gateway_log_file = args
        .gateway_log_file
        .or_else(|| {
            session
                .as_ref()
                .map(|session| session.gateway_log_file.clone())
        })
        .unwrap_or_else(default_gateway_log_file);

    match args.component {
        LogComponent::Agent => print_log_tail("agent", &agent_log_file, args.lines)?,
        LogComponent::Gateway => print_log_tail("gateway", &gateway_log_file, args.lines)?,
        LogComponent::Both => {
            print_log_tail("gateway", &gateway_log_file, args.lines)?;
            print_log_tail("agent", &agent_log_file, args.lines)?;
        }
    }

    Ok(())
}

fn run_disconnect(args: DisconnectArgs) -> Result<()> {
    let args = resolve_disconnect_args(args)?;
    let session = read_optional_json::<SessionManifest>(&args.session_file)?;
    if let Some(session) = &session {
        terminate_pid_except_self(session.supervisor_pid)?;
        wait_for_pid_exit_except_self(
            session.supervisor_pid,
            "supervisor",
            Duration::from_secs(3),
        )?;
        terminate_pid(session.agent_pid)?;
        terminate_pid(session.gateway_pid)?;
    }

    let agent_bin = sibling_binary("tunnel-agent")?;
    let gateway_bin = sibling_binary("tunnel-gateway")?;

    if args.agent_state_file.exists() {
        run_cleanup_binary(
            &agent_bin,
            &[
                "--config",
                path_arg(&args.agent_config)?,
                "--cleanup-only",
                "--route-mode",
                mode_str(args.route_mode),
                "--state-file",
                path_arg(&args.agent_state_file)?,
                "--status-file",
                path_arg(&args.agent_status_file)?,
            ],
        )?;
    } else {
        eprintln!(
            "agent cleanup skipped: state file not found: {}",
            args.agent_state_file.display()
        );
    }

    if args.gateway_state_file.exists() {
        run_cleanup_binary(
            &gateway_bin,
            &[
                "--cleanup-only",
                "--forwarding-mode",
                mode_str(args.forwarding_mode),
                "--nat-mode",
                mode_str(args.nat_mode),
                "--state-file",
                path_arg(&args.gateway_state_file)?,
                "--status-file",
                path_arg(&args.gateway_status_file)?,
            ],
        )?;
    } else {
        eprintln!(
            "gateway cleanup skipped: state file not found: {}",
            args.gateway_state_file.display()
        );
    }

    if args.session_file.exists() {
        fs::remove_file(&args.session_file).with_context(|| {
            format!(
                "failed to remove session file {}",
                args.session_file.display()
            )
        })?;
    }

    Ok(())
}

fn run_restart(args: RestartArgs) -> Result<()> {
    let mut session = load_manifest(&args.session_file)?;
    restart_component(&mut session, args.component)?;
    save_manifest(&args.session_file, &session)?;
    println!("{}", serde_json::to_string_pretty(&session)?);
    Ok(())
}

fn run_supervisor(args: SupervisorArgs) -> Result<()> {
    let mut args = args;
    args.connect = resolve_connect_args(args.connect)?;
    preflight_connect_args(&args.connect)?;
    let mut supervisor_log = open_log_file(&args.connect.supervisor_log_file, true)?;
    emit_supervisor_event(
        &mut supervisor_log,
        "supervisor_started",
        None,
        "starting tunnel supervisor",
        None,
    )?;

    ensure_supervised_session(&args, &mut supervisor_log)?;
    let mut session = load_manifest(&args.connect.session_file)?;
    emit_supervisor_event(
        &mut supervisor_log,
        "session_loaded",
        None,
        "supervisor loaded active session manifest",
        Some(&session),
    )?;

    let mut agent_state = ComponentSupervisorState::default();
    let mut gateway_state = ComponentSupervisorState::default();
    let mut iteration = 0_u64;

    loop {
        iteration += 1;

        let agent_changed = supervise_component(
            &mut session,
            ComponentSelection::Agent,
            &mut agent_state,
            &args,
            &mut supervisor_log,
        )?;
        let gateway_changed = supervise_component(
            &mut session,
            ComponentSelection::Gateway,
            &mut gateway_state,
            &args,
            &mut supervisor_log,
        )?;
        if agent_changed || gateway_changed {
            save_manifest(&args.connect.session_file, &session)?;
        }

        if args.max_iterations == Some(iteration) {
            emit_supervisor_event(
                &mut supervisor_log,
                "supervisor_stopped",
                None,
                format!("reached max_iterations={iteration}"),
                Some(&session),
            )?;
            return Ok(());
        }

        thread::sleep(Duration::from_secs(args.monitor_interval_secs.max(1)));
    }
}

fn run_doctor(args: DoctorArgs) -> Result<()> {
    let args = resolve_doctor_args(args)?;
    let mut checks = Vec::new();
    let session = read_optional_json::<SessionManifest>(&args.session_file)?;

    let Some(session) = session else {
        checks.push(doctor_check(
            "session_file",
            DoctorState::Fail,
            format!(
                "session manifest not found: {}",
                args.session_file.display()
            ),
        ));
        return print_doctor_report(args.target, checks);
    };

    checks.push(doctor_check(
        "session_file",
        DoctorState::Pass,
        format!(
            "session manifest found for tenant={} attachment={}",
            session.tenant, session.attachment
        ),
    ));

    check_process("agent_process", session.agent_pid, &mut checks);
    check_process("gateway_process", session.gateway_pid, &mut checks);

    let agent_state = read_optional_json::<AgentRuntimeState>(&session.agent_state_file)?;
    let gateway_state = read_optional_json::<GatewayRuntimeState>(&session.gateway_state_file)?;
    let gateway_config = read_optional_json::<TunnelConfig>(&session.gateway_config)?;

    check_agent_state(agent_state.as_ref(), &session.agent_state_file, &mut checks);
    check_gateway_state(
        gateway_state.as_ref(),
        &session.gateway_state_file,
        &mut checks,
    );
    check_route_to_target(&args.target, agent_state.as_ref(), &mut checks)?;
    check_gateway_pf_rules(
        gateway_state.as_ref(),
        gateway_config.as_ref(),
        &session.egress_interface,
        &mut checks,
    )?;
    let agent_packet_before = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?
        .map(|status| status.packet_path);
    let gateway_packet_before = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?
        .map(|status| status.packet_path);
    let probe_passed = check_probe(&args.target, args.probe_timeout_secs, &mut checks)?;
    if probe_passed {
        wait_for_active_status_after_probe(&session, args.post_probe_settle_secs)?;
    }

    let agent_status = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?;
    let gateway_status = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?;
    check_packet_path_analysis(
        probe_passed,
        agent_packet_before.as_ref(),
        agent_status.as_ref().map(|status| &status.packet_path),
        gateway_packet_before.as_ref(),
        gateway_status.as_ref().map(|status| &status.packet_path),
        &mut checks,
    );
    check_runtime_status(
        "agent_status",
        agent_status.as_ref(),
        &session.agent_status_file,
        args.stale_after_secs,
        probe_passed,
        &mut checks,
    );
    check_runtime_status(
        "gateway_status",
        gateway_status.as_ref(),
        &session.gateway_status_file,
        args.stale_after_secs,
        probe_passed,
        &mut checks,
    );

    print_doctor_report(args.target, checks)
}

fn run_soak(args: SoakArgs) -> Result<()> {
    let mut session = load_manifest(&args.session_file)?;
    let start = Instant::now();
    let agent_before = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?;
    let gateway_before = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?;
    let mut samples = Vec::with_capacity(args.count as usize);
    let mut sent = 0_u32;
    let mut received = 0_u32;
    let mut bounced_agent = None;
    let mut bounced_gateway = None;
    let mut agent_history = StatusHistory::default();
    let mut gateway_history = StatusHistory::default();

    for sequence in 1..=args.count {
        if args.bounce_agent_at == Some(sequence) {
            restart_component(&mut session, ComponentSelection::Agent)?;
            bounced_agent = Some(sequence);
            agent_history.recovery_started_at = Some(Instant::now());
            save_manifest(&args.session_file, &session)?;
        }

        if args.bounce_gateway_at == Some(sequence) {
            restart_component(&mut session, ComponentSelection::Gateway)?;
            bounced_gateway = Some(sequence);
            gateway_history.recovery_started_at = Some(Instant::now());
            save_manifest(&args.session_file, &session)?;
        }

        sent += 1;
        if let Some(rtt_ms) = ping_once(&args.target, args.probe_timeout_secs)? {
            received += 1;
            samples.push(rtt_ms);
        }

        observe_status_history(
            sequence,
            &session.agent_status_file,
            &mut agent_history,
            start,
        )?;
        observe_status_history(
            sequence,
            &session.gateway_status_file,
            &mut gateway_history,
            start,
        )?;

        if sequence != args.count {
            thread::sleep(Duration::from_secs_f64(args.interval_secs));
        }
    }

    let mut sorted = samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let agent_after = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?;
    let gateway_after = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?;
    let agent_delta = byte_delta(agent_before.as_ref(), agent_after.as_ref());
    let gateway_delta = byte_delta(gateway_before.as_ref(), gateway_after.as_ref());
    let transport_active_but_probe_failed = received == 0
        && [
            agent_after
                .as_ref()
                .map(is_transport_active)
                .unwrap_or(false),
            gateway_after
                .as_ref()
                .map(is_transport_active)
                .unwrap_or(false),
        ]
        .into_iter()
        .all(|active| active);
    let likely_failure_domain = classify_failure_domain(
        received,
        agent_delta.as_ref(),
        gateway_delta.as_ref(),
        agent_after.as_ref(),
        gateway_after.as_ref(),
    );

    let report = SoakReport {
        target: args.target,
        probe_timeout_secs: args.probe_timeout_secs,
        sent,
        received,
        packet_loss_percent: if sent == 0 {
            0.0
        } else {
            ((sent - received) as f64 / sent as f64) * 100.0
        },
        min_rtt_ms: sorted.first().copied(),
        avg_rtt_ms: average(&sorted),
        max_rtt_ms: sorted.last().copied(),
        p50_rtt_ms: percentile(&sorted, 50.0),
        p95_rtt_ms: percentile(&sorted, 95.0),
        p99_rtt_ms: percentile(&sorted, 99.0),
        mean_jitter_ms: mean_jitter(&samples),
        max_jitter_ms: max_jitter(&samples),
        bounced_agent_at: bounced_agent,
        bounced_gateway_at: bounced_gateway,
        agent_recovery_secs: agent_history.recovered_after_secs,
        gateway_recovery_secs: gateway_history.recovered_after_secs,
        agent_phase_transitions: agent_history.transitions,
        gateway_phase_transitions: gateway_history.transitions,
        agent_degraded_samples: agent_history.degraded_samples,
        gateway_degraded_samples: gateway_history.degraded_samples,
        agent_stale_samples: agent_history.stale_samples,
        gateway_stale_samples: gateway_history.stale_samples,
        agent_bytes_before: agent_before.as_ref().map(runtime_bytes_snapshot),
        agent_bytes_after: agent_after.as_ref().map(runtime_bytes_snapshot),
        gateway_bytes_before: gateway_before.as_ref().map(runtime_bytes_snapshot),
        gateway_bytes_after: gateway_after.as_ref().map(runtime_bytes_snapshot),
        agent_bytes_delta: agent_delta,
        gateway_bytes_delta: gateway_delta,
        transport_active_but_probe_failed,
        likely_failure_domain,
        elapsed_secs: start.elapsed().as_secs_f64(),
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_repair_test(args: RepairTestArgs) -> Result<()> {
    let session = load_manifest(&args.session_file)?;
    let mut checks = Vec::new();

    if !session.supervised {
        checks.push(RepairTestCheck {
            component: String::from("supervisor"),
            state: DoctorState::Fail,
            old_pid: session.supervisor_pid,
            new_pid: session.supervisor_pid,
            recovery_secs: None,
            probe_rtt_ms: None,
            detail: String::from("session is not supervised"),
        });
        return print_repair_test_report(args.target, session, checks);
    }

    if !pid_is_running_optional(session.supervisor_pid)? {
        let old_pid = session.supervisor_pid;
        let started_at = Instant::now();
        match spawn_supervisor_for_connect(&connect_args_from_session(&session, &args.session_file))
        {
            Ok((new_pid, _new_session)) => {
                checks.push(RepairTestCheck {
                    component: String::from("supervisor"),
                    state: DoctorState::Pass,
                    old_pid,
                    new_pid: Some(new_pid),
                    recovery_secs: Some(started_at.elapsed().as_secs_f64()),
                    probe_rtt_ms: None,
                    detail: String::from(
                        "supervisor was not running; started replacement supervisor",
                    ),
                });
            }
            Err(error) => {
                checks.push(RepairTestCheck {
                    component: String::from("supervisor"),
                    state: DoctorState::Fail,
                    old_pid,
                    new_pid: old_pid,
                    recovery_secs: None,
                    probe_rtt_ms: None,
                    detail: format!(
                        "supervisor process is not running and restart failed: {error:#}"
                    ),
                });
                return print_repair_test_report(args.target, session, checks);
            }
        }
    }

    if matches!(args.mode, RepairTestMode::State | RepairTestMode::All) {
        let old_pid = load_manifest(&args.session_file)?.supervisor_pid;
        terminate_pid_except_self(old_pid)?;
        wait_for_pid_exit_except_self(old_pid, "supervisor", Duration::from_secs(5))?;
        let started_at = Instant::now();
        match spawn_supervisor_for_connect(&connect_args_from_session(
            &load_manifest(&args.session_file)?,
            &args.session_file,
        )) {
            Ok((new_pid, _new_session)) => {
                checks.push(RepairTestCheck {
                    component: String::from("supervisor_refresh"),
                    state: DoctorState::Pass,
                    old_pid,
                    new_pid: Some(new_pid),
                    recovery_secs: Some(started_at.elapsed().as_secs_f64()),
                    probe_rtt_ms: None,
                    detail: String::from("refreshed supervisor before OS-state repair test"),
                });
            }
            Err(error) => {
                let session = load_manifest(&args.session_file)?;
                checks.push(RepairTestCheck {
                    component: String::from("supervisor_refresh"),
                    state: DoctorState::Fail,
                    old_pid,
                    new_pid: old_pid,
                    recovery_secs: None,
                    probe_rtt_ms: None,
                    detail: format!("failed to refresh supervisor before state test: {error:#}"),
                });
                return print_repair_test_report(args.target, session, checks);
            }
        }
    }

    let components: Vec<ComponentSelection> = args
        .component
        .map(|component| vec![component])
        .unwrap_or_else(|| vec![ComponentSelection::Agent, ComponentSelection::Gateway]);

    if matches!(args.mode, RepairTestMode::Process | RepairTestMode::All) {
        for component in &components {
            checks.push(run_component_repair_test(
                &args.session_file,
                *component,
                &args.target,
                args.probe_timeout_secs,
                Duration::from_secs(args.recovery_timeout_secs),
                Duration::from_secs_f64(args.poll_interval_secs.max(0.1)),
                args.post_repair_probe_attempts,
            )?);
        }
    }

    if matches!(args.mode, RepairTestMode::State | RepairTestMode::All) {
        for component in &components {
            checks.push(run_component_state_repair_test(
                &args.session_file,
                *component,
                &args.target,
                args.probe_timeout_secs,
                Duration::from_secs(args.recovery_timeout_secs),
                Duration::from_secs_f64(args.poll_interval_secs.max(0.1)),
                args.post_repair_probe_attempts,
            )?);
        }
    }

    let session = load_manifest(&args.session_file)?;
    print_repair_test_report(args.target, session, checks)
}

fn run_component_repair_test(
    session_file: &Path,
    component: ComponentSelection,
    target: &str,
    probe_timeout_secs: f64,
    recovery_timeout: Duration,
    poll_interval: Duration,
    post_repair_probe_attempts: u32,
) -> Result<RepairTestCheck> {
    let session = load_manifest(session_file)?;
    let old_pid = component_pid(&session, component);
    if old_pid.is_none() {
        return Ok(RepairTestCheck {
            component: component_label(component).to_owned(),
            state: DoctorState::Fail,
            old_pid,
            new_pid: None,
            recovery_secs: None,
            probe_rtt_ms: None,
            detail: String::from("session manifest has no component pid"),
        });
    }

    terminate_pid(old_pid)?;
    wait_for_pid_exit_except_self(old_pid, component_label(component), Duration::from_secs(5))?;

    let started_at = Instant::now();
    let deadline = started_at + recovery_timeout;
    loop {
        let session = load_manifest(session_file)?;
        let new_pid = component_pid(&session, component);
        let pid_changed = new_pid.is_some() && new_pid != old_pid;
        let pid_running = pid_is_running_optional(new_pid)?;
        let status =
            read_optional_json::<RuntimeStatus>(component_status_file(&session, component))?;
        let status_active = status.as_ref().map(is_transport_active).unwrap_or(false);

        if pid_changed && pid_running && status_active {
            let recovery_secs = started_at.elapsed().as_secs_f64();
            let probe_rtt_ms = wait_for_probe_success(
                target,
                probe_timeout_secs,
                post_repair_probe_attempts.max(1),
                poll_interval,
            )?;
            let state = if probe_rtt_ms.is_some() {
                DoctorState::Pass
            } else {
                DoctorState::Fail
            };
            return Ok(RepairTestCheck {
                component: component_label(component).to_owned(),
                state,
                old_pid,
                new_pid,
                recovery_secs: Some(recovery_secs),
                probe_rtt_ms,
                detail: if state == DoctorState::Pass {
                    format!(
                        "{} recovered with replacement pid {:?}",
                        component_label(component),
                        new_pid
                    )
                } else {
                    format!(
                        "{} recovered process/status, but probe to {target} failed",
                        component_label(component)
                    )
                },
            });
        }

        if Instant::now() >= deadline {
            return Ok(RepairTestCheck {
                component: component_label(component).to_owned(),
                state: DoctorState::Fail,
                old_pid,
                new_pid,
                recovery_secs: None,
                probe_rtt_ms: None,
                detail: format!(
                    "timed out after {:.1}s waiting for replacement pid and active status; pid_changed={pid_changed} pid_running={pid_running} status_phase={:?} status_state={:?}",
                    recovery_timeout.as_secs_f64(),
                    status.as_ref().map(|status| &status.phase),
                    status.as_ref().map(|status| &status.state)
                ),
            });
        }

        thread::sleep(poll_interval);
    }
}

fn run_component_state_repair_test(
    session_file: &Path,
    component: ComponentSelection,
    target: &str,
    probe_timeout_secs: f64,
    recovery_timeout: Duration,
    poll_interval: Duration,
    post_repair_probe_attempts: u32,
) -> Result<RepairTestCheck> {
    let session = load_manifest(session_file)?;
    let pid = component_pid(&session, component);
    let started_at = Instant::now();

    match component {
        ComponentSelection::Agent => inject_agent_route_drift(&session)?,
        ComponentSelection::Gateway => inject_gateway_os_state_drift(&session)?,
    }

    let deadline = started_at + recovery_timeout;
    loop {
        let session = load_manifest(session_file)?;
        let repaired = match component {
            ComponentSelection::Agent => agent_routes_are_healthy(&session)?,
            ComponentSelection::Gateway => gateway_os_state_is_healthy(&session)?,
        };

        if repaired {
            let probe_rtt_ms = wait_for_probe_success(
                target,
                probe_timeout_secs,
                post_repair_probe_attempts.max(1),
                poll_interval,
            )?;
            let state = if probe_rtt_ms.is_some() {
                DoctorState::Pass
            } else {
                DoctorState::Fail
            };
            return Ok(RepairTestCheck {
                component: format!("{}_state", component_label(component)),
                state,
                old_pid: pid,
                new_pid: component_pid(&session, component),
                recovery_secs: Some(started_at.elapsed().as_secs_f64()),
                probe_rtt_ms,
                detail: if state == DoctorState::Pass {
                    format!("{} OS state repaired in place", component_label(component))
                } else {
                    format!(
                        "{} OS state repaired, but probe to {target} failed",
                        component_label(component)
                    )
                },
            });
        }

        if Instant::now() >= deadline {
            return Ok(RepairTestCheck {
                component: format!("{}_state", component_label(component)),
                state: DoctorState::Fail,
                old_pid: pid,
                new_pid: component_pid(&session, component),
                recovery_secs: None,
                probe_rtt_ms: None,
                detail: format!(
                    "timed out after {:.1}s waiting for OS state repair",
                    recovery_timeout.as_secs_f64()
                ),
            });
        }

        thread::sleep(poll_interval);
    }
}

fn print_repair_test_report(
    target: String,
    session: SessionManifest,
    checks: Vec<RepairTestCheck>,
) -> Result<()> {
    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else if checks.iter().any(|check| check.state == DoctorState::Warn) {
        DoctorState::Warn
    } else {
        DoctorState::Pass
    };
    let failed = overall == DoctorState::Fail;
    let report = RepairTestReport {
        overall,
        target,
        supervised: session.supervised,
        supervisor_pid: session.supervisor_pid,
        checks,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if failed {
        bail!("repair test failed");
    }
    Ok(())
}

fn wait_for_probe_success(
    target: &str,
    probe_timeout_secs: f64,
    attempts: u32,
    interval: Duration,
) -> Result<Option<f64>> {
    for attempt in 1..=attempts {
        if let Some(rtt_ms) = ping_once(target, probe_timeout_secs)? {
            return Ok(Some(rtt_ms));
        }

        if attempt != attempts {
            thread::sleep(interval);
        }
    }

    Ok(None)
}

fn ensure_supervised_session(args: &SupervisorArgs, supervisor_log: &mut File) -> Result<()> {
    let existing_session = read_optional_json::<SessionManifest>(&args.connect.session_file)?;

    if let Some(mut session) = existing_session {
        let agent_running = pid_is_running_optional(session.agent_pid)?;
        let gateway_running = pid_is_running_optional(session.gateway_pid)?;

        if agent_running && gateway_running {
            session.supervised = true;
            session.supervisor_pid = Some(process::id());
            session.supervisor_log_file = args.connect.supervisor_log_file.clone();
            save_manifest(&args.connect.session_file, &session)?;
            emit_supervisor_event(
                supervisor_log,
                "session_reused",
                None,
                "existing tunnel session is already running",
                Some(&session),
            )?;
            return Ok(());
        }

        emit_supervisor_event(
            supervisor_log,
            "session_reconcile_started",
            None,
            format!(
                "existing session is not fully running: agent_running={agent_running} gateway_running={gateway_running}"
            ),
            Some(&session),
        )?;
        run_disconnect(disconnect_args_from_connect(&args.connect))?;
    }

    emit_supervisor_event(
        supervisor_log,
        "session_connect_started",
        None,
        "starting supervised tunnel session",
        None,
    )?;
    let mut connect_args = args.connect.clone();
    connect_args.oneshot = true;
    run_connect_oneshot(connect_args)?;
    let mut session = load_manifest(&args.connect.session_file)?;
    session.supervised = true;
    session.supervisor_pid = Some(process::id());
    session.supervisor_log_file = args.connect.supervisor_log_file.clone();
    save_manifest(&args.connect.session_file, &session)?;
    emit_supervisor_event(
        supervisor_log,
        "session_connect_ready",
        None,
        "supervised tunnel session is ready",
        Some(&session),
    )?;

    Ok(())
}

fn supervise_component(
    session: &mut SessionManifest,
    component: ComponentSelection,
    state: &mut ComponentSupervisorState,
    args: &SupervisorArgs,
    supervisor_log: &mut File,
) -> Result<bool> {
    let pid = component_pid(session, component);
    if !pid_is_running_optional(pid)? {
        return restart_supervised_component(
            session,
            component,
            state,
            args,
            supervisor_log,
            format!("process is not running: pid={pid:?}"),
        );
    }

    let status_path = component_status_file(session, component);
    let Some(status) = read_optional_json::<RuntimeStatus>(status_path)? else {
        return observe_unhealthy_component(
            session,
            component,
            state,
            args,
            supervisor_log,
            format!("status file not found: {}", status_path.display()),
        );
    };

    let age_secs = now_unix_secs().saturating_sub(status.observed_at_unix_secs);
    if age_secs > args.stale_after_secs {
        return observe_unhealthy_component(
            session,
            component,
            state,
            args,
            supervisor_log,
            format!("status is stale: observed {age_secs}s ago"),
        );
    }

    match repair_component_os_state(session, component, supervisor_log) {
        Ok(true) => {
            emit_supervisor_event(
                supervisor_log,
                "component_os_state_repaired",
                Some(component),
                format!("{} OS state repaired in place", component_label(component)),
                Some(session),
            )?;
        }
        Ok(false) => {}
        Err(error) => {
            emit_supervisor_event(
                supervisor_log,
                "component_os_state_repair_failed",
                Some(component),
                format!(
                    "{} OS state repair failed: {error:#}",
                    component_label(component)
                ),
                Some(session),
            )?;
        }
    }

    if status.state != HealthState::Healthy || status.phase != TunnelPhase::Active {
        emit_supervisor_event(
            supervisor_log,
            "component_runtime_observed",
            Some(component),
            format!(
                "{} runtime is {:?}/{:?}: {}; process is still running, so supervisor will not restart on dataplane idleness alone",
                component_label(component),
                status.state,
                status.phase,
                status.detail
            ),
            Some(session),
        )?;
        state.unhealthy_samples = 0;
        return Ok(false);
    }

    if state.unhealthy_samples > 0 {
        emit_supervisor_event(
            supervisor_log,
            "component_recovered_without_restart",
            Some(component),
            format!(
                "{} recovered after {} unhealthy sample(s)",
                component_label(component),
                state.unhealthy_samples
            ),
            Some(session),
        )?;
    }
    state.unhealthy_samples = 0;

    Ok(false)
}

fn observe_unhealthy_component(
    session: &mut SessionManifest,
    component: ComponentSelection,
    state: &mut ComponentSupervisorState,
    args: &SupervisorArgs,
    supervisor_log: &mut File,
    reason: String,
) -> Result<bool> {
    state.unhealthy_samples += 1;
    emit_supervisor_event(
        supervisor_log,
        "component_unhealthy_sample",
        Some(component),
        format!(
            "{reason}; sample={}/{}",
            state.unhealthy_samples, args.unhealthy_grace_samples
        ),
        Some(session),
    )?;

    if state.unhealthy_samples >= args.unhealthy_grace_samples.max(1) {
        return restart_supervised_component(
            session,
            component,
            state,
            args,
            supervisor_log,
            reason,
        );
    }

    Ok(false)
}

fn restart_supervised_component(
    session: &mut SessionManifest,
    component: ComponentSelection,
    state: &mut ComponentSupervisorState,
    args: &SupervisorArgs,
    supervisor_log: &mut File,
    reason: String,
) -> Result<bool> {
    if state.restart_count >= args.max_restarts_per_component {
        emit_supervisor_event(
            supervisor_log,
            "component_restart_limit_reached",
            Some(component),
            format!(
                "{} restart limit reached after {} restart(s): {reason}",
                component_label(component),
                state.restart_count
            ),
            Some(session),
        )?;
        bail!(
            "{} restart limit reached after {} restart(s)",
            component_label(component),
            state.restart_count
        );
    }

    if let Some(last_restart) = state.last_restart {
        let elapsed = last_restart.elapsed();
        let cooldown = Duration::from_secs(args.restart_cooldown_secs);
        if elapsed < cooldown {
            emit_supervisor_event(
                supervisor_log,
                "component_restart_suppressed",
                Some(component),
                format!(
                    "{} restart suppressed by cooldown; {:.1}s remaining: {reason}",
                    component_label(component),
                    (cooldown - elapsed).as_secs_f64()
                ),
                Some(session),
            )?;
            return Ok(false);
        }
    }

    emit_supervisor_event(
        supervisor_log,
        "component_restart_started",
        Some(component),
        format!("restarting {}: {reason}", component_label(component)),
        Some(session),
    )?;
    restart_component(session, component)?;
    state.restart_count += 1;
    state.unhealthy_samples = 0;
    state.last_restart = Some(Instant::now());
    emit_supervisor_event(
        supervisor_log,
        "component_restart_complete",
        Some(component),
        format!(
            "restarted {}; restart_count={}",
            component_label(component),
            state.restart_count
        ),
        Some(session),
    )?;

    Ok(true)
}

fn repair_component_os_state(
    session: &SessionManifest,
    component: ComponentSelection,
    supervisor_log: &mut File,
) -> Result<bool> {
    match component {
        ComponentSelection::Agent => repair_agent_routes(session, supervisor_log),
        ComponentSelection::Gateway => repair_gateway_os_state(session, supervisor_log),
    }
}

fn repair_agent_routes(session: &SessionManifest, supervisor_log: &mut File) -> Result<bool> {
    let Some(state) = read_optional_json::<AgentRuntimeState>(&session.agent_state_file)? else {
        return Ok(false);
    };
    let mut repaired = false;

    for cidr in &state.destination_cidrs {
        let target = cidr_route_probe_target(cidr);
        match route_interface_for_target(&target)? {
            Some(interface) if interface == state.tunnel_interface => {}
            observed_interface => {
                apply_agent_route(cidr, &state.tunnel_interface, observed_interface.as_deref())?;
                emit_supervisor_event(
                    supervisor_log,
                    "agent_route_repaired",
                    Some(ComponentSelection::Agent),
                    format!(
                        "route {cidr} repaired to interface {}; previous_interface={observed_interface:?}",
                        state.tunnel_interface
                    ),
                    Some(session),
                )?;
                repaired = true;
            }
        }
    }

    Ok(repaired)
}

fn agent_routes_are_healthy(session: &SessionManifest) -> Result<bool> {
    let Some(state) = read_optional_json::<AgentRuntimeState>(&session.agent_state_file)? else {
        return Ok(false);
    };

    for cidr in &state.destination_cidrs {
        let target = cidr_route_probe_target(cidr);
        if route_interface_for_target(&target)? != Some(state.tunnel_interface.clone()) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn inject_agent_route_drift(session: &SessionManifest) -> Result<()> {
    let Some(state) = read_optional_json::<AgentRuntimeState>(&session.agent_state_file)? else {
        bail!("agent state file is missing");
    };

    for cidr in &state.destination_cidrs {
        let _ = delete_agent_route(cidr, &state.tunnel_interface);
    }

    Ok(())
}

fn delete_agent_route(cidr: &str, interface_name: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = interface_name;
        return run_command_vec(
            "agent route drift injection",
            vec![
                String::from("route"),
                String::from("-n"),
                String::from("delete"),
                String::from("-net"),
                cidr.to_owned(),
            ],
        );
    }

    #[cfg(target_os = "linux")]
    {
        return run_command_vec(
            "agent route drift injection",
            vec![
                String::from("ip"),
                String::from("route"),
                String::from("del"),
                cidr.to_owned(),
                String::from("dev"),
                interface_name.to_owned(),
            ],
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (cidr, interface_name);
        Ok(())
    }
}

fn repair_gateway_os_state(session: &SessionManifest, supervisor_log: &mut File) -> Result<bool> {
    let Some(state) = read_optional_json::<GatewayRuntimeState>(&session.gateway_state_file)?
    else {
        return Ok(false);
    };
    let gateway_config = read_optional_json::<TunnelConfig>(&session.gateway_config)?;
    let mut repaired = false;

    if !ip_forwarding_enabled()? {
        enable_ip_forwarding()?;
        emit_supervisor_event(
            supervisor_log,
            "gateway_forwarding_repaired",
            Some(ComponentSelection::Gateway),
            "IP forwarding was disabled and has been re-enabled",
            Some(session),
        )?;
        repaired = true;
    }

    if repair_gateway_pf_rules_if_needed(&state, gateway_config.as_ref(), session)? {
        emit_supervisor_event(
            supervisor_log,
            "gateway_pf_repaired",
            Some(ComponentSelection::Gateway),
            "PF/NAT rules were missing or stale and have been re-applied",
            Some(session),
        )?;
        repaired = true;
    }

    Ok(repaired)
}

fn gateway_os_state_is_healthy(session: &SessionManifest) -> Result<bool> {
    let Some(state) = read_optional_json::<GatewayRuntimeState>(&session.gateway_state_file)?
    else {
        return Ok(false);
    };
    let gateway_config = read_optional_json::<TunnelConfig>(&session.gateway_config)?;
    let forwarding_ok = ip_forwarding_enabled()?;
    let anchor_ok = state
        .nat_anchor_name
        .as_deref()
        .map(gateway_pf_anchor_has_rules)
        .transpose()?
        .unwrap_or(false);
    let rules_ok = if let Some(path) = state.nat_rules_path.as_ref() {
        if path.exists() {
            let rules = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            gateway_pf_rules_text_is_valid(
                &rules,
                &state.tunnel_interface,
                state
                    .egress_interface
                    .as_deref()
                    .unwrap_or(&session.egress_interface),
                expected_gateway_tunnel_subnet(gateway_config.as_ref())?.as_deref(),
            )
        } else {
            false
        }
    } else {
        false
    };

    Ok(forwarding_ok && anchor_ok && rules_ok)
}

fn inject_gateway_os_state_drift(session: &SessionManifest) -> Result<()> {
    let Some(state) = read_optional_json::<GatewayRuntimeState>(&session.gateway_state_file)?
    else {
        bail!("gateway state file is missing");
    };

    if let Some(anchor_name) = state.nat_anchor_name.as_deref() {
        let _ = run_command_vec(
            "gateway PF drift injection",
            vec![
                String::from("pfctl"),
                String::from("-a"),
                anchor_name.to_owned(),
                String::from("-F"),
                String::from("all"),
            ],
        );
    }

    disable_ip_forwarding()
}

fn disable_ip_forwarding() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return run_command_vec(
            "gateway forwarding drift injection",
            vec![
                String::from("sysctl"),
                String::from("-w"),
                String::from("net.inet.ip.forwarding=0"),
            ],
        );
    }

    #[cfg(target_os = "linux")]
    {
        return run_command_vec(
            "gateway forwarding drift injection",
            vec![
                String::from("sysctl"),
                String::from("-w"),
                String::from("net.ipv4.ip_forward=0"),
            ],
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(())
    }
}

fn emit_supervisor_event(
    log: &mut File,
    event: &str,
    component: Option<ComponentSelection>,
    detail: impl Into<String>,
    session: Option<&SessionManifest>,
) -> Result<()> {
    let payload = serde_json::json!({
        "type": "supervisor_event",
        "event": event,
        "component": component.map(component_label),
        "detail": detail.into(),
        "observed_at_unix_secs": now_unix_secs(),
        "tenant": session.map(|session| session.tenant.as_str()),
        "attachment": session.map(|session| session.attachment.as_str()),
        "agent_pid": session.and_then(|session| session.agent_pid),
        "gateway_pid": session.and_then(|session| session.gateway_pid),
    });
    let line = serde_json::to_string(&payload)?;
    writeln!(log, "{line}").context("failed to write supervisor event")?;
    log.flush().context("failed to flush supervisor event")?;
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn component_pid(session: &SessionManifest, component: ComponentSelection) -> Option<u32> {
    match component {
        ComponentSelection::Agent => session.agent_pid,
        ComponentSelection::Gateway => session.gateway_pid,
    }
}

fn component_status_file(session: &SessionManifest, component: ComponentSelection) -> &Path {
    match component {
        ComponentSelection::Agent => &session.agent_status_file,
        ComponentSelection::Gateway => &session.gateway_status_file,
    }
}

fn component_label(component: ComponentSelection) -> &'static str {
    match component {
        ComponentSelection::Agent => "agent",
        ComponentSelection::Gateway => "gateway",
    }
}

fn disconnect_args_from_connect(args: &ConnectArgs) -> DisconnectArgs {
    DisconnectArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        agent_config: args.agent_config.clone(),
        agent_state_file: args.agent_state_file.clone(),
        agent_status_file: args.agent_status_file.clone(),
        gateway_state_file: args.gateway_state_file.clone(),
        gateway_status_file: args.gateway_status_file.clone(),
        session_file: args.session_file.clone(),
        route_mode: args.route_mode,
        forwarding_mode: args.forwarding_mode,
        nat_mode: args.nat_mode,
    }
}

fn connect_args_from_session(session: &SessionManifest, session_file: &Path) -> ConnectArgs {
    ConnectArgs {
        profile: Some(session.attachment.clone()),
        tenant: Some(session.tenant.clone()),
        attachment: Some(session.attachment.clone()),
        profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
        agent_config: session.agent_config.clone(),
        gateway_config: session.gateway_config.clone(),
        agent_state_file: session.agent_state_file.clone(),
        agent_status_file: session.agent_status_file.clone(),
        gateway_state_file: session.gateway_state_file.clone(),
        gateway_status_file: session.gateway_status_file.clone(),
        session_file: session_file.to_path_buf(),
        agent_log_file: session.agent_log_file.clone(),
        gateway_log_file: session.gateway_log_file.clone(),
        egress_interface: session.egress_interface.clone(),
        route_mode: session.route_mode,
        forwarding_mode: session.forwarding_mode,
        nat_mode: session.nat_mode,
        ready_timeout_secs: 12,
        oneshot: false,
        supervisor_log_file: session.supervisor_log_file.clone(),
    }
}

fn doctor_check(
    name: impl Into<String>,
    state: DoctorState,
    detail: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        state,
        detail: detail.into(),
    }
}

fn print_doctor_report(target: String, checks: Vec<DoctorCheck>) -> Result<()> {
    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else if checks.iter().any(|check| check.state == DoctorState::Warn) {
        DoctorState::Warn
    } else {
        DoctorState::Pass
    };

    let report = DoctorReport {
        overall,
        target,
        checks,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn check_process(name: &str, pid: Option<u32>, checks: &mut Vec<DoctorCheck>) {
    let Some(pid) = pid else {
        checks.push(doctor_check(
            name,
            DoctorState::Fail,
            "session manifest has no pid",
        ));
        return;
    };

    match pid_is_running(pid) {
        Ok(true) => checks.push(doctor_check(
            name,
            DoctorState::Pass,
            format!("pid {pid} is running"),
        )),
        Ok(false) => checks.push(doctor_check(
            name,
            DoctorState::Fail,
            format!("pid {pid} is not running"),
        )),
        Err(error) => checks.push(doctor_check(
            name,
            DoctorState::Warn,
            format!("could not verify pid {pid}: {error:#}"),
        )),
    }
}

fn check_runtime_status(
    name: &str,
    status: Option<&RuntimeStatus>,
    path: &Path,
    stale_after_secs: u64,
    probe_passed: bool,
    checks: &mut Vec<DoctorCheck>,
) {
    let Some(status) = status else {
        checks.push(doctor_check(
            name,
            DoctorState::Fail,
            format!("status file not found: {}", path.display()),
        ));
        return;
    };

    let age_secs = now_unix_secs().saturating_sub(status.observed_at_unix_secs);
    if age_secs > stale_after_secs {
        checks.push(doctor_check(
            name,
            DoctorState::Fail,
            format!("status is stale: observed {age_secs}s ago"),
        ));
        return;
    }

    if status.state != HealthState::Healthy {
        let state = if probe_passed {
            DoctorState::Warn
        } else {
            DoctorState::Fail
        };
        checks.push(doctor_check(
            name,
            state,
            format!(
                "runtime state is {:?}: {}; probe_passed={probe_passed}",
                status.state, status.detail
            ),
        ));
        return;
    }

    if status.phase != TunnelPhase::Active {
        checks.push(doctor_check(
            name,
            DoctorState::Warn,
            format!("runtime phase is {:?}: {}", status.phase, status.detail),
        ));
        return;
    }

    checks.push(doctor_check(
        name,
        DoctorState::Pass,
        format!(
            "healthy active status on {:?}; observed {age_secs}s ago",
            status.tunnel_interface
        ),
    ));
}

fn check_agent_state(
    state: Option<&AgentRuntimeState>,
    path: &Path,
    checks: &mut Vec<DoctorCheck>,
) {
    let Some(state) = state else {
        checks.push(doctor_check(
            "agent_state",
            DoctorState::Fail,
            format!("agent state file not found: {}", path.display()),
        ));
        return;
    };

    if state.destination_cidrs.is_empty() {
        checks.push(doctor_check(
            "agent_state",
            DoctorState::Warn,
            format!(
                "agent state exists for {}, but no destination CIDRs are configured",
                state.tunnel_interface
            ),
        ));
        return;
    }

    checks.push(doctor_check(
        "agent_state",
        DoctorState::Pass,
        format!(
            "agent interface {} owns {} route(s)",
            state.tunnel_interface,
            state.destination_cidrs.len()
        ),
    ));
}

fn check_gateway_state(
    state: Option<&GatewayRuntimeState>,
    path: &Path,
    checks: &mut Vec<DoctorCheck>,
) {
    let Some(state) = state else {
        checks.push(doctor_check(
            "gateway_state",
            DoctorState::Fail,
            format!("gateway state file not found: {}", path.display()),
        ));
        return;
    };

    checks.push(doctor_check(
        "gateway_state",
        DoctorState::Pass,
        format!(
            "gateway interface {} egress={:?} anchor={:?}",
            state.tunnel_interface, state.egress_interface, state.nat_anchor_name
        ),
    ));
}

fn check_route_to_target(
    target: &str,
    agent_state: Option<&AgentRuntimeState>,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let Some(agent_state) = agent_state else {
        checks.push(doctor_check(
            "route_to_target",
            DoctorState::Warn,
            "skipped because agent state is missing",
        ));
        return Ok(());
    };

    match route_interface_for_target(target)? {
        Some(interface) if interface == agent_state.tunnel_interface => {
            checks.push(doctor_check(
                "route_to_target",
                DoctorState::Pass,
                format!("{target} routes through {}", agent_state.tunnel_interface),
            ));
        }
        Some(interface) => {
            checks.push(doctor_check(
                "route_to_target",
                DoctorState::Fail,
                format!(
                    "{target} routes through {interface}, expected {}",
                    agent_state.tunnel_interface
                ),
            ));
        }
        None => {
            checks.push(doctor_check(
                "route_to_target",
                DoctorState::Fail,
                format!("could not determine route interface for {target}"),
            ));
        }
    }

    Ok(())
}

fn check_gateway_pf_rules(
    gateway_state: Option<&GatewayRuntimeState>,
    gateway_config: Option<&TunnelConfig>,
    session_egress_interface: &str,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let Some(state) = gateway_state else {
        checks.push(doctor_check(
            "gateway_pf_rules",
            DoctorState::Warn,
            "skipped because gateway state is missing",
        ));
        return Ok(());
    };

    let Some(rules_path) = state.nat_rules_path.as_ref() else {
        checks.push(doctor_check(
            "gateway_pf_rules",
            DoctorState::Fail,
            "gateway state has no NAT rules path",
        ));
        return Ok(());
    };

    if let Some(anchor) = state.nat_anchor_name.as_deref() {
        let old_nested_suffix = format!("/{}", state.tunnel_interface);
        if anchor.ends_with(&old_nested_suffix) {
            checks.push(doctor_check(
                "gateway_pf_anchor",
                DoctorState::Fail,
                format!("PF anchor is nested and may not be evaluated by macOS: {anchor}"),
            ));
        } else {
            checks.push(doctor_check(
                "gateway_pf_anchor",
                DoctorState::Pass,
                format!("PF anchor is direct: {anchor}"),
            ));
        }
    } else {
        checks.push(doctor_check(
            "gateway_pf_anchor",
            DoctorState::Warn,
            "gateway state has no PF anchor name",
        ));
    }

    if !rules_path.exists() {
        checks.push(doctor_check(
            "gateway_pf_rules",
            DoctorState::Fail,
            format!("PF rules file not found: {}", rules_path.display()),
        ));
        return Ok(());
    }

    let rules = fs::read_to_string(rules_path)
        .with_context(|| format!("failed to read {}", rules_path.display()))?;
    let egress_interface = state
        .egress_interface
        .as_deref()
        .unwrap_or(session_egress_interface);
    let mut failures = Vec::new();

    if !rules.contains(&format!("nat on {egress_interface}")) {
        failures.push(format!("missing NAT on {egress_interface}"));
    }
    if !rules.contains(&format!("pass in quick on {}", state.tunnel_interface)) {
        failures.push(format!(
            "missing pass-in rule on {}",
            state.tunnel_interface
        ));
    }

    if let Some(expected_subnet) = expected_gateway_tunnel_subnet(gateway_config)? {
        if !rules.contains(&expected_subnet) {
            failures.push(format!("missing expected tunnel subnet {expected_subnet}"));
        }
    }

    #[cfg(target_os = "macos")]
    if !rules.contains("route-to") {
        failures.push(String::from("missing macOS route-to egress rule"));
    }

    if failures.is_empty() {
        checks.push(doctor_check(
            "gateway_pf_rules",
            DoctorState::Pass,
            format!("PF rules file looks valid: {}", rules_path.display()),
        ));
    } else {
        checks.push(doctor_check(
            "gateway_pf_rules",
            DoctorState::Fail,
            failures.join("; "),
        ));
    }

    Ok(())
}

fn cidr_route_probe_target(cidr: &str) -> String {
    cidr.split('/').next().unwrap_or(cidr).to_owned()
}

fn apply_agent_route(
    cidr: &str,
    interface_name: &str,
    observed_interface: Option<&str>,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = observed_interface;
        let add_result = run_command_vec(
            "agent route repair",
            vec![
                String::from("route"),
                String::from("-n"),
                String::from("add"),
                String::from("-net"),
                cidr.to_owned(),
                String::from("-interface"),
                interface_name.to_owned(),
            ],
        );
        if add_result.is_ok() {
            return Ok(());
        }

        return run_command_vec(
            "agent route repair",
            vec![
                String::from("route"),
                String::from("-n"),
                String::from("change"),
                String::from("-net"),
                cidr.to_owned(),
                String::from("-interface"),
                interface_name.to_owned(),
            ],
        );
    }

    #[cfg(target_os = "linux")]
    {
        let _ = observed_interface;
        return run_command_vec(
            "agent route repair",
            vec![
                String::from("ip"),
                String::from("route"),
                String::from("replace"),
                cidr.to_owned(),
                String::from("dev"),
                interface_name.to_owned(),
            ],
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (cidr, interface_name, observed_interface);
        Ok(())
    }
}

fn ip_forwarding_enabled() -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .context("failed to query net.inet.ip.forwarding")?;
        if !output.status.success() {
            bail!(
                "failed to query net.inet.ip.forwarding: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return Ok(String::from_utf8_lossy(&output.stdout).trim() == "1");
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "net.ipv4.ip_forward"])
            .output()
            .context("failed to query net.ipv4.ip_forward")?;
        if !output.status.success() {
            bail!(
                "failed to query net.ipv4.ip_forward: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return Ok(String::from_utf8_lossy(&output.stdout).trim() == "1");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(true)
    }
}

fn enable_ip_forwarding() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return run_command_vec(
            "gateway forwarding repair",
            vec![
                String::from("sysctl"),
                String::from("-w"),
                String::from("net.inet.ip.forwarding=1"),
            ],
        );
    }

    #[cfg(target_os = "linux")]
    {
        return run_command_vec(
            "gateway forwarding repair",
            vec![
                String::from("sysctl"),
                String::from("-w"),
                String::from("net.ipv4.ip_forward=1"),
            ],
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(())
    }
}

fn repair_gateway_pf_rules_if_needed(
    state: &GatewayRuntimeState,
    gateway_config: Option<&TunnelConfig>,
    session: &SessionManifest,
) -> Result<bool> {
    let Some(anchor_name) = state.nat_anchor_name.as_deref() else {
        return Ok(false);
    };
    let Some(rules_path) = state.nat_rules_path.as_ref() else {
        return Ok(false);
    };

    let egress_interface = state
        .egress_interface
        .as_deref()
        .unwrap_or(&session.egress_interface);
    let expected_subnet = expected_gateway_tunnel_subnet(gateway_config)?;
    let mut needs_repair = !rules_path.exists();

    if !needs_repair {
        let rules = fs::read_to_string(rules_path)
            .with_context(|| format!("failed to read {}", rules_path.display()))?;
        needs_repair = !gateway_pf_rules_text_is_valid(
            &rules,
            &state.tunnel_interface,
            egress_interface,
            expected_subnet.as_deref(),
        );
    }

    if !gateway_pf_anchor_has_rules(anchor_name)? {
        needs_repair = true;
    }

    if !needs_repair {
        return Ok(false);
    }

    let rules = build_gateway_pf_rules(
        &state.tunnel_interface,
        egress_interface,
        expected_subnet.as_deref(),
    )?;
    if let Some(parent) = rules_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(rules_path, rules)
        .with_context(|| format!("failed to write {}", rules_path.display()))?;
    run_command_vec(
        "gateway nat repair",
        vec![String::from("pfctl"), String::from("-E")],
    )?;
    run_command_vec(
        "gateway nat repair",
        vec![
            String::from("pfctl"),
            String::from("-a"),
            anchor_name.to_owned(),
            String::from("-f"),
            rules_path.to_string_lossy().into_owned(),
        ],
    )?;

    Ok(true)
}

fn gateway_pf_rules_text_is_valid(
    rules: &str,
    tunnel_interface: &str,
    egress_interface: &str,
    expected_subnet: Option<&str>,
) -> bool {
    rules.contains(&format!("nat on {egress_interface}"))
        && rules.contains(&format!("pass in quick on {tunnel_interface}"))
        && expected_subnet
            .map(|subnet| rules.contains(subnet))
            .unwrap_or(true)
        && {
            #[cfg(target_os = "macos")]
            {
                rules.contains("route-to")
            }
            #[cfg(not(target_os = "macos"))]
            {
                true
            }
        }
}

fn gateway_pf_anchor_has_rules(anchor_name: &str) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("pfctl")
            .args(["-a", anchor_name, "-s", "rules"])
            .output()
            .context("failed to inspect PF anchor")?;
        if !output.status.success() {
            return Ok(false);
        }
        return Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = anchor_name;
        Ok(true)
    }
}

fn build_gateway_pf_rules(
    tunnel_interface: &str,
    egress_interface: &str,
    expected_subnet: Option<&str>,
) -> Result<String> {
    let subnet =
        expected_subnet.ok_or_else(|| anyhow!("gateway config missing expected tunnel subnet"))?;
    let egress_gateway = query_macos_default_gateway(egress_interface)?;
    let route_to = egress_gateway
        .as_deref()
        .map(|gateway| format!(" route-to ({egress_interface} {gateway})"))
        .unwrap_or_default();

    Ok(format!(
        "nat on {egress_interface} from {subnet} to any -> ({egress_interface})\n\
pass out quick on {egress_interface} inet from {subnet} to any keep state\n\
pass in quick on {tunnel_interface}{route_to} inet from {subnet} to any keep state\n\
pass out quick on {tunnel_interface} inet from any to {subnet} keep state\n"
    ))
}

fn query_macos_default_gateway(egress_interface: &str) -> Result<Option<String>> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .context("failed to query macOS default route")?;
        if !output.status.success() {
            bail!(
                "failed to query macOS default route\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let gateway = parse_route_get_field(&stdout, "gateway");
        let interface = parse_route_get_field(&stdout, "interface");
        if interface.as_deref() == Some(egress_interface) {
            return Ok(gateway);
        }
        Ok(None)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = egress_interface;
        Ok(None)
    }
}

fn check_probe(target: &str, timeout_secs: f64, checks: &mut Vec<DoctorCheck>) -> Result<bool> {
    match ping_once(target, timeout_secs)? {
        Some(rtt_ms) => {
            checks.push(doctor_check(
                "probe",
                DoctorState::Pass,
                format!("{target} replied in {rtt_ms:.3}ms"),
            ));
            Ok(true)
        }
        None => {
            checks.push(doctor_check(
                "probe",
                DoctorState::Fail,
                format!("{target} did not reply within {timeout_secs:.1}s"),
            ));
            Ok(false)
        }
    }
}

fn check_packet_path_analysis(
    probe_passed: bool,
    agent_before: Option<&PacketPathTelemetry>,
    agent_after: Option<&PacketPathTelemetry>,
    gateway_before: Option<&PacketPathTelemetry>,
    gateway_after: Option<&PacketPathTelemetry>,
    checks: &mut Vec<DoctorCheck>,
) {
    let Some(agent_delta) = packet_path_delta(agent_before, agent_after) else {
        checks.push(doctor_check(
            "packet_path_analysis",
            DoctorState::Warn,
            "agent packet-path telemetry is unavailable",
        ));
        return;
    };
    let Some(gateway_delta) = packet_path_delta(gateway_before, gateway_after) else {
        checks.push(doctor_check(
            "packet_path_analysis",
            DoctorState::Warn,
            "gateway packet-path telemetry is unavailable",
        ));
        return;
    };

    if let Some(error) = agent_delta
        .last_packet_error
        .as_ref()
        .or(gateway_delta.last_packet_error.as_ref())
    {
        checks.push(doctor_check(
            "packet_path_analysis",
            DoctorState::Fail,
            format!("packet-path error observed: {error}"),
        ));
        return;
    }

    let detail = format!(
        "agent tun_read_packets_delta={} udp_tx_packets_delta={} wg_encapsulated_delta={}; gateway udp_rx_packets_delta={} wg_decapsulated_delta={} tun_write_packets_delta={}",
        agent_delta.tun_read_packets_delta,
        agent_delta.udp_tx_packets_delta,
        agent_delta.wireguard_encapsulated_packets_delta,
        gateway_delta.udp_rx_packets_delta,
        gateway_delta.wireguard_decapsulated_packets_delta,
        gateway_delta.tun_write_packets_delta
    );

    if probe_passed {
        checks.push(doctor_check(
            "packet_path_analysis",
            DoctorState::Pass,
            format!("probe passed; packet path moved successfully. {detail}"),
        ));
        return;
    }

    let (state, reason) = if agent_delta.tun_read_packets_delta <= 0 {
        (
            DoctorState::Fail,
            "traffic did not enter the agent TUN; likely route/capture issue",
        )
    } else if agent_delta.wireguard_encapsulated_packets_delta <= 0 {
        (
            DoctorState::Fail,
            "agent read packets but did not encapsulate them; likely WireGuard encapsulation issue",
        )
    } else if agent_delta.udp_tx_packets_delta <= 0 {
        (
            DoctorState::Fail,
            "agent encapsulated packets but did not send UDP; likely UDP send/peer endpoint issue",
        )
    } else if gateway_delta.udp_rx_packets_delta <= 0 {
        (
            DoctorState::Fail,
            "agent sent UDP but gateway did not receive it; likely UDP path/listener issue",
        )
    } else if gateway_delta.wireguard_decapsulated_packets_delta <= 0 {
        (
            DoctorState::Fail,
            "gateway received UDP but did not decapsulate packets; likely WireGuard key/session issue",
        )
    } else if gateway_delta.tun_write_packets_delta <= 0 {
        (
            DoctorState::Fail,
            "gateway decapsulated packets but did not write to TUN; likely gateway TUN write issue",
        )
    } else {
        (
            DoctorState::Fail,
            "packets reached gateway TUN but probe failed; likely gateway egress/NAT/return-path issue",
        )
    };

    checks.push(doctor_check(
        "packet_path_analysis",
        state,
        format!("{reason}. {detail}"),
    ));
}

fn packet_path_delta(
    before: Option<&PacketPathTelemetry>,
    after: Option<&PacketPathTelemetry>,
) -> Option<PacketPathDelta> {
    let (before, after) = (before?, after?);
    Some(PacketPathDelta {
        tun_read_packets_delta: after.tun_read_packets as i64 - before.tun_read_packets as i64,
        tun_read_bytes_delta: after.tun_read_bytes as i64 - before.tun_read_bytes as i64,
        tun_write_packets_delta: after.tun_write_packets as i64 - before.tun_write_packets as i64,
        tun_write_bytes_delta: after.tun_write_bytes as i64 - before.tun_write_bytes as i64,
        udp_rx_packets_delta: after.udp_rx_packets as i64 - before.udp_rx_packets as i64,
        udp_rx_bytes_delta: after.udp_rx_bytes as i64 - before.udp_rx_bytes as i64,
        udp_tx_packets_delta: after.udp_tx_packets as i64 - before.udp_tx_packets as i64,
        udp_tx_bytes_delta: after.udp_tx_bytes as i64 - before.udp_tx_bytes as i64,
        wireguard_encapsulated_packets_delta: after.wireguard_encapsulated_packets as i64
            - before.wireguard_encapsulated_packets as i64,
        wireguard_decapsulated_packets_delta: after.wireguard_decapsulated_packets as i64
            - before.wireguard_decapsulated_packets as i64,
        last_packet_error: after
            .last_packet_error
            .clone()
            .or_else(|| before.last_packet_error.clone()),
    })
}

fn wait_for_active_status_after_probe(session: &SessionManifest, settle_secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(settle_secs);

    loop {
        let agent_status = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?;
        let gateway_status = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?;

        if agent_status
            .as_ref()
            .map(is_transport_active)
            .unwrap_or(false)
            && gateway_status
                .as_ref()
                .map(is_transport_active)
                .unwrap_or(false)
        {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Ok(());
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn pid_is_running(pid: u32) -> Result<bool> {
    let output = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .with_context(|| format!("failed to check pid {pid}"))?;
    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Operation not permitted") {
        return Ok(true);
    }

    Ok(false)
}

fn pid_is_running_optional(pid: Option<u32>) -> Result<bool> {
    pid.map(pid_is_running)
        .transpose()
        .map(|value| value.unwrap_or(false))
}

fn expected_gateway_tunnel_subnet(config: Option<&TunnelConfig>) -> Result<Option<String>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(wireguard) = config.wireguard.as_ref() else {
        return Ok(None);
    };
    Ok(Some(ipv4_subnet(
        &wireguard.local_tunnel_address,
        "255.255.255.0",
    )?))
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

fn route_interface_for_target(target: &str) -> Result<Option<String>> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", target])
            .output()
            .with_context(|| format!("failed to query route for {target}"))?;
        if !output.status.success() {
            return Ok(None);
        }
        return Ok(parse_route_get_field(
            &String::from_utf8_lossy(&output.stdout),
            "interface",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "get", target])
            .output()
            .with_context(|| format!("failed to query route for {target}"))?;
        if !output.status.success() {
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut parts = stdout.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                return Ok(parts.next().map(ToOwned::to_owned));
            }
        }
        return Ok(None);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = target;
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
fn parse_route_get_field(output: &str, field: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key.trim() == field).then(|| value.trim().to_owned())
    })
}

fn observe_status_history(
    sequence: u32,
    status_path: &Path,
    history: &mut StatusHistory,
    _suite_started_at: Instant,
) -> Result<()> {
    let Some(status) = read_optional_json::<RuntimeStatus>(status_path)? else {
        return Ok(());
    };

    if status.state != HealthState::Healthy {
        history.degraded_samples += 1;
    }
    if status.phase == TunnelPhase::Stale {
        history.stale_samples += 1;
    }

    if history.last_phase.as_ref() != Some(&status.phase) {
        history.transitions.push(PhaseTransition {
            sequence,
            from: history.last_phase.clone(),
            to: status.phase.clone(),
            observed_at_unix_secs: status.observed_at_unix_secs,
        });
        history.last_phase = Some(status.phase.clone());
    }

    if status.phase == TunnelPhase::Active
        && history.recovered_after_secs.is_none()
        && history.recovery_started_at.is_some()
    {
        history.recovered_after_secs = history
            .recovery_started_at
            .take()
            .map(|instant| instant.elapsed().as_secs_f64());
    }

    Ok(())
}

fn restart_component(session: &mut SessionManifest, component: ComponentSelection) -> Result<()> {
    match component {
        ComponentSelection::Agent => {
            terminate_pid(session.agent_pid)?;
            thread::sleep(Duration::from_millis(500));
            let agent_bin = sibling_binary("tunnel-agent")?;
            let (stdout, stderr) = log_stdio(&session.agent_log_file, true)?;
            let child = Command::new(&agent_bin)
                .arg("--config")
                .arg(&session.agent_config)
                .arg("--tun")
                .arg("--route-mode")
                .arg(mode_str(session.route_mode))
                .arg("--state-file")
                .arg(&session.agent_state_file)
                .arg("--status-file")
                .arg(&session.agent_status_file)
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .with_context(|| format!("failed to respawn {}", agent_bin.display()))?;
            session.agent_pid = Some(child.id());
        }
        ComponentSelection::Gateway => {
            terminate_pid(session.gateway_pid)?;
            thread::sleep(Duration::from_millis(500));
            let gateway_bin = sibling_binary("tunnel-gateway")?;
            let (stdout, stderr) = log_stdio(&session.gateway_log_file, true)?;
            let child = Command::new(&gateway_bin)
                .arg("--config")
                .arg(&session.gateway_config)
                .arg("--tun")
                .arg("--forwarding-mode")
                .arg(mode_str(session.forwarding_mode))
                .arg("--nat-mode")
                .arg(mode_str(session.nat_mode))
                .arg("--egress-interface")
                .arg(&session.egress_interface)
                .arg("--state-file")
                .arg(&session.gateway_state_file)
                .arg("--status-file")
                .arg(&session.gateway_status_file)
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .with_context(|| format!("failed to respawn {}", gateway_bin.display()))?;
            session.gateway_pid = Some(child.id());
        }
    }

    Ok(())
}

fn ping_once(target: &str, timeout_secs: f64) -> Result<Option<f64>> {
    #[cfg(target_os = "macos")]
    let output = {
        let timeout_arg = timeout_millis_arg(timeout_secs);
        let mut command = Command::new("ping");
        command.args(["-n", "-c", "1", "-W", &timeout_arg, target]);
        output_with_timeout(
            &mut command,
            Duration::from_secs_f64(timeout_secs.max(1.0) + 2.0),
            &format!("ping {target}"),
        )?
    };

    #[cfg(target_os = "linux")]
    let output = {
        let timeout_arg = timeout_secs_arg(timeout_secs);
        let mut command = Command::new("ping");
        command.args(["-n", "-c", "1", "-W", &timeout_arg, target]);
        output_with_timeout(
            &mut command,
            Duration::from_secs_f64(timeout_secs.max(1.0) + 2.0),
            &format!("ping {target}"),
        )?
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let output = {
        let mut command = Command::new("ping");
        command.args(["-c", "1", target]);
        output_with_timeout(
            &mut command,
            Duration::from_secs_f64(timeout_secs.max(1.0) + 2.0),
            &format!("ping {target}"),
        )?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && !stdout.contains("time=") {
        if !stderr.trim().is_empty() {
            eprintln!("ping failure: {}", stderr.trim());
        }
        return Ok(None);
    }

    Ok(extract_time_ms(&stdout))
}

fn output_with_timeout(command: &mut Command, timeout: Duration, label: &str) -> Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {label}"))?;
    let deadline = Instant::now() + timeout;

    loop {
        if child
            .try_wait()
            .with_context(|| format!("failed to poll {label}"))?
            .is_some()
        {
            return child
                .wait_with_output()
                .with_context(|| format!("failed to collect {label} output"));
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .with_context(|| format!("failed to collect timed-out {label} output"))?;
            eprintln!("{label} timed out after {:.1}s", timeout.as_secs_f64());
            return Ok(output);
        }

        thread::sleep(Duration::from_millis(25));
    }
}

fn extract_time_ms(output: &str) -> Option<f64> {
    output
        .lines()
        .find_map(|line| line.split("time=").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse::<f64>().ok())
}

fn average(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

#[cfg(target_os = "linux")]
fn timeout_secs_arg(timeout_secs: f64) -> String {
    timeout_secs.ceil().max(1.0).to_string()
}

#[cfg(target_os = "macos")]
fn timeout_millis_arg(timeout_secs: f64) -> String {
    ((timeout_secs * 1000.0).round() as u64).max(1).to_string()
}

fn runtime_bytes_snapshot(status: &RuntimeStatus) -> ByteSnapshot {
    ByteSnapshot {
        ingress_bytes: status.ingress_bytes,
        egress_bytes: status.egress_bytes,
        observed_at_unix_secs: status.observed_at_unix_secs,
    }
}

fn byte_delta(before: Option<&RuntimeStatus>, after: Option<&RuntimeStatus>) -> Option<ByteDelta> {
    let (before, after) = (before?, after?);
    Some(ByteDelta {
        ingress_delta: after.ingress_bytes as i64 - before.ingress_bytes as i64,
        egress_delta: after.egress_bytes as i64 - before.egress_bytes as i64,
    })
}

fn is_transport_active(status: &RuntimeStatus) -> bool {
    status.state == HealthState::Healthy && status.phase == TunnelPhase::Active
}

fn classify_failure_domain(
    received: u32,
    agent_delta: Option<&ByteDelta>,
    gateway_delta: Option<&ByteDelta>,
    agent_status: Option<&RuntimeStatus>,
    gateway_status: Option<&RuntimeStatus>,
) -> FailureDomain {
    if received > 0 {
        return FailureDomain::None;
    }

    let agent_active = agent_status.map(is_transport_active).unwrap_or(false);
    let gateway_active = gateway_status.map(is_transport_active).unwrap_or(false);
    let agent_moved = agent_delta
        .map(|delta| delta.ingress_delta > 0 || delta.egress_delta > 0)
        .unwrap_or(false);
    let gateway_moved = gateway_delta
        .map(|delta| delta.ingress_delta > 0 || delta.egress_delta > 0)
        .unwrap_or(false);

    match (agent_moved, gateway_moved, agent_active, gateway_active) {
        (false, false, _, _) => FailureDomain::ProbeNeverEnteredTunnel,
        (_, _, false, false) | (_, _, false, true) | (_, _, true, false) => {
            FailureDomain::TransportOrPeerLiveness
        }
        _ => FailureDomain::GatewayEgressOrReturnPath,
    }
}

fn percentile(values: &[f64], percentile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let position =
        ((percentile / 100.0) * (values.len().saturating_sub(1) as f64)).round() as usize;
    values.get(position).copied()
}

fn mean_jitter(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let diffs: Vec<f64> = values
        .windows(2)
        .map(|pair| (pair[1] - pair[0]).abs())
        .collect();
    average(&diffs)
}

fn max_jitter(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    values
        .windows(2)
        .map(|pair| (pair[1] - pair[0]).abs())
        .fold(None, |acc, value| match acc {
            Some(current) => Some(current.max(value)),
            None => Some(value),
        })
}

fn run_cleanup_binary(binary: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to run {}", binary.display()))?;

    if !status.success() {
        bail!("cleanup command failed for {}", binary.display());
    }

    Ok(())
}

fn run_command_vec(label: &str, command: Vec<String>) -> Result<()> {
    let rendered = command.join(" ");
    let Some((binary, args)) = command.split_first() else {
        bail!("{label} command is empty");
    };
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {label} command: {rendered}"))?;
    if !output.status.success() {
        bail!(
            "{label} command failed: {rendered}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn preflight_connect_args(args: &ConnectArgs) -> Result<()> {
    validate_config_file("agent config", &args.agent_config)?;
    validate_config_file("gateway config", &args.gateway_config)?;
    Ok(())
}

fn reconcile_before_connect(args: &ConnectArgs) -> Result<()> {
    let existing_session = read_optional_json::<SessionManifest>(&args.session_file)?;

    if let Some(session) = existing_session {
        let agent_running = pid_is_running_optional(session.agent_pid)?;
        let gateway_running = pid_is_running_optional(session.gateway_pid)?;

        if agent_running || gateway_running {
            bail!(
                "Tunnel is already running or partially running: agent_pid={:?} running={} gateway_pid={:?} running={}. Run tunnel-cli status or tunnel-cli disconnect first.",
                session.agent_pid,
                agent_running,
                session.gateway_pid,
                gateway_running
            );
        }

        eprintln!(
            "stale Tunnel session found at {}; reconciling before connect",
            args.session_file.display()
        );
    }

    cleanup_stale_tunnel_state(args)?;
    remove_stale_file("session", &args.session_file)?;

    Ok(())
}

fn remove_stale_file(label: &str, path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to remove stale {label} file {}", path.display()))?;
    }
    Ok(())
}

fn cleanup_stale_tunnel_state(args: &ConnectArgs) -> Result<()> {
    let agent_bin = sibling_binary("tunnel-agent")?;
    let gateway_bin = sibling_binary("tunnel-gateway")?;

    if args.agent_state_file.exists() {
        eprintln!(
            "cleaning stale agent state using {}",
            args.agent_state_file.display()
        );
        run_cleanup_binary(
            &agent_bin,
            &[
                "--config",
                path_arg(&args.agent_config)?,
                "--cleanup-only",
                "--route-mode",
                mode_str(args.route_mode),
                "--state-file",
                path_arg(&args.agent_state_file)?,
                "--status-file",
                path_arg(&args.agent_status_file)?,
            ],
        )?;
    } else {
        remove_stale_file("agent status", &args.agent_status_file)?;
    }

    if args.gateway_state_file.exists() {
        eprintln!(
            "cleaning stale gateway state using {}",
            args.gateway_state_file.display()
        );
        run_cleanup_binary(
            &gateway_bin,
            &[
                "--cleanup-only",
                "--forwarding-mode",
                mode_str(args.forwarding_mode),
                "--nat-mode",
                mode_str(args.nat_mode),
                "--state-file",
                path_arg(&args.gateway_state_file)?,
                "--status-file",
                path_arg(&args.gateway_status_file)?,
            ],
        )?;
    } else {
        remove_stale_file("gateway status", &args.gateway_status_file)?;
    }

    Ok(())
}

fn validate_config_file(label: &str, path: &Path) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("{label} not found or unreadable: {}", path.display()))?;
    let config: TunnelConfig = serde_json::from_str(&contents)
        .with_context(|| format!("{label} is invalid JSON: {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("{label} failed validation: {}", path.display()))?;
    Ok(())
}

fn ensure_child_still_running(child: &mut Child, label: &str, log_path: &Path) -> Result<()> {
    if let Some(status) = child
        .try_wait()
        .with_context(|| format!("failed to inspect {label} process"))?
    {
        bail!(
            "{label} exited during startup with status {status}. inspect logs with: tunnel-cli logs --component {label} --lines 80 or read {}",
            log_path.display()
        );
    }

    Ok(())
}

fn wait_for_connect_ready(args: &ConnectArgs) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.ready_timeout_secs);

    loop {
        let agent_status = read_optional_json::<RuntimeStatus>(&args.agent_status_file)?;
        let gateway_status = read_optional_json::<RuntimeStatus>(&args.gateway_status_file)?;
        let agent_state = read_optional_json::<AgentRuntimeState>(&args.agent_state_file)?;
        let gateway_state = read_optional_json::<GatewayRuntimeState>(&args.gateway_state_file)?;

        if runtime_status_is_fresh(agent_status.as_ref(), args.ready_timeout_secs)
            && runtime_status_is_fresh(gateway_status.as_ref(), args.ready_timeout_secs)
            && agent_state.is_some()
            && gateway_state.is_some()
        {
            return Ok(());
        }

        if Instant::now() >= deadline {
            bail!(
                "tunnel did not become ready within {}s. inspect logs with: tunnel-cli logs --component both --lines 80",
                args.ready_timeout_secs
            );
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn wait_for_supervised_connect_ready(args: &ConnectArgs, supervisor_pid: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.ready_timeout_secs);

    loop {
        if !pid_is_running(supervisor_pid)? {
            bail!(
                "tunnel supervisor exited during startup. inspect {}",
                args.supervisor_log_file.display()
            );
        }

        let session = read_optional_json::<SessionManifest>(&args.session_file)?;
        let agent_status = read_optional_json::<RuntimeStatus>(&args.agent_status_file)?;
        let gateway_status = read_optional_json::<RuntimeStatus>(&args.gateway_status_file)?;
        let agent_state = read_optional_json::<AgentRuntimeState>(&args.agent_state_file)?;
        let gateway_state = read_optional_json::<GatewayRuntimeState>(&args.gateway_state_file)?;

        if session
            .as_ref()
            .map(|session| {
                session.supervised
                    && session.supervisor_pid == Some(supervisor_pid)
                    && session.agent_pid.is_some()
                    && session.gateway_pid.is_some()
            })
            .unwrap_or(false)
            && runtime_status_is_fresh(agent_status.as_ref(), args.ready_timeout_secs)
            && runtime_status_is_fresh(gateway_status.as_ref(), args.ready_timeout_secs)
            && agent_state.is_some()
            && gateway_state.is_some()
        {
            return Ok(());
        }

        if Instant::now() >= deadline {
            bail!(
                "supervised tunnel did not become ready within {}s. inspect {} or run tunnel-cli logs --component both --lines 80",
                args.ready_timeout_secs,
                args.supervisor_log_file.display()
            );
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn runtime_status_is_fresh(status: Option<&RuntimeStatus>, stale_after_secs: u64) -> bool {
    status
        .map(|status| {
            now_unix_secs().saturating_sub(status.observed_at_unix_secs) <= stale_after_secs
        })
        .unwrap_or(false)
}

fn log_stdio(path: &Path, append: bool) -> Result<(Stdio, Stdio)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {}", parent.display()))?;
    }

    let stdout = open_log_file(path, append)?;
    let stderr = open_log_file(path, true)?;
    Ok((Stdio::from(stdout), Stdio::from(stderr)))
}

fn open_log_file(path: &Path, append: bool) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(append)
        .write(true)
        .truncate(!append)
        .open(path)
        .with_context(|| format!("failed to open log file {}", path.display()))
}

fn print_log_tail(label: &str, path: &Path, lines: usize) -> Result<()> {
    println!("==> {label}: {} <==", path.display());
    if !path.exists() {
        println!("log file not found");
        return Ok(());
    }

    for line in tail_lines(path, lines)? {
        println!("{line}");
    }
    Ok(())
}

fn tail_lines(path: &Path, lines: usize) -> Result<Vec<String>> {
    if lines == 0 {
        return Ok(Vec::new());
    }

    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut tail = Vec::with_capacity(lines);

    for line in reader.lines() {
        let line = line.with_context(|| format!("failed to read {}", path.display()))?;
        if tail.len() == lines {
            tail.remove(0);
        }
        tail.push(line);
    }

    Ok(tail)
}

fn sibling_binary(name: &str) -> Result<PathBuf> {
    let current = env::current_exe().context("failed to resolve current executable")?;
    let dir = current
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?;
    let candidate = dir.join(name);
    if candidate.exists() {
        return Ok(candidate);
    }

    bail!(
        "could not find sibling binary {} next to {}. build the workspace binaries first",
        name,
        current.display()
    );
}

fn default_agent_log_file() -> PathBuf {
    PathBuf::from("/private/tmp/tunnel-agent.log")
}

fn default_gateway_log_file() -> PathBuf {
    PathBuf::from("/private/tmp/tunnel-gateway.log")
}

fn default_supervisor_log_file() -> PathBuf {
    PathBuf::from("/private/tmp/tunnel-supervisor.log")
}

fn read_optional_json<T>(path: &Path) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    if !path.exists() {
        return Ok(None);
    }

    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Some(serde_json::from_str(&contents).with_context(
        || format!("failed to parse {}", path.display()),
    )?))
}

fn load_manifest(path: &Path) -> Result<SessionManifest> {
    read_optional_json(path)?
        .ok_or_else(|| anyhow!("session manifest not found: {}", path.display()))
}

fn save_manifest(path: &Path, manifest: &SessionManifest) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(manifest)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn terminate_pid(pid: Option<u32>) -> Result<()> {
    let Some(pid) = pid else {
        return Ok(());
    };

    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .with_context(|| format!("failed to send TERM to pid {pid}"))?;

    if !status.success() {
        eprintln!("warning: kill -TERM {pid} returned non-zero");
    }

    Ok(())
}

fn terminate_pid_except_self(pid: Option<u32>) -> Result<()> {
    if pid == Some(process::id()) {
        return Ok(());
    }
    terminate_pid(pid)
}

fn wait_for_pid_exit_except_self(pid: Option<u32>, label: &str, timeout: Duration) -> Result<()> {
    let Some(pid) = pid else {
        return Ok(());
    };
    if pid == process::id() {
        return Ok(());
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_running(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    eprintln!("warning: {label} pid {pid} did not exit within {timeout:?}");
    Ok(())
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("non-utf8 path is not supported: {}", path.display()))
}

fn mode_str(mode: SystemCommandMode) -> &'static str {
    match mode {
        SystemCommandMode::Skip => "skip",
        SystemCommandMode::Print => "print",
        SystemCommandMode::Apply => "apply",
    }
}

fn append_connect_args(command: &mut Command, args: &ConnectArgs) {
    if let Some(profile) = &args.profile {
        command.arg(profile);
    }
    if let Some(tenant) = &args.tenant {
        command.arg("--tenant").arg(tenant);
    }
    if let Some(attachment) = &args.attachment {
        command.arg("--attachment").arg(attachment);
    }

    command
        .arg("--profile-file")
        .arg(&args.profile_file)
        .arg("--agent-config")
        .arg(&args.agent_config)
        .arg("--gateway-config")
        .arg(&args.gateway_config)
        .arg("--agent-state-file")
        .arg(&args.agent_state_file)
        .arg("--agent-status-file")
        .arg(&args.agent_status_file)
        .arg("--gateway-state-file")
        .arg(&args.gateway_state_file)
        .arg("--gateway-status-file")
        .arg(&args.gateway_status_file)
        .arg("--session-file")
        .arg(&args.session_file)
        .arg("--agent-log-file")
        .arg(&args.agent_log_file)
        .arg("--gateway-log-file")
        .arg(&args.gateway_log_file)
        .arg("--egress-interface")
        .arg(&args.egress_interface)
        .arg("--route-mode")
        .arg(mode_str(args.route_mode))
        .arg("--forwarding-mode")
        .arg(mode_str(args.forwarding_mode))
        .arg("--nat-mode")
        .arg(mode_str(args.nat_mode))
        .arg("--ready-timeout-secs")
        .arg(args.ready_timeout_secs.to_string());
}
