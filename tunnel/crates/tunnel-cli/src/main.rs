#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tunnel_shared::{
    encode_key_32, now_unix_secs, AgentRuntimeState, ComponentKind, GatewayEndpoint,
    GatewayRuntimeState, HealthState, PacketPathTelemetry, RoutePolicy, RuntimeStatus,
    SocketEndpoint, TrafficClass, TransportKind, TunnelConfig, TunnelPhase, WireGuardConfig,
    WireGuardRole,
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
    Login(LoginArgs),
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
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    #[command(hide = true)]
    Soak(SoakArgs),
    #[command(hide = true)]
    RepairTest(RepairTestArgs),
    #[command(hide = true)]
    LifecycleTest(LifecycleTestArgs),
    #[command(hide = true)]
    RemoteLifecycleTest(RemoteLifecycleTestArgs),
    #[command(hide = true)]
    RemoteCheck(RemoteCheckArgs),
    #[command(hide = true)]
    RemoteSmokeTest(RemoteSmokeTestArgs),
    #[command(hide = true)]
    RemotePlan(RemotePlanArgs),
    #[command(hide = true)]
    RemoteDeploy(RemoteDeployArgs),
    #[command(hide = true)]
    GatewayRun(SideRunArgs),
    #[command(hide = true)]
    AgentRun(SideRunArgs),
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    Init(ProfileInitArgs),
    Export(ProfileExportArgs),
    Import(ProfileImportArgs),
}

#[derive(Debug, Args, Clone)]
struct LoginArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, default_value = "local-tenant")]
    tenant: String,
    #[arg(long)]
    attachment: Option<String>,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-wg.json")]
    gateway_config: PathBuf,
    #[arg(long, default_value = "127.0.0.1")]
    gateway_host: String,
    #[arg(long, default_value_t = 7000)]
    gateway_port: u16,
    #[arg(long, default_value = "1.1.1.0/24")]
    destination_cidr: String,
    #[arg(long, default_value = "10.201.0.2")]
    agent_tunnel_address: String,
    #[arg(long, default_value = "10.201.0.1")]
    gateway_tunnel_address: String,
    #[arg(long, default_value = "en0")]
    egress_interface: String,
    #[arg(long, hide = true, value_enum)]
    mode: Option<ProfileMode>,
    #[arg(long, hide = true, value_enum)]
    local_component: Option<ComponentSelection>,
    #[arg(long)]
    force: bool,
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
    #[arg(long, hide = true, default_value = "1.1.1.1")]
    warmup_target: String,
    #[arg(long, hide = true, default_value_t = 2.0)]
    warmup_probe_timeout_secs: f64,
    #[arg(long, hide = true, default_value_t = 15)]
    warmup_settle_secs: u64,
    #[arg(long, hide = true)]
    oneshot: bool,
    #[arg(
        long,
        hide = true,
        default_value = "/private/tmp/tunnel-supervisor.log"
    )]
    supervisor_log_file: PathBuf,
    #[arg(long, hide = true, value_enum, default_value_t = ProfileMode::Local)]
    mode: ProfileMode,
    #[arg(long, hide = true, value_enum)]
    local_component: Option<ComponentSelection>,
}

impl ConnectArgs {
    fn for_profile(profile: String, profile_file: PathBuf) -> Self {
        Self {
            profile: Some(profile),
            tenant: None,
            attachment: None,
            profile_file,
            agent_config: PathBuf::from("/private/tmp/tunnel-agent-wg.json"),
            gateway_config: PathBuf::from("/private/tmp/tunnel-gateway-wg.json"),
            agent_state_file: PathBuf::from("/private/tmp/tunnel-agent-state.json"),
            agent_status_file: PathBuf::from("/private/tmp/tunnel-agent-status.json"),
            gateway_state_file: PathBuf::from("/private/tmp/tunnel-gateway-state.json"),
            gateway_status_file: PathBuf::from("/private/tmp/tunnel-gateway-status.json"),
            session_file: PathBuf::from("/private/tmp/tunnel-session.json"),
            agent_log_file: PathBuf::from("/private/tmp/tunnel-agent.log"),
            gateway_log_file: PathBuf::from("/private/tmp/tunnel-gateway.log"),
            egress_interface: String::from("en0"),
            route_mode: SystemCommandMode::Apply,
            forwarding_mode: SystemCommandMode::Apply,
            nat_mode: SystemCommandMode::Apply,
            ready_timeout_secs: 12,
            warmup_target: String::from("1.1.1.1"),
            warmup_probe_timeout_secs: 2.0,
            warmup_settle_secs: 15,
            oneshot: false,
            supervisor_log_file: PathBuf::from("/private/tmp/tunnel-supervisor.log"),
            mode: ProfileMode::Local,
            local_component: None,
        }
    }
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

impl DisconnectArgs {
    fn for_profile(profile: String, profile_file: PathBuf) -> Self {
        Self {
            profile: Some(profile),
            profile_file,
            agent_config: PathBuf::from("/private/tmp/tunnel-agent-wg.json"),
            agent_state_file: PathBuf::from("/private/tmp/tunnel-agent-state.json"),
            agent_status_file: PathBuf::from("/private/tmp/tunnel-agent-status.json"),
            gateway_state_file: PathBuf::from("/private/tmp/tunnel-gateway-state.json"),
            gateway_status_file: PathBuf::from("/private/tmp/tunnel-gateway-status.json"),
            session_file: PathBuf::from("/private/tmp/tunnel-session.json"),
            route_mode: SystemCommandMode::Apply,
            forwarding_mode: SystemCommandMode::Apply,
            nat_mode: SystemCommandMode::Apply,
        }
    }
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
struct ProfileInitArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, default_value = "local-tenant")]
    tenant: String,
    #[arg(long)]
    attachment: Option<String>,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-wg.json")]
    gateway_config: PathBuf,
    #[arg(long, default_value = "en0")]
    egress_interface: String,
    #[arg(long, hide = true, value_enum, default_value_t = ProfileMode::Local)]
    mode: ProfileMode,
    #[arg(long, hide = true, value_enum)]
    local_component: Option<ComponentSelection>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args, Clone)]
struct ProfileExportArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-bundles")]
    out_dir: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args, Clone)]
struct ProfileImportArgs {
    #[arg(value_name = "BUNDLE_DIR")]
    bundle_dir: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, default_value = "/private/tmp")]
    install_dir: PathBuf,
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    force: bool,
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

#[derive(Debug, Args, Clone)]
struct LifecycleTestArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, default_value = "1.1.1.1")]
    target: String,
}

#[derive(Debug, Args, Clone)]
struct RemoteLifecycleTestArgs {
    #[arg(value_name = "PROFILE", default_value = "remote-dev")]
    profile: String,
    #[arg(
        long,
        default_value = "/private/tmp/tunnel-remote-lifecycle-profiles.json"
    )]
    profile_file: PathBuf,
    #[arg(long, default_value = "203.0.113.10")]
    gateway_host: String,
    #[arg(long, default_value_t = 7000)]
    gateway_port: u16,
}

#[derive(Debug, Args, Clone)]
struct RemoteCheckArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long)]
    peer_profile: Option<String>,
    #[arg(long)]
    peer_profile_file: Option<PathBuf>,
    #[arg(long)]
    gateway_host: Option<String>,
    #[arg(long)]
    gateway_port: Option<u16>,
    #[arg(long)]
    udp_probe: bool,
    #[arg(long, default_value_t = 2.0)]
    udp_probe_timeout_secs: f64,
}

#[derive(Debug, Args, Clone)]
struct RemoteSmokeTestArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long)]
    peer_profile: Option<String>,
    #[arg(long)]
    peer_profile_file: Option<PathBuf>,
    #[arg(long)]
    gateway_host: Option<String>,
    #[arg(long)]
    gateway_port: Option<u16>,
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, default_value = "1.1.1.1")]
    target: String,
    #[arg(long, default_value_t = 10)]
    count: u32,
    #[arg(long, default_value_t = 1.0)]
    interval_secs: f64,
    #[arg(long, default_value_t = 2.0)]
    probe_timeout_secs: f64,
    #[arg(long, default_value_t = 15)]
    stale_after_secs: u64,
    #[arg(long, default_value_t = 15)]
    post_probe_settle_secs: u64,
    #[arg(long, default_value_t = 2.0)]
    udp_probe_timeout_secs: f64,
}

#[derive(Debug, Args, Clone)]
struct RemotePlanArgs {
    #[arg(value_name = "PROFILE", default_value = "remote-prod")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
    #[arg(long, default_value = "local-tenant")]
    tenant: String,
    #[arg(long)]
    attachment: Option<String>,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-wg.json")]
    gateway_config: PathBuf,
    #[arg(long)]
    gateway_host: String,
    #[arg(long, default_value_t = 7000)]
    gateway_port: u16,
    #[arg(long, default_value = "1.1.1.0/24")]
    destination_cidr: String,
    #[arg(long, default_value = "10.201.0.2")]
    agent_tunnel_address: String,
    #[arg(long, default_value = "10.201.0.1")]
    gateway_tunnel_address: String,
    #[arg(long, default_value = "eth0")]
    egress_interface: String,
    #[arg(long, default_value = "/private/tmp/tunnel-bundles")]
    out_dir: PathBuf,
    #[arg(long, default_value = "agent-prod")]
    agent_profile: String,
    #[arg(long, default_value = "gateway-prod")]
    gateway_profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    remote_profile_file: PathBuf,
    #[arg(long, default_value = "/private/tmp")]
    remote_install_dir: PathBuf,
    #[arg(long, default_value = "/tmp/tunnel-agent-bundle")]
    agent_remote_bundle_dir: PathBuf,
    #[arg(long, default_value = "/tmp/tunnel-gateway-bundle")]
    gateway_remote_bundle_dir: PathBuf,
    #[arg(long)]
    agent_ssh_host: Option<String>,
    #[arg(long)]
    gateway_ssh_host: Option<String>,
    #[arg(long, default_value = "1.1.1.1")]
    smoke_target: String,
    #[arg(long, default_value_t = 10)]
    smoke_count: u32,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args, Clone)]
struct RemoteDeployArgs {
    #[command(flatten)]
    plan: RemotePlanArgs,
    #[arg(long, default_value = "ssh")]
    ssh_bin: String,
    #[arg(long, default_value = "scp")]
    scp_bin: String,
    #[arg(long, default_value_t = 10)]
    ssh_timeout_secs: u64,
    #[arg(long, default_value_t = 120)]
    step_timeout_secs: u64,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    require_host_preflight: bool,
    #[arg(long)]
    report_file: Option<PathBuf>,
    #[arg(long)]
    no_rollback: bool,
}

#[derive(Debug, Args, Clone)]
struct SideRunArgs {
    #[arg(value_name = "PROFILE", default_value = "local-dev")]
    profile: String,
    #[arg(long, default_value = "/private/tmp/tunnel-profiles.json")]
    profile_file: PathBuf,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum ProfileMode {
    Local,
    Remote,
}

impl Default for ProfileMode {
    fn default() -> Self {
        Self::Local
    }
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
    mode: ProfileMode,
    #[serde(default)]
    local_component: Option<ComponentSelection>,
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

#[derive(Debug, Serialize)]
struct ConnectWarmupReport {
    target: String,
    probe_rtt_ms: f64,
    agent_active: bool,
    gateway_active: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ConnectReport {
    tenant: String,
    attachment: String,
    mode: ProfileMode,
    local_component: Option<ComponentSelection>,
    remote_component: Option<ComponentSelection>,
    supervised: bool,
    supervisor_pid: Option<u32>,
    agent_pid: Option<u32>,
    gateway_pid: Option<u32>,
    agent_log_file: PathBuf,
    gateway_log_file: PathBuf,
    supervisor_log_file: PathBuf,
    ready: bool,
    warmup: Option<ConnectWarmupReport>,
    session_file: PathBuf,
    detail: String,
}

#[derive(Debug, Serialize)]
struct SideRunReport {
    component: ComponentSelection,
    tenant: String,
    attachment: String,
    pid: u32,
    config_file: PathBuf,
    state_file: PathBuf,
    status_file: PathBuf,
    log_file: PathBuf,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct DisconnectReport {
    tenant: Option<String>,
    attachment: Option<String>,
    disconnected: bool,
    supervisor_stopped: bool,
    agent_stopped: bool,
    gateway_stopped: bool,
    agent_cleaned: bool,
    gateway_cleaned: bool,
    session_removed: bool,
    agent_state_removed: bool,
    agent_status_removed: bool,
    gateway_state_removed: bool,
    gateway_status_removed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct LifecycleTestReport {
    overall: DoctorState,
    profile: String,
    login_ready: bool,
    connect_ready: bool,
    status_healthy: bool,
    disconnect_clean: bool,
    second_disconnect_clean: bool,
    warmup: ConnectWarmupReport,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct RemoteCheckReport {
    overall: DoctorState,
    profile: String,
    peer_profile: Option<String>,
    gateway_host: Option<String>,
    gateway_port: Option<u16>,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct RemoteSmokeTestReport {
    overall: DoctorState,
    profile: String,
    peer_profile: Option<String>,
    target: String,
    remote_check: RemoteCheckReport,
    gateway_udp_probe: UdpProbeReport,
    doctor: DoctorReport,
    soak: SoakReport,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Serialize)]
struct UdpProbeReport {
    host: String,
    port: u16,
    timeout_secs: f64,
    sent: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct RemotePlanReport {
    profile: String,
    profile_file: PathBuf,
    gateway_host: String,
    gateway_port: u16,
    destination_cidr: String,
    agent_bundle: PathBuf,
    gateway_bundle: PathBuf,
    agent_profile: String,
    gateway_profile: String,
    generated_configs: GeneratedConfigReport,
    readiness: ReadinessReport,
    remote_check: RemoteCheckReport,
    commands: RemotePlanCommands,
    next: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RemotePlanCommands {
    operator_remote_check: String,
    copy_agent_bundle: Option<String>,
    copy_gateway_bundle: Option<String>,
    agent_import: String,
    gateway_import: String,
    gateway_connect: String,
    agent_connect: String,
    agent_smoke_test: String,
}

#[derive(Debug, Serialize)]
struct RemoteDeployReport {
    overall: DoctorState,
    profile: String,
    agent_host: String,
    gateway_host: String,
    dry_run: bool,
    require_host_preflight: bool,
    ssh_timeout_secs: u64,
    step_timeout_secs: u64,
    rollback_on_fail: bool,
    rollback_attempted: bool,
    plan: RemotePlanReport,
    steps: Vec<RemoteDeployStep>,
}

#[derive(Debug, Serialize)]
struct RemoteDeployStep {
    name: String,
    host: Option<String>,
    command: String,
    state: DoctorState,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct RemoteLifecycleTestReport {
    overall: DoctorState,
    agent_profile: String,
    gateway_profile: String,
    agent_readiness_ready: bool,
    gateway_readiness_ready: bool,
    gateway_doctor_non_failing: bool,
    gateway_disconnect_clean: bool,
    remote_agent_state_preserved: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct ProfileExportReport {
    profile: String,
    out_dir: PathBuf,
    agent_bundle: PathBuf,
    gateway_bundle: PathBuf,
    agent_config: PathBuf,
    gateway_config: PathBuf,
}

#[derive(Debug, Serialize)]
struct ProfileImportReport {
    profile: String,
    side: ComponentSelection,
    profile_file: PathBuf,
    installed_config: PathBuf,
    ready: bool,
    readiness: ReadinessReport,
    next: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoteProfileBundleManifest {
    version: u32,
    profile: String,
    side: ComponentSelection,
    config_file: PathBuf,
    profile_file: PathBuf,
    run_hint: String,
    import_hint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProfileConfig {
    default: Option<String>,
    profiles: Vec<TunnelProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    mode: ProfileMode,
    #[serde(default)]
    local_component: Option<ComponentSelection>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    state: DoctorState,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ReadinessReport {
    ready: bool,
    profile: Option<String>,
    checks: Vec<ReadinessCheck>,
}

#[derive(Debug, Serialize)]
struct ReadinessCheck {
    name: String,
    state: DoctorState,
    detail: String,
}

#[derive(Debug, Serialize)]
struct GeneratedConfigReport {
    agent_config: ConfigBootstrapAction,
    gateway_config: ConfigBootstrapAction,
}

#[derive(Debug, Serialize)]
struct ConfigBootstrapAction {
    path: PathBuf,
    action: ConfigBootstrapActionKind,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigBootstrapActionKind {
    Created,
    Overwritten,
    Reused,
    PreservedInvalid,
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
        CommandKind::Login(args) => run_login(args)?,
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
        CommandKind::Profile {
            command: ProfileCommand::Init(args),
        } => run_profile_init(args)?,
        CommandKind::Profile {
            command: ProfileCommand::Export(args),
        } => run_profile_export(args)?,
        CommandKind::Profile {
            command: ProfileCommand::Import(args),
        } => run_profile_import(args)?,
        CommandKind::Soak(args) => run_soak(args)?,
        CommandKind::RepairTest(args) => run_repair_test(args)?,
        CommandKind::LifecycleTest(args) => run_lifecycle_test(args)?,
        CommandKind::RemoteLifecycleTest(args) => run_remote_lifecycle_test(args)?,
        CommandKind::RemoteCheck(args) => run_remote_check(args)?,
        CommandKind::RemoteSmokeTest(args) => run_remote_smoke_test(args)?,
        CommandKind::RemotePlan(args) => run_remote_plan(args)?,
        CommandKind::RemoteDeploy(args) => run_remote_deploy(args)?,
        CommandKind::GatewayRun(args) => run_side(args, ComponentSelection::Gateway)?,
        CommandKind::AgentRun(args) => run_side(args, ComponentSelection::Agent)?,
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
    args.mode = profile.mode;
    args.local_component = profile.local_component;
}

fn required_connect_value<'a>(value: Option<&'a String>, label: &str) -> Result<&'a str> {
    value
        .map(String::as_str)
        .ok_or_else(|| anyhow!("resolved connect args missing {label}"))
}

fn run_login(args: LoginArgs) -> Result<()> {
    let next = format!("tunnel-cli connect {}", args.profile);
    let generated_configs = ensure_local_configs_for_login(&args)?;
    let mode = resolved_login_mode(&args);
    let local_component = resolved_login_local_component(&args, mode)?;
    let profile_args = ProfileInitArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        tenant: args.tenant.clone(),
        attachment: args.attachment.clone(),
        agent_config: args.agent_config.clone(),
        gateway_config: args.gateway_config.clone(),
        egress_interface: args.egress_interface.clone(),
        mode,
        local_component,
        force: true,
    };
    write_profile(profile_args)?;

    let connect_args = resolve_connect_args(ConnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file.clone(),
    ))?;
    let readiness = build_connect_readiness(&connect_args);

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "logged_in": true,
            "mode": mode,
            "local_component": local_component,
            "remote_component": remote_component_for(mode, local_component),
            "profile": args.profile,
            "profile_file": args.profile_file,
            "gateway_host": args.gateway_host,
            "gateway_port": args.gateway_port,
            "generated_configs": generated_configs,
            "ready": readiness.ready,
            "readiness": readiness,
            "next": next,
        }))?
    );
    Ok(())
}

fn run_remote_plan(args: RemotePlanArgs) -> Result<()> {
    let report = build_remote_plan_report(args)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_remote_deploy(args: RemoteDeployArgs) -> Result<()> {
    let report_file = args.report_file.clone();
    let report = build_remote_deploy_report(args)?;
    let failed = report.overall == DoctorState::Fail;
    let report_json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = report_file {
        write_report_file(&path, &report_json)?;
    }
    println!("{report_json}");
    if failed {
        bail!("remote deploy failed");
    }
    Ok(())
}

fn write_report_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, format!("{contents}\n"))
        .with_context(|| format!("failed to write {}", path.display()))
}

fn build_remote_deploy_report(args: RemoteDeployArgs) -> Result<RemoteDeployReport> {
    let agent_host = args
        .plan
        .agent_ssh_host
        .clone()
        .ok_or_else(|| anyhow!("remote-deploy requires --agent-ssh-host"))?;
    let gateway_host = args
        .plan
        .gateway_ssh_host
        .clone()
        .ok_or_else(|| anyhow!("remote-deploy requires --gateway-ssh-host"))?;

    validate_remote_bundle_dir(
        &args.plan.agent_remote_bundle_dir,
        "agent_remote_bundle_dir",
    )?;
    validate_remote_bundle_dir(
        &args.plan.gateway_remote_bundle_dir,
        "gateway_remote_bundle_dir",
    )?;
    if args.ssh_timeout_secs == 0 {
        bail!("--ssh-timeout-secs must be greater than zero");
    }
    if args.step_timeout_secs == 0 {
        bail!("--step-timeout-secs must be greater than zero");
    }

    let plan = build_remote_plan_report(args.plan.clone())?;
    let mut steps = Vec::new();
    let rollback_on_fail = !args.no_rollback;
    let dry_run = args.dry_run;
    let require_host_preflight = args.require_host_preflight;
    let step_timeout = Duration::from_secs(args.step_timeout_secs);
    let mut gateway_started = false;
    let mut agent_started = false;
    steps.push(RemoteDeployStep {
        name: String::from("operator_remote_check"),
        host: None,
        command: plan.commands.operator_remote_check.clone(),
        state: plan.remote_check.overall,
        exit_code: Some(0),
        stdout: serde_json::to_string_pretty(&plan.remote_check)?,
        stderr: String::new(),
        detail: String::from("local remote profile check passed"),
    });

    if require_host_preflight && steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "gateway_host_preflight",
            Some(gateway_host.clone()),
            remote_gateway_host_preflight_command(&args)?,
            dry_run,
            step_timeout,
        ));
    }
    if require_host_preflight && steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "agent_host_preflight",
            Some(agent_host.clone()),
            remote_agent_host_preflight_command(&args)?,
            dry_run,
            step_timeout,
        ));
    }

    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "gateway_prepare_bundle_dir",
            Some(gateway_host.clone()),
            remote_prepare_bundle_command(
                &args.ssh_bin,
                &gateway_host,
                &args.plan.gateway_remote_bundle_dir,
                args.ssh_timeout_secs,
            )?,
            dry_run,
            step_timeout,
        ));
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "copy_gateway_bundle",
            Some(gateway_host.clone()),
            deploy_scp_command(
                &args.scp_bin,
                &plan.gateway_bundle,
                &gateway_host,
                &args.plan.gateway_remote_bundle_dir,
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        ));
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "agent_prepare_bundle_dir",
            Some(agent_host.clone()),
            remote_prepare_bundle_command(
                &args.ssh_bin,
                &agent_host,
                &args.plan.agent_remote_bundle_dir,
                args.ssh_timeout_secs,
            )?,
            dry_run,
            step_timeout,
        ));
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "copy_agent_bundle",
            Some(agent_host.clone()),
            deploy_scp_command(
                &args.scp_bin,
                &plan.agent_bundle,
                &agent_host,
                &args.plan.agent_remote_bundle_dir,
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        ));
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "gateway_import",
            Some(gateway_host.clone()),
            deploy_ssh_command(
                &args.ssh_bin,
                &gateway_host,
                &plan.commands.gateway_import,
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        ));
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        let step = build_remote_deploy_step(
            "gateway_connect",
            Some(gateway_host.clone()),
            deploy_ssh_command(
                &args.ssh_bin,
                &gateway_host,
                &remote_gateway_connect_command(&args.plan),
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        );
        gateway_started = !dry_run && step.state == DoctorState::Pass;
        steps.push(step);
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "agent_import",
            Some(agent_host.clone()),
            deploy_ssh_command(
                &args.ssh_bin,
                &agent_host,
                &plan.commands.agent_import,
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        ));
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        let step = build_remote_deploy_step(
            "agent_connect",
            Some(agent_host.clone()),
            deploy_ssh_command(
                &args.ssh_bin,
                &agent_host,
                &remote_agent_connect_command(&args.plan),
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        );
        agent_started = !dry_run && step.state == DoctorState::Pass;
        steps.push(step);
    }
    if steps.iter().all(|step| step.state != DoctorState::Fail) {
        steps.push(build_remote_deploy_step(
            "agent_smoke_test",
            Some(agent_host.clone()),
            deploy_ssh_command(
                &args.ssh_bin,
                &agent_host,
                &remote_agent_smoke_test_command(&args.plan),
                args.ssh_timeout_secs,
            ),
            dry_run,
            step_timeout,
        ));
    }

    let failed_before_rollback = steps.iter().any(|step| step.state == DoctorState::Fail);
    let rollback_attempted =
        failed_before_rollback && rollback_on_fail && (agent_started || gateway_started);
    if rollback_attempted {
        if agent_started {
            steps.push(build_remote_deploy_step(
                "rollback_agent_disconnect",
                Some(agent_host.clone()),
                deploy_ssh_command(
                    &args.ssh_bin,
                    &agent_host,
                    &remote_agent_disconnect_command(&args.plan),
                    args.ssh_timeout_secs,
                ),
                dry_run,
                step_timeout,
            ));
        }
        if gateway_started {
            steps.push(build_remote_deploy_step(
                "rollback_gateway_disconnect",
                Some(gateway_host.clone()),
                deploy_ssh_command(
                    &args.ssh_bin,
                    &gateway_host,
                    &remote_gateway_disconnect_command(&args.plan),
                    args.ssh_timeout_secs,
                ),
                dry_run,
                step_timeout,
            ));
        }
    }

    let overall = if steps.iter().any(|step| step.state == DoctorState::Fail) {
        DoctorState::Fail
    } else if steps.iter().any(|step| step.state == DoctorState::Warn) {
        DoctorState::Warn
    } else {
        DoctorState::Pass
    };

    Ok(RemoteDeployReport {
        overall,
        profile: plan.profile.clone(),
        agent_host,
        gateway_host,
        dry_run,
        require_host_preflight,
        ssh_timeout_secs: args.ssh_timeout_secs,
        step_timeout_secs: args.step_timeout_secs,
        rollback_on_fail,
        rollback_attempted,
        plan,
        steps,
    })
}

fn build_remote_plan_report(args: RemotePlanArgs) -> Result<RemotePlanReport> {
    let login_args = LoginArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        tenant: args.tenant.clone(),
        attachment: args.attachment.clone(),
        agent_config: args.agent_config.clone(),
        gateway_config: args.gateway_config.clone(),
        gateway_host: args.gateway_host.clone(),
        gateway_port: args.gateway_port,
        destination_cidr: args.destination_cidr.clone(),
        agent_tunnel_address: args.agent_tunnel_address.clone(),
        gateway_tunnel_address: args.gateway_tunnel_address.clone(),
        egress_interface: args.egress_interface.clone(),
        mode: Some(ProfileMode::Remote),
        local_component: Some(ComponentSelection::Agent),
        force: args.force,
    };
    let generated_configs = ensure_local_configs_for_login(&login_args)?;
    write_profile(ProfileInitArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        tenant: args.tenant.clone(),
        attachment: args.attachment.clone(),
        agent_config: args.agent_config.clone(),
        gateway_config: args.gateway_config.clone(),
        egress_interface: args.egress_interface.clone(),
        mode: ProfileMode::Remote,
        local_component: Some(ComponentSelection::Agent),
        force: args.force,
    })?;

    let connect_args = resolve_connect_args(ConnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file.clone(),
    ))?;
    let readiness = build_connect_readiness(&connect_args);
    bail_if_not_ready(&readiness)?;

    prepare_bundle_output_dir(&args.out_dir, args.force)?;
    let agent_bundle = args.out_dir.join("agent");
    let gateway_bundle = args.out_dir.join("gateway");
    export_side_bundle(&connect_args, ComponentSelection::Agent, &agent_bundle)?;
    export_side_bundle(&connect_args, ComponentSelection::Gateway, &gateway_bundle)?;

    let remote_check = build_remote_check_report(RemoteCheckArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        peer_profile: None,
        peer_profile_file: None,
        gateway_host: Some(args.gateway_host.clone()),
        gateway_port: Some(args.gateway_port),
        udp_probe: false,
        udp_probe_timeout_secs: 2.0,
    })?;
    if remote_check.overall == DoctorState::Fail {
        bail!("remote plan config check failed");
    }

    let commands = remote_plan_commands(&args, &agent_bundle, &gateway_bundle);
    let next = remote_plan_next_steps(&commands);
    let report = RemotePlanReport {
        profile: args.profile,
        profile_file: args.profile_file,
        gateway_host: args.gateway_host,
        gateway_port: args.gateway_port,
        destination_cidr: args.destination_cidr,
        agent_bundle,
        gateway_bundle,
        agent_profile: args.agent_profile,
        gateway_profile: args.gateway_profile,
        generated_configs,
        readiness,
        remote_check,
        commands,
        next,
    };
    Ok(report)
}

fn prepare_bundle_output_dir(out_dir: &Path, force: bool) -> Result<()> {
    if out_dir.exists() && !force {
        bail!(
            "bundle output directory already exists: {}. rerun with --force to overwrite",
            out_dir.display()
        );
    }
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)
            .with_context(|| format!("failed to replace {}", out_dir.display()))?;
    }
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    Ok(())
}

fn remote_plan_commands(
    args: &RemotePlanArgs,
    agent_bundle: &Path,
    gateway_bundle: &Path,
) -> RemotePlanCommands {
    let operator_remote_check = render_command(vec![
        String::from("tunnel-cli"),
        String::from("remote-check"),
        args.profile.clone(),
        String::from("--profile-file"),
        path_display(&args.profile_file),
        String::from("--gateway-host"),
        args.gateway_host.clone(),
        String::from("--gateway-port"),
        args.gateway_port.to_string(),
    ]);
    let copy_agent_bundle = args.agent_ssh_host.as_ref().map(|host| {
        render_command(vec![
            String::from("scp"),
            String::from("-r"),
            path_display(agent_bundle),
            format!("{host}:{}", path_display(&args.agent_remote_bundle_dir)),
        ])
    });
    let copy_gateway_bundle = args.gateway_ssh_host.as_ref().map(|host| {
        render_command(vec![
            String::from("scp"),
            String::from("-r"),
            path_display(gateway_bundle),
            format!("{host}:{}", path_display(&args.gateway_remote_bundle_dir)),
        ])
    });
    let agent_import = render_command(vec![
        String::from("tunnel-cli"),
        String::from("profile"),
        String::from("import"),
        path_display(&args.agent_remote_bundle_dir),
        String::from("--profile"),
        args.agent_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
        String::from("--install-dir"),
        path_display(&args.remote_install_dir),
        String::from("--force"),
    ]);
    let gateway_import = render_command(vec![
        String::from("tunnel-cli"),
        String::from("profile"),
        String::from("import"),
        path_display(&args.gateway_remote_bundle_dir),
        String::from("--profile"),
        args.gateway_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
        String::from("--install-dir"),
        path_display(&args.remote_install_dir),
        String::from("--force"),
    ]);
    let gateway_connect = render_command(vec![
        String::from("sudo"),
        String::from("tunnel-cli"),
        String::from("connect"),
        args.gateway_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
    ]);
    let agent_connect = render_command(vec![
        String::from("sudo"),
        String::from("tunnel-cli"),
        String::from("connect"),
        args.agent_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
    ]);
    let agent_smoke_test = render_command(vec![
        String::from("sudo"),
        String::from("tunnel-cli"),
        String::from("remote-smoke-test"),
        args.agent_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
        String::from("--gateway-host"),
        args.gateway_host.clone(),
        String::from("--gateway-port"),
        args.gateway_port.to_string(),
        String::from("--target"),
        args.smoke_target.clone(),
        String::from("--count"),
        args.smoke_count.to_string(),
    ]);

    RemotePlanCommands {
        operator_remote_check,
        copy_agent_bundle,
        copy_gateway_bundle,
        agent_import,
        gateway_import,
        gateway_connect,
        agent_connect,
        agent_smoke_test,
    }
}

fn remote_plan_next_steps(commands: &RemotePlanCommands) -> Vec<String> {
    let mut steps = Vec::new();
    steps.push(commands.operator_remote_check.clone());
    steps.push(
        commands
            .copy_gateway_bundle
            .clone()
            .unwrap_or_else(|| String::from("copy gateway_bundle to gateway host manually")),
    );
    steps.push(
        commands
            .copy_agent_bundle
            .clone()
            .unwrap_or_else(|| String::from("copy agent_bundle to agent host manually")),
    );
    steps.push(format!("gateway host: {}", commands.gateway_import));
    steps.push(format!("gateway host: {}", commands.gateway_connect));
    steps.push(format!("agent host: {}", commands.agent_import));
    steps.push(format!("agent host: {}", commands.agent_connect));
    steps.push(format!("agent host: {}", commands.agent_smoke_test));
    steps
}

fn validate_remote_bundle_dir(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "{label} must be an absolute remote path: {}",
            path.display()
        );
    }
    if path.parent().is_none() || path.file_name().is_none() {
        bail!("{label} must point to a concrete bundle directory");
    }
    let value = path_display(path);
    if value == "/" || value == "/tmp" || value == "/private/tmp" {
        bail!("{label} is too broad for deploy cleanup: {value}");
    }
    Ok(())
}

fn remote_prepare_bundle_command(
    ssh_bin: &str,
    host: &str,
    bundle_dir: &Path,
    ssh_timeout_secs: u64,
) -> Result<Vec<String>> {
    let parent = bundle_dir
        .parent()
        .ok_or_else(|| anyhow!("remote bundle dir has no parent: {}", bundle_dir.display()))?;
    let remote_command = format!(
        "rm -rf {} && mkdir -p {}",
        shell_quote(&path_display(bundle_dir)),
        shell_quote(&path_display(parent))
    );
    Ok(deploy_ssh_command(
        ssh_bin,
        host,
        &remote_command,
        ssh_timeout_secs,
    ))
}

fn deploy_scp_command(
    scp_bin: &str,
    local_dir: &Path,
    host: &str,
    remote_dir: &Path,
    ssh_timeout_secs: u64,
) -> Vec<String> {
    vec![
        scp_bin.to_owned(),
        String::from("-o"),
        format!("ConnectTimeout={ssh_timeout_secs}"),
        String::from("-o"),
        String::from("BatchMode=yes"),
        String::from("-r"),
        path_display(local_dir),
        format!("{host}:{}", path_display(remote_dir)),
    ]
}

fn deploy_ssh_command(
    ssh_bin: &str,
    host: &str,
    remote_command: &str,
    ssh_timeout_secs: u64,
) -> Vec<String> {
    vec![
        ssh_bin.to_owned(),
        String::from("-o"),
        format!("ConnectTimeout={ssh_timeout_secs}"),
        String::from("-o"),
        String::from("BatchMode=yes"),
        host.to_owned(),
        remote_command.to_owned(),
    ]
}

fn remote_gateway_host_preflight_command(args: &RemoteDeployArgs) -> Result<Vec<String>> {
    let host = args
        .plan
        .gateway_ssh_host
        .as_deref()
        .ok_or_else(|| anyhow!("remote-deploy requires --gateway-ssh-host"))?;
    let command = format!(
        "sh -lc {}",
        shell_quote(&format!(
            "command -v tunnel-cli >/dev/null && sudo -n true && test -c /dev/net/tun && command -v ip >/dev/null && command -v iptables >/dev/null && {}",
            gateway_udp_port_available_script(args.plan.gateway_port)
        ))
    );
    Ok(deploy_ssh_command(
        &args.ssh_bin,
        host,
        &command,
        args.ssh_timeout_secs,
    ))
}

fn remote_agent_host_preflight_command(args: &RemoteDeployArgs) -> Result<Vec<String>> {
    let host = args
        .plan
        .agent_ssh_host
        .as_deref()
        .ok_or_else(|| anyhow!("remote-deploy requires --agent-ssh-host"))?;
    let command = format!(
        "sh -lc {}",
        shell_quote(&format!(
            "command -v tunnel-cli >/dev/null && sudo -n true && test -c /dev/net/tun && command -v ip >/dev/null && ip route get {} >/dev/null",
            shell_quote(&args.plan.gateway_host)
        ))
    );
    Ok(deploy_ssh_command(
        &args.ssh_bin,
        host,
        &command,
        args.ssh_timeout_secs,
    ))
}

fn gateway_udp_port_available_script(port: u16) -> String {
    format!(
        "if command -v ss >/dev/null 2>&1; then ! ss -H -lun 'sport = :{port}' | grep -q .; elif command -v netstat >/dev/null 2>&1; then ! netstat -lun | awk '{{print $4}}' | grep -Eq '(:|\\.){port}$'; else true; fi"
    )
}

fn remote_gateway_connect_command(args: &RemotePlanArgs) -> String {
    render_command(vec![
        String::from("sudo"),
        String::from("-n"),
        String::from("tunnel-cli"),
        String::from("connect"),
        args.gateway_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
    ])
}

fn remote_agent_connect_command(args: &RemotePlanArgs) -> String {
    render_command(vec![
        String::from("sudo"),
        String::from("-n"),
        String::from("tunnel-cli"),
        String::from("connect"),
        args.agent_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
    ])
}

fn remote_gateway_disconnect_command(args: &RemotePlanArgs) -> String {
    render_command(vec![
        String::from("sudo"),
        String::from("-n"),
        String::from("tunnel-cli"),
        String::from("disconnect"),
        args.gateway_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
    ])
}

fn remote_agent_disconnect_command(args: &RemotePlanArgs) -> String {
    render_command(vec![
        String::from("sudo"),
        String::from("-n"),
        String::from("tunnel-cli"),
        String::from("disconnect"),
        args.agent_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
    ])
}

fn remote_agent_smoke_test_command(args: &RemotePlanArgs) -> String {
    render_command(vec![
        String::from("sudo"),
        String::from("-n"),
        String::from("tunnel-cli"),
        String::from("remote-smoke-test"),
        args.agent_profile.clone(),
        String::from("--profile-file"),
        path_display(&args.remote_profile_file),
        String::from("--gateway-host"),
        args.gateway_host.clone(),
        String::from("--gateway-port"),
        args.gateway_port.to_string(),
        String::from("--target"),
        args.smoke_target.clone(),
        String::from("--count"),
        args.smoke_count.to_string(),
    ])
}

fn run_command_step(
    name: &str,
    host: Option<String>,
    command: Vec<String>,
    timeout: Duration,
) -> RemoteDeployStep {
    let command_text = render_command(command.clone());
    if command.is_empty() {
        return RemoteDeployStep {
            name: name.to_owned(),
            host,
            command: command_text,
            state: DoctorState::Fail,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            detail: String::from("empty command"),
        };
    }

    let mut child = match Command::new(&command[0])
        .args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return RemoteDeployStep {
                name: name.to_owned(),
                host,
                command: command_text,
                state: DoctorState::Fail,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                detail: format!("failed to execute command: {error}"),
            };
        }
    };

    let started_at = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return match child.wait_with_output() {
                    Ok(output) => remote_deploy_step_from_output(name, host, command_text, output),
                    Err(error) => RemoteDeployStep {
                        name: name.to_owned(),
                        host,
                        command: command_text,
                        state: DoctorState::Fail,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        detail: format!("failed to collect command output: {error}"),
                    },
                };
            }
            Ok(None) if started_at.elapsed() >= timeout => {
                let kill_result = child.kill();
                return match child.wait_with_output() {
                    Ok(output) => remote_deploy_timeout_step(
                        name,
                        host,
                        command_text,
                        timeout,
                        output,
                        kill_result.err(),
                    ),
                    Err(error) => RemoteDeployStep {
                        name: name.to_owned(),
                        host,
                        command: command_text,
                        state: DoctorState::Fail,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        detail: format!(
                            "command timed out after {:.3}s and output collection failed: {error}",
                            timeout.as_secs_f64()
                        ),
                    },
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                return RemoteDeployStep {
                    name: name.to_owned(),
                    host,
                    command: command_text,
                    state: DoctorState::Fail,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    detail: format!("failed while waiting for command: {error}"),
                };
            }
        }
    }
}

fn build_remote_deploy_step(
    name: &str,
    host: Option<String>,
    command: Vec<String>,
    dry_run: bool,
    timeout: Duration,
) -> RemoteDeployStep {
    if dry_run {
        return planned_remote_deploy_step(name, host, command);
    }
    run_command_step(name, host, command, timeout)
}

fn planned_remote_deploy_step(
    name: &str,
    host: Option<String>,
    command: Vec<String>,
) -> RemoteDeployStep {
    RemoteDeployStep {
        name: name.to_owned(),
        host,
        command: render_command(command),
        state: DoctorState::Warn,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        detail: String::from("dry-run planned; command was not executed"),
    }
}

fn remote_deploy_step_from_output(
    name: &str,
    host: Option<String>,
    command: String,
    output: Output,
) -> RemoteDeployStep {
    let state = if output.status.success() {
        DoctorState::Pass
    } else {
        DoctorState::Fail
    };
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let detail = match (state, exit_code) {
        (DoctorState::Pass, Some(code)) => format!("command exited {code}"),
        (DoctorState::Pass, None) => String::from("command exited successfully"),
        (DoctorState::Fail, Some(code)) => format!("command failed with exit code {code}"),
        (DoctorState::Fail, None) => String::from("command failed without an exit code"),
        (DoctorState::Warn, _) => String::from("command completed with warning"),
    };

    RemoteDeployStep {
        name: name.to_owned(),
        host,
        command,
        state,
        exit_code,
        stdout,
        stderr,
        detail,
    }
}

fn remote_deploy_timeout_step(
    name: &str,
    host: Option<String>,
    command: String,
    timeout: Duration,
    output: Output,
    kill_error: Option<std::io::Error>,
) -> RemoteDeployStep {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let detail = if let Some(error) = kill_error {
        format!(
            "command timed out after {:.3}s; kill returned error: {error}",
            timeout.as_secs_f64()
        )
    } else {
        format!(
            "command timed out after {:.3}s; process was killed",
            timeout.as_secs_f64()
        )
    };

    RemoteDeployStep {
        name: name.to_owned(),
        host,
        command,
        state: DoctorState::Fail,
        exit_code: None,
        stdout,
        stderr,
        detail,
    }
}

fn path_display(path: &Path) -> String {
    path.display().to_string()
}

fn render_command(parts: Vec<String>) -> String {
    parts
        .iter()
        .map(|part| shell_quote(part.as_str()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:@".contains(&byte))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn resolved_login_mode(args: &LoginArgs) -> ProfileMode {
    args.mode.unwrap_or_else(|| {
        if args.gateway_host == "127.0.0.1" {
            ProfileMode::Local
        } else {
            ProfileMode::Remote
        }
    })
}

fn resolved_login_local_component(
    args: &LoginArgs,
    mode: ProfileMode,
) -> Result<Option<ComponentSelection>> {
    match mode {
        ProfileMode::Local => Ok(args.local_component),
        ProfileMode::Remote => Ok(Some(
            args.local_component.unwrap_or(ComponentSelection::Agent),
        )),
    }
}

fn run_profile_init(args: ProfileInitArgs) -> Result<()> {
    write_profile(args.clone())?;
    let profile = args.profile.clone();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "profile": profile,
            "profile_file": args.profile_file,
            "default": args.profile,
            "created": true,
        }))?
    );
    Ok(())
}

fn run_profile_export(args: ProfileExportArgs) -> Result<()> {
    let connect_args = resolve_connect_args(ConnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file,
    ))?;
    validate_config_file("agent_config", &connect_args.agent_config)?;
    validate_config_file("gateway_config", &connect_args.gateway_config)?;

    if args.out_dir.exists() && !args.force {
        bail!(
            "bundle output directory already exists: {}. rerun with --force to overwrite",
            args.out_dir.display()
        );
    }
    if args.out_dir.exists() {
        fs::remove_dir_all(&args.out_dir)
            .with_context(|| format!("failed to replace {}", args.out_dir.display()))?;
    }

    let agent_bundle = args.out_dir.join("agent");
    let gateway_bundle = args.out_dir.join("gateway");
    export_side_bundle(&connect_args, ComponentSelection::Agent, &agent_bundle)?;
    export_side_bundle(&connect_args, ComponentSelection::Gateway, &gateway_bundle)?;

    let report = ProfileExportReport {
        profile: args.profile,
        out_dir: args.out_dir,
        agent_config: agent_bundle.join("tunnel-agent-wg.json"),
        gateway_config: gateway_bundle.join("tunnel-gateway-wg.json"),
        agent_bundle,
        gateway_bundle,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_profile_import(args: ProfileImportArgs) -> Result<()> {
    let manifest_path = args.bundle_dir.join("tunnel-bundle.json");
    let manifest: RemoteProfileBundleManifest = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
    if manifest.version != 1 {
        bail!("unsupported bundle version {}", manifest.version);
    }

    let bundled_profiles_path = args.bundle_dir.join(&manifest.profile_file);
    let bundled_profiles = load_profile_config(&bundled_profiles_path)?;
    let bundled_profile = bundled_profiles
        .profiles
        .iter()
        .find(|profile| profile.name == manifest.profile)
        .ok_or_else(|| {
            anyhow!(
                "profile {:?} not found in {}",
                manifest.profile,
                bundled_profiles_path.display()
            )
        })?;
    let source_config = args.bundle_dir.join(&manifest.config_file);
    let installed_config = args.install_dir.join(match manifest.side {
        ComponentSelection::Agent => "tunnel-agent-wg.json",
        ComponentSelection::Gateway => "tunnel-gateway-wg.json",
    });
    install_bundle_config(&source_config, &installed_config, args.force)?;

    let profile_name = args.profile.unwrap_or(manifest.profile);
    let imported_profile = imported_side_profile(
        &profile_name,
        bundled_profile,
        manifest.side,
        &installed_config,
    );
    write_profile_entry(&args.profile_file, imported_profile, args.force)?;

    let connect_args = resolve_connect_args(ConnectArgs::for_profile(
        profile_name.clone(),
        args.profile_file.clone(),
    ))?;
    let readiness = build_connect_readiness(&connect_args);
    let report = ProfileImportReport {
        profile: profile_name.clone(),
        side: manifest.side,
        profile_file: args.profile_file,
        installed_config,
        ready: readiness.ready,
        readiness,
        next: format!("tunnel-cli connect {profile_name}"),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn ensure_local_configs_for_login(args: &LoginArgs) -> Result<GeneratedConfigReport> {
    let agent_valid = validate_config_file("agent_config", &args.agent_config);
    let gateway_valid = validate_config_file("gateway_config", &args.gateway_config);
    let should_generate =
        args.force || !args.agent_config.exists() || !args.gateway_config.exists();

    if should_generate {
        let (agent_config, gateway_config) = build_local_wireguard_config_pair(args);
        agent_config
            .validate()
            .context("generated agent config is invalid")?;
        gateway_config
            .validate()
            .context("generated gateway config is invalid")?;

        let agent_action = write_generated_config(
            "agent_config",
            &args.agent_config,
            &agent_config,
            args.force,
            agent_valid.is_ok(),
        )?;
        let gateway_action = write_generated_config(
            "gateway_config",
            &args.gateway_config,
            &gateway_config,
            args.force,
            gateway_valid.is_ok(),
        )?;

        return Ok(GeneratedConfigReport {
            agent_config: agent_action,
            gateway_config: gateway_action,
        });
    }

    Ok(GeneratedConfigReport {
        agent_config: existing_config_action("agent_config", &args.agent_config, agent_valid),
        gateway_config: existing_config_action(
            "gateway_config",
            &args.gateway_config,
            gateway_valid,
        ),
    })
}

fn write_generated_config(
    label: &str,
    path: &Path,
    config: &TunnelConfig,
    force: bool,
    existing_valid: bool,
) -> Result<ConfigBootstrapAction> {
    let existed = path.exists();
    if existed && existing_valid && !force {
        return Ok(ConfigBootstrapAction {
            path: path.to_path_buf(),
            action: ConfigBootstrapActionKind::Reused,
            detail: format!("existing valid {label} reused"),
        });
    }
    if existed && !force {
        return Ok(ConfigBootstrapAction {
            path: path.to_path_buf(),
            action: ConfigBootstrapActionKind::PreservedInvalid,
            detail: format!(
                "existing invalid {label} preserved; rerun login with --force to replace it"
            ),
        });
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_string_pretty(config)?)
        .with_context(|| format!("failed to write generated {label} {}", path.display()))?;

    Ok(ConfigBootstrapAction {
        path: path.to_path_buf(),
        action: if existed {
            ConfigBootstrapActionKind::Overwritten
        } else {
            ConfigBootstrapActionKind::Created
        },
        detail: if existed {
            format!("existing {label} overwritten")
        } else {
            format!("missing {label} generated")
        },
    })
}

fn existing_config_action(
    label: &str,
    path: &Path,
    validation: Result<()>,
) -> ConfigBootstrapAction {
    match validation {
        Ok(()) => ConfigBootstrapAction {
            path: path.to_path_buf(),
            action: ConfigBootstrapActionKind::Reused,
            detail: format!("existing valid {label} reused"),
        },
        Err(error) => ConfigBootstrapAction {
            path: path.to_path_buf(),
            action: ConfigBootstrapActionKind::PreservedInvalid,
            detail: format!("{error}; rerun login with --force to replace it"),
        },
    }
}

fn build_local_wireguard_config_pair(args: &LoginArgs) -> (TunnelConfig, TunnelConfig) {
    let tunnel_id = String::from("local-tunnel");
    let gateway_host = args.gateway_host.clone();
    let gateway_port = args.gateway_port;
    let route_policy = RoutePolicy {
        traffic_class: TrafficClass::BulkExport,
        destination_cidrs: vec![args.destination_cidr.clone()],
        routing_mark: 100,
    };
    let (agent_private, agent_public) = generate_wireguard_keypair();
    let (gateway_private, gateway_public) = generate_wireguard_keypair();

    let agent_config = TunnelConfig {
        tenant_id: args.tenant.clone(),
        tunnel_id: tunnel_id.clone(),
        gateway: GatewayEndpoint {
            host: gateway_host.clone(),
            port: gateway_port,
        },
        route_policy: route_policy.clone(),
        heartbeat_interval_secs: 5,
        max_chunk_bytes: 4096,
        wireguard: Some(WireGuardConfig {
            local_bind_host: String::from("0.0.0.0"),
            local_bind_port: 0,
            peer_endpoint: Some(SocketEndpoint {
                host: gateway_host.clone(),
                port: gateway_port,
            }),
            local_tunnel_address: args.agent_tunnel_address.clone(),
            peer_tunnel_address: args.gateway_tunnel_address.clone(),
            private_key_base64: encode_key_32(&agent_private),
            peer_public_key_base64: encode_key_32(&gateway_public),
            preshared_key_base64: None,
            persistent_keepalive_secs: Some(25),
            role: WireGuardRole::Agent,
        }),
    };

    let gateway_config = TunnelConfig {
        tenant_id: args.tenant.clone(),
        tunnel_id,
        gateway: GatewayEndpoint {
            host: gateway_host,
            port: gateway_port,
        },
        route_policy,
        heartbeat_interval_secs: 5,
        max_chunk_bytes: 4096,
        wireguard: Some(WireGuardConfig {
            local_bind_host: String::from("0.0.0.0"),
            local_bind_port: gateway_port,
            peer_endpoint: None,
            local_tunnel_address: args.gateway_tunnel_address.clone(),
            peer_tunnel_address: args.agent_tunnel_address.clone(),
            private_key_base64: encode_key_32(&gateway_private),
            peer_public_key_base64: encode_key_32(&agent_public),
            preshared_key_base64: None,
            persistent_keepalive_secs: None,
            role: WireGuardRole::Gateway,
        }),
    };

    (agent_config, gateway_config)
}

fn generate_wireguard_keypair() -> ([u8; 32], [u8; 32]) {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

fn build_connect_readiness(args: &ConnectArgs) -> ReadinessReport {
    let mut checks = Vec::new();

    push_required_string_check(
        &mut checks,
        "tenant",
        args.tenant.as_deref(),
        "tenant is set",
        "tenant is missing",
    );
    push_required_string_check(
        &mut checks,
        "attachment",
        args.attachment.as_deref(),
        "attachment is set",
        "attachment is missing",
    );
    checks.push(ReadinessCheck {
        name: String::from("mode"),
        state: DoctorState::Pass,
        detail: format!("profile mode is {:?}", args.mode),
    });
    match args.mode {
        ProfileMode::Local => {
            push_config_check(&mut checks, "agent_config", &args.agent_config);
            push_config_check(&mut checks, "gateway_config", &args.gateway_config);
        }
        ProfileMode::Remote => {
            if let Some(local_component) = args.local_component {
                checks.push(ReadinessCheck {
                    name: String::from("local_component"),
                    state: DoctorState::Pass,
                    detail: format!("local component is {}", component_label(local_component)),
                });
                match local_component {
                    ComponentSelection::Agent => {
                        push_config_check(&mut checks, "agent_config", &args.agent_config)
                    }
                    ComponentSelection::Gateway => {
                        push_config_check(&mut checks, "gateway_config", &args.gateway_config)
                    }
                }
            } else {
                checks.push(ReadinessCheck {
                    name: String::from("local_component"),
                    state: DoctorState::Fail,
                    detail: String::from("remote profile requires local_component"),
                });
            }
        }
    }
    push_required_string_check(
        &mut checks,
        "egress_interface",
        Some(args.egress_interface.as_str()),
        "egress interface is set",
        "egress interface is empty",
    );
    push_mode_check(&mut checks, "route_mode", args.route_mode);
    push_mode_check(&mut checks, "forwarding_mode", args.forwarding_mode);
    push_mode_check(&mut checks, "nat_mode", args.nat_mode);

    let ready = checks.iter().all(|check| check.state != DoctorState::Fail);
    ReadinessReport {
        ready,
        profile: args.profile.clone(),
        checks,
    }
}

fn push_required_string_check(
    checks: &mut Vec<ReadinessCheck>,
    name: &str,
    value: Option<&str>,
    pass_detail: &str,
    fail_detail: &str,
) {
    if value.is_some_and(|value| !value.trim().is_empty()) {
        checks.push(ReadinessCheck {
            name: name.to_owned(),
            state: DoctorState::Pass,
            detail: pass_detail.to_owned(),
        });
    } else {
        checks.push(ReadinessCheck {
            name: name.to_owned(),
            state: DoctorState::Fail,
            detail: fail_detail.to_owned(),
        });
    }
}

fn push_config_check(checks: &mut Vec<ReadinessCheck>, name: &str, path: &Path) {
    match validate_config_file(name, path) {
        Ok(()) => checks.push(ReadinessCheck {
            name: name.to_owned(),
            state: DoctorState::Pass,
            detail: format!("valid config: {}", path.display()),
        }),
        Err(error) => checks.push(ReadinessCheck {
            name: name.to_owned(),
            state: DoctorState::Fail,
            detail: error.to_string(),
        }),
    }
}

fn push_mode_check(checks: &mut Vec<ReadinessCheck>, name: &str, mode: SystemCommandMode) {
    let (state, detail) = if mode == SystemCommandMode::Apply {
        (DoctorState::Pass, format!("{name} will apply OS state"))
    } else {
        (
            DoctorState::Warn,
            format!("{name} is {mode:?}; tunnel may not own OS state"),
        )
    };
    checks.push(ReadinessCheck {
        name: name.to_owned(),
        state,
        detail,
    });
}

fn bail_if_not_ready(readiness: &ReadinessReport) -> Result<()> {
    if readiness.ready {
        return Ok(());
    }

    let failures = readiness
        .checks
        .iter()
        .filter(|check| check.state == DoctorState::Fail)
        .map(|check| format!("{}: {}", check.name, check.detail))
        .collect::<Vec<_>>()
        .join("; ");
    let profile = readiness.profile.as_deref().unwrap_or("selected profile");
    bail!(
        "tunnel profile {profile:?} is not ready: {failures}. Run tunnel-cli login {profile} --force after fixing the missing config."
    );
}

fn write_profile(args: ProfileInitArgs) -> Result<()> {
    let attachment = args
        .attachment
        .clone()
        .unwrap_or_else(|| args.profile.clone());
    let profile = TunnelProfile {
        name: args.profile.clone(),
        tenant: args.tenant.clone(),
        attachment,
        agent_config: Some(args.agent_config.clone()),
        gateway_config: Some(args.gateway_config.clone()),
        agent_state_file: Some(PathBuf::from("/private/tmp/tunnel-agent-state.json")),
        agent_status_file: Some(PathBuf::from("/private/tmp/tunnel-agent-status.json")),
        gateway_state_file: Some(PathBuf::from("/private/tmp/tunnel-gateway-state.json")),
        gateway_status_file: Some(PathBuf::from("/private/tmp/tunnel-gateway-status.json")),
        session_file: Some(PathBuf::from("/private/tmp/tunnel-session.json")),
        agent_log_file: Some(PathBuf::from("/private/tmp/tunnel-agent.log")),
        gateway_log_file: Some(PathBuf::from("/private/tmp/tunnel-gateway.log")),
        supervisor_log_file: Some(PathBuf::from("/private/tmp/tunnel-supervisor.log")),
        egress_interface: Some(args.egress_interface.clone()),
        route_mode: Some(SystemCommandMode::Apply),
        forwarding_mode: Some(SystemCommandMode::Apply),
        nat_mode: Some(SystemCommandMode::Apply),
        ready_timeout_secs: Some(12),
        mode: args.mode,
        local_component: args.local_component,
    };
    write_profile_entry(&args.profile_file, profile, args.force)
}

fn write_profile_entry(profile_file: &Path, profile: TunnelProfile, force: bool) -> Result<()> {
    let mut config = if profile_file.exists() {
        load_profile_config(profile_file)?
    } else {
        ProfileConfig {
            default: None,
            profiles: Vec::new(),
        }
    };

    if config
        .profiles
        .iter()
        .any(|existing| existing.name == profile.name)
        && !force
    {
        bail!(
            "profile {:?} already exists in {}. rerun with --force to overwrite",
            profile.name,
            profile_file.display()
        );
    }

    config
        .profiles
        .retain(|existing| existing.name != profile.name);
    let profile_name = profile.name.clone();
    config.profiles.push(profile);
    config.default = Some(profile_name);
    config
        .profiles
        .sort_by(|left, right| left.name.cmp(&right.name));

    if let Some(parent) = profile_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(profile_file, serde_json::to_string_pretty(&config)?)
        .with_context(|| format!("failed to write {}", profile_file.display()))?;

    Ok(())
}

fn export_side_bundle(
    args: &ConnectArgs,
    side: ComponentSelection,
    bundle_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(bundle_dir)
        .with_context(|| format!("failed to create {}", bundle_dir.display()))?;
    let profile_name = args.profile.clone().unwrap_or_else(|| {
        required_connect_value(args.attachment.as_ref(), "attachment")
            .unwrap_or("remote")
            .to_owned()
    });
    let source_config = match side {
        ComponentSelection::Agent => &args.agent_config,
        ComponentSelection::Gateway => &args.gateway_config,
    };
    let config_file = match side {
        ComponentSelection::Agent => PathBuf::from("tunnel-agent-wg.json"),
        ComponentSelection::Gateway => PathBuf::from("tunnel-gateway-wg.json"),
    };
    let bundle_config_path = bundle_dir.join(&config_file);
    fs::copy(source_config, &bundle_config_path).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source_config.display(),
            bundle_config_path.display()
        )
    })?;

    let profile = side_bundle_profile(args, side, &profile_name, &config_file)?;
    write_json_file(
        &bundle_dir.join("tunnel-profiles.json"),
        &ProfileConfig {
            default: Some(profile_name.clone()),
            profiles: vec![profile],
        },
    )?;
    write_json_file(
        &bundle_dir.join("tunnel-bundle.json"),
        &RemoteProfileBundleManifest {
            version: 1,
            profile: profile_name.clone(),
            side,
            config_file,
            profile_file: PathBuf::from("tunnel-profiles.json"),
            run_hint: format!("tunnel-cli connect {profile_name}"),
            import_hint: format!(
                "tunnel-cli profile import {} --profile-file /private/tmp/tunnel-profiles.json",
                bundle_dir.display()
            ),
        },
    )?;

    Ok(())
}

fn side_bundle_profile(
    args: &ConnectArgs,
    side: ComponentSelection,
    profile_name: &str,
    config_file: &Path,
) -> Result<TunnelProfile> {
    let tenant = required_connect_value(args.tenant.as_ref(), "tenant")?.to_owned();
    let attachment = required_connect_value(args.attachment.as_ref(), "attachment")?.to_owned();
    Ok(TunnelProfile {
        name: profile_name.to_owned(),
        tenant,
        attachment,
        agent_config: (side == ComponentSelection::Agent).then(|| config_file.to_path_buf()),
        gateway_config: (side == ComponentSelection::Gateway).then(|| config_file.to_path_buf()),
        agent_state_file: (side == ComponentSelection::Agent)
            .then(|| PathBuf::from("/private/tmp/tunnel-agent-state.json")),
        agent_status_file: (side == ComponentSelection::Agent)
            .then(|| PathBuf::from("/private/tmp/tunnel-agent-status.json")),
        gateway_state_file: (side == ComponentSelection::Gateway)
            .then(|| PathBuf::from("/private/tmp/tunnel-gateway-state.json")),
        gateway_status_file: (side == ComponentSelection::Gateway)
            .then(|| PathBuf::from("/private/tmp/tunnel-gateway-status.json")),
        session_file: Some(PathBuf::from("/private/tmp/tunnel-session.json")),
        agent_log_file: (side == ComponentSelection::Agent)
            .then(|| PathBuf::from("/private/tmp/tunnel-agent.log")),
        gateway_log_file: (side == ComponentSelection::Gateway)
            .then(|| PathBuf::from("/private/tmp/tunnel-gateway.log")),
        supervisor_log_file: Some(PathBuf::from("/private/tmp/tunnel-supervisor.log")),
        egress_interface: Some(args.egress_interface.clone()),
        route_mode: Some(args.route_mode),
        forwarding_mode: Some(args.forwarding_mode),
        nat_mode: Some(args.nat_mode),
        ready_timeout_secs: Some(args.ready_timeout_secs),
        mode: ProfileMode::Remote,
        local_component: Some(side),
    })
}

fn install_bundle_config(source: &Path, destination: &Path, force: bool) -> Result<()> {
    validate_config_file("bundle_config", source)?;
    if destination.exists() && !force {
        bail!(
            "config already exists at {}. rerun with --force to overwrite",
            destination.display()
        );
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to install bundle config {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn imported_side_profile(
    profile_name: &str,
    bundled_profile: &TunnelProfile,
    side: ComponentSelection,
    installed_config: &Path,
) -> TunnelProfile {
    TunnelProfile {
        name: profile_name.to_owned(),
        tenant: bundled_profile.tenant.clone(),
        attachment: bundled_profile.attachment.clone(),
        agent_config: (side == ComponentSelection::Agent).then(|| installed_config.to_path_buf()),
        gateway_config: (side == ComponentSelection::Gateway)
            .then(|| installed_config.to_path_buf()),
        agent_state_file: (side == ComponentSelection::Agent)
            .then(|| PathBuf::from("/private/tmp/tunnel-agent-state.json")),
        agent_status_file: (side == ComponentSelection::Agent)
            .then(|| PathBuf::from("/private/tmp/tunnel-agent-status.json")),
        gateway_state_file: (side == ComponentSelection::Gateway)
            .then(|| PathBuf::from("/private/tmp/tunnel-gateway-state.json")),
        gateway_status_file: (side == ComponentSelection::Gateway)
            .then(|| PathBuf::from("/private/tmp/tunnel-gateway-status.json")),
        session_file: Some(PathBuf::from("/private/tmp/tunnel-session.json")),
        agent_log_file: (side == ComponentSelection::Agent)
            .then(|| PathBuf::from("/private/tmp/tunnel-agent.log")),
        gateway_log_file: (side == ComponentSelection::Gateway)
            .then(|| PathBuf::from("/private/tmp/tunnel-gateway.log")),
        supervisor_log_file: Some(PathBuf::from("/private/tmp/tunnel-supervisor.log")),
        egress_interface: bundled_profile
            .egress_interface
            .clone()
            .or_else(|| Some(String::from("en0"))),
        route_mode: bundled_profile
            .route_mode
            .or(Some(SystemCommandMode::Apply)),
        forwarding_mode: bundled_profile
            .forwarding_mode
            .or(Some(SystemCommandMode::Apply)),
        nat_mode: bundled_profile.nat_mode.or(Some(SystemCommandMode::Apply)),
        ready_timeout_secs: bundled_profile.ready_timeout_secs.or(Some(12)),
        mode: ProfileMode::Remote,
        local_component: Some(side),
    }
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

    let report = match args.mode {
        ProfileMode::Local => connect_supervised(args)?,
        ProfileMode::Remote => connect_remote_side(args)?,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn connect_supervised(args: ConnectArgs) -> Result<ConnectReport> {
    preflight_connect_args(&args)?;

    if let Some(session) = read_optional_json::<SessionManifest>(&args.session_file)? {
        let supervisor_running = pid_is_running_optional(session.supervisor_pid)?;
        let agent_running = pid_is_running_optional(session.agent_pid)?;
        let gateway_running = pid_is_running_optional(session.gateway_pid)?;
        if supervisor_running && agent_running && gateway_running {
            let warmup = warm_connect_session(&args, &session)?;
            return Ok(connect_report_from_session(&args, session, warmup));
        }
    }

    let (supervisor_pid, session) = spawn_supervisor_for_connect(&args)?;
    let warmup = warm_connect_session(&args, &session)?;
    let mut report = connect_report_from_session(&args, session, warmup);
    report.supervisor_pid = report.supervisor_pid.or(Some(supervisor_pid));
    Ok(report)
}

fn connect_report_from_session(
    args: &ConnectArgs,
    session: SessionManifest,
    warmup: ConnectWarmupReport,
) -> ConnectReport {
    ConnectReport {
        tenant: session.tenant,
        attachment: session.attachment,
        mode: session.mode,
        local_component: session.local_component,
        remote_component: remote_component_for(session.mode, session.local_component),
        supervised: true,
        supervisor_pid: session.supervisor_pid,
        agent_pid: session.agent_pid,
        gateway_pid: session.gateway_pid,
        agent_log_file: session.agent_log_file,
        gateway_log_file: session.gateway_log_file,
        supervisor_log_file: session.supervisor_log_file,
        ready: true,
        warmup: Some(warmup),
        session_file: args.session_file.clone(),
        detail: String::from("local supervised tunnel is active"),
    }
}

fn connect_remote_side(args: ConnectArgs) -> Result<ConnectReport> {
    let local_component = args
        .local_component
        .ok_or_else(|| anyhow!("remote profile requires local_component=agent or gateway"))?;
    preflight_side_args(&args, local_component)?;

    if let Some(session) = read_optional_json::<SessionManifest>(&args.session_file)? {
        let supervisor_running = pid_is_running_optional(session.supervisor_pid)?;
        let local_running = pid_is_running_optional(component_pid(&session, local_component))?;
        if supervisor_running && local_running {
            return Ok(remote_connect_report_from_session(&args, session));
        }
    }

    let (supervisor_pid, session) = spawn_supervisor_for_connect(&args)?;
    let mut report = remote_connect_report_from_session(&args, session);
    report.supervisor_pid = report.supervisor_pid.or(Some(supervisor_pid));
    Ok(report)
}

fn remote_connect_report_from_session(
    args: &ConnectArgs,
    session: SessionManifest,
) -> ConnectReport {
    let local_component = session
        .local_component
        .expect("remote session must record local component");
    let remote_component = remote_component_for(ProfileMode::Remote, Some(local_component))
        .expect("remote session must have opposite component");

    ConnectReport {
        tenant: session.tenant,
        attachment: session.attachment,
        mode: session.mode,
        local_component: session.local_component,
        remote_component: Some(remote_component),
        supervised: session.supervised,
        supervisor_pid: session.supervisor_pid,
        agent_pid: session.agent_pid,
        gateway_pid: session.gateway_pid,
        agent_log_file: session.agent_log_file,
        gateway_log_file: session.gateway_log_file,
        supervisor_log_file: session.supervisor_log_file,
        ready: true,
        warmup: None,
        session_file: args.session_file.clone(),
        detail: format!(
            "remote profile supervising local {}; remote {} must already be running on its host",
            component_label(local_component),
            component_label(remote_component)
        ),
    }
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

fn warm_connect_session(
    args: &ConnectArgs,
    session: &SessionManifest,
) -> Result<ConnectWarmupReport> {
    let rtt_ms = wait_for_probe_success(
        &args.warmup_target,
        args.warmup_probe_timeout_secs,
        args.warmup_settle_secs.max(1) as u32,
        Duration::from_secs(1),
    )?
    .ok_or_else(|| {
        anyhow!(
            "connect warm-up failed: {} did not reply within {:.1}s after {} attempt(s)",
            args.warmup_target,
            args.warmup_probe_timeout_secs,
            args.warmup_settle_secs.max(1)
        )
    })?;

    wait_for_active_status_after_probe(session, args.warmup_settle_secs)?;
    let agent_status = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?;
    let gateway_status = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?;
    let agent_active = agent_status
        .as_ref()
        .map(is_transport_active)
        .unwrap_or(false);
    let gateway_active = gateway_status
        .as_ref()
        .map(is_transport_active)
        .unwrap_or(false);

    if !agent_active || !gateway_active {
        bail!(
            "connect warm-up moved probe traffic to {}, but tunnel did not become active: agent_active={} gateway_active={}. inspect logs with: tunnel-cli logs --component both --lines 80",
            args.warmup_target,
            agent_active,
            gateway_active
        );
    }

    Ok(ConnectWarmupReport {
        target: args.warmup_target.clone(),
        probe_rtt_ms: rtt_ms,
        agent_active,
        gateway_active,
        detail: String::from("packet path warmed and runtime is active"),
    })
}

fn run_connect_oneshot(args: ConnectArgs) -> Result<()> {
    if args.mode != ProfileMode::Local {
        bail!(
            "oneshot connect only owns local profiles; remote profiles use side-specific lifecycle"
        );
    }
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
        mode: ProfileMode::Local,
        local_component: None,
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

fn run_side(args: SideRunArgs, component: ComponentSelection) -> Result<()> {
    let connect_args =
        resolve_connect_args(ConnectArgs::for_profile(args.profile, args.profile_file))?;
    preflight_side_args(&connect_args, component)?;
    let report = match component {
        ComponentSelection::Agent => run_agent_side(connect_args)?,
        ComponentSelection::Gateway => run_gateway_side(connect_args)?,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_gateway_side(args: ConnectArgs) -> Result<SideRunReport> {
    validate_config_file("gateway_config", &args.gateway_config)?;
    let tenant = required_connect_value(args.tenant.as_ref(), "tenant")?.to_owned();
    let attachment = required_connect_value(args.attachment.as_ref(), "attachment")?.to_owned();
    let gateway_bin = sibling_binary("tunnel-gateway")?;
    let (stdout, stderr) = log_stdio(&args.gateway_log_file, false)?;

    let mut command = Command::new(&gateway_bin);
    command
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
        .stdout(stdout)
        .stderr(stderr);

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {}", gateway_bin.display()))?;
    thread::sleep(Duration::from_millis(750));
    ensure_child_still_running(&mut child, "gateway", &args.gateway_log_file)?;

    Ok(SideRunReport {
        component: ComponentSelection::Gateway,
        tenant,
        attachment,
        pid: child.id(),
        config_file: args.gateway_config,
        state_file: args.gateway_state_file,
        status_file: args.gateway_status_file,
        log_file: args.gateway_log_file,
        ready: true,
    })
}

fn run_agent_side(args: ConnectArgs) -> Result<SideRunReport> {
    validate_config_file("agent_config", &args.agent_config)?;
    let tenant = required_connect_value(args.tenant.as_ref(), "tenant")?.to_owned();
    let attachment = required_connect_value(args.attachment.as_ref(), "attachment")?.to_owned();
    let agent_bin = sibling_binary("tunnel-agent")?;
    let (stdout, stderr) = log_stdio(&args.agent_log_file, false)?;

    let mut command = Command::new(&agent_bin);
    command
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
        .stdout(stdout)
        .stderr(stderr);

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {}", agent_bin.display()))?;
    thread::sleep(Duration::from_millis(750));
    ensure_child_still_running(&mut child, "agent", &args.agent_log_file)?;

    Ok(SideRunReport {
        component: ComponentSelection::Agent,
        tenant,
        attachment,
        pid: child.id(),
        config_file: args.agent_config,
        state_file: args.agent_state_file,
        status_file: args.agent_status_file,
        log_file: args.agent_log_file,
        ready: true,
    })
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
    let report = disconnect_tunnel(args)?;
    println!("{}", serde_json::to_string_pretty(&report)?);

    if !report.disconnected {
        bail!("disconnect completed with remaining tunnel state");
    }

    Ok(())
}

fn disconnect_tunnel(args: DisconnectArgs) -> Result<DisconnectReport> {
    let session = read_optional_json::<SessionManifest>(&args.session_file)?;
    let tenant = session.as_ref().map(|session| session.tenant.clone());
    let attachment = session.as_ref().map(|session| session.attachment.clone());
    let supervisor_pid = session.as_ref().and_then(|session| session.supervisor_pid);
    let agent_pid = session.as_ref().and_then(|session| session.agent_pid);
    let gateway_pid = session.as_ref().and_then(|session| session.gateway_pid);
    let owns_agent = session
        .as_ref()
        .map(|session| component_is_locally_owned(session, ComponentSelection::Agent))
        .unwrap_or(true);
    let owns_gateway = session
        .as_ref()
        .map(|session| component_is_locally_owned(session, ComponentSelection::Gateway))
        .unwrap_or(true);

    if let Some(session) = &session {
        terminate_pid_hard_except_self(session.supervisor_pid, "supervisor")?;
        if owns_agent {
            terminate_pid_hard(session.agent_pid, "agent")?;
        }
        if owns_gateway {
            terminate_pid_hard(session.gateway_pid, "gateway")?;
        }
    }

    let agent_bin = sibling_binary("tunnel-agent")?;
    let gateway_bin = sibling_binary("tunnel-gateway")?;

    if owns_agent && args.agent_state_file.exists() {
        run_cleanup_binary_quiet(
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
    }

    if owns_gateway && args.gateway_state_file.exists() {
        run_cleanup_binary_quiet(
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
    }

    if owns_agent {
        remove_stale_file("agent status", &args.agent_status_file)?;
    }
    if owns_gateway {
        remove_stale_file("gateway status", &args.gateway_status_file)?;
    }

    let mut session_removed = !args.session_file.exists();
    if args.session_file.exists() {
        fs::remove_file(&args.session_file).with_context(|| {
            format!(
                "failed to remove session file {}",
                args.session_file.display()
            )
        })?;
        session_removed = true;
    }

    let supervisor_stopped = !pid_is_running_optional(supervisor_pid)?;
    let agent_stopped = !owns_agent || !pid_is_running_optional(agent_pid)?;
    let gateway_stopped = !owns_gateway || !pid_is_running_optional(gateway_pid)?;
    let agent_state_removed = !owns_agent || !args.agent_state_file.exists();
    let agent_status_removed = !owns_agent || !args.agent_status_file.exists();
    let gateway_state_removed = !owns_gateway || !args.gateway_state_file.exists();
    let gateway_status_removed = !owns_gateway || !args.gateway_status_file.exists();
    let agent_cleaned = agent_state_removed && agent_status_removed;
    let gateway_cleaned = gateway_state_removed && gateway_status_removed;
    let disconnected = supervisor_stopped
        && agent_stopped
        && gateway_stopped
        && agent_cleaned
        && gateway_cleaned
        && session_removed
        && agent_state_removed
        && agent_status_removed
        && gateway_state_removed
        && gateway_status_removed;

    let report = DisconnectReport {
        tenant,
        attachment,
        disconnected,
        supervisor_stopped,
        agent_stopped,
        gateway_stopped,
        agent_cleaned,
        gateway_cleaned,
        session_removed,
        agent_state_removed,
        agent_status_removed,
        gateway_state_removed,
        gateway_status_removed,
        detail: if disconnected {
            String::from("tunnel lifecycle cleanup complete")
        } else {
            String::from("tunnel cleanup completed with remaining state")
        },
    };
    Ok(report)
}

fn run_lifecycle_test(args: LifecycleTestArgs) -> Result<()> {
    let mut checks = Vec::new();
    let login_args = LoginArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        tenant: String::from("local-tenant"),
        attachment: Some(args.profile.clone()),
        agent_config: PathBuf::from("/private/tmp/tunnel-agent-wg.json"),
        gateway_config: PathBuf::from("/private/tmp/tunnel-gateway-wg.json"),
        gateway_host: String::from("127.0.0.1"),
        gateway_port: 7000,
        destination_cidr: String::from("1.1.1.0/24"),
        agent_tunnel_address: String::from("10.201.0.2"),
        gateway_tunnel_address: String::from("10.201.0.1"),
        egress_interface: String::from("en0"),
        mode: None,
        local_component: None,
        force: false,
    };

    let _ = disconnect_tunnel(resolve_disconnect_args(DisconnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file.clone(),
    ))?)?;

    ensure_local_configs_for_login(&login_args)?;
    write_profile(ProfileInitArgs {
        profile: login_args.profile.clone(),
        profile_file: login_args.profile_file.clone(),
        tenant: login_args.tenant.clone(),
        attachment: login_args.attachment.clone(),
        agent_config: login_args.agent_config.clone(),
        gateway_config: login_args.gateway_config.clone(),
        egress_interface: login_args.egress_interface.clone(),
        mode: ProfileMode::Local,
        local_component: None,
        force: true,
    })?;

    let mut connect_args = resolve_connect_args(ConnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file.clone(),
    ))?;
    connect_args.warmup_target = args.target.clone();
    let readiness = build_connect_readiness(&connect_args);
    push_lifecycle_check(
        &mut checks,
        "login_ready",
        readiness.ready,
        "login produced a ready profile",
        "login profile readiness failed",
    );

    let connect_report = connect_supervised(connect_args.clone())?;
    push_lifecycle_check(
        &mut checks,
        "connect_ready",
        connect_report.ready
            && connect_report
                .warmup
                .as_ref()
                .is_some_and(|warmup| warmup.agent_active && warmup.gateway_active),
        "connect warmed the packet path and both runtimes are active",
        "connect did not produce an active warmed tunnel",
    );

    let agent_status = read_optional_json::<RuntimeStatus>(&connect_args.agent_status_file)?;
    let gateway_status = read_optional_json::<RuntimeStatus>(&connect_args.gateway_status_file)?;
    let status_healthy = agent_status
        .as_ref()
        .map(is_transport_active)
        .unwrap_or(false)
        && gateway_status
            .as_ref()
            .map(is_transport_active)
            .unwrap_or(false);
    push_lifecycle_check(
        &mut checks,
        "status_healthy",
        status_healthy,
        "status reports healthy active agent and gateway",
        "status did not report healthy active agent and gateway",
    );

    let disconnect_report = disconnect_tunnel(resolve_disconnect_args(
        DisconnectArgs::for_profile(args.profile.clone(), args.profile_file.clone()),
    )?)?;
    push_lifecycle_check(
        &mut checks,
        "disconnect_clean",
        disconnect_report.disconnected,
        "disconnect cleaned tunnel lifecycle state",
        "disconnect left tunnel lifecycle state behind",
    );

    let second_disconnect_report = disconnect_tunnel(resolve_disconnect_args(
        DisconnectArgs::for_profile(args.profile.clone(), args.profile_file.clone()),
    )?)?;
    push_lifecycle_check(
        &mut checks,
        "second_disconnect_clean",
        second_disconnect_report.disconnected,
        "second disconnect was idempotent",
        "second disconnect was not idempotent",
    );

    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else {
        DoctorState::Pass
    };
    let report = LifecycleTestReport {
        overall,
        profile: args.profile,
        login_ready: readiness.ready,
        connect_ready: connect_report.ready,
        status_healthy,
        disconnect_clean: disconnect_report.disconnected,
        second_disconnect_clean: second_disconnect_report.disconnected,
        warmup: connect_report
            .warmup
            .expect("local lifecycle connect always returns warmup"),
        checks,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    if report.overall != DoctorState::Pass {
        bail!("lifecycle test failed");
    }

    Ok(())
}

fn run_remote_lifecycle_test(args: RemoteLifecycleTestArgs) -> Result<()> {
    let mut checks = Vec::new();
    let root = remote_lifecycle_test_root(&args);
    fs::create_dir_all(&root).with_context(|| format!("failed to create {}", root.display()))?;

    let agent_profile = format!("{}-agent", args.profile);
    let gateway_profile = format!("{}-gateway", args.profile);
    let agent_paths = RemoteLifecyclePaths::new(&root, &agent_profile);
    let gateway_paths = RemoteLifecyclePaths::new(&root, &gateway_profile);

    prepare_remote_lifecycle_side(
        &args,
        &agent_profile,
        &agent_paths,
        ComponentSelection::Agent,
    )?;
    prepare_remote_lifecycle_side(
        &args,
        &gateway_profile,
        &gateway_paths,
        ComponentSelection::Gateway,
    )?;
    write_remote_lifecycle_profiles(
        &args,
        &agent_profile,
        &agent_paths,
        &gateway_profile,
        &gateway_paths,
    )?;

    remove_stale_file("remote gateway config", &agent_paths.gateway_config)?;
    remove_stale_file("remote agent config", &gateway_paths.agent_config)?;

    let agent_connect = resolve_connect_args(ConnectArgs::for_profile(
        agent_profile.clone(),
        args.profile_file.clone(),
    ))?;
    let gateway_connect = resolve_connect_args(ConnectArgs::for_profile(
        gateway_profile.clone(),
        args.profile_file.clone(),
    ))?;
    let agent_readiness = build_connect_readiness(&agent_connect);
    let gateway_readiness = build_connect_readiness(&gateway_connect);
    push_lifecycle_check(
        &mut checks,
        "remote_agent_profile_ready",
        agent_readiness.ready && agent_connect.local_component == Some(ComponentSelection::Agent),
        "remote agent profile is ready with only agent-owned config",
        "remote agent profile is not ready",
    );
    push_lifecycle_check(
        &mut checks,
        "remote_gateway_profile_ready",
        gateway_readiness.ready
            && gateway_connect.local_component == Some(ComponentSelection::Gateway),
        "remote gateway profile is ready with only gateway-owned config",
        "remote gateway profile is not ready",
    );

    write_gateway_doctor_fixture(&gateway_connect)?;
    let doctor_report = build_doctor_report(DoctorArgs {
        profile: Some(gateway_profile.clone()),
        profile_file: args.profile_file.clone(),
        session_file: gateway_connect.session_file.clone(),
        target: String::from("1.1.1.1"),
        probe_timeout_secs: 0.2,
        stale_after_secs: 60,
        post_probe_settle_secs: 1,
    })?;
    let gateway_doctor_non_failing = doctor_report.overall != DoctorState::Fail
        && doctor_report
            .checks
            .iter()
            .all(|check| check.state != DoctorState::Fail);
    push_lifecycle_check(
        &mut checks,
        "remote_gateway_doctor_non_failing",
        gateway_doctor_non_failing,
        "doctor treats remote-owned agent state as non-failing",
        "doctor failed because of remote-owned agent state",
    );

    remove_stale_file("gateway state", &gateway_connect.gateway_state_file)?;
    remove_stale_file("gateway status", &gateway_connect.gateway_status_file)?;
    write_remote_agent_owned_files(&gateway_connect)?;
    write_remote_lifecycle_session(&gateway_connect, None)?;
    let disconnect_report = disconnect_tunnel(resolve_disconnect_args(
        DisconnectArgs::for_profile(gateway_profile.clone(), args.profile_file.clone()),
    )?)?;
    let remote_agent_state_preserved = gateway_connect.agent_state_file.exists()
        && gateway_connect.agent_status_file.exists()
        && !gateway_connect.session_file.exists();
    push_lifecycle_check(
        &mut checks,
        "remote_gateway_disconnect_clean",
        disconnect_report.disconnected,
        "disconnect cleaned local gateway lifecycle state",
        "disconnect did not clean local gateway lifecycle state",
    );
    push_lifecycle_check(
        &mut checks,
        "remote_agent_state_preserved",
        remote_agent_state_preserved,
        "disconnect preserved remote-owned agent state",
        "disconnect removed or damaged remote-owned agent state",
    );

    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else {
        DoctorState::Pass
    };
    let report = RemoteLifecycleTestReport {
        overall,
        agent_profile,
        gateway_profile,
        agent_readiness_ready: agent_readiness.ready,
        gateway_readiness_ready: gateway_readiness.ready,
        gateway_doctor_non_failing,
        gateway_disconnect_clean: disconnect_report.disconnected,
        remote_agent_state_preserved,
        checks,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    let _ = fs::remove_dir_all(&root);
    if report.overall != DoctorState::Pass {
        bail!("remote lifecycle test failed");
    }

    Ok(())
}

struct RemoteLifecyclePaths {
    agent_config: PathBuf,
    gateway_config: PathBuf,
    agent_state_file: PathBuf,
    agent_status_file: PathBuf,
    gateway_state_file: PathBuf,
    gateway_status_file: PathBuf,
    session_file: PathBuf,
    agent_log_file: PathBuf,
    gateway_log_file: PathBuf,
    supervisor_log_file: PathBuf,
}

impl RemoteLifecyclePaths {
    fn new(root: &Path, profile: &str) -> Self {
        Self {
            agent_config: root.join(format!("{profile}-agent.json")),
            gateway_config: root.join(format!("{profile}-gateway.json")),
            agent_state_file: root.join(format!("{profile}-agent-state.json")),
            agent_status_file: root.join(format!("{profile}-agent-status.json")),
            gateway_state_file: root.join(format!("{profile}-gateway-state.json")),
            gateway_status_file: root.join(format!("{profile}-gateway-status.json")),
            session_file: root.join(format!("{profile}-session.json")),
            agent_log_file: root.join(format!("{profile}-agent.log")),
            gateway_log_file: root.join(format!("{profile}-gateway.log")),
            supervisor_log_file: root.join(format!("{profile}-supervisor.log")),
        }
    }
}

fn remote_lifecycle_test_root(args: &RemoteLifecycleTestArgs) -> PathBuf {
    args.profile_file
        .parent()
        .unwrap_or_else(|| Path::new("/private/tmp"))
        .join(format!(
            "tunnel-remote-lifecycle-{}-{}",
            process::id(),
            now_unix_secs()
        ))
}

fn prepare_remote_lifecycle_side(
    args: &RemoteLifecycleTestArgs,
    profile: &str,
    paths: &RemoteLifecyclePaths,
    local_component: ComponentSelection,
) -> Result<()> {
    let login_args = LoginArgs {
        profile: profile.to_owned(),
        profile_file: args.profile_file.clone(),
        tenant: String::from("local-tenant"),
        attachment: Some(profile.to_owned()),
        agent_config: paths.agent_config.clone(),
        gateway_config: paths.gateway_config.clone(),
        gateway_host: args.gateway_host.clone(),
        gateway_port: args.gateway_port,
        destination_cidr: String::from("1.1.1.0/24"),
        agent_tunnel_address: String::from("10.201.0.2"),
        gateway_tunnel_address: String::from("10.201.0.1"),
        egress_interface: String::from("en0"),
        mode: Some(ProfileMode::Remote),
        local_component: Some(local_component),
        force: true,
    };
    ensure_local_configs_for_login(&login_args)?;
    Ok(())
}

fn write_remote_lifecycle_profiles(
    args: &RemoteLifecycleTestArgs,
    agent_profile: &str,
    agent_paths: &RemoteLifecyclePaths,
    gateway_profile: &str,
    gateway_paths: &RemoteLifecyclePaths,
) -> Result<()> {
    let config = ProfileConfig {
        default: Some(agent_profile.to_owned()),
        profiles: vec![
            remote_lifecycle_profile(
                agent_profile,
                agent_paths,
                ComponentSelection::Agent,
                "local-tenant",
            ),
            remote_lifecycle_profile(
                gateway_profile,
                gateway_paths,
                ComponentSelection::Gateway,
                "local-tenant",
            ),
        ],
    };
    write_json_file(&args.profile_file, &config)
}

fn remote_lifecycle_profile(
    profile: &str,
    paths: &RemoteLifecyclePaths,
    local_component: ComponentSelection,
    tenant: &str,
) -> TunnelProfile {
    TunnelProfile {
        name: profile.to_owned(),
        tenant: tenant.to_owned(),
        attachment: profile.to_owned(),
        agent_config: Some(paths.agent_config.clone()),
        gateway_config: Some(paths.gateway_config.clone()),
        agent_state_file: Some(paths.agent_state_file.clone()),
        agent_status_file: Some(paths.agent_status_file.clone()),
        gateway_state_file: Some(paths.gateway_state_file.clone()),
        gateway_status_file: Some(paths.gateway_status_file.clone()),
        session_file: Some(paths.session_file.clone()),
        agent_log_file: Some(paths.agent_log_file.clone()),
        gateway_log_file: Some(paths.gateway_log_file.clone()),
        supervisor_log_file: Some(paths.supervisor_log_file.clone()),
        egress_interface: Some(String::from("en0")),
        route_mode: Some(SystemCommandMode::Apply),
        forwarding_mode: Some(SystemCommandMode::Apply),
        nat_mode: Some(SystemCommandMode::Apply),
        ready_timeout_secs: Some(12),
        mode: ProfileMode::Remote,
        local_component: Some(local_component),
    }
}

fn write_gateway_doctor_fixture(args: &ConnectArgs) -> Result<()> {
    let gateway_config: TunnelConfig = serde_json::from_str(
        &fs::read_to_string(&args.gateway_config)
            .with_context(|| format!("failed to read {}", args.gateway_config.display()))?,
    )?;
    let subnet = expected_gateway_tunnel_subnet(Some(&gateway_config))?
        .unwrap_or_else(|| String::from("10.201.0.0/24"));
    let rules_path = args.gateway_state_file.with_extension("pf.conf");
    let rules = format!(
        "nat on {egress} from {subnet} to any -> ({egress})\npass in quick on {tun} inet from {subnet} to any keep state\npass out quick on {egress} route-to ({egress} 192.0.2.1) inet from {subnet} to any keep state\n",
        egress = args.egress_interface,
        tun = "utun-test",
    );
    fs::write(&rules_path, rules)
        .with_context(|| format!("failed to write {}", rules_path.display()))?;
    write_json_file(
        &args.gateway_state_file,
        &GatewayRuntimeState {
            tunnel_interface: String::from("utun-test"),
            nat_anchor_name: Some(String::from("com.apple/tunnel-utun-test")),
            nat_rules_path: Some(rules_path),
            forwarding_was_enabled: Some(true),
            egress_interface: Some(args.egress_interface.clone()),
        },
    )?;
    write_json_file(
        &args.gateway_status_file,
        &runtime_status(ComponentKind::Gateway, Some(String::from("utun-test"))),
    )?;
    write_remote_lifecycle_session(args, Some(process::id()))
}

fn write_remote_agent_owned_files(args: &ConnectArgs) -> Result<()> {
    write_json_file(
        &args.agent_state_file,
        &AgentRuntimeState {
            tunnel_interface: String::from("utun-remote-agent"),
            destination_cidrs: vec![String::from("1.1.1.0/24")],
        },
    )?;
    write_json_file(
        &args.agent_status_file,
        &runtime_status(
            ComponentKind::Agent,
            Some(String::from("utun-remote-agent")),
        ),
    )
}

fn write_remote_lifecycle_session(args: &ConnectArgs, gateway_pid: Option<u32>) -> Result<()> {
    let tenant = required_connect_value(args.tenant.as_ref(), "tenant")?.to_owned();
    let attachment = required_connect_value(args.attachment.as_ref(), "attachment")?.to_owned();
    let session = SessionManifest {
        tenant,
        attachment,
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
        agent_pid: None,
        gateway_pid,
        mode: ProfileMode::Remote,
        local_component: Some(ComponentSelection::Gateway),
        supervised: false,
        supervisor_pid: None,
        supervisor_log_file: args.supervisor_log_file.clone(),
    };
    save_manifest(&args.session_file, &session)
}

fn runtime_status(component: ComponentKind, tunnel_interface: Option<String>) -> RuntimeStatus {
    let now = now_unix_secs();
    RuntimeStatus {
        component,
        state: HealthState::Healthy,
        phase: TunnelPhase::Active,
        tenant_id: Some(String::from("local-tenant")),
        tunnel_id: Some(String::from("local-tunnel")),
        transport: TransportKind::WireGuardUdp,
        tunnel_interface,
        peer_endpoint: Some(String::from("127.0.0.1:7000")),
        ingress_bytes: 0,
        egress_bytes: 0,
        last_ingress_at_unix_secs: Some(now),
        last_egress_at_unix_secs: Some(now),
        last_peer_activity_unix_secs: Some(now),
        last_activity_unix_secs: Some(now),
        packet_path: PacketPathTelemetry::default(),
        observed_at_unix_secs: now,
        detail: String::from("remote lifecycle fixture"),
    }
}

fn run_remote_check(args: RemoteCheckArgs) -> Result<()> {
    let report = build_remote_check_report(args)?;
    println!("{}", serde_json::to_string_pretty(&report)?);

    if report.overall == DoctorState::Fail {
        bail!("remote check failed");
    }

    Ok(())
}

fn build_remote_check_report(args: RemoteCheckArgs) -> Result<RemoteCheckReport> {
    let mut checks = Vec::new();
    let mut connect_args =
        ConnectArgs::for_profile(args.profile.clone(), args.profile_file.clone());
    connect_args = match resolve_connect_args(connect_args) {
        Ok(args) => {
            checks.push(doctor_check(
                "profile",
                DoctorState::Pass,
                "profile resolved successfully",
            ));
            args
        }
        Err(error) => {
            checks.push(doctor_check(
                "profile",
                DoctorState::Fail,
                format!("profile resolution failed: {error:#}"),
            ));
            return Ok(make_remote_check_report(args, checks));
        }
    };
    let peer_connect_args = if let Some(peer_profile) = args.peer_profile.clone() {
        let peer_profile_file = args
            .peer_profile_file
            .clone()
            .unwrap_or_else(|| args.profile_file.clone());
        let peer_args = ConnectArgs::for_profile(peer_profile.clone(), peer_profile_file.clone());
        match resolve_connect_args(peer_args) {
            Ok(peer_args) => {
                checks.push(doctor_check(
                    "peer_profile",
                    DoctorState::Pass,
                    format!(
                        "peer profile {:?} resolved successfully from {}",
                        peer_profile,
                        peer_profile_file.display()
                    ),
                ));
                Some(peer_args)
            }
            Err(error) => {
                checks.push(doctor_check(
                    "peer_profile",
                    DoctorState::Fail,
                    format!("peer profile resolution failed: {error:#}"),
                ));
                None
            }
        }
    } else {
        None
    };

    let (agent_config_path, gateway_config_path) =
        remote_check_config_paths(&connect_args, peer_connect_args.as_ref(), &mut checks);
    push_config_validation_check(&mut checks, "agent_config", &agent_config_path);
    push_config_validation_check(&mut checks, "gateway_config", &gateway_config_path);

    let agent_config = read_optional_json::<TunnelConfig>(&agent_config_path)?;
    let gateway_config = read_optional_json::<TunnelConfig>(&gateway_config_path)?;
    check_remote_config_intent(
        &mut checks,
        agent_config.as_ref(),
        gateway_config.as_ref(),
        args.gateway_host.as_deref(),
        args.gateway_port,
    );
    if args.udp_probe {
        push_gateway_udp_probe_check(
            &mut checks,
            agent_config.as_ref(),
            args.gateway_host.as_deref(),
            args.gateway_port,
            args.udp_probe_timeout_secs,
        );
    }

    Ok(make_remote_check_report(args, checks))
}

fn push_config_validation_check(checks: &mut Vec<DoctorCheck>, name: &str, path: &Path) {
    match validate_config_file(name, path) {
        Ok(()) => checks.push(doctor_check(
            name,
            DoctorState::Pass,
            format!("valid config: {}", path.display()),
        )),
        Err(error) => checks.push(doctor_check(name, DoctorState::Fail, format!("{error:#}"))),
    }
}

fn remote_check_config_paths(
    primary: &ConnectArgs,
    peer: Option<&ConnectArgs>,
    checks: &mut Vec<DoctorCheck>,
) -> (PathBuf, PathBuf) {
    let Some(peer) = peer else {
        return (primary.agent_config.clone(), primary.gateway_config.clone());
    };

    match (primary.local_component, peer.local_component) {
        (Some(ComponentSelection::Agent), Some(ComponentSelection::Gateway)) => {
            checks.push(doctor_check(
                "profile_pair",
                DoctorState::Pass,
                "primary agent profile is paired with peer gateway profile",
            ));
            (primary.agent_config.clone(), peer.gateway_config.clone())
        }
        (Some(ComponentSelection::Gateway), Some(ComponentSelection::Agent)) => {
            checks.push(doctor_check(
                "profile_pair",
                DoctorState::Pass,
                "primary gateway profile is paired with peer agent profile",
            ));
            (peer.agent_config.clone(), primary.gateway_config.clone())
        }
        (Some(left), Some(right)) => {
            checks.push(doctor_check(
                "profile_pair",
                DoctorState::Fail,
                format!(
                    "primary and peer profiles must be opposite remote sides; got {} and {}",
                    component_label(left),
                    component_label(right)
                ),
            ));
            (primary.agent_config.clone(), primary.gateway_config.clone())
        }
        _ => {
            checks.push(doctor_check(
                "profile_pair",
                DoctorState::Fail,
                "peer profile validation requires both profiles to declare local_component",
            ));
            (primary.agent_config.clone(), primary.gateway_config.clone())
        }
    }
}

fn check_remote_config_intent(
    checks: &mut Vec<DoctorCheck>,
    agent_config: Option<&TunnelConfig>,
    gateway_config: Option<&TunnelConfig>,
    expected_host: Option<&str>,
    expected_port: Option<u16>,
) {
    let Some(agent_config) = agent_config else {
        checks.push(doctor_check(
            "agent_config_intent",
            DoctorState::Fail,
            "agent config could not be loaded",
        ));
        return;
    };
    let Some(gateway_config) = gateway_config else {
        checks.push(doctor_check(
            "gateway_config_intent",
            DoctorState::Fail,
            "gateway config could not be loaded",
        ));
        return;
    };
    let Some(agent_wg) = agent_config.wireguard.as_ref() else {
        checks.push(doctor_check(
            "agent_wireguard",
            DoctorState::Fail,
            "agent config has no WireGuard section",
        ));
        return;
    };
    let Some(gateway_wg) = gateway_config.wireguard.as_ref() else {
        checks.push(doctor_check(
            "gateway_wireguard",
            DoctorState::Fail,
            "gateway config has no WireGuard section",
        ));
        return;
    };
    let Some(peer_endpoint) = agent_wg.peer_endpoint.as_ref() else {
        checks.push(doctor_check(
            "agent_peer_endpoint",
            DoctorState::Fail,
            "agent config has no gateway peer endpoint",
        ));
        return;
    };

    let expected_host = expected_host.unwrap_or(&agent_config.gateway.host);
    let expected_port = expected_port.unwrap_or(agent_config.gateway.port);
    push_lifecycle_check(
        checks,
        "agent_gateway_endpoint",
        peer_endpoint.host == expected_host && peer_endpoint.port == expected_port,
        "agent peer endpoint matches expected gateway host/port",
        "agent peer endpoint does not match expected gateway host/port",
    );
    push_lifecycle_check(
        checks,
        "gateway_bind_port",
        gateway_wg.local_bind_port == expected_port,
        "gateway bind port matches expected gateway port",
        "gateway bind port does not match expected gateway port",
    );
    push_lifecycle_check(
        checks,
        "gateway_host_consistency",
        agent_config.gateway.host == gateway_config.gateway.host
            && agent_config.gateway.host == expected_host,
        "agent/gateway configs agree on gateway host",
        "agent/gateway configs disagree on gateway host",
    );
    push_lifecycle_check(
        checks,
        "tunnel_address_pair",
        agent_wg.local_tunnel_address == gateway_wg.peer_tunnel_address
            && agent_wg.peer_tunnel_address == gateway_wg.local_tunnel_address,
        "agent/gateway tunnel addresses are mirrored",
        "agent/gateway tunnel addresses are not mirrored",
    );
    push_lifecycle_check(
        checks,
        "destination_cidrs",
        !agent_config.route_policy.destination_cidrs.is_empty()
            && agent_config.route_policy.destination_cidrs
                == gateway_config.route_policy.destination_cidrs,
        "agent/gateway destination CIDRs match",
        "agent/gateway destination CIDRs are missing or mismatched",
    );
}

fn make_remote_check_report(args: RemoteCheckArgs, checks: Vec<DoctorCheck>) -> RemoteCheckReport {
    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else if checks.iter().any(|check| check.state == DoctorState::Warn) {
        DoctorState::Warn
    } else {
        DoctorState::Pass
    };
    RemoteCheckReport {
        overall,
        profile: args.profile,
        peer_profile: args.peer_profile,
        gateway_host: args.gateway_host,
        gateway_port: args.gateway_port,
        checks,
    }
}

fn push_gateway_udp_probe_check(
    checks: &mut Vec<DoctorCheck>,
    agent_config: Option<&TunnelConfig>,
    expected_host: Option<&str>,
    expected_port: Option<u16>,
    timeout_secs: f64,
) {
    let Some((host, port)) = gateway_endpoint_for_probe(agent_config, expected_host, expected_port)
    else {
        checks.push(doctor_check(
            "gateway_udp_probe",
            DoctorState::Fail,
            "gateway host/port could not be resolved for UDP probe",
        ));
        return;
    };

    let report = probe_gateway_udp(&host, port, timeout_secs);
    let state = if report.sent {
        DoctorState::Pass
    } else {
        DoctorState::Fail
    };
    checks.push(doctor_check("gateway_udp_probe", state, report.detail));
}

fn gateway_endpoint_for_probe(
    agent_config: Option<&TunnelConfig>,
    expected_host: Option<&str>,
    expected_port: Option<u16>,
) -> Option<(String, u16)> {
    let host = expected_host
        .map(str::to_owned)
        .or_else(|| agent_config.map(|config| config.gateway.host.clone()))?;
    let port = expected_port.or_else(|| agent_config.map(|config| config.gateway.port))?;
    Some((host, port))
}

fn probe_gateway_udp(host: &str, port: u16, timeout_secs: f64) -> UdpProbeReport {
    let timeout = Duration::from_secs_f64(timeout_secs.max(0.001));
    let detail = match (host, port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => match UdpSocket::bind(if addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            }) {
                Ok(socket) => {
                    let _ = socket.set_write_timeout(Some(timeout));
                    match socket.connect(addr) {
                        Ok(()) => match socket.send(&[0]) {
                            Ok(bytes) => {
                                return UdpProbeReport {
                                    host: host.to_owned(),
                                    port,
                                    timeout_secs,
                                    sent: true,
                                    detail: format!(
                                        "sent {bytes} byte UDP probe datagram to {host}:{port}; UDP reachability requires gateway-side packet counters for acknowledgement"
                                    ),
                                };
                            }
                            Err(error) => format!("failed to send UDP probe: {error}"),
                        },
                        Err(error) => format!("failed to connect UDP socket: {error}"),
                    }
                }
                Err(error) => format!("failed to bind UDP probe socket: {error}"),
            },
            None => format!("gateway endpoint {host}:{port} resolved to no socket addresses"),
        },
        Err(error) => format!("failed to resolve gateway endpoint {host}:{port}: {error}"),
    };

    UdpProbeReport {
        host: host.to_owned(),
        port,
        timeout_secs,
        sent: false,
        detail,
    }
}

fn run_remote_smoke_test(args: RemoteSmokeTestArgs) -> Result<()> {
    let mut checks = Vec::new();
    let remote_check_args = RemoteCheckArgs {
        profile: args.profile.clone(),
        profile_file: args.profile_file.clone(),
        peer_profile: args.peer_profile.clone(),
        peer_profile_file: args.peer_profile_file.clone(),
        gateway_host: args.gateway_host.clone(),
        gateway_port: args.gateway_port,
        udp_probe: false,
        udp_probe_timeout_secs: args.udp_probe_timeout_secs,
    };
    let remote_check = build_remote_check_report(remote_check_args.clone())?;
    push_lifecycle_check(
        &mut checks,
        "remote_check",
        remote_check.overall != DoctorState::Fail,
        "remote profile/config check is non-failing",
        "remote profile/config check failed",
    );

    let connect_args = resolve_connect_args(ConnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file.clone(),
    ))?;
    push_lifecycle_check(
        &mut checks,
        "agent_side_profile",
        connect_args.local_component == Some(ComponentSelection::Agent),
        "smoke test is running from the agent-side profile",
        "remote smoke-test must run from the agent-side host/profile so it can generate routed probe traffic",
    );

    let gateway_udp_probe =
        gateway_udp_probe_for_remote_args(&remote_check_args, args.udp_probe_timeout_secs)?;
    push_lifecycle_check(
        &mut checks,
        "gateway_udp_probe",
        gateway_udp_probe.sent,
        "gateway UDP endpoint accepted an outbound probe datagram",
        gateway_udp_probe.detail.as_str(),
    );

    let doctor_args = resolve_doctor_args(DoctorArgs {
        profile: Some(args.profile.clone()),
        profile_file: args.profile_file.clone(),
        session_file: args.session_file.clone(),
        target: args.target.clone(),
        probe_timeout_secs: args.probe_timeout_secs,
        stale_after_secs: args.stale_after_secs,
        post_probe_settle_secs: args.post_probe_settle_secs,
    })?;
    let session_file = doctor_args.session_file.clone();
    let doctor = build_doctor_report(doctor_args)?;
    push_lifecycle_check(
        &mut checks,
        "doctor",
        doctor.overall != DoctorState::Fail,
        "doctor is non-failing",
        "doctor failed",
    );

    let soak = build_soak_report(SoakArgs {
        session_file,
        target: args.target.clone(),
        count: args.count,
        interval_secs: args.interval_secs,
        probe_timeout_secs: args.probe_timeout_secs,
        bounce_agent_at: None,
        bounce_gateway_at: None,
    })?;
    push_lifecycle_check(
        &mut checks,
        "soak",
        soak.sent > 0 && soak.received == soak.sent,
        "soak completed with zero packet loss",
        "soak reported packet loss",
    );

    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else if checks.iter().any(|check| check.state == DoctorState::Warn)
        || remote_check.overall == DoctorState::Warn
        || doctor.overall == DoctorState::Warn
    {
        DoctorState::Warn
    } else {
        DoctorState::Pass
    };
    let report = RemoteSmokeTestReport {
        overall,
        profile: args.profile,
        peer_profile: args.peer_profile,
        target: args.target,
        remote_check,
        gateway_udp_probe,
        doctor,
        soak,
        checks,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    if report.overall == DoctorState::Fail {
        bail!("remote smoke test failed");
    }

    Ok(())
}

fn gateway_udp_probe_for_remote_args(
    args: &RemoteCheckArgs,
    timeout_secs: f64,
) -> Result<UdpProbeReport> {
    let mut checks = Vec::new();
    let primary = resolve_connect_args(ConnectArgs::for_profile(
        args.profile.clone(),
        args.profile_file.clone(),
    ))?;
    let peer = if let Some(peer_profile) = args.peer_profile.clone() {
        Some(resolve_connect_args(ConnectArgs::for_profile(
            peer_profile,
            args.peer_profile_file
                .clone()
                .unwrap_or_else(|| args.profile_file.clone()),
        ))?)
    } else {
        None
    };
    let (agent_config_path, _) = remote_check_config_paths(&primary, peer.as_ref(), &mut checks);
    let agent_config = read_optional_json::<TunnelConfig>(&agent_config_path)?;
    let (host, port) = gateway_endpoint_for_probe(
        agent_config.as_ref(),
        args.gateway_host.as_deref(),
        args.gateway_port,
    )
    .ok_or_else(|| anyhow!("gateway host/port could not be resolved for UDP probe"))?;
    Ok(probe_gateway_udp(&host, port, timeout_secs))
}

fn push_lifecycle_check(
    checks: &mut Vec<DoctorCheck>,
    name: &str,
    passed: bool,
    pass_detail: &str,
    fail_detail: &str,
) {
    checks.push(doctor_check(
        name,
        if passed {
            DoctorState::Pass
        } else {
            DoctorState::Fail
        },
        if passed { pass_detail } else { fail_detail },
    ));
}

fn run_restart(args: RestartArgs) -> Result<()> {
    let mut session = load_manifest(&args.session_file)?;
    if !component_is_locally_owned(&session, args.component) {
        bail!(
            "cannot restart remote-owned {} from this host",
            component_label(args.component)
        );
    }
    restart_component(&mut session, args.component)?;
    save_manifest(&args.session_file, &session)?;
    println!("{}", serde_json::to_string_pretty(&session)?);
    Ok(())
}

fn run_supervisor(args: SupervisorArgs) -> Result<()> {
    let mut args = args;
    args.connect = resolve_connect_args(args.connect)?;
    match args.connect.mode {
        ProfileMode::Local => preflight_connect_args(&args.connect)?,
        ProfileMode::Remote => {
            let local_component = args.connect.local_component.ok_or_else(|| {
                anyhow!("remote supervisor requires local_component=agent or gateway")
            })?;
            preflight_side_args(&args.connect, local_component)?;
        }
    }
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

        let agent_changed = if component_is_locally_owned(&session, ComponentSelection::Agent) {
            supervise_component(
                &mut session,
                ComponentSelection::Agent,
                &mut agent_state,
                &args,
                &mut supervisor_log,
            )?
        } else {
            false
        };
        let gateway_changed = if component_is_locally_owned(&session, ComponentSelection::Gateway) {
            supervise_component(
                &mut session,
                ComponentSelection::Gateway,
                &mut gateway_state,
                &args,
                &mut supervisor_log,
            )?
        } else {
            false
        };
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
    let report = build_doctor_report(args)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn build_doctor_report(args: DoctorArgs) -> Result<DoctorReport> {
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
        return Ok(make_doctor_report(args.target, checks));
    };

    checks.push(doctor_check(
        "session_file",
        DoctorState::Pass,
        format!(
            "session manifest found for tenant={} attachment={}",
            session.tenant, session.attachment
        ),
    ));

    check_component_process(&session, ComponentSelection::Agent, &mut checks);
    check_component_process(&session, ComponentSelection::Gateway, &mut checks);

    let agent_state = read_optional_json::<AgentRuntimeState>(&session.agent_state_file)?;
    let gateway_state = read_optional_json::<GatewayRuntimeState>(&session.gateway_state_file)?;
    let gateway_config = read_optional_json::<TunnelConfig>(&session.gateway_config)?;

    if component_is_locally_owned(&session, ComponentSelection::Agent) {
        check_agent_state(agent_state.as_ref(), &session.agent_state_file, &mut checks);
        check_route_to_target(&args.target, agent_state.as_ref(), &mut checks)?;
    } else {
        push_remote_skip(&mut checks, "agent_state", ComponentSelection::Agent);
        push_remote_skip(&mut checks, "route_to_target", ComponentSelection::Agent);
    }

    if component_is_locally_owned(&session, ComponentSelection::Gateway) {
        check_gateway_state(
            gateway_state.as_ref(),
            &session.gateway_state_file,
            &mut checks,
        );
        check_gateway_os_rules(
            gateway_state.as_ref(),
            gateway_config.as_ref(),
            &session.egress_interface,
            &mut checks,
        )?;
    } else {
        push_remote_skip(&mut checks, "gateway_state", ComponentSelection::Gateway);
        push_remote_skip(&mut checks, "gateway_os_rules", ComponentSelection::Gateway);
    }
    let agent_packet_before = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?
        .map(|status| status.packet_path);
    let gateway_packet_before = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?
        .map(|status| status.packet_path);
    let should_probe = session.mode == ProfileMode::Local
        || session.local_component == Some(ComponentSelection::Agent);
    let probe_passed = if should_probe {
        check_probe(&args.target, args.probe_timeout_secs, &mut checks)?
    } else {
        checks.push(doctor_check(
            "probe",
            DoctorState::Warn,
            "skipped because this remote host owns the gateway side, not the agent route side",
        ));
        false
    };
    if probe_passed {
        wait_for_active_status_after_probe(&session, args.post_probe_settle_secs)?;
    }

    let agent_status = read_optional_json::<RuntimeStatus>(&session.agent_status_file)?;
    let gateway_status = read_optional_json::<RuntimeStatus>(&session.gateway_status_file)?;
    if should_probe {
        check_packet_path_analysis(
            probe_passed,
            agent_packet_before.as_ref(),
            agent_status.as_ref().map(|status| &status.packet_path),
            gateway_packet_before.as_ref(),
            gateway_status.as_ref().map(|status| &status.packet_path),
            &mut checks,
        );
    } else {
        checks.push(doctor_check(
            "packet_path_analysis",
            DoctorState::Warn,
            "skipped because this remote host cannot generate agent-side routed probe traffic",
        ));
    }
    if component_is_locally_owned(&session, ComponentSelection::Agent) {
        check_runtime_status(
            "agent_status",
            agent_status.as_ref(),
            &session.agent_status_file,
            args.stale_after_secs,
            probe_passed,
            &mut checks,
        );
    } else {
        push_remote_skip(&mut checks, "agent_status", ComponentSelection::Agent);
    }
    if component_is_locally_owned(&session, ComponentSelection::Gateway) {
        check_runtime_status(
            "gateway_status",
            gateway_status.as_ref(),
            &session.gateway_status_file,
            args.stale_after_secs,
            probe_passed,
            &mut checks,
        );
    } else {
        push_remote_skip(&mut checks, "gateway_status", ComponentSelection::Gateway);
    }

    Ok(make_doctor_report(args.target, checks))
}

fn run_soak(args: SoakArgs) -> Result<()> {
    let report = build_soak_report(args)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn build_soak_report(args: SoakArgs) -> Result<SoakReport> {
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

    Ok(SoakReport {
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
    })
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
        let local_components = local_components_for_session(&session);
        let local_components_running = local_components
            .iter()
            .map(|component| pid_is_running_optional(component_pid(&session, *component)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|running| running);

        if local_components_running {
            session.supervised = true;
            session.supervisor_pid = Some(process::id());
            session.supervisor_log_file = args.connect.supervisor_log_file.clone();
            save_manifest(&args.connect.session_file, &session)?;
            emit_supervisor_event(
                supervisor_log,
                "session_reused",
                None,
                "existing local-owned tunnel session is already running",
                Some(&session),
            )?;
            return Ok(());
        }

        emit_supervisor_event(
            supervisor_log,
            "session_reconcile_started",
            None,
            format!(
                "existing session is not fully running for local-owned components: {:?}",
                local_components
            ),
            Some(&session),
        )?;
        disconnect_tunnel(disconnect_args_from_connect(&args.connect))?;
    }

    emit_supervisor_event(
        supervisor_log,
        "session_connect_started",
        None,
        "starting supervised tunnel session",
        None,
    )?;
    let mut connect_args = args.connect.clone();
    match connect_args.mode {
        ProfileMode::Local => {
            connect_args.oneshot = true;
            run_connect_oneshot(connect_args)?;
        }
        ProfileMode::Remote => {
            start_remote_side_session(&connect_args)?;
        }
    }
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

fn start_remote_side_session(args: &ConnectArgs) -> Result<()> {
    let local_component = local_component_for_connect(args)?;
    preflight_side_args(args, local_component)?;
    cleanup_remote_side_state(args, local_component)?;

    let side_report = match local_component {
        ComponentSelection::Agent => run_agent_side(args.clone())?,
        ComponentSelection::Gateway => run_gateway_side(args.clone())?,
    };
    let tenant = required_connect_value(args.tenant.as_ref(), "tenant")?.to_owned();
    let attachment = required_connect_value(args.attachment.as_ref(), "attachment")?.to_owned();
    let session = SessionManifest {
        tenant,
        attachment,
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
        agent_pid: (local_component == ComponentSelection::Agent).then_some(side_report.pid),
        gateway_pid: (local_component == ComponentSelection::Gateway).then_some(side_report.pid),
        mode: ProfileMode::Remote,
        local_component: Some(local_component),
        supervised: false,
        supervisor_pid: None,
        supervisor_log_file: args.supervisor_log_file.clone(),
    };
    save_manifest(&args.session_file, &session)
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

    if repair_gateway_os_rules_if_needed(&state, gateway_config.as_ref(), session)? {
        emit_supervisor_event(
            supervisor_log,
            "gateway_os_rules_repaired",
            Some(ComponentSelection::Gateway),
            "gateway forwarding/NAT rules were missing or stale and have been re-applied",
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
    let forwarding_ok = ip_forwarding_enabled()?;
    let rules_ok = gateway_os_rules_are_healthy(&state, session)?;

    Ok(forwarding_ok && rules_ok)
}

fn inject_gateway_os_state_drift(session: &SessionManifest) -> Result<()> {
    let Some(state) = read_optional_json::<GatewayRuntimeState>(&session.gateway_state_file)?
    else {
        bail!("gateway state file is missing");
    };

    match current_target_os() {
        TargetOs::Macos => {
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
        }
        TargetOs::Linux => {
            for check in build_linux_gateway_rule_checks(&state, &session.egress_interface) {
                let _ = run_command_vec(
                    "gateway iptables drift injection",
                    linux_rule_command_with_operation(&check.command, "-D"),
                );
            }
        }
        TargetOs::Other => {}
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

fn remote_component_for(
    mode: ProfileMode,
    local_component: Option<ComponentSelection>,
) -> Option<ComponentSelection> {
    if mode != ProfileMode::Remote {
        return None;
    }

    match local_component? {
        ComponentSelection::Agent => Some(ComponentSelection::Gateway),
        ComponentSelection::Gateway => Some(ComponentSelection::Agent),
    }
}

fn component_is_locally_owned(session: &SessionManifest, component: ComponentSelection) -> bool {
    session.mode == ProfileMode::Local || session.local_component == Some(component)
}

fn local_components_for_session(session: &SessionManifest) -> Vec<ComponentSelection> {
    match session.mode {
        ProfileMode::Local => vec![ComponentSelection::Agent, ComponentSelection::Gateway],
        ProfileMode::Remote => session.local_component.into_iter().collect(),
    }
}

fn local_component_for_connect(args: &ConnectArgs) -> Result<ComponentSelection> {
    args.local_component
        .ok_or_else(|| anyhow!("remote profile requires local_component=agent or gateway"))
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
        warmup_target: String::from("1.1.1.1"),
        warmup_probe_timeout_secs: 2.0,
        warmup_settle_secs: 15,
        oneshot: false,
        supervisor_log_file: session.supervisor_log_file.clone(),
        mode: session.mode,
        local_component: session.local_component,
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

fn make_doctor_report(target: String, checks: Vec<DoctorCheck>) -> DoctorReport {
    let overall = if checks.iter().any(|check| check.state == DoctorState::Fail) {
        DoctorState::Fail
    } else if checks.iter().any(|check| check.state == DoctorState::Warn) {
        DoctorState::Warn
    } else {
        DoctorState::Pass
    };

    DoctorReport {
        overall,
        target,
        checks,
    }
}

fn check_component_process(
    session: &SessionManifest,
    component: ComponentSelection,
    checks: &mut Vec<DoctorCheck>,
) {
    let name = format!("{}_process", component_label(component));
    if !component_is_locally_owned(session, component) {
        checks.push(doctor_check(
            name,
            DoctorState::Warn,
            format!(
                "remote {} process is owned by the other host",
                component_label(component)
            ),
        ));
        return;
    }

    check_process(&name, component_pid(session, component), checks);
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

fn push_remote_skip(checks: &mut Vec<DoctorCheck>, name: &str, component: ComponentSelection) {
    checks.push(doctor_check(
        name,
        DoctorState::Warn,
        format!(
            "skipped because remote {} state is owned by the other host",
            component_label(component)
        ),
    ));
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

fn check_gateway_os_rules(
    gateway_state: Option<&GatewayRuntimeState>,
    gateway_config: Option<&TunnelConfig>,
    session_egress_interface: &str,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    match current_target_os() {
        TargetOs::Macos => check_gateway_pf_rules(
            gateway_state,
            gateway_config,
            session_egress_interface,
            checks,
        ),
        TargetOs::Linux => {
            check_gateway_linux_rules(gateway_state, session_egress_interface, checks)
        }
        TargetOs::Other => {
            checks.push(doctor_check(
                "gateway_os_rules",
                DoctorState::Warn,
                "skipped because this OS has no gateway rule inspector",
            ));
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayCommandCheck {
    name: &'static str,
    command: Vec<String>,
    pass_detail: String,
    fail_detail: String,
}

fn check_gateway_linux_rules(
    gateway_state: Option<&GatewayRuntimeState>,
    session_egress_interface: &str,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let Some(state) = gateway_state else {
        checks.push(doctor_check(
            "gateway_linux_rules",
            DoctorState::Warn,
            "skipped because gateway state is missing",
        ));
        return Ok(());
    };

    match ip_forwarding_enabled() {
        Ok(true) => checks.push(doctor_check(
            "gateway_ip_forwarding",
            DoctorState::Pass,
            "net.ipv4.ip_forward is enabled",
        )),
        Ok(false) => checks.push(doctor_check(
            "gateway_ip_forwarding",
            DoctorState::Fail,
            "net.ipv4.ip_forward is disabled",
        )),
        Err(error) => checks.push(doctor_check(
            "gateway_ip_forwarding",
            DoctorState::Fail,
            format!("failed to inspect IP forwarding: {error:#}"),
        )),
    }

    for rule_check in build_linux_gateway_rule_checks(state, session_egress_interface) {
        match command_succeeds(&rule_check.command) {
            Ok(true) => checks.push(doctor_check(
                rule_check.name,
                DoctorState::Pass,
                rule_check.pass_detail,
            )),
            Ok(false) => checks.push(doctor_check(
                rule_check.name,
                DoctorState::Fail,
                format!(
                    "{}: {}",
                    rule_check.fail_detail,
                    rule_check.command.join(" ")
                ),
            )),
            Err(error) => checks.push(doctor_check(
                rule_check.name,
                DoctorState::Fail,
                format!(
                    "failed to inspect rule with '{}': {error:#}",
                    rule_check.command.join(" ")
                ),
            )),
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

fn repair_gateway_os_rules_if_needed(
    state: &GatewayRuntimeState,
    gateway_config: Option<&TunnelConfig>,
    session: &SessionManifest,
) -> Result<bool> {
    match current_target_os() {
        TargetOs::Macos => repair_gateway_pf_rules_if_needed(state, gateway_config, session),
        TargetOs::Linux => repair_gateway_linux_rules_if_needed(state, session),
        TargetOs::Other => Ok(false),
    }
}

fn gateway_os_rules_are_healthy(
    state: &GatewayRuntimeState,
    session: &SessionManifest,
) -> Result<bool> {
    match current_target_os() {
        TargetOs::Macos => {
            let gateway_config = read_optional_json::<TunnelConfig>(&session.gateway_config)?;
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
            Ok(anchor_ok && rules_ok)
        }
        TargetOs::Linux => linux_gateway_rules_are_present(state, &session.egress_interface),
        TargetOs::Other => Ok(true),
    }
}

fn repair_gateway_linux_rules_if_needed(
    state: &GatewayRuntimeState,
    session: &SessionManifest,
) -> Result<bool> {
    let mut repaired = false;
    for check in build_linux_gateway_rule_checks(state, &session.egress_interface) {
        if !command_succeeds(&check.command)? {
            run_command_vec(
                "gateway iptables repair",
                linux_rule_command_with_operation(&check.command, "-A"),
            )?;
            repaired = true;
        }
    }
    Ok(repaired)
}

fn linux_gateway_rules_are_present(
    state: &GatewayRuntimeState,
    session_egress_interface: &str,
) -> Result<bool> {
    for check in build_linux_gateway_rule_checks(state, session_egress_interface) {
        if !command_succeeds(&check.command)? {
            return Ok(false);
        }
    }
    Ok(true)
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

fn build_linux_gateway_rule_checks(
    state: &GatewayRuntimeState,
    session_egress_interface: &str,
) -> Vec<GatewayCommandCheck> {
    let tunnel_interface = state.tunnel_interface.clone();
    let egress_interface = state
        .egress_interface
        .as_deref()
        .unwrap_or(session_egress_interface)
        .to_owned();

    vec![
        GatewayCommandCheck {
            name: "gateway_iptables_forward_in",
            command: vec![
                String::from("iptables"),
                String::from("-C"),
                String::from("FORWARD"),
                String::from("-i"),
                tunnel_interface.clone(),
                String::from("-j"),
                String::from("ACCEPT"),
            ],
            pass_detail: format!("FORWARD accepts ingress from {tunnel_interface}"),
            fail_detail: format!("missing FORWARD ingress rule for {tunnel_interface}"),
        },
        GatewayCommandCheck {
            name: "gateway_iptables_forward_established",
            command: vec![
                String::from("iptables"),
                String::from("-C"),
                String::from("FORWARD"),
                String::from("-o"),
                tunnel_interface.clone(),
                String::from("-m"),
                String::from("state"),
                String::from("--state"),
                String::from("RELATED,ESTABLISHED"),
                String::from("-j"),
                String::from("ACCEPT"),
            ],
            pass_detail: format!("FORWARD allows established return traffic to {tunnel_interface}"),
            fail_detail: format!("missing established return rule for {tunnel_interface}"),
        },
        GatewayCommandCheck {
            name: "gateway_iptables_forward_egress",
            command: vec![
                String::from("iptables"),
                String::from("-C"),
                String::from("FORWARD"),
                String::from("-i"),
                tunnel_interface.clone(),
                String::from("-o"),
                egress_interface.clone(),
                String::from("-j"),
                String::from("ACCEPT"),
            ],
            pass_detail: format!(
                "FORWARD allows {tunnel_interface} to egress on {egress_interface}"
            ),
            fail_detail: format!(
                "missing FORWARD egress rule from {tunnel_interface} to {egress_interface}"
            ),
        },
        GatewayCommandCheck {
            name: "gateway_iptables_nat",
            command: vec![
                String::from("iptables"),
                String::from("-t"),
                String::from("nat"),
                String::from("-C"),
                String::from("POSTROUTING"),
                String::from("-o"),
                egress_interface.clone(),
                String::from("-j"),
                String::from("MASQUERADE"),
            ],
            pass_detail: format!("POSTROUTING masquerades traffic on {egress_interface}"),
            fail_detail: format!("missing POSTROUTING MASQUERADE rule on {egress_interface}"),
        },
    ]
}

fn command_succeeds(command: &[String]) -> Result<bool> {
    let Some((binary, args)) = command.split_first() else {
        bail!("command is empty");
    };
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", command.join(" ")))?;
    Ok(output.status.success())
}

fn linux_rule_command_with_operation(command: &[String], operation: &str) -> Vec<String> {
    let mut command = command.to_vec();
    if let Some(flag) = command.iter_mut().find(|part| part.as_str() == "-C") {
        *flag = operation.to_owned();
    }
    command
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
        return Ok(!pid_is_zombie(pid)?);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Operation not permitted") {
        return Ok(true);
    }

    Ok(false)
}

fn pid_is_zombie(pid: u32) -> Result<bool> {
    let output = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .with_context(|| format!("failed to inspect pid {pid} state"))?;
    if !output.status.success() {
        return Ok(false);
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_start()
        .starts_with('Z'))
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

fn run_cleanup_binary_quiet(binary: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run {}", binary.display()))?;

    if !output.status.success() {
        bail!(
            "cleanup command failed for {}\nstdout: {}\nstderr: {}",
            binary.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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
    let readiness = build_connect_readiness(args);
    bail_if_not_ready(&readiness)?;
    Ok(())
}

fn preflight_side_args(args: &ConnectArgs, component: ComponentSelection) -> Result<()> {
    required_connect_value(args.tenant.as_ref(), "tenant")?;
    required_connect_value(args.attachment.as_ref(), "attachment")?;

    match component {
        ComponentSelection::Agent => validate_config_file("agent_config", &args.agent_config)?,
        ComponentSelection::Gateway => {
            validate_config_file("gateway_config", &args.gateway_config)?
        }
    }

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

fn cleanup_remote_side_state(args: &ConnectArgs, component: ComponentSelection) -> Result<()> {
    match component {
        ComponentSelection::Agent => {
            let agent_bin = sibling_binary("tunnel-agent")?;
            if args.agent_state_file.exists() {
                run_cleanup_binary_quiet(
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
        }
        ComponentSelection::Gateway => {
            let gateway_bin = sibling_binary("tunnel-gateway")?;
            if args.gateway_state_file.exists() {
                run_cleanup_binary_quiet(
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
        }
    }

    remove_stale_file("session", &args.session_file)?;
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

        if let Some(session) = session.as_ref() {
            if supervised_session_components_ready(
                args,
                supervisor_pid,
                session,
                agent_status.as_ref(),
                gateway_status.as_ref(),
                agent_state.as_ref(),
                gateway_state.as_ref(),
            ) {
                return Ok(());
            }
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

fn supervised_session_components_ready(
    args: &ConnectArgs,
    supervisor_pid: u32,
    session: &SessionManifest,
    agent_status: Option<&RuntimeStatus>,
    gateway_status: Option<&RuntimeStatus>,
    agent_state: Option<&AgentRuntimeState>,
    gateway_state: Option<&GatewayRuntimeState>,
) -> bool {
    let manifest_ready = session.supervised && session.supervisor_pid == Some(supervisor_pid);
    let runtime_ready = match session.mode {
        ProfileMode::Local => {
            session.agent_pid.is_some()
                && session.gateway_pid.is_some()
                && runtime_status_is_fresh(agent_status, args.ready_timeout_secs)
                && runtime_status_is_fresh(gateway_status, args.ready_timeout_secs)
                && agent_state.is_some()
                && gateway_state.is_some()
        }
        ProfileMode::Remote => match session.local_component {
            Some(ComponentSelection::Agent) => {
                session.agent_pid.is_some()
                    && runtime_status_is_fresh(agent_status, args.ready_timeout_secs)
                    && agent_state.is_some()
            }
            Some(ComponentSelection::Gateway) => {
                session.gateway_pid.is_some()
                    && runtime_status_is_fresh(gateway_status, args.ready_timeout_secs)
                    && gateway_state.is_some()
            }
            None => false,
        },
    };

    manifest_ready && runtime_ready
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
    write_json_file(path, manifest)
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)
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

fn terminate_pid_hard(pid: Option<u32>, label: &str) -> Result<()> {
    terminate_pid(pid)?;
    wait_for_pid_exit_or_kill(pid, label, Duration::from_secs(3))
}

fn terminate_pid_hard_except_self(pid: Option<u32>, label: &str) -> Result<()> {
    if pid == Some(process::id()) {
        return Ok(());
    }
    terminate_pid_hard(pid, label)
}

fn wait_for_pid_exit_or_kill(pid: Option<u32>, label: &str, timeout: Duration) -> Result<()> {
    let Some(pid) = pid else {
        return Ok(());
    };
    if pid == process::id() {
        return Ok(());
    }

    if wait_for_pid_exit(pid, timeout)? {
        return Ok(());
    }

    eprintln!("warning: {label} pid {pid} did not exit within {timeout:?}; sending KILL");
    let status = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .with_context(|| format!("failed to send KILL to {label} pid {pid}"))?;
    if !status.success() {
        eprintln!("warning: kill -KILL {pid} returned non-zero");
    }
    let _ = wait_for_pid_exit(pid, Duration::from_secs(1))?;
    Ok(())
}

fn wait_for_pid_exit_except_self(pid: Option<u32>, label: &str, timeout: Duration) -> Result<()> {
    let Some(pid) = pid else {
        return Ok(());
    };
    if pid == process::id() {
        return Ok(());
    }

    if wait_for_pid_exit(pid, timeout)? {
        return Ok(());
    }

    eprintln!("warning: {label} pid {pid} did not exit within {timeout:?}");
    Ok(())
}

fn wait_for_pid_exit(pid: u32, timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_running(pid)? {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(100));
    }

    Ok(false)
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

fn profile_mode_str(mode: ProfileMode) -> &'static str {
    match mode {
        ProfileMode::Local => "local",
        ProfileMode::Remote => "remote",
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
        .arg(args.ready_timeout_secs.to_string())
        .arg("--warmup-target")
        .arg(&args.warmup_target)
        .arg("--warmup-probe-timeout-secs")
        .arg(args.warmup_probe_timeout_secs.to_string())
        .arg("--warmup-settle-secs")
        .arg(args.warmup_settle_secs.to_string())
        .arg("--mode")
        .arg(profile_mode_str(args.mode));

    if let Some(local_component) = args.local_component {
        command
            .arg("--local-component")
            .arg(component_label(local_component));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn public_help_hides_profile_plumbing() {
        let mut command = Cli::command();
        let help = command.render_help().to_string();

        assert!(help.contains("login"));
        assert!(help.contains("connect"));
        assert!(!help.contains("profile"));
    }

    #[test]
    fn login_generation_creates_valid_configs_and_ready_profile() -> Result<()> {
        let root = test_root("generates-ready")?;
        let args = test_login_args(&root, true);

        let report = ensure_local_configs_for_login(&args)?;
        assert_eq!(
            report.agent_config.action,
            ConfigBootstrapActionKind::Created
        );
        assert_eq!(
            report.gateway_config.action,
            ConfigBootstrapActionKind::Created
        );
        validate_config_file("agent_config", &args.agent_config)?;
        validate_config_file("gateway_config", &args.gateway_config)?;

        write_profile_for_login(&args)?;
        let connect_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        let readiness = build_connect_readiness(&connect_args);

        assert!(readiness.ready);
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn login_generation_reuses_existing_valid_configs_without_force() -> Result<()> {
        let root = test_root("reuses-valid")?;
        let mut args = test_login_args(&root, true);
        ensure_local_configs_for_login(&args)?;
        let agent_before = fs::read_to_string(&args.agent_config)?;
        let gateway_before = fs::read_to_string(&args.gateway_config)?;

        args.force = false;
        let report = ensure_local_configs_for_login(&args)?;

        assert_eq!(
            report.agent_config.action,
            ConfigBootstrapActionKind::Reused
        );
        assert_eq!(
            report.gateway_config.action,
            ConfigBootstrapActionKind::Reused
        );
        assert_eq!(fs::read_to_string(&args.agent_config)?, agent_before);
        assert_eq!(fs::read_to_string(&args.gateway_config)?, gateway_before);
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn login_generation_preserves_invalid_existing_config_until_force() -> Result<()> {
        let root = test_root("preserves-invalid")?;
        let mut args = test_login_args(&root, false);
        fs::write(&args.agent_config, "{bad json")?;

        let report = ensure_local_configs_for_login(&args)?;
        assert_eq!(
            report.agent_config.action,
            ConfigBootstrapActionKind::PreservedInvalid
        );
        assert_eq!(fs::read_to_string(&args.agent_config)?, "{bad json");
        assert!(validate_config_file("agent_config", &args.agent_config).is_err());

        write_profile_for_login(&args)?;
        let connect_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        assert!(!build_connect_readiness(&connect_args).ready);

        args.force = true;
        let forced_report = ensure_local_configs_for_login(&args)?;
        assert_eq!(
            forced_report.agent_config.action,
            ConfigBootstrapActionKind::Overwritten
        );
        validate_config_file("agent_config", &args.agent_config)?;
        validate_config_file("gateway_config", &args.gateway_config)?;

        write_profile_for_login(&args)?;
        let forced_connect_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        assert!(build_connect_readiness(&forced_connect_args).ready);
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn connect_preflight_fails_before_launch_when_config_is_invalid() -> Result<()> {
        let root = test_root("preflight-invalid")?;
        let args = test_login_args(&root, false);
        fs::write(&args.agent_config, "{bad json")?;
        ensure_local_configs_for_login(&args)?;
        write_profile_for_login(&args)?;

        let connect_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        let error = preflight_connect_args(&connect_args)
            .expect_err("invalid config must fail preflight before launch");

        assert!(error.to_string().contains("not ready"));
        assert!(error.to_string().contains("agent_config"));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn side_preflight_only_requires_selected_component_config() -> Result<()> {
        let root = test_root("side-preflight")?;
        let args = test_login_args(&root, true);
        ensure_local_configs_for_login(&args)?;
        write_profile_for_login(&args)?;

        let agent_config = args.agent_config.clone();
        fs::remove_file(&agent_config)?;
        let gateway_only_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        preflight_side_args(&gateway_only_args, ComponentSelection::Gateway)?;
        assert!(preflight_connect_args(&gateway_only_args).is_err());

        ensure_local_configs_for_login(&args)?;
        let gateway_config = args.gateway_config.clone();
        fs::remove_file(&gateway_config)?;
        let agent_only_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        preflight_side_args(&agent_only_args, ComponentSelection::Agent)?;
        assert!(preflight_connect_args(&agent_only_args).is_err());

        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_profile_readiness_only_requires_local_component_config() -> Result<()> {
        let root = test_root("remote-profile-readiness")?;
        let args = test_login_args(&root, true);
        ensure_local_configs_for_login(&args)?;
        write_profile(ProfileInitArgs {
            profile: args.profile.clone(),
            profile_file: args.profile_file.clone(),
            tenant: args.tenant.clone(),
            attachment: args.attachment.clone(),
            agent_config: args.agent_config.clone(),
            gateway_config: args.gateway_config.clone(),
            egress_interface: args.egress_interface.clone(),
            mode: ProfileMode::Remote,
            local_component: Some(ComponentSelection::Gateway),
            force: true,
        })?;

        fs::remove_file(&args.agent_config)?;
        let connect_args = resolve_connect_args(ConnectArgs::for_profile(
            args.profile.clone(),
            args.profile_file.clone(),
        ))?;
        let readiness = build_connect_readiness(&connect_args);

        assert!(readiness.ready);
        assert_eq!(connect_args.mode, ProfileMode::Remote);
        assert_eq!(
            connect_args.local_component,
            Some(ComponentSelection::Gateway)
        );
        assert!(preflight_connect_args(&connect_args).is_ok());
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_supervised_ready_only_requires_local_component_state() -> Result<()> {
        let root = test_root("remote-supervised-ready")?;
        let mut args =
            ConnectArgs::for_profile(String::from("remote-gateway"), root.join("profiles.json"));
        args.tenant = Some(String::from("tenant"));
        args.attachment = Some(String::from("remote-gateway"));
        args.mode = ProfileMode::Remote;
        args.local_component = Some(ComponentSelection::Gateway);
        args.session_file = root.join("session.json");
        args.gateway_state_file = root.join("gateway-state.json");
        args.gateway_status_file = root.join("gateway-status.json");
        args.ready_timeout_secs = 1;

        let gateway_state = GatewayRuntimeState {
            tunnel_interface: String::from("utun-test"),
            nat_anchor_name: None,
            nat_rules_path: None,
            forwarding_was_enabled: Some(true),
            egress_interface: Some(String::from("en0")),
        };
        let gateway_status =
            runtime_status(ComponentKind::Gateway, Some(String::from("utun-test")));
        let session = SessionManifest {
            tenant: String::from("tenant"),
            attachment: String::from("remote-gateway"),
            agent_config: root.join("missing-agent.json"),
            gateway_config: root.join("gateway.json"),
            agent_state_file: root.join("missing-agent-state.json"),
            agent_status_file: root.join("missing-agent-status.json"),
            gateway_state_file: args.gateway_state_file.clone(),
            gateway_status_file: args.gateway_status_file.clone(),
            agent_log_file: root.join("agent.log"),
            gateway_log_file: root.join("gateway.log"),
            egress_interface: String::from("en0"),
            route_mode: SystemCommandMode::Apply,
            forwarding_mode: SystemCommandMode::Apply,
            nat_mode: SystemCommandMode::Apply,
            agent_pid: None,
            gateway_pid: Some(42),
            mode: ProfileMode::Remote,
            local_component: Some(ComponentSelection::Gateway),
            supervised: true,
            supervisor_pid: Some(7),
            supervisor_log_file: root.join("supervisor.log"),
        };

        assert!(supervised_session_components_ready(
            &args,
            7,
            &session,
            None,
            Some(&gateway_status),
            None,
            Some(&gateway_state),
        ));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn login_generation_supports_remote_gateway_host() -> Result<()> {
        let root = test_root("remote-gateway")?;
        let mut args = test_login_args(&root, true);
        args.gateway_host = String::from("203.0.113.10");
        args.gateway_port = 7182;
        args.destination_cidr = String::from("8.8.8.0/24");

        ensure_local_configs_for_login(&args)?;
        let agent_config: TunnelConfig =
            serde_json::from_str(&fs::read_to_string(&args.agent_config)?)?;
        let gateway_config: TunnelConfig =
            serde_json::from_str(&fs::read_to_string(&args.gateway_config)?)?;

        assert_eq!(agent_config.gateway.host, "203.0.113.10");
        assert_eq!(agent_config.gateway.port, 7182);
        assert_eq!(
            agent_config
                .wireguard
                .as_ref()
                .and_then(|wireguard| wireguard.peer_endpoint.as_ref())
                .map(|endpoint| (endpoint.host.as_str(), endpoint.port)),
            Some(("203.0.113.10", 7182))
        );
        assert_eq!(
            agent_config.route_policy.destination_cidrs,
            vec![String::from("8.8.8.0/24")]
        );
        assert_eq!(gateway_config.gateway.host, "203.0.113.10");
        assert_eq!(
            gateway_config
                .wireguard
                .as_ref()
                .map(|wireguard| wireguard.local_bind_port),
            Some(7182)
        );
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn profile_export_separates_private_keys_and_imports_side_bundle() -> Result<()> {
        let root = test_root("profile-export")?;
        let args = test_login_args(&root, true);
        ensure_local_configs_for_login(&args)?;
        write_profile_for_login(&args)?;

        let agent_config: TunnelConfig =
            serde_json::from_str(&fs::read_to_string(&args.agent_config)?)?;
        let gateway_config: TunnelConfig =
            serde_json::from_str(&fs::read_to_string(&args.gateway_config)?)?;
        let agent_private_key = agent_config
            .wireguard
            .as_ref()
            .map(|wireguard| wireguard.private_key_base64.clone())
            .expect("agent wireguard config should exist");
        let gateway_private_key = gateway_config
            .wireguard
            .as_ref()
            .map(|wireguard| wireguard.private_key_base64.clone())
            .expect("gateway wireguard config should exist");

        let out_dir = root.join("bundles");
        run_profile_export(ProfileExportArgs {
            profile: args.profile.clone(),
            profile_file: args.profile_file.clone(),
            out_dir: out_dir.clone(),
            force: true,
        })?;

        let agent_bundle_contents = read_dir_text(&out_dir.join("agent"))?;
        let gateway_bundle_contents = read_dir_text(&out_dir.join("gateway"))?;
        assert!(agent_bundle_contents.contains(&agent_private_key));
        assert!(!agent_bundle_contents.contains(&gateway_private_key));
        assert!(gateway_bundle_contents.contains(&gateway_private_key));
        assert!(!gateway_bundle_contents.contains(&agent_private_key));

        let imported_profile_file = root.join("imported-profiles.json");
        run_profile_import(ProfileImportArgs {
            bundle_dir: out_dir.join("agent"),
            profile_file: imported_profile_file.clone(),
            install_dir: root.join("installed"),
            profile: Some(String::from("imported-agent")),
            force: true,
        })?;
        let imported_connect = resolve_connect_args(ConnectArgs::for_profile(
            String::from("imported-agent"),
            imported_profile_file,
        ))?;
        assert_eq!(imported_connect.mode, ProfileMode::Remote);
        assert_eq!(
            imported_connect.local_component,
            Some(ComponentSelection::Agent)
        );
        assert!(build_connect_readiness(&imported_connect).ready);
        assert!(imported_connect.agent_config.exists());

        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_check_validates_imported_agent_gateway_profile_pair() -> Result<()> {
        let root = test_root("remote-check-imported-pair")?;
        let mut args = test_login_args(&root, true);
        args.gateway_host = String::from("203.0.113.10");
        ensure_local_configs_for_login(&args)?;
        write_profile_for_login(&args)?;

        let out_dir = root.join("bundles");
        run_profile_export(ProfileExportArgs {
            profile: args.profile.clone(),
            profile_file: args.profile_file.clone(),
            out_dir: out_dir.clone(),
            force: true,
        })?;

        let agent_profile_file = root.join("agent-profiles.json");
        let gateway_profile_file = root.join("gateway-profiles.json");
        run_profile_import(ProfileImportArgs {
            bundle_dir: out_dir.join("agent"),
            profile_file: agent_profile_file.clone(),
            install_dir: root.join("agent-install"),
            profile: Some(String::from("agent-side")),
            force: true,
        })?;
        run_profile_import(ProfileImportArgs {
            bundle_dir: out_dir.join("gateway"),
            profile_file: gateway_profile_file.clone(),
            install_dir: root.join("gateway-install"),
            profile: Some(String::from("gateway-side")),
            force: true,
        })?;

        let report = build_remote_check_report(RemoteCheckArgs {
            profile: String::from("agent-side"),
            profile_file: agent_profile_file,
            peer_profile: Some(String::from("gateway-side")),
            peer_profile_file: Some(gateway_profile_file),
            gateway_host: Some(String::from("203.0.113.10")),
            gateway_port: Some(7000),
            udp_probe: false,
            udp_probe_timeout_secs: 0.1,
        })?;

        assert_eq!(report.overall, DoctorState::Pass);
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "profile_pair" && check.state == DoctorState::Pass));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_plan_exports_bundles_and_operator_commands() -> Result<()> {
        let root = test_root("remote-plan")?;
        let report = build_remote_plan_report(RemotePlanArgs {
            profile: String::from("remote-prod"),
            profile_file: root.join("profiles.json"),
            tenant: String::from("tenant"),
            attachment: Some(String::from("attachment")),
            agent_config: root.join("agent.json"),
            gateway_config: root.join("gateway.json"),
            gateway_host: String::from("203.0.113.10"),
            gateway_port: 7000,
            destination_cidr: String::from("1.1.1.0/24"),
            agent_tunnel_address: String::from("10.201.0.2"),
            gateway_tunnel_address: String::from("10.201.0.1"),
            egress_interface: String::from("eth0"),
            out_dir: root.join("bundles"),
            agent_profile: String::from("agent-prod"),
            gateway_profile: String::from("gateway-prod"),
            remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
            remote_install_dir: PathBuf::from("/private/tmp"),
            agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
            gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
            agent_ssh_host: Some(String::from("agent.example")),
            gateway_ssh_host: Some(String::from("gateway.example")),
            smoke_target: String::from("1.1.1.1"),
            smoke_count: 10,
            force: true,
        })?;

        assert!(report.readiness.ready);
        assert_eq!(report.remote_check.overall, DoctorState::Pass);
        assert!(report.agent_bundle.join("tunnel-bundle.json").exists());
        assert!(report.gateway_bundle.join("tunnel-bundle.json").exists());
        assert!(report.commands.copy_agent_bundle.is_some());
        assert!(report.commands.copy_gateway_bundle.is_some());
        assert!(report
            .commands
            .agent_smoke_test
            .contains("remote-smoke-test agent-prod"));
        assert!(report
            .next
            .iter()
            .any(|step| step.contains("gateway host:")));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_runs_plan_steps_over_ssh_and_scp() -> Result<()> {
        let root = test_root("remote-deploy")?;
        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: String::from("true"),
            scp_bin: String::from("true"),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: false,
            require_host_preflight: false,
            report_file: None,
            no_rollback: false,
        })?;

        assert_eq!(report.overall, DoctorState::Pass);
        assert!(!report.dry_run);
        assert_eq!(report.ssh_timeout_secs, 10);
        assert_eq!(report.step_timeout_secs, 120);
        assert_eq!(report.agent_host, "agent.example");
        assert_eq!(report.gateway_host, "gateway.example");
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "copy_agent_bundle"
                && step.state == DoctorState::Pass
                && step.command.contains("ConnectTimeout=10")));
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "gateway_connect"
                && step
                    .command
                    .contains("sudo -n tunnel-cli connect gateway-prod")));
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "agent_smoke_test"
                && step
                    .command
                    .contains("sudo -n tunnel-cli remote-smoke-test agent-prod")));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_times_out_hung_remote_step() -> Result<()> {
        let root = test_root("remote-deploy-timeout")?;
        let fake_bin = root.join("sleepy-ssh-scp");
        write_sleeping_remote_deploy_binary(&fake_bin, 5)?;

        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&fake_bin),
            scp_bin: path_display(&fake_bin),
            ssh_timeout_secs: 1,
            step_timeout_secs: 1,
            dry_run: false,
            require_host_preflight: false,
            report_file: None,
            no_rollback: false,
        })?;

        assert_eq!(report.overall, DoctorState::Fail);
        assert_eq!(report.ssh_timeout_secs, 1);
        assert_eq!(report.step_timeout_secs, 1);
        assert!(report.steps.iter().any(|step| {
            step.name == "gateway_prepare_bundle_dir"
                && step.state == DoctorState::Fail
                && step.exit_code.is_none()
                && step.detail.contains("timed out")
        }));
        assert!(!report
            .steps
            .iter()
            .any(|step| step.name == "copy_gateway_bundle"));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_rolls_back_started_sides_after_smoke_failure() -> Result<()> {
        let root = test_root("remote-deploy-rollback")?;
        let fake_bin = root.join("fake-ssh-scp");
        write_fake_remote_deploy_binary(&fake_bin, "remote-smoke-test")?;

        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&fake_bin),
            scp_bin: path_display(&fake_bin),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: false,
            require_host_preflight: false,
            report_file: None,
            no_rollback: false,
        })?;

        assert_eq!(report.overall, DoctorState::Fail);
        assert!(report.rollback_on_fail);
        assert!(report.rollback_attempted);
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "agent_smoke_test" && step.state == DoctorState::Fail));
        assert!(report.steps.iter().any(|step| {
            step.name == "rollback_agent_disconnect"
                && step
                    .command
                    .contains("sudo -n tunnel-cli disconnect agent-prod")
        }));
        assert!(report.steps.iter().any(|step| {
            step.name == "rollback_gateway_disconnect"
                && step
                    .command
                    .contains("sudo -n tunnel-cli disconnect gateway-prod")
        }));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_no_rollback_leaves_failure_for_debugging() -> Result<()> {
        let root = test_root("remote-deploy-no-rollback")?;
        let fake_bin = root.join("fake-ssh-scp");
        write_fake_remote_deploy_binary(&fake_bin, "remote-smoke-test")?;

        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&fake_bin),
            scp_bin: path_display(&fake_bin),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: false,
            require_host_preflight: false,
            report_file: None,
            no_rollback: true,
        })?;

        assert_eq!(report.overall, DoctorState::Fail);
        assert!(!report.rollback_on_fail);
        assert!(!report.rollback_attempted);
        assert!(!report
            .steps
            .iter()
            .any(|step| step.name.starts_with("rollback_")));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_dry_run_plans_steps_without_executing_remote_commands() -> Result<()> {
        let root = test_root("remote-deploy-dry-run")?;
        let missing_bin = root.join("definitely-not-a-real-command");

        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&missing_bin),
            scp_bin: path_display(&missing_bin),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: true,
            require_host_preflight: false,
            report_file: None,
            no_rollback: false,
        })?;

        assert_eq!(report.overall, DoctorState::Warn);
        assert!(report.dry_run);
        assert!(report.rollback_on_fail);
        assert!(!report.rollback_attempted);
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "operator_remote_check" && step.state == DoctorState::Pass));
        assert!(report
            .steps
            .iter()
            .filter(|step| step.name != "operator_remote_check")
            .all(|step| step.state == DoctorState::Warn
                && step
                    .detail
                    .contains("dry-run planned; command was not executed")));
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "agent_smoke_test"
                && step
                    .command
                    .contains("sudo -n tunnel-cli remote-smoke-test agent-prod")));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_writes_report_file() -> Result<()> {
        let root = test_root("remote-deploy-report-file")?;
        let missing_bin = root.join("definitely-not-a-real-command");
        let report_file = root.join("reports").join("deploy-report.json");

        run_remote_deploy(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&missing_bin),
            scp_bin: path_display(&missing_bin),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: true,
            require_host_preflight: true,
            report_file: Some(report_file.clone()),
            no_rollback: false,
        })?;

        let report: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report_file)?)?;
        assert_eq!(report["profile"], "remote-prod");
        assert_eq!(report["dry_run"], true);
        assert_eq!(report["require_host_preflight"], true);
        let steps = report["steps"]
            .as_array()
            .expect("steps should be an array");
        assert!(steps
            .iter()
            .any(|step| step["name"] == "gateway_host_preflight"));
        assert!(steps.iter().any(|step| step["name"] == "agent_smoke_test"));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_host_preflight_failure_stops_before_mutation() -> Result<()> {
        let root = test_root("remote-deploy-preflight-fail")?;
        let fake_bin = root.join("fake-ssh-scp");
        write_fake_remote_deploy_binary(&fake_bin, "iptables")?;

        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&fake_bin),
            scp_bin: path_display(&fake_bin),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: false,
            require_host_preflight: true,
            report_file: None,
            no_rollback: false,
        })?;

        assert_eq!(report.overall, DoctorState::Fail);
        assert!(report.require_host_preflight);
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "gateway_host_preflight" && step.state == DoctorState::Fail));
        assert!(!report.steps.iter().any(|step| {
            step.name == "copy_gateway_bundle"
                || step.name == "gateway_import"
                || step.name == "gateway_connect"
        }));
        assert!(!report.rollback_attempted);
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn remote_deploy_dry_run_includes_host_preflight_without_execution() -> Result<()> {
        let root = test_root("remote-deploy-preflight-dry-run")?;
        let missing_bin = root.join("definitely-not-a-real-command");

        let report = build_remote_deploy_report(RemoteDeployArgs {
            plan: RemotePlanArgs {
                profile: String::from("remote-prod"),
                profile_file: root.join("profiles.json"),
                tenant: String::from("tenant"),
                attachment: Some(String::from("attachment")),
                agent_config: root.join("agent.json"),
                gateway_config: root.join("gateway.json"),
                gateway_host: String::from("203.0.113.10"),
                gateway_port: 7000,
                destination_cidr: String::from("1.1.1.0/24"),
                agent_tunnel_address: String::from("10.201.0.2"),
                gateway_tunnel_address: String::from("10.201.0.1"),
                egress_interface: String::from("eth0"),
                out_dir: root.join("bundles"),
                agent_profile: String::from("agent-prod"),
                gateway_profile: String::from("gateway-prod"),
                remote_profile_file: PathBuf::from("/private/tmp/tunnel-profiles.json"),
                remote_install_dir: PathBuf::from("/private/tmp"),
                agent_remote_bundle_dir: PathBuf::from("/tmp/tunnel-agent-bundle"),
                gateway_remote_bundle_dir: PathBuf::from("/tmp/tunnel-gateway-bundle"),
                agent_ssh_host: Some(String::from("agent.example")),
                gateway_ssh_host: Some(String::from("gateway.example")),
                smoke_target: String::from("1.1.1.1"),
                smoke_count: 10,
                force: true,
            },
            ssh_bin: path_display(&missing_bin),
            scp_bin: path_display(&missing_bin),
            ssh_timeout_secs: 10,
            step_timeout_secs: 120,
            dry_run: true,
            require_host_preflight: true,
            report_file: None,
            no_rollback: false,
        })?;

        assert_eq!(report.overall, DoctorState::Warn);
        assert!(report.dry_run);
        assert!(report.require_host_preflight);
        assert!(report.steps.iter().any(|step| {
            step.name == "gateway_host_preflight"
                && step.state == DoctorState::Warn
                && step.command.contains("command -v iptables")
        }));
        assert!(report.steps.iter().any(|step| {
            step.name == "agent_host_preflight"
                && step.state == DoctorState::Warn
                && step.command.contains("ip route get")
        }));
        remove_test_root(root);
        Ok(())
    }

    #[test]
    fn linux_gateway_rule_checks_match_runtime_commands() {
        let state = GatewayRuntimeState {
            tunnel_interface: String::from("tun0"),
            nat_anchor_name: None,
            nat_rules_path: None,
            forwarding_was_enabled: Some(false),
            egress_interface: Some(String::from("eth0")),
        };

        let checks = build_linux_gateway_rule_checks(&state, "ignored0");
        let commands = checks
            .iter()
            .map(|check| check.command.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            commands,
            vec![
                vec!["iptables", "-C", "FORWARD", "-i", "tun0", "-j", "ACCEPT"],
                vec![
                    "iptables",
                    "-C",
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
                vec!["iptables", "-C", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT",],
                vec![
                    "iptables",
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-o",
                    "eth0",
                    "-j",
                    "MASQUERADE",
                ],
            ]
            .into_iter()
            .map(string_vec)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn linux_rule_operation_rewrites_check_commands() {
        let command = string_vec(vec![
            "iptables",
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-o",
            "eth0",
            "-j",
            "MASQUERADE",
        ]);

        assert_eq!(
            linux_rule_command_with_operation(&command, "-A"),
            string_vec(vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                "eth0",
                "-j",
                "MASQUERADE",
            ])
        );
        assert_eq!(
            linux_rule_command_with_operation(&command, "-D"),
            string_vec(vec![
                "iptables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                "eth0",
                "-j",
                "MASQUERADE",
            ])
        );
    }

    fn test_login_args(root: &Path, force: bool) -> LoginArgs {
        LoginArgs {
            profile: String::from("test-dev"),
            profile_file: root.join("profiles.json"),
            tenant: String::from("test-tenant"),
            attachment: Some(String::from("test-attachment")),
            agent_config: root.join("agent.json"),
            gateway_config: root.join("gateway.json"),
            gateway_host: String::from("127.0.0.1"),
            gateway_port: 7000,
            destination_cidr: String::from("1.1.1.0/24"),
            agent_tunnel_address: String::from("10.201.0.2"),
            gateway_tunnel_address: String::from("10.201.0.1"),
            egress_interface: String::from("en0"),
            mode: None,
            local_component: None,
            force,
        }
    }

    fn write_profile_for_login(args: &LoginArgs) -> Result<()> {
        write_profile(ProfileInitArgs {
            profile: args.profile.clone(),
            profile_file: args.profile_file.clone(),
            tenant: args.tenant.clone(),
            attachment: args.attachment.clone(),
            agent_config: args.agent_config.clone(),
            gateway_config: args.gateway_config.clone(),
            egress_interface: args.egress_interface.clone(),
            mode: ProfileMode::Local,
            local_component: None,
            force: true,
        })
    }

    fn test_root(name: &str) -> Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = env::temp_dir().join(format!("tunnel-cli-{name}-{}-{nanos}", process::id()));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn remove_test_root(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }

    fn read_dir_text(path: &Path) -> Result<String> {
        let mut combined = String::new();
        for entry in
            fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                combined.push_str(&fs::read_to_string(entry.path())?);
                combined.push('\n');
            }
        }
        Ok(combined)
    }

    fn write_fake_remote_deploy_binary(path: &Path, fail_when_contains: &str) -> Result<()> {
        let script = format!(
            "#!/bin/sh\ncase \"$*\" in\n  *{}*) exit 42 ;;\n  *) exit 0 ;;\nesac\n",
            fail_when_contains
        );
        fs::write(path, script)?;
        let mut permissions = fs::metadata(path)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }

    fn write_sleeping_remote_deploy_binary(path: &Path, sleep_secs: u64) -> Result<()> {
        let script = format!("#!/bin/sh\nsleep {sleep_secs}\nexit 0\n");
        fs::write(path, script)?;
        let mut permissions = fs::metadata(path)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }

    fn string_vec(parts: Vec<&str>) -> Vec<String> {
        parts.into_iter().map(String::from).collect()
    }
}
