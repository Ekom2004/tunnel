#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tunnel_shared::{
    AgentRuntimeState, GatewayRuntimeState, HealthState, RuntimeStatus, TunnelPhase,
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
    Connect(ConnectArgs),
    Status(StatusArgs),
    Disconnect(DisconnectArgs),
    Usage(StatusArgs),
    Restart(RestartArgs),
    Soak(SoakArgs),
}

#[derive(Debug, Args, Clone)]
struct ConnectArgs {
    #[arg(long)]
    tenant: String,
    #[arg(long)]
    attachment: String,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-wg.json")]
    gateway_config: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-state.json")]
    agent_state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-status.json")]
    agent_status_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-state.json")]
    gateway_state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-status.json")]
    gateway_status_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, default_value = "en0")]
    egress_interface: String,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Apply)]
    route_mode: SystemCommandMode,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Apply)]
    forwarding_mode: SystemCommandMode,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Apply)]
    nat_mode: SystemCommandMode,
}

#[derive(Debug, Args, Clone)]
struct StatusArgs {
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-state.json")]
    agent_state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-status.json")]
    agent_status_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-state.json")]
    gateway_state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-status.json")]
    gateway_status_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
}

#[derive(Debug, Args, Clone)]
struct DisconnectArgs {
    #[arg(long, default_value = "/private/tmp/tunnel-agent-wg.json")]
    agent_config: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-state.json")]
    agent_state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-agent-status.json")]
    agent_status_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-state.json")]
    gateway_state_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-gateway-status.json")]
    gateway_status_file: PathBuf,
    #[arg(long, default_value = "/private/tmp/tunnel-session.json")]
    session_file: PathBuf,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Apply)]
    route_mode: SystemCommandMode,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Apply)]
    forwarding_mode: SystemCommandMode,
    #[arg(long, value_enum, default_value_t = SystemCommandMode::Apply)]
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
    egress_interface: String,
    route_mode: SystemCommandMode,
    forwarding_mode: SystemCommandMode,
    nat_mode: SystemCommandMode,
    agent_pid: Option<u32>,
    gateway_pid: Option<u32>,
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
#[serde(rename_all = "snake_case")]
enum FailureDomain {
    None,
    ProbeNeverEnteredTunnel,
    TransportOrPeerLiveness,
    GatewayEgressOrReturnPath,
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
        CommandKind::Soak(args) => run_soak(args)?,
    }

    Ok(())
}

fn run_connect(args: ConnectArgs) -> Result<()> {
    let gateway_bin = sibling_binary("tunnel-gateway")?;
    let agent_bin = sibling_binary("tunnel-agent")?;

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
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let gateway_child = gateway
        .spawn()
        .with_context(|| format!("failed to spawn {}", gateway_bin.display()))?;

    thread::sleep(Duration::from_millis(750));

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
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let agent_child = agent
        .spawn()
        .with_context(|| format!("failed to spawn {}", agent_bin.display()))?;

    let manifest = SessionManifest {
        tenant: args.tenant.clone(),
        attachment: args.attachment.clone(),
        agent_config: args.agent_config.clone(),
        gateway_config: args.gateway_config.clone(),
        agent_state_file: args.agent_state_file.clone(),
        agent_status_file: args.agent_status_file.clone(),
        gateway_state_file: args.gateway_state_file.clone(),
        gateway_status_file: args.gateway_status_file.clone(),
        egress_interface: args.egress_interface.clone(),
        route_mode: args.route_mode,
        forwarding_mode: args.forwarding_mode,
        nat_mode: args.nat_mode,
        agent_pid: Some(agent_child.id()),
        gateway_pid: Some(gateway_child.id()),
    };
    save_manifest(&args.session_file, &manifest)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "tenant": args.tenant,
            "attachment": args.attachment,
            "gateway_pid": gateway_child.id(),
            "agent_pid": agent_child.id(),
            "agent_status_file": args.agent_status_file,
            "gateway_status_file": args.gateway_status_file,
            "session_file": args.session_file,
        }))?
    );

    Ok(())
}

fn run_status(args: StatusArgs) -> Result<()> {
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

fn run_disconnect(args: DisconnectArgs) -> Result<()> {
    let session = read_optional_json::<SessionManifest>(&args.session_file)?;
    if let Some(session) = &session {
        terminate_pid(session.agent_pid)?;
        terminate_pid(session.gateway_pid)?;
    }

    let agent_bin = sibling_binary("tunnel-agent")?;
    let gateway_bin = sibling_binary("tunnel-gateway")?;

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
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .with_context(|| format!("failed to respawn {}", agent_bin.display()))?;
            session.agent_pid = Some(child.id());
        }
        ComponentSelection::Gateway => {
            terminate_pid(session.gateway_pid)?;
            thread::sleep(Duration::from_millis(500));
            let gateway_bin = sibling_binary("tunnel-gateway")?;
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
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .with_context(|| format!("failed to respawn {}", gateway_bin.display()))?;
            session.gateway_pid = Some(child.id());
        }
    }

    Ok(())
}

fn ping_once(target: &str, timeout_secs: f64) -> Result<Option<f64>> {
    #[cfg(target_os = "macos")]
    let output = Command::new("ping")
        .args([
            "-n",
            "-c",
            "1",
            "-W",
            &timeout_millis_arg(timeout_secs),
            target,
        ])
        .output()
        .with_context(|| format!("failed to ping {target}"))?;

    #[cfg(target_os = "linux")]
    let output = Command::new("ping")
        .args([
            "-n",
            "-c",
            "1",
            "-W",
            &timeout_secs_arg(timeout_secs),
            target,
        ])
        .output()
        .with_context(|| format!("failed to ping {target}"))?;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let output = Command::new("ping")
        .args(["-c", "1", target])
        .output()
        .with_context(|| format!("failed to ping {target}"))?;

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
