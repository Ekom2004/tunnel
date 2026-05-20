#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelConfig {
    pub tenant_id: String,
    pub tunnel_id: String,
    pub gateway: GatewayEndpoint,
    pub route_policy: RoutePolicy,
    pub heartbeat_interval_secs: u64,
    pub max_chunk_bytes: usize,
    pub wireguard: Option<WireGuardConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutePolicy {
    pub traffic_class: TrafficClass,
    pub destination_cidrs: Vec<String>,
    pub routing_mark: u32,
    #[serde(default)]
    pub allow_full_tunnel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrafficClass {
    BulkExport,
    Backup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageRecord {
    pub tenant_id: String,
    pub tunnel_id: String,
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
    pub observed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub local_bind_host: String,
    pub local_bind_port: u16,
    pub peer_endpoint: Option<SocketEndpoint>,
    pub local_tunnel_address: String,
    pub peer_tunnel_address: String,
    pub private_key_base64: String,
    pub peer_public_key_base64: String,
    pub preshared_key_base64: Option<String>,
    pub persistent_keepalive_secs: Option<u16>,
    pub role: WireGuardRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub component: ComponentKind,
    pub state: HealthState,
    pub phase: TunnelPhase,
    pub tenant_id: Option<String>,
    pub tunnel_id: Option<String>,
    pub transport: TransportKind,
    pub tunnel_interface: Option<String>,
    pub peer_endpoint: Option<String>,
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
    pub last_ingress_at_unix_secs: Option<u64>,
    pub last_egress_at_unix_secs: Option<u64>,
    pub last_peer_activity_unix_secs: Option<u64>,
    pub last_activity_unix_secs: Option<u64>,
    #[serde(default)]
    pub packet_path: PacketPathTelemetry,
    pub observed_at_unix_secs: u64,
    pub detail: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketPathTelemetry {
    pub tun_read_packets: u64,
    pub tun_read_bytes: u64,
    pub tun_write_packets: u64,
    pub tun_write_bytes: u64,
    pub udp_rx_packets: u64,
    pub udp_rx_bytes: u64,
    pub udp_tx_packets: u64,
    pub udp_tx_bytes: u64,
    pub wireguard_encapsulated_packets: u64,
    pub wireguard_decapsulated_packets: u64,
    pub last_packet_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRuntimeState {
    pub tunnel_interface: String,
    pub destination_cidrs: Vec<String>,
    #[serde(default)]
    pub rp_filter: Option<AgentRpFilterState>,
    #[serde(default)]
    pub fallback_routes: Vec<AgentFallbackRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRpFilterState {
    pub all: Option<u8>,
    pub default: Option<u8>,
    pub tunnel_interface: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentFallbackRoute {
    pub cidr: String,
    pub probe_target: String,
    pub fallback_interface: Option<String>,
    pub fallback_gateway: Option<String>,
    #[serde(default)]
    pub exact_route: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRuntimeState {
    pub tunnel_interface: String,
    pub nat_anchor_name: Option<String>,
    pub nat_rules_path: Option<std::path::PathBuf>,
    pub forwarding_was_enabled: Option<bool>,
    pub egress_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WireGuardRole {
    Agent,
    Gateway,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportKind {
    JsonTcp,
    WireGuardUdp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelPhase {
    Establishing,
    Recovering,
    Active,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToGateway {
    SessionOpen {
        tenant_id: String,
        tunnel_id: String,
    },
    Heartbeat {
        observed_at_unix_secs: u64,
    },
    Payload {
        sequence: u64,
        bytes: Vec<u8>,
    },
    SessionClose,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayToAgent {
    Health { status: HealthStatus },
    Ack { sequence: u64, usage: UsageRecord },
    Payload { sequence: u64, bytes: Vec<u8> },
    FinalUsage { usage: UsageRecord },
    Error { detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthStatus {
    pub component: ComponentKind,
    pub state: HealthState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComponentKind {
    Agent,
    ControlPlane,
    Gateway,
    Tunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("gateway host must not be empty")]
    EmptyGatewayHost,
    #[error("at least one destination CIDR is required")]
    EmptyDestinationCidrs,
    #[error("destination CIDR {cidr} is not allowed: {reason}")]
    InvalidDestinationCidr { cidr: String, reason: String },
    #[error("heartbeat interval must be greater than zero")]
    InvalidHeartbeatInterval,
    #[error("max chunk bytes must be greater than zero")]
    InvalidChunkSize,
    #[error("tunnel id must not be empty")]
    EmptyTunnelId,
    #[error("tenant id must not be empty")]
    EmptyTenantId,
    #[error("wireguard local bind host must not be empty")]
    EmptyWireGuardBindHost,
    #[error("wireguard local tunnel address must not be empty")]
    EmptyWireGuardTunnelAddress,
    #[error("wireguard peer tunnel address must not be empty")]
    EmptyWireGuardPeerTunnelAddress,
    #[error("wireguard peer endpoint host must not be empty when configured")]
    EmptyWireGuardPeerEndpointHost,
    #[error("wireguard private key is invalid")]
    InvalidWireGuardPrivateKey,
    #[error("wireguard peer public key is invalid")]
    InvalidWireGuardPeerPublicKey,
    #[error("wireguard preshared key is invalid")]
    InvalidWireGuardPresharedKey,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl TunnelConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.tenant_id.trim().is_empty() {
            return Err(ConfigError::EmptyTenantId);
        }

        if self.tunnel_id.trim().is_empty() {
            return Err(ConfigError::EmptyTunnelId);
        }

        if self.gateway.host.trim().is_empty() {
            return Err(ConfigError::EmptyGatewayHost);
        }

        if self.route_policy.destination_cidrs.is_empty() {
            return Err(ConfigError::EmptyDestinationCidrs);
        }
        self.route_policy.validate()?;

        if self.heartbeat_interval_secs == 0 {
            return Err(ConfigError::InvalidHeartbeatInterval);
        }

        if self.max_chunk_bytes == 0 {
            return Err(ConfigError::InvalidChunkSize);
        }

        if let Some(wireguard) = &self.wireguard {
            wireguard.validate()?;
        }

        Ok(())
    }
}

impl RoutePolicy {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.destination_cidrs.is_empty() {
            return Err(ConfigError::EmptyDestinationCidrs);
        }

        for cidr in &self.destination_cidrs {
            validate_destination_cidr(cidr, self.allow_full_tunnel)?;
        }

        Ok(())
    }
}

impl WireGuardConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.local_bind_host.trim().is_empty() {
            return Err(ConfigError::EmptyWireGuardBindHost);
        }

        if self.local_tunnel_address.trim().is_empty() {
            return Err(ConfigError::EmptyWireGuardTunnelAddress);
        }

        if self.peer_tunnel_address.trim().is_empty() {
            return Err(ConfigError::EmptyWireGuardPeerTunnelAddress);
        }

        if let Some(endpoint) = &self.peer_endpoint {
            if endpoint.host.trim().is_empty() {
                return Err(ConfigError::EmptyWireGuardPeerEndpointHost);
            }
        }

        decode_key_32_raw(&self.private_key_base64)
            .map_err(|_| ConfigError::InvalidWireGuardPrivateKey)?;
        decode_key_32_raw(&self.peer_public_key_base64)
            .map_err(|_| ConfigError::InvalidWireGuardPeerPublicKey)?;

        if let Some(key) = &self.preshared_key_base64 {
            decode_key_32_raw(key).map_err(|_| ConfigError::InvalidWireGuardPresharedKey)?;
        }

        Ok(())
    }
}

pub fn decode_key_32(value: &str) -> Result<[u8; 32], ConfigError> {
    decode_key_32_raw(value).map_err(|_| ConfigError::InvalidWireGuardPrivateKey)
}

pub fn encode_key_32(value: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn decode_key_32_raw(
    value: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync + 'static>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(value)?;
    Ok(bytes.as_slice().try_into()?)
}

fn validate_destination_cidr(cidr: &str, allow_full_tunnel: bool) -> Result<(), ConfigError> {
    let cidr = cidr.trim();
    let (addr, prefix) =
        parse_destination_cidr(cidr).map_err(|reason| ConfigError::InvalidDestinationCidr {
            cidr: cidr.to_owned(),
            reason,
        })?;

    let reason = match addr {
        IpAddr::V4(addr) => validate_ipv4_route(addr, prefix, allow_full_tunnel),
        IpAddr::V6(addr) => validate_ipv6_route(addr, prefix, allow_full_tunnel),
    };

    if let Some(reason) = reason {
        return Err(ConfigError::InvalidDestinationCidr {
            cidr: cidr.to_owned(),
            reason,
        });
    }

    Ok(())
}

fn parse_destination_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| String::from("CIDR must include a prefix length"))?;
    if addr.trim() != addr || prefix.trim() != prefix {
        return Err(String::from("CIDR must not contain surrounding whitespace"));
    }

    let addr = addr
        .parse::<IpAddr>()
        .map_err(|_| String::from("invalid IP address"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| String::from("invalid prefix length"))?;

    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(format!("prefix length must be <= {max_prefix}"));
    }

    Ok((addr, prefix))
}

fn validate_ipv4_route(addr: Ipv4Addr, prefix: u8, allow_full_tunnel: bool) -> Option<String> {
    if prefix == 0 {
        return (!allow_full_tunnel || addr != Ipv4Addr::UNSPECIFIED)
            .then(|| String::from("full-tunnel route requires allow_full_tunnel=true"));
    }
    if addr.is_unspecified() {
        return Some(String::from("unspecified address ranges are not routable"));
    }
    if addr.is_loopback() {
        return Some(String::from(
            "loopback ranges must not be routed through Tunnel",
        ));
    }
    if addr.is_multicast() {
        return Some(String::from(
            "multicast ranges must not be routed through Tunnel",
        ));
    }
    if addr.is_link_local() {
        return Some(String::from(
            "link-local ranges must not be routed through Tunnel",
        ));
    }
    if !is_ipv4_network_address(addr, prefix) {
        return Some(String::from("CIDR address must be the network address"));
    }
    None
}

fn validate_ipv6_route(addr: Ipv6Addr, prefix: u8, allow_full_tunnel: bool) -> Option<String> {
    if prefix == 0 {
        return (!allow_full_tunnel || addr != Ipv6Addr::UNSPECIFIED)
            .then(|| String::from("full-tunnel route requires allow_full_tunnel=true"));
    }
    if addr.is_unspecified() {
        return Some(String::from("unspecified address ranges are not routable"));
    }
    if addr.is_loopback() {
        return Some(String::from(
            "loopback ranges must not be routed through Tunnel",
        ));
    }
    if addr.is_multicast() {
        return Some(String::from(
            "multicast ranges must not be routed through Tunnel",
        ));
    }
    if addr.is_unicast_link_local() {
        return Some(String::from(
            "link-local ranges must not be routed through Tunnel",
        ));
    }
    if !is_ipv6_network_address(addr, prefix) {
        return Some(String::from("CIDR address must be the network address"));
    }
    None
}

fn is_ipv4_network_address(addr: Ipv4Addr, prefix: u8) -> bool {
    let value = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    value & !mask == 0
}

fn is_ipv6_network_address(addr: Ipv6Addr, prefix: u8) -> bool {
    let value = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    value & !mask == 0
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<(), ProtocolError>
where
    W: Write,
    T: Serialize,
{
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

pub fn read_json_line<R, T>(reader: &mut R) -> Result<Option<T>, ProtocolError>
where
    R: BufRead,
    T: DeserializeOwned,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }

    let value = serde_json::from_str(line.trim_end())?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_happy_path() {
        let config = TunnelConfig {
            tenant_id: String::from("tenant-a"),
            tunnel_id: String::from("tunnel-a"),
            gateway: GatewayEndpoint {
                host: String::from("127.0.0.1"),
                port: 7000,
            },
            route_policy: RoutePolicy {
                traffic_class: TrafficClass::BulkExport,
                destination_cidrs: vec![String::from("10.0.0.0/8")],
                routing_mark: 100,
                allow_full_tunnel: false,
            },
            heartbeat_interval_secs: 5,
            max_chunk_bytes: 4096,
            wireguard: None,
        };

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn rejects_zero_chunk_size() {
        let config = TunnelConfig {
            tenant_id: String::from("tenant-a"),
            tunnel_id: String::from("tunnel-a"),
            gateway: GatewayEndpoint {
                host: String::from("127.0.0.1"),
                port: 7000,
            },
            route_policy: RoutePolicy {
                traffic_class: TrafficClass::BulkExport,
                destination_cidrs: vec![String::from("10.0.0.0/8")],
                routing_mark: 100,
                allow_full_tunnel: false,
            },
            heartbeat_interval_secs: 5,
            max_chunk_bytes: 0,
            wireguard: None,
        };

        assert_eq!(config.validate(), Err(ConfigError::InvalidChunkSize));
    }

    #[test]
    fn rejects_invalid_and_dangerous_destination_cidrs() {
        for cidr in [
            "not-a-cidr",
            "1.1.1.1/24",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "::1/128",
            "fe80::/10",
            "ff00::/8",
            "0.0.0.0/0",
        ] {
            let policy = RoutePolicy {
                traffic_class: TrafficClass::BulkExport,
                destination_cidrs: vec![String::from(cidr)],
                routing_mark: 100,
                allow_full_tunnel: false,
            };

            assert!(
                matches!(
                    policy.validate(),
                    Err(ConfigError::InvalidDestinationCidr { .. })
                ),
                "{cidr} should be rejected"
            );
        }
    }

    #[test]
    fn allows_explicit_full_tunnel_destination_cidr() {
        let policy = RoutePolicy {
            traffic_class: TrafficClass::BulkExport,
            destination_cidrs: vec![String::from("0.0.0.0/0")],
            routing_mark: 100,
            allow_full_tunnel: true,
        };

        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn round_trips_protocol_message() {
        let message = AgentToGateway::Heartbeat {
            observed_at_unix_secs: 123,
        };
        let mut buf = Vec::new();
        write_json_line(&mut buf, &message).expect("write should work");

        let mut reader = std::io::BufReader::new(buf.as_slice());
        let decoded: AgentToGateway = read_json_line(&mut reader)
            .expect("read should work")
            .expect("message should exist");

        assert_eq!(decoded, message);
    }
}
