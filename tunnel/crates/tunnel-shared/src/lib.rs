#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
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
            },
            heartbeat_interval_secs: 5,
            max_chunk_bytes: 0,
            wireguard: None,
        };

        assert_eq!(config.validate(), Err(ConfigError::InvalidChunkSize));
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
