#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

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

        Ok(())
    }
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
