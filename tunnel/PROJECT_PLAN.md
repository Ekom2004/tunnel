# Gum Tunnel v1 Plan

## Summary

Build a production-grade, egress-only tunnel platform that lets customers route outbound traffic from their cloud accounts through isolated encrypted tunnels to Gum-operated bare-metal gateways, using customer-owned private connectivity where available.

The first implementation should be cloud-agnostic at the architecture level, but ship with AWS as the first provider adapter because the product mechanics and pricing case are currently defined there.

Success means:

- A customer can register a tenant, provision a dedicated tunnel, install a Rust agent, and route selected outbound traffic through Gum egress.
- Traffic is encrypted end-to-end over the tunnel, exits from Gum infrastructure, and is metered per tenant.
- Operators can manage the full lifecycle through API and CLI without needing a dashboard.
- The design supports adding additional cloud providers without reworking the core control plane or gateway model.

## Key Changes

### Platform Architecture

- Split the system into four subsystems:
- Rust control plane service for tenant, tunnel, key, policy, and lifecycle management.
- Rust customer agent that runs inside the customer environment, establishes the tunnel, and steers egress traffic into it.
- Rust gateway and egress node on Gum bare metal that terminates tunnels, enforces tenant isolation, meters traffic, and forwards to the public internet.
- Metering and state stores for configuration, tunnel state, and per-tenant usage records.
- Keep provider-specific logic behind a cloud adapter boundary. Core concepts such as tenant, tunnel, route policy, private-link attachment, and usage record must not encode AWS-only semantics.
- Treat AWS as adapter v1: support its route constructs and private-connectivity model first, but expose them through generic platform abstractions.

### Public Interfaces And Core Domain

- Define first-class resources:
- `Tenant`
- `Tunnel`
- `GatewayAttachment`
- `RoutePolicy`
- `AgentEnrollment`
- `UsageRecord`
- Expose REST/JSON APIs for:
- tenant creation and isolation setup
- tunnel provisioning and key rotation
- agent enrollment and bootstrap
- route policy updates
- tunnel health and state queries
- usage export
- Provide a CLI that wraps the same APIs for:
- creating tenants and tunnels
- generating bootstrap material for agents
- listing health and traffic counters
- rotating credentials and disabling tunnels
- Use dedicated tunnel identity, keys, and policy boundaries per tenant by default. Shared gateways are acceptable, but packet path identity, config, and accounting must remain tenant-specific.

### Data Plane Behavior

- Support egress-only traffic in v1.
- Agent responsibilities:
- authenticate to the control plane
- receive tunnel config and route policy
- establish an encrypted tunnel to the assigned gateway
- steer configured outbound traffic into the tunnel
- emit health and traffic telemetry
- Gateway responsibilities:
- terminate the encrypted tunnel
- map incoming traffic to a single tenant and tunnel context
- enforce route and egress policy
- NAT or forward traffic to the public internet from Gum infrastructure
- emit authoritative ingress and egress usage counters
- Connectivity model:
- primary mode is customer-owned private connectivity bound to Gum gateways
- plan an explicit interface for private-link attachments so future adapters can represent AWS Direct Connect, Azure ExpressRoute, GCP Interconnect, or equivalent
- do not require internet-tunnel fallback for v1 delivery, but avoid interfaces that would prevent adding it later
- Metering:
- store per-tenant, per-tunnel byte counts and session and health events
- usage accounting is required; invoicing is out of scope
- gateway-side counters are the source of truth, with agent telemetry used for diagnostics

### Persistence, Security, And Operations

- Persist control-plane state in a relational store with strong support for transactional lifecycle updates and auditability.
- Persist high-cardinality usage and telemetry separately if needed; do not overload the primary control-plane store with raw time-series volume.
- Security defaults:
- mutual authentication between agent and control plane
- per-tunnel key material with rotation support
- encrypted transport for all control-plane and data-plane links
- auditable operator actions
- least-privilege enrollment and bootstrap flow for agents
- Operational requirements for v1:
- health model for agent, tunnel, gateway, and provider attachment
- structured logs and metrics for control plane and gateways
- clear degraded states for tunnel up but no traffic, attachment down, gateway unreachable, and policy mismatch
- production-safe rollout model for gateways and agents without cross-tenant config bleed

## CLI And Onboarding

### CLI Shape

- The operator workflow is `login` plus a resource-aware `connect` command.
- The CLI connects to a managed tenant and specific cloud attachment, not to a raw AWS account ID alone.
- `Tenant + Attachment` is the primary connection identity.
- `cloud-account` is an input attribute, not the sole resource identifier.

### Example Commands

```bash
tunnel login
tunnel tenant create acme
tunnel attachment register --provider aws --cloud-account 123456789012 --name prod
tunnel agent enroll --tenant acme --token <token>
tunnel policy apply --tenant acme --profile backups
tunnel connect --tenant acme --attachment prod
tunnel status --tenant acme
tunnel usage --tenant acme
```

### Onboarding Principle

- The ideal customer experience is close to `tunnel connect`, but v1 still requires one-time setup for agent enrollment, attachment registration, and traffic policy.
- The promise is no application rewrite and minimal operator change, not literal zero change.
- `tunnel connect` should activate a preconfigured tunnel path, validate attachment health, retrieve tunnel config, and confirm the encrypted session is up before declaring success.

## Test Plan

- Unit tests for domain lifecycle:
- tenant creation
- tunnel provisioning
- key rotation
- route policy validation
- usage record attribution
- Integration tests for control-plane APIs:
- create tenant and tunnel
- enroll agent
- fetch config
- rotate credentials
- disable and re-enable tunnel
- End-to-end environment tests:
- agent establishes tunnel to gateway
- configured outbound traffic exits through Gum egress
- traffic is attributed to the correct tenant and tunnel
- tunnel teardown stops egress immediately
- Failure-mode tests:
- private-link unavailable
- gateway node unavailable
- stale or revoked agent credentials
- control-plane loss after agent bootstrap
- metering continuity across reconnects
- Cloud-adapter tests:
- generic tunnel lifecycle passes through adapter contracts
- AWS adapter correctly maps generic attachment and routing concepts to AWS primitives
- Security tests:
- cross-tenant isolation
- unauthorized agent enrollment rejection
- key rotation without traffic leakage to the wrong tunnel

## Assumptions And Defaults

- First provider implementation is AWS, even though the architecture must remain cloud-agnostic.
- v1 is production-oriented, not a single-customer proof of concept.
- Customer onboarding and operations happen through REST API and CLI only; no web dashboard is required in v1.
- Traffic scope is outbound internet egress only; inbound and private service access are deferred.
- Customers own or approve the private-connectivity arrangement; Gum binds its platform onto that attachment model.
- Rust is the default implementation language for both control plane and data plane unless a later constraint forces a split.
- Billing artifacts, invoicing, and customer-facing finance workflows are out of scope; accurate usage accounting is in scope.
