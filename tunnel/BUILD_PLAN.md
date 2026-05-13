# Gum Tunnel Phased Build Plan

## Summary

Do not build Gum in one go. Build it in 5 phases, where each phase removes one major risk before the next layer is added.

The first phase should prove the real data path. Later phases should add operator workflow, repeatability, isolation, and broader production hardening.

Rust rules are part of the plan, not an afterthought:

- no `unsafe` by default
- idiomatic Rust required
- strict linting and formatting required
- explicit exceptions only after measurement proves a real need

## Engineering Rules

- Default rule: no `unsafe` in phase 1 or normal feature work.
- Any future `unsafe` use must be:
- isolated to a narrow module
- justified by measured performance or systems necessity
- documented with invariants and failure assumptions
- covered by focused tests
- Rust quality gate:
- `cargo fmt` clean
- strict `clippy` clean
- clear module boundaries
- typed errors instead of ad hoc strings where practical
- explicit config and state types
- tests required for lifecycle and failure behavior
- Prefer proven OS and network primitives first:
- routing rules
- `iptables`
- standard tunnel and device interfaces
- Defer deeper kernel tricks until the baseline is stable and measured.

## Phase Plan

### Phase 1: Single Real Data Path

- One AWS account, one customer host, one Gum gateway.
- One traffic class only: bulk export or backup traffic.
- Build:
- gateway tunnel termination and egress forwarding
- agent tunnel establishment
- host routing and `iptables`-based traffic steering
- gateway-side usage counters
- basic health and degraded-state reporting
- Success criteria:
- selected traffic exits through Gum
- usage is attributed correctly
- tunnel and gateway failures are visible and controlled

### Phase 2: Thin Control Plane And CLI

- Add the minimum management surface needed to operate phase 1 cleanly.
- Build:
- minimal REST API
- CLI for login, tenant creation, attachment registration, enrollment, connect, status, usage
- config issuance for one tunnel and one route policy
- bootstrap and credential flow for one agent
- Success criteria:
- the phase 1 path can be stood up and operated without hand-editing config
- operator workflow is coherent and repeatable

### Phase 3: Repeatable Onboarding

- Turn the first path into a reusable deployment pattern.
- Build:
- standard onboarding flow for a new tenant
- reusable route-policy profiles for the first traffic class
- clearer status, diagnostics, and failure messages
- reconciliation between expected transfer volume and gateway usage counters
- Success criteria:
- a second customer and account can be onboarded without custom engineering work
- support and debug workflow is clear

### Phase 4: Isolation And Lifecycle Hardening

- Harden the system from "working path" into "trustworthy platform slice."
- Build:
- stronger tenant isolation boundaries
- key rotation
- tunnel disable and re-enable lifecycle
- safer rollout and restart behavior for gateway and agent
- stronger degraded-state handling
- Success criteria:
- tenant boundaries are explicit and testable
- reconnects, revokes, and rotations do not create ambiguous behavior

### Phase 5: Production v1 Expansion

- Broaden only after the first slice is stable.
- Build:
- more complete control-plane lifecycle
- stronger observability and auditability
- additional AWS environment patterns
- readiness for second traffic class or second provider adapter boundary
- Success criteria:
- the system is production-credible for the initial AWS-first use case
- the architecture can expand without rework of the core tunnel contract

## Public Interfaces

- Keep the first public resource set small and stable:
- `Tenant`
- `Tunnel`
- `GatewayAttachment`
- `RoutePolicy`
- `AgentEnrollment`
- `UsageRecord`
- Keep the first CLI workflow:
- `tunnel login`
- `tunnel tenant create`
- `tunnel attachment register`
- `tunnel agent enroll`
- `tunnel policy apply`
- `tunnel connect`
- `tunnel status`
- `tunnel usage`
- `tunnel connect` activates a preconfigured path; it does not perform all infrastructure creation from scratch.

## Test Plan

- Phase 1 tests:
- tunnel up and down behavior
- selected traffic capture only
- gateway usage attribution
- failure visibility for dropped gateway or tunnel
- Phase 2 tests:
- config issuance
- CLI and API lifecycle for one tenant and one tunnel
- enrollment and credential validation
- Phase 3 tests:
- repeated onboarding of a new tenant and account
- usage reconciliation and operator diagnostics
- Phase 4 tests:
- key rotation
- revoke and reconnect behavior
- cross-tenant isolation
- Phase 5 tests:
- broader lifecycle regression coverage
- production-like soak and recovery scenarios

## Assumptions And Defaults

- Start AWS-only in delivery, while keeping provider abstractions internally clean.
- Use Rust across agent, gateway, CLI, and control plane.
- Use OS routing and `iptables` before considering eBPF or more aggressive kernel work.
- Optimize for correctness, observability, and repeatability before deeper performance work.
- `unsafe` is banned by default and only reconsidered after measured evidence shows a real need.
