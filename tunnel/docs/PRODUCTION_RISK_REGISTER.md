# Production Risk Register

This is the canonical engineering risk register for Tunnel production readiness.

Every production hardening patch should reference one or more IDs from this file in its commit message, PR, or implementation notes.

Status values:

- `open`: known risk, not yet fixed
- `in_progress`: implementation underway
- `mitigated`: fix exists, but still needs real-host validation
- `closed`: fix is implemented, tested, and validated in production-shaped environments

## Open Risks

| ID | Severity | Area | Risk | Current State | Required Fix | Exit Criteria | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-001 | P0 | WireGuard UDP | UDP peer endpoint hijack or DoS if endpoint is learned from unauthenticated UDP source. | Peer endpoint learning needs audit/hardening. | Only update peer endpoint after authenticated WireGuard handshake or valid authenticated packet; count/rate-limit rejected packets. | Spoofed UDP packet cannot change endpoint; authenticated packet can; tests cover both. | open |
| SEC-002 | P1 | Key handling | Private keys are written as normal JSON files, often under temporary paths. | Config files can contain private keys and are not yet enterprise-hardened. | Use secure config directories, atomic writes, `0600` files, `0700` parent dirs, and refuse unsafe permissions. | Private-key configs are not world/group-readable; unsafe files fail preflight; Unix permission tests pass. | open |
| SEC-003 | P0 | Legacy transport | JSON/TCP tunnel mode can trust client-provided tenant/tunnel identity if exposed. | Legacy mode exists and needs production guardrails. | Disable outside explicit dev mode or require authenticated tunnel/session credentials. | JSON/TCP refuses unauthenticated non-dev use; tests cover refusal path. | open |
| SEC-004 | P1 | Packet capture | Gateway packet capture/output mode can write decrypted plaintext packets to disk. | Capture mode needs explicit production safety controls. | Require explicit dangerous/debug flag, secure output permissions, and production refusal unless allowed. | Capture cannot be enabled accidentally; status/report flags capture as dangerous; tests cover refusal. | open |
| SEC-005 | P0 | Route policy | Destination CIDR validation is too weak. Invalid or overly broad routes could be installed. | Route strings are not sufficiently policy-validated. | Structurally parse CIDRs; reject invalid, loopback, multicast, link-local, and broad/default routes unless explicitly allowed. | Invalid/broad CIDRs fail readiness; explicit override is required and audited. | open |
| REL-001 | P0 | Fail-open | If Tunnel fails while VPC routes still target the tunnel agent, customer traffic can blackhole. | Local cleanup exists, but AWS route-table fail-open is not implemented. | Capture fallback target before route takeover; restore fallback on tunnel failure; support automatic/manual re-enable with cooldown. | Route takeover refuses without fallback target or explicit waiver; failure restores NAT/default AWS egress; integration test validates route restoration logic. | open |
| NET-001 | P0 | MTU/MSS | Missing TCP MSS clamping can cause TLS/large-flow hangs due to WireGuard overhead and PMTU blackholes. | TUN MTU is configured, but transit TCP MSS rewrite is not installed. | Add Linux mangle TCPMSS clamp for forwarded traffic; cleanup symmetrically; add doctor checks. | TCP SYN/SYN-ACK MSS is clamped to safe value; doctor verifies rule; Linux command tests pass. | open |
| NET-002 | P1 | Linux routing | Strict `rp_filter` can silently drop asymmetric return traffic arriving on tunnel interfaces. | No reverse-path filter sysctl handling is applied. | Set loose mode `rp_filter=2` for relevant interfaces or all/default where appropriate; restore safely; add doctor checks. | Agent/gateway preflight detects strict RPF; setup applies loose mode; cleanup behavior is documented/tested. | open |
| PERF-001 | P2 | Throughput | User-space TUN plus boringtun can bottleneck at high packet rates due to syscall/context switching overhead. | Portable user-space datapath is functional but not performance-proven. | Benchmark first; then evaluate batching, socket buffer tuning, multi-queue, or Linux kernel WireGuard control-plane mode. | Throughput baseline exists; target throughput/SLO documented; optimization path selected from measurements. | open |

## Recently Mitigated Areas

| ID | Area | Mitigation | Remaining Validation |
| --- | --- | --- | --- |
| OPS-001 | Remote deploy safety | `remote-deploy` supports dry-run, rollback, host preflight, report files, step timeouts, failure log collection, and report redaction. | Run against real two-host Linux VMs and preserve deploy reports. |

## Notes

- For enterprise egress replacement, fail-open must prefer customer continuity over savings. Failure mode should be higher AWS egress/NAT cost, not traffic outage.
- AWS route-table fail-open is separate from local route cleanup. The product must know the original route target and have scoped permission to restore it.
- Notion can mirror this document for planning, but this repo file is the engineering source of truth.
