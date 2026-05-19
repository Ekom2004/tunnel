# Remote Two-Host Validation

This is the production-shaped validation path after the local and Fly namespace tests pass.

The topology is:

- agent host: customer-side route owner
- gateway host: internet egress/NAT owner
- UDP/WireGuard path between the two hosts

## Flow

On the build/operator machine, generate an operator plan:

```sh
tunnel-cli remote-plan remote-prod \
  --gateway-host <gateway-public-or-private-ip> \
  --out-dir /tmp/tunnel-bundles \
  --agent-ssh-host <agent-ssh-target> \
  --gateway-ssh-host <gateway-ssh-target> \
  --force
```

The plan emits JSON containing the generated bundle paths plus exact copy, import, connect, `remote-check`, and `remote-smoke-test` commands.

The underlying manual flow is:

```sh
tunnel-cli login remote-prod \
  --gateway-host <gateway-public-or-private-ip> \
  --gateway-port 7000 \
  --destination-cidr 1.1.1.0/24 \
  --force

tunnel-cli profile export remote-prod --out-dir /tmp/tunnel-bundles --force
```

Install the agent bundle on the agent host:

```sh
tunnel-cli profile import /tmp/tunnel-bundles/agent \
  --profile agent-prod \
  --profile-file /private/tmp/tunnel-profiles.json \
  --force
```

Install the gateway bundle on the gateway host:

```sh
tunnel-cli profile import /tmp/tunnel-bundles/gateway \
  --profile gateway-prod \
  --profile-file /private/tmp/tunnel-profiles.json \
  --force
```

Before starting traffic, verify that both imported side profiles still form one tunnel:

```sh
tunnel-cli remote-check agent-prod \
  --peer-profile gateway-prod \
  --peer-profile-file /path/to/gateway/tunnel-profiles.json \
  --gateway-host <gateway-public-or-private-ip> \
  --gateway-port 7000 \
  --udp-probe
```

Start the gateway on the gateway host:

```sh
sudo tunnel-cli connect gateway-prod
```

Start the agent on the agent host:

```sh
sudo tunnel-cli connect agent-prod
```

Then run the end-to-end smoke test from the agent host:

```sh
sudo tunnel-cli remote-smoke-test agent-prod \
  --peer-profile gateway-prod \
  --peer-profile-file /path/to/gateway/tunnel-profiles.json \
  --target 1.1.1.1 \
  --count 10
```

The smoke test runs profile-pair validation, a gateway UDP probe datagram, `doctor`, and `soak`.

## Notes

The UDP probe can prove local UDP send and address resolution, but UDP has no built-in listener acknowledgement. The authoritative end-to-end proof is still packet movement through `doctor` plus zero-loss `soak`.
