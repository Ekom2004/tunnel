# Fly Linux Validation

This is a temporary Linux validation target for Tunnel. It is useful for proving whether Fly Machines expose enough Linux networking control for the current packet path.

The validation image builds a split Linux topology inside one Fly Machine:

- gateway runs in the root network namespace and egresses through `eth0`
- agent runs in its own Linux network namespace
- a veth pair connects the agent namespace to the gateway namespace
- the agent route to the target CIDR exists only in the agent namespace

This matters because a single shared Linux route table is not a valid local model for Tunnel. If agent and gateway share one route table, the agent route can also capture gateway egress and create a local routing loop.

The validation flow runs:

- `tunnel-cli login`
- `tunnel-cli remote-check` against the generated split profile
- Linux namespace and veth setup
- `tunnel-gateway` in the root namespace
- `tunnel-agent` in the agent namespace
- agent-side ping through the tunnel
- agent-side `doctor`
- gateway/agent status inspection
- agent-side `soak`
- cleanup for routes, NAT rules, processes, veth, and namespace

It requires root, `/dev/net/tun`, `ip netns`, `ip route`, `sysctl`, and `iptables`. If Fly does not expose TUN, network namespaces, or usable packet-filter privileges, the script exits with code `78`; that means Fly is not a valid host for this production-OS proof.

## Run

Install and authenticate `flyctl`, then create/deploy with an app name you own:

```sh
fly launch --copy-config --name your-tunnel-linux-validation --region iad --no-deploy
fly deploy
fly logs
```

To run the validation manually inside the machine:

```sh
fly ssh console -C tunnel-fly-validate
```

## Important

Fly is only a validation target here. It is not the final Tunnel gateway model because the business depends on controlled transit, interconnects, and provider routing economics.
