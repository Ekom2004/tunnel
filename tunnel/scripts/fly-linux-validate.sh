#!/usr/bin/env sh
set -eu

PROFILE="${TUNNEL_PROFILE:-local-dev}"
TARGET="${TUNNEL_TARGET:-1.1.1.1}"
DESTINATION_CIDR="${TUNNEL_DESTINATION_CIDR:-1.1.1.0/24}"
EGRESS_INTERFACE="${TUNNEL_EGRESS_INTERFACE:-eth0}"
AGENT_NS="${TUNNEL_AGENT_NAMESPACE:-tunnel-agent-ns}"
ROOT_VETH="${TUNNEL_ROOT_VETH:-tun-gw-veth}"
AGENT_VETH="${TUNNEL_AGENT_VETH:-tun-agent-veth}"
ROOT_VETH_IP="${TUNNEL_ROOT_VETH_IP:-10.250.0.1}"
AGENT_VETH_IP="${TUNNEL_AGENT_VETH_IP:-10.250.0.2}"
VETH_CIDR="${TUNNEL_VETH_CIDR:-10.250.0.0/30}"
GATEWAY_PORT="${TUNNEL_GATEWAY_PORT:-7000}"

AGENT_CONFIG="/private/tmp/tunnel-agent-wg.json"
GATEWAY_CONFIG="/private/tmp/tunnel-gateway-wg.json"
AGENT_STATE="/private/tmp/tunnel-agent-state.json"
AGENT_STATUS="/private/tmp/tunnel-agent-status.json"
GATEWAY_STATE="/private/tmp/tunnel-gateway-state.json"
GATEWAY_STATUS="/private/tmp/tunnel-gateway-status.json"
SESSION_FILE="/private/tmp/tunnel-session.json"
AGENT_LOG="/private/tmp/tunnel-agent.log"
GATEWAY_LOG="/private/tmp/tunnel-gateway.log"
SUPERVISOR_LOG="/private/tmp/tunnel-supervisor.log"
PROFILE_FILE="/private/tmp/tunnel-profiles.json"
DISCONNECT_LOG="/tmp/tunnel-fly-disconnect.log"

AGENT_PID=""
GATEWAY_PID=""

mkdir -p /private/tmp /var/run/netns

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 78
  fi
}

cleanup() {
  set +e
  if [ -n "$AGENT_PID" ]; then
    kill "$AGENT_PID" 2>/dev/null || true
  fi
  if [ -n "$GATEWAY_PID" ]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
  fi
  sleep 1
  if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$AGENT_NS"; then
    ip netns exec "$AGENT_NS" tunnel-agent \
      --config "$AGENT_CONFIG" \
      --cleanup-only \
      --route-mode apply \
      --state-file "$AGENT_STATE" \
      --status-file "$AGENT_STATUS" >>"$DISCONNECT_LOG" 2>&1 || true
  fi
  tunnel-gateway \
    --cleanup-only \
    --forwarding-mode apply \
    --nat-mode apply \
    --state-file "$GATEWAY_STATE" \
    --status-file "$GATEWAY_STATUS" >>"$DISCONNECT_LOG" 2>&1 || true
  ip netns delete "$AGENT_NS" 2>/dev/null || true
  ip link delete "$ROOT_VETH" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

dump_diagnostics() {
  echo "==== tunnel fly diagnostics ===="
  echo "---- kernel/network identity ----"
  uname -a || true
  id || true
  echo "---- root interfaces ----"
  ip addr || true
  echo "---- root routes ----"
  ip route || true
  ip route get "$TARGET" || true
  echo "---- agent namespace interfaces ----"
  ip netns exec "$AGENT_NS" ip addr || true
  echo "---- agent namespace routes ----"
  ip netns exec "$AGENT_NS" ip route || true
  ip netns exec "$AGENT_NS" ip route get "$TARGET" || true
  echo "---- forwarding ----"
  sysctl net.ipv4.ip_forward || true
  echo "---- iptables filter ----"
  iptables -S || true
  echo "---- iptables nat ----"
  iptables -t nat -S || true
  echo "---- tunnel status ----"
  tunnel-cli status "$PROFILE" --profile-file "$PROFILE_FILE" --session-file "$SESSION_FILE" || true
  echo "---- agent-side doctor ----"
  ip netns exec "$AGENT_NS" tunnel-cli doctor "$PROFILE" \
    --profile-file "$PROFILE_FILE" \
    --session-file "$SESSION_FILE" \
    --target "$TARGET" || true
  echo "---- gateway-side doctor ----"
  tunnel-cli doctor "$PROFILE" \
    --profile-file "$PROFILE_FILE" \
    --session-file "$SESSION_FILE" \
    --target "$TARGET" || true
  echo "---- tunnel logs ----"
  tunnel-cli logs "$PROFILE" \
    --profile-file "$PROFILE_FILE" \
    --session-file "$SESSION_FILE" \
    --lines 160 || true
  echo "---- cleanup log ----"
  cat "$DISCONNECT_LOG" 2>/dev/null || true
  echo "==== end tunnel fly diagnostics ===="
}

run_step() {
  name="$1"
  shift
  echo "==> $name"
  if "$@"; then
    return 0
  else
    status="$?"
    echo "step failed: $name" >&2
    dump_diagnostics
    exit "$status"
  fi
}

wait_for_file() {
  path="$1"
  deadline="$2"
  elapsed=0
  while [ "$elapsed" -lt "$deadline" ]; do
    if [ -s "$path" ]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "timed out waiting for $path" >&2
  return 1
}

write_session_manifest() {
  cat >"$SESSION_FILE" <<EOF
{
  "tenant": "local-tenant",
  "attachment": "$PROFILE",
  "agent_config": "$AGENT_CONFIG",
  "gateway_config": "$GATEWAY_CONFIG",
  "agent_state_file": "$AGENT_STATE",
  "agent_status_file": "$AGENT_STATUS",
  "gateway_state_file": "$GATEWAY_STATE",
  "gateway_status_file": "$GATEWAY_STATUS",
  "agent_log_file": "$AGENT_LOG",
  "gateway_log_file": "$GATEWAY_LOG",
  "egress_interface": "$EGRESS_INTERFACE",
  "route_mode": "Apply",
  "forwarding_mode": "Apply",
  "nat_mode": "Apply",
  "agent_pid": $AGENT_PID,
  "gateway_pid": $GATEWAY_PID,
  "mode": "Remote",
  "local_component": "Agent",
  "supervised": false,
  "supervisor_pid": null,
  "supervisor_log_file": "$SUPERVISOR_LOG"
}
EOF
}

require_command tunnel-cli
require_command tunnel-agent
require_command tunnel-gateway
require_command ip
require_command iptables
require_command ping

if [ "$(id -u)" != "0" ]; then
  echo "Tunnel Linux validation must run as root so it can manage TUN, routes, forwarding, and NAT." >&2
  exit 78
fi

if [ ! -c /dev/net/tun ]; then
  echo "TUN is unavailable: /dev/net/tun is missing or not a character device." >&2
  echo "This host cannot prove Tunnel's Linux packet path." >&2
  exit 78
fi

if ! iptables -L >/dev/null 2>&1; then
  echo "iptables is not usable from this environment." >&2
  echo "This usually means the VM/container lacks NET_ADMIN-style privileges." >&2
  exit 78
fi

if ! ip link show "$EGRESS_INTERFACE" >/dev/null 2>&1; then
  echo "egress interface not found: $EGRESS_INTERFACE" >&2
  ip addr >&2 || true
  exit 78
fi

echo "Tunnel Fly Linux validation starting"
echo "profile=$PROFILE target=$TARGET destination_cidr=$DESTINATION_CIDR egress_interface=$EGRESS_INTERFACE agent_ns=$AGENT_NS"

run_step "baseline direct ping" ping -c 1 -W 2 "$TARGET"

run_step "login" tunnel-cli login "$PROFILE" \
  --force \
  --profile-file "$PROFILE_FILE" \
  --gateway-host "$ROOT_VETH_IP" \
  --gateway-port "$GATEWAY_PORT" \
  --destination-cidr "$DESTINATION_CIDR" \
  --egress-interface "$EGRESS_INTERFACE"

run_step "remote config check" tunnel-cli remote-check "$PROFILE" \
  --profile-file "$PROFILE_FILE" \
  --gateway-host "$ROOT_VETH_IP" \
  --gateway-port "$GATEWAY_PORT"

run_step "create agent namespace" ip netns add "$AGENT_NS"
run_step "create veth pair" ip link add "$ROOT_VETH" type veth peer name "$AGENT_VETH"
run_step "configure root veth" ip addr add "$ROOT_VETH_IP/30" dev "$ROOT_VETH"
run_step "bring root veth up" ip link set "$ROOT_VETH" up
run_step "move agent veth" ip link set "$AGENT_VETH" netns "$AGENT_NS"
run_step "bring agent lo up" ip netns exec "$AGENT_NS" ip link set lo up
run_step "configure agent veth" ip netns exec "$AGENT_NS" ip addr add "$AGENT_VETH_IP/30" dev "$AGENT_VETH"
run_step "bring agent veth up" ip netns exec "$AGENT_NS" ip link set "$AGENT_VETH" up
run_step "agent can reach gateway veth" ip netns exec "$AGENT_NS" ping -c 1 -W 2 "$ROOT_VETH_IP"

echo "==> start gateway"
tunnel-gateway \
  --config "$GATEWAY_CONFIG" \
  --tun \
  --forwarding-mode apply \
  --nat-mode apply \
  --egress-interface "$EGRESS_INTERFACE" \
  --state-file "$GATEWAY_STATE" \
  --status-file "$GATEWAY_STATUS" >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID="$!"
wait_for_file "$GATEWAY_STATUS" 15 || {
  dump_diagnostics
  exit 1
}

echo "==> start agent in namespace"
ip netns exec "$AGENT_NS" tunnel-agent \
  --config "$AGENT_CONFIG" \
  --tun \
  --route-mode apply \
  --state-file "$AGENT_STATE" \
  --status-file "$AGENT_STATUS" >"$AGENT_LOG" 2>&1 &
AGENT_PID="$!"
wait_for_file "$AGENT_STATUS" 15 || {
  dump_diagnostics
  exit 1
}

write_session_manifest

run_step "agent namespace route check" ip netns exec "$AGENT_NS" ip route get "$TARGET"
run_step "gateway root route check" ip route get "$TARGET"
run_step "agent-side ping through tunnel" ip netns exec "$AGENT_NS" ping -c 5 -W 2 "$TARGET"
run_step "agent-side doctor" ip netns exec "$AGENT_NS" tunnel-cli doctor "$PROFILE" \
  --profile-file "$PROFILE_FILE" \
  --session-file "$SESSION_FILE" \
  --target "$TARGET"
run_step "gateway status" tunnel-cli status "$PROFILE" \
  --profile-file "$PROFILE_FILE" \
  --session-file "$SESSION_FILE"
run_step "agent-side soak" ip netns exec "$AGENT_NS" tunnel-cli soak \
  --session-file "$SESSION_FILE" \
  --target "$TARGET" \
  --count 10 \
  --probe-timeout-secs 2

cleanup
trap - EXIT INT TERM

echo "Tunnel Fly Linux validation passed"
