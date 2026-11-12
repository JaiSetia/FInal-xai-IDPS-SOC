#!/bin/sh
# Network namespace of the lab SOC (soc joins it with network_mode: service:soc-net and has no
# capabilities, so nothing inside the SOC can change this). Fails closed like lab/netns/setup.sh.
#
# - No default route: the SOC reaches nothing outside 10.10.3.0/24.
# - Inbound: only TCP 8443 (the sensor, and the dashboard through the published 127.0.0.1 port).
# - Outbound: only replies. The SOC never opens a connection, so it can't reach the lab, the
#   Docker host or the internet even if it were compromised.
set -eu

ip route del default 2>/dev/null || true

nft -f - <<'EOF'
table inet socguard {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 8443 accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
  }
}
EOF

if ip route | grep -q '^default'; then
  echo "soc-net: default route still present, refusing to start" >&2
  exit 1
fi
touch /tmp/ready
exec sleep infinity
