#!/bin/sh
# Network namespace of the lab SOC (soc joins it with network_mode: service:soc-net and has no
# capabilities, so nothing inside the SOC can change this). Fails closed like lab/netns/setup.sh.
#
# - No default route: the SOC reaches nothing outside 10.10.3.0/24.
# - Inbound: only TCP 8443 (the sensor, and the dashboard through the published 127.0.0.1 port).
# - Outbound: only replies, by default. The SOC never opens a connection, so it can't reach the
#   lab, the Docker host or the internet even if it were compromised.
# - Optional exception (SOC_EGRESS_HOSTS, from LAB_SOC_EGRESS_HOSTS in lab/.env): HTTPS (TCP 443)
#   to the public IPv4 addresses those host names resolve to, e.g. api.abuseipdb.com for IP
#   reputation or hooks.slack.com for Slack. Each address gets its own /32 route through the
#   Docker gateway (still no default route); private and reserved answers are refused. Names are
#   looked up again every 2 minutes and an address stays allowed for an hour after it was last
#   seen, so rotating CDN answers keep working and stale ones age out.
#   Accepted risks (see lab/README.md): the rule is per address, so other sites on the same CDN
#   addresses are reachable too, and a compromised SOC could send data out through them; DNS
#   queries already reach the internet through Docker's resolver.
set -eu
set -f            # no globbing of SOC_EGRESS_HOSTS
trap 'exit 0' TERM INT

GW=""
REFRESH_SECONDS=120
RETRY_SECONDS=30
KEEP=1h           # an address stays allowed this long after it was last resolved
MAX_PER_HOST=32

public_ipv4() {  # $1 is a dotted IPv4 address; true unless private, shared, loopback or reserved
  case "$1" in
    0.*|10.*|127.*|169.254.*|192.168.*|192.0.0.*|192.0.2.*|198.18.*|198.19.*|198.51.100.*|203.0.113.*) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
    22[4-9].*|2[3-5][0-9].*) return 1 ;;
  esac
  return 0
}

valid_host() {  # a DNS name: letters, digits, dots, hyphens; no empty label; no label edge hyphen
  [ "${#1}" -le 253 ] || return 1
  case "$1" in
    ""|*[!A-Za-z0-9.-]*|.*|*.|*..*|-*|*-|*.-*|*-.*) return 1 ;;
  esac
  return 0
}

resolve() {  # dotted-quad A records of $1 (two lookups, to catch rotating answers), capped
  { getent ahostsv4 "$1" || true; getent ahostsv4 "$1" || true; } \
    | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1}' | sort -u | head -n "$MAX_PER_HOST"
}

allowed_now() {  # addresses currently in the set
  nft list set inet socguard egress4 | sed -n '/elements/,$p' \
    | grep -oE '([0-9]+\.){3}[0-9]+' | sort -u || true
}

refresh() {  # returns 1, changing nothing, when no host gave a public address or nft/ip failed
  found=""
  for h in $HOSTS; do
    got=""
    for a in $(resolve "$h"); do
      if public_ipv4 "$a"; then got="$got $a"; else
        echo "soc-net: ignoring non-public address $a for $h" >&2; fi
    done
    [ -n "$got" ] || echo "soc-net: no public address for $h this time (its earlier ones stay until they expire)" >&2
    found="$found$got"
  done
  found=$(printf '%s\n' $found | sort -u)  # two names may share addresses (CDNs)
  [ -n "$found" ] || return 1
  # Routes first, then the set: a failure leaves the rule as it was.
  for a in $found; do ip route replace "$a/32" via "$GW" proto 99 || return 1; done
  elems=""
  for a in $found; do elems="$elems${elems:+, }$a timeout $KEEP"; done
  printf 'add element inet socguard egress4 { %s }\n' "$elems" | nft -f - || return 1
  # Drop the routes of addresses that have expired from the set.
  keep=$(allowed_now)
  for r in $(ip -4 route show proto 99 | awk '{print $1}'); do
    printf '%s\n' "$keep" | grep -qxF "$r" || ip route del "$r/32" via "$GW" proto 99 || true
  done
  now="$(printf '%s' "$keep" | tr '\n' ' ')"
  if [ "$now" != "${LAST_ALLOWED:-}" ]; then  # log changes only
    echo "soc-net: HTTPS allowed to $HOSTS ($now)" >&2
    LAST_ALLOWED=$now
  fi
}

[ "${NETGUARD_LIB:-}" = 1 ] && return 0 2>/dev/null  # sourced by tests: functions only

# Normalise "a, b,,c" to "a b c"; only separators means none.
set -- $(printf '%s' "${SOC_EGRESS_HOSTS:-}" | tr ',' ' ')
HOSTS="$*"
for h in $HOSTS; do
  valid_host "$h" || { echo "soc-net: bad host name in SOC_EGRESS_HOSTS: $h" >&2; exit 1; }
done

GW=$(ip -4 route show default | awk '{print $3; exit}')
ip route del default 2>/dev/null || true

nft -f - <<'NFT'
table inet socguard {
  set egress4 { type ipv4_addr; flags timeout; }
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
    ip daddr @egress4 tcp dport 443 accept
  }
}
NFT

if [ -n "$HOSTS" ] && [ -z "$GW" ]; then
  echo "soc-net: no Docker gateway for SOC_EGRESS_HOSTS" >&2; exit 1
fi
if ip route | grep -q '^default'; then
  echo "soc-net: default route still present, refusing to start" >&2
  exit 1
fi
touch /tmp/ready  # the SOC starts either way; the exception is optional

if [ -z "$HOSTS" ]; then
  while :; do sleep 3600 & wait $!; done
fi
# Until the first success (DNS down at start, say) retry often; nothing is allowed meanwhile.
until refresh; do
  echo "soc-net: could not resolve $HOSTS yet; nothing allowed, retrying in ${RETRY_SECONDS}s" >&2
  sleep "$RETRY_SECONDS" & wait $!
done
while :; do
  sleep "$REFRESH_SECONDS" & wait $!
  refresh || echo "soc-net: refresh failed; addresses already allowed expire after $KEEP" >&2
done
