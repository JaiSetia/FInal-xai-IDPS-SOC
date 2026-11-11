#!/bin/sh
# Run on the host after `docker compose up`. Checks the lab is cut off from the
# outside world and that lab traffic goes through the sensor. Sends no attack traffic.
cd "$(dirname "$0")" || exit 1
FAIL=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAIL=1; }
in_c() { c=$1; shift; docker exec "idps-$c" sh -c "$*" >/dev/null 2>&1; }

for c in sensor attacker victim dvwa; do
  if in_c "$c" '(ip route 2>/dev/null || route -n) | grep -qE "^(default|0\.0\.0\.0)"'; then
    fail "$c has a default route"; else pass "$c has no default route"; fi
done

for c in attacker victim; do
  if in_c "$c" 'getent hosts example.com'; then
    fail "$c can resolve internet names"; else pass "$c can't resolve internet names"; fi
done

if in_c attacker 'ping -c1 -W1 10.10.1.1'; then fail "attacker reaches gateway 10.10.1.1"; else pass "attacker can't reach gateway 10.10.1.1"; fi
if in_c attacker 'ping -c1 -W1 10.10.2.1'; then fail "attacker reaches gateway 10.10.2.1 via sensor"; else pass "attacker can't reach gateway 10.10.2.1"; fi
if in_c attacker 'ip route add default via 10.10.1.1'; then
  in_c attacker 'ip route del default'; fail "attacker can change its routes"
else pass "attacker can't change its routes"; fi

if in_c attacker 'ping -c1 -W2 10.10.2.10'; then pass "attacker reaches victim"; else fail "attacker can't reach victim"; fi
if docker exec idps-attacker ip route get 10.10.2.10 | grep -q 'via 10.10.1.2'; then
  pass "attacker -> victim goes via the sensor"; else fail "attacker -> victim does not go via the sensor"; fi

[ "$FAIL" = 0 ] && echo "All isolation checks passed." || { echo "Some checks FAILED: don't run attacks."; exit 1; }
