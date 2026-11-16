"""lab/soc/netguard.sh: which resolver answers may be allowed, which host names are accepted, and
what one refresh does, with fake getent, ip and nft programs on PATH.

The script is sourced with NETGUARD_LIB=1 so only its functions load (no real nft or routes).
Each call prints ALLOW or REFUSE, so a script that fails to load can't pass a refusal test."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "lab" / "soc" / "netguard.sh"
SH = shutil.which("sh")
pytestmark = pytest.mark.skipif(SH is None, reason="needs a POSIX sh")


def _call(func: str, arg: str) -> bool:
    cmd = f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; if {func} "$1"; then echo ALLOW; else echo REFUSE; fi'
    r = subprocess.run([SH, "-c", cmd, "sh", arg], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() in ("ALLOW", "REFUSE"), (r.returncode, r.stdout, r.stderr)
    return r.stdout.strip() == "ALLOW"


@pytest.mark.parametrize("ip", [
    "104.26.12.38", "172.67.70.74", "1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0",
    "172.15.255.255", "172.32.0.0", "192.169.0.1", "198.17.255.255", "198.20.0.0",
    "223.255.255.255", "11.0.0.1",
])
def test_public_addresses_are_allowed(ip):
    assert _call("public_ipv4", ip)


@pytest.mark.parametrize("ip", [
    "0.0.0.0", "10.0.0.1", "10.10.2.10", "127.0.0.1", "169.254.169.254", "172.16.0.1",
    "172.31.255.255", "192.168.1.1", "100.64.0.0", "100.100.1.1", "100.127.255.255",
    "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9",
    "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
])
def test_private_and_reserved_addresses_are_refused(ip):
    assert not _call("public_ipv4", ip)


@pytest.mark.parametrize("host", ["api.abuseipdb.com", "hooks.slack.com", "a-b.example.org", "localhost"])
def test_valid_host_names(host):
    assert _call("valid_host", host)


@pytest.mark.parametrize("host", [
    "", "*", "-x", "a.-b.com", "a-.b.com", "a..b", ".a.com", "a.com.", "a b", "a;b", "$(id)",
    "a/b", "x" * 254,
])
def test_bad_host_names_are_refused(host):
    assert not _call("valid_host", host)


# --- one refresh with fake tools ------------------------------------------------------------

FAKE_GETENT = """#!/bin/sh
# getent ahostsv4 NAME: answers from $FAKE/dns/NAME (one address per line); none = not found
f="$FAKE/dns/$2"; [ -f "$f" ] || exit 2
while read -r a; do echo "$a STREAM $2"; echo "$a DGRAM"; done < "$f"
"""
FAKE_IP = """#!/bin/sh
# Records route changes in $FAKE/routes; `ip -4 route show proto 99` lists them.
case "$*" in
  "route replace "*) a=${3%/32}; grep -qxF "$a" "$FAKE/routes" 2>/dev/null || echo "$a" >> "$FAKE/routes" ;;
  "route del "*) a=${3%/32}; grep -vxF "$a" "$FAKE/routes" > "$FAKE/r.tmp" || true; mv "$FAKE/r.tmp" "$FAKE/routes" ;;
  "-4 route show proto 99") [ -f "$FAKE/routes" ] && sed 's/$/ via 10.0.0.1 dev eth0 proto 99/' "$FAKE/routes" ;;
  *) echo "fake ip: $*" >&2; exit 1 ;;
esac
[ ! -f "$FAKE/ip_fails" ]
"""
FAKE_NFT = """#!/bin/sh
# `nft -f -` adds the addresses it is given to $FAKE/set; `nft list set ...` prints them.
case "$1" in
  -f) [ ! -f "$FAKE/nft_fails" ] || exit 1
      cat > "$FAKE/last_nft"
      grep -oE '([0-9]+\\.){3}[0-9]+' "$FAKE/last_nft" >> "$FAKE/set"; sort -u "$FAKE/set" -o "$FAKE/set" ;;
  list) echo "table inet socguard {"; echo "  set egress4 {"
        printf '    elements = { %s }\\n' "$(sed 's/$/ timeout 1h expires 59m/' "$FAKE/set" 2>/dev/null | paste -sd, -)"
        echo "  }"; echo "}" ;;
esac
"""


@pytest.fixture
def fake(tmp_path):
    bin_ = tmp_path / "bin"
    (tmp_path / "dns").mkdir()
    bin_.mkdir()
    for name, body in (("getent", FAKE_GETENT), ("ip", FAKE_IP), ("nft", FAKE_NFT)):
        f = bin_ / name
        f.write_text(body)
        f.chmod(0o755)
    return tmp_path


def _dns(fake, name, *addrs):
    (fake / "dns" / name).write_text("".join(f"{a}\n" for a in addrs))


def _refresh(fake, hosts):
    env = {**os.environ, "FAKE": str(fake), "PATH": f"{fake / 'bin'}:{os.environ['PATH']}"}
    cmd = (f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; HOSTS="$1"; GW=10.0.0.1; '
           'if refresh; then echo OK; else echo FAIL; fi')
    r = subprocess.run([SH, "-c", cmd, "sh", hosts], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.strip().splitlines()[-1] in ("OK", "FAIL"), (r.stdout, r.stderr)
    return r.stdout.strip().splitlines()[-1] == "OK", r.stderr


def _lines(path):
    return sorted(path.read_text().split()) if path.exists() else []


def test_refresh_allows_public_answers_and_refuses_private_ones(fake):
    _dns(fake, "api.example.com", "104.26.12.38", "10.0.0.5", "104.26.13.38")
    ok, err = _refresh(fake, "api.example.com")
    assert ok
    assert _lines(fake / "set") == ["104.26.12.38", "104.26.13.38"]
    assert _lines(fake / "routes") == ["104.26.12.38", "104.26.13.38"]
    assert "ignoring non-public address 10.0.0.5" in err


def test_shared_addresses_across_hosts_go_in_once(fake):
    _dns(fake, "a.example.com", "104.26.12.38", "104.26.13.38")
    _dns(fake, "b.example.com", "104.26.13.38", "172.67.70.74")
    ok, _ = _refresh(fake, "a.example.com b.example.com")
    assert ok
    sent = (fake / "last_nft").read_text()
    assert sent.count("104.26.13.38") == 1
    assert _lines(fake / "set") == ["104.26.12.38", "104.26.13.38", "172.67.70.74"]


def test_a_host_that_fails_does_not_block_the_others(fake):
    _dns(fake, "good.example.com", "104.26.12.38")
    ok, err = _refresh(fake, "missing.example.com good.example.com")
    assert ok and _lines(fake / "set") == ["104.26.12.38"]
    assert "no public address for missing.example.com" in err


def test_nothing_resolved_or_only_private_fails_and_changes_nothing(fake):
    _dns(fake, "private.example.com", "192.168.1.10")
    ok, _ = _refresh(fake, "private.example.com missing.example.com")
    assert not ok
    assert _lines(fake / "set") == [] and _lines(fake / "routes") == []


def test_answers_are_capped_per_host(fake):
    _dns(fake, "many.example.com", *(f"104.16.0.{i}" for i in range(1, 60)))
    ok, _ = _refresh(fake, "many.example.com")
    assert ok and len(_lines(fake / "set")) == 32


def test_a_failed_nft_update_reports_failure(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    (fake / "nft_fails").write_text("")
    ok, _ = _refresh(fake, "api.example.com")
    assert not ok and _lines(fake / "set") == []


def test_routes_of_expired_addresses_are_removed(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    (fake / "routes").write_text("1.2.3.4\n")  # an address no longer in the set
    ok, _ = _refresh(fake, "api.example.com")
    assert ok and _lines(fake / "routes") == ["104.26.12.38"]
