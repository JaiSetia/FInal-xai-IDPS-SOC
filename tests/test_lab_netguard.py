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
# `nft -f -` adds the addresses it is given to the named set's file ($FAKE/set for egress4,
# $FAKE/set_<name> for others); `nft list set inet socguard NAME` prints them.
file_of() { if [ "$1" = egress4 ]; then echo "$FAKE/set"; else echo "$FAKE/set_$1"; fi; }
case "$1" in
  -f) [ ! -f "$FAKE/nft_fails" ] || exit 1
      cat > "$FAKE/last_nft"
      f=$(file_of "$(awk '{print $5; exit}' "$FAKE/last_nft")")
      grep -oE '([0-9]+\\.){3}[0-9]+' "$FAKE/last_nft" >> "$f"; sort -u "$f" -o "$f" ;;
  list) f=$(file_of "$5"); echo "table inet socguard {"; echo "  set $5 {"
        printf '    elements = { %s }\\n' "$(sed 's/$/ timeout 1h expires 59m/' "$f" 2>/dev/null | paste -sd, -)"
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


# --- the email exception: one host, one port, its own set --------------------------------------

def _refresh_all(fake, hosts, smtp_host, smtp_port="587"):
    env = {**os.environ, "FAKE": str(fake), "PATH": f"{fake / 'bin'}:{os.environ['PATH']}"}
    cmd = (f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; HOSTS="$1"; SMTP_HOST="$2"; SMTP_PORT="$3"; '
           'GW=10.0.0.1; if refresh_all; then echo OK; else echo FAIL; fi')
    r = subprocess.run([SH, "-c", cmd, "sh", hosts, smtp_host, smtp_port], capture_output=True,
                       text=True, env=env)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return r.stdout.strip().splitlines()[-1] == "OK", r.stderr


@pytest.mark.parametrize("port,ok", [("25", True), ("465", True), ("587", True), ("443", False),
                                     ("22", False), ("5870", False), ("", False), ("58 7", False)])
def test_only_mail_ports_are_accepted(port, ok):
    assert _call("valid_smtp_port", port) is ok


def test_the_mail_server_goes_in_its_own_set_not_the_https_one(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    _dns(fake, "smtp.example.com", "142.250.4.108", "10.1.1.1")
    ok, err = _refresh_all(fake, "api.example.com", "smtp.example.com")
    assert ok
    assert _lines(fake / "set") == ["104.26.12.38"]  # HTTPS set unchanged by email
    assert _lines(fake / "set_egress_smtp4") == ["142.250.4.108"]  # private answer refused
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]  # both keep their routes
    assert "SMTP port 587 allowed to smtp.example.com" in err


def test_email_only_works_without_https_hosts(fake):
    _dns(fake, "smtp.example.com", "142.250.4.108")
    ok, _ = _refresh_all(fake, "", "smtp.example.com")
    assert ok and _lines(fake / "set") == [] and _lines(fake / "set_egress_smtp4") == ["142.250.4.108"]


def test_an_unresolvable_mail_server_does_not_hold_up_https(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    ok, err = _refresh_all(fake, "api.example.com", "missing.example.com")
    assert ok  # one set working ends the fast start-up retries
    assert _lines(fake / "set") == ["104.26.12.38"] and _lines(fake / "set_egress_smtp4") == []
    assert "mail server not resolved: missing.example.com" in err


def test_nothing_resolved_at_all_fails(fake):
    ok, _ = _refresh_all(fake, "missing.example.com", "nomail.example.com")
    assert not ok


@pytest.mark.parametrize("host,local", [("", True), ("localhost", True), ("127.0.0.1", True),
                                        ("10.10.3.5", True), ("smtp.gmail.com", False),
                                        ("142.250.4.108", False)])
def test_a_local_test_mail_server_needs_no_exception(host, local):
    assert _call("local_mail_host", host) is local


def _run(fake, script):
    env = {**os.environ, "FAKE": str(fake), "PATH": f"{fake / 'bin'}:{os.environ['PATH']}"}
    r = subprocess.run([SH, "-c", f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; GW=10.0.0.1; {script}'],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return r.stderr


def test_an_https_refresh_keeps_the_mail_route_and_vice_versa(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    _dns(fake, "smtp.example.com", "142.250.4.108")
    (fake / "set_egress_smtp4").write_text("142.250.4.108\n")
    (fake / "routes").write_text("142.250.4.108\n")
    _run(fake, 'HOSTS=api.example.com; SMTP_HOST=smtp.example.com; refresh')
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]
    _run(fake, 'HOSTS=api.example.com; SMTP_HOST=smtp.example.com; '
               'refresh_set egress_smtp4 SMTP smtp.example.com')
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]


def test_a_stale_mail_route_is_removed_and_a_shared_one_kept(fake):
    _dns(fake, "smtp.example.com", "142.250.4.108")
    (fake / "set").write_text("104.26.12.38\n")  # also an HTTPS address
    (fake / "routes").write_text("104.26.12.38\n9.9.9.9\n")  # 9.9.9.9 is in no set
    _run(fake, 'HOSTS=""; SMTP_HOST=smtp.example.com; refresh_set egress_smtp4 SMTP smtp.example.com')
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]


def test_the_allowed_log_line_is_written_once(fake):
    _dns(fake, "smtp.example.com", "142.250.4.108")
    err = _run(fake, 'HOSTS=""; SMTP_HOST=smtp.example.com; SMTP_PORT=587; '
                     'refresh_all; refresh_all')
    assert err.count("SMTP port 587 allowed") == 1


@pytest.mark.parametrize("host,local", [("foo.localhost", True), ("1.2", False), ("::1", False)])
def test_more_local_host_cases(host, local):
    # Not local: "1.2" is resolved like a name and every answer is checked by public_ipv4; "::1"
    # is then refused by valid_host in the main section (email stays blocked, the SOC starts).
    assert _call("local_mail_host", host) is local
