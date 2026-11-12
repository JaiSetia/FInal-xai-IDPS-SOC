# Lab

Docker network: `attacker` (10.10.1.10) on `attack_net` (10.10.1.0/24), `victim`
(10.10.2.10) and `dvwa` (10.10.2.11) on `victim_net` (10.10.2.0/24). The `sensor`
(10.10.1.2 / 10.10.2.2) is on both and routes between them, so it is inline and can block.
The lab SOC (10.10.3.10) is on a third network, `mgmt_net`, that only the sensor joins
(10.10.3.2). Run attacks only here.

```sh
cp .env.example .env      # then set the lab-only passwords (victim, SOC admin)
docker compose up -d --build
./check_isolation.sh      # run after every start; all checks must pass
docker compose exec attacker /attacks/portscan.sh
```

## How the lab is isolated

The networks are **not** Docker `internal` networks: Docker drops packets on internal
networks whose destination is outside the subnet, which would stop the sensor routing.
Instead:

- **No default route anywhere.** No container can send traffic out of the lab.
- **Endpoints can't change their own network.** `attacker`, `victim` and `dvwa` have no
  `NET_ADMIN`. Each shares the network namespace of a small `*-net` container
  ([netns/setup.sh](netns/setup.sh)) that sets the routes and firewall rules and then idles.
  The rules block Docker's DNS (so no name lookups or DNS tunnelling out) and the Docker VM
  gateway (`10.10.x.1`).
- **The sensor forwards only lab-to-lab traffic** ([sensor/nftables.conf](sensor/nftables.conf)),
  with each rule bound to its interface and strict reverse-path filtering. It never forwards to
  or from `lab_mgmt`, and nothing on `mgmt_net` can open a connection to it.
- **The SOC can't reach anything.** It runs with no capabilities in the namespace of
  `soc-net` ([soc/netguard.sh](soc/netguard.sh)): no default route, inbound TCP 8443 only,
  outbound replies only. Its port is published on `127.0.0.1` only, for the dashboard.
- **Fails closed.** If any setup step fails, that container exits and the containers that
  depend on it never start.

The containers that do have `NET_ADMIN` are the sensor (it's the IPS) and the `*-net` and
`soc-net` holders.
Don't run anything else in them.

## Scripts

`attacks/`: `portscan.sh`, `ssh_bruteforce.sh`, `dos.sh [syn|slow]`, `webattack.sh`
(sqlmap vs DVWA), `replay.sh` (tcpreplay of dataset PCAPs). They all refuse to run unless
the targets are exactly 10.10.2.10 / 10.10.2.11 **and** they run inside the attacker container.

Export `LAB_VICTIM_PASSWORD` in the attacker shell for the brute-force script to hit the real password.

To replay a dataset capture (frames are sent only to the sensor's MAC address):

```sh
docker compose cp capture.pcap attacker:/tmp/capture.pcap
docker compose exec attacker /attacks/replay.sh /tmp/capture.pcap
```

## The lab SOC and dashboard

`soc` runs the SOC API (same image as the sensor) on `https://10.10.3.10:8443`. On first start
[soc/start.sh](soc/start.sh) makes a private CA and server certificate, the JWT secret, the
admin user `admin` (password `LAB_SOC_ADMIN_PASSWORD` from `.env`; change it later in the
dashboard's Admin page) and a sensor token. The certificate and the token go to a volume the
sensor mounts read-only at `/run/idps-soc`; keys, secret and database stay in the SOC's own volume.

To open the dashboard, run it from `soc/web` against the published port, trusting the lab CA:

```sh
docker compose exec sensor cat /run/idps-soc/ca.pem > /tmp/lab-soc-ca.pem
cd ../soc/web && NODE_EXTRA_CA_CERTS=/tmp/lab-soc-ca.pem IDPS_SOC_API=https://127.0.0.1:8443 npm run dev
```

## Running detection on the sensor

`live.sh` runs `python -m idps.live` with the SOC's address, CA and token, so alerts and
blocks show up on the dashboard (about 2 minutes after the traffic: NFStream reports a flow
when its 120 s idle timeout fires). Run it on the attack-side interface while an attack script
runs from the attacker container:

```sh
docker compose exec \
    -e IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24,10.10.3.0/24 \
    sensor live.sh --interface lab_attack --model models/friday_xgboost.joblib
docker compose exec attacker sh /attacks/portscan.sh      # in a second terminal
```

`IDPS_ALLOWLIST` must contain the servers you protect (here the whole victim network
10.10.2.0/24, which includes the victim and DVWA) plus the gateway, the sensor and the SOC. It is
the real guarantee that a server is never blocked: a flow can start with the server's reply, so
the server can appear as the source (the loop corrects the obvious cases, but an allowlist is what
you can rely on). Do not allowlist the attacker's network.

Dry-run is on by default: detections that would be blocked are logged (`would_block`), nothing is
changed in nftables. To try real blocking with a short block time, add
`-e IDPS_DRY_RUN=false -e IDPS_BLOCK_TTL_SECONDS=60`. The block appears on the dashboard's Blocks
page and disappears from "active only" when nftables removes it
(`docker compose exec sensor nft list table inet idps` shows it on the sensor). Measured results
are in the "Lab sensor check" section of [../docs/live.md](../docs/live.md).

Without the SOC (`python -m idps.live` directly, or before the SOC has made its token) it writes alerts as JSON lines to
`/opt/idps/data/processed/live_alerts.jsonl` (read with `docker compose exec sensor cat ...`).
Settings, metrics and expected latency: [../docs/live.md](../docs/live.md).

Code and scripts are copied into the images (macOS blocks Docker from mounting folders under
`~/Desktop`), so rebuild after changing them: `docker compose up -d --build sensor soc`.
