# Lab

Docker network: `attacker` (10.10.1.10) on `attack_net` (10.10.1.0/24), `victim`
(10.10.2.10) and `dvwa` (10.10.2.11) on `victim_net` (10.10.2.0/24). The `sensor`
(10.10.1.2 / 10.10.2.2) is on both and routes between them, so it is inline and can block.
Run attacks only here.

```sh
cp .env.example .env      # then set the lab-only password
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
- **The sensor forwards only lab-to-lab traffic** ([sensor/nftables.conf](sensor/nftables.conf)).
- **Fails closed.** If any setup step fails, that container exits and the containers that
  depend on it never start.

The containers that do have `NET_ADMIN` are the sensor (it's the IPS) and the `*-net` holders.
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

## Running detection on the sensor

The sensor image already contains `models/` and `idps/`. Run the live loop on the attack-side
interface while an attack script runs from the attacker container:

```sh
docker compose exec \
    -e IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24 \
    sensor python -m idps.live --interface lab_attack --model models/friday_xgboost.joblib
```

`IDPS_ALLOWLIST` must contain the servers you protect (here the whole victim network
10.10.2.0/24, which includes the victim and DVWA) plus the gateway and the sensor. It is the real
guarantee that a server is never blocked: a flow can start with the server's reply, so the server
can appear as the source (the loop corrects the obvious cases, but an allowlist is what you can
rely on). Do not allowlist the attacker's network.

Dry-run is on by default: detections that would be blocked are logged (`would_block`), nothing is
changed in nftables. Real blocking needs `IDPS_DRY_RUN=false` and `IDPS_ALLOWLIST`. To try it with
a short block time:

```sh
docker compose exec \
    -e IDPS_DRY_RUN=false -e IDPS_BLOCK_TTL_SECONDS=60 \
    -e IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24 \
    sensor python -m idps.live --interface lab_attack --model models/friday_xgboost.joblib
docker compose exec attacker sh /attacks/portscan.sh      # in a second terminal
docker compose exec sensor nft list table inet idps       # after about 2 minutes
```

The alerts and the block come about two minutes after the scan: NFStream reports a flow when its
120 s idle timeout fires. The loop sends a one-second UDP heartbeat out of the interface so this
also happens on a quiet link (see [../docs/live.md](../docs/live.md)). The block disappears by
itself when its time runs out. Measured results are in the "Lab sensor check" section there.

The sensor has no route to the host, so unless a SOC is reachable it writes alerts as JSON lines to
`/opt/idps/data/processed/live_alerts.jsonl` (read with `docker compose exec sensor cat ...`).
Settings, metrics and expected latency: [../docs/live.md](../docs/live.md).

Code and scripts are copied into the images (macOS blocks Docker from mounting folders under
`~/Desktop`), so rebuild after changing them: `docker compose up -d --build`.
