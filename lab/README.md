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

Code and scripts are copied into the images (macOS blocks Docker from mounting folders under
`~/Desktop`), so rebuild after changing them: `docker compose up -d --build`.
