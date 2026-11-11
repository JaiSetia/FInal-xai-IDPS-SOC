# Lab

Isolated Docker network: `attacker` (10.10.1.10) on `attack_net` (10.10.1.0/24), `victim`
(10.10.2.10) and `dvwa` (10.10.2.11) on `victim_net` (10.10.2.0/24). The `sensor`
(10.10.1.2 / 10.10.2.2) is on both and routes between them, so it is inline and can block.
Both networks are `internal`, so the lab has no outside connectivity. Run attacks only here.

```sh
cp .env.example .env      # then edit the lab-only password
docker compose up -d --build
docker compose exec attacker /attacks/portscan.sh
```

Scripts in `attacks/`: `portscan.sh`, `ssh_bruteforce.sh`, `dos.sh [syn|slow]`,
`webattack.sh` (sqlmap vs DVWA), `replay.sh` (tcpreplay of dataset PCAPs).
Export `LAB_VICTIM_PASSWORD` in the attacker shell for the brute-force script to hit the real password.

Note on `dvwa`: the `vulnerables/web-dvwa` image may lack `ip`/`route`. If the return route
fails (warning in `docker compose logs dvwa`), either build a small derived image with iproute2,
or add `iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE` on the sensor (the sensor still
sees real attacker IPs, so blocking works).
