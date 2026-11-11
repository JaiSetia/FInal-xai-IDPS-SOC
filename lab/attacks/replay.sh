#!/bin/sh
# Dataset replay (mixed classes). Run on the HOST or sensor with tcpreplay installed:
#   replay.sh path/to/capture.pcap [interface]
# Replays onto the sensor-side interface; do this only inside the lab.
[ -n "$1" ] || { echo "usage: $0 capture.pcap [iface]" >&2; exit 1; }
exec tcpreplay --intf1="${2:-eth0}" --mbps=10 "$1"
