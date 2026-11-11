#!/bin/sh
# Expected class: PortScan
. "$(dirname "$0")/common.sh"
exec nmap -sS -p 1-1024 -T4 "$VICTIM_IP"
