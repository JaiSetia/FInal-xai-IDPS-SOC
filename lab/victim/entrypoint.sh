#!/bin/sh
# Lab-only credentials come from the environment, never from the image.
set -e
: "${LAB_VICTIM_PASSWORD:?LAB_VICTIM_PASSWORD must be set}"
echo "labuser:${LAB_VICTIM_PASSWORD}" | chpasswd
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# No default route: the lab must not reach the outside world.
ip route del default 2>/dev/null || true
ip route replace "${ATTACK_NET:-10.10.1.0/24}" via "${SENSOR_IP:-10.10.2.2}"
/usr/sbin/sshd
exec nginx -g 'daemon off;'
