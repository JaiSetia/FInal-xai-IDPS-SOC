#!/bin/sh
# Route the victim network via the sensor, then idle.
set -e
# No default route: the lab must not reach the outside world.
ip route del default 2>/dev/null || true
ip route replace "${VICTIM_NET:-10.10.2.0/24}" via "${SENSOR_IP:-10.10.1.2}"
exec sleep infinity
