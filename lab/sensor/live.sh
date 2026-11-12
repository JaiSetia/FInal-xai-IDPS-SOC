#!/bin/sh
# python -m idps.live, sending alerts to the lab SOC when it has published a sensor token.
# Usage: docker compose exec sensor live.sh --interface lab_attack --model models/friday_xgboost.joblib
# Without the SOC (no token file yet) alerts go to data/processed/live_alerts.jsonl as before.
set -eu
SHARED=/run/idps-soc
if [ -s "$SHARED/sensor_token" ] && [ -s "$SHARED/ca.pem" ]; then
  IDPS_SOC_SENSOR_TOKEN=$(cat "$SHARED/sensor_token")
  export IDPS_SOC_SENSOR_TOKEN
  export IDPS_SOC_URL="${IDPS_SOC_URL:-https://10.10.3.10:8443}"
  export IDPS_SOC_CA_FILE="$SHARED/ca.pem"
else
  echo "live.sh: no lab SOC token in $SHARED; alerts go to a file" >&2
fi
exec python -m idps.live "$@"
