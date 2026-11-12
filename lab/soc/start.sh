#!/bin/sh
# Lab SOC: TLS certificate, secrets, admin user and sensor token on first start, then the API.
# Fails closed. Two volumes:
#   /var/lib/idps-soc  SOC only: database, JWT secret, TLS private keys
#   /run/idps-soc      shared with the sensor (read-only there): ca.pem and sensor_token
set -eu
umask 077
DATA=/var/lib/idps-soc
SHARED=/run/idps-soc

case "${LAB_SOC_ADMIN_PASSWORD:-}" in
  "") echo "soc: LAB_SOC_ADMIN_PASSWORD is not set; copy lab/.env.example to lab/.env" >&2; exit 1 ;;
  change-me*) echo "soc: set your own LAB_SOC_ADMIN_PASSWORD in lab/.env" >&2; exit 1 ;;
esac

# A private CA for the lab, and a server certificate for the SOC's lab address and localhost
# (the dashboard reaches it through the published port 127.0.0.1:8443).
# The CA key signs once and is deleted; when the certificate is due to expire (within 30 days)
# the whole set is made again, and the sensor picks up the new ca.pem on its next start.
if [ ! -s "$DATA/server.pem" ] || ! openssl x509 -checkend 2592000 -noout -in "$DATA/server.pem" >/dev/null; then
  openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 \
    -subj "/CN=IDPS lab CA" -keyout "$DATA/ca.key" -out "$DATA/ca.pem"
  openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -subj "/CN=soc.lab" -keyout "$DATA/server.key" -out "$DATA/server.csr"
  printf 'subjectAltName=IP:10.10.3.10,IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' \
    > "$DATA/server.ext"
  openssl x509 -req -in "$DATA/server.csr" -CA "$DATA/ca.pem" -CAkey "$DATA/ca.key" \
    -CAcreateserial -days 365 -extfile "$DATA/server.ext" -out "$DATA/server.pem"
  rm -f "$DATA/server.csr" "$DATA/server.ext" "$DATA/ca.key" "$DATA/ca.srl"
fi
install -m 0644 "$DATA/ca.pem" "$SHARED/ca.pem"  # a certificate: public, readable by all

if [ ! -s "$DATA/jwt_secret" ]; then
  python -c "import secrets; print(secrets.token_urlsafe(48))" > "$DATA/jwt_secret.tmp"
  mv "$DATA/jwt_secret.tmp" "$DATA/jwt_secret"
fi
IDPS_SOC_JWT_SECRET=$(cat "$DATA/jwt_secret")
export IDPS_SOC_JWT_SECRET
export IDPS_SOC_DATABASE_URL="sqlite:///$DATA/soc.db"

python /opt/idps/lab/soc/bootstrap.py "$SHARED/sensor_token"
# The admin password is only needed for the first start; keep it out of the server's environment.
# (It still shows in `docker inspect`; it is a lab-only password. Changing it in lab/.env later
# has no effect: change it in the dashboard's Admin page instead.)
unset LAB_SOC_ADMIN_PASSWORD

# One process: the live alert feed is an in-process broadcaster (see soc/api/main.py).
exec uvicorn soc.api.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile "$DATA/server.key" --ssl-certfile "$DATA/server.pem"
