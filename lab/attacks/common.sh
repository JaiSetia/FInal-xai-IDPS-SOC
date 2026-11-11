# Shared lab addresses. Run attacks ONLY against these lab hosts.
VICTIM_IP="${VICTIM_IP:-10.10.2.10}"
DVWA_IP="${DVWA_IP:-10.10.2.11}"
case "$VICTIM_IP $DVWA_IP" in
  *10.10.2.*) ;;
  *) echo "Refusing: targets must be in the lab victim_net (10.10.2.0/24)" >&2; exit 1 ;;
esac
