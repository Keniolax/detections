#!/usr/bin/env bash
# Load wazuh/local_rules.xml into a running home-soc-lab manager and reload it.
#
# Point LAB_DIR at the home-soc-lab checkout (default: ../home-soc-lab).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
lab="${LAB_DIR:-$here/../home-soc-lab}"
lab="$(cd "$lab" && pwd)"
rules="$here/wazuh/local_rules.xml"

python3 "$here/convert/sigma_to_wazuh.py" --check

cd "$lab"
docker compose cp "$rules" wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control restart >/dev/null 2>&1

# Wait for the manager and the agent to come back.
until docker compose exec -T wazuh.manager sh -c \
  "/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-analysisd is running'"; do sleep 3; done
until docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l 2>/dev/null \
  | grep -q 'Name: victim,.*Active$'; do sleep 3; done
echo "apply: loaded $(grep -c '<rule ' "$rules") rules into the manager"
