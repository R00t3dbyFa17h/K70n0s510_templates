#!/bin/bash

# K70n0s510 Scanner - Alerting Edition
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET=$1

# Absolute Path to templates
TEMPLATE_DIR="$HOME/K70n0s510_templates/owasp-2025/"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: ./run-scan.sh <target>${NC}"
    exit 1
fi

echo -e "${GREEN}🚀 K70n0s510 Scanner: Active on $TARGET...${NC}"
echo -e "${BLUE}📂 Loading templates from: $TEMPLATE_DIR ${NC}"
echo -e "${BLUE}🔔 Alerts configured: Sending hits to Discord.${NC}"

# Pipeline: Nuclei -> JSON -> Notify -> Discord
# Note: Requires 'notify' tool installed and configured in ~/.config/notify/provider-config.yaml
nuclei -u "$TARGET" -t "$TEMPLATE_DIR" -rl 50 -bs 10 -silent -j | tee -a scan_results.json | notify -provider-config ~/.config/notify/provider-config.yaml -id k70-alerts -bulk

echo -e "${GREEN}✅ Scan Complete.${NC}"
