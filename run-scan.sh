#!/bin/bash

# K70n0s510 Scanner - Visual Console Edition
# Features: Colorful Nuclei Output + Background Discord Alerts
# Author: Nicholas Mullenski

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# 1. Path Configuration
# We use $HOME to ensure it finds the templates even if run via symlink
TEMPLATE_DIR="$HOME/K70n0s510_templates/owasp-2025/"
CONFIG_PATH="$HOME/.config/notify/provider-config.yaml"
OUTPUT_FILE="scan_results.txt"

TARGET=$1

if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: K70scan <target_domain_OR_file>${NC}"
    exit 1
fi

# 2. Determine Target Type
if [ -f "$TARGET" ]; then
    echo -e "${GREEN}📜 Target List Detected: $TARGET ${NC}"
    NUCLEI_ARGS="-l $TARGET"
else
    echo -e "${GREEN}🎯 Single Target Detected: $TARGET ${NC}"
    NUCLEI_ARGS="-u $TARGET"
fi

echo -e "${BLUE}🚀 Starting K70n0s510 Scan... (Visual Mode)${NC}"
echo -e "${BLUE}📂 Loading Templates from: $TEMPLATE_DIR ${NC}"

# 3. Start Background Alert Listener
# Watches the file for new hits and pipes them to Discord silently.
# Filters out "[INF]" lines so only vulnerabilities are sent.
touch $OUTPUT_FILE
tail -n 0 -f $OUTPUT_FILE | grep --line-buffered "\[" | grep -v "\[INF\]" | notify -provider-config "$CONFIG_PATH" -id k70-alerts -bulk > /dev/null 2>&1 &
LISTENER_PID=$!

# 4. Run Nuclei (Foreground)
# -o: Saves to file (which triggers the listener)
# -stats: Shows the progress bar
# No -silent: Ensures colorful bracket output in terminal
nuclei $NUCLEI_ARGS -t "$TEMPLATE_DIR" -o $OUTPUT_FILE -rl 50 -bs 10 -stats

# 5. Cleanup
# Kill the background listener when Nuclei finishes
kill $LISTENER_PID > /dev/null 2>&1

echo -e "\n${GREEN}✅ Scan Complete. Full results saved to $OUTPUT_FILE${NC}"
