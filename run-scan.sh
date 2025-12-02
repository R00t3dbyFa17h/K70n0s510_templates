#!/bin/bash

# K70n0s510 Scanner Launcher
# Usage: ./run-scan.sh https://target.com

TARGET=$1

if [ -z "$TARGET" ]; then
  echo "❌ Error: No target specified."
  echo "Usage: ./run-scan.sh https://target.com"
  exit 1
fi

echo "🚀 K70n0s510 Scanner: Initiating OWASP 2025 Protocol on $TARGET..."

# Run Nuclei using the local templates folder
nuclei -u "$TARGET" -t owasp-2025/ -v

echo "✅ Scan Complete."
