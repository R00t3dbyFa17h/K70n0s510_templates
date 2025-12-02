#!/bin/bash

# Define Colors for Professional Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function: Help Menu
show_help() {
    echo -e "${BLUE}K70n0s510 Detection Engine - OWASP 2025 Scanner${NC}"
    echo ""
    echo "Usage: ./run-scan.sh [TARGET_URL] [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  TARGET_URL    The full URL to scan (e.g., https://example.com)"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message and exit"
    echo ""
    echo "Examples:"
    echo "  ./run-scan.sh https://target.com"
    echo "  ./run-scan.sh --help"
    echo ""
}

# Check for Help Flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Check if Target is provided
if [ -z "$1" ]; then
    echo -e "${RED}❌ Error: No target specified.${NC}"
    show_help
    exit 1
fi

TARGET=$1

# Check if Nuclei is installed
if ! command -v nuclei &> /dev/null; then
    echo -e "${RED}❌ Error: Nuclei is not installed or not in your PATH.${NC}"
    echo -e "${YELLOW}💡 Fix: Please install it via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
    exit 1
fi

# Start the Scan
echo -e "${GREEN}🚀 K70n0s510 Scanner: Initiating OWASP 2025 Protocol on $TARGET...${NC}"
echo -e "${YELLOW}Running custom templates from: owasp-2025/${NC}"

# Run Nuclei using the local templates folder
# Flags Explanation:
# -t owasp-2025/   -> Use your custom folder
# -rl 50           -> Rate Limit (Safe speed)
# -bs 10           -> Bulk Size (Parallel requests)
# -nm              -> No Metadata (Cleaner output)
nuclei -u "$TARGET" -t owasp-2025/ -rl 50 -bs 10 -nm

echo ""
echo -e "${GREEN}✅ Scan Complete. Happy Hunting.${NC}"
