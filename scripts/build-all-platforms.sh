#!/bin/bash
# Cross-platform build script for rust-bottle
# Builds for: macOS/ARM, macOS/x86_64, Linux/x86_64, Linux/ARM64
# Run from macOS/ARM (Apple Silicon)

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Feature sets to test
declare -a FEATURES=(
    ""
    "ml-kem"
    "post-quantum"
    "ml-kem,post-quantum"
)

# Results tracking (using arrays compatible with bash 3.2+)
RESULTS_TARGETS=()
RESULTS_STATUS=()
TOTAL_TARGETS=0
PASSED_TARGETS=0
FAILED_TARGETS=0

# Function to print header
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Function to print result
print_result() {
    local target=$1
    local status=$2
    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    
    # Store results in parallel arrays
    RESULTS_TARGETS+=("$target")
    RESULTS_STATUS+=("$status")
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓ ${target}: PASSED${NC}"
        PASSED_TARGETS=$((PASSED_TARGETS + 1))
    else
        echo -e "${RED}✗ ${target}: FAILED${NC}"
        FAILED_TARGETS=$((FAILED_TARGETS + 1))
    fi
}

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}ERROR: This script is designed to run on macOS${NC}"
    exit 1
fi

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "arm64" ]; then
    echo -e "${YELLOW}WARNING: This script is optimized for macOS/ARM (Apple Silicon)${NC}"
    echo -e "${YELLOW}Some builds may not work as expected on Intel Macs${NC}"
fi

print_header "Cross-Platform Build Test for rust-bottle"

echo "Platform: macOS/ARM (Apple Silicon)"
echo "Targets:"
echo "  - macOS/ARM (native)"
echo "  - macOS/x86_64 (Rosetta 2)"
echo "  - Linux/x86_64 (Docker)"
echo "  - Linux/ARM64 (Docker)"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# 1. Native macOS/ARM build
print_header "1. Building for macOS/ARM (native)"
if "$SCRIPT_DIR/build-macos-arm.sh"; then
    print_result "macOS/ARM" "PASS"
else
    print_result "macOS/ARM" "FAIL"
fi

# 2. macOS/x86_64 build using Rosetta 2
print_header "2. Building for macOS/x86_64 (Rosetta 2)"
if "$SCRIPT_DIR/build-macos-x86_64.sh"; then
    print_result "macOS/x86_64" "PASS"
else
    print_result "macOS/x86_64" "FAIL"
fi

# 3. Linux/x86_64 build using Docker
print_header "3. Building for Linux/x86_64 (Docker)"
if "$SCRIPT_DIR/build-linux-x86_64.sh"; then
    print_result "Linux/x86_64" "PASS"
else
    print_result "Linux/x86_64" "FAIL"
fi

# 4. Linux/ARM64 build using Docker
print_header "4. Building for Linux/ARM64 (Docker)"
if "$SCRIPT_DIR/build-linux-arm64.sh"; then
    print_result "Linux/ARM64" "PASS"
else
    print_result "Linux/ARM64" "FAIL"
fi

# Print summary
print_header "Build Summary"
echo "Total targets: $TOTAL_TARGETS"
echo -e "${GREEN}Passed: $PASSED_TARGETS${NC}"
if [ $FAILED_TARGETS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TARGETS${NC}"
else
    echo -e "${GREEN}Failed: $FAILED_TARGETS${NC}"
fi
echo ""

# Print detailed results
echo "Detailed Results:"
# Use a counter instead of array indices for bash 3.2 compatibility
i=0
while [ $i -lt ${#RESULTS_TARGETS[@]} ]; do
    target="${RESULTS_TARGETS[$i]}"
    status="${RESULTS_STATUS[$i]}"
    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}✓${NC} $target"
    else
        echo -e "  ${RED}✗${NC} $target"
    fi
    i=$((i + 1))
done
echo ""

# Exit with appropriate code
if [ $FAILED_TARGETS -eq 0 ]; then
    echo -e "${GREEN}All builds completed successfully!${NC}"
    exit 0
else
    echo -e "${RED}Some builds failed. Check the output above for details.${NC}"
    exit 1
fi

