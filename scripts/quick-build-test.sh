#!/bin/bash
# Quick build test script - tests builds without running full test suite
# Useful for quickly verifying compilation across platforms

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

echo -e "${BLUE}Quick Build Test - Compilation Only${NC}"
echo "This script quickly tests compilation (no tests) for all platforms"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Quick build function
quick_build() {
    local target=$1
    local name=$2
    local features=${3:-""}
    
    echo -e "${YELLOW}Building ${name}...${NC}"
    
    if [ -z "$features" ]; then
        if cargo build --target "$target" --release 2>&1 | grep -q "Finished"; then
            echo -e "${GREEN}✓ ${name} compiled successfully${NC}"
            return 0
        else
            echo -e "${RED}✗ ${name} compilation failed${NC}"
            return 1
        fi
    else
        if cargo build --target "$target" --features "$features" --release 2>&1 | grep -q "Finished"; then
            echo -e "${GREEN}✓ ${name} compiled successfully${NC}"
            return 0
        else
            echo -e "${RED}✗ ${name} compilation failed${NC}"
            return 1
        fi
    fi
}

FAILED=0

# 1. macOS/ARM (native)
if [ "$(uname -m)" = "arm64" ]; then
    rustup target add aarch64-apple-darwin 2>/dev/null || true
    if ! quick_build "aarch64-apple-darwin" "macOS/ARM" ""; then
        FAILED=1
    fi
    if ! quick_build "aarch64-apple-darwin" "macOS/ARM (ml-kem)" "ml-kem"; then
        FAILED=1
    fi
fi

# 2. macOS/x86_64 (if Rosetta 2 available)
if arch -x86_64 /usr/bin/true &>/dev/null 2>&1; then
    arch -x86_64 rustup target add x86_64-apple-darwin 2>/dev/null || true
    if ! arch -x86_64 cargo build --target x86_64-apple-darwin --release 2>&1 | grep -q "Finished"; then
        echo -e "${RED}✗ macOS/x86_64 compilation failed${NC}"
        FAILED=1
    else
        echo -e "${GREEN}✓ macOS/x86_64 compiled successfully${NC}"
    fi
fi

# 3. Linux targets (check if Docker or Podman is available)
HAS_CONTAINER_RUNTIME=0
if command -v podman &> /dev/null && podman info &>/dev/null 2>&1; then
    echo -e "${YELLOW}Podman is available - Linux builds can be tested${NC}"
    echo -e "${YELLOW}Run full build scripts for Linux targets${NC}"
    HAS_CONTAINER_RUNTIME=1
elif command -v docker &> /dev/null && docker info &>/dev/null 2>&1; then
    echo -e "${YELLOW}Docker is available - Linux builds can be tested${NC}"
    echo -e "${YELLOW}Run full build scripts for Linux targets${NC}"
    HAS_CONTAINER_RUNTIME=1
else
    echo -e "${YELLOW}No container runtime (Docker/Podman) available - skipping Linux builds${NC}"
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Quick build test passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Quick build test failed${NC}"
    exit 1
fi

