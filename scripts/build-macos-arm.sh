#!/bin/bash
# Build script for macOS/ARM (Apple Silicon) - native build
# This is the native platform, so no special setup needed

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

echo -e "${YELLOW}Building for macOS/ARM (Apple Silicon) - Native${NC}"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Verify we're on ARM
ARCH=$(uname -m)
if [ "$ARCH" != "arm64" ]; then
    echo -e "${RED}ERROR: This script should run on ARM64 Mac${NC}"
    exit 1
fi

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo -e "${RED}ERROR: Rust is not installed${NC}"
    echo "   Install it with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Install target if needed
echo "Installing target: aarch64-apple-darwin"
rustup target add aarch64-apple-darwin 2>/dev/null || true

# Build for each feature set
FAILED=0
for features in "${FEATURES[@]}"; do
    feature_name=${features:-"default"}
    echo -e "${YELLOW}Building with features: ${feature_name}${NC}"
    
    if [ -z "$features" ]; then
        if ! cargo build --target aarch64-apple-darwin --release; then
            echo -e "${RED}Build failed for ${feature_name}${NC}"
            FAILED=1
        fi
    else
        if ! cargo build --target aarch64-apple-darwin --features "$features" --release; then
            echo -e "${RED}Build failed for ${feature_name}${NC}"
            FAILED=1
        fi
    fi
    
    # Run tests
    echo -e "${YELLOW}Running tests with features: ${feature_name}${NC}"
    if [ -z "$features" ]; then
        if ! cargo test --target aarch64-apple-darwin; then
            echo -e "${RED}Tests failed for ${feature_name}${NC}"
            FAILED=1
        fi
    else
        if ! cargo test --target aarch64-apple-darwin --features "$features"; then
            echo -e "${RED}Tests failed for ${feature_name}${NC}"
            FAILED=1
        fi
    fi
    echo ""
done

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ macOS/ARM build completed successfully${NC}"
    exit 0
else
    echo -e "${RED}✗ macOS/ARM build failed${NC}"
    exit 1
fi

