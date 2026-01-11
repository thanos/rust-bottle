#!/bin/bash
# Build script for macOS/x86_64 (Intel) using Rosetta 2
# This uses arch -x86_64 to run commands in x86_64 mode

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

echo -e "${YELLOW}Building for macOS/x86_64 (Intel) using Rosetta 2${NC}"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Check if Rosetta 2 is available
if ! arch -x86_64 /usr/bin/true &>/dev/null; then
    echo -e "${RED}ERROR: Rosetta 2 is not available${NC}"
    echo "   Install Rosetta 2 with: softwareupdate --install-rosetta"
    exit 1
fi

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo -e "${RED}ERROR: Rust is not installed${NC}"
    echo "   Install it with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Install target if needed (using x86_64 arch)
echo "Installing target: x86_64-apple-darwin"
arch -x86_64 rustup target add x86_64-apple-darwin 2>/dev/null || true

# Set up environment for x86_64 builds
# We need to use arch -x86_64 for all cargo commands
CARGO_CMD="arch -x86_64 cargo"

# Build for each feature set
FAILED=0
for features in "${FEATURES[@]}"; do
    feature_name=${features:-"default"}
    echo -e "${YELLOW}Building with features: ${feature_name}${NC}"
    
    if [ -z "$features" ]; then
        if ! $CARGO_CMD build --target x86_64-apple-darwin --release; then
            echo -e "${RED}Build failed for ${feature_name}${NC}"
            FAILED=1
        fi
    else
        if ! $CARGO_CMD build --target x86_64-apple-darwin --features "$features" --release; then
            echo -e "${RED}Build failed for ${feature_name}${NC}"
            FAILED=1
        fi
    fi
    
    # Run tests
    echo -e "${YELLOW}Running tests with features: ${feature_name}${NC}"
    if [ -z "$features" ]; then
        if ! $CARGO_CMD test --target x86_64-apple-darwin; then
            echo -e "${RED}Tests failed for ${feature_name}${NC}"
            FAILED=1
        fi
    else
        if ! $CARGO_CMD test --target x86_64-apple-darwin --features "$features"; then
            echo -e "${RED}Tests failed for ${feature_name}${NC}"
            FAILED=1
        fi
    fi
    echo ""
done

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ macOS/x86_64 build completed successfully${NC}"
    exit 0
else
    echo -e "${RED}✗ macOS/x86_64 build failed${NC}"
    exit 1
fi

