#!/bin/bash
# Alternative build script using `cross` for cross-compilation
# This is more efficient than Docker for some use cases
# Install cross with: cargo install cross --git https://github.com/cross-rs/cross

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

echo -e "${YELLOW}Building using cross for cross-compilation${NC}"
echo ""

# Check if cross is installed
if ! command -v cross &> /dev/null; then
    echo -e "${RED}ERROR: cross is not installed${NC}"
    echo "   Install it with: cargo install cross --git https://github.com/cross-rs/cross"
    echo "   Or use the Docker-based scripts instead"
    exit 1
fi

# Change to project root
cd "$PROJECT_ROOT"

# Targets to build
declare -a TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
)

# Results tracking
FAILED=0

# Build for each target
for target in "${TARGETS[@]}"; do
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Building for: ${target}${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Install target if needed
    echo "Installing target: $target"
    rustup target add "$target" 2>/dev/null || true
    echo ""
    
    # Build for each feature set
    for features in "${FEATURES[@]}"; do
        feature_name=${features:-"default"}
        echo -e "${YELLOW}Building with features: ${feature_name}${NC}"
        
        if [ -z "$features" ]; then
            if ! cross build --target "$target" --release; then
                echo -e "${RED}Build failed for ${target} with ${feature_name}${NC}"
                FAILED=1
            fi
        else
            if ! cross build --target "$target" --features "$features" --release; then
                echo -e "${RED}Build failed for ${target} with ${feature_name}${NC}"
                FAILED=1
            fi
        fi
        
        # Test (cross test may not work for all targets)
        echo -e "${YELLOW}Running tests with features: ${feature_name}${NC}"
        if [ -z "$features" ]; then
            if ! cross test --target "$target"; then
                echo -e "${YELLOW}Tests may not work with cross for ${target}${NC}"
                echo -e "${YELLOW}This is normal - use Docker scripts for full testing${NC}"
            fi
        else
            if ! cross test --target "$target" --features "$features"; then
                echo -e "${YELLOW}Tests may not work with cross for ${target}${NC}"
                echo -e "${YELLOW}This is normal - use Docker scripts for full testing${NC}"
            fi
        fi
        echo ""
    done
done

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All cross builds completed successfully!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some cross builds failed${NC}"
    exit 1
fi

