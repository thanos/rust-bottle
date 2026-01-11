#!/bin/bash
# Prerequisites check script for cross-platform builds
# Checks if all required tools are installed and configured

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Checking Prerequisites for Cross-Platform Builds${NC}"
echo ""

ALL_OK=1

# Check Rust
echo -n "Checking Rust... "
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    echo -e "${GREEN}✓${NC} $RUST_VERSION"
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "   Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    ALL_OK=0
fi

# Check Cargo
echo -n "Checking Cargo... "
if command -v cargo &> /dev/null; then
    CARGO_VERSION=$(cargo --version)
    echo -e "${GREEN}✓${NC} $CARGO_VERSION"
else
    echo -e "${RED}✗ Not installed${NC}"
    ALL_OK=0
fi

# Check platform
echo -n "Checking platform... "
if [[ "$OSTYPE" == "darwin"* ]]; then
    ARCH=$(uname -m)
    OS_VERSION=$(sw_vers -productVersion)
    echo -e "${GREEN}✓${NC} macOS $OS_VERSION ($ARCH)"
    
    # Check Rosetta 2
    if [ "$ARCH" = "arm64" ]; then
        echo -n "Checking Rosetta 2... "
        if arch -x86_64 /usr/bin/true &>/dev/null 2>&1; then
            echo -e "${GREEN}✓ Available${NC}"
        else
            echo -e "${YELLOW}⚠ Not available${NC}"
            echo "   Install with: softwareupdate --install-rosetta"
            echo "   (Required for macOS/x86_64 builds)"
        fi
    fi
else
    echo -e "${YELLOW}⚠ Not macOS - some scripts may not work${NC}"
fi

# Check Docker/Podman
HAS_CONTAINER_RUNTIME=0

# Check Podman first (preferred if available)
echo -n "Checking Podman... "
if command -v podman &> /dev/null; then
    PODMAN_VERSION=$(podman --version)
    echo -e "${GREEN}✓${NC} $PODMAN_VERSION"
    
    # Check if Podman is working (no daemon needed)
    echo -n "Checking Podman... "
    if podman info &>/dev/null 2>&1; then
        echo -e "${GREEN}✓ Working${NC}"
        HAS_CONTAINER_RUNTIME=1
    else
        echo -e "${YELLOW}⚠ Installed but not working${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Not installed${NC}"
fi

# Check Docker
echo -n "Checking Docker... "
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo -e "${GREEN}✓${NC} $DOCKER_VERSION"
    
    # Check if Docker is running
    echo -n "Checking Docker daemon... "
    if docker info &>/dev/null 2>&1; then
        echo -e "${GREEN}✓ Running${NC}"
        HAS_CONTAINER_RUNTIME=1
        
        # Check Docker buildx for multi-platform
        echo -n "Checking Docker buildx... "
        if docker buildx version &>/dev/null 2>&1; then
            echo -e "${GREEN}✓ Available${NC}"
        else
            echo -e "${YELLOW}⚠ Not available${NC}"
            echo "   (Helpful for multi-platform builds)"
        fi
    else
        echo -e "${RED}✗ Not running${NC}"
        echo "   Start Docker Desktop and try again"
    fi
else
    echo -e "${YELLOW}⚠ Not installed${NC}"
fi

# Summary for container runtime
if [ $HAS_CONTAINER_RUNTIME -eq 0 ]; then
    echo -e "${YELLOW}⚠ No container runtime available${NC}"
    echo "   Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    echo "   Or install Podman from: https://podman.io/getting-started/installation"
    echo "   (Required for Linux builds)"
    ALL_OK=0
fi

# Check Rust targets
echo ""
echo "Checking Rust targets..."
TARGETS=(
    "aarch64-apple-darwin:macOS/ARM"
    "x86_64-apple-darwin:macOS/x86_64"
    "x86_64-unknown-linux-gnu:Linux/x86_64"
    "aarch64-unknown-linux-gnu:Linux/ARM64"
)

for target_info in "${TARGETS[@]}"; do
    IFS=':' read -r target name <<< "$target_info"
    echo -n "  $name ($target)... "
    if rustup target list --installed 2>/dev/null | grep -q "^$target$"; then
        echo -e "${GREEN}✓ Installed${NC}"
    else
        echo -e "${YELLOW}⚠ Not installed${NC}"
        echo "     Install with: rustup target add $target"
    fi
done

# Check cross tool (optional)
echo ""
echo -n "Checking cross tool (optional)... "
if command -v cross &> /dev/null; then
    CROSS_VERSION=$(cross --version 2>/dev/null || echo "installed")
    echo -e "${GREEN}✓${NC} $CROSS_VERSION"
    echo "   (Alternative to Docker for cross-compilation)"
else
    echo -e "${YELLOW}⚠ Not installed${NC}"
    echo "   Install with: cargo install cross --git https://github.com/cross-rs/cross"
    echo "   (Optional - Docker scripts work without it)"
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
if [ $ALL_OK -eq 1 ]; then
    echo -e "${GREEN}✓ All essential prerequisites are met!${NC}"
    echo "   You can run: ./scripts/build-all-platforms.sh"
    exit 0
else
    echo -e "${YELLOW}⚠ Some prerequisites are missing${NC}"
    echo "   Please install missing tools before running build scripts"
    exit 1
fi

