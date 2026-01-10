#!/bin/bash
# Build script for Linux/x86_64 using Docker or Podman
# Uses Docker/Podman to build in a Linux environment

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

# Detect container runtime (Podman or Docker)
detect_container_runtime() {
    if command -v podman &> /dev/null; then
        if podman info &>/dev/null 2>&1; then
            echo "podman"
            return 0
        fi
    fi
    
    if command -v docker &> /dev/null; then
        if docker info &>/dev/null 2>&1; then
            echo "docker"
            return 0
        fi
    fi
    
    return 1
}

# Detect and set container runtime
CONTAINER_RUNTIME=$(detect_container_runtime || echo "")

if [ -z "$CONTAINER_RUNTIME" ]; then
    echo -e "${RED}ERROR: Neither Docker nor Podman is available${NC}"
    echo "   Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    echo "   Or install Podman from: https://podman.io/getting-started/installation"
    exit 1
fi

echo -e "${YELLOW}Building for Linux/x86_64 using ${CONTAINER_RUNTIME}${NC}"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Docker image name
IMAGE_NAME="rust-bottle-linux-x86_64"
DOCKERFILE="$SCRIPT_DIR/Dockerfile.linux-x86_64"

# Build Docker image if it doesn't exist or if Dockerfile is newer
if [ ! -f "$DOCKERFILE" ]; then
    echo -e "${RED}ERROR: Dockerfile not found: $DOCKERFILE${NC}"
    exit 1
fi

echo "Building container image: $IMAGE_NAME"
echo "Note: This may take a few minutes on first run..."
$CONTAINER_RUNTIME build -f "$DOCKERFILE" -t "$IMAGE_NAME" "$PROJECT_ROOT"

# Run builds in Docker container
FAILED=0
for features in "${FEATURES[@]}"; do
    feature_name=${features:-"default"}
    echo -e "${YELLOW}Building with features: ${feature_name}${NC}"
    
    # Prepare cargo command
    if [ -z "$features" ]; then
        CARGO_BUILD="cargo build --target x86_64-unknown-linux-gnu --release"
        CARGO_TEST="cargo test --target x86_64-unknown-linux-gnu"
    else
        CARGO_BUILD="cargo build --target x86_64-unknown-linux-gnu --features $features --release"
        CARGO_TEST="cargo test --target x86_64-unknown-linux-gnu --features $features"
    fi
    
    # Build
    if ! $CONTAINER_RUNTIME run --rm \
        -v "$PROJECT_ROOT:/workspace" \
        -w /workspace \
        "$IMAGE_NAME" \
        bash -c "$CARGO_BUILD"; then
        echo -e "${RED}Build failed for ${feature_name}${NC}"
        FAILED=1
    fi
    
    # Test
    echo -e "${YELLOW}Running tests with features: ${feature_name}${NC}"
    if ! $CONTAINER_RUNTIME run --rm \
        -v "$PROJECT_ROOT:/workspace" \
        -w /workspace \
        "$IMAGE_NAME" \
        bash -c "$CARGO_TEST"; then
        echo -e "${RED}Tests failed for ${feature_name}${NC}"
        FAILED=1
    fi
    echo ""
done

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Linux/x86_64 build completed successfully${NC}"
    exit 0
else
    echo -e "${RED}✗ Linux/x86_64 build failed${NC}"
    exit 1
fi

