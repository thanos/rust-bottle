# Cross-Platform Build Scripts

This directory contains scripts for building and testing `rust-bottle` on multiple platforms from a macOS/ARM (Apple Silicon) machine.

## Supported Platforms

- **macOS/ARM** (Apple Silicon) - Native build
- **macOS/x86_64** (Intel) - Using Rosetta 2
- **Linux/x86_64** - Using Docker or Podman
- **Linux/ARM64** - Using Docker or Podman with cross-compilation

## Prerequisites

### Check Prerequisites

Before running build scripts, check if all prerequisites are met:

```bash
./scripts/check-prerequisites.sh
```

This will verify:
- Rust and Cargo installation
- Platform information
- Rosetta 2 availability (for macOS/x86_64)
- Docker or Podman installation and status
- Required Rust targets
- Optional `cross` tool

### For All Builds
- Rust toolchain installed (`rustup`)
- Cargo installed

### For macOS/x86_64 Builds
- Rosetta 2 installed (usually pre-installed on Apple Silicon Macs)
  - If not installed: `softwareupdate --install-rosetta`

### For Linux Builds
- **Docker** or **Podman** installed and working
  - **Docker Desktop**: https://www.docker.com/products/docker-desktop
  - **Podman**: https://podman.io/getting-started/installation
  - Scripts automatically detect and use whichever is available (Podman is preferred if both are installed)
  - Ensure Docker daemon is running (if using Docker) before executing Linux build scripts
  - Podman doesn't require a daemon

## Quick Start

### Build All Platforms

Run the main script to build for all platforms:

```bash
./scripts/build-all-platforms.sh
```

This will:
1. Build for macOS/ARM (native)
2. Build for macOS/x86_64 (using Rosetta 2)
3. Build for Linux/x86_64 (using Docker or Podman)
4. Build for Linux/ARM64 (using Docker or Podman)

### Build Individual Platforms

You can also build for individual platforms:

```bash
# macOS/ARM (native)
./scripts/build-macos-arm.sh

# macOS/x86_64 (Rosetta 2)
./scripts/build-macos-x86_64.sh

# Linux/x86_64 (Docker or Podman)
./scripts/build-linux-x86_64.sh

# Linux/ARM64 (Docker or Podman)
./scripts/build-linux-arm64.sh
```

### Quick Build Test (Compilation Only)

For a quick test that only checks compilation (no tests):

```bash
./scripts/quick-build-test.sh
```

### Alternative: Using `cross` Tool

For more efficient cross-compilation, you can use the `cross` tool:

```bash
# Install cross first
cargo install cross --git https://github.com/cross-rs/cross

# Run cross builds
./scripts/build-using-cross.sh
```

**Note**: The `cross` tool is faster for compilation but may not support running tests for all targets. Use container-based scripts (Docker/Podman) for full test coverage.

## How It Works

### macOS/ARM (Native)
- Uses the native Rust toolchain
- No special setup required
- Fastest build option

### macOS/x86_64 (Rosetta 2)
- Uses `arch -x86_64` to run commands in x86_64 mode
- Automatically installs the `x86_64-apple-darwin` target
- All cargo commands run through Rosetta 2

### Linux/x86_64 (Docker/Podman)
- Uses Docker or Podman with the official Rust image
- Automatically detects and uses Podman if available, otherwise falls back to Docker
- Builds in a Linux container environment
- Uses native x86_64 container runtime (or emulation if needed)

### Linux/ARM64 (Docker/Podman)
- Uses Docker or Podman with cross-compilation support
- Automatically detects and uses Podman if available, otherwise falls back to Docker
- Can use native ARM64 container runtime (if available) or QEMU emulation
- Installs cross-compilation toolchain (`gcc-aarch64-linux-gnu`)

## Feature Testing

All scripts test multiple feature combinations:
- Default (no features)
- `ml-kem` only
- `post-quantum` only
- `ml-kem,post-quantum` (all features)

Each feature combination is built and tested.

## Container Images

The container images (Docker/Podman compatible) are built automatically when you run the Linux build scripts. They are based on:
- `rust:latest` - Official Rust Docker image (latest stable version)
- Includes build dependencies (build-essential, pkg-config, libssl-dev)
- Pre-configured with cross-compilation targets
- Supports Cargo.lock v4 format

### Container Image Names
- `rust-bottle-linux-x86_64` - For Linux x86_64 builds
- `rust-bottle-linux-arm64` - For Linux ARM64 builds

### Rebuilding Container Images

Container images are automatically rebuilt if the Dockerfile changes. To force a rebuild:

```bash
# Using Docker
docker build -f scripts/Dockerfile.linux-x86_64 -t rust-bottle-linux-x86_64 .
docker build -f scripts/Dockerfile.linux-arm64 -t rust-bottle-linux-arm64 .

# Using Podman
podman build -f scripts/Dockerfile.linux-x86_64 -t rust-bottle-linux-x86_64 .
podman build -f scripts/Dockerfile.linux-arm64 -t rust-bottle-linux-arm64 .
```

**Note**: The scripts automatically detect whether to use Docker or Podman and use the appropriate command.

## Troubleshooting

### Rosetta 2 Not Available
If you get an error about Rosetta 2:
```bash
softwareupdate --install-rosetta
```

### Container Runtime Not Working
If container commands fail:

**For Docker:**
1. Start Docker Desktop
2. Wait for it to fully start
3. Verify with: `docker info`

**For Podman:**
1. Podman doesn't require a daemon, but verify it's working: `podman info`
2. On macOS, you may need Podman Machine: `podman machine init && podman machine start`
3. Verify with: `podman info`

### Cross-Compilation Issues
If Linux ARM64 builds fail:
1. Ensure your container runtime (Docker/Podman) supports multi-platform builds
2. Check that QEMU is available (usually automatic with Docker Desktop or Podman)
3. Try building the container image manually to see detailed errors
4. For Podman, ensure `podman machine` is configured for multi-arch support

### Rust Target Not Installed
The scripts automatically install required targets, but if you encounter issues:
```bash
# macOS targets
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin

# Linux targets (for container builds)
# These are installed inside containers automatically
```

### Permission Denied
If scripts are not executable:
```bash
chmod +x scripts/build-*.sh
```

## Build Artifacts

Build artifacts are stored in:
- `target/aarch64-apple-darwin/release/` - macOS/ARM builds
- `target/x86_64-apple-darwin/release/` - macOS/x86_64 builds
- `target/x86_64-unknown-linux-gnu/release/` - Linux/x86_64 builds (in containers)
- `target/aarch64-unknown-linux-gnu/release/` - Linux/ARM64 builds (in containers)

## Performance Notes

- **macOS/ARM**: Fastest (native)
- **macOS/x86_64**: Slower (Rosetta 2 translation overhead)
- **Linux/x86_64**: Medium speed (container overhead, but native architecture)
- **Linux/ARM64**: Slowest (container + cross-compilation or emulation)

## CI/CD Integration

These scripts can be integrated into CI/CD pipelines:
- GitHub Actions
- GitLab CI
- CircleCI
- etc.

Example GitHub Actions workflow:
```yaml
- name: Build all platforms
  run: ./scripts/build-all-platforms.sh
```

## Advanced Usage

### Building Specific Features Only

You can modify the scripts to test only specific features by editing the `FEATURES` array in each script.

### Custom Container Images

You can customize the container images (Docker/Podman compatible) by editing the Dockerfiles:
- `scripts/Dockerfile.linux-x86_64`
- `scripts/Dockerfile.linux-arm64`

### Parallel Builds

The scripts run builds sequentially. For faster execution, you could modify them to run in parallel, but be aware of resource constraints (especially with containers).

## Configuration

Cross-compilation settings are configured in `.cargo/config.toml`. You can modify this file to adjust linker settings or add additional targets.

## Podman vs Docker

The scripts automatically detect and use **Podman** if available, otherwise fall back to **Docker**. Both are fully supported:

### Podman Advantages
- No daemon required (rootless by default)
- Better security model (rootless containers)
- Docker-compatible commands
- Works well on macOS with Podman Machine

### Docker Advantages
- More widely used and documented
- Better GUI support (Docker Desktop)
- More mature ecosystem

### Which to Use?
- **Use Podman** if you prefer rootless containers and don't need Docker Desktop
- **Use Docker** if you want Docker Desktop's GUI and ecosystem
- Scripts work with either - they auto-detect what's available

## See Also

- [Rust Cross-Compilation Guide](https://rust-lang.github.io/rustup/cross-compilation.html)
- [Docker Multi-Platform Builds](https://docs.docker.com/build/building/multi-platform/)
- [Podman Documentation](https://docs.podman.io/)
- [Rosetta 2 Documentation](https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment)

