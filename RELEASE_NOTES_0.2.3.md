# Release Notes - rust-bottle v0.2.3

**Release Date:** January 11, 2026

This release adds comprehensive cross-platform build and testing infrastructure, enabling automated builds and testing across all supported platforms from a single development machine.

## Overview

Version 0.2.3 adds cross-platform build scripts that enable building and testing rust-bottle on macOS/ARM, macOS/x86_64, Linux/x86_64, and Linux/ARM64 from a macOS/ARM (Apple Silicon) machine.

## New Features

### Cross-Platform Build Scripts

A complete set of build scripts has been added to the `scripts/` directory:

- **build-all-platforms.sh**: Orchestrates builds for all supported platforms
- **build-macos-arm.sh**: Native macOS/ARM (Apple Silicon) builds
- **build-macos-x86_64.sh**: macOS/x86_64 (Intel) builds using Rosetta 2
- **build-linux-x86_64.sh**: Linux/x86_64 builds using Docker or Podman
- **build-linux-arm64.sh**: Linux/ARM64 builds using Docker or Podman
- **build-using-cross.sh**: Alternative build method using the `cross` tool
- **check-prerequisites.sh**: Verifies required tools and setup before building
- **quick-build-test.sh**: Quick compilation test without running full test suite

### Container Support

Full support for both Docker and Podman:

- **Automatic Detection**: Scripts automatically detect and use Podman if available, otherwise fall back to Docker
- **Docker Images**: Pre-configured Docker images for Linux builds
  - `rust-bottle-linux-x86_64`: Linux x86_64 build environment
  - `rust-bottle-linux-arm64`: Linux ARM64 build environment with cross-compilation toolchain
- **Latest Rust**: Docker images use `rust:latest` to support Cargo.lock v4 format
- **Rootless Support**: Podman support enables rootless container builds

### Cross-Compilation Configuration

- **.cargo/config.toml**: Added cross-compilation linker configuration for Linux targets
- **Automatic Target Installation**: Scripts automatically install required Rust targets
- **Linker Configuration**: Pre-configured linkers for cross-compilation targets

## Build Infrastructure

### Platform Support

The build system supports building for:

1. **macOS/ARM (Apple Silicon)**: Native builds using the host toolchain
2. **macOS/x86_64 (Intel)**: Builds using Rosetta 2 translation
3. **Linux/x86_64**: Container-based builds with native x86_64 architecture
4. **Linux/ARM64**: Container-based builds with cross-compilation or QEMU emulation

### Feature Testing

All build scripts test multiple feature combinations:

- Default (no features)
- `ml-kem` only
- `post-quantum` only
- `ml-kem,post-quantum` (all features)

Each feature combination is built and tested to ensure compatibility across all platforms.

### Compatibility

- **Bash 3.2+ Compatible**: All scripts work with macOS's default bash version
- **Docker/Podman Support**: Works with either container runtime
- **Cargo.lock v4**: Updated Docker images support the latest lock file format

## Usage

### Quick Start

Check prerequisites:
```bash
./scripts/check-prerequisites.sh
```

Build for all platforms:
```bash
./scripts/build-all-platforms.sh
```

Build for individual platforms:
```bash
./scripts/build-macos-arm.sh
./scripts/build-macos-x86_64.sh
./scripts/build-linux-x86_64.sh
./scripts/build-linux-arm64.sh
```

### Prerequisites

- Rust toolchain (rustup)
- For macOS/x86_64: Rosetta 2 (usually pre-installed)
- For Linux builds: Docker Desktop or Podman

See `scripts/README_BUILD.md` for complete documentation.

## Documentation

### New Documentation

- **scripts/README_BUILD.md**: Guide covering:
  - Prerequisites and setup
  - Usage instructions for all build scripts
  - Docker vs Podman differences
  - Troubleshooting guide
  - CI/CD integration examples
  - Performance notes

### Updated Files

- **.gitignore**: Updated to allow `.cargo/config.toml` while ignoring other cargo files
- **.cargo/config.toml**: Added cross-compilation configuration

## Technical Details

### Docker Images

The Docker images are based on:
- `rust:latest`: Official Rust Docker image (latest stable)
- Includes: build-essential, pkg-config, libssl-dev
- Pre-configured with cross-compilation targets
- Supports Cargo.lock v4 format

### Script Architecture

- **Modular Design**: Individual scripts for each platform
- **Error Handling**: Comprehensive error checking and reporting
- **Color Output**: Colored terminal output for better readability
- **Status Tracking**: Build results are tracked and summarized

### Container Runtime Detection

Scripts use a `detect_container_runtime()` function that:
1. Checks for Podman first (preferred if available)
2. Falls back to Docker if Podman is not available
3. Uses the detected runtime for all container operations

## Benefits

- Automated testing across all platforms
- CI/CD integration support
- Cross-compilation verification
- Consistent build environments
- Documentation for setup and troubleshooting

## Migration Notes

No code changes are required. This is purely infrastructure addition. Existing build processes continue to work unchanged.

## Files Added

- `scripts/build-all-platforms.sh`
- `scripts/build-macos-arm.sh`
- `scripts/build-macos-x86_64.sh`
- `scripts/build-linux-x86_64.sh`
- `scripts/build-linux-arm64.sh`
- `scripts/build-using-cross.sh`
- `scripts/check-prerequisites.sh`
- `scripts/quick-build-test.sh`
- `scripts/Dockerfile.linux-x86_64`
- `scripts/Dockerfile.linux-arm64`
- `scripts/.dockerignore`
- `scripts/README_BUILD.md`
- `.cargo/config.toml`

## Files Modified

- `.gitignore`: Added cargo configuration patterns

## Testing

All build scripts have been tested on:
- macOS/ARM (Apple Silicon) with bash 3.2.57
- Docker Desktop and Podman compatibility verified
- All feature combinations tested across platforms

## Acknowledgments

This infrastructure enables cross-platform testing and verification of rust-bottle builds across all supported platforms.

## Links

- **Repository**: https://github.com/thanos/rust-bottle
- **Documentation**: https://docs.rs/rust-bottle
- **Build Scripts Documentation**: See `scripts/README_BUILD.md`

---
