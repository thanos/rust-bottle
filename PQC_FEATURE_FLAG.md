# Post-Quantum Cryptography Feature Flag

## Overview

Post-quantum cryptography support in rust-bottle is available via optional Cargo feature flags. This allows the library to compile and work on all platforms, with PQC support available when explicitly enabled.

## Implementation

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) uses RustCrypto's pure Rust `ml-kem` crate, which:
- Is FIPS 203-compliant
- Works on all platforms including macOS/ARM (no platform-specific issues)
- Has no FFI or C dependencies (pure Rust)
- Does not require any patches or workarounds

## Usage

### Without Post-Quantum Support (Default)

The library compiles and works normally without PQC dependencies:

```bash
cargo build
cargo test
```

This is the default behavior and works on all platforms.

### With Post-Quantum Support

To enable post-quantum cryptography support:

```bash
# Enable signatures only (ML-DSA and SLH-DSA)
cargo build --features post-quantum

# Enable encryption (ML-KEM) - works on all platforms including macOS/ARM
cargo build --features post-quantum,ml-kem

# Enable everything
cargo build --features post-quantum,ml-kem
```

**Note**: ML-KEM works on all platforms including macOS/ARM. No platform-specific issues or patches are required.

## What's Included

When the `post-quantum` feature is enabled:
- **ML-DSA-44**, **ML-DSA-65**, **ML-DSA-87** signatures
- **SLH-DSA-128s**, **SLH-DSA-192s**, **SLH-DSA-256s** signatures

When the `ml-kem` feature is enabled (requires `post-quantum` for full functionality):
- **ML-KEM-768** and **ML-KEM-1024** encryption
- **Hybrid encryption** (ML-KEM + X25519)

## Code Changes

All post-quantum code is conditionally compiled:

```rust
#[cfg(feature = "ml-kem")]
pub struct MlKem768Key { ... }

#[cfg(feature = "ml-kem")]
pub fn mlkem768_encrypt(...) { ... }
```

The library gracefully handles missing PQC support - functions that require PQC will simply not be available when the feature is disabled.

## Testing

PQC tests are also conditionally compiled:

```rust
#[cfg(feature = "post-quantum")]
#[test]
fn test_mldsa44_signing() { ... }

#[cfg(feature = "ml-kem")]
#[test]
fn test_mlkem768_encryption() { ... }
```

Run PQC tests with:
```bash
# Test signatures only
cargo test --features post-quantum

# Test everything including ML-KEM
cargo test --features post-quantum,ml-kem
```

## Platform Compatibility

All post-quantum algorithms work on all platforms:

- **ML-DSA**: Works on all platforms (uses clean dilithium2/3/5 implementations)
- **SLH-DSA**: Works on all platforms (uses clean sphincsshake256 implementations)
- **ML-KEM**: Works on all platforms including macOS/ARM (pure Rust implementation)

No platform-specific patches, workarounds, or limitations are required.

## Recommendations

1. **For production use on all platforms**: Full PQC support (ML-KEM, ML-DSA, SLH-DSA) is available on all platforms including macOS/ARM.

2. **For maximum compatibility**: Keep PQC disabled by default and enable it only when needed.

3. **For smaller binaries**: Only enable the features you need (e.g., `post-quantum` for signatures only, or add `ml-kem` for encryption).

## Dependencies

Post-quantum cryptography support uses:

```toml
[dependencies]
# ML-KEM (pure Rust, works on all platforms)
ml-kem = { version = "0.3.0-pre.2", optional = true }
hybrid-array = { version = "0.4", optional = true }
typenum = { version = "1.17", optional = true }
zerocopy = { version = "0.7", optional = true }
rand_core_09 = { version = "0.9", package = "rand_core", optional = true }

# ML-DSA and SLH-DSA
pqcrypto-dilithium = { version = "0.5", optional = true }
pqcrypto-sphincsplus = { version = "0.5", optional = true }
pqcrypto-traits = { version = "0.3", optional = true }

[features]
post-quantum = ["pqcrypto-dilithium", "pqcrypto-sphincsplus", "pqcrypto-traits"]
ml-kem = ["dep:ml-kem", "dep:rand_core_09", "dep:zerocopy", "dep:hybrid-array", "dep:typenum"]
```
