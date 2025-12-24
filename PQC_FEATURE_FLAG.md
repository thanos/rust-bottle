# Post-Quantum Cryptography Feature Flag

## Issue (RESOLVED)

The `pqcrypto-kyber` crate (version 0.5) had compatibility issues on macOS/ARM (AArch64) platforms, which have been **resolved** via a local patch. 

### Technical Details

`pqcrypto-kyber` v0.5.0 is designed to automatically select the appropriate implementation:
- **x86/x86_64**: Uses AVX2-optimized implementation if available at runtime, falls back to "clean" (generic/portable) implementation
- **AArch64 (ARM)**: Should automatically use the "clean" (generic/portable) implementation using `PQCLEAN_KYBER*_CLEAN_*` functions

However, there is a **bug** in `pqcrypto-kyber` v0.5.0 where AVX2 FFI function declarations (`PQCLEAN_KYBER*_AVX2_*`) are not properly guarded with `#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]` in the FFI bindings. This causes compilation failures on AArch64 platforms even though:
1. The code would never call these functions (runtime feature detection only runs on x86)
2. The "clean" implementation functions are available and should work correctly on AArch64

**Answer to your question**: Yes, on AArch64 we should be using the "clean" (generic/portable) implementation, not AVX2. The bug prevents the crate from compiling, but if it did compile, it would use the clean implementation.

## Solution

Post-quantum cryptography support has been made **optional** via a Cargo feature flag. This allows the library to compile and work on all platforms, with PQC support available when explicitly enabled.

## Usage

### Without Post-Quantum Support (Default)

The library compiles and works normally without PQC dependencies:

```bash
cargo build
cargo test
```

This is the default behavior and works on all platforms, including macOS/ARM.

### With Post-Quantum Support

To enable post-quantum cryptography support:

```bash
cargo build --features post-quantum
cargo test --features post-quantum
```

**Note**: ML-KEM now works on all platforms including macOS/ARM. The AVX2 compilation issue has been fixed via a local patch that adds proper `#[cfg]` guards to AVX2-specific functions. The patch is automatically applied via Cargo's `[patch.crates-io]` feature.

## What's Included

When the `post-quantum` feature is enabled:

- **ML-KEM-768** and **ML-KEM-1024** encryption (if `pqcrypto-kyber` compiles)
- **ML-DSA-44**, **ML-DSA-65**, **ML-DSA-87** signatures
- **SLH-DSA-128s**, **SLH-DSA-192s**, **SLH-DSA-256s** signatures
- **Hybrid encryption** (ML-KEM + X25519)

## Code Changes

All post-quantum code is conditionally compiled:

```rust
#[cfg(feature = "post-quantum")]
pub struct MlKem768Key { ... }

#[cfg(feature = "post-quantum")]
pub fn mlkem768_encrypt(...) { ... }
```

The library gracefully handles missing PQC support - functions that require PQC will simply not be available when the feature is disabled.

## Testing

PQC tests are also conditionally compiled:

```rust
#[cfg(feature = "post-quantum")]
#[test]
fn test_mlkem768_encryption() { ... }
```

Run PQC tests with:
```bash
cargo test --features post-quantum
```

## Recommendations

1. **For production use on all platforms**: Full PQC support (ML-KEM, ML-DSA, SLH-DSA) is now available on all platforms including macOS/ARM.

2. **For maximum compatibility**: Keep PQC disabled by default and enable it only when needed.

## Technical Details

The fix involved patching `pqcrypto-kyber` v0.5.0 to add `#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]` guards to AVX2-specific functions (`keypair_avx2`, `encapsulate_avx2`, `decapsulate_avx2`) in the `kyber512.rs`, `kyber768.rs`, and `kyber1024.rs` modules. This ensures that:
- On x86/x86_64: AVX2-optimized code is used when available, falling back to clean implementation
- On AArch64 (macOS/ARM): Only the clean (generic/portable) implementation is compiled and used

The patch is located in `patches/pqcrypto-kyber-0.5.0/` and is automatically applied via Cargo's `[patch.crates-io]` feature in `Cargo.toml`.

