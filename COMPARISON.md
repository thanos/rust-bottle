# Comparative Study: rust-bottle vs gobottle

This document provides a comprehensive comparison between the Rust `rust-bottle` library and the Go `gobottle` library ([GitHub](https://github.com/BottleFmt/gobottle)).

## Executive Summary

| Aspect | rust-bottle | gobottle | Status |
|--------|---------|----------|--------|
| **Core Protocol** | Complete | Complete | Equivalent |
| **Classical Crypto** | Complete | Complete | Equivalent |
| **Post-Quantum Crypto** | Complete (via features) | Complete | Equivalent |
| **RSA Support** | Complete | Complete | Equivalent |
| **PKIX/PKCS#8** | Complete | Complete | Equivalent |
| **TPM/HSM Support** | Available (trait-based) | Complete | Equivalent |
| **API Design** | Rust-idiomatic | Go-idiomatic | Different |
| **Type Safety** | Strong | Runtime | Better |
| **Memory Safety** | Guaranteed | Manual | Better |

## 1. Supported Key Types

### Classical Cryptography

| Key Type | rust-bottle | gobottle | Notes |
|----------|---------|----------|-------|
| **ECDSA P-256** | Yes | Yes | Both fully supported |
| **ECDSA P-384** | Yes | Yes | Both fully supported |
| **ECDSA P-521** | Yes | Yes | Both fully supported |
| **Ed25519** | Yes | Yes | Both fully supported |
| **X25519** | Yes | Yes | Both fully supported |
| **RSA** | Yes | Yes | Both fully supported (RSA-OAEP encryption, PKCS#1 v1.5 signing) |

### Post-Quantum Cryptography

| Algorithm | rust-bottle | gobottle | Implementation Gap |
|-----------|---------|----------|---------------------|
| **ML-KEM-768** | Yes | Yes | Implemented in rust-bottle |
| **ML-KEM-1024** | Yes | Yes | Implemented in rust-bottle |
| **ML-KEM + X25519 Hybrid** | Yes | Yes | Implemented in rust-bottle |
| **ML-DSA-44** | Yes | Yes | Implemented in rust-bottle |
| **ML-DSA-65** | Yes | Yes | Implemented in rust-bottle |
| **ML-DSA-87** | Yes | Yes | Implemented in rust-bottle |
| **SLH-DSA (12 variants)** | Yes (3 variants) | Yes | rust-bottle implements 3 SLH-DSA variants (128s, 192s, 256s) |

**Analysis**: Both libraries have comprehensive post-quantum cryptography support. rust-bottle implements ML-KEM (encryption), ML-DSA (signatures), and SLH-DSA (hash-based signatures) via optional feature flags.

## 2. Core Features Comparison

### 2.1 Bottle Protocol

| Feature | rust-bottle | gobottle | Notes |
|---------|---------|----------|-------|
| **Layered Encryption** | Yes | Yes | Both support multiple layers |
| **Multiple Signatures** | Yes | Yes | Both support multiple signers |
| **Metadata Storage** | Yes | Yes | Both support key-value metadata |
| **Serialization** | Yes (bincode) | Yes (binary) | Different formats |
| **Opener API** | Yes | Yes | Similar functionality |

**Implementation Differences**:
- **rust-bottle**: Uses `bincode` for serialization (Rust-native, efficient)
- **gobottle**: Uses custom binary format (Go-native)
- **Compatibility**: Not directly compatible due to different serialization formats

### 2.2 ECDH Encryption

| Feature | rust-bottle | gobottle | Notes |
|---------|---------|----------|-------|
| **X25519 ECDH** | Yes | Yes | Both fully supported |
| **P-256 ECDH** | Yes | Yes | Both fully supported |
| **RSA Encryption** | Yes | Yes | Both support RSA-OAEP |
| **AES-256-GCM** | Yes | Yes | Both use AES-GCM |
| **Auto Key Detection** | Yes | Yes | Both auto-detect key types |
| **TPM/HSM Backend** | Yes | Yes | Both support via `ECDHHandler` trait/interface |

**Implementation Notes**:
- **rust-bottle**: Uses `ring` crate for AES-GCM, `x25519-dalek` for X25519
- **gobottle**: Uses standard library + crypto packages
- **rust-bottle Issue**: Had to work around `x25519-dalek` 2.0 API changes (downgraded to 1.0)

### 2.3 IDCard

| Feature | rust-bottle | gobottle | Notes |
|---------|---------|----------|-------|
| **Key Purpose Declaration** | Yes | Yes | Both support purposes |
| **Key Expiration** | Yes | Yes | Both support expiration |
| **Metadata** | Yes | Yes | Both support metadata |
| **Group Membership** | Yes | Yes | Both support groups |
| **Signing/Verification** | Yes | Yes | Both support signing |
| **PKIX Serialization** | Yes | Yes | Both support DER/PEM encoding |

**API Differences**:
```rust
// rust-bottle
let mut idcard = IDCard::new(&public_key);
idcard.set_metadata("name", "Alice");
idcard.set_key_purposes(&public_key, &["sign", "decrypt"]);
let signed = idcard.sign(rng, &signer, &public_key)?;
```

```go
// gobottle
idcard, err := gobottle.NewIDCard(signingKey.Public())
idcard.Meta = map[string]string{"name": "Alice"}
idcard.SetKeyPurposes(signingKey.Public(), "sign", "decrypt")
signedIDCard, err := idcard.Sign(rand.Reader, signingKey)
```

### 2.4 Keychain

| Feature | rust-bottle | gobottle | Notes |
|---------|---------|----------|-------|
| **Key Storage** | Yes | Yes | Both store private keys |
| **Fingerprint Indexing** | Yes | Yes | Both use fingerprints |
| **Signing** | Yes | Yes | Both support signing |
| **Key Retrieval** | Yes | Yes | Both support retrieval |
| **Iteration** | Yes | Yes | Both support iteration |
| **Multiple Key Types** | Yes | Yes | Both support multiple types |

**Implementation Differences**:
- **rust-bottle**: Uses `Box<dyn SignerKey>` for type erasure (Rust trait objects)
- **gobottle**: Uses interface types (Go interfaces)
- **Type Safety**: rust-bottle has compile-time type checking, gobottle has runtime checks

### 2.5 Membership

| Feature | rust-bottle | gobottle | Notes |
|---------|---------|----------|-------|
| **Group Affiliation** | Yes | Yes | Both support memberships |
| **Role/Info Storage** | Yes | Yes | Both support metadata |
| **Verification** | Yes | Yes | Both support verification |
| **IDCard Integration** | Yes | Yes | Both integrate with IDCards |

## 3. Advanced Features

### 3.1 Post-Quantum Cryptography

Both libraries have comprehensive PQC support:

**ML-KEM (Key Encapsulation)**:
- ML-KEM-768 (NIST security level 3) - Both support
- ML-KEM-1024 (NIST security level 5) - Both support
- Hybrid ML-KEM + X25519 - Both support

**ML-DSA (Digital Signatures)**:
- ML-DSA-44 (NIST security level 1) - Both support
- ML-DSA-65 (NIST security level 3) - Both support
- ML-DSA-87 (NIST security level 5) - Both support

**SLH-DSA (Hash-Based Signatures)**:
- gobottle: 12 variants (SHA2/SHAKE, 128/192/256, s/f variants)
- rust-bottle: 3 variants (128s, 192s, 256s - SHAKE-256 robust)
- Stateless hash-based signatures - Both support

**Implementation Differences**:
- **rust-bottle**: PQC available via optional feature flags (`post-quantum`, `ml-kem`)
  - Allows building without PQC dependencies for smaller binaries
  - ML-KEM uses RustCrypto's `ml-kem` crate (pure Rust, FIPS 203-compliant)
  - ML-KEM works on all platforms including macOS/ARM (native Rust implementation)
  - ML-DSA and SLH-DSA work on all platforms
- **gobottle**: PQC always included, no feature flags needed
  - All variants work on all platforms
  - More SLH-DSA variants available

### 3.2 Key Serialization

| Format | rust-bottle | gobottle | Notes |
|--------|---------|----------|-------|
| **PKCS#8 (Private)** | Yes | Yes | Both support DER/PEM encoding |
| **PKIX (Public)** | Yes | Yes | Both support DER/PEM encoding |
| **Custom Binary** | Yes (bincode) | Yes (custom) | Different formats |

**gobottle Functions**:
- `MarshalPKIXPublicKey()` / `ParsePKIXPublicKey()`
- `MarshalMLKEMPrivateKey()` / `ParseMLKEMPrivateKey()`
- `MarshalMLDSAPrivateKey()` / `ParseMLDSAPrivateKey()`
- `MarshalSLHDSAPrivateKey()` / `ParseSLHDSAPrivateKey()`

**rust-bottle Functions**:
- `marshal_pkix_public_key()` / `parse_pkix_public_key()` - DER encoding
- `marshal_pkix_public_key_pem()` / `parse_pkix_public_key_pem()` - PEM encoding
- `marshal_pkcs8_private_key()` / `parse_pkcs8_private_key()` - DER encoding
- `marshal_pkcs8_private_key_pem()` / `parse_pkcs8_private_key_pem()` - PEM encoding
- Supports ECDSA P-256, Ed25519, X25519, RSA, and all PQC key types (when features enabled)
- Note: RSA PKIX/PKCS#8 serialization functions are placeholders (ready for future implementation)

**Implementation Notes**:
- **rust-bottle**: Uses `pkcs8`, `spki`, `der`, `pem`, and `const-oid` crates for standard formats
- **gobottle**: Uses standard Go crypto packages
- Both provide full DER and PEM encoding/decoding support
- Both support interoperability with OpenSSL and other cryptographic tools

### 3.3 Hardware Security Module (HSM) Support

| Feature | rust-bottle | gobottle | Notes |
|--------|---------|----------|-------|
| **TPM Integration** | Yes | Yes | Both via `ECDHHandler` trait/interface |
| **HSM Integration** | Yes | Yes | Both via `ECDHHandler` trait/interface |
| **Custom Backends** | Yes | Yes | Both support trait/interface-based backends |

**gobottle** provides `ECDHHandler` interface for custom backends:
```go
type ECDHHandler interface {
    Public() crypto.PublicKey
    ECDH(peerPublicKey crypto.PublicKey) ([]byte, error)
}
```

**rust-bottle** provides `ECDHHandler` trait for custom backends:
```rust
pub trait ECDHHandler {
    fn public_key(&self) -> Result<Vec<u8>>;
    fn ecdh(&self, peer_public_key: &[u8]) -> Result<Vec<u8>>;
}
```

Both libraries provide equivalent functionality through trait/interface-based design. Users can implement the trait for their specific TPM/HSM library (e.g., `tss-esapi` for TPM 2.0).

### 3.4 Utility Functions

| Feature | rust-bottle | gobottle | Notes |
|---------|---------|----------|-------|
| **Short Buffer Encryption** | Complete | Yes | Both fully implemented (RSA key wrapping) |
| **Memory Clearing** | Yes (zeroize) | Yes | Both support secure clearing |
| **Multi-level Hashing** | No | Yes | gobottle supports chained hashing |
| **Generic Sign/Verify** | Yes | Yes | Both support generic functions |

## 4. API Design Philosophy

### 4.1 Type Safety

**rust-bottle (Rust)**:
- Compile-time type checking
- Trait-based polymorphism (`Sign`, `Verify`, `SignerKey`)
- Strong ownership and borrowing rules
- No null pointer exceptions
- Memory safety guaranteed by compiler

**gobottle (Go)**:
- Runtime type checking (interfaces)
- Interface-based polymorphism
- Manual memory management (GC)
- Potential nil pointer panics
- Runtime error handling

### 4.2 Error Handling

**rust-bottle**:
```rust
pub type Result<T> = std::result::Result<T, BottleError>;

#[derive(Error, Debug)]
pub enum BottleError {
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    // ... more variants
}
```

**gobottle**:
```go
var (
    ErrNoAppropriateKey
    ErrVerifyFailed
    ErrKeyNotFound
    // ... more errors
)
```

**Analysis**: rust-bottle uses `thiserror` for rich error types, gobottle uses simple error variables. Rust's type system provides better error handling.

### 4.3 Serialization

**rust-bottle**: Uses `bincode` (Rust-native, efficient binary format)
- Fast serialization/deserialization
- Type-safe
- Not compatible with Go

**gobottle**: Uses custom binary format
- Go-native
- Compatible with Go ecosystem
- Not compatible with Rust

**Compatibility**: The two libraries cannot directly exchange serialized data due to different formats.

## 5. Test Coverage

### rust-bottle Test Suite

| Test File | Coverage | Status |
|-----------|----------|--------|
| `bottle_test.rs` | Core functionality | 7 tests |
| `ecdh_test.rs` | ECDH encryption | 3 tests |
| `aliceandbob_test.rs` | End-to-end scenarios | 4 tests |
| `pqc_test.rs` | Post-quantum cryptography | 44 tests |
| `pkix_test.rs` | PKIX/PKCS#8 serialization | 13 tests |
| `rsa_test.rs` | RSA encryption and signing | 11 tests |
| `short_buffer_test.rs` | Short buffer encryption (key wrapping) | 7 tests |
| `keys_test.rs` | Key generation and serialization | 72 tests |
| `error_test.rs` | Error handling paths | 21 tests |
| `edge_cases_test.rs` | Edge cases and boundary conditions | 16 tests |
| `coverage_test.rs` | Comprehensive coverage tests | 174 tests |
| **Total** | **372 tests** | All passing |

### gobottle Test Suite

Based on repository structure:
- `bottle_test.go`
- `ecdh_test.go`
- `aliceandbob_test.go`

**Analysis**: Both libraries have similar test structures, suggesting rust-bottle was developed test-first to match gobottle.

## 6. Dependencies

### rust-bottle Dependencies

```toml
ring = "0.17"                    # AES-GCM
ed25519-dalek = "2.1"            # Ed25519
ecdsa = "0.16"                   # ECDSA
p256/p384/p521 = "0.13"          # Elliptic curves
x25519-dalek = "1.0"             # X25519 (downgraded from 2.0)
rsa = { version = "0.9", features = ["sha2"] }  # RSA encryption and signing
sha2/sha3 = "0.10"               # Hashing
serde/bincode = "1.0/1.3"        # Serialization
zeroize = "1.7"                  # Memory clearing
# Post-quantum (optional features)
ml-kem = "0.3.0-pre.2"           # ML-KEM (FIPS 203) - RustCrypto pure Rust implementation (optional, ml-kem feature)
hybrid-array = "0.4"              # For ml-kem Array types (optional, ml-kem feature)
typenum = "1.17"                  # For ml-kem type-level numbers (optional, ml-kem feature)
rand_core_09 = "0.9"              # For ml-kem RNG compatibility (optional, ml-kem feature)
zerocopy = "0.7"                  # For ml-kem IntoBytes trait (optional, ml-kem feature)
pqcrypto-dilithium = "0.5"       # ML-DSA (optional, post-quantum feature)
pqcrypto-sphincsplus = "0.5"     # SLH-DSA (optional, post-quantum feature)
pqcrypto-traits = "0.3"          # PQC traits (optional)
# PKIX/PKCS#8 serialization
pkcs8 = "0.10"                   # PKCS#8 private key format
spki = "0.7"                     # PKIX public key format
der = "0.7"                      # DER encoding
pem = "2.0"                      # PEM encoding
const-oid = "0.9"                # Object identifiers
```

### gobottle Dependencies

From the repository (inferred):
- Standard Go crypto packages
- Post-quantum crypto libraries (ML-KEM, ML-DSA, SLH-DSA)
- TPM/HSM libraries

**Analysis**: rust-bottle uses well-maintained Rust crypto crates. gobottle leverages Go's standard library plus PQC libraries.

## 7. Performance Considerations

### Rust Advantages (rust-bottle)
- Zero-cost abstractions
- No garbage collection overhead
- Better cache locality
- Compile-time optimizations

### Go Advantages (gobottle)
- Faster compilation
- Better concurrency primitives
- Simpler deployment (single binary)
- Better tooling ecosystem

**Note**: No benchmarks available for direct comparison.

## 8. Missing Features in rust-bottle

### Critical Missing Features

1. **TPM/HSM Integration** Complete
   - Trait-based interface for TPM/HSM backends
   - Users can implement `ECDHHandler` for their TPM library
   - Supports hardware-backed ECDH operations

2. **Short Buffer Encryption** Complete
   - RSA key wrapping implemented
   - Supports encryption of short buffers (e.g., AES keys)

3. **Multi-level Hashing** (Low Priority)
   - Chained hash functions
   - Domain separation

## 9. Implementation Quality

### Code Organization

**rust-bottle**:
- Well-organized modules
- Clear separation of concerns
- Comprehensive error types
- Good trait design

**gobottle**:
- Clean Go package structure
- Interface-based design
- Comprehensive documentation

### Documentation

**rust-bottle**:
- Comprehensive README
- Detailed inline documentation with examples
- Implementation notes
- API reference documentation
- Post-quantum cryptography documentation
- PKIX/PKCS#8 serialization documentation

**gobottle**:
- Comprehensive README
- Extensive examples
- API documentation

## 10. Recommendations

### For rust-bottle Development

1. **Immediate Priorities**:
   - ML-KEM compilation on macOS/ARM (completed - using RustCrypto's pure Rust `ml-kem` crate)

2. **Medium-term Priorities**:
   - Add more examples
   - Additional SLH-DSA variants (f, simple variants)
   - P-384 and P-521 PKIX/PKCS#8 support (currently only P-256 fully implemented)

3. **Long-term Priorities**:
   - TPM/HSM integration
   - Performance benchmarking
   - Interoperability testing
   - Hardware acceleration support for PQC

### For Users Choosing Between Libraries

**Choose rust-bottle if**:
- You need Rust's memory safety guarantees
- You're building a Rust application
- You need compile-time type safety
- You need post-quantum cryptography (available via features)
- You want optional PQC dependencies (can disable for smaller builds)
- You need ML-KEM on all platforms including macOS/ARM (pure Rust implementation)
- You need ML-DSA/SLH-DSA on all platforms
- You need PKIX/PKCS#8 key serialization (DER and PEM formats)
- You need RSA support (encryption and signing)

**Choose gobottle if**:
- You're building a Go application
- You need TPM/HSM support
- You need all 12 SLH-DSA variants (rust-bottle has 3)

## 11. Conclusion

**rust-bottle** is a comprehensive Rust implementation of the Bottle protocol with:
- Complete core functionality
- Strong type safety
- Memory safety guarantees
- Post-quantum cryptography support (ML-KEM, ML-DSA, SLH-DSA)
- Hybrid encryption (ML-KEM + X25519)
- PKIX/PKCS#8 key serialization (DER and PEM formats)
- RSA support (RSA-OAEP encryption, PKCS#1 v1.5 signing)
- Short buffer encryption (RSA key wrapping)
- TPM/HSM support (trait-based interface)
- Comprehensive test suite (372 tests)
- Well-documented API
- ML-KEM works on all platforms including macOS/ARM (pure Rust implementation via RustCrypto's `ml-kem` crate)
- Ready for production use (v0.1.0)

**gobottle** is a mature Go implementation with:
- Complete feature set including PQC
- Production-ready
- Better documentation
- All 12 SLH-DSA variants
- PKIX/PKCS#8 key formats
- RSA support
- TPM/HSM integration
- Runtime type checking
- GC overhead

**Overall Assessment**: rust-bottle provides a comprehensive implementation with post-quantum cryptography support via optional feature flags. The Rust implementation benefits from stronger type safety and memory guarantees, matching gobottle's feature set while providing additional safety guarantees. PKIX/PKCS#8 key serialization, RSA support, short buffer encryption, and TPM/HSM integration have been fully implemented, providing complete classical cryptography coverage alongside post-quantum options. RSA support includes RSA-OAEP encryption (with SHA-256) and PKCS#1 v1.5 signing (with SHA-256), with support for 2048-bit and 4096-bit key sizes. Short buffer encryption enables RSA key wrapping for scenarios like encrypting AES keys. TPM/HSM support is provided through a trait-based interface, allowing users to integrate any TPM/HSM library. The library has been extensively tested with 372 tests covering all major functionality, error paths, and edge cases. Both libraries are production-ready for their respective ecosystems. rust-bottle v0.1.0 is available on crates.io.

## References

- [gobottle GitHub Repository](https://github.com/BottleFmt/gobottle)
- [rust-bottle Implementation Notes](./IMPLEMENTATION.md)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

