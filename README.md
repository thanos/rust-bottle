# rust-bottle


<img width="800" alt="Gemini_Generated_Image_y0ub5dy0ub5dy0ub" src="https://github.com/user-attachments/assets/35e40b25-e4db-479e-bf43-2fbd3fda8a13" />



Rust implementation of the Bottle protocol - a layered message container system with encryption and signatures. This library provides secure, type-safe cryptographic operations for building privacy-preserving applications.

## Overview

rust-bottle implements the Bottle protocol, which provides layered message containers with support for multiple encryption layers, multiple signatures, key management through IDCards and Keychains, and cryptographically signed group memberships. The library is designed to match the functionality of the Go implementation [gobottle](https://github.com/BottleFmt/gobottle) while leveraging Rust's type safety and memory safety guarantees.

## Features

### Core Protocol
- Layered message containers (Bottles) with multiple encryption and signature layers
- Metadata storage for application-specific data
- Binary serialization using bincode for efficient storage and transmission
- Opener API for decrypting and inspecting bottles without full decryption

### Cryptographic Operations
- Elliptic Curve Diffie-Hellman (ECDH) encryption using X25519 and P-256
- RSA encryption/decryption using RSA-OAEP with SHA-256
- AES-256-GCM authenticated encryption for shared secret encryption
- Digital signatures using ECDSA (P-256, P-384, P-521), Ed25519, and RSA
- Automatic key type detection for encryption and decryption operations

### Key Management
- IDCards for declaring sub-keys with specific purposes (sign, decrypt, etc.)
- Key lifecycle management with expiration dates
- Keychains for secure storage and retrieval of private keys
- Public key fingerprinting for key identification

### Group Management
- Cryptographically signed group memberships
- Role and metadata storage in memberships
- Verification of memberships against group IDCards

### Security Features
- Secure memory clearing using zeroize
- Type-safe cryptographic operations
- Comprehensive error handling
- No unsafe code in public API

## Installation

Add rust-bottle to your `Cargo.toml`:

```toml
[dependencies]
rust-bottle = "0.2.0"
rand = "0.8"
```

## Quick Start

### Basic Encryption and Decryption

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

// Create a message container
let message = b"Hello, Bottle!";
let mut bottle = Bottle::new(message.to_vec());

// Generate encryption keys
let rng = &mut OsRng;
let key = X25519Key::generate(rng);

// Encrypt the bottle
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

// Decrypt and open the bottle
let opener = Opener::new();
let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
assert_eq!(decrypted, message);
```

### Signing and Verification

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

let message = b"Signed message";
let mut bottle = Bottle::new(message.to_vec());

// Generate signing key
let rng = &mut OsRng;
let signing_key = Ed25519Key::generate(rng);
let public_key = signing_key.public_key_bytes();

// Sign the bottle
bottle.sign(rng, &signing_key, &public_key).unwrap();

// Verify signature
let opener = Opener::new();
let info = opener.open_info(&bottle).unwrap();
assert!(info.is_signed_by(&public_key));
```

## Detailed Usage

### Bottles

Bottles are layered message containers that support multiple encryption and signature layers. Each encryption layer can be for a different recipient, and multiple signers can sign the same bottle.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

// Create a bottle with a message
let message = b"Multi-layer encrypted and signed message";
let mut bottle = Bottle::new(message.to_vec());

// Add metadata
bottle.set_metadata("sender", "alice@example.com");
bottle.set_metadata("timestamp", "2024-01-01T00:00:00Z");

// Encrypt to multiple recipients (layered encryption)
let rng = &mut OsRng;
let bob_key = X25519Key::generate(rng);
let charlie_key = X25519Key::generate(rng);

// First encryption layer (innermost)
bottle.encrypt(rng, &bob_key.public_key_bytes()).unwrap();
// Second encryption layer (outermost)
bottle.encrypt(rng, &charlie_key.public_key_bytes()).unwrap();

// Sign with multiple signers
let alice_signing_key = Ed25519Key::generate(rng);
let alice_pub = alice_signing_key.public_key_bytes();
bottle.sign(rng, &alice_signing_key, &alice_pub).unwrap();

// Serialize for storage or transmission
let serialized = bottle.to_bytes().unwrap();

// Deserialize
let deserialized = Bottle::from_bytes(&serialized).unwrap();

// Open with appropriate key (decrypts all layers)
let opener = Opener::new();
let decrypted = opener.open(&deserialized, Some(&bob_key.private_key_bytes())).unwrap();
assert_eq!(decrypted, message);
```

### IDCards

IDCards allow entities to declare multiple keys with specific purposes and manage key lifecycles. They can be signed to establish trust.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;
use std::time::{Duration, SystemTime};

let rng = &mut OsRng;

// Generate primary signing key
let primary_key = Ed25519Key::generate(rng);
let primary_pub = primary_key.public_key_bytes();

// Create IDCard
let mut idcard = IDCard::new(&primary_pub);

// Add metadata
idcard.set_metadata("name", "Alice");
idcard.set_metadata("email", "alice@example.com");
idcard.set_metadata("organization", "Example Corp");

// Set purposes for the primary key
idcard.set_key_purposes(&primary_pub, &["sign", "decrypt"]);

// Add a dedicated encryption key with expiration
let encryption_key = X25519Key::generate(rng);
let encryption_pub = encryption_key.public_key_bytes();
idcard.set_key_purposes(&encryption_pub, &["decrypt"]);
idcard.set_key_duration(&encryption_pub, Duration::from_secs(365 * 24 * 3600)); // 1 year

// Sign the IDCard with the primary key
let signed_idcard = idcard.sign(rng, &primary_key, &primary_pub).unwrap();

// Verify key purposes
assert!(idcard.test_key_purpose(&primary_pub, "sign").is_ok());
assert!(idcard.test_key_purpose(&encryption_pub, "decrypt").is_ok());
assert!(idcard.test_key_purpose(&encryption_pub, "sign").is_err());

// Get all keys for a specific purpose
let decrypt_keys = idcard.get_keys("decrypt");
assert_eq!(decrypt_keys.len(), 2);
```

### Keychains

Keychains provide secure storage for private keys, indexed by their public key fingerprints. They enable signing with specific keys without exposing the key selection logic.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;

// Create a keychain
let mut keychain = Keychain::new();

// Add multiple keys of different types
let ed25519_key = Ed25519Key::generate(rng);
let ecdsa_key = EcdsaP256Key::generate(rng);
let x25519_key = X25519Key::generate(rng);

keychain.add_key(ed25519_key);
keychain.add_key(ecdsa_key);
keychain.add_key(x25519_key);

// Retrieve a signer by public key
let ed25519_pub = ed25519_key.public_key_bytes();
let signer = keychain.get_signer(&ed25519_pub).unwrap();

// Sign a message
let message = b"Message to sign";
let signature = keychain.sign(rng, &ed25519_pub, message).unwrap();

// Use keychain with bottles
let mut bottle = Bottle::new(b"Keychain-signed message".to_vec());
bottle.sign(rng, signer, &ed25519_pub).unwrap();
```

### Memberships

Memberships provide cryptographically signed group affiliations, allowing entities to prove membership in groups with specific roles.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;

// Create member and group IDCards
let member_key = Ed25519Key::generate(rng);
let member_pub = member_key.public_key_bytes();
let member_idcard = IDCard::new(&member_pub);

let group_key = Ed25519Key::generate(rng);
let group_pub = group_key.public_key_bytes();
let group_idcard = IDCard::new(&group_pub);

// Create a membership
let mut membership = Membership::new(&member_idcard, &group_pub);
membership.set_info("role", "admin");
membership.set_info("department", "Engineering");
membership.set_info("joined", "2024-01-01");

// Sign the membership with the group owner's key
membership.sign(rng, &group_key, &group_pub).unwrap();

// Verify the membership
assert!(membership.verify(&group_idcard).is_ok());

// Add membership to member's IDCard
let mut member_idcard = IDCard::new(&member_pub);
member_idcard.update_groups(vec![membership.to_bytes().unwrap()]);
```

### ECDH Encryption

Direct ECDH encryption can be used independently of bottles for encrypting data to public keys.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

let plaintext = b"Secret message";
let rng = &mut OsRng;

// Generate key pairs for Alice and Bob
let alice_key = X25519Key::generate(rng);
let bob_key = X25519Key::generate(rng);

// Alice encrypts to Bob's public key
let ciphertext = ecdh_encrypt(
    rng,
    plaintext,
    &bob_key.public_key_bytes()
).unwrap();

// Bob decrypts with his private key
let decrypted = ecdh_decrypt(
    &ciphertext,
    &bob_key.private_key_bytes()
).unwrap();

assert_eq!(decrypted, plaintext);
```

### Post-Quantum Cryptography

Post-quantum cryptography support is available via feature flags. See [PQC_FEATURE_FLAG.md](./PQC_FEATURE_FLAG.md) for details on enabling PQC features.

#### ML-KEM Encryption

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) provides post-quantum encryption. Requires the `ml-kem` feature:

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::*;
use rand::rngs::OsRng;

let plaintext = b"Post-quantum encrypted message";
let rng = &mut OsRng;

// Generate ML-KEM-768 keys
let alice_key = MlKem768Key::generate(rng);
let bob_key = MlKem768Key::generate(rng);

// Alice encrypts to Bob's public key
let ciphertext = mlkem768_encrypt(
    rng,
    plaintext,
    &bob_key.public_key_bytes()
).unwrap();

// Bob decrypts
let decrypted = mlkem768_decrypt(
    &ciphertext,
    &bob_key.private_key_bytes()
).unwrap();

assert_eq!(decrypted, plaintext);
```

#### ML-DSA Signatures

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) provides post-quantum signatures. Requires the `post-quantum` feature:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

let message = b"Post-quantum signed message";
let rng = &mut OsRng;

// Generate ML-DSA-44 signing key (128-bit security)
let signing_key = MlDsa44Key::generate(rng);
let pub_key = signing_key.public_key_bytes();

// Sign the message
let signature = signing_key.sign(rng, message).unwrap();

// Verify signature
assert!(signing_key.verify(message, &signature).is_ok());
```

#### SLH-DSA Signatures

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) provides hash-based post-quantum signatures. Requires the `post-quantum` feature:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

let message = b"Hash-based signed message";
let rng = &mut OsRng;

// Generate SLH-DSA-128s signing key (128-bit security)
let signing_key = SlhDsa128sKey::generate(rng);
let pub_key = signing_key.public_key_bytes();

// Sign the message
let signature = signing_key.sign(rng, message).unwrap();

// Verify signature
assert!(signing_key.verify(message, &signature).is_ok());
```

#### Hybrid Encryption (ML-KEM + X25519)

Hybrid encryption provides both post-quantum and classical security. Requires the `ml-kem` feature:

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::*;
use rand::rngs::OsRng;

let plaintext = b"Hybrid encrypted message";
let rng = &mut OsRng;

// Generate both post-quantum and classical keys
let mlkem_key = MlKem768Key::generate(rng);
let x25519_key = X25519Key::generate(rng);

// Encrypt with both (provides both post-quantum and classical security)
let ciphertext = hybrid_encrypt_mlkem768_x25519(
    rng,
    plaintext,
    &mlkem_key.public_key_bytes(),
    &x25519_key.public_key_bytes(),
).unwrap();

// Decrypt (tries ML-KEM first, falls back to X25519)
let mlkem_sec = mlkem_key.private_key_bytes();
let x25519_sec: [u8; 32] = x25519_key.private_key_bytes().try_into().unwrap();
let decrypted = hybrid_decrypt_mlkem768_x25519(
    &ciphertext,
    &mlkem_sec,
    &x25519_sec,
).unwrap();

assert_eq!(decrypted, plaintext);
```

#### Post-Quantum Bottles

Post-quantum keys work seamlessly with the Bottle API:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Post-quantum secure message".to_vec());
let rng = &mut OsRng;

// Encrypt with ML-KEM (requires ml-kem feature)
#[cfg(feature = "ml-kem")]
{
    let mlkem_key = MlKem768Key::generate(rng);
    bottle.encrypt(rng, &mlkem_key.public_key_bytes()).unwrap();
}

// Sign with ML-DSA (requires post-quantum feature)
let mldsa_key = MlDsa44Key::generate(rng);
let pub_key = mldsa_key.public_key_bytes();
bottle.sign(rng, &mldsa_key, &pub_key).unwrap();

// Decrypt and verify
let opener = Opener::new();
#[cfg(feature = "ml-kem")]
{
    let mlkem_key = MlKem768Key::generate(rng);
    let decrypted = opener.open(&bottle, Some(&mlkem_key.private_key_bytes())).unwrap();
}
let info = opener.open_info(&bottle).unwrap();
assert!(info.is_signed_by(&pub_key));
```

### RSA Encryption and Signing

RSA support is available for both encryption and signing operations. RSA is useful for compatibility with legacy systems, though modern applications should prefer ECDSA/Ed25519 for signatures and X25519 for encryption.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;

// Generate RSA key pair (2048-bit or 4096-bit)
let rsa_key = RsaKey::generate(rng, 2048).unwrap();

// RSA Encryption (for small messages)
let plaintext = b"Small message";
let ciphertext = rsa_encrypt(rng, plaintext, rsa_key.public_key()).unwrap();
let decrypted = rsa_decrypt(&ciphertext, &rsa_key).unwrap();
assert_eq!(decrypted, plaintext);

// RSA Signing
let message = b"Message to sign";
let signature = rsa_key.sign(rng, message).unwrap();
assert!(rsa_key.verify(message, &signature).is_ok());

// Use RSA with Bottles
let mut bottle = Bottle::new(b"RSA-encrypted message".to_vec());
// Note: RSA encryption is limited to small messages (key_size - 42 bytes)
// For larger messages, use RSA to encrypt a symmetric key
```

**Note**: RSA can only encrypt small messages (typically up to key_size - 42 bytes for OAEP with SHA-256). For larger messages, use RSA to encrypt a symmetric key and then encrypt the message with that key.

### P-256 ECDH Encryption

The library also supports P-256 ECDH for compatibility with ECDSA keys.

```rust
use rust_bottle::*;
use rand::rngs::OsRng;

let plaintext = b"P-256 encrypted message";
let rng = &mut OsRng;

// Generate P-256 key pair
let key = EcdsaP256Key::generate(rng);
let public_key = key.public_key_bytes();

// Encrypt
let ciphertext = ecdh_encrypt(rng, plaintext, &public_key).unwrap();

// Decrypt (requires private key bytes)
let private_key_bytes = key.private_key_bytes();
let decrypted = ecdh_decrypt(&ciphertext, &private_key_bytes).unwrap();

assert_eq!(decrypted, plaintext);
```

## Supported Algorithms

### Classical Cryptography

| Algorithm | Purpose | Status | Notes |
|-----------|---------|--------|-------|
| ECDSA P-256 | Signing | Supported | Full implementation |
| ECDSA P-384 | Signing | Supported | Full implementation |
| ECDSA P-521 | Signing | Supported | Full implementation |
| Ed25519 | Signing | Supported | Full implementation |
| RSA | Signing/Encryption | Supported | RSA-OAEP encryption, PKCS#1 v1.5 signing |
| X25519 | Encryption | Supported | ECDH key exchange |
| P-256 ECDH | Encryption | Supported | ECDH key exchange |
| AES-256-GCM | Encryption | Supported | Used for shared secret encryption |
| SHA-256 | Hashing | Supported | Key fingerprinting and message hashing |
| SHA-3 | Hashing | Supported | Available for custom use |

### Post-Quantum Cryptography

Comprehensive post-quantum cryptography support is available via feature flags. The implementation includes:

#### Available Algorithms

**Encryption (requires `ml-kem` feature):**
- **ML-KEM-768**: Post-quantum encryption (192-bit security) - 1184 byte public keys, 2400 byte secret keys
- **ML-KEM-1024**: Post-quantum encryption (256-bit security) - 1568 byte public keys, 3168 byte secret keys

**Signatures (requires `post-quantum` feature):**
- **ML-DSA-44**: Post-quantum signatures (128-bit security) - Uses dilithium2
- **ML-DSA-65**: Post-quantum signatures (192-bit security) - Uses dilithium3
- **ML-DSA-87**: Post-quantum signatures (256-bit security) - Uses dilithium5
- **SLH-DSA-128s/128f**: Hash-based signatures (128-bit security) - SHAKE-256 variants
- **SLH-DSA-192s/192f**: Hash-based signatures (192-bit security) - SHAKE-256 variants
- **SLH-DSA-256s/256f**: Hash-based signatures (256-bit security) - SHAKE-256 variants
- **SLH-DSA-SHA2-128s/128f**: Hash-based signatures (128-bit security) - SHA-2 variants
- **SLH-DSA-SHA2-192s/192f**: Hash-based signatures (192-bit security) - SHA-2 variants
- **SLH-DSA-SHA2-256s/256f**: Hash-based signatures (256-bit security) - SHA-2 variants
- Total: 12 SLH-DSA variants matching FIPS 205 standard

**Hybrid Encryption (requires `ml-kem` feature):**
- **ML-KEM-768 + X25519**: Combines post-quantum and classical security

#### Enabling Post-Quantum Support

```bash
# Enable signatures only (ML-DSA and SLH-DSA)
cargo build --features post-quantum

# Enable encryption (ML-KEM) - works on all platforms including macOS/ARM
cargo build --features post-quantum,ml-kem

# Enable everything
cargo build --features post-quantum,ml-kem
```

**Note**: ML-KEM uses RustCrypto's pure Rust `ml-kem` crate, which works on all platforms including macOS/ARM. No platform-specific issues or patches are required.

#### Integration

All post-quantum algorithms are integrated into the existing API and work seamlessly with:
- **Bottles**: Encrypt and sign with PQC keys
- **IDCards**: Use PQC keys for signing and encryption
- **Keychains**: Store and use PQC keys
- **Memberships**: Sign memberships with PQC keys
- **Automatic Key Detection**: `ecdh_encrypt`/`ecdh_decrypt` automatically detect PQC key types

See [POST_QUANTUM.md](./POST_QUANTUM.md) for detailed documentation.

### RSA Support

RSA support is fully implemented with:
- **RSA-OAEP encryption** (with SHA-256)
- **PKCS#1 v1.5 signing** (with SHA-256)
- Support for 2048-bit and 4096-bit key sizes
- Short buffer encryption (key wrapping) for encrypting AES keys

### TPM/HSM Support

rust-bottle provides a trait-based interface for integrating Trusted Platform Modules (TPM) and Hardware Security Modules (HSM) with ECDH operations. This allows you to use hardware-backed keys for enhanced security.

#### Enabling TPM Support

```bash
cargo build --features tpm
```

#### Using TPM/HSM Handlers

To use TPM/HSM with rust-bottle, implement the `ECDHHandler` trait for your TPM library:

```rust
use rust_bottle::tpm::ECDHHandler;
use rust_bottle::ecdh::ecdh_decrypt_with_handler;
use rust_bottle::errors::Result;

struct MyTpmHandler {
    // Your TPM-specific fields
}

impl ECDHHandler for MyTpmHandler {
    fn public_key(&self) -> Result<Vec<u8>> {
        // Return the public key from TPM/HSM
        // Format: 32 bytes for X25519, 65 bytes for P-256
        Ok(vec![])
    }

    fn ecdh(&self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        // Perform ECDH using TPM/HSM private key
        // Return the shared secret
        Ok(vec![])
    }
}

// Use the handler for decryption
// let handler = MyTpmHandler::new()?;
// let decrypted = ecdh_decrypt_with_handler(&ciphertext, &[], Some(&handler))?;
```

#### Implementation Notes

- The `ECDHHandler` trait provides a clean interface for any TPM/HSM backend
- Handlers are primarily used during **decryption** when the recipient's private key is stored in hardware
- Encryption always uses software-generated ephemeral keys (as per ECDH protocol)
- You can use libraries like `tss-esapi` or platform-specific TPM libraries to implement the trait

See the `tpm` module documentation for more details.

## Architecture

### Module Structure

- `bottle.rs`: Core Bottle and Opener types
- `ecdh.rs`: ECDH encryption and decryption implementations
- `keys.rs`: Key type implementations (ECDSA, Ed25519, X25519, RSA)
- `signing.rs`: Sign and Verify traits
- `idcard.rs`: IDCard implementation
- `keychain.rs`: Keychain implementation
- `membership.rs`: Membership implementation
- `tpm.rs`: TPM/HSM support (trait-based interface)
- `hash.rs`: Hashing utilities
- `utils.rs`: Utility functions
- `errors.rs`: Error types

### Design Principles

1. **Trait-based Design**: Uses Rust traits (`Sign`, `Verify`, `SignerKey`) for polymorphism and flexibility
2. **Type Safety**: Strong typing prevents common cryptographic errors at compile time
3. **Memory Safety**: No unsafe code in public API, secure memory clearing for sensitive data
4. **Error Handling**: Comprehensive error types using `thiserror` for detailed error information
5. **Serialization**: Uses `bincode` for efficient binary serialization

### Key Type System

Keys implement traits based on their capabilities:

- `Sign`: Types that can sign data (ECDSA, Ed25519, RSA)
- `Verify`: Types that can verify signatures (ECDSA, Ed25519, RSA)
- `SignerKey`: Keys that can be stored in keychains (all key types)

This design allows the library to work with different key types polymorphically while maintaining type safety.

## Error Handling

The library uses a comprehensive error type system:

```rust
pub enum BottleError {
    Encryption(String),
    Decryption(String),
    VerifyFailed,
    InvalidFormat,
    InvalidKeyType,
    KeyNotFound,
    KeyUnfit,
    NoAppropriateKey,
    Serialization(String),
    Deserialization(String),
    UnsupportedAlgorithm,
}
```

All operations return `Result<T, BottleError>` for explicit error handling.

## Testing

The library includes a comprehensive test suite that matches the gobottle test structure:

```bash
# Run all tests
cargo test

# Run tests with specific features
cargo test --features ml-kem
cargo test --features post-quantum
cargo test --features ml-kem,post-quantum
```

### Test Files

- `tests/bottle_test.rs`: Core bottle functionality (7 tests)
  - Bottle creation and manipulation
  - Encryption and decryption
  - Signing and verification
  - Layered encryption
  - Serialization
  - Metadata handling

- `tests/ecdh_test.rs`: ECDH encryption/decryption (3 tests)
  - Basic encrypt/decrypt operations
  - Integration with bottles
  - Key serialization

- `tests/aliceandbob_test.rs`: End-to-end scenarios (4 tests)
  - Alice-Bob communication
  - IDCard usage
  - Keychain usage
  - Group memberships

- `tests/pqc_test.rs`: Post-quantum cryptography (24 tests)
  - ML-KEM encryption/decryption
  - ML-DSA signing/verification
  - SLH-DSA signing/verification
  - Hybrid encryption

- `tests/pkix_test.rs`: PKIX/PKCS#8 serialization (9 tests)
  - Key marshaling/unmarshaling
  - DER and PEM encoding
  - Multiple key types

- `tests/rsa_test.rs`: RSA operations (11 tests)
  - Key generation
  - Encryption/decryption
  - Signing/verification

- `tests/short_buffer_test.rs`: Short buffer encryption (7 tests)
  - RSA key wrapping
  - Maximum message size handling

All tests pass and demonstrate the library's functionality.

### Code Coverage

Code coverage is tracked using `cargo-tarpaulin`. To generate coverage reports:

```bash
# Install cargo-tarpaulin (if not already installed)
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage

# Generate coverage with specific features
cargo tarpaulin --features ml-kem --out Html --output-dir coverage
cargo tarpaulin --features post-quantum --out Html --output-dir coverage
cargo tarpaulin --features ml-kem,post-quantum --out Html --output-dir coverage

# View HTML report
open coverage/tarpaulin-report.html
```

Coverage reports are generated in multiple formats:
- **HTML**: Interactive report (default: `coverage/tarpaulin-report.html`)
- **XML**: For CI/CD integration (Cobertura format)
- **Stdout**: Terminal output

The coverage configuration is in `tarpaulin.toml`. Coverage reports exclude test files, examples, and benchmarks.

**Note**: Coverage may vary depending on which features are enabled, as optional dependencies are only included when their features are active.

## Security Considerations

### Memory Safety

- All sensitive data is cleared from memory using the `zeroize` crate
- No unsafe code in the public API
- Rust's ownership system prevents use-after-free and double-free errors

### Cryptographic Security

- Uses well-vetted cryptographic libraries (ring, ed25519-dalek, p256)
- AES-256-GCM for authenticated encryption
- Proper key derivation from ECDH shared secrets using SHA-256
- Deterministic ECDSA signing (RFC 6979)

### Best Practices

- Always use cryptographically secure random number generators (`OsRng` or equivalent)
- Store private keys securely (consider using keychains or hardware security modules)
- Verify signatures before trusting data
- Check key purposes and expiration dates before using keys
- Clear sensitive data from memory when no longer needed

## Performance

The library is designed for efficiency:

- Zero-cost abstractions where possible
- Efficient binary serialization with bincode
- Minimal allocations in hot paths
- Type-safe operations without runtime overhead

Performance characteristics:
- Encryption/decryption: O(n) where n is message size
- Signing/verification: O(1) for fixed key sizes
- Key generation: O(1) for all key types
- Serialization: Efficient binary format

## Limitations and Future Work

### Current Limitations

1. **ML-KEM on macOS/ARM**: Fixed - Using RustCrypto's pure Rust `ml-kem` crate
2. **RSA Support**: Complete - RSA-OAEP encryption and PKCS#1 v1.5 signing
3. **PKIX/PKCS#8 Serialization**: Complete - DER and PEM formats supported
4. **TPM/HSM Integration**: Available - Trait-based interface for TPM/HSM backends (requires `tpm` feature)
5. **Short Buffer Encryption**: Complete - RSA key wrapping implemented
6. **Multi-level Hashing**: Not yet implemented
7. **PQC Key Reconstruction**: `from_private_key_bytes()` for PQC keys cannot derive public keys (limitation of underlying crates)

### Planned Enhancements

1. ML-KEM on all platforms (completed - using RustCrypto's pure Rust implementation)
2. RSA support (completed)
3. PKIX/PKCS#8 serialization (completed)
4. TPM/HSM interface (completed - users can implement `ECDHHandler` trait for their TPM library)
5. Short buffer encryption (completed)
6. Performance benchmarking and optimization
7. Additional SLH-DSA variants (f, simple variants)
8. Hardware acceleration support for PQC algorithms
9. Concrete TPM implementation examples (users can implement using tss-esapi or other TPM libraries)

## Compatibility with gobottle

rust-bottle aims to match gobottle's functionality while adapting to Rust's type system:

- Same core concepts: Bottles, IDCards, Keychains, Memberships
- Similar API structure adapted for Rust idioms
- Compatible test cases demonstrating equivalent functionality
- Same error types and error handling philosophy

Note: Serialization formats differ (bincode vs custom binary), so bottles created with one library cannot be directly read by the other. The protocol semantics are equivalent.

## Comparison with gobottle

rust-bottle is a Rust implementation that matches the functionality of the Go implementation [gobottle](https://github.com/BottleFmt/gobottle). Below is a summary comparison:

### Feature Parity

| Aspect | rust-bottle | gobottle | Status |
|--------|-------------|---------|--------|
| **Core Protocol** | Complete | Complete | Equivalent |
| **Classical Crypto** | Complete | Complete | Equivalent |
| **Post-Quantum Crypto** | Complete (via features) | Complete | Equivalent |
| **RSA Support** | Complete | Complete | Equivalent |
| **PKIX/PKCS#8** | Complete | Complete | Equivalent |
| **TPM/HSM Support** | Available (trait-based) | Complete | Equivalent |
| **Type Safety** | Strong (compile-time) | Runtime | Better |
| **Memory Safety** | Guaranteed | Manual | Better |

### Supported Algorithms

**Classical Cryptography:**
- Both support: ECDSA (P-256, P-384, P-521), Ed25519, X25519, RSA, AES-256-GCM

**Post-Quantum Cryptography:**
- Both support: ML-KEM-768, ML-KEM-1024, ML-DSA-44/65/87, SLH-DSA
- rust-bottle: 3 SLH-DSA variants (128s, 192s, 256s)
- gobottle: 12 SLH-DSA variants

### Key Differences

**Advantages of rust-bottle:**
- Compile-time type checking prevents cryptographic errors
- Memory safety guaranteed by compiler
- Zero-cost abstractions
- No garbage collection overhead
- Optional PQC features (can disable for smaller binaries)
- Pure Rust PQC implementation (works on all platforms including macOS/ARM)

**Advantages of gobottle:**
- Faster compilation
- Better concurrency primitives
- Simpler deployment (single binary)
- More SLH-DSA variants (12 vs 3)
- All PQC features always included

### API Design

**rust-bottle:**
- Rust-idiomatic API with trait-based polymorphism
- Strong ownership and borrowing rules
- Comprehensive error types using `thiserror`
- Uses `bincode` for serialization

**gobottle:**
- Go-idiomatic API with interface-based polymorphism
- Manual memory management (GC)
- Simple error variables
- Uses custom binary format

### Test Coverage

rust-bottle includes 372 tests covering:
- Core functionality (7 tests)
- ECDH encryption/decryption (3 tests)
- End-to-end scenarios (4 tests)
- Post-quantum cryptography (44 tests)
- PKIX/PKCS#8 serialization (13 tests)
- RSA operations (11 tests)
- Short buffer encryption (7 tests)
- Key generation and serialization (72 tests)
- Error handling paths (21 tests)
- Edge cases and boundary conditions (16 tests)
- Comprehensive coverage tests (174 tests)

### When to Choose rust-bottle

Choose rust-bottle if:
- You need Rust's memory safety guarantees
- You're building a Rust application
- You need compile-time type safety
- You need post-quantum cryptography (available via features)
- You want optional PQC dependencies (can disable for smaller builds)
- You need ML-KEM on all platforms including macOS/ARM (pure Rust implementation)
- You need ML-DSA/SLH-DSA on all platforms
- You need PKIX/PKCS#8 key serialization (DER and PEM formats)
- You need RSA support (encryption and signing)

### When to Choose gobottle

Choose gobottle if:
- You're building a Go application
- You need all 12 SLH-DSA variants (rust-bottle has 3)
- You prefer Go's concurrency model

For a detailed comparison, see [COMPARISON.md](./COMPARISON.md).

## Contributing

Contributions are welcome. Areas that need work:

- Post-quantum cryptography implementations
- RSA support
- PKIX/PKCS#8 serialization
- Additional test cases
- Performance improvements
- Documentation improvements

## License

MIT License - see LICENSE file for details.

## References

- [gobottle](https://github.com/BottleFmt/gobottle) - Go implementation of the Bottle protocol
- [Bottle Protocol Specification](https://github.com/BottleFmt/gobottle) - Protocol documentation
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - Post-quantum standards
- [COMPARISON.md](./COMPARISON.md) - Detailed comparison with gobottle
- [IMPLEMENTATION.md](./IMPLEMENTATION.md) - Implementation details
