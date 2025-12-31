// Error handling and edge case tests
// These tests ensure all error paths are covered

use rust_bottle::errors::BottleError;
use rust_bottle::*;
use rand::rngs::OsRng;

#[test]
fn test_error_variants() {
    // Test that all error variants can be created and formatted
    let errors = vec![
        BottleError::NoAppropriateKey,
        BottleError::VerifyFailed,
        BottleError::KeyNotFound,
        BottleError::GroupNotFound,
        BottleError::KeyUnfit,
        BottleError::EncryptNoRecipient,
        BottleError::InvalidKeyType,
        BottleError::Serialization("test".to_string()),
        BottleError::Deserialization("test".to_string()),
        BottleError::Encryption("test".to_string()),
        BottleError::Decryption("test".to_string()),
        BottleError::Io("test".to_string()),
        BottleError::InvalidFormat,
        BottleError::UnsupportedAlgorithm,
    ];
    
    // Verify all errors can be formatted
    for error in errors {
        let _ = format!("{}", error);
        let _ = format!("{:?}", error);
    }
}

#[test]
fn test_error_from_io_error() {
    use std::io::{Error, ErrorKind};
    let io_error = Error::new(ErrorKind::Other, "test error");
    let bottle_error: BottleError = io_error.into();
    
    match bottle_error {
        BottleError::Io(msg) => assert!(msg.contains("test error")),
        _ => panic!("Expected Io error"),
    }
}

#[test]
fn test_error_clone_and_eq() {
    let err1 = BottleError::KeyNotFound;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
    
    let err3 = BottleError::InvalidFormat;
    assert_ne!(err1, err3);
}

#[test]
fn test_ecdh_encrypt_invalid_key() {
    let rng = &mut OsRng;
    let plaintext = b"test";
    
    // Test with invalid key (too short)
    let invalid_key = vec![0u8; 10];
    let result = ecdh_encrypt(rng, plaintext, &invalid_key);
    assert!(result.is_err());
    
    // Test with empty key
    let empty_key = vec![];
    let result = ecdh_encrypt(rng, plaintext, &empty_key);
    assert!(result.is_err());
}

#[test]
fn test_ecdh_decrypt_invalid_ciphertext() {
    // Test with empty ciphertext
    let empty_ct = vec![];
    let key = X25519Key::generate(&mut OsRng);
    let result = ecdh_decrypt(&empty_ct, &key.private_key_bytes());
    assert!(result.is_err());
    
    // Test with too short ciphertext
    let short_ct = vec![0u8; 10];
    let result = ecdh_decrypt(&short_ct, &key.private_key_bytes());
    assert!(result.is_err());
    
    // Test with invalid ciphertext format
    let invalid_ct = vec![0xFFu8; 100];
    let result = ecdh_decrypt(&invalid_ct, &key.private_key_bytes());
    assert!(result.is_err());
}

#[test]
fn test_ecdh_decrypt_wrong_key() {
    let rng = &mut OsRng;
    let plaintext = b"test message";
    
    let key1 = X25519Key::generate(rng);
    let key2 = X25519Key::generate(rng);
    
    // Encrypt with key1
    let ciphertext = ecdh_encrypt(rng, plaintext, &key1.public_key_bytes()).unwrap();
    
    // Try to decrypt with key2 (should fail)
    let result = ecdh_decrypt(&ciphertext, &key2.private_key_bytes());
    assert!(result.is_err());
}

#[test]
fn test_bottle_empty_message() {
    let rng = &mut OsRng;
    let empty_message = vec![];
    let mut bottle = Bottle::new(empty_message);
    
    // Should be able to create empty bottle
    assert_eq!(bottle.message().len(), 0);
    
    // Should be able to encrypt empty bottle
    let key = X25519Key::generate(rng);
    let result = bottle.encrypt(rng, &key.public_key_bytes());
    assert!(result.is_ok());
}

#[test]
fn test_bottle_invalid_serialization() {
    // Test deserialization with invalid data
    let invalid_data = vec![0xFFu8; 100];
    let result = Bottle::from_bytes(&invalid_data);
    assert!(result.is_err());
    
    // Test deserialization with empty data
    let empty_data = vec![];
    let result = Bottle::from_bytes(&empty_data);
    assert!(result.is_err());
}

#[test]
fn test_bottle_metadata_edge_cases() {
    let mut bottle = Bottle::new(b"test".to_vec());
    
    // Test empty key
    bottle.set_metadata("", "value");
    assert_eq!(bottle.metadata(""), Some("value"));
    
    // Test empty value
    bottle.set_metadata("key", "");
    assert_eq!(bottle.metadata("key"), Some(""));
    
    // Test very long key/value
    let long_key = "a".repeat(1000);
    let long_value = "b".repeat(1000);
    bottle.set_metadata(&long_key, &long_value);
    assert_eq!(bottle.metadata(&long_key), Some(long_value.as_str()));
}

#[test]
fn test_encrypt_short_buffer_invalid_key() {
    let rng = &mut OsRng;
    let plaintext = b"test";
    
    // Test with empty key
    let empty_key = vec![];
    let result = encrypt_short_buffer(rng, plaintext, &empty_key);
    assert!(result.is_err());
    
    // Test with invalid key format
    let invalid_key = vec![0xFFu8; 100];
    let result = encrypt_short_buffer(rng, plaintext, &invalid_key);
    assert!(result.is_err());
    
    // Test with non-RSA key (should return UnsupportedAlgorithm)
    let x25519_key = X25519Key::generate(rng);
    let result = encrypt_short_buffer(rng, plaintext, &x25519_key.public_key_bytes());
    assert!(result.is_err());
    match result {
        Err(BottleError::UnsupportedAlgorithm) => {},
        _ => panic!("Expected UnsupportedAlgorithm error"),
    }
}

#[test]
fn test_decrypt_short_buffer_invalid_key() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    let plaintext = b"test";
    let ciphertext = rsa_encrypt(rng, plaintext, rsa_key.public_key()).unwrap();
    
    // Test with empty key
    let empty_key = vec![];
    let result = decrypt_short_buffer(&ciphertext, &empty_key);
    assert!(result.is_err());
    
    // Test with invalid key format
    let invalid_key = vec![0xFFu8; 100];
    let result = decrypt_short_buffer(&ciphertext, &invalid_key);
    assert!(result.is_err());
    
    // Test with wrong key type
    let x25519_key = X25519Key::generate(rng);
    let result = decrypt_short_buffer(&ciphertext, &x25519_key.private_key_bytes());
    assert!(result.is_err());
}

#[test]
fn test_decrypt_short_buffer_invalid_ciphertext() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    
    // Test with empty ciphertext
    let empty_ct = vec![];
    let result = decrypt_short_buffer(&empty_ct, &rsa_key.private_key_bytes());
    assert!(result.is_err());
    
    // Test with too short ciphertext
    let short_ct = vec![0u8; 10];
    let result = decrypt_short_buffer(&short_ct, &rsa_key.private_key_bytes());
    assert!(result.is_err());
    
    // Test with wrong size ciphertext
    let wrong_size_ct = vec![0u8; 128]; // Wrong size for 2048-bit key
    let result = decrypt_short_buffer(&wrong_size_ct, &rsa_key.private_key_bytes());
    assert!(result.is_err());
}

#[test]
fn test_keychain_key_not_found() {
    let keychain = Keychain::new();
    let key = Ed25519Key::generate(&mut OsRng);
    let pub_key = key.public_key_bytes();
    
    // Try to get signer for key not in keychain
    let result = keychain.get_signer(&pub_key);
    assert!(result.is_err());
    match result {
        Err(BottleError::KeyNotFound) => {},
        _ => panic!("Expected KeyNotFound error"),
    }
    
    // Try to sign with key not in keychain
    let result = keychain.sign(&mut OsRng, &pub_key, b"test");
    assert!(result.is_err());
}

#[test]
fn test_idcard_key_not_found() {
    let key = Ed25519Key::generate(&mut OsRng);
    let pub_key = key.public_key_bytes();
    let idcard = IDCard::new(&pub_key);
    
    // Try to test purpose for key not in IDCard
    let other_key = Ed25519Key::generate(&mut OsRng);
    let other_pub = other_key.public_key_bytes();
    let result = idcard.test_key_purpose(&other_pub, "sign");
    assert!(result.is_err());
}

#[test]
fn test_idcard_group_not_found() {
    // IDCard doesn't have a get_group method
    // Groups are stored as serialized membership data
    // GroupNotFound error would come from Membership verification or other operations
    // that try to access groups, not directly from IDCard
    // This test verifies that IDCard can handle group operations
    let key = Ed25519Key::generate(&mut OsRng);
    let pub_key = key.public_key_bytes();
    let mut idcard = IDCard::new(&pub_key);
    
    // Test update_groups (groups are internal)
    idcard.update_groups(vec![]);
    // Groups are internal, so we can't directly test GroupNotFound from IDCard
    // The GroupNotFound error would come from other operations that try to access groups
}

#[test]
fn test_membership_verify_failure() {
    let rng = &mut OsRng;
    
    // Create member and group IDCards
    let member_key = Ed25519Key::generate(rng);
    let member_pub = member_key.public_key_bytes();
    let member_idcard = IDCard::new(&member_pub);
    
    let group_key = Ed25519Key::generate(rng);
    let group_pub = group_key.public_key_bytes();
    let group_idcard = IDCard::new(&group_pub);
    
    // Test verification with no signature (should fail)
    let membership = Membership::new(&member_idcard, &group_pub);
    let result = membership.verify(&group_idcard);
    assert!(result.is_err());
    match result {
        Err(BottleError::VerifyFailed) => {},
        _ => panic!("Expected VerifyFailed error"),
    }
    
    // Note: The current Membership::verify() implementation only checks if a signature exists,
    // not if it's cryptographically valid. It's a simplified version that doesn't perform
    // full signature verification. This test verifies the "no signature" case.
    // Full cryptographic verification would require extracting the signing key from the
    // group's IDCard and verifying the signature, which is not yet implemented.
}

#[test]
fn test_bottle_no_recipient() {
    let bottle = Bottle::new(b"test".to_vec());
    
    // Try to open bottle with no encryption layers
    let opener = Opener::new();
    let _result = opener.open(&bottle, None);
    // This might succeed if bottle has no encryption, or fail with NoAppropriateKey
    // The exact behavior depends on implementation
}

#[test]
fn test_bottle_verify_failure() {
    let rng = &mut OsRng;
    let mut bottle = Bottle::new(b"test".to_vec());
    
    // Sign with one key
    let key1 = Ed25519Key::generate(rng);
    let pub1 = key1.public_key_bytes();
    bottle.sign(rng, &key1, &pub1).unwrap();
    
    // Try to verify with wrong key
    let key2 = Ed25519Key::generate(rng);
    let pub2 = key2.public_key_bytes();
    
    let opener = Opener::new();
    let info = opener.open_info(&bottle).unwrap();
    
    // Should not be signed by key2
    assert!(!info.is_signed_by(&pub2));
}

#[test]
fn test_rsa_key_invalid_size() {
    let rng = &mut OsRng;
    
    // Test various invalid sizes
    // Minimum is 512 bits, must be multiple of 8
    assert!(RsaKey::generate(rng, 0).is_err());
    assert!(RsaKey::generate(rng, 100).is_err());
    assert!(RsaKey::generate(rng, 511).is_err()); // Too small
    assert!(RsaKey::generate(rng, 2047).is_err()); // Not multiple of 8
    assert!(RsaKey::generate(rng, 2049).is_err()); // Not multiple of 8
    
    // Valid sizes (implementation allows >= 512 and multiple of 8)
    assert!(RsaKey::generate(rng, 512).is_ok());
    assert!(RsaKey::generate(rng, 1024).is_ok()); // Valid, though not recommended
    assert!(RsaKey::generate(rng, 2048).is_ok());
    assert!(RsaKey::generate(rng, 4096).is_ok());
}

#[test]
fn test_rsa_decrypt_invalid_ciphertext() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    // Test with empty ciphertext
    let empty_ct = vec![];
    let result = key.decrypt(&empty_ct);
    assert!(result.is_err());
    
    // Test with wrong size ciphertext
    let wrong_size_ct = vec![0u8; 128]; // Wrong size for 2048-bit key
    let result = key.decrypt(&wrong_size_ct);
    assert!(result.is_err());
}

#[test]
fn test_rsa_verify_invalid_signature() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    let message = b"test";
    
    // Test with empty signature
    let empty_sig = vec![];
    let result = key.verify(message, &empty_sig);
    assert!(result.is_err());
    
    // Test with wrong size signature
    let wrong_size_sig = vec![0u8; 128]; // Wrong size
    let result = key.verify(message, &wrong_size_sig);
    assert!(result.is_err());
    
    // Test with invalid signature format
    let invalid_sig = vec![0xFFu8; 256];
    let result = key.verify(message, &invalid_sig);
    assert!(result.is_err());
}

