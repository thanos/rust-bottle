// Edge case tests for various modules
// These tests cover boundary conditions and unusual inputs

use rust_bottle::*;
use rand::rngs::OsRng;

#[test]
fn test_bottle_empty_message() {
    let empty = vec![];
    let bottle = Bottle::new(empty.clone());
    assert_eq!(bottle.message(), &empty);
}

#[test]
fn test_bottle_very_large_message() {
    let large_message = vec![0u8; 1_000_000]; // 1MB
    let bottle = Bottle::new(large_message.clone());
    assert_eq!(bottle.message().len(), 1_000_000);
}

#[test]
fn test_bottle_multiple_encryption_layers() {
    let rng = &mut OsRng;
    let message = b"Multi-layer encrypted";
    let mut bottle = Bottle::new(message.to_vec());
    
    // Add multiple encryption layers
    for _ in 0..5 {
        let key = X25519Key::generate(rng);
        bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
    }
    
    assert_eq!(bottle.encryption_count(), 5);
}

#[test]
fn test_bottle_multiple_signatures() {
    let rng = &mut OsRng;
    let message = b"Multi-signed message";
    let mut bottle = Bottle::new(message.to_vec());
    
    // Add multiple signatures
    for _ in 0..5 {
        let key = Ed25519Key::generate(rng);
        let pub_key = key.public_key_bytes();
        bottle.sign(rng, &key, &pub_key).unwrap();
    }
    
    let opener = Opener::new();
    let info = opener.open_info(&bottle).unwrap();
    assert!(info.is_signed);
    assert!(info.signers.len() >= 5);
}

#[test]
fn test_bottle_metadata_unicode() {
    let mut bottle = Bottle::new(b"test".to_vec());
    
    // Test Unicode keys and values
    bottle.set_metadata("key_中文", "value_日本語");
    assert_eq!(bottle.metadata("key_中文"), Some("value_日本語"));
    
    // Test emoji
    bottle.set_metadata("emoji_key", "🎉🎊🎈");
    assert_eq!(bottle.metadata("emoji_key"), Some("🎉🎊🎈"));
}

#[test]
fn test_ecdh_empty_plaintext() {
    let rng = &mut OsRng;
    let key = X25519Key::generate(rng);
    let empty_plaintext = vec![];
    
    // Should be able to encrypt empty plaintext
    let ciphertext = ecdh_encrypt(rng, &empty_plaintext, &key.public_key_bytes());
    assert!(ciphertext.is_ok());
    
    // Should be able to decrypt empty plaintext
    if let Ok(ct) = ciphertext {
        let decrypted = ecdh_decrypt(&ct, &key.private_key_bytes());
        assert!(decrypted.is_ok());
        if let Ok(dec) = decrypted {
            assert_eq!(dec, empty_plaintext);
        }
    }
}

#[test]
fn test_ecdh_very_large_plaintext() {
    let rng = &mut OsRng;
    let key = X25519Key::generate(rng);
    let large_plaintext = vec![0x42u8; 10_000_000]; // 10MB
    
    let ciphertext = ecdh_encrypt(rng, &large_plaintext, &key.public_key_bytes());
    assert!(ciphertext.is_ok());
    
    if let Ok(ct) = ciphertext {
        let decrypted = ecdh_decrypt(&ct, &key.private_key_bytes());
        assert!(decrypted.is_ok());
        if let Ok(dec) = decrypted {
            assert_eq!(dec.len(), large_plaintext.len());
        }
    }
}

#[test]
fn test_keychain_multiple_keys() {
    let mut keychain = Keychain::new();
    let rng = &mut OsRng;
    
    // Add many keys
    let mut pub_keys = vec![];
    for _ in 0..20 {
        let key = Ed25519Key::generate(rng);
        let pub_key = key.public_key_bytes();
        pub_keys.push(pub_key.clone());
        keychain.add_key(key);
    }
    
    // Verify all keys are accessible
    for pub_key in pub_keys {
        let signer = keychain.get_signer(&pub_key);
        assert!(signer.is_ok());
    }
}

#[test]
fn test_idcard_multiple_keys() {
    let rng = &mut OsRng;
    let primary_key = Ed25519Key::generate(rng);
    let primary_pub = primary_key.public_key_bytes();
    let mut idcard = IDCard::new(&primary_pub);
    
    // Add multiple keys with different purposes
    for i in 0..10 {
        let key = X25519Key::generate(rng);
        let pub_key = key.public_key_bytes();
        let purpose = if i % 2 == 0 { "decrypt" } else { "sign" };
        idcard.set_key_purposes(&pub_key, &[purpose]);
    }
    
    // Verify purposes
    assert!(idcard.test_key_purpose(&primary_pub, "sign").is_ok());
}

#[test]
fn test_idcard_expiration() {
    use std::time::Duration;
    let rng = &mut OsRng;
    let key = Ed25519Key::generate(rng);
    let pub_key = key.public_key_bytes();
    let mut idcard = IDCard::new(&pub_key);
    
    // Set expiration in the future
    let future_duration = Duration::from_secs(3600);
    idcard.set_key_duration(&pub_key, future_duration);
    
    // Key should not be expired (test_key_purpose should succeed)
    assert!(idcard.test_key_purpose(&pub_key, "sign").is_ok());
    
    // Note: set_key_duration sets expiration from now, so we can't directly test past expiration
    // Expiration is checked in test_key_purpose, which returns KeyUnfit if expired
}

#[test]
fn test_membership_multiple_info() {
    let rng = &mut OsRng;
    let member_key = Ed25519Key::generate(rng);
    let member_pub = member_key.public_key_bytes();
    let member_idcard = IDCard::new(&member_pub);
    
    let group_key = Ed25519Key::generate(rng);
    let group_pub = group_key.public_key_bytes();
    
    let mut membership = Membership::new(&member_idcard, &group_pub);
    
    // Add multiple info fields
    for i in 0..20 {
        membership.set_info(&format!("key_{}", i), &format!("value_{}", i));
    }
    
    // Verify all info fields
    for i in 0..20 {
        let key = format!("key_{}", i);
        let value = format!("value_{}", i);
        assert_eq!(membership.info(&key), Some(value.as_str()));
    }
}

#[test]
fn test_rsa_key_sizes() {
    let rng = &mut OsRng;
    
    // Test all supported key sizes
    let sizes = vec![2048, 4096];
    for size in sizes {
        let key = RsaKey::generate(rng, size);
        assert!(key.is_ok());
        if let Ok(k) = key {
            assert_eq!(k.key_size(), size / 8);
        }
    }
}

#[test]
fn test_rsa_encryption_different_sizes() {
    let rng = &mut OsRng;
    
    // Test with 2048-bit key
    let key2048 = RsaKey::generate(rng, 2048).unwrap();
    let plaintext = b"test 2048";
    let ct2048 = rsa_encrypt(rng, plaintext, key2048.public_key()).unwrap();
    assert_eq!(ct2048.len(), 256); // 2048 bits = 256 bytes
    let dec2048 = key2048.decrypt(&ct2048).unwrap();
    assert_eq!(dec2048, plaintext);
    
    // Test with 4096-bit key
    let key4096 = RsaKey::generate(rng, 4096).unwrap();
    let plaintext = b"test 4096";
    let ct4096 = rsa_encrypt(rng, plaintext, key4096.public_key()).unwrap();
    assert_eq!(ct4096.len(), 512); // 4096 bits = 512 bytes
    let dec4096 = key4096.decrypt(&ct4096).unwrap();
    assert_eq!(dec4096, plaintext);
}

#[test]
fn test_mem_clr() {
    use rust_bottle::utils::mem_clr;
    
    let mut data = vec![0x42u8; 100];
    mem_clr(&mut data);
    
    // Data should be zeroed
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn test_bottle_serialization_roundtrip() {
    let rng = &mut OsRng;
    let mut bottle = Bottle::new(b"test message".to_vec());
    
    // Add encryption and signature
    let enc_key = X25519Key::generate(rng);
    bottle.encrypt(rng, &enc_key.public_key_bytes()).unwrap();
    
    let sig_key = Ed25519Key::generate(rng);
    let sig_pub = sig_key.public_key_bytes();
    bottle.sign(rng, &sig_key, &sig_pub).unwrap();
    
    // Add metadata
    bottle.set_metadata("key1", "value1");
    bottle.set_metadata("key2", "value2");
    
    // Serialize and deserialize
    let serialized = bottle.to_bytes().unwrap();
    let deserialized = Bottle::from_bytes(&serialized).unwrap();
    
    // Verify metadata
    assert_eq!(deserialized.metadata("key1"), Some("value1"));
    assert_eq!(deserialized.metadata("key2"), Some("value2"));
    
    // Verify encryption layers
    assert_eq!(deserialized.encryption_count(), 1);
    
    // Verify signatures
    let opener = Opener::new();
    let info = opener.open_info(&deserialized).unwrap();
    assert!(info.is_signed);
}

#[test]
fn test_utils_parse_rsa_key_invalid_der() {
    use rust_bottle::utils::encrypt_short_buffer;
    use rand::rngs::OsRng;
    
    let rng = &mut OsRng;
    let plaintext = b"test";
    
    // Test with invalid DER (not starting with 0x30)
    let invalid_der = vec![0xFFu8; 100];
    let result = encrypt_short_buffer(rng, plaintext, &invalid_der);
    assert!(result.is_err());
    
    // Test with empty DER
    let empty_der = vec![];
    let result = encrypt_short_buffer(rng, plaintext, &empty_der);
    assert!(result.is_err());
    
    // Test with too short DER
    let short_der = vec![0x30, 0x05]; // Valid start but too short
    let result = encrypt_short_buffer(rng, plaintext, &short_der);
    assert!(result.is_err());
}

