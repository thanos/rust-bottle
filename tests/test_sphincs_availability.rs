#[cfg(feature = "post-quantum")]
#[test]
fn test_sphincs_variants_available() {
    use pqcrypto_sphincsplus as sp;
    
    // Test if fast variants are available
    let _ = sp::sphincsshake256128frobust::keypair;
    let _ = sp::sphincsshake256192frobust::keypair;
    let _ = sp::sphincsshake256256frobust::keypair;
    
    // Test if SHA-2 variants are available
    let _ = sp::sphincssha256128srobust::keypair;
    let _ = sp::sphincssha256128frobust::keypair;
    let _ = sp::sphincssha256192srobust::keypair;
    let _ = sp::sphincssha256192frobust::keypair;
    let _ = sp::sphincssha256256srobust::keypair;
    let _ = sp::sphincssha256256frobust::keypair;
}
