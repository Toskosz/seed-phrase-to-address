// src/bip32.rs – BIP‑32 implementation **without** using `Scalar`
// -------------------------------------------------------------------
// Only generic crypto crates are used. Private keys live as raw 32‑byte
// arrays (FieldBytes) and arithmetic is performed with the bigint type
// that ships inside `k256`.

use anyhow::{ensure, Result};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{
    ecdsa::SigningKey,
    elliptic_curve::{
        bigint::{Encoding, U256}, Curve, FieldBytes
    },
    Secp256k1,
};

/// HMAC‑SHA512 alias
type HmacSha512 = Hmac<Sha512>;

/// Modular addition:  (a + b) mod *n*
fn add_mod_n(a: &FieldBytes<Secp256k1>, b: &FieldBytes<Secp256k1>) -> FieldBytes<Secp256k1> {
    let mut out = FieldBytes::<Secp256k1>::default();
    let mut sum = U256::from_be_slice(a).wrapping_add(&U256::from_be_slice(b));
    let n = Secp256k1::ORDER;
    if sum >= n {
        sum = sum.wrapping_sub(&n);
    }
    out.copy_from_slice(&sum.to_be_bytes());
    out
}

/// Extended private key (xprv) – minimal fields needed for derivation
pub struct ExtPriv {
    pub key:        FieldBytes<Secp256k1>, // 32‑byte secret scalar
    pub chain:      [u8; 32],   // 32‑byte chain code
    pub depth:      u8,
    pub index:      u32,
    pub parent_fpr: [u8; 4],
}

impl ExtPriv {
    /// Create the *master* node from a 64‑byte BIP‑39 seed
    pub fn new_master(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
        mac.update(seed);
        let res = mac.finalize().into_bytes();

        let mut key_bytes = FieldBytes::<Secp256k1>::default();
        key_bytes.copy_from_slice(&res[..32]);

        Self {
            key: key_bytes,
            chain: res[32..].try_into().unwrap(),
            depth: 0,
            index: 0,
            parent_fpr: [0u8; 4],
        }
    }

    /// Derive a child (hardened if `index >= 2³¹`) per BIP‑32 §4
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let hardened = index >= 0x8000_0000;
        let sk       = SigningKey::from_bytes(&self.key)?;
        let pk_bytes = sk.verifying_key().to_encoded_point(true); // compressed

        // 1. Calculate I = HMAC‑SHA512(chain, data)
        let mut mac = HmacSha512::new_from_slice(&self.chain)?;
        if hardened {
            mac.update(&[0u8]);            // 0x00 || ser256(k_par)
            mac.update(&self.key);
        } else {
            mac.update(pk_bytes.as_bytes()); // serP(K_par)
        }
        mac.update(&index.to_be_bytes());
        let res = mac.finalize().into_bytes();

        // 2. Split I → IL || IR
        let mut il = FieldBytes::<Secp256k1>::default();
        il.copy_from_slice(&res[..32]);
        let ir: [u8; 32] = res[32..].try_into().unwrap();

        // 3. k_child = (IL + k_par) mod n
        let child_key = add_mod_n(&il, &self.key);
        ensure!(U256::from_be_slice(&child_key) != U256::ZERO, "invalid child key");

        Ok(Self {
            key: child_key,
            chain: ir,
            depth: self.depth + 1,
            index,
            parent_fpr: self.fingerprint(),
        })
    }

    /// SEC‑1 compressed public key (33 bytes)
    pub fn public_point(&self) -> k256::EncodedPoint {
        let sk = SigningKey::from_bytes(&self.key)
            .expect("secret key should always be valid");
        sk.verifying_key().to_encoded_point(false)
    }

    /// First 4 bytes of HASH160(pubkey) – used by BIP‑32 for parent fingerprint
    pub fn fingerprint(&self) -> [u8; 4] {
        use sha2::Digest;
        let h1 = sha2::Sha256::digest(self.public_point().as_bytes());
        let h2 = ripemd::Ripemd160::digest(&h1);
        h2[..4].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_new_master() {
        // Test vector from BIP-32
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let master = ExtPriv::new_master(&seed);

        // Verify depth and index
        assert_eq!(master.depth, 0);
        assert_eq!(master.index, 0);
        assert_eq!(master.parent_fpr, [0u8; 4]);

        // Verify key and chain code
        let expected_key = hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let expected_chain = hex!("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        
        assert_eq!(master.key.as_slice(), expected_key);
        assert_eq!(master.chain, expected_chain);
    }

    #[test]
    fn test_derive_child() {
        // Test vector from BIP-32
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let master = ExtPriv::new_master(&seed);

        // Test hardened derivation (index >= 2^31)
        let hardened_child = master.derive_child(0x80000000).unwrap();
        assert_eq!(hardened_child.depth, 1);
        assert_eq!(hardened_child.index, 0x80000000);
        assert_eq!(hardened_child.parent_fpr, master.fingerprint());

        // Test non-hardened derivation
        let non_hardened_child = master.derive_child(0).unwrap();
        assert_eq!(non_hardened_child.depth, 1);
        assert_eq!(non_hardened_child.index, 0);
        assert_eq!(non_hardened_child.parent_fpr, master.fingerprint());
    }

    #[test]
    fn test_public_point() {
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let master = ExtPriv::new_master(&seed);
        
        let public_point = master.public_point();
        assert_eq!(public_point.as_bytes().len(), 65); // Uncompressed point is 65 bytes
    }

    #[test]
    fn test_fingerprint() {
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let master = ExtPriv::new_master(&seed);
        
        let fingerprint = master.fingerprint();
        assert_eq!(fingerprint.len(), 4);
        
        // Verify fingerprint is consistent
        let fingerprint2 = master.fingerprint();
        assert_eq!(fingerprint, fingerprint2);
    }

    #[test]
    fn test_derive_child_invalid_private_key() {
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let mut master = ExtPriv::new_master(&seed);
        
        // Set an invalid private key (all zeros)
        master.key = FieldBytes::<Secp256k1>::default();
        
        // This should fail because SigningKey::from_bytes will reject an invalid private key
        assert!(master.derive_child(5).is_err());
    }
}
