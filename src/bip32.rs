use anyhow::{ensure, Result};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{
    elliptic_curve::{
        bigint::{Encoding, U256}, sec1::ToEncodedPoint, Curve, FieldBytes
    }, PublicKey, Secp256k1, SecretKey
};

type HmacSha512 = Hmac<Sha512>;

fn parse256_add_mod_n(il: &[u8; 32], kpar: &[u8; 32]) -> [u8; 32] {
    let x = U256::from_be_slice(&FieldBytes::<Secp256k1>::from_slice(il));
    let y = U256::from_be_slice(&FieldBytes::<Secp256k1>::from_slice(kpar));

    let n = x.add_mod(&y, &Secp256k1::ORDER);

    n.to_be_bytes()
}

pub struct ExtPriv {
    pub key:        SecretKey,
    pub chain:      [u8; 32],   // 32‑byte chain code
    pub depth:      u8,
    pub index:      u32,
    pub parent_fpr: [u8; 4],
}

impl ExtPriv {
    pub fn new_master(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
        mac.update(seed);
        let res = mac.finalize().into_bytes();

        let mut key_bytes = FieldBytes::<Secp256k1>::default();
        key_bytes.copy_from_slice(&res[..32]);

        Self {
            key: SecretKey::from_bytes(&key_bytes).unwrap(),
            chain: res[32..].try_into().unwrap(),
            depth: 0,
            index: 0,
            parent_fpr: [0u8; 4],
        }
    }

    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let hardened = index >= 0x8000_0000;

        let mut mac = HmacSha512::new_from_slice(&self.chain)?;
        if hardened {
            let mut data = Vec::with_capacity(37);
            data.push(0);
            data.extend_from_slice(&self.key.to_bytes());
            data.extend_from_slice(&index.to_be_bytes());
            mac.update(&data);
        } else {
            let mut data = ExtPriv::serP_point_kpar(&self.key);
            data.extend_from_slice(&index.to_be_bytes());
            mac.update(&data);
        }
        let res = mac.finalize().into_bytes();

        let child_key_bytes = res[..32].try_into().unwrap();
        let child_chain: [u8; 32] = res[32..].try_into().unwrap();

        let child_key = parse256_add_mod_n(&child_key_bytes, &self.key.to_bytes().as_slice().try_into().unwrap());
        ensure!(U256::from_be_slice(&child_key) != U256::ZERO, "invalid child key");

        Ok(Self {
            key: SecretKey::from_bytes(&child_key.try_into().unwrap())?,
            chain: child_chain,
            depth: self.depth + 1,
            index,
            parent_fpr: self.fingerprint(),
        })
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        use sha2::Digest;
        let h1 = sha2::Sha256::digest(ExtPriv::serP_point_kpar(&self.key).as_slice());
        let h2 = ripemd::Ripemd160::digest(&h1);
        h2[..4].try_into().unwrap()
    }

    pub fn serP_point_kpar(kpar: &SecretKey) -> Vec<u8> {
        let public_key = PublicKey::from_secret_scalar(&kpar.to_nonzero_scalar());

        let compressed_bytes = public_key.to_encoded_point(true).as_bytes().to_vec();

        compressed_bytes
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
        
        assert_eq!(master.key.to_bytes().as_slice(), expected_key.as_slice());
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
        
        let public_point = ExtPriv::serP_point_kpar(&master.key);
        assert_eq!(public_point.len(), 33); // compressed point is 33 bytes
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
}
