use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{
    ecdsa::SigningKey,
    Scalar, AffinePoint, FieldBytes
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
type HmacSha512 = Hmac<Sha512>;
use anyhow::ensure;

pub struct ExtPriv {
    key:   [u8; 32],     // 32-byte sk
    chain: [u8; 32],   // chain code
    depth: u8,
    index: u32,
    parent_fpr: [u8; 4],
}

impl ExtPriv {
    pub fn new_master(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
        mac.update(seed);
        let res = mac.finalize().into_bytes();
        Self {
            key:   res[..32].try_into().unwrap(),
            chain: res[32..].try_into().unwrap(),
            depth: 0,
            index: 0,
            parent_fpr: [0; 4],
        }
    }

    /// hardened = index >= 2³¹
    pub fn derive_child(&self, index: u32) -> anyhow::Result<Self> {
        let mut mac = HmacSha512::new_from_slice(&self.chain).unwrap();
        if index >= 0x8000_0000 {
            // hardened: 0x00 || ser256(kpar)
            mac.update(&[0u8]);
            mac.update(&self.key);
        } else {
            // non-hardened: serP(point(kpar))
            let pk = (&SigningKey::from_bytes(&FieldBytes::from(self.key)).unwrap())
                .verifying_key();
            mac.update(pk.to_encoded_point(true).as_bytes());
        }
        mac.update(&index.to_be_bytes());
        let res = mac.finalize().into_bytes();
        let kpar = Scalar::from_bytes_reduced(self.key.into());
        let il = Scalar::from_bytes_reduced(res[..32].into());
        let child_key = (il + kpar).to_bytes(); // child_key is [u8; 32]
        ensure!(!child_key.is_zero(), "invalid child key");     // §8.5
        Ok(Self {
            key:   child_key,
            chain: res[32..].try_into().unwrap(),
            depth: self.depth + 1,
            index,
            parent_fpr: self.fingerprint(),
        })
    }

    pub fn public_point(&self) -> AffinePoint {
        *((&SigningKey::from_bytes(&FieldBytes::from(self.key)).unwrap())
            .verifying_key()
            .as_affine())
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        use sha2::Digest;
        let h1 = sha2::Sha256::digest(self.public_point().to_encoded_point(false).as_bytes());
        let h2 = ripemd::Ripemd160::digest(&h1);
        h2[..4].try_into().unwrap()
    }
}
