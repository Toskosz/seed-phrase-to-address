use k256::EncodedPoint;
use sha2::Digest;

use crate::bech32;

pub fn p2wpkh(addr_hrp: &str, addr_pubkey: &EncodedPoint) -> String {
    let h1 = sha2::Sha256::digest(addr_pubkey.as_bytes());
    let hash160 = ripemd::Ripemd160::digest(&h1);

    let mut data = vec![0u8];
    data.extend_from_slice(&hash160);

    bech32::encode(addr_hrp, &data)
}