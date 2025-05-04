use anyhow::{anyhow, ensure};
use bitvec::{order::Msb0, view::BitView, field::BitField};
use pbkdf2::hmac;
use sha2::Digest;
use lazy_static::lazy_static;

lazy_static! {
    static ref WORDLIST: Vec<&'static str> = include_str!("../resources/wordlist.txt").split('\n').collect();
}

pub fn mnemonic_to_entropy(mnemonic: &str) -> anyhow::Result<Vec<u8>> {
    let words: Vec<_> = mnemonic.split_whitespace().collect();
    ensure!(matches!(words.len(), 12 | 24), "words count must be 12 or 24");

    // map words to 11-bit index
    // Msb0 -> most significant bit first
    let mut bits = bitvec::bitvec![u8, Msb0;];
    for w in &words {
        let index = WORDLIST.iter().position(|&x| x == *w)
            .ok_or_else(|| anyhow!("invalid word: {w}"))?;
        for i in (0..11).rev() {
            bits.push((index >> i) & 1 == 1);
        }
    }

    let checksum_length = bits.len() / 32;
    let (ent_bits, chk_bits) = bits.split_at(bits.len() - checksum_length);

    let entropy = ent_bits.chunks(8).map(|b| b.load::<u8>()).collect::<Vec<u8>>();


    let digest = sha2::Sha256::digest(&entropy);
    ensure!(chk_bits == digest.view_bits::<bitvec::order::Msb0>()[..checksum_length], "checksum mismatch");
    Ok(entropy)
}

pub fn seed_from_mnemonic(mnemonic: &str, passphrase: &str) -> anyhow::Result<Vec<u8>> {
    let salt = format!("mnemonic{passphrase}");
    let mut seed = [0u8; 64];

    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed
    ).map_err(|_| anyhow!("failed to generate seed"))?;

    Ok(seed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_to_entropy_valid_12_words() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = mnemonic_to_entropy(mnemonic).unwrap();
        assert_eq!(result, vec![0x00; 16]); // All zeros entropy for this mnemonic
    }

    #[test]
    fn test_mnemonic_to_entropy_valid_24_words() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let result = mnemonic_to_entropy(mnemonic).unwrap();
        assert_eq!(result, vec![0x00; 32]); // All zeros entropy for this mnemonic
    }

    #[test]
    fn test_mnemonic_to_entropy_invalid_word_count() {
        let mnemonic = "abandon abandon abandon"; // Only 3 words
        let result = mnemonic_to_entropy(mnemonic);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("words count must be 12 or 24"));
    }

    #[test]
    fn test_mnemonic_to_entropy_invalid_word() {
        let mnemonic = "invalidword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = mnemonic_to_entropy(mnemonic);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid word: invalidword"));
    }

    #[test]
    fn test_mnemonic_to_entropy_checksum_mismatch() {
        // This mnemonic has a modified last word to create a checksum mismatch
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = mnemonic_to_entropy(mnemonic);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum mismatch"));
    }

    #[test]
    fn test_seed_from_mnemonic_without_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "";
        let result = seed_from_mnemonic(mnemonic, passphrase).unwrap();
        assert_eq!(result.len(), 64); // Seed should be 64 bytes
    }

    #[test]
    fn test_seed_from_mnemonic_with_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "test";
        let result = seed_from_mnemonic(mnemonic, passphrase).unwrap();
        assert_eq!(result.len(), 64); // Seed should be 64 bytes
    }

    #[test]
    fn test_seed_from_mnemonic_different_passphrases() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase1 = "pass1";
        let passphrase2 = "pass2";
        
        let seed1 = seed_from_mnemonic(mnemonic, passphrase1).unwrap();
        let seed2 = seed_from_mnemonic(mnemonic, passphrase2).unwrap();
        
        assert_ne!(seed1, seed2); // Different passphrases should produce different seeds
    }
}