use crate::bech32;

pub fn p2wpkh(addr_hrp: &str, addr_pubkey: &[u8]) -> anyhow::Result<String> {
    bech32::encode(addr_hrp, &addr_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2wpkh_mainnet() {
        let public_key_bytes = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();

        let address = p2wpkh("bc", &public_key_bytes).unwrap();
        
        // Verify the structure of the address
        assert!(address.starts_with("bc1"));
        assert!(address.len() > 3); // Should have some data after the prefix
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    }

    #[test]
    fn test_p2wpkh_testnet() {
        let public_key_bytes = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();

        let address = p2wpkh("tb", &public_key_bytes).unwrap();
        
        // Verify the structure of the address
        assert!(address.starts_with("tb1"));
        assert!(address.len() > 3); // Should have some data after the prefix
        assert_eq!(address, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
    }

    #[test]
    fn test_p2wpkh_consistency() {
        let public_key_bytes = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();

        let address1 = p2wpkh("bc", &public_key_bytes).unwrap();
        let address2 = p2wpkh("bc", &public_key_bytes).unwrap();
        
        // Same input should produce same output
        assert_eq!(address1, address2);
    }

    #[test]
    fn test_p2wpkh_different_keys() {
        let public_key_bytes1 = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();

        let public_key_bytes2 = hex::decode("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();

        let address1 = p2wpkh("bc", &public_key_bytes1).unwrap();
        let address2 = p2wpkh("bc", &public_key_bytes2).unwrap();
        
        // Different keys should produce different addresses
        assert_ne!(address1, address2);
    }
}