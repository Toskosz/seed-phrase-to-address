use sha2::Digest;
use hex;

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn encode(hrp: &str, data: &[u8]) -> anyhow::Result<String> {
    let h1 = sha2::Sha256::digest(data);
    let h2 = ripemd::Ripemd160::digest(&h1);
    
    let converted = convert_bits(h2.as_slice())?;
    
    // add 0x00 to the beginning of the converted array
    let mut witness = vec![0x00];
    witness.extend_from_slice(&converted);

    // checksum
    let checksum = compute_checksum(hrp, &witness);

    witness.extend_from_slice(&checksum);

    let mut out = String::new();
    out.push_str(hrp);
    out.push('1');
    for b in witness {
        out.push(CHARSET[b as usize] as char);
    }

    Ok(out)
}

fn convert_bits(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = 31;
    let mut ret = Vec::new();

    for &b in data {

        buffer = (buffer << 8) | b as u32;
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            ret.push(((buffer >> bits) & maxv) as u8);
        }
    }

    Ok(ret)
}

fn compute_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = expand_hrp(hrp);
    
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);

    let polymod = polymod(&values) ^ 1;

    (0..6).map(|i| ((polymod >> (5 * (5-i))) & 0x1F) as u8).collect()
}

fn expand_hrp(hrp: &str) -> Vec<u8> {
    let mut ret = Vec::new();
    for c in hrp.chars() {
        ret.push((c as u8) >> 5);
    }
    ret.push(0);
    for c in hrp.chars() {
        ret.push((c as u8) & 0x1F);
    }
    ret
}

fn polymod(values: &[u8]) -> u32 {
    let mut check: u32 = 1;
    let generator: [u32; 5] = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3,
    ];

    for &v in values {
        let b = check >> 25;
        check = ((check & 0x1ffffff) << 5) ^ (v as u32);
        for i in 0..5 {
            if ((b >> i) & 1) != 0 {
                check ^= generator[i];
            }
        }
    }

    check
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic() -> anyhow::Result<()> {
        let hrp = "bc";
        let data = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let encoded = encode(hrp, &data)?;
        
        // Verify the structure of the encoded string
        assert!(encoded.starts_with("bc1"));
        assert_eq!(encoded, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(encoded.len() > 3); // Should have some data after the prefix
        Ok(())
    }

    #[test]
    fn test_encode_empty_data() -> anyhow::Result<()> {
        let hrp = "bc";
        let data = b"";
        let encoded = encode(hrp, data)?;
        
        // Even with empty data, we should get a valid bech32 string
        assert!(encoded.starts_with("bc1"));
        Ok(())
    }

    #[test]
    fn test_encode_different_hrp() -> anyhow::Result<()> {
        let hrp = "tb";
        let data = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let encoded = encode(hrp, &data)?;
        
        // Verify the HRP is correctly used
        assert!(encoded.starts_with("tb1"));
        assert_eq!(encoded, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        Ok(())
    }

    #[test]
    fn test_encode_consistency() -> anyhow::Result<()> {
        let hrp = "bc";
        let data = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let encoded1 = encode(hrp, &data)?;
        let encoded2 = encode(hrp, &data)?;
        
        // Same input should produce same output
        assert_eq!(encoded1, encoded2);
        assert_eq!(encoded1, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        Ok(())
    }

    #[test]
    fn test_convert_bits() -> anyhow::Result<()> {
        // Test with empty input
        assert_eq!(convert_bits(&[])?, Vec::<u8>::new());

        // Test with multiple bytes
        let input = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let expected = vec![0x0e, 0x14, 0x0f, 0x07, 0x0d, 0x1a, 0x00, 0x19, 0x12, 0x06, 0x0b, 0x0d, 0x08, 0x15, 0x04, 0x14, 0x03, 0x11, 0x02, 0x1d, 0x03, 0x0c, 0x1d, 0x03, 0x04, 0x0f, 0x18, 0x14, 0x06, 0x0e, 0x1e, 0x16];
        assert_eq!(convert_bits(&input)?, expected);

        Ok(())
    }

    #[test]
    fn test_compute_checksum() {
        // Test with empty data
        let hrp = "bc";
        let data = vec![];
        let checksum = compute_checksum(hrp, &data);
        assert_eq!(checksum.len(), 6);

        // Test with some data
        let hrp = "bc";
        let data = vec![0x00, 0x01, 0x02];
        let checksum = compute_checksum(hrp, &data);
        assert_eq!(checksum.len(), 6);

        // Test with different HRP
        let hrp = "tb";
        let data = vec![0x00, 0x01, 0x02];
        let checksum = compute_checksum(hrp, &data);
        assert_eq!(checksum.len(), 6);
    }

    #[test]
    fn test_expand_hrp() {
        // Test with empty HRP
        assert_eq!(expand_hrp(""), vec![0]);

        // Test with testnet HRP
        let expanded = expand_hrp("tb");
        assert_eq!(expanded.len(), 5); // 4 for the characters + 1 for the separator
        assert_eq!(expanded[0], 0x03); // 't' >> 5
        assert_eq!(expanded[1], 0x03); // 'b' >> 5
        assert_eq!(expanded[2], 0x00); // separator
        assert_eq!(expanded[3], 0x14); // 't' & 0x1F
        assert_eq!(expanded[4], 0x02); // 'b' & 0x1F

        // Test with multiple characters
        let expanded = expand_hrp("bc");
        assert_eq!(expanded.len(), 5); // 4 for the characters + 1 for the separator
        assert_eq!(expanded[0], 0x03); // 'b' >> 5
        assert_eq!(expanded[1], 0x03); // 'c' >> 5
        assert_eq!(expanded[2], 0x00); // separator
        assert_eq!(expanded[3], 0x02); // 'b' & 0x1F
        assert_eq!(expanded[4], 0x03); // 'c' & 0x1F
    }

    #[test]
    fn test_polymod_known_case_1() {
        // Example from BIP-0173: empty input should yield 1
        let values: Vec<u8> = vec![];
        assert_eq!(polymod(&values), 1);
    }
}