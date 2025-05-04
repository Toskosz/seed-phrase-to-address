use sha2::Digest;

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn encode(hrp: &str, data: &[u8]) -> String {
    let h1 = sha2::Sha256::digest(data);
    let h2 = ripemd::Ripemd160::digest(&h1);

    let mut out = String::new();
    out.push_str(hrp);
    out.push('1');
    for b in h2 {
        out.push(CHARSET[b as usize] as char);
    }

    out
}