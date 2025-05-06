use sha256::digest;
use sha3::{Digest, Keccak256};

pub fn concatenate_and_hash(hexa_strings: &[&str]) -> String {
    let mut hasher = Keccak256::default();
    for hexa_string in hexa_strings {
        println!("value {}", hexa_string);
        hasher.update(hex_string_to_byte_array(hexa_string));
    }
    format!("0x{:x}", hasher.finalize())
}

pub fn hex_string_to_byte_array(input: &str) -> Vec<u8> {
    let clean_input = clean_hex_prefix(input);
    let len = clean_input.len();
    if len == 0 {
        return vec![];
    }

    let mut data: Vec<u8> = vec![];
    let start_idx = if len % 2 != 0 {
        let byte = u8::from_str_radix(&clean_input[0..1], 16).expect("");
        data.push(byte);
        1
    } else {
        0
    };

    for i in (start_idx..len).step_by(2) {
        data.push(u8::from_str_radix(&clean_input[i..i + 2], 16).expect(""));
    }

    data
}

pub fn clean_hex_prefix(input: &str) -> &str {
    input.strip_prefix("0x").unwrap_or(input)
}

pub fn sha256(input: String) -> String {
    format!("0x{}", digest(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_one_value() {
        let hexa1 = "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860";
        assert_eq!(
            "0x7ec1be13dbade2e3bfde8c2bdf68859dfff4ea620b3340c451ec56b5fa505ab1",
            concatenate_and_hash(&[hexa1])
        )
    }

    #[test]
    fn hash_two_values() {
        let hexa1 = "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860";
        let hexa2 = "0xd94b63fc2d3ec4b96daf84b403bbafdc8c8517e8e2addd51fec0fa4e67801be8";
        assert_eq!(
            "0x9ca8cbf81a285c62778678c874dae13fdc6857566b67a9a825434dd557e18a8d",
            concatenate_and_hash(&[hexa1, hexa2])
        )
    }

    #[test]
    fn hash_three_values() {
        let hexa1 = "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860";
        let hexa2 = "0xd94b63fc2d3ec4b96daf84b403bbafdc8c8517e8e2addd51fec0fa4e67801be8";
        let hexa3 = "0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596";
        assert_eq!(
            "0x54a76d209e8167e1ffa3bde8e3e7b30068423ca9554e1d605d8ee8fd0f165562",
            concatenate_and_hash(&[hexa1, hexa2, hexa3])
        )
    }

    #[test]
    fn it_removes_prefix() {
        assert_eq!(
            "54a76d209e8167e1ffa3bde8e3e7b30068423ca9554e1d605d8ee8fd0f165562",
            clean_hex_prefix("0x54a76d209e8167e1ffa3bde8e3e7b30068423ca9554e1d605d8ee8fd0f165562")
        )
    }

    #[test]
    fn it_returns_value_when_no_prefix() {
        assert_eq!(
            "54a76d209e8167e1ffa3bde8e3e7b30068423ca9554e1d605d8ee8fd0f165562",
            clean_hex_prefix("54a76d209e8167e1ffa3bde8e3e7b30068423ca9554e1d605d8ee8fd0f165562")
        )
    }

    #[test]
    fn get_sha256_digest() {
        assert_eq!(
            "0xb33845db05fb0822f1f1e3677cc6787b8a1a7a21f3c12f9e97c70cb596222218",
            sha256(String::from("utf8String"))
        )
    }
}
