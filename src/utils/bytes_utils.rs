use alloy_primitives::hex;

pub const EMPTY_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
pub const BYTES_32_SIZE: usize = 32;
pub const EMPTY_HEX_STRING_32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

pub fn bytes_to_string(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn string_to_bytes(hex_string: &str) -> Vec<u8> {
    if let Some(stripped) = hex_string.strip_prefix("0x") {
        hex::decode(stripped).unwrap_or_default()
    } else {
        hex::decode(hex_string).unwrap_or_default()
    }
}

pub fn is_hex_string_with_prefix(hex_string: &str) -> bool {
    if hex_string.is_empty() || !hex_string.starts_with("0x") {
        return false;
    }
    hex_string[2..].chars().all(|c| c.is_digit(16))
}

pub fn is_hex_string(hex_string: &str) -> bool {
    if hex_string.is_empty() {
        return false;
    }
    let check_str = if hex_string.starts_with("0x") {
        &hex_string[2..]
    } else {
        hex_string
    };
    check_str.chars().all(|c| c.is_digit(16))
}

pub fn is_hex_string_with_prefix_and_proper_bytes_size(hex_string: &str, expected_byte_size: usize) -> bool {
    expected_byte_size > 0
        && is_hex_string_with_prefix(hex_string)
        && string_to_bytes(hex_string).len() == expected_byte_size
}

pub fn is_non_zeroed_hex_string_with_prefix_and_proper_bytes_size(hex_string: &str, expected_byte_size: usize) -> bool {
    is_hex_string_with_prefix_and_proper_bytes_size(hex_string, expected_byte_size)
        && string_to_bytes(hex_string) != vec![0; expected_byte_size]
}

pub fn is_bytes32(hex_string: &str) -> bool {
    is_hex_string_with_prefix_and_proper_bytes_size(hex_string, BYTES_32_SIZE)
}

pub fn is_non_zeroed_bytes32(hex_string: &str) -> bool {
    is_non_zeroed_hex_string_with_prefix_and_proper_bytes_size(hex_string, BYTES_32_SIZE)
}