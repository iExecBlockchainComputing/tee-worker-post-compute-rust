use alloy_primitives::{Address, hex};
use alloy_signer::k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use log::error;

/// Derives an Ethereum address from a private key.
///
/// # Arguments
///
/// * `private_key` - A string slice containing the private key with or without "0x" prefix
///
/// # Returns
///
/// * A string representing the Ethereum address with "0x" prefix, or an empty string if invalid
pub fn get_address(private_key: &str) -> String {
    if !is_valid_private_key(private_key) {
        let key_length = if !private_key.is_empty() {
            private_key.len()
        } else {
            0
        };
        error!(
            "Cannot get address from private key [privateKeyLength:{}]",
            key_length
        );
        return String::new();
    }

    private_key_to_address(private_key).unwrap_or_else(|e| {
        error!("Error creating address from private key: {}", e);
        String::new()
    })
}

/// Validates that a private key is properly formatted.
///
/// # Arguments
///
/// * `private_key` - A string slice containing the private key to validate
///
/// # Returns
///
/// * `true` if the private key is valid, `false` otherwise
pub fn is_valid_private_key(private_key: &str) -> bool {
    // Check if has valid 0x prefix
    let clean_key = match private_key.strip_prefix("0x") {
        Some(key) => key,
        None => {
            error!("Private key must start with '0x'");
            return false;
        }
    };

    // Check valid length (32 bytes = 64 hex chars)
    if clean_key.len() != 64 {
        error!("Private key length is {}, expected 64", clean_key.len());
        return false;
    }

    // Check if it's valid hex
    if !clean_key.chars().all(|c| c.is_ascii_hexdigit()) {
        error!("Private key is not valid hex");
        return false;
    }

    // Check if not all zeros
    if clean_key.chars().all(|c| c == '0') {
        error!("Private key cannot be all zeros");
        return false;
    }

    true
}

/// Converts a private key to an Ethereum address.
///
/// # Arguments
///
/// * `private_key` - A string slice containing the private key
///
/// # Returns
///
/// * A `Result` containing either the address as a String or an error
fn private_key_to_address(private_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Remove 0x prefix if present
    let clean_key = private_key.strip_prefix("0x").unwrap_or(private_key);

    // Decode hex string to bytes
    let key_bytes = hex::decode(clean_key)?;

    // Create signing key from private key bytes
    let signing_key = SigningKey::from_slice(&key_bytes)?;

    // Get the public key from the signing key
    let verifying_key = signing_key.verifying_key();

    // Convert to uncompressed point format (65 bytes with 0x04 prefix)
    let public_key = verifying_key.to_encoded_point(false);

    // Hash the public key (excluding the first byte) with Keccak-256
    let mut hasher = Keccak256::new();
    hasher.update(&public_key.as_bytes()[1..]);
    let hash = hasher.finalize();

    // Take the last 20 bytes of the hash to get the address
    let address = Address::from_slice(&hash[12..32]);

    // Format with 0x prefix
    Ok(format!("{:#x}", address))
}
