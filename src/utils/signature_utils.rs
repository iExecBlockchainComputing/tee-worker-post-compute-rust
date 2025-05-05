use alloy_primitives::hex::{decode, encode};
use alloy_signer::k256::ecdsa::Signature;
use std::error::Error;

impl Signature {
    pub fn new(value: String) -> Self {
        // Ensure the value has 0x prefix
        let prefixed_value = if !value.starts_with("0x") {
            format!("0x{}", value)
        } else {
            value
        };

        Self { value: prefixed_value }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hex_value = encode(bytes);
        Self::new(format!("0x{}", hex_value))
    }

    pub fn from_rsv(r: &[u8], s: &[u8], v: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(r);
        bytes.extend_from_slice(s);
        bytes.extend_from_slice(v);

        Self::from_bytes(&bytes)
    }

    pub fn get_r(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let bytes = self.to_bytes()?;  // assuming to_bytes returns Result
        if bytes.len() < 32 {
            return Err("Signature too short for R component".into());
        }
        Ok(bytes[0..32].to_vec())
    }

    pub fn get_s(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let bytes = self.to_bytes()?;
        if bytes.len() < 64 {
            return Err("Signature too short for S component".into());
        }
        Ok(bytes[32..64].to_vec())
    }

    pub fn get_v(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let bytes = self.to_bytes()?;
        if bytes.len() < 65 {
            return Err("Signature too short for V component".into());
        }
        Ok(vec![bytes[64]])
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let clean_value = self.value.strip_prefix("0x").unwrap_or(&self.value);
        decode(clean_value).map_err(|e| format!("Failed to decode signature: {}", e).into())
    }
}


