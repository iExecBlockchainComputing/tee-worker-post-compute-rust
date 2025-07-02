use crate::compute::{
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use base64::{Engine as _, engine::general_purpose};
use log::{error, info};
use std::{error::Error, fs, path::Path};

const ENCRYPTION_PREFIX: &str = "encrypted-";
const AES_KEY_RSA_FILENAME: &str = "aes-key.rsa";

pub fn eventually_encrypt_result(in_data_file_path: &str) -> Result<String, Box<dyn Error>> {
    info!("Encryption stage started");
    let should_encrypt: bool = match get_env_var_or_error(
        TeeSessionEnvironmentVariable::ResultEncryption,
        ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO: Update this error cause to a more specific one
    ) {
        Ok(value) => match value.parse::<bool>() {
            Ok(parsed_value) => parsed_value,
            Err(e) => {
                error!(
                    "Failed to parse RESULT_ENCRYPTION environment variable as a boolean [callback_env_var:{}]",
                    value
                );
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            error!("Failed to get RESULT_ENCRYPTION environment variable");
            return Err(Box::new(e));
        }
    };

    if !should_encrypt {
        info!("Encryption stage mode: NO_ENCRYPTION");
        return Ok(in_data_file_path.to_string());
    }

    info!("Encryption stage mode: ENCRYPTION_REQUESTED");
    let beneficiary_rsa_public_key_base64 = match get_env_var_or_error(
        TeeSessionEnvironmentVariable::ResultEncryptionPublicKey,
        ReplicateStatusCause::PostComputeEncryptionPublicKeyMissing,
    ) {
        Ok(key) => key,
        Err(e) => return Err(Box::new(e)),
    };

    let plain_text_beneficiary_rsa_public_key = match general_purpose::STANDARD.decode(beneficiary_rsa_public_key_base64) {
        Ok(key_bytes) => match String::from_utf8(key_bytes) {
            Ok(key_string) => key_string,
            Err(e) => {
                error!("Decoded key is not valid UTF-8: {}", e);
                return Err(Box::new(ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey));
            }
        },
        Err(e) => {
            error!("Result encryption public key base64 decoding failed: {}", e);
            return Err(Box::new(ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey));
        }
    };

    match encrypt_data(in_data_file_path, &plain_text_beneficiary_rsa_public_key, true) {
        Ok(file) if file.is_empty() => {
            Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed))
        }
        Ok(file) => {
            info!("Encryption stage completed");
            Ok(file)
        },
        Err(e) => {
            error!("Result encryption failed: {}", e);
            Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed))
        }
    }
}

pub fn encrypt_data(
    in_data_file_path: &str,
    plain_text_rsa_pub: &str,
    produce_zip: bool,
) -> Result<String, Box<dyn Error>> {
    let path = Path::new(in_data_file_path);
    let in_data_filename = path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            error!("Failed to extract filename from path: {}", in_data_file_path);
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?;
    let out_encrypted_data_filename = format!("{}.aes", in_data_filename);

    let work_dir = path.parent()
        .and_then(|p| p.to_str())
        .ok_or_else(|| {
            error!("Failed to get parent directory of: {}", in_data_file_path);
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?;

    let filename_without_ext = path.file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            error!("Failed to extract filename without extension from '{}'", in_data_file_path);
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?;
    let out_enc_dir = format!("{}/{}{}", work_dir, ENCRYPTION_PREFIX, filename_without_ext); //location of future encrypted files (./encrypted-0x1_result)

    // Get data to encrypt
    let data = fs::read(in_data_file_path)?;
    if data.is_empty() {
        error!("Failed to encrypt_data (read_file error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    };

    // Generate AES key for data encryption
    let aes_key = generate_aes_key()?;
    if aes_key.is_empty() {
        error!("Failed to encrypt_data (generate_aes_key error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    };

    // Encrypt data with Base64 AES key
    let encrypted_data = aes_encrypt(&data, &aes_key)?;
    if encrypted_data.is_empty() {
        error!("Failed to encrypt_data (aes_encrypt error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    };

    // Create folder for future out_encrypted_data & out_encrypted_aes_key
    let is_out_dir_created = create_folder(&out_enc_dir)?;
    if !is_out_dir_created {
        error!("Failed to encrypt_data (is_out_dir_created error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    }

    // Store encrypted data in ./0xtask1 [out_enc_dir]
    let is_encrypted_data_stored = write_file(format!("{}/{}", &out_enc_dir, &out_encrypted_data_filename), &encrypted_data)?;
    if !is_encrypted_data_stored {
        error!("Failed to encrypt_data (is_encrypted_data_stored error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    }

    // Get RSA public key
    let rsa_public_key = base64_to_rsa_public_key(plain_text_rsa_pub)?;
    if rsa_public_key.is_empty() {
        error!("Failed to encrypt_data (get_rsa_public_key error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    }

    // Encrypt AES key with RSA public key
    let encrypted_aes_key = rsa_encrypt(&aes_key, &rsa_public_key)?;
    if encrypted_aes_key.is_empty() {
        error!("Failed to encrypt_data (rsa_encrypt error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    }

    // Store encrypted AES key in ./0xtask1 [outEncDir]
    let is_encrypted_aes_key_stored = write_file(format!("{}/{}", &out_enc_dir, AES_KEY_RSA_FILENAME), &encrypted_aes_key)?;
    if !is_encrypted_aes_key_stored {
        error!("Failed to encrypt_data (is_encrypted_aes_key_stored error) [in_data_file_path:{}]", in_data_file_path);
        return Ok(String::new());
    }

    if produce_zip {
        // Zip encrypted files folder
        let out_enc_zip = zip_folder(&out_enc_dir)?;
        if out_enc_zip.is_empty() {
            error!("Failed to encrypt_data (out_enc_zip error) [in_data_file_path:{}]", in_data_file_path);
            return Ok(String::new());
        }
        return Ok(out_enc_zip);
    }

    Ok(out_enc_dir)
}


pub fn generate_aes_key() -> Result<String, Box<dyn Error>> {
    todo!()
}

pub fn aes_encrypt(data: &[u8], aes_key: &str) -> Result<String, Box<dyn Error>> {
    todo!()
}

fn create_folder(out_enc_dir: &str) -> Result<bool, Box<dyn Error>> {
    todo!()
}

pub fn plain_text_to_rsa_public_key(plain_text_rsa_pub: &str) -> Result<String, Box<dyn Error>> {
    todo!()
}


pub fn write_file(format: String, encrypted_data: &str) -> Result<bool, Box<dyn Error>> {
    todo!()
}

pub fn base64_to_rsa_public_key(plain_text_rsa_pub: &str) -> Result<String, Box<dyn Error>> {
    todo!()
}

pub fn rsa_encrypt(aes_key: &str, public_key: &str) -> Result<String, Box<dyn Error>> {
    todo!()
}

pub fn zip_folder(out_enc_dir: &str) -> Result<String, Box<dyn Error>> {
    todo!()
}
