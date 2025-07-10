use crate::compute::web2_result::{Web2ResultInterface, Web2ResultService};
use crate::compute::{
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use aes::{
    Aes256,
    cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use base64::{Engine as _, engine::general_purpose};
use cbc::Encryptor;
use log::{error, info};
use rand::{RngCore, rngs::OsRng};
use rsa::Pkcs1v15Encrypt;
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use sha3::{Digest, Sha3_256};
use std::{error::Error, fs, path::Path};

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

    let plain_text_beneficiary_rsa_public_key =
        match general_purpose::STANDARD.decode(beneficiary_rsa_public_key_base64) {
            Ok(key_bytes) => match String::from_utf8(key_bytes) {
                Ok(key_string) => key_string,
                Err(e) => {
                    error!("Decoded key is not valid UTF-8: {}", e);
                    return Err(Box::new(
                        ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey,
                    ));
                }
            },
            Err(e) => {
                error!("Result encryption public key base64 decoding failed: {}", e);
                return Err(Box::new(
                    ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey,
                ));
            }
        };

    match encrypt_data(
        in_data_file_path,
        &plain_text_beneficiary_rsa_public_key,
        true,
    ) {
        Ok(file) if file.is_empty() => {
            Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed))
        }
        Ok(file) => {
            info!("Encryption stage completed");
            Ok(file)
        }
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
    let in_data_filename = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => {
            error!(
                "Failed to extract filename from path: {}",
                in_data_file_path
            );
            return Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed));
        }
    };
    let out_encrypted_data_filename = format!("{}.aes", in_data_filename);

    let work_dir = match path.parent().and_then(|p| p.to_str()) {
        Some(dir) => dir,
        None => {
            error!("Failed to get parent directory of: {}", in_data_file_path);
            return Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed));
        }
    };

    let filename_without_ext = match path.file_stem().and_then(|stem| stem.to_str()) {
        Some(stem) => stem,
        None => {
            error!(
                "Failed to extract filename without extension from '{}'",
                in_data_file_path
            );
            return Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed));
        }
    };
    let out_enc_dir = format!("{}/{}{}", work_dir, "encrypted-", filename_without_ext); //location of future encrypted files (./encrypted-0x1_result)

    // Get data to encrypt
    let data = match fs::read(in_data_file_path) {
        Ok(d) => {
            if d.is_empty() {
                error!(
                    "Failed to encrypt_data (empty file error) [in_data_file_path:{}]",
                    in_data_file_path
                );
                return Ok(String::new());
            } else {
                d
            }
        }
        Err(e) => {
            error!(
                "Failed to encrypt_data (read_file error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Err(Box::new(e));
        }
    };

    // Generate AES key for data encryption
    let aes_key = match generate_aes_key() {
        Ok(key) => key,
        Err(e) => {
            error!(
                "Failed to encrypt_data (generate_aes_key error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    // Encrypt data with Base64 AES key
    let encrypted_data = match aes_encrypt(&data, &aes_key) {
        Ok(enc) => enc,
        Err(e) => {
            error!(
                "Failed to encrypt_data (aes_encrypt error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    // Create folder for future out_encrypted_data & out_encrypted_aes_key
    match create_folder(&out_enc_dir) {
        Ok(_) => (),
        Err(e) => {
            error!(
                "Failed to encrypt_data (is_out_dir_created error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    // Store encrypted data in ./0xtask1 [out_enc_dir]
    match write_file(
        format!("{}/{}", &out_enc_dir, &out_encrypted_data_filename),
        &encrypted_data,
    ) {
        Ok(_) => (),
        Err(e) => {
            error!(
                "Failed to encrypt_data (is_encrypted_data_stored error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    // Get RSA public key
    let rsa_public_key = match base64_to_rsa_public_key(plain_text_rsa_pub) {
        Ok(pk) => pk,
        Err(e) => {
            error!(
                "Failed to encrypt_data (get_rsa_public_key error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    // Encrypt AES key with RSA public key
    let encrypted_aes_key = match rsa_encrypt(&aes_key, &rsa_public_key) {
        Ok(enc) => enc,
        Err(e) => {
            error!(
                "Failed to encrypt_data (rsa_encrypt error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    // Store encrypted AES key in ./0xtask1 [outEncDir]
    match write_file(
        format!("{}/{}", &out_enc_dir, "aes-key.rsa"),
        encrypted_aes_key.as_bytes(),
    ) {
        Ok(_) => (),
        Err(e) => {
            error!(
                "Failed to encrypt_data (is_encrypted_aes_key_stored error) [in_data_file_path:{}]: {}",
                in_data_file_path, e
            );
            return Ok(String::new());
        }
    };

    if produce_zip {
        // Zip encrypted files folder
        let out_enc_zip = match zip_folder(&out_enc_dir) {
            Ok(zip) => zip,
            Err(e) => {
                error!(
                    "Failed to encrypt_data (out_enc_zip error) [in_data_file_path:{}]: {}",
                    in_data_file_path, e
                );
                return Ok(String::new());
            }
        };
        if out_enc_zip.is_empty() {
            error!(
                "Failed to encrypt_data (out_enc_zip error) [in_data_file_path:{}]",
                in_data_file_path
            );
            return Ok(String::new());
        }
        return Ok(out_enc_zip);
    }

    Ok(out_enc_dir)
}

pub fn generate_aes_key() -> Result<Vec<u8>, ReplicateStatusCause> {
    let mut key_bytes = [0u8; 32]; // 256-bit key
    if let Err(e) = OsRng.try_fill_bytes(&mut key_bytes) {
        error!("Failed to generate AES key: {}", e);
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }
    Ok(key_bytes.to_vec())
}

pub fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ReplicateStatusCause> {
    if data.is_empty() {
        error!("AES encryption input data is empty");
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }
    if key.len() != 32 {
        error!(
            "AES encryption key must be 32 bytes (256 bits), got {}",
            key.len()
        );
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }

    // Generate random IV
    let mut iv = [0u8; 16];
    if let Err(e) = OsRng.try_fill_bytes(&mut iv) {
        error!("Failed to generate IV for AES encryption: {}", e);
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }

    // Encrypt using allocating convenience method
    let cipher = Encryptor::<Aes256>::new(key.into(), &iv.into());
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

    // Prepend IV to ciphertext
    let mut result = Vec::with_capacity(iv.len() + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

fn create_folder(out_enc_dir: &str) -> Result<(), ReplicateStatusCause> {
    let path = std::path::Path::new(out_enc_dir);
    if path.exists() {
        return Ok(());
    }
    match std::fs::create_dir_all(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Failed to create directory '{}': {}", out_enc_dir, e);
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        }
    }
}

pub fn write_file(file_path: String, data: &[u8]) -> Result<(), ReplicateStatusCause> {
    if let Err(e) = fs::write(&file_path, data) {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let hash_hex = format!("{:x}", hash);
        error!(
            "Failed to write file [file_path:{}, data_hash:{}]: {}",
            file_path, hash_hex, e
        );
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }
    Ok(())
}

pub fn base64_to_rsa_public_key(
    plain_text_rsa_pub: &str,
) -> Result<RsaPublicKey, ReplicateStatusCause> {
    let stripped = plain_text_rsa_pub
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .collect::<String>();
    let decoded = match base64::engine::general_purpose::STANDARD.decode(&stripped) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to decode base64 RSA public key: {}", e);
            return Err(ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey);
        }
    };
    match RsaPublicKey::from_public_key_der(&decoded) {
        Ok(pk) => Ok(pk),
        Err(e) => {
            error!("Failed to parse RSA public key: {}", e);
            Err(ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey)
        }
    }
}

pub fn rsa_encrypt(
    aes_key: &[u8],
    public_key: &RsaPublicKey,
) -> Result<String, ReplicateStatusCause> {
    let encrypted = match public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, aes_key) {
        Ok(ct) => ct,
        Err(e) => {
            error!("RSA encryption failed: {}", e);
            return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
        }
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
}

pub fn zip_folder(out_enc_dir: &str) -> Result<String, ReplicateStatusCause> {
    let parent = Path::new(out_enc_dir)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let service = Web2ResultService;
    service.zip_iexec_out(out_enc_dir, parent.to_str().unwrap())
}
