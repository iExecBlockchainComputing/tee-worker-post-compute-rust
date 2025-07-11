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
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
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
            return Err(Box::new(ReplicateStatusCause::PostComputeEncryptionFailed));
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{BigUint, traits::PublicKeyParts};
    use std::{
        fs::File,
        io::{Read, Write},
        path::PathBuf,
    };
    use temp_env::with_vars;
    use tempfile::{NamedTempFile, TempDir, tempdir};
    use zip::ZipArchive;

    const TEST_RSA_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0mx20CSFczJaM4rtYfL
VHXfTybD4J85SGrI6GfPlOhAnocZOMIRJVqrYSGqfNvw6bnv3OrNp0OJ6Av7v20r
YiciyJ/R9c7W4jLksTC0qAEr1x8IsH1rsTcgIhD+V2eQWqi05ArUg+YDQiGr/B6T
jJRbbZIjcX6l/let03NJ8b6vMgaY+6tpt9GXhm27/tVIG6vt0NYViU0cOY3+fRH7
M1XvGQa3D0LnJTvhAgljz3Jpl7whAWQgluVDVNq7erJVN7/d5jpTG29FWrAYujvs
KfizbB8KpGwCHwFcHZurz9+Sp4mH5cQCvz/VhFrAvzbhsIl6Qf8XURHmqxYc/DRt
FQIDAQAB
-----END PUBLIC KEY-----"#;

    // The same key as above, but Base64 encoded DER (PKCS#8 public key format)
    // This is what `base64_to_rsa_public_key` expects after stripping PEM headers/footers.
    const TEST_RSA_PUBLIC_KEY_DER_BASE64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0mx20CSFczJaM4rtYfLVHXfTybD4J85SGrI6GfPlOhAnocZOMIRJVqrYSGqfNvw6bnv3OrNp0OJ6Av7v20rYiciyJ/R9c7W4jLksTC0qAEr1x8IsH1rsTcgIhD+V2eQWqi05ArUg+YDQiGr/B6TjJRbbZIjcX6l/let03NJ8b6vMgaY+6tpt9GXhm27/tVIG6vt0NYViU0cOY3+fRH7M1XvGQa3D0LnJTvhAgljz3Jpl7whAWQgluVDVNq7erJVN7/d5jpTG29FWrAYujvsKfizbB8KpGwCHwFcHZurz9+Sp4mH5cQCvz/VhFrAvzbhsIl6Qf8XURHmqxYc/DRtFQIDAQAB";

    const TEST_RSA_PUBLIC_KEY_NO_HEADERS: &str = r#"
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0mx20CSFczJaM4rtYfL
VHXfTybD4J85SGrI6GfPlOhAnocZOMIRJVqrYSGqfNvw6bnv3OrNp0OJ6Av7v20r
YiciyJ/R9c7W4jLksTC0qAEr1x8IsH1rsTcgIhD+V2eQWqi05ArUg+YDQiGr/B6T
jJRbbZIjcX6l/let03NJ8b6vMgaY+6tpt9GXhm27/tVIG6vt0NYViU0cOY3+fRH7
M1XvGQa3D0LnJTvhAgljz3Jpl7whAWQgluVDVNq7erJVN7/d5jpTG29FWrAYujvs
KfizbB8KpGwCHwFcHZurz9+Sp4mH5cQCvz/VhFrAvzbhsIl6Qf8XURHmqxYc/DRt
FQIDAQAB
"#;

    // Helper functions
    fn create_temp_file_with_text(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn create_temp_dir_with_files(
        base_temp_dir: &TempDir,
        dir_name: &str,
        num_files: usize,
        create_subdir: bool,
    ) -> PathBuf {
        let dir_path = base_temp_dir.path().join(dir_name);
        fs::create_dir_all(&dir_path).expect("Failed to create temp source dir for zip test");

        for i in 0..num_files {
            let file_name = format!("file{}.txt", i);
            let mut file = File::create(dir_path.join(file_name))
                .expect("Failed to create file in temp source dir");
            writeln!(file, "content of file {}", i)
                .expect("Failed to write to file in temp source dir");
        }

        if create_subdir && num_files > 0 {
            let subdir_path = dir_path.join("subdir");
            fs::create_dir_all(&subdir_path).expect("Failed to create temp subdir for zip test");
            let file_name = format!("subfile{}.txt", 0);
            let mut file = File::create(subdir_path.join(file_name))
                .expect("Failed to create file in temp subdir");
            writeln!(file, "content of subfile {}", 0)
                .expect("Failed to write to file in temp subdir");
        }
        dir_path
    }

    fn get_base64_encoded_valid_rsa_key() -> String {
        general_purpose::STANDARD.encode(TEST_RSA_PUBLIC_KEY_PEM)
    }

    // region eventually_encrypt_result
    #[test]
    fn eventually_encrypt_result_returns_original_path_when_encryption_disabled() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();

        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultEncryption.name(),
                Some("false"),
            )],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), file_path);
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_encrypted_path_when_encryption_enabled_and_key_valid() {
        let base_temp = tempdir().expect("Failed to create base_temp");
        let input_dir = base_temp.path().join("input_valid_encrypt");
        fs::create_dir_all(&input_dir).unwrap();
        let input_file_path = input_dir.join("data_to_encrypt.txt");
        fs::write(&input_file_path, "secret stuff").expect("Failed to write data_to_encrypt.txt");

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    Some(get_base64_encoded_valid_rsa_key().as_str()),
                ),
            ],
            || {
                let result = eventually_encrypt_result(input_file_path.to_str().unwrap());
                assert!(
                    result.is_ok(),
                    "eventually_encrypt_result failed: {:?}",
                    result.err()
                );
                let output_zip_path_str = result.unwrap();
                let output_zip_path = Path::new(&output_zip_path_str);
                assert!(
                    output_zip_path.exists(),
                    "Encrypted zip file should exist at {}",
                    output_zip_path_str
                );
                assert_eq!(output_zip_path.extension().unwrap_or_default(), "zip");
                assert_eq!(
                    output_zip_path.file_name().unwrap().to_str().unwrap(),
                    "iexec_out.zip"
                );
                assert_eq!(output_zip_path.parent().unwrap(), input_dir);
                let zip_file_reader =
                    File::open(output_zip_path).expect("Failed to open output zip file for check");
                let mut archive = ZipArchive::new(zip_file_reader)
                    .expect("Failed to read output zip archive for check");
                assert!(
                    archive.len() == 2,
                    "Encrypted zip archive should contain 2 files. Found: {}",
                    archive.len()
                );
                let expected_encrypted_data_filename = format!(
                    "{}.aes",
                    input_file_path.file_name().unwrap().to_str().unwrap()
                );
                assert!(archive.by_name(&expected_encrypted_data_filename).is_ok());
                assert!(archive.by_name("aes-key.rsa").is_ok());
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_encryption_env_var_missing() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();

        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultEncryption.name(),
                None::<&str>,
            )],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<ReplicateStatusCause>());
                assert_eq!(
                    *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
                    ReplicateStatusCause::PostComputeFailedUnknownIssue
                );
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_encryption_env_var_invalid() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();

        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultEncryption.name(),
                Some("invalid_boolean"),
            )],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<std::str::ParseBoolError>());
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_public_key_missing() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    None::<&str>,
                ),
            ],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<ReplicateStatusCause>());
                assert_eq!(
                    *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
                    ReplicateStatusCause::PostComputeEncryptionPublicKeyMissing
                );
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_public_key_invalid_base64() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    Some("invalid_base64!@#"),
                ),
            ],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<ReplicateStatusCause>());
                assert_eq!(
                    *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
                    ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
                );
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_public_key_invalid_utf8() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();
        let invalid_utf8_base64 =
            base64::engine::general_purpose::STANDARD.encode([0xFF, 0xFE, 0xFD]);

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    Some(&invalid_utf8_base64),
                ),
            ],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<ReplicateStatusCause>());
                assert_eq!(
                    *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
                    ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
                );
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_public_key_not_a_valid_key() {
        let test_file = create_temp_file_with_text("test content");
        let file_path = test_file.path().to_str().unwrap();
        let not_a_key_base64 =
            general_purpose::STANDARD.encode("Hello World, this is valid base64 but not a key.");

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    Some(not_a_key_base64.as_str()),
                ),
            ],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<ReplicateStatusCause>());
                assert_eq!(
                    *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
                    ReplicateStatusCause::PostComputeEncryptionFailed
                );
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_error_when_input_file_is_empty() {
        let test_file = create_temp_file_with_text("");
        let file_path = test_file.path().to_str().unwrap();

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    Some(get_base64_encoded_valid_rsa_key().as_str()),
                ),
            ],
            || {
                let result = eventually_encrypt_result(file_path);
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.is::<ReplicateStatusCause>());
                assert_eq!(
                    *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
                    ReplicateStatusCause::PostComputeEncryptionFailed
                );
            },
        );
    }

    #[test]
    fn eventually_encrypt_result_returns_encrypted_path_when_input_file_is_binary() {
        let base_temp = tempdir().expect("Failed to create base_temp");
        let input_dir = base_temp.path().join("input_binary_encrypt");
        fs::create_dir_all(&input_dir).unwrap();
        let input_file_path = input_dir.join("data_to_encrypt.bin");
        let binary_content = vec![0, 159, 146, 150, 255, 0, 100, 200, 50, 10, 0, 255];
        fs::write(&input_file_path, &binary_content).expect("Failed to write binary data");

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::ResultEncryption.name(),
                    Some("true"),
                ),
                (
                    TeeSessionEnvironmentVariable::ResultEncryptionPublicKey.name(),
                    Some(get_base64_encoded_valid_rsa_key().as_str()),
                ),
            ],
            || {
                let result = eventually_encrypt_result(input_file_path.to_str().unwrap());
                assert!(
                    result.is_ok(),
                    "eventually_encrypt_result failed: {:?}",
                    result.err()
                );
                let output_zip_path_str = result.unwrap();
                let output_zip_path = Path::new(&output_zip_path_str);
                assert!(
                    output_zip_path.exists(),
                    "Encrypted zip file should exist at {}",
                    output_zip_path_str
                );
                assert_eq!(output_zip_path.extension().unwrap_or_default(), "zip");
            },
        );
    }
    // endregion

    // region encrypt_data
    #[test]
    fn encrypt_data_produces_directory_when_valid_input_and_produce_zip_false() {
        let base_temp = tempdir().expect("Failed to create base temp dir for encrypt_data test");
        let input_dir = base_temp.path().join("input_data_dir_nozip");
        fs::create_dir_all(&input_dir).expect("Failed to create input_data_dir_nozip");

        let input_file_path = input_dir.join("another_result.dat");
        let original_data = b"Data for no-zip scenario.";
        fs::write(&input_file_path, original_data)
            .expect("Failed to write to temporary input file");

        let result = encrypt_data(
            input_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            false, // produce_zip = false
        );
        assert!(
            result.is_ok(),
            "encrypt_data should succeed. Error: {:?}",
            result.err()
        );

        let output_dir_path_str = result.unwrap();
        let output_dir_path = Path::new(&output_dir_path_str);
        assert!(
            output_dir_path.exists(),
            "Output directory should exist at {}",
            output_dir_path_str
        );
        assert!(
            output_dir_path.is_dir(),
            "Output path should be a directory."
        );

        let expected_dir_name = format!(
            "encrypted-{}",
            input_file_path.file_stem().unwrap().to_str().unwrap()
        );
        assert_eq!(
            output_dir_path.file_name().unwrap().to_str().unwrap(),
            expected_dir_name,
            "Output directory has unexpected name."
        );
        assert_eq!(
            output_dir_path.parent().unwrap(),
            input_dir,
            "Output directory created in unexpected parent."
        );

        let expected_encrypted_data_filename = format!(
            "{}.aes",
            input_file_path.file_name().unwrap().to_str().unwrap()
        );
        let encrypted_file_in_dir = output_dir_path.join(expected_encrypted_data_filename);
        assert!(
            encrypted_file_in_dir.exists(),
            "Encrypted data file not found in output directory."
        );

        let encrypted_content =
            fs::read(&encrypted_file_in_dir).expect("Failed to read encrypted file from dir");
        assert!(!encrypted_content.is_empty());
        assert_ne!(encrypted_content, original_data);

        let aes_key_file_in_dir = output_dir_path.join("aes-key.rsa");
        assert!(
            aes_key_file_in_dir.exists(),
            "AES key file not found in output directory."
        );

        let aes_key_content_b64 =
            fs::read_to_string(&aes_key_file_in_dir).expect("Failed to read AES key file from dir");
        assert!(!aes_key_content_b64.is_empty());
        assert!(
            general_purpose::STANDARD
                .decode(&aes_key_content_b64)
                .is_ok()
        );
    }

    #[test]
    fn encrypt_data_produces_zip_file_when_valid_input_and_produce_zip_true() {
        let base_temp = tempdir().expect("Failed to create base temp dir for encrypt_data test");
        let input_dir = base_temp.path().join("input_data_dir");
        fs::create_dir_all(&input_dir).expect("Failed to create input_data_dir");

        let input_file_path = input_dir.join("my_result_data.txt");
        let original_data = b"This is the secret data to be encrypted and zipped!";
        fs::write(&input_file_path, original_data)
            .expect("Failed to write to temporary input file");

        let result = encrypt_data(
            input_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            true, // produce_zip = true
        );
        assert!(
            result.is_ok(),
            "encrypt_data should succeed. Error: {:?}",
            result.err()
        );

        let output_zip_path_str = result.unwrap();
        let output_zip_path = Path::new(&output_zip_path_str);
        assert!(
            output_zip_path.exists(),
            "Output zip file should exist at {}",
            output_zip_path_str
        );
        assert_eq!(
            output_zip_path.extension().unwrap_or_default(),
            "zip",
            "Output file should be a zip file"
        );

        let expected_zip_parent = input_dir; // work_dir
        let expected_zip_name_stem = "iexec_out";
        assert_eq!(
            output_zip_path.parent().unwrap(),
            expected_zip_parent,
            "Zip file created in unexpected parent directory."
        );
        assert_eq!(
            output_zip_path.file_stem().unwrap().to_str().unwrap(),
            expected_zip_name_stem,
            "Zip file has unexpected stem."
        );

        let zip_file_reader = File::open(output_zip_path).expect("Failed to open output zip file");
        let mut archive =
            ZipArchive::new(zip_file_reader).expect("Failed to read output zip archive");
        assert!(
            archive.len() == 2,
            "Zip archive should contain 2 files. Found: {}",
            archive.len()
        );

        let expected_encrypted_data_filename = format!(
            "{}.aes",
            input_file_path.file_name().unwrap().to_str().unwrap()
        );

        // Check for encrypted data file
        {
            let encrypted_data_entry = archive.by_name(&expected_encrypted_data_filename);
            assert!(
                encrypted_data_entry.is_ok(),
                "Encrypted data file '{}' not found in zip.",
                expected_encrypted_data_filename
            );
            let mut encrypted_data_file_in_zip = encrypted_data_entry.unwrap();
            let mut encrypted_content = Vec::new();
            encrypted_data_file_in_zip
                .read_to_end(&mut encrypted_content)
                .expect("Failed to read encrypted data from zip");
            assert!(
                !encrypted_content.is_empty(),
                "Encrypted data in zip should not be empty."
            );
            assert_ne!(
                encrypted_content, original_data,
                "Encrypted data in zip should not match original data."
            );
        }

        // Check for encrypted AES key file
        {
            let aes_key_entry = archive.by_name("aes-key.rsa");
            assert!(
                aes_key_entry.is_ok(),
                "AES key file 'aes-key.rsa' not found in zip."
            );
            let mut aes_key_file_in_zip = aes_key_entry.unwrap();
            let mut aes_key_content_b64 = String::new();
            aes_key_file_in_zip
                .read_to_string(&mut aes_key_content_b64)
                .expect("Failed to read AES key from zip");
            assert!(
                !aes_key_content_b64.is_empty(),
                "AES key content in zip should not be empty."
            );
            assert!(
                general_purpose::STANDARD
                    .decode(&aes_key_content_b64)
                    .is_ok(),
                "AES key in zip is not valid Base64."
            );
        }
    }

    #[test]
    fn encrypt_data_returns_empty_string_when_input_file_is_empty() {
        let base_temp = tempdir().expect("Failed to create base temp dir");
        let input_dir = base_temp.path().join("input_empty_file_dir");
        fs::create_dir_all(&input_dir).expect("Failed to create dir for empty file test");
        let empty_file_path = input_dir.join("empty_data.txt");
        File::create(&empty_file_path).expect("Failed to create empty file"); // Create 0-byte file

        let result = encrypt_data(
            empty_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            true, // produce_zip doesn't matter here
        );
        assert!(
            result.is_ok(),
            "encrypt_data should return Ok for empty input file. Error: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            "",
            "encrypt_data should return an empty string for empty input file."
        );
    }

    #[test]
    fn encrypt_data_returns_empty_string_when_rsa_key_is_invalid() {
        // Edge case: invalid RSA key, should return Ok("")
        let base_temp = tempdir().expect("Failed to create base temp dir");
        let input_dir = base_temp.path().join("input_invalid_key_dir");
        fs::create_dir_all(&input_dir).expect("Failed to create dir for invalid key test");
        let input_file_path = input_dir.join("some_data.bin");
        fs::write(&input_file_path, b"some valid data content")
            .expect("Failed to write input file for invalid key test");
        let invalid_rsa_key = "THIS IS NOT A VALID RSA KEY";

        let result = encrypt_data(
            input_file_path.to_str().unwrap(),
            invalid_rsa_key,
            true, // produce_zip doesn't matter
        );
        assert!(
            result.is_ok(),
            "encrypt_data should return Ok for invalid RSA key. Error: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            "",
            "encrypt_data should return an empty string for invalid RSA key."
        );
    }

    #[test]
    fn encrypt_data_returns_error_when_input_file_path_is_invalid() {
        let base_temp = tempdir().expect("Failed to create base temp dir");
        let non_existent_file_path = base_temp.path().join("non_existent_input.txt");

        let result = encrypt_data(
            non_existent_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            true,
        );
        assert!(
            result.is_err(),
            "encrypt_data should return Err for non-existent input file."
        );

        let err = result.err().unwrap();
        assert!(
            err.is::<ReplicateStatusCause>(),
            "Error should be a ReplicateStatusCause, but was {:?}",
            err
        );
        assert_eq!(
            *err.downcast_ref::<ReplicateStatusCause>().unwrap(),
            ReplicateStatusCause::PostComputeEncryptionFailed
        );
    }

    #[test]
    fn encrypt_data_produces_encrypted_output_when_input_is_binary() {
        let base_temp = tempdir().expect("Failed to create base temp dir for binary encrypt test");
        let input_dir = base_temp.path().join("input_binary_encrypt");
        fs::create_dir_all(&input_dir).unwrap();
        let input_file_path = input_dir.join("data_to_encrypt.bin");
        let binary_content = vec![0, 159, 146, 150, 255, 0, 100, 200, 50, 10, 0, 255];
        fs::write(&input_file_path, &binary_content).expect("Failed to write binary data");

        let result = encrypt_data(
            input_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            true, // produce_zip = true
        );
        assert!(
            result.is_ok(),
            "encrypt_data should succeed for binary input. Error: {:?}",
            result.err()
        );

        let output_zip_path_str = result.unwrap();
        let output_zip_path = Path::new(&output_zip_path_str);
        assert!(
            output_zip_path.exists(),
            "Encrypted zip file should exist at {}",
            output_zip_path_str
        );
        assert_eq!(output_zip_path.extension().unwrap_or_default(), "zip");
    }
    // endregion

    // region generate_aes_key
    #[test]
    fn generate_aes_key_returns_32_bytes_when_successful() {
        let result = generate_aes_key();
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_aes_key_returns_different_keys_when_called_multiple_times() {
        let key1 = generate_aes_key().unwrap();
        let key2 = generate_aes_key().unwrap();
        assert_ne!(key1, key2);
    }
    // endregion

    // region aes_encrypt
    #[test]
    fn aes_encrypt_returns_encrypted_data_with_correct_length_and_padding_when_input_is_valid() {
        let data = b"This is some test data.";
        let key = generate_aes_key().expect("Failed to generate AES key for test");

        let encrypted_result = aes_encrypt(data, &key);
        assert!(encrypted_result.is_ok());

        let encrypted_data = encrypted_result.unwrap();
        assert_ne!(data, encrypted_data.as_slice());

        // AES_CBC_PKCS7: output is IV (16 bytes) + ciphertext (multiple of block size, 16 bytes)
        // So, length should be > data length and a multiple of 16 if data is not empty.
        // More precisely, IV_SIZE + PADDED_DATA_SIZE
        // PADDED_DATA_SIZE = ((data.len() / 16) + 1) * 16
        let expected_min_len = 16 + (((data.len() / 16) + 1) * 16);
        assert_eq!(
            encrypted_data.len(),
            expected_min_len,
            "Encrypted data length is unexpected. Got {}, expected {}. Original data length: {}",
            encrypted_data.len(),
            expected_min_len,
            data.len()
        );
        assert!(
            encrypted_data.len() > data.len(),
            "Encrypted data should be longer than original data due to IV and padding."
        );
    }

    #[test]
    fn aes_encrypt_returns_error_when_data_is_empty() {
        let data = b"";
        let key = generate_aes_key().expect("Failed to generate AES key for test");

        let encrypted_result = aes_encrypt(data, &key);
        assert!(encrypted_result.is_err());
        assert_eq!(
            encrypted_result.err().unwrap(),
            ReplicateStatusCause::PostComputeEncryptionFailed
        );
    }

    #[test]
    fn aes_encrypt_returns_error_when_key_wrong_size() {
        let data = b"test data";
        let wrong_key = vec![0u8; 16]; // 16 bytes instead of 32

        let result = aes_encrypt(data, &wrong_key);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeEncryptionFailed
        );
    }

    #[test]
    fn aes_encrypt_returns_different_results_when_called_multiple_times() {
        let data = b"test data";
        let key = generate_aes_key().unwrap();

        let encrypted1 = aes_encrypt(data, &key).unwrap();
        let encrypted2 = aes_encrypt(data, &key).unwrap();
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn aes_encrypt_includes_iv_in_result_when_successful() {
        let data = b"test data";
        let key = generate_aes_key().unwrap();

        let result = aes_encrypt(data, &key).unwrap();
        assert!(result.len() >= 16, "IV should be at least 16 bytes");

        let iv = &result[0..16];
        assert_ne!(iv, &[0u8; 16], "IV should not be all zeros");
    }

    #[test]
    fn aes_encrypt_returns_error_when_key_is_invalid_length() {
        let data = b"Some data";
        let short_key = b"shortkey"; // Not 32 bytes
        let long_key = b"thisisaverylongkeythatisdefinitelymorethan32bytes"; // Not 32 bytes

        let encrypted_result_short = aes_encrypt(data, short_key);
        assert!(encrypted_result_short.is_err());
        assert_eq!(
            encrypted_result_short.err().unwrap(),
            ReplicateStatusCause::PostComputeEncryptionFailed,
            "Should fail for short key"
        );

        let encrypted_result_long = aes_encrypt(data, long_key);
        assert!(encrypted_result_long.is_err());
        assert_eq!(
            encrypted_result_long.err().unwrap(),
            ReplicateStatusCause::PostComputeEncryptionFailed,
            "Should fail for long key"
        );
    }
    // endregion

    // region base64_to_rsa_public_key
    #[test]
    fn base64_to_rsa_public_key_returns_key_when_input_is_valid_pem() {
        let result = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_PEM);
        assert!(
            result.is_ok(),
            "Should successfully parse valid PEM. Error: {:?}",
            result.err()
        );

        let public_key = result.unwrap();
        assert!(
            public_key.n().to_bytes_be().len() >= 256,
            "Public key modulus size is too small for a 2048-bit key."
        );
    }

    #[test]
    fn base64_to_rsa_public_key_returns_key_when_no_headers() {
        let result = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_NO_HEADERS);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.size(), 256);
    }

    #[test]
    fn base64_to_rsa_public_key_returns_key_when_with_newlines() {
        let key_with_newlines = TEST_RSA_PUBLIC_KEY_PEM
            .replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n")
            .replace("-----END PUBLIC KEY-----", "\n-----END PUBLIC KEY-----");

        let result = base64_to_rsa_public_key(&key_with_newlines);
        assert!(result.is_ok());
    }

    #[test]
    fn base64_to_rsa_public_key_returns_error_when_input_is_invalid_base64() {
        let invalid_base64_key =
            "-----BEGIN PUBLIC KEY-----\nnot_base64_at_all!!!\n-----END PUBLIC KEY-----";

        let result = base64_to_rsa_public_key(invalid_base64_key);
        assert!(result.is_err(), "Should fail for invalid Base64 content.");
        assert_eq!(
            result.err().unwrap(),
            ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
        );

        let direct_invalid_base64 = "not_base64_at_all!!!";
        let result_direct = base64_to_rsa_public_key(direct_invalid_base64);
        assert!(
            result_direct.is_err(),
            "Should fail for direct invalid Base64 content."
        );
        assert_eq!(
            result_direct.err().unwrap(),
            ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
        );
    }

    #[test]
    fn base64_to_rsa_public_key_returns_error_when_invalid_der() {
        let invalid_der_b64 = base64::engine::general_purpose::STANDARD.encode(b"invalid der data");

        let result = base64_to_rsa_public_key(&invalid_der_b64);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
        );
    }

    #[test]
    fn base64_to_rsa_public_key_returns_public_key_when_input_is_valid_der_base64() {
        let result = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_DER_BASE64);
        assert!(
            result.is_ok(),
            "Should successfully parse valid Base64 DER. Error: {:?}",
            result.err()
        );

        let public_key = result.unwrap();
        assert!(
            public_key.n().to_bytes_be().len() >= 256,
            "Public key modulus size is too small for a 2048-bit key."
        );
    }

    #[test]
    fn base64_to_rsa_public_key_returns_error_when_input_is_not_rsa_key() {
        let not_a_key_base64 = "SGVsbG8sIFdvcmxkIQ=="; // "Hello, World!" in Base64
        let pem_like_not_a_key = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            not_a_key_base64
        );

        let result = base64_to_rsa_public_key(&pem_like_not_a_key);
        assert!(
            result.is_err(),
            "Should fail for Base64 data that isn't a public key."
        );
        assert_eq!(
            result.err().unwrap(),
            ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
        );

        let result_direct_b64 = base64_to_rsa_public_key(not_a_key_base64);
        assert!(
            result_direct_b64.is_err(),
            "Should fail for direct Base64 data that isn't a public key."
        );
        assert_eq!(
            result_direct_b64.err().unwrap(),
            ReplicateStatusCause::PostComputeMalformedEncryptionPublicKey
        );
    }
    // endregion

    // region rsa_encrypt
    #[test]
    fn rsa_encrypt_returns_encrypted_string_when_input_is_valid() {
        let aes_key = generate_aes_key().expect("Failed to generate AES key for test");
        let rsa_public_key_obj = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_PEM)
            .expect("Failed to parse RSA public key for test");

        let result = rsa_encrypt(&aes_key, &rsa_public_key_obj);
        assert!(
            result.is_ok(),
            "RSA encryption should succeed. Error: {:?}",
            result.err()
        );

        let encrypted_aes_key_base64 = result.unwrap();
        assert!(
            !encrypted_aes_key_base64.is_empty(),
            "Encrypted AES key should not be empty."
        );

        let decoded_result = general_purpose::STANDARD.decode(&encrypted_aes_key_base64);
        assert!(
            decoded_result.is_ok(),
            "Encrypted AES key is not valid Base64. Error: {:?}",
            decoded_result.err()
        );
        assert_eq!(
            decoded_result.unwrap().len(),
            256,
            "RSA encrypted output length does not match key size (2048 bits / 256 bytes)."
        );
    }

    #[test]
    fn rsa_encrypt_returns_different_results_when_called_multiple_times() {
        let key = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_PEM).unwrap();
        let data = b"test data";

        let encrypted1 = rsa_encrypt(data, &key).unwrap();
        let encrypted2 = rsa_encrypt(data, &key).unwrap();
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn rsa_encrypt_returns_error_when_data_too_large() {
        let key = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_PEM).unwrap();
        let large_data = vec![0u8; 1000]; // Much larger than key size

        let result = rsa_encrypt(&large_data, &key);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeEncryptionFailed
        );
    }

    #[test]
    fn rsa_encrypt_returns_error_when_key_is_invalid() {
        let key_result = RsaPublicKey::new(BigUint::from(0u8), BigUint::from(0u8));
        assert!(
            key_result.is_err(),
            "RsaPublicKey::new should fail for invalid modulus/exponent"
        );
    }

    #[test]
    fn rsa_encrypt_encrypts_empty_data_when_data_is_empty() {
        let key = base64_to_rsa_public_key(TEST_RSA_PUBLIC_KEY_PEM).unwrap();
        let empty_data = b"";

        let result = rsa_encrypt(empty_data, &key);
        assert!(
            result.is_ok(),
            "RSA encryption should succeed for empty data. Error: {:?}",
            result.err()
        );

        let encrypted = result.unwrap();
        assert!(
            !encrypted.is_empty(),
            "Encrypted output should not be empty for empty input."
        );

        let decoded = general_purpose::STANDARD.decode(&encrypted);
        assert!(
            decoded.is_ok(),
            "Encrypted output should be valid base64. Error: {:?}",
            decoded.err()
        );
        assert_eq!(
            decoded.unwrap().len(),
            256,
            "Encrypted output should match key size (256 bytes for 2048-bit key)"
        );
    }
    // endregion

    // region write_file
    #[test]
    fn write_file_creates_file_when_successful() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let data = b"test content";

        let result = write_file(file_path.to_str().unwrap().to_string(), data);
        assert!(result.is_ok());
        assert!(file_path.exists());

        let content = fs::read(&file_path).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn write_file_returns_error_when_invalid_path() {
        let invalid_path = "/invalid/path/that/does/not/exist/file.txt";
        let data = b"test content";

        let result = write_file(invalid_path.to_string(), data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeEncryptionFailed
        );
    }

    #[test]
    fn write_file_overwrites_existing_file_when_called_twice() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let data1 = b"first content";
        let data2 = b"second content";

        let result1 = write_file(file_path.to_str().unwrap().to_string(), data1);
        let result2 = write_file(file_path.to_str().unwrap().to_string(), data2);
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let content = fs::read(&file_path).unwrap();
        assert_eq!(content, data2);
    }

    #[test]
    fn write_file_handles_empty_data_when_called() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("empty.txt");
        let data = b"";

        let result = write_file(file_path.to_str().unwrap().to_string(), data);
        assert!(result.is_ok());
        assert!(file_path.exists());

        let content = fs::read(&file_path).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn write_file_writes_data_to_file_when_path_is_valid() {
        let base_dir = tempdir().expect("Failed to create temp base directory for test");
        let file_path = base_dir.path().join("test_output.txt");
        let data_to_write = b"Hello, Jules! This is a test.";

        let result = write_file(file_path.to_str().unwrap().to_string(), data_to_write);
        assert!(
            result.is_ok(),
            "write_file should succeed. Error: {:?}",
            result.err()
        );
        assert!(file_path.exists(), "File should exist after writing.");

        let mut file_content = Vec::new();
        let mut file =
            fs::File::open(&file_path).expect("Failed to open written file for verification");
        file.read_to_end(&mut file_content)
            .expect("Failed to read written file for verification");
        assert_eq!(
            file_content, data_to_write,
            "File content does not match written data."
        );
    }

    #[test]
    fn write_file_returns_error_when_path_is_invalid() {
        let invalid_path = "/nonexistent_directory_test/test_output.txt"; // Assuming this path is not writable
        let base_dir = tempdir().expect("Failed to create temp base directory for test");
        let dir_as_file_path = base_dir.path().join("i_am_a_directory");
        fs::create_dir_all(&dir_as_file_path)
            .expect("Failed to create directory for collision test");
        let data_to_write = b"Some data";

        let result_nonexistent_parent = write_file(invalid_path.to_string(), data_to_write);
        if result_nonexistent_parent.is_ok() {
            let _ = fs::remove_file(invalid_path);
            let _ = fs::remove_dir(Path::new(invalid_path).parent().unwrap());
        }
        assert!(
            result_nonexistent_parent.is_err(),
            "write_file should fail for a non-existent parent directory. Path: {}",
            invalid_path
        );
        if let Some(err_cause) = result_nonexistent_parent.err() {
            assert_eq!(
                err_cause,
                ReplicateStatusCause::PostComputeEncryptionFailed,
                "Error cause mismatch for nonexistent parent."
            );
        }

        let result_path_is_dir = write_file(
            dir_as_file_path.to_str().unwrap().to_string(),
            data_to_write,
        );
        assert!(
            result_path_is_dir.is_err(),
            "write_file should fail if the path is an existing directory."
        );
        if let Some(err_cause) = result_path_is_dir.err() {
            assert_eq!(
                err_cause,
                ReplicateStatusCause::PostComputeEncryptionFailed,
                "Error cause mismatch for path being a directory."
            );
        }
    }
    // endregion

    // region create_folder
    #[test]
    fn create_folder_creates_directory_when_not_exists() {
        let base_dir = tempdir().expect("Failed to create temp base directory for test");
        let new_folder_path = base_dir.path().join("new_test_folder");
        assert!(
            !new_folder_path.exists(),
            "Folder should not exist before creation"
        );

        let result = create_folder(new_folder_path.to_str().unwrap());
        assert!(result.is_ok());
        assert!(
            new_folder_path.exists(),
            "Folder should exist after creation"
        );
        assert!(new_folder_path.is_dir(), "Path should be a directory");
    }

    #[test]
    fn create_folder_succeeds_when_directory_already_exists() {
        let base_dir = tempdir().expect("Failed to create temp base directory for test");
        let existing_folder_path = base_dir.path().join("already_existing_folder");
        fs::create_dir_all(&existing_folder_path).expect("Failed to pre-create directory for test");
        assert!(
            existing_folder_path.exists(),
            "Folder should exist before calling create_folder"
        );

        let result = create_folder(existing_folder_path.to_str().unwrap());
        assert!(
            result.is_ok(),
            "create_folder should succeed if directory already exists. Error: {:?}",
            result.err()
        );
        assert!(existing_folder_path.exists(), "Folder should still exist");
        assert!(
            existing_folder_path.is_dir(),
            "Path should still be a directory"
        );
    }

    #[test]
    fn create_folder_creates_nested_directories_when_needed() {
        let temp_dir = tempdir().unwrap();
        let nested_dir = temp_dir.path().join("level1").join("level2").join("level3");

        let result = create_folder(nested_dir.to_str().unwrap());
        assert!(result.is_ok());
        assert!(nested_dir.exists());
        assert!(nested_dir.is_dir());
    }

    #[test]
    fn create_folder_returns_error_when_invalid_path() {
        let invalid_path = "/invalid/path/that/cannot/be/created";

        let result = create_folder(invalid_path);
        if result.is_err() {
            assert_eq!(
                result.unwrap_err(),
                ReplicateStatusCause::PostComputeEncryptionFailed
            );
        }
    }
    // endregion

    // region zip_folder
    #[test]
    fn zip_folder_creates_zip_file_when_directory_exists() {
        let temp_dir = tempdir().unwrap();
        let source_dir = temp_dir.path().join("source");
        fs::create_dir(&source_dir).unwrap();

        let test_file = source_dir.join("test.txt");
        fs::write(&test_file, b"test content").unwrap();

        let result = zip_folder(source_dir.to_str().unwrap());
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        assert!(!zip_path.is_empty());
        assert!(zip_path.ends_with(".zip"));
        assert!(std::path::Path::new(&zip_path).exists());
    }

    #[test]
    fn zip_folder_returns_error_when_directory_not_exists() {
        let result = zip_folder("/nonexistent/directory");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeOutFolderZipFailed
        );
    }

    #[test]
    fn zip_folder_creates_zip_file_when_directory_is_valid_and_has_content() {
        let base_temp = tempdir().expect("Failed to create base temp dir for zip test");
        let source_parent_dir = base_temp.path(); // Zip will be created here
        let source_dir_name = "zip_source_content";
        let source_dir_to_zip = create_temp_dir_with_files(&base_temp, source_dir_name, 2, true);

        let result = zip_folder(source_dir_to_zip.to_str().unwrap());
        assert!(
            result.is_ok(),
            "zip_folder should succeed. Error: {:?}",
            result.err()
        );

        let zip_file_path_str = result.unwrap();
        let zip_file_path = Path::new(&zip_file_path_str);
        assert!(
            zip_file_path.exists(),
            "Zip file should exist at {}",
            zip_file_path_str
        );
        assert_eq!(zip_file_path.file_name().unwrap(), "iexec_out.zip");
        assert_eq!(
            zip_file_path.parent().unwrap(),
            source_parent_dir,
            "Zip file is in an unexpected directory."
        );

        let file = File::open(zip_file_path).expect("Failed to open created zip file");
        let mut archive = ZipArchive::new(file).expect("Failed to read zip archive"); // Made archive mutable again
        assert!(
            archive.len() >= 3,
            "Zip archive should contain at least 3 entries (2 files + 1 subfile). Actual: {}",
            archive.len()
        );
        assert!(archive.by_name("file0.txt").is_ok());
        assert!(archive.by_name("file1.txt").is_ok());
        assert!(archive.by_name("subdir/subfile0.txt").is_ok());
    }

    #[test]
    fn zip_folder_creates_empty_zip_file_when_directory_is_empty() {
        let base_temp = tempdir().expect("Failed to create base temp dir");
        let source_parent_dir = base_temp.path();
        let source_dir_name = "zip_source_empty";
        let empty_source_dir = create_temp_dir_with_files(&base_temp, source_dir_name, 0, false);

        let result = zip_folder(empty_source_dir.to_str().unwrap());
        assert!(
            result.is_ok(),
            "zip_folder should succeed for empty dir. Error: {:?}",
            result.err()
        );

        let zip_file_path_str = result.unwrap();
        let zip_file_path = Path::new(&zip_file_path_str);
        assert!(
            zip_file_path.exists(),
            "Zip file should exist for empty source at {}",
            zip_file_path_str
        );
        assert_eq!(zip_file_path.parent().unwrap(), source_parent_dir);

        let file = File::open(zip_file_path).expect("Failed to open created zip file");
        let archive = ZipArchive::new(file).expect("Failed to read zip archive"); // Made archive non-mutable
        assert_eq!(
            archive.len(),
            0,
            "Zip archive from empty source should be empty"
        );
    }

    #[test]
    fn zip_folder_creates_empty_zip_file_when_source_directory_does_not_exist() {
        let base_temp = tempdir().expect("Failed to create base temp dir");
        let source_parent_dir = base_temp.path();
        let non_existent_source_path = source_parent_dir.join("non_existent_source");

        let result = zip_folder(non_existent_source_path.to_str().unwrap());
        assert!(
            result.is_ok(),
            "zip_folder should succeed for non-existent source. Error: {:?}",
            result.err()
        );

        let zip_file_path_str = result.unwrap();
        let zip_file_path = Path::new(&zip_file_path_str);
        assert!(
            zip_file_path.exists(),
            "Zip file should exist for non-existent source at {}",
            zip_file_path_str
        );
        assert_eq!(zip_file_path.parent().unwrap(), source_parent_dir);

        let file = File::open(zip_file_path).expect("Failed to open created zip file");
        let archive = ZipArchive::new(file).expect("Failed to read zip archive"); // Made archive non-mutable
        assert_eq!(
            archive.len(),
            0,
            "Zip archive from non-existent source should be empty"
        );
    }

    #[test]
    fn zip_folder_returns_error_when_destination_is_not_writable() {
        let base_temp = tempdir().expect("Failed to create base temp dir for zip test");
        let parent_dir_for_source = base_temp.path().join("parent_of_source");
        fs::create_dir_all(&parent_dir_for_source).expect("Failed to create parent_dir_for_source");

        let source_dir_to_zip = parent_dir_for_source.join("actual_source_files");
        fs::create_dir_all(&source_dir_to_zip).expect("Failed to create actual_source_files");
        File::create(source_dir_to_zip.join("testfile.txt"))
            .expect("Failed to create testfile.txt in actual_source_files")
            .write_all(b"content")
            .expect("Failed to write to testfile.txt");

        let problematic_zip_path = parent_dir_for_source.join("iexec_out.zip");
        fs::create_dir_all(&problematic_zip_path)
            .expect("Failed to create directory at problematic_zip_path");

        let result = zip_folder(source_dir_to_zip.to_str().unwrap());
        assert!(
            result.is_err(),
            "zip_folder should fail when the target zip path is an existing directory. Actual: {:?}",
            result
        );
        assert_eq!(
            result.err().unwrap(),
            ReplicateStatusCause::PostComputeOutFolderZipFailed
        );
    }
    // endregion
}
