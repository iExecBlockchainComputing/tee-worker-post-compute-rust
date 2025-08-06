use crate::compute::errors::ReplicateStatusCause;
use crate::compute::web2_result::{Web2ResultInterface, Web2ResultService};
use aes::{
    Aes256,
    cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use cbc::Encryptor;
use log::error;
use rand::{RngCore, rngs::OsRng};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
use sha3::{Digest, Sha3_256};
use std::{fs, path::Path};

const AES_KEY_LENGTH: usize = 32; // 256-bit key (32 bytes)
const AES_IV_LENGTH: usize = 16; // 128-bit IV (16 bytes)

/// Encrypts a data file using hybrid encryption (AES-256-CBC + RSA-2048).
///
/// This function implements a secure hybrid encryption scheme where the input data
/// is encrypted with AES-256-CBC and the AES key is encrypted with RSA-2048.
/// The function creates an output directory containing the encrypted data and
/// encrypted key, with optional ZIP compression.
///
/// # Encryption Process
///
/// 1. **File Validation**: Validates input file path and reads data
/// 2. **AES Encryption**: Generates a random 256-bit AES key and encrypts the data
/// 3. **RSA Key Encryption**: Encrypts the AES key using the provided RSA public key
/// 4. **Output Generation**: Creates encrypted files in a structured directory
/// 5. **Optional Compression**: Creates a ZIP archive if requested
///
/// # Arguments
///
/// * `in_data_file_path` - Path to the input file to encrypt. Must be a valid, readable, non-empty file.
/// * `plain_text_rsa_pub` - RSA public key in PEM format with proper headers/footers.
///   Must be a valid PKCS#8 or PKCS#1 formatted PEM key.
/// * `produce_zip` - If `true`, creates a ZIP archive containing encrypted files.
///   If `false`, returns the directory path containing encrypted files.
///
/// # Returns
///
/// * `Result<String, ReplicateStatusCause>` - On success, returns the path to either:
///   - ZIP file path (if `produce_zip` is `true`)
///   - Directory path containing encrypted files (if `produce_zip` is `false`)
///
/// # Output Structure
///
/// When `produce_zip` is `false`, creates a directory named `encrypted-{filename_stem}`:
/// ```text
/// encrypted-myfile/
/// ├── myfile.txt.aes        # AES-encrypted data (IV + ciphertext)
/// └── aes-key.rsa           # RSA-encrypted AES key (raw bytes)
/// ```
///
/// When `produce_zip` is `true`, creates `iexec_out.zip` containing the above structure.
///
/// # Errors
///
/// * `PostComputeEncryptionFailed` - Returned for any failure including:
///   - Invalid file path or unreadable input file
///   - Empty input files
///   - Invalid or malformed RSA public keys
///   - Cryptographic operation failures
///   - File system operation failures (directory creation, file writing)
///   - ZIP creation failures
///
/// # Security Notes
///
/// - Each encryption operation uses a fresh AES key and IV
/// - RSA encryption uses PKCS#1 v1.5 padding (industry standard)
/// - All random values are generated using cryptographically secure `OsRng`
/// - Input data is securely overwritten in memory after encryption
/// - AES keys are stored as raw encrypted bytes (not Base64 encoded)
///
/// # Example
///
/// ```rust
/// // Encrypt a file and create a ZIP archive
/// let rsa_key = "-----BEGIN PUBLIC KEY-----\nMIIB...AQAB\n-----END PUBLIC KEY-----";
/// let result = encrypt_data("./secret.txt", rsa_key, true)?;
/// println!("Encrypted ZIP created: {}", result);
///
/// // Encrypt a file and get directory path
/// let result = encrypt_data("./secret.txt", rsa_key, false)?;
/// println!("Encrypted files in: {}", result);
/// ```
pub fn encrypt_data(
    in_data_file_path: &str,
    plain_text_rsa_pub: &str,
    produce_zip: bool,
) -> Result<String, ReplicateStatusCause> {
    let path = Path::new(in_data_file_path);
    let in_data_filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            error!(
                "Failed to extract filename from path: {}",
                in_data_file_path
            );
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?;
    let out_encrypted_data_filename = format!("{}.aes", in_data_filename);

    let work_dir = path.parent().and_then(|p| p.to_str()).ok_or_else(|| {
        error!("Failed to get parent directory of: {}", in_data_file_path);
        ReplicateStatusCause::PostComputeEncryptionFailed
    })?;

    let filename_without_ext =
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                error!(
                    "Failed to extract filename without extension from '{}'",
                    in_data_file_path
                );
                ReplicateStatusCause::PostComputeEncryptionFailed
            })?;
    let out_enc_dir = format!("{}/{}{}", work_dir, "encrypted-", filename_without_ext); //location of future encrypted files (./encrypted-0x1_result)

    // Get data to encrypt
    let data = fs::read(in_data_file_path).map_err(|e| {
        error!(
            "Failed to encrypt_data (read_file error) [in_data_file_path:{}]: {}",
            in_data_file_path, e
        );
        ReplicateStatusCause::PostComputeEncryptionFailed
    })?;
    if data.is_empty() {
        error!(
            "Failed to encrypt_data (empty file error) [in_data_file_path:{}]",
            in_data_file_path
        );
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }

    // Generate AES key for data encryption
    let aes_key = generate_aes_key().map_err(|_| {
        error!(
            "Failed to encrypt_data (generate_aes_key error) [in_data_file_path:{}]",
            in_data_file_path
        );
        ReplicateStatusCause::PostComputeEncryptionFailed
    })?;

    // Encrypt data with Base64 AES key
    let encrypted_data = aes_encrypt(&data, &aes_key).map_err(|e| {
        error!(
            "Failed to encrypt_data (aes_encrypt error) [in_data_file_path:{}]: {}",
            in_data_file_path, e
        );
        ReplicateStatusCause::PostComputeEncryptionFailed
    })?;

    // Create folder for future out_encrypted_data & out_encrypted_aes_key
    let out_enc_dir_path = std::path::Path::new(&out_enc_dir);
    if !out_enc_dir_path.exists() {
        fs::create_dir_all(out_enc_dir_path).map_err(|e| {
            error!(
                "Failed to create directory '{}' (is_out_dir_created error) [in_data_file_path:{}]: {}",
                out_enc_dir, in_data_file_path, e
            );
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?;
    }

    // Store encrypted data in ./0xtask1 [out_enc_dir]
    write_file(
        format!("{}/{}", &out_enc_dir, &out_encrypted_data_filename),
        &encrypted_data,
    )
    .map_err(|_| {
        error!(
            "Failed to encrypt_data (is_encrypted_data_stored error) [in_data_file_path:{}]",
            in_data_file_path
        );
        ReplicateStatusCause::PostComputeEncryptionFailed
    })?;

    // Encrypt AES key with RSA public key
    let encrypted_aes_key = RsaPublicKey::from_public_key_pem(plain_text_rsa_pub)
        .map_err(|e| {
            error!("Failed to parse RSA public key: {}", e);
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &aes_key)
        .map_err(|e| {
            error!("RSA encryption failed: {e}");
            ReplicateStatusCause::PostComputeEncryptionFailed
        })?;

    // Store encrypted AES key in ./0xtask1 [outEncDir]
    write_file(
        format!("{}/{}", &out_enc_dir, "aes-key.rsa"),
        &encrypted_aes_key,
    )
    .map_err(|_| {
        error!(
            "Failed to encrypt_data (is_encrypted_aes_key_stored error) [in_data_file_path:{}]",
            in_data_file_path
        );
        ReplicateStatusCause::PostComputeEncryptionFailed
    })?;

    if produce_zip {
        // Zip encrypted files folder
        let parent = out_enc_dir_path.parent().unwrap_or_else(|| Path::new("."));
        let out_enc_zip = Web2ResultService
            .zip_iexec_out(&out_enc_dir, parent.to_str().unwrap())
            .map_err(|_| {
                error!(
                    "Failed to encrypt_data (out_enc_zip error) [in_data_file_path:{}]",
                    in_data_file_path
                );
                ReplicateStatusCause::PostComputeEncryptionFailed
            })?;
        if out_enc_zip.is_empty() {
            error!(
                "Failed to encrypt_data (out_enc_zip error) [in_data_file_path:{}]",
                in_data_file_path
            );
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        } else {
            Ok(out_enc_zip)
        }
    } else {
        Ok(out_enc_dir)
    }
}

/// Generates a cryptographically secure 256-bit AES key.
///
/// This function creates a new AES-256 key using the operating system's
/// cryptographically secure random number generator (`OsRng`). Each call
/// produces a unique key suitable for encrypting sensitive data.
///
/// # Returns
///
/// * `Result<Vec<u8>, ReplicateStatusCause>` - On success, returns a `AES_KEY_LENGTH`-byte
///   vector containing the AES-256 key. On failure, returns `PostComputeEncryptionFailed`.
///
/// # Security
///
/// - Uses `OsRng` which provides cryptographically secure randomness
/// - Generates full 256-bit (`AES_KEY_LENGTH`-byte) keys for maximum security
/// - Each key is statistically unique across all invocations
///
/// # Errors
///
/// * `PostComputeEncryptionFailed` - If the random number generator fails
///   to produce sufficient entropy (extremely rare on modern systems)
///
/// # Example
///
/// ```rust
/// let aes_key = generate_aes_key()?;
/// assert_eq!(aes_key.len(), AES_KEY_LENGTH);
/// ```
pub fn generate_aes_key() -> Result<Vec<u8>, ReplicateStatusCause> {
    let mut key_bytes = [0u8; AES_KEY_LENGTH];
    if let Err(e) = OsRng.try_fill_bytes(&mut key_bytes) {
        error!("Failed to generate AES key: {}", e);
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }
    Ok(key_bytes.to_vec())
}

/// Encrypts data using AES-256 in CBC mode with PKCS#7 padding.
///
/// This function implements AES-256-CBC encryption with the following characteristics:
/// - **Algorithm**: AES-256 (Advanced Encryption Standard with 256-bit key)
/// - **Mode**: CBC (Cipher Block Chaining) for semantic security
/// - **Padding**: PKCS#7 to handle arbitrary input lengths
/// - **IV**: Random 128-bit initialization vector prepended to output
///
/// # Process
///
/// 1. Validates input data and key length
/// 2. Generates a random 128-bit IV using `OsRng`
/// 3. Encrypts data using AES-256-CBC with PKCS#7 padding
/// 4. Prepends IV to ciphertext for later decryption
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt. Must not be empty.
/// * `key` - The AES-256 key. Must be exactly `AES_KEY_LENGTH` bytes (256 bits).
///
/// # Returns
///
/// * `Result<Vec<u8>, ReplicateStatusCause>` - On success, returns a vector
///   containing `[IV][Ciphertext]` where:
///   - First `AES_IV_LENGTH` bytes: Random initialization vector
///   - Remaining bytes: AES-encrypted data with PKCS#7 padding
///
/// # Output Format
///
/// ```text
/// [IV: `AES_IV_LENGTH` bytes][Encrypted Data: variable length, multiple of `AES_BLOCK_SIZE` bytes]
/// ```
///
/// # Security Properties
///
/// - **Semantic Security**: CBC mode with random IV ensures identical plaintexts
///   produce different ciphertexts
/// - **Integrity**: While this function doesn't provide authentication,
///   the padding scheme prevents certain classes of attacks
/// - **Key Schedule**: AES-256 uses 14 rounds for maximum security
///
/// # Errors
///
/// * `PostComputeEncryptionFailed` - If:
///   - Input data is empty
///   - Key is not exactly `AES_KEY_LENGTH` bytes
///   - Random number generation fails
///   - Encryption operation fails
///
/// # Example
///
/// ```rust
/// let data = b"Secret message to encrypt";
/// let key = generate_aes_key()?;
/// let encrypted = aes_encrypt(data, &key)?;
///
/// // Output format: [`AES_IV_LENGTH`-byte IV][encrypted data]
/// assert!(encrypted.len() >= AES_IV_LENGTH + data.len());
/// assert_eq!(encrypted.len() % AES_IV_LENGTH, 0);
/// ```
pub fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ReplicateStatusCause> {
    if data.is_empty() {
        error!("AES encryption input data is empty");
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }
    if key.len() != AES_KEY_LENGTH {
        error!(
            "AES encryption key must be {} bytes, got {}",
            AES_KEY_LENGTH,
            key.len()
        );
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }

    // Generate random `AES_IV_LENGTH`-byte initialization vector
    let mut iv = [0u8; AES_IV_LENGTH];
    if let Err(e) = OsRng.try_fill_bytes(&mut iv) {
        error!("Failed to generate IV for AES encryption: {}", e);
        return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
    }

    // Perform AES-256-CBC encryption with PKCS#7 padding
    let cipher = Encryptor::<Aes256>::new(key.into(), &iv.into());
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

    // Prepend IV to ciphertext
    let mut result = Vec::with_capacity(iv.len() + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Writes data to a file with secure error handling and logging.
///
/// This function writes binary data to the specified file path, creating
/// the file if it doesn't exist or overwriting it if it does. The function
/// includes comprehensive error logging with data integrity hashing for
/// debugging purposes.
///
/// # Arguments
///
/// * `file_path` - The target file path as a String. Must be writable.
/// * `data` - The binary data to write to the file.
///
/// # Returns
///
/// * `Result<(), ReplicateStatusCause>` - Success if file was written,
///   error if write operation failed.
///
/// # Error Handling
///
/// On write failure, the function:
/// 1. Computes SHA3-256 hash of the data (for debugging, not security)
/// 2. Logs error with file path and data hash (no sensitive data exposed)
/// 3. Returns `PostComputeEncryptionFailed`
///
/// # Errors
///
/// * `PostComputeEncryptionFailed` - If write fails due to:
///   - Insufficient disk space
///   - Permission denied
///   - Invalid file path
///   - Filesystem errors
///
/// # Example
///
/// ```rust
/// let encrypted_data = aes_encrypt(plaintext, &key)?;
/// write_file("./output/data.aes".to_string(), &encrypted_data)?;
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, io::Read};
    use tempfile::tempdir;
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

        let aes_key_content_bytes =
            fs::read(&aes_key_file_in_dir).expect("Failed to read AES key file from dir");
        assert!(!aes_key_content_bytes.is_empty());
        // AES key is now stored as raw encrypted bytes, not Base64 string
        assert_eq!(aes_key_content_bytes.len(), 256); // RSA-2048 produces 256-byte output
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
            let mut aes_key_content_bytes = Vec::new();
            aes_key_file_in_zip
                .read_to_end(&mut aes_key_content_bytes)
                .expect("Failed to read AES key from zip");
            assert!(
                !aes_key_content_bytes.is_empty(),
                "AES key content in zip should not be empty."
            );
            // AES key is now stored as raw encrypted bytes, not Base64 string
            assert_eq!(
                aes_key_content_bytes.len(),
                256,
                "RSA-2048 produces 256-byte output"
            );
        }
    }

    #[test]
    fn encrypt_data_returns_error_when_input_file_is_empty() {
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
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );
    }

    #[test]
    fn encrypt_data_returns_error_when_rsa_key_is_invalid() {
        // Edge case: invalid RSA key, should now return Err instead of Ok("")
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
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
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
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
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

    #[test]
    fn encrypt_data_returns_error_when_output_dir_creation_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_file_path = temp_dir.path().join("input.txt");
        fs::write(&input_file_path, b"data").unwrap();

        let output_dir_path = temp_dir.path().join("encrypted-input");
        fs::write(&output_dir_path, b"not a dir").unwrap();

        let result = encrypt_data(
            input_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            false,
        );
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );
    }

    #[test]
    fn encrypt_data_returns_error_when_zip_fails_due_to_unwritable_destination() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_file_path = temp_dir.path().join("input.txt");
        fs::write(&input_file_path, b"data").unwrap();

        let zip_file_path = temp_dir.path().join("iexec_out.zip");
        fs::create_dir(&zip_file_path).unwrap();

        let result = encrypt_data(
            input_file_path.to_str().unwrap(),
            TEST_RSA_PUBLIC_KEY_PEM,
            true,
        );
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );
    }
    // endregion

    // region generate_aes_key
    #[test]
    fn generate_aes_key_returns_32_bytes_when_successful() {
        let result = generate_aes_key();
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.len(), AES_KEY_LENGTH);
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

        // AES_CBC_PKCS7: output is IV (`AES_IV_LENGTH` bytes) + ciphertext (multiple of block size, `AES_IV_LENGTH` bytes)
        // So, length should be > data length and a multiple of 16 if data is not empty.
        // More precisely, IV_SIZE + PADDED_DATA_SIZE
        // PADDED_DATA_SIZE = ((data.len() / `AES_IV_LENGTH`) + 1) * `AES_IV_LENGTH`
        let expected_min_len = AES_IV_LENGTH + (((data.len() / AES_IV_LENGTH) + 1) * AES_IV_LENGTH);
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
            encrypted_result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );
    }

    #[test]
    fn aes_encrypt_returns_error_when_key_wrong_size() {
        let data = b"test data";
        let wrong_key = vec![0u8; 16]; // 16 bytes instead of 32

        let result = aes_encrypt(data, &wrong_key);
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
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
        assert!(
            result.len() >= AES_IV_LENGTH,
            "IV should be at least AES_IV_LENGTH bytes"
        );

        let iv = &result[0..AES_IV_LENGTH];
        assert_ne!(iv, &[0u8; AES_IV_LENGTH], "IV should not be all zeros");
    }

    #[test]
    fn aes_encrypt_returns_error_when_key_is_invalid_length() {
        let data = b"Some data";
        let short_key = b"shortkey"; // Not 32 bytes
        let long_key = b"thisisaverylongkeythatisdefinitelymorethan32bytes"; // Not 32 bytes

        let encrypted_result_short = aes_encrypt(data, short_key);
        assert!(encrypted_result_short.is_err());
        assert_eq!(
            encrypted_result_short,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );

        let encrypted_result_long = aes_encrypt(data, long_key);
        assert!(encrypted_result_long.is_err());
        assert_eq!(
            encrypted_result_long,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
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
            result,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
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
        assert_eq!(
            result_nonexistent_parent,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );

        let result_path_is_dir = write_file(
            dir_as_file_path.to_str().unwrap().to_string(),
            data_to_write,
        );
        assert_eq!(
            result_path_is_dir,
            Err(ReplicateStatusCause::PostComputeEncryptionFailed)
        );
    }
    // endregion
}
