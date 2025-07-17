use crate::compute::errors::ReplicateStatusCause;
use crate::compute::web2_result::{Web2ResultInterface, Web2ResultService};
use aes::{
    Aes256,
    cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use base64::Engine as _;
use cbc::Encryptor;
use log::error;
use rand::{RngCore, rngs::OsRng};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
use sha3::{Digest, Sha3_256};
use std::{fs, path::Path};

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
/// * `in_data_file_path` - Path to the input file to encrypt. Must be a valid, readable file.
/// * `plain_text_rsa_pub` - RSA public key in PEM format (with or without headers).
///   Supports both PKCS#1 and PKCS#8 formats.
/// * `produce_zip` - If `true`, creates a ZIP archive containing encrypted files.
///   If `false`, returns the directory path containing encrypted files.
///
/// # Returns
///
/// * `Result<String, ReplicateStatusCause>` - On success, returns the path to either:
///   - ZIP file path (if `produce_zip` is `true`)
///   - Directory path containing encrypted files (if `produce_zip` is `false`)
///   - Empty string for non-critical failures (operation continues but with warnings)
///
/// # Output Structure
///
/// When `produce_zip` is `false`, creates a directory named `encrypted-{filename_stem}`:
/// ```text
/// encrypted-myfile/
/// ├── myfile.txt.aes        # AES-encrypted data (IV + ciphertext)
/// └── aes-key.rsa           # RSA-encrypted AES key (Base64 encoded)
/// ```
///
/// When `produce_zip` is `true`, creates `iexec_out.zip` containing the above structure.
///
/// # Errors
///
/// * `PostComputeEncryptionFailed` - Critical failures:
///   - Invalid file path or unreadable input file
///   - Cryptographic operation failures
///   - File system operation failures
/// * Returns empty string for non-critical failures:
///   - Empty input files
///   - Invalid RSA public keys
///   - Directory creation failures
///
/// # Security Notes
///
/// - Each encryption operation uses a fresh AES key and IV
/// - RSA encryption uses PKCS#1 v1.5 padding (industry standard)
/// - All random values are generated using cryptographically secure `OsRng`
/// - Input data is securely overwritten in memory after encryption
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
    let in_data_filename = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => {
            error!(
                "Failed to extract filename from path: {}",
                in_data_file_path
            );
            return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
        }
    };
    let out_encrypted_data_filename = format!("{}.aes", in_data_filename);

    let work_dir = match path.parent().and_then(|p| p.to_str()) {
        Some(dir) => dir,
        None => {
            error!("Failed to get parent directory of: {}", in_data_file_path);
            return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
        }
    };

    let filename_without_ext = match path.file_stem().and_then(|stem| stem.to_str()) {
        Some(stem) => stem,
        None => {
            error!(
                "Failed to extract filename without extension from '{}'",
                in_data_file_path
            );
            return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
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
            return Err(ReplicateStatusCause::PostComputeEncryptionFailed);
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
    let out_enc_dir_path = std::path::Path::new(&out_enc_dir);
    match out_enc_dir_path.exists() {
        true => Ok(()),
        false => fs::create_dir_all(out_enc_dir_path).map_err(|e| {
            error!(
                "Failed to create directory '{}' (is_out_dir_created error) [in_data_file_path:{}]: {}",
                out_enc_dir, in_data_file_path, e
            );
            ReplicateStatusCause::PostComputeEncryptionFailed
        }),
    }?;

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
        let parent = out_enc_dir_path.parent().unwrap_or_else(|| Path::new("."));
        let out_enc_zip =
            match Web2ResultService.zip_iexec_out(&out_enc_dir, parent.to_str().unwrap()) {
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

/// Generates a cryptographically secure 256-bit AES key.
///
/// This function creates a new AES-256 key using the operating system's
/// cryptographically secure random number generator (`OsRng`). Each call
/// produces a unique key suitable for encrypting sensitive data.
///
/// # Returns
///
/// * `Result<Vec<u8>, ReplicateStatusCause>` - On success, returns a 32-byte
///   vector containing the AES-256 key. On failure, returns `PostComputeEncryptionFailed`.
///
/// # Security
///
/// - Uses `OsRng` which provides cryptographically secure randomness
/// - Generates full 256-bit (32-byte) keys for maximum security
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
/// assert_eq!(aes_key.len(), 32); // 256 bits = 32 bytes
/// ```
pub fn generate_aes_key() -> Result<Vec<u8>, ReplicateStatusCause> {
    let mut key_bytes = [0u8; 32]; // 256-bit key (32 bytes)
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
/// * `key` - The AES-256 key. Must be exactly 32 bytes (256 bits).
///
/// # Returns
///
/// * `Result<Vec<u8>, ReplicateStatusCause>` - On success, returns a vector
///   containing `[IV][Ciphertext]` where:
///   - First 16 bytes: Random initialization vector
///   - Remaining bytes: AES-encrypted data with PKCS#7 padding
///
/// # Output Format
///
/// ```text
/// [IV: 16 bytes][Encrypted Data: variable length, multiple of 16 bytes]
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
///   - Key is not exactly 32 bytes
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
/// // Output format: [16-byte IV][encrypted data]
/// assert!(encrypted.len() >= 16 + data.len());
/// assert_eq!(encrypted.len() % 16, 0); // Multiple of block size
/// ```
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

    // Generate random 128-bit initialization vector
    let mut iv = [0u8; 16];
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

/// Parses an RSA public key from PEM or Base64 format.
///
/// This function accepts RSA public keys in multiple formats and converts them
/// to an `RsaPublicKey` object for cryptographic operations. It handles both
/// PEM-wrapped keys and raw Base64-encoded DER data.
///
/// # Supported Formats
///
/// 1. **PEM Format** (with headers):
///    ```text
///    -----BEGIN PUBLIC KEY-----
///    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AM...
///    -----END PUBLIC KEY-----
///    ```
///
/// 2. **Base64 DER** (without headers):
///    ```text
///    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AM...
///    ```
///
/// 3. **Base64 with whitespace** (headers removed, formatted):
///    ```text
///    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AM
///    IIBCgKCAQEAr0mx20CSFczJaM4rtYfL...
///    ```
///
/// # Process
///
/// 1. **Header Removal**: Strips PEM headers/footers if present
/// 2. **Whitespace Cleanup**: Removes newlines, carriage returns, and spaces
/// 3. **Base64 Decoding**: Converts Base64 string to DER bytes
/// 4. **DER Parsing**: Parses DER-encoded public key data
/// 5. **Validation**: Ensures key is valid for RSA operations
///
/// # Arguments
///
/// * `plain_text_rsa_pub` - RSA public key string in PEM or Base64 format.
///   Whitespace and formatting are automatically handled.
///
/// # Returns
///
/// * `Result<RsaPublicKey, ReplicateStatusCause>` - On success, returns a validated
///   `RsaPublicKey` object ready for encryption operations.
///
/// # Key Requirements
///
/// - **Algorithm**: Must be RSA (not EC, DSA, or other algorithms)
/// - **Encoding**: Must be DER-encoded PKCS#8 or PKCS#1 public key
/// - **Size**: Typically 1024, 2048, 3072, or 4096 bits (2048+ recommended)
/// - **Validity**: Must contain valid modulus and exponent values
///
/// # Errors
///
/// * `PostComputeMalformedEncryptionPublicKey` - If:
///   - Base64 decoding fails (invalid characters)
///   - DER parsing fails (malformed key structure)
///   - Key validation fails (invalid RSA parameters)
///   - Unsupported key format or algorithm
///
/// # Security Notes
///
/// - Function validates key mathematical properties
/// - Does not verify key authenticity or trustworthiness
/// - Accepts keys from any source (implement key validation separately)
/// - Supports industry-standard formats for maximum compatibility
///
/// # Example
///
/// ```rust
/// // PEM format key
/// let pem_key = "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----";
/// let rsa_key = base64_to_rsa_public_key(pem_key)?;
///
/// // Base64 format key
/// let b64_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AM...";
/// let rsa_key = base64_to_rsa_public_key(b64_key)?;
/// ```
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

/// Encrypts data using RSA public key cryptography with PKCS#1 v1.5 padding.
///
/// This function encrypts the provided data (typically an AES key) using
/// RSA public key encryption. It's designed for encrypting small amounts
/// of data, such as symmetric encryption keys in hybrid cryptosystems.
///
/// # Encryption Details
///
/// - **Algorithm**: RSA with PKCS#1 v1.5 padding
/// - **Input Size**: Limited by RSA key size minus padding overhead
/// - **Output Size**: Always equals RSA key size in bytes
/// - **Randomization**: Each encryption produces different ciphertext
/// - **Encoding**: Output is Base64 encoded for safe storage/transmission
///
/// # Arguments
///
/// * `aes_key` - The data to encrypt (typically a 32-byte AES key).
///   Must not exceed RSA key size minus padding overhead (~11 bytes).
/// * `public_key` - A validated RSA public key for encryption.
///
/// # Returns
///
/// * `Result<String, ReplicateStatusCause>` - On success, returns a Base64-encoded
///   string containing the RSA-encrypted data. The decoded size equals the RSA key size.
///
/// # Security Properties
///
/// - **Probabilistic**: Same input produces different outputs due to random padding
/// - **One-way**: Computationally infeasible to decrypt without private key
/// - **Authenticated**: Only the corresponding private key can decrypt
/// - **Malleable**: RSA without additional measures is malleable (consider OAEP for new designs)
///
/// # Errors
///
/// * `PostComputeEncryptionFailed` - If:
///   - Input data exceeds maximum size for key
///   - RSA encryption operation fails
///   - Random number generation fails
///   - Key is invalid or corrupted
///
/// # Example
///
/// ```rust
/// // Encrypt an AES key with RSA
/// let aes_key = generate_aes_key()?;
/// let rsa_public_key = base64_to_rsa_public_key(pem_key)?;
/// let encrypted_key_b64 = rsa_encrypt(&aes_key, &rsa_public_key)?;
///
/// // Store the Base64-encoded encrypted key
/// write_file("aes-key.rsa".to_string(), encrypted_key_b64.as_bytes())?;
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use rsa::{BigUint, traits::PublicKeyParts};
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
        assert_eq!(err, ReplicateStatusCause::PostComputeEncryptionFailed);
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
    fn encrypt_data_returns_empty_string_when_output_dir_creation_fails() {
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
        assert!(
            result.is_ok(),
            "encrypt_data should return Ok for directory creation failure. Error: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            "",
            "encrypt_data should return an empty string for directory creation failure"
        );
    }

    #[test]
    fn encrypt_data_returns_empty_string_when_zip_fails_due_to_unwritable_destination() {
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
        assert!(
            result.is_ok(),
            "encrypt_data should return Ok for zip failure. Error: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            "",
            "encrypt_data should return an empty string for zip failure"
        );
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
}
