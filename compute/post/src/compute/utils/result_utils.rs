use crate::compute::utils::hash_utils::{concatenate_and_hash, sha256};
use crate::compute::{computed_file::ComputedFile, utils::hash_utils::keccak256};
use log::error;
use std::{
    fs::{self, DirEntry},
    io::Error,
    path::Path,
};

/// Computes the result digest for web3 tasks using keccak256 hashing.
///
/// This function is used for tasks that involve smart contract callbacks. It computes
/// a keccak256 hash of the callback data, which is the standard hashing algorithm
/// used in Ethereum and other EVM-compatible blockchains.
///
/// # Arguments
///
/// * `computed_file` - A reference to the [`ComputedFile`] containing the callback data
///
/// # Returns
///
/// * `String` - The keccak256 hash of the callback data in hexadecimal format (prefixed with "0x")
///   or an empty string if the computation fails
///
/// # Behavior
///
/// The function will return an empty string in the following cases:
/// * The task ID is missing from the computed file
/// * The callback data is missing, empty, or None
///
/// # Example
///
/// ```
/// use tee_worker_post_compute::compute::{computed_file::ComputedFile, utils::result_utils::compute_web3_result_digest};
///
/// let computed_file = ComputedFile {
///     task_id: Some("0x123".to_string()),
///     callback_data: Some("0x0000000000000000000000000000000000000000000000000000000000000001".to_string()),
///     deterministic_output_path: None,
///     result_digest: None,
///     enclave_signature: None,
///     error_message: None,
/// };
///
/// let digest = compute_web3_result_digest(&computed_file);
/// println!("Web3 result digest: {}", digest);
/// // Output: Web3 result digest: 0xcb371be217faa47dab94e0d0ff0840c6cbf41645f0dc1a6ae3f34447155a76f3
/// ```
pub fn compute_web3_result_digest(computed_file: &ComputedFile) -> String {
    if computed_file.task_id.is_none() {
        return "".to_string();
    }

    let callback_data = match &computed_file.callback_data {
        Some(data) if !data.is_empty() => data,
        _ => {
            error!(
                "Failed to compute_web3_result_digest (callback_data empty) [chainTaskId:{}]",
                computed_file.task_id.as_ref().unwrap()
            );
            return "".to_string();
        }
    };

    keccak256(callback_data)
}

/// Computes the result digest for web2 tasks using SHA256 hashing of output files.
///
/// This function is used for traditional tasks that produce file outputs. It computes
/// a SHA256-based digest of the files in the deterministic output path. The computation
/// method depends on whether the output is a single file or a directory tree.
///
/// # Arguments
///
/// * `computed_file` - A reference to the [`ComputedFile`] containing the output path information
///
/// # Returns
///
/// * `String` - The SHA256-based digest of the output files in hexadecimal format (prefixed with "0x")
///   or an empty string if the computation fails
///
/// # Behavior
///
/// The function will return an empty string in the following cases:
/// * The deterministic output path is missing, empty, or None
/// * The specified path does not exist on the filesystem
/// * File reading or hashing operations fail
///
/// The digest computation follows these rules:
/// * **Single file**: Direct SHA256 hash of the file content
/// * **Directory**: Combined hash of all files in the directory (sorted by filename for consistency)
///
/// # Example
///
/// ```
/// use tee_worker_post_compute::compute::{computed_file::ComputedFile, utils::result_utils::compute_web2_result_digest};
///
/// let computed_file = ComputedFile {
///     task_id: Some("0x123".to_string()),
///     callback_data: None,
///     deterministic_output_path: Some("/iexec_out/results".to_string()),
///     result_digest: None,
///     enclave_signature: None,
///     error_message: None,
/// };
///
/// let digest = compute_web2_result_digest(&computed_file);
/// println!("Web2 result digest: {}", digest);
/// ```
pub fn compute_web2_result_digest(computed_file: &ComputedFile) -> String {
    let host_deterministic_output_path = match &computed_file.deterministic_output_path {
        Some(path) => {
            if path.is_empty() {
                error!(
                    "Failed to compute_web2_result_digest (deterministic_output_path empty) [chainTaskId:{}]",
                    computed_file.task_id.as_ref().unwrap()
                );
                return "".to_string();
            } else {
                Path::new(path)
            }
        }
        _ => {
            return "".to_string();
        }
    };

    if !host_deterministic_output_path.exists() {
        error!(
            "Failed to compute_web2_result_digest (host_deterministic_output_path missing) [chainTaskId:{}]",
            computed_file.task_id.as_ref().unwrap()
        );
        return "".to_string();
    }

    get_file_tree_sha256(host_deterministic_output_path)
}

/// Computes the SHA256 hash of a single file's content.
///
/// This function reads the entire content of a file and computes its SHA256 hash.
/// It includes validation to ensure the file exists, is readable, and contains data.
///
/// # Arguments
///
/// * `file_path` - A reference to the [`Path`] of the file to hash
///
/// # Returns
///
/// * `String` - The SHA256 hash of the file content in hexadecimal format (prefixed with "0x")
///   or an empty string if the operation fails
///
/// # Behavior
///
/// The function will return an empty string in the following cases:
/// * The file does not exist or cannot be read
/// * The file is empty (contains no data)
/// * I/O errors occur during file reading
///
/// # Example
///
/// ```
/// use std::path::Path;
/// use tee_worker_post_compute::compute::utils::result_utils::sha256_file;
///
/// let file_path = Path::new("/path/to/result.txt");
/// let hash = sha256_file(&file_path);
///
/// if !hash.is_empty() {
///     println!("File hash: {}", hash);
/// } else {
///     println!("Failed to compute file hash");
/// }
/// ```
pub fn sha256_file(file_path: &Path) -> String {
    let data = match fs::read(file_path) {
        Ok(data) => {
            if data.is_empty() {
                error!(
                    "Null file content [file_path:{}]",
                    file_path.to_str().unwrap()
                );
                return "".to_string();
            } else {
                data
            }
        }
        Err(_) => {
            error!(
                "Failed to read file [file_path:{}]",
                file_path.to_str().unwrap()
            );
            return "".to_string();
        }
    };
    sha256(data)
}

/// Computes the SHA256-based digest of a file tree (directory or single file).
///
/// This function provides a unified way to compute digests for both single files and
/// directory trees. For directories, it ensures deterministic results by sorting
/// files alphabetically before computing the combined hash.
///
/// # Arguments
///
/// * `file_tree_path` - A reference to the [`Path`] of the file or directory to process
///
/// # Returns
///
/// * `String` - The computed digest in hexadecimal format (prefixed with "0x")
///   or an empty string if the operation fails
///
/// # Behavior
///
/// The function handles different input types as follows:
/// * **Single file**: Returns the SHA256 hash of the file content
/// * **Directory**: Computes SHA256 hash of each file, then combines all hashes using keccak256
/// * **Non-existent path**: Returns an empty string
/// * **Empty directory**: Returns an empty string
///
/// For directories, files are processed in alphabetical order to ensure consistent
/// results across different filesystems and environments.
///
/// # Example
///
/// ```
/// use std::path::Path;
/// use tee_worker_post_compute::compute::utils::result_utils::get_file_tree_sha256;
///
/// // Single file
/// let file_path = Path::new("/path/to/result.txt");
/// let file_digest = get_file_tree_sha256(&file_path);
///
/// // Directory tree
/// let dir_path = Path::new("/path/to/results/");
/// let tree_digest = get_file_tree_sha256(&dir_path);
///
/// println!("File digest: {}", file_digest);
/// println!("Tree digest: {}", tree_digest);
/// ```
pub fn get_file_tree_sha256(file_tree_path: &Path) -> String {
    if !file_tree_path.exists() {
        return "".to_string();
    }
    //file_tree_path points to a leaf, a single file
    if !file_tree_path.is_dir() {
        return sha256_file(file_tree_path);
    }
    //file_tree_path points to a tree, with multiple files
    let mut entries = match fs::read_dir(file_tree_path) {
        Ok(read_dir) => match read_dir.collect::<Result<Vec<DirEntry>, Error>>() {
            Ok(entries) => {
                if entries.is_empty() {
                    return "".to_string();
                } else {
                    entries
                }
            }
            Err(_) => return "".to_string(),
        },
        Err(_) => return "".to_string(),
    };
    // /!\ files MUST be sorted to ensure final concatenate_and_hash(..) is always the same (order matters)
    entries.sort_by_key(|entry| entry.path());

    let mut hashes_vec = Vec::new();
    entries.iter().for_each(|entry| {
        let path = entry.path();
        let hash = sha256_file(&path);
        hashes_vec.push(hash);
    });
    let hashes: Vec<&str> = hashes_vec.iter().map(|s| s.as_str()).collect();
    let hashes = hashes.as_slice();
    concatenate_and_hash(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn compute_web3_result_digest_returns_digest_when_valid_input() {
        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: Some(
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
            deterministic_output_path: None,
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web3_result_digest(&computed_file);

        assert_eq!(
            result,
            "0xcb371be217faa47dab94e0d0ff0840c6cbf41645f0dc1a6ae3f34447155a76f3"
        );
    }

    #[test]
    fn compute_web3_result_digest_returns_empty_string_when_task_id_is_none() {
        let computed_file = ComputedFile {
            task_id: None,
            callback_data: Some("0xdata".to_string()),
            deterministic_output_path: None,
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web3_result_digest(&computed_file);

        assert_eq!(result, "");
    }

    #[test]
    fn compute_web3_result_digest_returns_empty_string_when_callback_data_is_none() {
        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: None,
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web3_result_digest(&computed_file);

        assert_eq!(result, "");
    }

    #[test]
    fn compute_web3_result_digest_returns_empty_string_when_callback_data_is_empty() {
        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: Some("".to_string()),
            deterministic_output_path: None,
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web3_result_digest(&computed_file);

        assert_eq!(result, "");
    }

    #[test]
    fn compute_web2_result_digest_returns_digest_when_valid_input() {
        let dir = tempdir().unwrap();
        let output_dir = dir.path().join("output");
        fs::create_dir(&output_dir).unwrap();

        let test_file_path = output_dir.join("test.txt");
        let mut file = fs::File::create(&test_file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: Some(output_dir.to_str().unwrap().to_string()),
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web2_result_digest(&computed_file);

        assert!(!result.is_empty());
        assert!(result.starts_with("0x"));
    }

    #[test]
    fn compute_web2_result_digest_returns_empty_string_when_deterministic_output_path_is_none() {
        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: None,
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web2_result_digest(&computed_file);

        assert_eq!(result, "");
    }

    #[test]
    fn compute_web2_result_digest_returns_empty_string_when_deterministic_output_path_is_empty() {
        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: Some("".to_string()),
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web2_result_digest(&computed_file);

        assert_eq!(result, "");
    }

    #[test]
    fn compute_web2_result_digest_returns_empty_string_when_host_deterministic_output_path_does_not_exist()
     {
        let computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: Some("/non_existent_path".to_string()),
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = compute_web2_result_digest(&computed_file);

        assert_eq!(result, "");
    }

    #[test]
    fn sha256_file_returns_digest_when_valid_input() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let result = sha256_file(&file_path);

        assert!(!result.is_empty());
        assert!(result.starts_with("0x"));
    }

    #[test]
    fn sha256_file_returns_empty_string_when_file_is_empty() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("empty.txt");

        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"").unwrap();

        let result = sha256_file(&file_path);
        assert!(result.is_empty());
    }

    #[test]
    fn sha256_file_returns_empty_string_when_file_does_not_exist() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("nonexistent.txt");

        let result = sha256_file(&file_path);

        assert_eq!(result, "");
    }

    #[test]
    fn get_file_tree_sha256_returns_digest_when_input_is_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let result = get_file_tree_sha256(&file_path);

        assert!(!result.is_empty());
        assert!(result.starts_with("0x"));
    }

    #[test]
    fn get_file_tree_sha256_returns_digest_when_input_is_directory() {
        let dir = tempdir().unwrap();

        // Create some files in the directory
        let file_path1 = dir.path().join("file1.txt");
        let mut file1 = fs::File::create(&file_path1).unwrap();
        file1.write_all(b"content 1").unwrap();

        let file_path2 = dir.path().join("file2.txt");
        let mut file2 = fs::File::create(&file_path2).unwrap();
        file2.write_all(b"content 2").unwrap();

        let result = get_file_tree_sha256(dir.path());

        assert!(!result.is_empty());
        assert!(result.starts_with("0x"));
    }

    #[test]
    fn get_file_tree_sha256_returns_empty_string_when_path_does_not_exist() {
        let dir = tempdir().unwrap();
        let nonexistent_path = dir.path().join("nonexistent");

        let result = get_file_tree_sha256(&nonexistent_path);

        assert_eq!(result, "");
    }

    #[test]
    fn get_file_tree_sha256_returns_empty_string_when_directory_is_empty() {
        let dir = tempdir().unwrap();

        let result = get_file_tree_sha256(dir.path());

        assert_eq!(result, "");
    }
}
