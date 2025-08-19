use crate::compute::errors::ReplicateStatusCause;
use crate::compute::pre_compute_args::PreComputeArgs;
use crate::compute::utils::file_utils::{download_file, download_from_url, write_file};
use crate::compute::utils::hash_utils::{sha256, sha256_from_bytes};
use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use cbc::{
    Decryptor,
    cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7},
};
use log::{error, info};
#[cfg(test)]
use mockall::automock;
use multiaddr::Multiaddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

type Aes256CbcDec = Decryptor<Aes256>;
const IPFS_GATEWAYS: &[&str] = &[
    "https://ipfs-gateway.v8-bellecour.iex.ec",
    "https://gateway.ipfs.io",
    "https://gateway.pinata.cloud",
];
const AES_KEY_LENGTH: usize = 32;
const AES_IV_LENGTH: usize = 16;

#[cfg_attr(test, automock)]
pub trait PreComputeAppTrait {
    fn run(&mut self, chain_task_id: &str) -> Result<(), ReplicateStatusCause>;
    fn check_output_folder(&self) -> Result<(), ReplicateStatusCause>;
    fn download_input_files(&self) -> Result<(), ReplicateStatusCause>;
    fn download_encrypted_dataset(&self) -> Result<Vec<u8>, ReplicateStatusCause>;
    fn decrypt_dataset(&self, encrypted_content: &[u8]) -> Result<Vec<u8>, ReplicateStatusCause>;
    fn save_plain_dataset_file(&self, plain_content: &[u8]) -> Result<(), ReplicateStatusCause>;
}

pub struct PreComputeApp {
    chain_task_id: Option<String>,
    pre_compute_args: Option<PreComputeArgs>,
}

impl PreComputeApp {
    pub fn new() -> Self {
        PreComputeApp {
            chain_task_id: None,
            pre_compute_args: None,
        }
    }
}

impl PreComputeAppTrait for PreComputeApp {
    fn run(&mut self, chain_task_id: &str) -> Result<(), ReplicateStatusCause> {
        self.chain_task_id = Some(chain_task_id.to_string());
        self.pre_compute_args = Some(PreComputeArgs::read_args()?);
        self.check_output_folder()?;
        if self.pre_compute_args.as_ref().unwrap().is_dataset_required {
            let encrypted_content = self.download_encrypted_dataset()?;
            let plain_content = self.decrypt_dataset(&encrypted_content)?;
            self.save_plain_dataset_file(&plain_content)?;
        }
        self.download_input_files()?;
        Ok(())
    }

    /// Checks whether the output folder specified in `pre_compute_args` exists.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the output directory (`output_dir`) exists.
    /// - `Err(ReplicateStatusCause::PreComputeOutputFolderNotFound)` if the directory does not exist,
    ///   or if `pre_compute_args` is missing.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::pre_compute_app::PreComputeApp;
    ///
    /// let pre_compute_app = PreComputeApp::new();
    /// pre_compute_app.chain_task_id = Some("0x123456789abcdef");
    /// pre_compute_app.pre_compute_args = Some(PreComputeArgs::read_args()?);
    ///
    /// pre_compute_app.check_output_folder()?;
    /// ```
    fn check_output_folder(&self) -> Result<(), ReplicateStatusCause> {
        let output_dir = self
            .pre_compute_args
            .as_ref()
            .ok_or(ReplicateStatusCause::PreComputeOutputFolderNotFound)?
            .output_dir
            .clone();

        let chain_task_id = self.chain_task_id.as_deref().unwrap_or("unknown");

        info!("Checking output folder [chainTaskId:{chain_task_id}, path:{output_dir}]");

        if Path::new(&output_dir).is_dir() {
            return Ok(());
        }

        error!("Output folder not found [chainTaskId:{chain_task_id}, path:{output_dir}]");

        Err(ReplicateStatusCause::PreComputeOutputFolderNotFound)
    }

    /// Downloads the input files listed in `pre_compute_args.input_files` to the specified `output_dir`.
    ///
    /// Each URL is hashed (SHA-256) to generate a unique local filename.
    /// If any download fails, the function returns an error.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all files are downloaded successfully.
    /// - `Err(ReplicateStatusCause::PreComputeInputFileDownloadFailed)` if any file fails to download.
    ///
    /// # Panics
    ///
    /// This function panics if:
    /// - `pre_compute_args` is `None`.
    /// - `chain_task_id` is `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::pre_compute_app::PreComputeApp;
    ///
    /// let pre_compute_app = PreComputeApp::new();
    /// pre_compute_app.chain_task_id = Some("0x123456789abcdef");
    /// pre_compute_app.pre_compute_args = Some(PreComputeArgs::read_args()?);
    ///
    /// pre_compute_app.download_input_files()?;
    /// ```
    fn download_input_files(&self) -> Result<(), ReplicateStatusCause> {
        let args = self.pre_compute_args.as_ref().unwrap();
        let chain_task_id = self.chain_task_id.as_ref().unwrap();

        for url in &args.input_files {
            info!("Downloading input file [chainTaskId:{chain_task_id}, url:{url}]");

            let filename = sha256(url.to_string());
            if download_file(url, &args.output_dir, &filename).is_none() {
                return Err(ReplicateStatusCause::PreComputeInputFileDownloadFailed);
            }
        }
        Ok(())
    }

    /// Downloads the encrypted dataset file from a URL or IPFS multi-address, and verifies its checksum.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` containing the dataset's encrypted content if download and verification succeed.
    /// * `Err(ReplicateStatusCause::PreComputeDatasetDownloadFailed)` if the download fails or inputs are missing.
    /// * `Err(ReplicateStatusCause::PreComputeInvalidDatasetChecksum)` if checksum validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// let app = PreComputeApp::new();
    /// pre_compute_app.chain_task_id = Some("0x123456789abcdef");
    /// pre_compute_app.pre_compute_args = Some(PreComputeArgs::read_args()?);
    ///
    /// app.download_encrypted_dataset()?;
    /// ```
    fn download_encrypted_dataset(&self) -> Result<Vec<u8>, ReplicateStatusCause> {
        let args = self.pre_compute_args.as_ref().unwrap();
        let chain_task_id = self.chain_task_id.as_ref().unwrap();
        let encrypted_dataset_url = args.encrypted_dataset_url.as_ref().unwrap();

        info!(
            "Downloading encrypted dataset file [chainTaskId:{chain_task_id}, url:{encrypted_dataset_url}]",
        );

        let encrypted_content = if is_multi_address(encrypted_dataset_url) {
            IPFS_GATEWAYS.iter().find_map(|gateway| {
                let full_url = format!("{gateway}{encrypted_dataset_url}");
                info!("Attempting to download dataset from {full_url}");

                if let Some(content) = download_from_url(&full_url) {
                    info!("Successfully downloaded from {full_url}");
                    Some(content)
                } else {
                    info!("Failed to download from {full_url}");
                    None
                }
            })
        } else {
            download_from_url(encrypted_dataset_url)
        }
        .ok_or(ReplicateStatusCause::PreComputeDatasetDownloadFailed)?;

        info!("Checking encrypted dataset checksum [chainTaskId:{chain_task_id}]");
        let expected_checksum = args
            .encrypted_dataset_checksum
            .as_ref()
            .ok_or(ReplicateStatusCause::PreComputeDatasetDownloadFailed)?;
        let actual_checksum = sha256_from_bytes(&encrypted_content);

        if actual_checksum != *expected_checksum {
            error!(
                "Invalid dataset checksum [chainTaskId:{chain_task_id}, expected:{expected_checksum}, actual:{actual_checksum}]"
            );
            return Err(ReplicateStatusCause::PreComputeInvalidDatasetChecksum);
        }

        info!("Dataset downloaded and verified successfully.");
        Ok(encrypted_content)
    }

    /// Decrypts the provided encrypted dataset bytes using AES-CBC.
    ///
    /// The first 16 bytes of `encrypted_content` are treated as the IV.
    /// The rest is the ciphertext. The decryption key is decoded from a Base64 string.
    ///
    /// # Arguments
    ///
    /// * `encrypted_content` - Full encrypted dataset, including the IV prefix.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` containing the plaintext dataset if decryption succeeds.
    /// * `Err(ReplicateStatusCause::PreComputeDatasetDecryptionFailed)` if the key is missing, decoding fails, or decryption fails.
    ///
    /// # Example
    ///
    /// ```
    /// let app = PreComputeApp::new();
    /// pre_compute_app.chain_task_id = Some("0x123456789abcdef");
    /// pre_compute_app.pre_compute_args = Some(PreComputeArgs::read_args()?);
    ///
    /// let encrypted = vec![/* ... */];
    /// let decrypted = app.decrypt_dataset(&encrypted)?;
    /// ```
    fn decrypt_dataset(&self, encrypted_content: &[u8]) -> Result<Vec<u8>, ReplicateStatusCause> {
        let base64_key = self
            .pre_compute_args
            .as_ref()
            .unwrap()
            .encrypted_dataset_base64_key
            .as_ref()
            .unwrap();

        let key = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|_| ReplicateStatusCause::PreComputeDatasetDecryptionFailed)?;

        if encrypted_content.len() < AES_IV_LENGTH || key.len() != AES_KEY_LENGTH {
            return Err(ReplicateStatusCause::PreComputeDatasetDecryptionFailed);
        }

        let key_slice = &key[..AES_KEY_LENGTH];
        let iv_slice = &encrypted_content[..AES_IV_LENGTH];
        let ciphertext = &encrypted_content[AES_IV_LENGTH..];

        Aes256CbcDec::new(key_slice.into(), iv_slice.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| ReplicateStatusCause::PreComputeDatasetDecryptionFailed)
    }

    /// Saves the decrypted (plain) dataset to disk in the configured output directory.
    ///
    /// The output filename is taken from `pre_compute_args.plain_dataset_filename`.
    ///
    /// # Arguments
    ///
    /// * `plain_dataset` - The dataset content to write to a file.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the file is successfully saved.
    /// * `Err(ReplicateStatusCause::PreComputeSavingPlainDatasetFailed)` if the path is invalid or write fails.
    ///
    /// # Example
    ///
    /// ```
    /// let app = PreComputeApp::new();
    /// pre_compute_app.chain_task_id = Some("0x123456789abcdef");
    /// pre_compute_app.pre_compute_args = Some(PreComputeArgs::read_args()?);
    ///
    /// let plain_data = vec![/* ... */];
    /// app.save_plain_dataset_file(&plain_data)?;
    /// ```
    fn save_plain_dataset_file(&self, plain_dataset: &[u8]) -> Result<(), ReplicateStatusCause> {
        let chain_task_id = self.chain_task_id.as_ref().unwrap();
        let args = self.pre_compute_args.as_ref().unwrap();
        let output_dir = &args.output_dir;
        let plain_dataset_filename = args.plain_dataset_filename.as_ref().unwrap();

        let mut path = PathBuf::from(output_dir);
        path.push(plain_dataset_filename);

        info!(
            "Saving plain dataset file [chain_task_id:{chain_task_id}, path:{}]",
            path.display()
        );

        write_file(
            plain_dataset,
            &path,
            &format!("chainTaskId:{chain_task_id}"),
        )
        .map_err(|_| ReplicateStatusCause::PreComputeSavingPlainDatasetFailed)
    }
}

fn is_multi_address(uri: &str) -> bool {
    !uri.trim().is_empty() && Multiaddr::from_str(uri).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::pre_compute_args::PreComputeArgs;
    use std::fs;
    use tempfile::TempDir;
    use testcontainers::core::WaitFor;
    use testcontainers::runners::SyncRunner;
    use testcontainers::{Container, GenericImage};

    const CHAIN_TASK_ID: &str = "0x123456789abcdef";
    const DATASET_CHECKSUM: &str =
        "0x02a12ef127dcfbdb294a090c8f0b69a0ca30b7940fc36cabf971f488efd374d7";
    const ENCRYPTED_DATASET_KEY: &str = "ubA6H9emVPJT91/flYAmnKHC0phSV3cfuqsLxQfgow0=";
    const HTTP_DATASET_URL: &str = "https://raw.githubusercontent.com/iExecBlockchainComputing/tee-worker-pre-compute-rust/main/src/tests_resources/encrypted-data.bin";
    const IPFS_DATASET_URL: &str = "/ipfs/QmUVhChbLFiuzNK1g2GsWyWEiad7SXPqARnWzGumgziwEp";
    const PLAIN_DATA_FILE: &str = "plain-data.txt";

    fn get_pre_compute_app(
        chain_task_id: &str,
        urls: Vec<&str>,
        output_dir: &str,
    ) -> PreComputeApp {
        PreComputeApp {
            chain_task_id: Some(chain_task_id.to_string()),
            pre_compute_args: Some(PreComputeArgs {
                input_files: urls.into_iter().map(String::from).collect(),
                output_dir: output_dir.to_string(),
                is_dataset_required: true,
                encrypted_dataset_url: Some(HTTP_DATASET_URL.to_string()),
                encrypted_dataset_base64_key: Some(ENCRYPTED_DATASET_KEY.to_string()),
                encrypted_dataset_checksum: Some(DATASET_CHECKSUM.to_string()),
                plain_dataset_filename: Some(PLAIN_DATA_FILE.to_string()),
            }),
        }
    }

    fn start_container() -> (Container<GenericImage>, String, String) {
        let container = GenericImage::new("kennethreitz/httpbin", "latest")
            .with_wait_for(WaitFor::message_on_stderr("Listening at"))
            .start()
            .expect("Failed to start Httpbin");
        let port = container
            .get_host_port_ipv4(80)
            .expect("Could not get host port");

        let json_url = format!("http://127.0.0.1:{port}/json");
        let xml_url = format!("http://127.0.0.1:{port}/xml");

        (container, json_url, xml_url)
    }

    // region check_output_folder
    #[test]
    fn check_output_folder_returns_ok_with_valid_args() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().to_str().unwrap();

        let app = get_pre_compute_app(CHAIN_TASK_ID, vec![], output_path);

        let result = app.check_output_folder();
        assert!(result.is_ok());
    }

    #[test]
    fn check_output_folder_returns_err_with_invalid_file_path() {
        let non_existing_path = "/tmp/some_non_existing_output_dir_xyz_123".to_string();

        let app = get_pre_compute_app(CHAIN_TASK_ID, vec![], &non_existing_path);

        let result = app.check_output_folder();
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PreComputeOutputFolderNotFound)
        );
    }

    #[test]
    fn check_output_folder_returns_err_with_invalid_pre_compute_args() {
        let app = PreComputeApp {
            chain_task_id: Some(CHAIN_TASK_ID.to_string()),
            pre_compute_args: None,
        };

        let result = app.check_output_folder();
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PreComputeOutputFolderNotFound)
        );
    }
    // endregion

    // region download_input_files
    #[test]
    fn download_input_files_success_with_single_file() {
        let (_container, json_url, _) = start_container();

        let temp_dir = TempDir::new().unwrap();
        let app = get_pre_compute_app(
            CHAIN_TASK_ID,
            vec![&json_url],
            temp_dir.path().to_str().unwrap(),
        );

        let result = app.download_input_files();
        assert!(result.is_ok());

        let url_hash = sha256(json_url);
        let downloaded_file = temp_dir.path().join(url_hash);
        assert!(downloaded_file.exists());
    }

    #[test]
    fn download_input_files_success_with_multiple_files() {
        let (_container, json_url, xml_url) = start_container();

        let temp_dir = TempDir::new().unwrap();
        let app = get_pre_compute_app(
            CHAIN_TASK_ID,
            vec![&json_url, &xml_url],
            temp_dir.path().to_str().unwrap(),
        );

        let result = app.download_input_files();
        assert!(result.is_ok());

        let json_hash = sha256(json_url);
        let xml_hash = sha256(xml_url);

        assert!(temp_dir.path().join(json_hash).exists());
        assert!(temp_dir.path().join(xml_hash).exists());
    }

    #[test]
    fn test_download_failure_returns_error() {
        let temp_dir = TempDir::new().unwrap();
        let app = get_pre_compute_app(
            CHAIN_TASK_ID,
            vec!["https://invalid-url-that-should-fail.com/file.txt"],
            temp_dir.path().to_str().unwrap(),
        );

        let result = app.download_input_files();
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PreComputeInputFileDownloadFailed
        );
    }

    #[test]
    fn test_partial_failure_stops_on_first_error() {
        let (_container, json_url, xml_url) = start_container();

        let temp_dir = TempDir::new().unwrap();
        let app = get_pre_compute_app(
            CHAIN_TASK_ID,
            vec![
                &json_url,                                           // This should succeed
                "https://invalid-url-that-should-fail.com/file.txt", // This should fail
                &xml_url,                                            // This shouldn't be reached
            ],
            temp_dir.path().to_str().unwrap(),
        );

        let result = app.download_input_files();
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PreComputeInputFileDownloadFailed
        );

        // First file should be downloaded with SHA256 filename
        let json_hash = sha256(json_url);
        assert!(temp_dir.path().join(json_hash).exists());

        // Third file should NOT be downloaded (stopped on second failure)
        let xml_hash = sha256(xml_url);
        assert!(!temp_dir.path().join(xml_hash).exists());
    }
    // endregion

    // region download_encrypted_dataset
    #[test]
    fn download_encrypted_dataset_success_with_valid_dataset_url() {
        let app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");

        let actual_content = app.download_encrypted_dataset();
        let expected_content = download_from_url(HTTP_DATASET_URL)
            .ok_or(ReplicateStatusCause::PreComputeDatasetDownloadFailed);
        assert_eq!(actual_content, expected_content);
    }

    #[test]
    fn download_encrypted_dataset_failure_with_invalid_dataset_url() {
        let mut app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");
        if let Some(args) = &mut app.pre_compute_args {
            args.encrypted_dataset_url = Some("http://bad-url".to_string());
        }
        let actual_content = app.download_encrypted_dataset();
        assert_eq!(
            actual_content,
            Err(ReplicateStatusCause::PreComputeDatasetDownloadFailed)
        );
    }

    #[test]
    fn download_encrypted_dataset_success_with_valid_iexec_gateway() {
        let mut app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");
        if let Some(args) = &mut app.pre_compute_args {
            args.encrypted_dataset_url = Some(IPFS_DATASET_URL.to_string());
            args.encrypted_dataset_checksum = Some(
                "0x323b1637c7999942fbebfe5d42fe15dbfe93737577663afa0181938d7ad4a2ac".to_string(),
            )
        }
        let actual_content = app.download_encrypted_dataset();
        let expected_content = Ok("hello world !\n".as_bytes().to_vec());
        assert_eq!(actual_content, expected_content);
    }

    #[test]
    fn download_encrypted_dataset_failure_with_invalid_gateway() {
        let mut app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");
        if let Some(args) = &mut app.pre_compute_args {
            args.encrypted_dataset_url = Some("/ipfs/INVALID_IPFS_DATASET_URL".to_string());
        }
        let actual_content = app.download_encrypted_dataset();
        let expected_content = Err(ReplicateStatusCause::PreComputeDatasetDownloadFailed);
        assert_eq!(actual_content, expected_content);
    }

    #[test]
    fn download_encrypted_dataset_failure_with_invalid_dataset_checksum() {
        let mut app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");
        if let Some(args) = &mut app.pre_compute_args {
            args.encrypted_dataset_checksum = Some("invalid_dataset_checksum".to_string())
        }
        let actual_content = app.download_encrypted_dataset();
        let expected_content = Err(ReplicateStatusCause::PreComputeInvalidDatasetChecksum);
        assert_eq!(actual_content, expected_content);
    }
    // endregion

    // region decrypt_dataset
    #[test]
    fn decrypt_dataset_success_with_valid_dataset() {
        let app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");

        let encrypted_data = app.download_encrypted_dataset().unwrap();
        let expected_plain_data = Ok("Some very useful data.".as_bytes().to_vec());
        let actual_plain_data = app.decrypt_dataset(&encrypted_data);

        assert_eq!(actual_plain_data, expected_plain_data);
    }

    #[test]
    fn decrypt_dataset_failure_with_bad_key() {
        let mut app = get_pre_compute_app(CHAIN_TASK_ID, vec![], "");
        if let Some(args) = &mut app.pre_compute_args {
            args.encrypted_dataset_base64_key = Some("bad_key".to_string());
        }
        let encrypted_data = app.download_encrypted_dataset().unwrap();
        let actual_plain_data = app.decrypt_dataset(&encrypted_data);

        assert_eq!(
            actual_plain_data,
            Err(ReplicateStatusCause::PreComputeDatasetDecryptionFailed)
        );
    }
    // endregion

    // region save_plain_dataset_file
    #[test]
    fn save_plain_dataset_file_success_with_valid_output_dir() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().to_str().unwrap();

        let app = get_pre_compute_app(CHAIN_TASK_ID, vec![], output_path);

        let plain_dataset = "Some very useful data.".as_bytes().to_vec();
        let saved_dataset = app.save_plain_dataset_file(&plain_dataset);

        assert!(saved_dataset.is_ok());

        let expected_file_path = temp_dir.path().join(PLAIN_DATA_FILE);
        assert!(
            expected_file_path.exists(),
            "The dataset file should have been created."
        );

        let file_content =
            fs::read(&expected_file_path).expect("Should be able to read the created file");
        assert_eq!(
            file_content, plain_dataset,
            "File content should match the original data."
        );
    }

    #[test]
    fn save_plain_dataset_file_failure_with_invalid_output_dir() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().to_str().unwrap();

        let mut app = get_pre_compute_app(CHAIN_TASK_ID, vec![], output_path);
        if let Some(args) = &mut app.pre_compute_args {
            args.plain_dataset_filename = Some("/some-folder-123/not-found".to_string());
        }
        let plain_dataset = "Some very useful data.".as_bytes().to_vec();
        let saved_dataset = app.save_plain_dataset_file(&plain_dataset);

        assert_eq!(
            saved_dataset,
            Err(ReplicateStatusCause::PreComputeSavingPlainDatasetFailed)
        );
    }
    // endregion
}
