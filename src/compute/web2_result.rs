use crate::api::result_proxy_api_client::{ResultProxyApiClient, StreamingResultModel};
use crate::compute::{
    computed_file::ComputedFile,
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use log::{debug, error, info};
#[cfg(test)]
use mockall::automock;
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use zip::{ZipWriter, write::FileOptions};

const SLASH_POST_COMPUTE_TMP: &str = "/post-compute-tmp";
const RESULT_FILE_NAME_MAX_LENGTH: usize = 31;
const IPFS_RESULT_STORAGE_PROVIDER: &str = "ipfs";
const DROPBOX_RESULT_STORAGE_PROVIDER: &str = "dropbox";

/// Trait defining the interface for Web2 result processing operations.
///
/// This trait encapsulates all the operations needed to process computation results
/// for Web2 storage systems. It provides a clean abstraction that allows for easy
/// testing through mocking and potential alternative implementations.
///
/// The trait methods represent the main stages of the result processing workflow:
/// validation, compression, and upload. Each method can be used independently or
/// as part of the complete workflow provided by [`encrypt_and_upload_result`].
///
///
/// # Example Implementation
///
/// ```rust
/// use crate::compute::web2_result::Web2ResultInterface;
/// use crate::compute::computed_file::ComputedFile;
/// use crate::compute::errors::ReplicateStatusCause;
///
/// struct MockResultService;
///
/// impl Web2ResultInterface for MockResultService {
///     fn encrypt_and_upload_result(&self, computed_file: &ComputedFile) -> Result<(), ReplicateStatusCause> {
///         // Mock implementation for testing
///         Ok(())
///     }
///
///     // ... implement other methods
/// }
/// ```
#[cfg_attr(test, automock)]
pub trait Web2ResultInterface {
    fn encrypt_and_upload_result(
        &self,
        computed_file: &ComputedFile,
    ) -> Result<(), ReplicateStatusCause>;
    fn check_result_files_name(
        &self,
        task_id: &str,
        iexec_out_path: &str,
    ) -> Result<(), ReplicateStatusCause>;
    fn zip_iexec_out(
        &self,
        iexec_out_path: &str,
        save_in: &str,
    ) -> Result<String, ReplicateStatusCause>;
    fn upload_result(
        &self,
        computed_file: &ComputedFile,
        file_to_upload_path: &str,
    ) -> Result<String, ReplicateStatusCause>;
    fn upload_to_ipfs_with_iexec_proxy(
        &self,
        computed_file: &ComputedFile,
        base_url: &str,
        token: &str,
        file_to_upload_path: &str,
    ) -> Result<String, ReplicateStatusCause>;
}

/// Production implementation of [`Web2ResultInterface`].
///
/// [`Web2ResultService`] provides the concrete implementation of all Web2 result processing
/// operations. It handles the complete workflow from validation through upload, coordinating
/// between different components to ensure reliable result storage.
///
/// # Example
///
/// ```rust
/// use crate::compute::web2_result::{Web2ResultService, Web2ResultInterface};
/// use crate::compute::computed_file::ComputedFile;
///
/// let service = Web2ResultService;
/// let computed_file = ComputedFile {
///     task_id: Some(String::from("0x123")),
///     result_digest: Some(String::from("0xabc")),
///     enclave_signature: Some(String::from("0xdef")),
///     ..Default::default()
/// };
///
/// // Process and upload results
/// match service.encrypt_and_upload_result(&computed_file) {
///     Ok(()) => println!("Results uploaded successfully"),
///     Err(e) => eprintln!("Upload failed: {:?}", e),
/// }
/// ```
pub struct Web2ResultService;

impl Web2ResultService {
    /// Adds all files from a directory to a ZIP archive.
    ///
    /// This private method recursively traverses the source directory and adds all
    /// regular files to the provided ZIP writer. It maintains the directory structure
    /// within the archive and handles various file types appropriately.
    ///
    /// # File Handling
    ///
    /// The method:
    /// - Includes all regular files in the directory tree
    /// - Preserves the relative directory structure
    /// - Skips symbolic links to avoid potential security issues
    /// - Uses streaming I/O for memory efficiency with large files
    ///
    /// # Arguments
    ///
    /// * `zip` - Mutable reference to the ZIP writer
    /// * `source_dir` - Path to the source directory to compress
    /// * `options` - ZIP file options (compression method, etc.)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All files were successfully added to the archive
    /// * `Err(ReplicateStatusCause)` - An error occurred during compression
    ///
    /// # Errors
    ///
    /// This method will return [`ReplicateStatusCause::PostComputeOutFolderZipFailed`] if:
    /// - A file cannot be opened for reading
    /// - An I/O error occurs during file copying
    /// - The ZIP writer encounters an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs::File;
    /// use zip::{ZipWriter, write::FileOptions};
    ///
    /// let file = File::create("output.zip")?;
    /// let mut zip = ZipWriter::new(file);
    /// let options = FileOptions::default();
    ///
    /// service.add_directory_to_zip(&mut zip, Path::new("/path/to/source"), options)?;
    /// zip.finish()?;
    /// ```
    fn add_directory_to_zip<W: Write + io::Seek>(
        &self,
        zip: &mut ZipWriter<W>,
        source_dir: &Path,
        options: FileOptions<()>,
    ) -> Result<(), ReplicateStatusCause> {
        WalkDir::new(source_dir)
            .min_depth(1)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file() && !entry.path_is_symlink())
            .try_for_each(|entry| {
                debug!(
                    "Adding file to zip [file:{}, zip:{}]",
                    entry.path().display(),
                    source_dir.display()
                );

                let path = entry.path();
                let relative = path.strip_prefix(source_dir).unwrap();

                zip.start_file(relative.to_string_lossy(), options)
                    .map_err(|e| {
                        error!("Failed to add file to zip: {}", e);
                        ReplicateStatusCause::PostComputeOutFolderZipFailed
                    })?;

                let mut file = File::open(path).map_err(|e| {
                    error!("Failed to open file for zipping: {}", e);
                    ReplicateStatusCause::PostComputeOutFolderZipFailed
                })?;

                io::copy(&mut file, zip).map_err(|e| {
                    error!("Failed to copy file to zip: {}", e);
                    ReplicateStatusCause::PostComputeOutFolderZipFailed
                })?;

                Ok(())
            })
    }
}

impl Web2ResultInterface for Web2ResultService {
    /// Executes the complete result processing workflow.
    ///
    /// This is the main entry point for processing computation results. It orchestrates
    /// the entire workflow including validation, compression, and upload operations.
    /// The method name maintains compatibility with the Java implementation, though
    /// encryption is not yet implemented.
    ///
    /// # Arguments
    ///
    /// * `computed_file` - The [`ComputedFile`] containing task information and metadata
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The result was successfully processed and uploaded
    /// * `Err(ReplicateStatusCause)` - An error occurred during processing
    ///
    /// # Errors
    ///
    /// This method can return various errors depending on the failure point:
    /// - [`ReplicateStatusCause::PostComputeTooLongResultFileName`] - Filename validation failed
    /// - [`ReplicateStatusCause::PostComputeOutFolderZipFailed`] - Compression failed
    /// - [`ReplicateStatusCause::PostComputeIpfsUploadFailed`] - Upload failed
    fn encrypt_and_upload_result(
        &self,
        computed_file: &ComputedFile,
    ) -> Result<(), ReplicateStatusCause> {
        // check result file names are not too long
        self.check_result_files_name(computed_file.task_id.as_ref().unwrap(), "/iexec_out")?;

        // save zip file to the protected region /post-compute-tmp (temporarily)
        let zip_path = match self.zip_iexec_out("/iexec_out", SLASH_POST_COMPUTE_TMP) {
            Ok(path) => path,
            Err(..) => {
                error!("zipIexecOut stage failed");
                return Err(ReplicateStatusCause::PostComputeOutFolderZipFailed);
            }
        };

        let result_path = zip_path.clone(); // eventually_encrypt_result(&zip_path) here
        self.upload_result(computed_file, &result_path)?; //TODO Share result link to beneficiary

        // Clean up the temporary zip file
        if let Err(e) = fs::remove_file(&zip_path) {
            error!("Failed to remove temporary zip file {}: {}", zip_path, e);
            // We don't return an error here as the upload was successful
        };

        Ok(())
    }

    /// Validates that all result filenames meet the length requirements.
    ///
    /// This method checks all files in the specified directory to ensure their names
    /// don't exceed the maximum allowed length. This validation prevents issues with
    /// storage systems that have filename limitations.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task identifier for logging purposes
    /// * `iexec_out_path` - Path to the directory containing result files
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All filenames are within the allowed length
    /// * `Err(ReplicateStatusCause)` - At least one filename exceeds the limit
    fn check_result_files_name(
        &self,
        task_id: &str,
        iexec_out_path: &str,
    ) -> Result<(), ReplicateStatusCause> {
        if !Path::new(iexec_out_path).exists() {
            error!("Can't check result files [chain_task_id: {}]", task_id);
            return Err(ReplicateStatusCause::PostComputeFailedUnknownIssue);
        }

        let long_filenames: Vec<_> = WalkDir::new(iexec_out_path)
            .into_iter()
            .filter_map(|entry| entry.ok()) // Skip unreadable entries gracefully
            .filter(|entry| entry.file_type().is_file()) // Only process files
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .filter(|name| name.len() > RESULT_FILE_NAME_MAX_LENGTH)
                    .map(|name| (String::from(name), entry.path().to_path_buf()))
            })
            .collect();

        for (file_name, path) in &long_filenames {
            error!(
                "Too long result file name [chain_task_id:{}, file:{}, filename:{}]",
                task_id,
                path.display(),
                file_name
            );
        }

        if long_filenames.is_empty() {
            Ok(())
        } else {
            Err(ReplicateStatusCause::PostComputeTooLongResultFileName)
        }
    }

    /// Compresses the result directory into a ZIP archive.
    ///
    /// This method creates a compressed archive of all files in the specified directory.
    /// The compression uses the DEFLATE algorithm for optimal balance between compression
    /// ratio and processing speed.
    ///
    /// # Arguments
    ///
    /// * `iexec_out_path` - Path to the directory containing files to compress
    /// * `save_in` - Directory where the ZIP file should be saved
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Path to the created ZIP file
    /// * `Err(ReplicateStatusCause)` - Compression failed
    fn zip_iexec_out(
        &self,
        iexec_out_path: &str,
        save_in: &str,
    ) -> Result<String, ReplicateStatusCause> {
        let source_path = Path::new(iexec_out_path);
        let zip_file_name = "iexec_out.zip";
        let zip_path = PathBuf::from(save_in).join(zip_file_name);

        let file = File::create(&zip_path).map_err(|e| {
            error!("Failed to create zip file: {}", e);
            ReplicateStatusCause::PostComputeOutFolderZipFailed
        })?;

        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        self.add_directory_to_zip(&mut zip, source_path, options)?;
        zip.finish().map_err(|e| {
            error!("Failed to finish zip file: {}", e);
            ReplicateStatusCause::PostComputeOutFolderZipFailed
        })?;

        info!("Folder zipped [path:{}]", zip_path.display());
        Ok(String::from(zip_path.to_string_lossy()))
    }

    /// Uploads the compressed result to the configured storage provider.
    ///
    /// This method handles the upload process to the configured storage system.
    /// Currently supports IPFS through the iExec result proxy, with the potential
    /// for additional storage providers in the future.
    ///
    /// # Arguments
    ///
    /// * `computed_file` - The [`ComputedFile`] containing task metadata
    /// * `file_to_upload_path` - Path to the file that should be uploaded
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The storage link where the result was uploaded
    /// * `Err(ReplicateStatusCause)` - Upload failed
    fn upload_result(
        &self,
        computed_file: &ComputedFile,
        file_to_upload_path: &str,
    ) -> Result<String, ReplicateStatusCause> {
        info!("Upload stage started");
        let storage_provider = get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageProvider,
            ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO Define better error
        )?;
        let storage_proxy = get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageProxy,
            ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO Define better error
        )?;
        let storage_token = get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageToken,
            ReplicateStatusCause::PostComputeStorageTokenMissing,
        )?;
        let result_link = match storage_provider.as_str() {
            IPFS_RESULT_STORAGE_PROVIDER => {
                info!("Upload stage mode: IPFS_STORAGE");
                self.upload_to_ipfs_with_iexec_proxy(
                    computed_file,
                    &storage_proxy,
                    &storage_token,
                    file_to_upload_path,
                )?
            }
            DROPBOX_RESULT_STORAGE_PROVIDER => {
                error!(
                    "Dropbox storage provider is not supported [task_id:{}]",
                    computed_file.task_id.as_ref().unwrap()
                );
                return Err(ReplicateStatusCause::PostComputeDropboxUploadFailed);
            }
            _ => {
                info!(
                    "Unknown storage provider '{}', falling back to IPFS [task_id:{}]",
                    storage_provider,
                    computed_file.task_id.as_ref().unwrap()
                );
                self.upload_to_ipfs_with_iexec_proxy(
                    computed_file,
                    &storage_proxy,
                    &storage_token,
                    file_to_upload_path,
                )?
            }
        };

        info!("Upload stage completed");
        Ok(result_link)
    }

    /// Uploads a file to IPFS in streaming mode using the iExec result proxy service.
    ///
    /// This method specifically handles uploads to IPFS through the iExec result proxy.
    /// It creates a [`ResultModel`] with the necessary metadata and sends it to the
    /// proxy service for IPFS storage.
    ///
    /// # Arguments
    ///
    /// * `computed_file` - The [`ComputedFile`] containing task metadata
    /// * `base_url` - The base URL of the result proxy service
    /// * `token` - Authentication token for the result proxy
    /// * `file_to_upload_path` - Path to the file that should be uploaded
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The IPFS link where the result was stored
    /// * `Err(ReplicateStatusCause)` - Upload failed
    fn upload_to_ipfs_with_iexec_proxy(
        &self,
        computed_file: &ComputedFile,
        base_url: &str,
        token: &str,
        file_to_upload_path: &str,
    ) -> Result<String, ReplicateStatusCause> {

        let task_id = computed_file.task_id.as_ref().unwrap();

        let file = File::open(file_to_upload_path).map_err(|e| {
            error!(
                "Can't upload_to_ipfs_with_iexec_proxy (missing file_path to upload) [task_id:{}, file_to_upload_path:{}]: {}",
                task_id, file_to_upload_path, e
            );
            ReplicateStatusCause::PostComputeResultFileNotFound
        })?;

        let file_name = Path::new(file_to_upload_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        

        let streaming_result_model = StreamingResultModel {
            chain_task_id: task_id.clone(),
            determinist_hash: computed_file.result_digest.as_ref().unwrap().clone(),
            enclave_signature: computed_file.enclave_signature.as_ref().unwrap().clone(),
            zip_file_path: file_name.clone(),
            ..Default::default()
        };

        
        let client = ResultProxyApiClient::new(base_url);

        match client.upload_to_ipfs_streaming(token, &streaming_result_model, file) {
            Ok(ipfs_link) => Ok(ipfs_link),
            Err(e) => {
                error!(
                    "Can't upload_to_ipfs_with_iexec_proxy (result proxy issue) [task_id:{}]: {}",
                    task_id, e
                );
                Err(ReplicateStatusCause::PostComputeIpfsUploadFailed)
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::{eq, function};
    use std::os::unix::fs::symlink;
    use temp_env;
    use tempfile::TempDir;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    use zip::ZipArchive;

    fn create_test_computed_file(task_id: &str) -> ComputedFile {
        ComputedFile {
            task_id: Some(String::from(task_id)),
            result_digest: Some(String::from("0xabc123")),
            enclave_signature: Some(String::from("0xdef456")),
            ..Default::default()
        }
    }

    // region encrypt_and_upload_result
    fn run_encrypt_and_upload_result<T: Web2ResultInterface>(
        service: &T,
        computed_file: &ComputedFile,
    ) -> Result<(), ReplicateStatusCause> {
        service.check_result_files_name(computed_file.task_id.as_ref().unwrap(), "/iexec_out")?;
        let zip_path = match service.zip_iexec_out("/iexec_out", SLASH_POST_COMPUTE_TMP) {
            Ok(path) => path,
            Err(..) => {
                error!("zipIexecOut stage failed");
                return Err(ReplicateStatusCause::PostComputeOutFolderZipFailed);
            }
        };
        let result_path = zip_path;
        service.upload_result(computed_file, &result_path)?;
        Ok(())
    }

    #[test]
    fn encrypt_and_upload_result_completes_successfully_when_all_operations_succeed() {
        let mut web2_result_mock = MockWeb2ResultInterface::new();
        let computed_file = create_test_computed_file("0x123");
        let zip_path = "/post-compute-tmp/iexec_out.zip";

        web2_result_mock
            .expect_check_result_files_name()
            .with(eq("0x123"), eq("/iexec_out"))
            .times(1)
            .returning(|_, _| Ok(()));

        web2_result_mock
            .expect_zip_iexec_out()
            .with(eq("/iexec_out"), eq(SLASH_POST_COMPUTE_TMP))
            .times(1)
            .returning(move |_, _| Ok(String::from(zip_path)));

        web2_result_mock
            .expect_upload_result()
            .with(eq(computed_file.clone()), eq(zip_path))
            .times(1)
            .returning(|_, _| Ok(String::from("https://ipfs.io/ipfs/QmHash")));

        let result = run_encrypt_and_upload_result(&web2_result_mock, &computed_file);
        assert!(result.is_ok());
    }

    #[test]
    fn encrypt_and_upload_result_returns_zip_failed_error_when_zip_creation_fails() {
        let mut web2_result_mock = MockWeb2ResultInterface::new();
        let computed_file = create_test_computed_file("0x123");

        web2_result_mock
            .expect_check_result_files_name()
            .returning(|_, _| Ok(()));

        web2_result_mock
            .expect_zip_iexec_out()
            .returning(|_, _| Err(ReplicateStatusCause::PostComputeOutFolderZipFailed));

        let result = run_encrypt_and_upload_result(&web2_result_mock, &computed_file);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeOutFolderZipFailed
        );
    }

    #[test]
    fn encrypt_and_upload_result_returns_error_when_check_files_fails() {
        let mut web2_result_mock = MockWeb2ResultInterface::new();
        let computed_file = create_test_computed_file("0x123");

        web2_result_mock
            .expect_check_result_files_name()
            .returning(|_, _| Err(ReplicateStatusCause::PostComputeTooLongResultFileName));

        let result = run_encrypt_and_upload_result(&web2_result_mock, &computed_file);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeTooLongResultFileName
        );
    }

    #[test]
    fn encrypt_and_upload_result_returns_error_when_upload_fails() {
        let mut web2_result_mock = MockWeb2ResultInterface::new();
        let computed_file = create_test_computed_file("0x123");
        let zip_path = "/post-compute-tmp/iexec_out.zip";

        web2_result_mock
            .expect_check_result_files_name()
            .returning(|_, _| Ok(()));

        web2_result_mock
            .expect_zip_iexec_out()
            .returning(move |_, _| Ok(String::from(zip_path)));

        web2_result_mock
            .expect_upload_result()
            .returning(|_, _| Err(ReplicateStatusCause::PostComputeIpfsUploadFailed));

        let result = run_encrypt_and_upload_result(&web2_result_mock, &computed_file);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeIpfsUploadFailed
        );
    }
    // endregion

    // region check_result_files_name
    #[test]
    fn check_result_files_name_returns_ok_when_all_filenames_valid() {
        let temp_dir = TempDir::new().unwrap();
        let task_id = "0x0";

        File::create(temp_dir.path().join("result.txt")).unwrap();
        File::create(temp_dir.path().join("computed.json")).unwrap();
        File::create(temp_dir.path().join("output.log")).unwrap();

        let result =
            Web2ResultService.check_result_files_name(task_id, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn check_result_files_name_returns_ok_when_directory_empty() {
        let temp_dir = TempDir::new().unwrap();
        let task_id = "0x0";

        let result =
            Web2ResultService.check_result_files_name(task_id, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn check_result_files_name_returns_error_when_filename_too_long() {
        let temp_dir = TempDir::new().unwrap();
        let task_id = "0x0";

        let long_filename = "result-0x0000000000000000000.txt";
        assert!(long_filename.len() > RESULT_FILE_NAME_MAX_LENGTH);

        File::create(temp_dir.path().join(long_filename)).unwrap();
        File::create(temp_dir.path().join("computed.json")).unwrap();

        let result =
            Web2ResultService.check_result_files_name(task_id, temp_dir.path().to_str().unwrap());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeTooLongResultFileName
        );
    }

    #[test]
    fn check_result_files_name_returns_error_when_directory_not_found() {
        let task_id = "0x0";
        let non_existent_path = "/dummy/folder/that/doesnt/exist";

        let result = Web2ResultService.check_result_files_name(task_id, non_existent_path);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeFailedUnknownIssue
        );
    }

    #[test]
    fn check_result_files_name_handles_nested_directories_when_checking_files() {
        let temp_dir = TempDir::new().unwrap();
        let task_id = "0x0";

        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();

        File::create(temp_dir.path().join("root.txt")).unwrap();

        let long_filename = "this_is_a_very_long_filename_exceeding_limit.txt";
        File::create(sub_dir.join(long_filename)).unwrap();

        let result =
            Web2ResultService.check_result_files_name(task_id, temp_dir.path().to_str().unwrap());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeTooLongResultFileName
        );
    }

    #[test]
    fn check_result_files_name_returns_ok_when_max_length_filename() {
        let temp_dir = TempDir::new().unwrap();
        let task_id = "0x0";

        let max_length_filename = "a".repeat(RESULT_FILE_NAME_MAX_LENGTH);
        File::create(temp_dir.path().join(&max_length_filename)).unwrap();

        let result =
            Web2ResultService.check_result_files_name(task_id, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
    }
    // endregion

    // region zip_iexec_out
    #[test]
    fn zip_iexec_out_creates_zip_file_when_directory_has_content() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        File::create(source_dir.path().join("result.txt"))
            .unwrap()
            .write_all(b"test content")
            .unwrap();
        File::create(source_dir.path().join("data.json"))
            .unwrap()
            .write_all(b"{\"key\": \"value\"}")
            .unwrap();

        let result = Web2ResultService.zip_iexec_out(
            source_dir.path().to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
        );
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        assert!(PathBuf::from(&zip_path).exists());
        assert!(zip_path.ends_with("iexec_out.zip"));

        let metadata = fs::metadata(&zip_path).unwrap();
        assert!(metadata.len() > 0);
    }

    #[test]
    fn zip_iexec_out_creates_empty_zip_when_directory_is_empty() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        let result = Web2ResultService.zip_iexec_out(
            source_dir.path().to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
        );
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        assert!(PathBuf::from(&zip_path).exists());

        let metadata = fs::metadata(&zip_path).unwrap();
        assert!(metadata.len() > 0);
    }

    #[test]
    fn zip_iexec_out_maintains_structure_when_directory_has_subdirectories() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        let sub_dir = source_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let nested_dir = sub_dir.join("nested");
        fs::create_dir(&nested_dir).unwrap();

        File::create(source_dir.path().join("root.txt"))
            .unwrap()
            .write_all(b"root file")
            .unwrap();
        File::create(sub_dir.join("sub.txt"))
            .unwrap()
            .write_all(b"sub file")
            .unwrap();
        File::create(nested_dir.join("nested.txt"))
            .unwrap()
            .write_all(b"nested file")
            .unwrap();

        let result = Web2ResultService.zip_iexec_out(
            source_dir.path().to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
        );
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        assert!(PathBuf::from(&zip_path).exists());

        let file = File::open(&zip_path).unwrap();
        let archive = ZipArchive::new(file).unwrap();
        let file_names: Vec<String> = archive.file_names().map(String::from).collect();
        assert!(file_names.contains(&String::from("root.txt")));
        assert!(file_names.contains(&String::from("subdir/sub.txt")));
        assert!(file_names.contains(&String::from("subdir/nested/nested.txt")));
    }

    #[test]
    fn zip_iexec_out_returns_error_when_cannot_create_zip_file() {
        let source_dir = TempDir::new().unwrap();
        let invalid_dest = "/invalid/path/that/does/not/exist";

        let result =
            Web2ResultService.zip_iexec_out(source_dir.path().to_str().unwrap(), invalid_dest);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeOutFolderZipFailed
        );
    }

    #[test]
    #[cfg(unix)]
    fn zip_iexec_out_handles_special_files_when_zipping() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        File::create(source_dir.path().join(".hidden")).unwrap();
        File::create(source_dir.path().join("file with spaces.txt")).unwrap();
        File::create(source_dir.path().join("file-with-dashes.log")).unwrap();
        symlink("/tmp/target", source_dir.path().join("symlink")).unwrap();

        let result = Web2ResultService.zip_iexec_out(
            source_dir.path().to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
        );
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        let file = File::open(&zip_path).unwrap();
        let archive = ZipArchive::new(file).unwrap();
        let mut file_names: Vec<&str> = archive.file_names().collect();
        file_names.sort();
        let mut expected = vec![".hidden", "file with spaces.txt", "file-with-dashes.log"];
        expected.sort();
        assert_eq!(file_names, expected);
        assert_eq!(archive.len(), 3, "Zip should contain exactly 3 files");
    }
    // endregion

    // region add_directory_to_zip
    #[test]
    #[cfg(unix)]
    fn zip_iexec_out_skips_symlinks_via_add_directory() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        File::create(source_dir.path().join("regular.txt"))
            .unwrap()
            .write_all(b"content")
            .unwrap();
        symlink("/tmp/target", source_dir.path().join("symlink.txt")).unwrap();

        let result = Web2ResultService.add_directory_to_zip(
            &mut ZipWriter::new(File::create(dest_dir.path().join("test.zip")).unwrap()),
            source_dir.path(),
            FileOptions::default(),
        );
        assert!(result.is_ok());

        let file = File::open(dest_dir.path().join("test.zip")).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 1);
        assert!(archive.by_name("regular.txt").is_ok());
    }
    // endregion

    // region upload_result
    #[allow(clippy::wildcard_in_or_patterns)]
    fn run_upload_result<T: Web2ResultInterface>(
        service: &T,
        computed_file: &ComputedFile,
        file_to_upload_path: &str,
    ) -> Result<String, ReplicateStatusCause> {
        info!("Upload stage started");
        let storage_provider = get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageProvider,
            ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO Define better error
        )?;
        let storage_proxy = get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageProxy,
            ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO Define better error
        )?;
        let storage_token = get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageToken,
            ReplicateStatusCause::PostComputeStorageTokenMissing,
        )?;
        let result_link = match storage_provider.as_str() {
            IPFS_RESULT_STORAGE_PROVIDER | _ => {
                info!("Upload stage mode: IPFS_STORAGE");
                service.upload_to_ipfs_with_iexec_proxy(
                    computed_file,
                    &storage_proxy,
                    &storage_token,
                    file_to_upload_path,
                )?
            }
        };

        info!("Upload stage completed");
        Ok(result_link)
    }

    fn run_upload_result_ipfs(provider: &str) {
        temp_env::with_vars(
            vec![
                ("RESULT_STORAGE_PROVIDER", Some(provider)),
                ("RESULT_STORAGE_TOKEN", Some("storageToken")),
                ("RESULT_STORAGE_PROXY", Some("https://proxy.example.com")),
            ],
            || {
                let temp_dir = TempDir::new().unwrap();
                let file_path = temp_dir.path().join("test.zip");
                File::create(&file_path)
                    .unwrap()
                    .write_all(b"test content")
                    .unwrap();

                let mut mock_service = MockWeb2ResultInterface::new();
                let computed_file = create_test_computed_file("0x0");
                let expected_link = "ipfs://QmHash123";

                mock_service
                    .expect_upload_to_ipfs_with_iexec_proxy()
                    .with(
                        eq(computed_file.clone()),
                        eq("https://proxy.example.com"),
                        eq("storageToken"),
                        function(|path: &str| path.ends_with("test.zip")),
                    )
                    .times(1)
                    .returning(move |_, _, _, _| Ok(String::from(expected_link)));

                let result =
                    run_upload_result(&mock_service, &computed_file, file_path.to_str().unwrap());
                assert!(result.is_ok());
            },
        );
    }

    #[test]
    fn upload_result_returns_ipfs_link_when_using_ipfs_provider() {
        run_upload_result_ipfs("ipfs");
    }

    #[test]
    fn upload_result_uses_ipfs_when_provider_not_recognized() {
        run_upload_result_ipfs("unknown-provider");
    }

    fn run_upload_result_missing_env(missing_var: &str, expected_error: ReplicateStatusCause) {
        let mut envs = vec![
            ("RESULT_STORAGE_PROVIDER", Some("ipfs")),
            ("RESULT_STORAGE_TOKEN", Some("token")),
            ("RESULT_STORAGE_PROXY", Some("proxy")),
        ];
        envs.retain(|(k, _)| *k != missing_var);
        temp_env::with_vars(envs, || {
            let computed_file = create_test_computed_file("0x0");
            let file_path = "fileToUpload.zip";

            let result = Web2ResultService.upload_result(&computed_file, file_path);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), expected_error);
        });
    }

    #[test]
    fn upload_result_returns_error_when_storage_token_missing() {
        run_upload_result_missing_env(
            "RESULT_STORAGE_TOKEN",
            ReplicateStatusCause::PostComputeStorageTokenMissing,
        );
    }

    #[test]
    fn upload_result_returns_error_when_storage_proxy_missing() {
        run_upload_result_missing_env(
            "RESULT_STORAGE_PROXY",
            ReplicateStatusCause::PostComputeFailedUnknownIssue,
        );
    }

    #[test]
    fn upload_result_returns_error_when_storage_provider_missing() {
        run_upload_result_missing_env(
            "RESULT_STORAGE_PROVIDER",
            ReplicateStatusCause::PostComputeFailedUnknownIssue,
        );
    }
    // endregion

    // region upload_to_ipfs_with_iexec_proxy
    async fn actually_upload_to_ipfs_with_iexec_proxy(
        computed_file: ComputedFile,
        mock_server: MockServer,
        file_path: PathBuf,
    ) -> Result<String, ReplicateStatusCause> {
        tokio::task::spawn_blocking(move || {
            Web2ResultService.upload_to_ipfs_with_iexec_proxy(
                &computed_file,
                &mock_server.uri(),
                "test-token",
                file_path.to_str().unwrap(),
            )
        })
        .await
        .expect("Task panicked")
    }

    #[tokio::test]
    async fn upload_to_ipfs_with_iexec_proxy_returns_link_when_upload_succeeds() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("fileToUpload.zip");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test zip content").unwrap();

        let computed_file = ComputedFile {
            task_id: Some(String::from("0x0")),
            result_digest: Some(String::from("0xdigest")),
            enclave_signature: Some(String::from("0xsignature")),
            ..Default::default()
        };

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ipfs://QmHash123"))
            .mount(&mock_server)
            .await;

        let result =
            actually_upload_to_ipfs_with_iexec_proxy(computed_file, mock_server, file_path).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "ipfs://QmHash123");
    }

    #[test]
    fn upload_to_ipfs_with_iexec_proxy_returns_error_when_file_not_found() {
        let computed_file = create_test_computed_file("0x0");
        let non_existent_file = "/this/file/does/not/exist";
        let base_url = "http://localhost";
        let token = "IPFS_TOKEN";

        let result = Web2ResultService.upload_to_ipfs_with_iexec_proxy(
            &computed_file,
            base_url,
            token,
            non_existent_file,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeResultFileNotFound
        );
    }

    #[tokio::test]
    async fn upload_to_ipfs_with_iexec_proxy_returns_error_when_api_request_fails() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("fileToUpload.zip");
        File::create(&file_path)
            .unwrap()
            .write_all(b"test content")
            .unwrap();
        let computed_file = create_test_computed_file("0x0");

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let result =
            actually_upload_to_ipfs_with_iexec_proxy(computed_file, mock_server, file_path).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeIpfsUploadFailed
        );
    }
    // endregion

    // region add_directory_to_zip
    #[test]
    fn add_directory_to_zip_adds_files_correctly() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        File::create(source_dir.path().join("file1.txt"))
            .unwrap()
            .write_all(b"content1")
            .unwrap();

        let sub_dir = source_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        File::create(sub_dir.join("file2.txt"))
            .unwrap()
            .write_all(b"content2")
            .unwrap();

        let result = Web2ResultService.add_directory_to_zip(
            &mut ZipWriter::new(File::create(dest_dir.path().join("test.zip")).unwrap()),
            source_dir.path(),
            FileOptions::default(),
        );
        assert!(result.is_ok());

        let file = File::open(dest_dir.path().join("test.zip")).unwrap();
        let archive = ZipArchive::new(file).unwrap();
        let mut file_names: Vec<&str> = archive.file_names().collect();
        file_names.sort();
        let mut expected_file_names = vec!["file1.txt", "subdir/file2.txt"];
        expected_file_names.sort();
        assert_eq!(file_names, expected_file_names);
    }

    #[test]
    #[cfg(unix)]
    fn add_directory_to_zip_skips_symlinks() {
        let source_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        File::create(source_dir.path().join("regular.txt"))
            .unwrap()
            .write_all(b"content")
            .unwrap();
        symlink("/tmp/target", source_dir.path().join("symlink.txt")).unwrap();

        let result = Web2ResultService.add_directory_to_zip(
            &mut ZipWriter::new(File::create(dest_dir.path().join("test.zip")).unwrap()),
            source_dir.path(),
            FileOptions::default(),
        );
        assert!(result.is_ok());

        let file = File::open(dest_dir.path().join("test.zip")).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 1);
        assert!(archive.by_name("regular.txt").is_ok());
    }
    // endregion
}
