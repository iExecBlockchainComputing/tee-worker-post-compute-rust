use crate::api::result_proxy_api_client::{ResultModel, ResultProxyApiClient};
use crate::compute::{
    computed_file::ComputedFile,
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use log::{debug, error, info};
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

#[automock]
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

pub struct Web2ResultService;

impl Web2ResultService {
    fn add_directory_to_zip<W: Write + io::Seek>(
        &self,
        zip: &mut ZipWriter<W>,
        source_dir: &Path,
        options: FileOptions<()>,
    ) -> Result<(), ReplicateStatusCause> {
        for entry in WalkDir::new(source_dir)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            debug!(
                "Adding file to zip [file:{}, zip:{}]",
                entry.path().display(),
                source_dir.display()
            );
            let path = entry.path();
            let relative = path.strip_prefix(source_dir).unwrap();
            if entry.file_type().is_file() && !entry.path_is_symlink() {
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
            }
        }
        Ok(())
    }
}

impl Web2ResultInterface for Web2ResultService {
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

        let result_path = zip_path; // eventually_encrypt_result(&zip_path) here
        self.upload_result(computed_file, &result_path)?; //TODO Share result link to beneficiary
        Ok(())
    }

    fn check_result_files_name(
        &self,
        task_id: &str,
        iexec_out_path: &str,
    ) -> Result<(), ReplicateStatusCause> {
        let mut has_long_filename = false;
        for entry in WalkDir::new(iexec_out_path) {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        if let Some(file_name) = entry.file_name().to_str() {
                            if file_name.len() > RESULT_FILE_NAME_MAX_LENGTH {
                                error!(
                                    "Too long result file name [chain_task_id:{}, file:{}]",
                                    task_id,
                                    entry.path().display()
                                );
                                has_long_filename = true;
                            }
                        }
                    }
                }
                Err(..) => {
                    error!("Can't check result files [chain_task_id: {}]", task_id);
                    return Err(ReplicateStatusCause::PostComputeFailedUnknownIssue);
                }
            }
        }
        if has_long_filename {
            return Err(ReplicateStatusCause::PostComputeTooLongResultFileName);
        }
        Ok(())
    }

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
        Ok(zip_path.to_string_lossy().to_string())
    }

    #[allow(clippy::wildcard_in_or_patterns)]
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
            IPFS_RESULT_STORAGE_PROVIDER | _ => {
                info!("Upload stage mode: IPFS_STORAGE");
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

    fn upload_to_ipfs_with_iexec_proxy(
        &self,
        computed_file: &ComputedFile,
        base_url: &str,
        token: &str,
        file_to_upload_path: &str,
    ) -> Result<String, ReplicateStatusCause> {
        let task_id = computed_file.task_id.as_ref().unwrap();

        let file_to_upload = fs::read(file_to_upload_path).map_err(|e| {
            error!(
            "Can't upload_to_ipfs_with_iexec_proxy (missing file_path to upload) [taskId:{}, fileToUploadPath:{}]: {}",
            task_id, file_to_upload_path, e
        );
            ReplicateStatusCause::PostComputeResultFileNotFound
        })?;

        let result_model = ResultModel {
            chain_task_id: task_id.clone(),
            deterministic_hash: computed_file.result_digest.as_ref().unwrap().clone(),
            enclave_signature: computed_file.enclave_signature.as_ref().unwrap().clone(),
            zip: file_to_upload,
            ..Default::default()
        };

        let client = ResultProxyApiClient::new(base_url);
        match client.upload_to_ipfs(token, &result_model) {
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
    use crate::compute::computed_file::ComputedFile;
    use mockall::predicate::*;
    use std::{
        fs::{self, File},
        io::Write,
        os::unix::fs::symlink,
    };
    use temp_env;
    use tempfile::TempDir;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    use zip::ZipArchive;

    fn create_test_computed_file(task_id: &str) -> ComputedFile {
        ComputedFile {
            task_id: Some(task_id.to_string()),
            result_digest: Some("0xabc123".to_string()),
            enclave_signature: Some("0xdef456".to_string()),
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
            .returning(|_, _| Ok(zip_path.to_string()));

        web2_result_mock
            .expect_upload_result()
            .with(eq(computed_file.clone()), eq(zip_path))
            .times(1)
            .returning(|_, _| Ok("https://ipfs.io/ipfs/QmHash".to_string()));

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
            .returning(|_, _| Ok(zip_path.to_string()));

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

        use zip::ZipArchive;
        let file = File::open(&zip_path).unwrap();
        let archive = ZipArchive::new(file).unwrap();
        let file_names: Vec<String> = archive.file_names().map(|s| s.to_string()).collect();
        assert!(file_names.contains(&"root.txt".to_string()));
        assert!(file_names.contains(&"subdir/sub.txt".to_string()));
        assert!(file_names.contains(&"subdir/nested/nested.txt".to_string()));
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
    }
    // endregion

    // region add_directory_to_zip
    fn verify_zip_contents(zip_path: &str, expected_files: &[&str]) {
        let file = File::open(zip_path).unwrap();
        let archive = ZipArchive::new(file).unwrap();

        let actual_files: Vec<String> = archive.file_names().map(|name| name.to_string()).collect();

        for expected_file in expected_files {
            assert!(
                actual_files.contains(&expected_file.to_string()),
                "Zip archive should contain file '{}', but found only: {:?}",
                expected_file,
                actual_files
            );
        }
    }

    #[test]
    fn zip_iexec_out_correctly_adds_files_to_zip() {
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

        let result = Web2ResultService.zip_iexec_out(
            source_dir.path().to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
        );
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        verify_zip_contents(&zip_path, &["file1.txt", "subdir/file2.txt"]);
    }

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

        let result = Web2ResultService.zip_iexec_out(
            source_dir.path().to_str().unwrap(),
            dest_dir.path().to_str().unwrap(),
        );
        assert!(result.is_ok());

        let zip_path = result.unwrap();
        let file = File::open(&zip_path).unwrap();
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
                    .returning(|_, _, _, _| Ok(expected_link.to_string()));

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
            task_id: Some("0x0".to_string()),
            result_digest: Some("0xdigest".to_string()),
            enclave_signature: Some("0xsignature".to_string()),
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
        File::create(source_dir.path().join("file2.txt"))
            .unwrap()
            .write_all(b"content2")
            .unwrap();

        let zip_path = dest_dir.path().join("test.zip");
        let zip_file = File::create(&zip_path).unwrap();
        let mut zip = ZipWriter::new(zip_file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        let result = Web2ResultService.add_directory_to_zip(&mut zip, source_dir.path(), options);
        assert!(result.is_ok());

        zip.finish().unwrap();
        let file = File::open(&zip_path).unwrap();
        let archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 2);
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

        let zip_path = dest_dir.path().join("test.zip");
        let zip_file = File::create(&zip_path).unwrap();
        let mut zip = ZipWriter::new(zip_file);
        let options = FileOptions::default();

        let result = Web2ResultService.add_directory_to_zip(&mut zip, source_dir.path(), options);
        assert!(result.is_ok());

        zip.finish().unwrap();
        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 1);
        assert!(archive.by_name("regular.txt").is_ok());
    }
    // endregion
}
