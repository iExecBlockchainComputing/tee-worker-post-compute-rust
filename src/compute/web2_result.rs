use crate::api::result_proxy_api_client::{ResultModel, ResultProxyApiClient};
use crate::compute::{
    computed_file::ComputedFile,
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use log::{debug, error, info};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
};
use walkdir::WalkDir;
use zip::{ZipWriter, write::FileOptions};

const SLASH_POST_COMPUTE_TMP: &str = "/post-compute-tmp";
const RESULT_FILE_NAME_MAX_LENGTH: usize = 31;
const IPFS_RESULT_STORAGE_PROVIDER: &str = "ipfs";

pub fn encrypt_and_upload_result(computed_file: &ComputedFile) -> Result<(), ReplicateStatusCause> {
    // check result file names are not too long
    check_result_files_name(computed_file.task_id.as_ref().unwrap(), "/iexec_out")?;

    // save zip file to the protected region /post-compute-tmp (temporarily)
    let zip_path = match zip_iexec_out("/iexec_out", SLASH_POST_COMPUTE_TMP) {
        Ok(path) => path,
        Err(..) => {
            error!("zipIexecOut stage failed");
            return Err(ReplicateStatusCause::PostComputeOutFolderZipFailed);
        }
    };

    let result_path = zip_path; // eventually_encrypt_result(&zip_path) here
    upload_result(computed_file, &result_path)?; //TODO Share result link to beneficiary
    Ok(())
}

fn check_result_files_name(
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

fn zip_iexec_out(iexec_out_path: &str, save_in: &str) -> Result<String, ReplicateStatusCause> {
    let source_path = Path::new(iexec_out_path);
    let zip_file_name = "iexec_out.zip";
    let zip_path = Path::new(save_in).join(zip_file_name);

    let file = File::create(&zip_path).map_err(|e| {
        error!("Failed to create zip file: {}", e);
        ReplicateStatusCause::PostComputeOutFolderZipFailed
    })?;

    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    add_directory_to_zip(&mut zip, source_path, options)?;
    zip.finish().map_err(|e| {
        error!("Failed to finish zip file: {}", e);
        ReplicateStatusCause::PostComputeOutFolderZipFailed
    })?;

    info!("Folder zipped [path:{}]", zip_path.display());
    Ok(zip_path.to_string_lossy().to_string())
}

fn add_directory_to_zip<W: Write + io::Seek>(
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

#[allow(clippy::wildcard_in_or_patterns)]
fn upload_result(
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
            upload_to_ipfs_with_iexec_proxy(
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
