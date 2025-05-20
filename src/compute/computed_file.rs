use crate::compute::errors::ReplicateStatusCause;
use crate::compute::utils::result_utils::{compute_web2_result_digest, compute_web3_result_digest};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
pub struct ComputedFile {
    #[serde(rename = "deterministicOutputPath")]
    pub deterministic_output_path: Option<String>,

    #[serde(rename = "callbackData")]
    pub callback_data: Option<String>,

    #[serde(rename = "taskId")]
    pub task_id: Option<String>,

    #[serde(rename = "resultDigest")]
    pub result_digest: Option<String>,

    #[serde(rename = "enclaveSignature")]
    pub enclave_signature: Option<String>,

    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
}

pub fn read_computed_file(
    chain_task_id: &str,
    computed_file_dir: &str,
) -> Result<ComputedFile, ReplicateStatusCause> {
    info!("read_computed_file stage started");
    if chain_task_id.is_empty() {
        error!(
            "Failed to read compute file (empty chain_task_id) [chain_task_id:{}, computed_file_dir:{}]",
            chain_task_id, computed_file_dir
        );
        return Err(ReplicateStatusCause::PostComputeComputedFileNotFound);
    }

    if computed_file_dir.is_empty() {
        error!(
            "Failed to read compute file (empty computed_file_dir) [chain_task_id:{}, computed_file_dir:{}]",
            chain_task_id, computed_file_dir
        );
        return Err(ReplicateStatusCause::PostComputeComputedFileNotFound);
    }

    let computed_file_path = Path::new(computed_file_dir).join("computed.json");
    let json_string = fs::read_to_string(&computed_file_path).unwrap();

    if json_string.is_empty() {
        error!(
            "Failed to read compute file (invalid path) [chain_task_id:{}, computed_file_dir:{}]",
            chain_task_id, computed_file_dir
        );
        return Err(ReplicateStatusCause::PostComputeComputedFileNotFound);
    }

    match serde_json::from_str::<ComputedFile>(&json_string) {
        Ok(mut computed_file) => {
            computed_file.task_id = Some(chain_task_id.to_string());
            info!("read_computed_file stage completed");
            Ok(computed_file)
        }
        Err(_) => {
            error!(
                "Failed to read compute file [chain_task_id:{}, computed_file_dir:{}]",
                chain_task_id, computed_file_dir
            );
            Err(ReplicateStatusCause::PostComputeComputedFileNotFound)
        }
    }
}

pub fn build_result_digest_in_computed_file(
    computed_file: &mut ComputedFile,
    is_callback_mode: bool,
) -> Result<(), ReplicateStatusCause> {
    info!(
        "build_result_digest_in_computed_file stage started [mode:{}]",
        if is_callback_mode { "web3" } else { "web2" }
    );

    let result_digest = if is_callback_mode {
        compute_web3_result_digest(computed_file)
    } else {
        compute_web2_result_digest(computed_file)
    };

    if result_digest.is_empty() {
        return Err(ReplicateStatusCause::PostComputeResultDigestComputationFailed);
    }

    computed_file.result_digest = Some(result_digest.to_string());
    Ok(())
}
