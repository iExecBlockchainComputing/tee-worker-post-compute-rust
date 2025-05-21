use crate::compute::errors::ReplicateStatusCause;
use crate::compute::utils::result_utils::{compute_web2_result_digest, compute_web3_result_digest};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Serialize, Deserialize)]
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
    let json_string = match fs::read_to_string(&computed_file_path) {
        Ok(content) => content,
        Err(e) => {
            error!(
                "Failed to read compute file [chain_task_id:{}, computed_file_dir:{}, error:{}]",
                chain_task_id, computed_file_dir, e
            );
            return Err(ReplicateStatusCause::PostComputeComputedFileNotFound);
        }
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    // region read_computed_file
    #[test]
    fn read_computed_file_returns_computed_file_when_valid_input() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        let file_path = dir.path().join("computed.json");

        let test_json =
            r#"{"deterministicOutputPath":"/iexec_out/result.txt","callbackData":"0xabc"}"#;
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();

        let result = read_computed_file("0x123", dir_path);
        assert!(result.is_ok());

        let computed_file = result.unwrap();
        assert_eq!(computed_file.task_id, Some("0x123".to_string()));
        assert_eq!(
            computed_file.deterministic_output_path,
            Some("/iexec_out/result.txt".to_string())
        );
        assert_eq!(computed_file.callback_data, Some("0xabc".to_string()));
    }

    #[test]
    fn read_computed_file_returns_error_when_chain_task_id_is_empty() {
        let result = read_computed_file("", "/tmp");

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeComputedFileNotFound
        );
    }

    #[test]
    fn read_computed_file_returns_error_when_computed_file_dir_is_empty() {
        let result = read_computed_file("0x123", "");

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeComputedFileNotFound
        );
    }

    #[test]
    fn read_computed_file_returns_error_when_computed_json_is_missing() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();

        let result = read_computed_file("0x123", dir_path);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeComputedFileNotFound
        );
    }

    #[test]
    fn read_computed_file_returns_error_when_computed_json_is_empty() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("computed.json");

        let test_json = "";
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();

        let result = read_computed_file("0x123", dir.path().to_str().unwrap());

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeComputedFileNotFound
        );
    }

    #[test]
    fn read_computed_file_returns_error_when_computed_json_is_invalid() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("computed.json");

        let test_json = r#"{"invalidJson":}"#;
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();

        let result = read_computed_file("0x123", dir.path().to_str().unwrap());

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeComputedFileNotFound
        );
    }
    // endregion

    // region build_result_digest_in_computed_file
    #[test]
    fn build_result_digest_in_computed_file_computes_web3_digest_when_is_callback_mode_is_true() {
        let mut computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: Some(
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
            deterministic_output_path: None,
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = build_result_digest_in_computed_file(&mut computed_file, true);

        assert!(result.is_ok());
        assert_eq!(
            computed_file.result_digest,
            Some("0xcb371be217faa47dab94e0d0ff0840c6cbf41645f0dc1a6ae3f34447155a76f3".to_string())
        );
    }

    #[test]
    fn build_result_digest_in_computed_file_computes_web2_digest_when_is_callback_mode_is_false() {
        let dir = tempdir().unwrap();
        let output_dir = dir.path().join("output");
        fs::create_dir(&output_dir).unwrap();

        let test_file_path = output_dir.join("test.txt");
        let mut file = fs::File::create(&test_file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let mut computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: Some(output_dir.to_str().unwrap().to_string()),
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = build_result_digest_in_computed_file(&mut computed_file, false);

        assert!(result.is_ok());
        assert!(computed_file.result_digest.is_some());
    }

    #[test]
    fn build_result_digest_in_computed_file_returns_error_when_result_digest_is_empty() {
        let mut computed_file = ComputedFile {
            task_id: Some("0x123".to_string()),
            callback_data: None,
            deterministic_output_path: Some("/non_existent_path".to_string()),
            result_digest: None,
            enclave_signature: None,
            error_message: None,
        };

        let result = build_result_digest_in_computed_file(&mut computed_file, false);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeResultDigestComputationFailed
        );
    }
    // endregion
}
