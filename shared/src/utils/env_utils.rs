use crate::errors::ReplicateStatusCause;
use std::env;

pub enum TeeSessionEnvironmentVariable {
    // Common
    IexecTaskId,
    SignTeeChallengePrivateKey,
    SignWorkerAddress,
    WorkerHostEnvVar,

    // Pre-compute
    IexecDatasetChecksum,
    IexecDatasetFilename,
    IexecDatasetKey,
    IexecDatasetUrl,
    IexecInputFileUrlPrefix(usize),
    IexecInputFilesNumber,
    IexecPreComputeOut,
    IsDatasetRequired,

    // Post-compute
    ResultEncryption,
    ResultEncryptionPublicKey,
    ResultStorageCallback,
    ResultStorageProvider,
    ResultStorageProxy,
    ResultStorageToken,
}

impl TeeSessionEnvironmentVariable {
    pub fn name(&self) -> String {
        match self {
            TeeSessionEnvironmentVariable::IexecDatasetChecksum => {
                "IEXEC_DATASET_CHECKSUM".to_string()
            }
            TeeSessionEnvironmentVariable::IexecDatasetFilename => {
                "IEXEC_DATASET_FILENAME".to_string()
            }
            TeeSessionEnvironmentVariable::IexecDatasetKey => "IEXEC_DATASET_KEY".to_string(),
            TeeSessionEnvironmentVariable::IexecDatasetUrl => "IEXEC_DATASET_URL".to_string(),
            TeeSessionEnvironmentVariable::IexecInputFileUrlPrefix(index) => {
                format!("IEXEC_INPUT_FILE_URL_{index}")
            }
            TeeSessionEnvironmentVariable::IexecInputFilesNumber => {
                "IEXEC_INPUT_FILES_NUMBER".to_string()
            }
            TeeSessionEnvironmentVariable::IexecPreComputeOut => {
                "IEXEC_PRE_COMPUTE_OUT".to_string()
            }
            TeeSessionEnvironmentVariable::IexecTaskId => "IEXEC_TASK_ID".to_string(),
            TeeSessionEnvironmentVariable::IsDatasetRequired => "IS_DATASET_REQUIRED".to_string(),
            TeeSessionEnvironmentVariable::ResultEncryption => "RESULT_ENCRYPTION".to_string(),
            TeeSessionEnvironmentVariable::ResultEncryptionPublicKey => {
                "RESULT_ENCRYPTION_PUBLIC_KEY".to_string()
            }
            TeeSessionEnvironmentVariable::ResultStorageCallback => "RESULT_STORAGE_CALLBACK".to_string(),
            TeeSessionEnvironmentVariable::ResultStorageProvider => "RESULT_STORAGE_PROVIDER".to_string(),
            TeeSessionEnvironmentVariable::ResultStorageProxy => "RESULT_STORAGE_PROXY".to_string(),
            TeeSessionEnvironmentVariable::ResultStorageToken => "RESULT_STORAGE_TOKEN".to_string(),
            TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey => {
                "SIGN_TEE_CHALLENGE_PRIVATE_KEY".to_string()
            }
            TeeSessionEnvironmentVariable::SignWorkerAddress => "SIGN_WORKER_ADDRESS".to_string(),
            TeeSessionEnvironmentVariable::WorkerHostEnvVar => "WORKER_HOST_ENV_VAR".to_string(),
        }
    }
}

pub fn get_env_var_or_error(
    env_var: TeeSessionEnvironmentVariable,
    status_cause_if_missing: ReplicateStatusCause,
) -> Result<String, ReplicateStatusCause> {
    match get_env_var(env_var) {
        val if val.is_empty() => Err(status_cause_if_missing),
        val => Ok(val),
    }
}

pub fn get_env_var(env_var: TeeSessionEnvironmentVariable) -> String {
    match env::var(env_var.name()) {
        Ok(value) => value,
        _ => "".to_string(),
    }
}

