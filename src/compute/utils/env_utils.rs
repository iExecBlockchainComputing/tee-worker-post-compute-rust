use crate::compute::errors::ReplicateStatusCause;
use std::env;

pub enum TeeSessionEnvironmentVariable {
    IexecTaskId,
    ResultEncryption,
    ResultEncryptionPublicKey,
    ResultStorageCallback,
    ResultStorageProvider,
    ResultStorageProxy,
    ResultStorageToken,
    SignTeeChallengePrivateKey,
    SignWorkerAddress,
    WorkerHostEnvVar,
}

impl TeeSessionEnvironmentVariable {
    pub fn name(&self) -> &str {
        match self {
            TeeSessionEnvironmentVariable::IexecTaskId => "IEXEC_TASK_ID",
            TeeSessionEnvironmentVariable::ResultEncryption => "RESULT_ENCRYPTION",
            TeeSessionEnvironmentVariable::ResultEncryptionPublicKey => {
                "RESULT_ENCRYPTION_PUBLIC_KEY"
            }
            TeeSessionEnvironmentVariable::ResultStorageCallback => "RESULT_STORAGE_CALLBACK",
            TeeSessionEnvironmentVariable::ResultStorageProvider => "RESULT_STORAGE_PROVIDER",
            TeeSessionEnvironmentVariable::ResultStorageProxy => "RESULT_STORAGE_PROXY",
            TeeSessionEnvironmentVariable::ResultStorageToken => "RESULT_STORAGE_TOKEN",
            TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey => {
                "SIGN_TEE_CHALLENGE_PRIVATE_KEY"
            }
            TeeSessionEnvironmentVariable::SignWorkerAddress => "SIGN_WORKER_ADDRESS",
            TeeSessionEnvironmentVariable::WorkerHostEnvVar => "WORKER_HOST",
        }
    }
}

pub fn get_env_var_or_error(
    env_var: TeeSessionEnvironmentVariable,
    status_cause_if_missing: ReplicateStatusCause,
) -> Result<String, ReplicateStatusCause> {
    match get_env_var(env_var) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(status_cause_if_missing),
    }
}

pub fn get_env_var(env_var: TeeSessionEnvironmentVariable) -> String {
    env::var(env_var.name())
}
