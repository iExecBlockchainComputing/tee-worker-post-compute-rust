use crate::compute::errors::ReplicateStatusCause;
use std::env;

pub enum TeeSessionEnvironmentVariable {
    IEXEC_TASK_ID,
    RESULT_STORAGE_CALLBACK,
    SIGN_TEE_CHALLENGE_PRIVATE_KEY,
    SIGN_WORKER_ADDRESS,
    WORKER_HOST_ENV_VAR,
}

impl TeeSessionEnvironmentVariable {
    pub fn name(&self) -> &str {
        match self {
            TeeSessionEnvironmentVariable::IEXEC_TASK_ID => "IEXEC_TASK_ID",
            TeeSessionEnvironmentVariable::RESULT_STORAGE_CALLBACK => "RESULT_STORAGE_CALLBACK",
            TeeSessionEnvironmentVariable::SIGN_TEE_CHALLENGE_PRIVATE_KEY => {
                "SIGN_TEE_CHALLENGE_PRIVATE_KEY"
            }
            TeeSessionEnvironmentVariable::SIGN_WORKER_ADDRESS => "SIGN_WORKER_ADDRESS",
            TeeSessionEnvironmentVariable::WORKER_HOST_ENV_VAR => "WORKER_HOST",
        }
    }
}

pub fn get_env_var_or_error(
    env_var: TeeSessionEnvironmentVariable,
    status_cause_if_missing: ReplicateStatusCause,
) -> Result<String, ReplicateStatusCause> {
    match env::var(env_var.name()) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(status_cause_if_missing),
    }
}
