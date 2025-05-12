use crate::post_compute::errors::{PostComputeError, ReplicateStatusCause};
use std::env;

pub enum TeeSessionEnvironmentVariable {
    IEXEC_TASK_ID,
    WORKER_HOST_ENV_VAR,
    SIGN_WORKER_ADDRESS,
    SIGN_TEE_CHALLENGE_PRIVATE_KEY,
}

impl TeeSessionEnvironmentVariable {
    pub fn name(&self) -> &str {
        match self {
            TeeSessionEnvironmentVariable::IEXEC_TASK_ID => "IEXEC_TASK_ID",
            TeeSessionEnvironmentVariable::WORKER_HOST_ENV_VAR => "WORKER_HOST",
            TeeSessionEnvironmentVariable::SIGN_WORKER_ADDRESS => "SIGN_WORKER_ADDRESS",
            TeeSessionEnvironmentVariable::SIGN_TEE_CHALLENGE_PRIVATE_KEY => {
                "SIGN_TEE_CHALLENGE_PRIVATE_KEY"
            }
        }
    }
}

pub fn get_env_var_or_error(
    env_var: TeeSessionEnvironmentVariable,
    status_cause_if_missing: ReplicateStatusCause,
) -> Result<String, PostComputeError> {
    match env::var(env_var.name()) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(PostComputeError::new(status_cause_if_missing)),
    }
}
