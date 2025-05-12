use crate::post_compute::errors::ReplicateStatusCause;
use crate::utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error};
use reqwest::Error;
use reqwest::blocking::ClientBuilder;
use reqwest::header::AUTHORIZATION;
use serde::Serialize;

const DEFAULT_WORKER_HOST: &str = "worker:13100";

#[derive(Serialize, Debug)]
pub struct ExitMessage<'a> {
    #[serde(rename = "cause")]
    pub cause: &'a ReplicateStatusCause,
}

impl<'a> From<&'a ReplicateStatusCause> for ExitMessage<'a> {
    fn from(cause: &'a ReplicateStatusCause) -> Self {
        Self { cause }
    }
}

pub fn send_exit_cause(
    authorization: &str,
    chain_task_id: &str,
    exit_cause: &ExitMessage,
) -> Result<(), Error> {
    let worker_host = get_env_var_or_error(
        TeeSessionEnvironmentVariable::WORKER_HOST_ENV_VAR,
        ReplicateStatusCause::PostComputeWorkerAddressMissing,
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "Failed to get worker host related environment variable: {}",
            e.exit_cause()
        );
        DEFAULT_WORKER_HOST.to_string()
    });
    let url = format!(
        "http://{}/compute/post/{}/exit",
        &worker_host, chain_task_id
    );

    let response = ClientBuilder::new()
        .build()?
        .post(&url)
        .header(AUTHORIZATION, authorization)
        .json(exit_cause)
        .send()?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(response.error_for_status().unwrap_err())
    }
}
