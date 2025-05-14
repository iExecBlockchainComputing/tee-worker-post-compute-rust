use crate::post_compute::errors::ReplicateStatusCause;
use crate::utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error};
use reqwest::{Error, blocking::Client, header::AUTHORIZATION};
use serde::Serialize;
use std::sync::OnceLock;

const DEFAULT_WORKER_HOST: &str = "worker:13100";

/// Represents payload that can be sent to the worker API to report the outcome of the
/// post‑compute stage.
///
/// The JSON structure expected by the REST endpoint is:
/// ```json
/// {
///   "cause": "<ReplicateStatusCause as string>"
/// }
/// ```
///
/// # Arguments
///
/// * `cause` - A reference to the ReplicateStatusCause indicating why the post-compute operation exited
///
/// # Example
///
/// ```
/// use crate::api::worker_api::ExitMessage;
/// use crate::post_compute::errors::ReplicateStatusCause;
///
/// let exit_message = ExitMessage::from(&ReplicateStatusCause::PostComputeInvalidTeeSignature);
/// ```
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

/// Thin wrapper around a [`Client`] that knows how to reach the iExec worker API.
///
/// The client is shareable across threads thanks to the underlying [`OnceLock`].
///
/// # Example
///
/// ```
/// use crate::api::worker_api::WorkerApiClient;
///
/// let client = WorkerApiClient::new("http://worker:13100");
/// ```
pub struct WorkerApiClient {
    base_url: String,
    client: Client,
}

pub static WORKER_API_CLIENT: OnceLock<WorkerApiClient> = OnceLock::new();

/// Returns a reference to the global [`WorkerApiClient`] instance.
///
/// This function provides a convenient way to access a shared [`WorkerApiClient`] instance,
/// initializing it with the appropriate base URL on first access. The base URL is
/// determined from the [`WORKER_HOST`] environment variable, defaulting to `"worker:13100"`
/// if the variable is not set.
///
/// # Returns
///
/// * `&'static WorkerApiClient` - A reference to the singleton [`WorkerApiClient`] instance
///
/// # Example
///
/// ```
/// use crate::api::worker_api::get_worker_api_client;
///
/// let client = get_worker_api_client();
/// ```
pub fn get_worker_api_client() -> &'static WorkerApiClient {
    WORKER_API_CLIENT.get_or_init(|| {
        let worker_host = get_env_var_or_error(
            TeeSessionEnvironmentVariable::WORKER_HOST_ENV_VAR,
            ReplicateStatusCause::PostComputeWorkerAddressMissing,
        )
        .unwrap_or_else(|_| DEFAULT_WORKER_HOST.to_string());
        let base_url = format!("http://{}", &worker_host);
        WorkerApiClient::new(&base_url)
    })
}

impl WorkerApiClient {
    pub fn new(base_url: &str) -> Self {
        WorkerApiClient {
            base_url: base_url.to_string(),
            client: Client::builder().build().unwrap(),
        }
    }

    /// Sends an exit cause for a post-compute operation to the Worker API.
    ///
    /// This method reports the exit cause of a post-compute operation to the Worker API,
    /// which can be used for tracking and debugging purposes.
    ///
    /// # Arguments
    ///
    /// * `authorization` - The authorization token to use for the API request
    /// * `chain_task_id` - The chain task ID for which to report the exit cause
    /// * `exit_cause` - The exit cause to report
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the exit cause was successfully reported
    /// * `Err(Error)` - If the exit cause could not be reported due to an HTTP error
    ///
    /// # Errors
    ///
    /// This function will return an [`Error`] if the request could not be sent or
    /// the server responded with a non‑success status.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::api::worker_api::{ExitMessage, WorkerApiClient};
    /// use crate::post_compute::errors::ReplicateStatusCause;
    ///
    /// let client = WorkerApiClient::new("http://worker:13100");
    /// let exit_message = ExitMessage::from(&ReplicateStatusCause::PostComputeInvalidTeeSignature);
    ///
    /// match client.send_exit_cause_for_post_compute_stage(
    ///     "authorization_token",
    ///     "0x123456789abcdef",
    ///     &exit_message,
    /// ) {
    ///     Ok(()) => println!("Exit cause reported successfully"),
    ///     Err(error) => eprintln!("Failed to report exit cause: {}", error),
    /// }
    /// ```
    pub fn send_exit_cause_for_post_compute_stage(
        &self,
        authorization: &str,
        chain_task_id: &str,
        exit_cause: &ExitMessage,
    ) -> Result<(), Error> {
        let url = format!("{}/compute/post/{}/exit", self.base_url, chain_task_id);
        let response = self
            .client
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    #[tokio::test]
    async fn should_send_exit_cause() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let expected_body = json!({
            "cause": ReplicateStatusCause::PostComputeInvalidTeeSignature,
        });

        Mock::given(method("POST"))
            .and(path("/compute/post/0x0/exit"))
            .and(header("Authorization", "challenge"))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PostComputeInvalidTeeSignature);
            let worker_api_client = WorkerApiClient::new(&server_url);
            worker_api_client.send_exit_cause_for_post_compute_stage(
                "challenge",
                "0x0",
                &exit_message,
            )
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn should_not_send_exit_cause() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path("/compute/post/0x0/exit"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PostComputeFailedUnknownIssue);
            let worker_api_client = WorkerApiClient::new(&server_url);
            worker_api_client.send_exit_cause_for_post_compute_stage(
                "challenge",
                "0x0",
                &exit_message,
            )
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());

        if let Err(error) = result {
            assert_eq!(error.status().unwrap(), 404);
        }
    }
}
