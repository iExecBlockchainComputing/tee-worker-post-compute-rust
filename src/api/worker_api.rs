use crate::compute::{
    computed_file::ComputedFile,
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use reqwest::{Error, blocking::Client, header::AUTHORIZATION};
use serde::Serialize;

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
/// use crate::compute::errors::ReplicateStatusCause;
///
/// let exit_message = ExitMessage::from(&ReplicateStatusCause::PostComputeInvalidTeeSignature);
/// ```
#[derive(Serialize, Debug)]
pub struct ExitMessage<'a> {
    pub cause: &'a ReplicateStatusCause,
}

impl<'a> From<&'a ReplicateStatusCause> for ExitMessage<'a> {
    fn from(cause: &'a ReplicateStatusCause) -> Self {
        Self { cause }
    }
}

/// Thin wrapper around a [`Client`] that knows how to reach the iExec worker API.
///
/// This client can be created directly with a base URL using [`new()`], or
/// configured from environment variables using [`from_env()`].
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

const DEFAULT_WORKER_HOST: &str = "worker:13100";

impl WorkerApiClient {
    pub fn new(base_url: &str) -> Self {
        WorkerApiClient {
            base_url: base_url.to_string(),
            client: Client::builder().build().unwrap(),
        }
    }

    /// Creates a new WorkerApiClient instance with configuration from environment variables.
    ///
    /// This method retrieves the worker host from the [`WORKER_HOST_ENV_VAR`] environment variable.
    /// If the variable is not set or empty, it defaults to `"worker:13100"`.
    ///
    /// # Returns
    ///
    /// * `WorkerApiClient` - A new client configured with the appropriate base URL
    ///
    /// # Example
    ///
    /// ```
    /// use crate::api::worker_api::WorkerApiClient;
    ///
    /// let client = WorkerApiClient::from_env();
    /// ```
    pub fn from_env() -> Self {
        let worker_host = get_env_var_or_error(
            TeeSessionEnvironmentVariable::WorkerHostEnvVar,
            ReplicateStatusCause::PostComputeWorkerAddressMissing,
        )
        .unwrap_or_else(|_| DEFAULT_WORKER_HOST.to_string());

        let base_url = format!("http://{}", &worker_host);
        Self::new(&base_url)
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
    /// use crate::compute::errors::ReplicateStatusCause;
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

    /// Sends the completed computed.json file to the worker host.
    ///
    /// This method transmits the computed file containing task results, signatures,
    /// and metadata to the worker API. The computed file is sent as JSON in the
    /// request body, allowing the worker to verify and process the computation results.
    ///
    /// # Arguments
    ///
    /// * `authorization` - The authorization token/challenge to validate the request on the worker side
    /// * `chain_task_id` - The blockchain task identifier associated with this computation
    /// * `computed_file` - The computed file containing results and signatures to be sent
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the computed file was successfully sent (HTTP 2xx response)
    /// * `Err(Error)` - If the request failed due to an HTTP error
    ///
    /// # Example
    ///
    /// ```
    /// use crate::api::worker_api::WorkerApiClient;
    /// use crate::compute::computed_file::ComputedFile;
    ///
    /// let client = WorkerApiClient::new("http://worker:13100");
    /// let computed_file = ComputedFile {
    ///     task_id: Some("0x123456789abcdef".to_string()),
    ///     result_digest: Some("0xdigest".to_string()),
    ///     enclave_signature: Some("0xsignature".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// match client.send_computed_file_to_host(
    ///     "Bearer auth_token",
    ///     "0x123456789abcdef",
    ///     &computed_file,
    /// ) {
    ///     Ok(()) => println!("Computed file sent successfully"),
    ///     Err(error) => eprintln!("Failed to send computed file: {}", error),
    /// }
    /// ```
    pub fn send_computed_file_to_host(
        &self,
        authorization: &str,
        chain_task_id: &str,
        computed_file: &ComputedFile,
    ) -> Result<(), Error> {
        let url = format!("{}/compute/post/{}/computed", self.base_url, chain_task_id);
        let response = self
            .client
            .post(&url)
            .header(AUTHORIZATION, authorization)
            .json(computed_file)
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
    use crate::compute::utils::env_utils::TeeSessionEnvironmentVariable::*;
    use serde_json::{json, to_string};
    use temp_env::with_vars;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    const CHALLENGE: &str = "challenge";
    const CHAIN_TASK_ID: &str = "0x123456789abcdef";

    // region ExitMessage()
    #[test]
    fn should_serialize_exit_message() {
        let causes = [
            (
                ReplicateStatusCause::PostComputeInvalidTeeSignature,
                "POST_COMPUTE_INVALID_TEE_SIGNATURE",
            ),
            (
                ReplicateStatusCause::PostComputeWorkerAddressMissing,
                "POST_COMPUTE_WORKER_ADDRESS_MISSING",
            ),
            (
                ReplicateStatusCause::PostComputeFailedUnknownIssue,
                "POST_COMPUTE_FAILED_UNKNOWN_ISSUE",
            ),
        ];

        for (cause, message) in causes {
            let exit_message = ExitMessage::from(&cause);
            let serialized = to_string(&exit_message).expect("Failed to serialize");
            let expected = format!("{{\"cause\":\"{message}\"}}");
            assert_eq!(serialized, expected);
        }
    }
    // endregion

    // region get_worker_api_client
    #[test]
    fn should_get_worker_api_client_with_env_var() {
        with_vars(
            vec![(WorkerHostEnvVar.name(), Some("custom-worker-host:9999"))],
            || {
                let client = WorkerApiClient::from_env();
                assert_eq!(client.base_url, "http://custom-worker-host:9999");
            },
        );
    }

    #[test]
    fn should_get_worker_api_client_without_env_var() {
        with_vars(vec![(WorkerHostEnvVar.name(), None::<&str>)], || {
            let client = WorkerApiClient::from_env();
            assert_eq!(client.base_url, format!("http://{}", DEFAULT_WORKER_HOST));
        });
    }
    // endregion

    // region send_exit_cause_for_post_compute_stage()
    #[tokio::test]
    async fn should_send_exit_cause() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let expected_body = json!({
            "cause": ReplicateStatusCause::PostComputeInvalidTeeSignature,
        });

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{}/exit", CHAIN_TASK_ID)))
            .and(header("Authorization", CHALLENGE))
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
                CHALLENGE,
                CHAIN_TASK_ID,
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
            .and(path(format!("/compute/post/{}/exit", CHAIN_TASK_ID)))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PostComputeFailedUnknownIssue);
            let worker_api_client = WorkerApiClient::new(&server_url);
            worker_api_client.send_exit_cause_for_post_compute_stage(
                CHALLENGE,
                CHAIN_TASK_ID,
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
    // endregion

    // region send_computed_file_to_host()
    #[tokio::test]
    async fn should_send_computed_file_successfully() {
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let computed_file = ComputedFile {
            task_id: Some(CHAIN_TASK_ID.to_string()),
            result_digest: Some("0xdigest".to_string()),
            enclave_signature: Some("0xsignature".to_string()),
            ..Default::default()
        };

        let expected_path = format!("/compute/post/{}/computed", CHAIN_TASK_ID);
        let expected_body = json!(computed_file);

        Mock::given(method("POST"))
            .and(path(expected_path.as_str()))
            .and(header("Authorization", CHALLENGE))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let client = WorkerApiClient::new(&server_uri);
            client.send_computed_file_to_host(CHALLENGE, CHAIN_TASK_ID, &computed_file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn should_fail_send_computed_file_on_server_error() {
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let computed_file = ComputedFile {
            task_id: Some(CHAIN_TASK_ID.to_string()),
            result_digest: Some("0xdigest".to_string()),
            enclave_signature: Some("0xsignature".to_string()),
            ..Default::default()
        };
        let expected_path = format!("/compute/post/{}/computed", CHAIN_TASK_ID);
        let expected_body = json!(computed_file);

        Mock::given(method("POST"))
            .and(path(expected_path.as_str()))
            .and(header("Authorization", CHALLENGE))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let client = WorkerApiClient::new(&server_uri);
            client.send_computed_file_to_host(CHALLENGE, CHAIN_TASK_ID, &computed_file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.status().unwrap(), 500);
        }
    }

    #[tokio::test]
    async fn should_handle_invalid_chain_task_id_in_url() {
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let invalid_chain_task_id = "invalidTaskId";
        let computed_file = ComputedFile {
            task_id: Some(invalid_chain_task_id.to_string()),
            ..Default::default()
        };

        let result = tokio::task::spawn_blocking(move || {
            let client = WorkerApiClient::new(&server_uri);
            client.send_computed_file_to_host(CHALLENGE, invalid_chain_task_id, &computed_file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err(), "Should fail with invalid chain task ID");
        if let Err(error) = result {
            assert_eq!(error.status().unwrap(), 404);
        }
    }

    #[tokio::test]
    async fn should_send_computed_file_with_minimal_data() {
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let computed_file = ComputedFile {
            task_id: Some(CHAIN_TASK_ID.to_string()),
            ..Default::default()
        };

        let expected_path = format!("/compute/post/{}/computed", CHAIN_TASK_ID);
        let expected_body = json!(computed_file);

        Mock::given(method("POST"))
            .and(path(expected_path.as_str()))
            .and(header("Authorization", CHALLENGE))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let client = WorkerApiClient::new(&server_uri);
            client.send_computed_file_to_host(CHALLENGE, CHAIN_TASK_ID, &computed_file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
    }
    // endregion
}
