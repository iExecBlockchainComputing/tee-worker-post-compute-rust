use super::{
    errors::{BaseErrorType, ComputeStage, ReplicateStatusCause},
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use log::error;
use reqwest::{blocking::Client, header::AUTHORIZATION};
use serde::Serialize;

/// Represents payload that can be sent to the worker API to report the outcome of the
/// pre‑compute stage.
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
/// * `cause` - A reference to the ReplicateStatusCause indicating why the pre-compute operation exited
///
/// # Example
///
/// ```rust
/// use shared::worker_api::ExitMessage;
/// use shared::errors::ReplicateStatusCause;
///
/// let exit_message = ExitMessage::from(&ReplicateStatusCause::PreComputeInvalidTeeSignature);
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
/// ```rust
/// use shared::worker_api::WorkerApiClient;
///
/// let client = WorkerApiClient::new("http://worker:13100");
/// ```
pub struct WorkerApiClient {
    pub base_url: String,
    pub client: Client,
}

const DEFAULT_WORKER_HOST: &str = "worker:13100";

impl WorkerApiClient {
    pub fn new(base_url: &str) -> Self {
        WorkerApiClient {
            base_url: base_url.to_string(),
            client: Client::new(),
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
    /// use shared::worker_api::WorkerApiClient;
    ///
    /// let client = WorkerApiClient::from_env();
    /// ```
    pub fn from_env() -> Self {
        let worker_host = get_env_var_or_error(
            TeeSessionEnvironmentVariable::WorkerHostEnvVar,
            ReplicateStatusCause::PreComputeWorkerAddressMissing,
        )
        .unwrap_or_else(|_| DEFAULT_WORKER_HOST.to_string());

        let base_url = format!("http://{worker_host}");
        Self::new(&base_url)
    }

    /// This generic method eliminates duplication between pre and post compute exit cause reporting.
    /// It automatically handles stage-specific URL paths and fallback errors.
    ///
    /// # Arguments
    ///
    /// * `stage` - The compute stage (PreCompute or PostCompute) for appropriate URL and error handling
    /// * `authorization` - The authorization token to use for the API request
    /// * `chain_task_id` - The chain task ID for which to report the exit cause
    /// * `exit_cause` - The exit cause to report
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the exit cause was successfully reported
    /// * `Err(ReplicateStatusCause)` - If the exit cause could not be reported, with stage-appropriate error
    ///
    /// # Errors
    ///
    /// This function will return stage-appropriate errors:
    /// * HTTP request failures → stage-specific unknown failure error
    /// * Non-success HTTP responses → stage-specific unknown failure error
    pub fn send_exit_cause_for_compute_stage(
        &self,
        stage: ComputeStage,
        authorization: &str,
        chain_task_id: &str,
        exit_cause: &ExitMessage,
    ) -> Result<(), ReplicateStatusCause> {
        // Build stage-specific URL path
        let stage_path = match stage {
            ComputeStage::PreCompute => "pre",
            ComputeStage::PostCompute => "post",
        };
        let url = format!(
            "{}/compute/{stage_path}/{chain_task_id}/exit",
            self.base_url
        );

        let fallback_error =
            ReplicateStatusCause::map_error(stage, BaseErrorType::FailedUnknownIssue);

        match self
            .client
            .post(&url)
            .header(AUTHORIZATION, authorization)
            .json(exit_cause)
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().unwrap_or_default();
                    error!(
                        "Failed to send exit cause to worker: [status:{status:?}, body:{body:#?}]"
                    );
                    Err(fallback_error)
                }
            }
            Err(e) => {
                error!("HTTP request failed when sending exit cause to {url}: {e:?}");
                Err(fallback_error)
            }
        }
    }

    /// Sends an exit cause for a pre-compute operation to the Worker API.
    ///
    /// This method reports the exit cause of a pre-compute operation to the Worker API,
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
    /// ```rust
    /// use shared::worker_api::{ExitMessage, WorkerApiClient};
    /// use shared::errors::ReplicateStatusCause;
    ///
    /// let client = WorkerApiClient::new("http://worker:13100");
    /// let exit_message = ExitMessage::from(&ReplicateStatusCause::PreComputeInvalidTeeSignature);
    ///
    /// match client.send_exit_cause_for_pre_compute_stage(
    ///     "authorization_token",
    ///     "0x123456789abcdef",
    ///     &exit_message,
    /// ) {
    ///     Ok(()) => println!("Exit cause reported successfully"),
    ///     Err(error) => eprintln!("Failed to report exit cause: {error}"),
    /// }
    /// ```
    pub fn send_exit_cause_for_pre_compute_stage(
        &self,
        authorization: &str,
        chain_task_id: &str,
        exit_cause: &ExitMessage,
    ) -> Result<(), ReplicateStatusCause> {
        self.send_exit_cause_for_compute_stage(
            ComputeStage::PreCompute,
            authorization,
            chain_task_id,
            exit_cause,
        )
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
    /// use shared::worker_api::{ExitMessage, WorkerApiClient};
    /// use shared::errors::ReplicateStatusCause;
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
    ) -> Result<(), ReplicateStatusCause> {
        self.send_exit_cause_for_compute_stage(
            ComputeStage::PostCompute,
            authorization,
            chain_task_id,
            exit_cause,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::env_utils::TeeSessionEnvironmentVariable::WorkerHostEnvVar;
    use serde_json::{json, to_string};
    use temp_env::with_vars;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    // region ExitMessage()
    #[test]
    fn exit_message_serializes_correctly_when_created_from_replicate_status_cause() {
        let causes = [
            (
                ReplicateStatusCause::PreComputeInvalidTeeSignature,
                "PRE_COMPUTE_INVALID_TEE_SIGNATURE",
            ),
            (
                ReplicateStatusCause::PreComputeWorkerAddressMissing,
                "PRE_COMPUTE_WORKER_ADDRESS_MISSING",
            ),
            (
                ReplicateStatusCause::PreComputeFailedUnknownIssue,
                "PRE_COMPUTE_FAILED_UNKNOWN_ISSUE",
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
    fn worker_api_client_uses_custom_host_when_env_var_set() {
        with_vars(
            vec![(WorkerHostEnvVar.name(), Some("custom-worker-host:9999"))],
            || {
                let client = WorkerApiClient::from_env();
                assert_eq!(client.base_url, "http://custom-worker-host:9999");
            },
        );
    }

    #[test]
    fn worker_api_client_uses_default_host_when_env_var_missing() {
        temp_env::with_vars_unset(vec![WorkerHostEnvVar.name()], || {
            let client = WorkerApiClient::from_env();
            assert_eq!(client.base_url, format!("http://{DEFAULT_WORKER_HOST}"));
        });
    }
    // endregion

    // region send_exit_cause_for_pre_compute_stage()
    const CHALLENGE: &str = "challenge";
    const CHAIN_TASK_ID: &str = "0x123456789abcdef";

    #[tokio::test]
    async fn send_exit_cause_for_pre_compute_stage_succeeds_when_server_returns_200() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let expected_body = json!({
            "cause": ReplicateStatusCause::PreComputeInvalidTeeSignature,
        });

        Mock::given(method("POST"))
            .and(path(format!("/compute/pre/{CHAIN_TASK_ID}/exit")))
            .and(header("Authorization", CHALLENGE))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PreComputeInvalidTeeSignature);
            let worker_api_client = WorkerApiClient::new(&server_url);
            worker_api_client.send_exit_cause_for_pre_compute_stage(
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
    async fn send_exit_cause_for_pre_compute_stage_returns_error_when_server_returns_503() {
        testing_logger::setup();
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path(format!("/compute/pre/{CHAIN_TASK_ID}/exit")))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PreComputeFailedUnknownIssue);
            let worker_api_client = WorkerApiClient::new(&server_url);
            let response = worker_api_client.send_exit_cause_for_pre_compute_stage(
                CHALLENGE,
                CHAIN_TASK_ID,
                &exit_message,
            );
            testing_logger::validate(|captured_logs| {
                let logs = captured_logs
                    .iter()
                    .filter(|c| c.level == log::Level::Error)
                    .collect::<Vec<&testing_logger::CapturedLog>>();

                assert_eq!(logs.len(), 1);
                assert_eq!(
                    logs[0].body,
                    "Failed to send exit cause to worker: [status:503, body:\"Service Unavailable\"]"
                );
            });
            response
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PreComputeFailedUnknownIssue)
        );
    }

    #[test]
    fn send_exit_cause_for_pre_compute_stage_returns_error_when_http_request_fails() {
        testing_logger::setup();
        let exit_message = ExitMessage::from(&ReplicateStatusCause::PreComputeFailedUnknownIssue);
        let worker_api_client = WorkerApiClient::new("wrong_url");
        let result = worker_api_client.send_exit_cause_for_pre_compute_stage(
            CHALLENGE,
            CHAIN_TASK_ID,
            &exit_message,
        );
        testing_logger::validate(|captured_logs| {
            let logs = captured_logs
                .iter()
                .filter(|c| c.level == log::Level::Error)
                .collect::<Vec<&testing_logger::CapturedLog>>();

            assert_eq!(logs.len(), 1);
            assert_eq!(
                logs[0].body,
                "HTTP request failed when sending exit cause to wrong_url/compute/pre/0x123456789abcdef/exit: reqwest::Error { kind: Builder, source: RelativeUrlWithoutBase }"
            );
        });
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PreComputeFailedUnknownIssue)
        );
    }
    // endregion

    // region send_exit_cause_for_post_compute_stage()

    #[tokio::test]
    async fn send_exit_cause_for_post_compute_stage_succeeds_when_server_returns_200() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let expected_body = json!({
            "cause": ReplicateStatusCause::PostComputeInvalidTeeSignature,
        });

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{CHAIN_TASK_ID}/exit")))
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
    async fn send_exit_cause_for_post_compute_stage_returns_error_when_server_returns_503() {
        testing_logger::setup();
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{CHAIN_TASK_ID}/exit")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PostComputeFailedUnknownIssue);
            let worker_api_client = WorkerApiClient::new(&server_url);
            let response = worker_api_client.send_exit_cause_for_post_compute_stage(
                CHALLENGE,
                CHAIN_TASK_ID,
                &exit_message,
            );
            testing_logger::validate(|captured_logs| {
                let logs = captured_logs
                    .iter()
                    .filter(|c| c.level == log::Level::Error)
                    .collect::<Vec<&testing_logger::CapturedLog>>();

                assert_eq!(logs.len(), 1);
                assert!(logs[0].body.contains("status:404"));
            });
            response
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeFailedUnknownIssue)
        );
    }

    // region Unified API Tests
    #[tokio::test]
    async fn send_exit_cause_for_compute_stage_succeeds_when_pre_compute_stage_provided() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let expected_body = json!({
            "cause": ReplicateStatusCause::PreComputeInvalidTeeSignature,
        });

        Mock::given(method("POST"))
            .and(path(format!("/compute/pre/{CHAIN_TASK_ID}/exit")))
            .and(header("Authorization", CHALLENGE))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&mock_server)
            .await;

        tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PreComputeInvalidTeeSignature);
            let worker_api_client = WorkerApiClient::new(&server_url);

            // Test both the unified method and the backward compatibility wrapper
            let unified_result = worker_api_client.send_exit_cause_for_compute_stage(
                ComputeStage::PreCompute,
                CHALLENGE,
                CHAIN_TASK_ID,
                &exit_message,
            );

            let wrapper_result = worker_api_client.send_exit_cause_for_pre_compute_stage(
                CHALLENGE,
                CHAIN_TASK_ID,
                &exit_message,
            );

            // Both should succeed and be equivalent
            assert!(unified_result.is_ok(), "Unified method should succeed");
            assert!(wrapper_result.is_ok(), "Wrapper method should succeed");
        })
        .await
        .expect("Task panicked");
    }

    #[tokio::test]
    async fn send_exit_cause_for_compute_stage_succeeds_when_post_compute_stage_provided() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        let expected_body = json!({
            "cause": ReplicateStatusCause::PostComputeInvalidTeeSignature,
        });

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{CHAIN_TASK_ID}/exit")))
            .and(header("Authorization", CHALLENGE))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&mock_server)
            .await;

        tokio::task::spawn_blocking(move || {
            let exit_message =
                ExitMessage::from(&ReplicateStatusCause::PostComputeInvalidTeeSignature);
            let worker_api_client = WorkerApiClient::new(&server_url);

            // Test both methods
            let unified_result = worker_api_client.send_exit_cause_for_compute_stage(
                ComputeStage::PostCompute,
                CHALLENGE,
                CHAIN_TASK_ID,
                &exit_message,
            );

            let wrapper_result = worker_api_client.send_exit_cause_for_post_compute_stage(
                CHALLENGE,
                CHAIN_TASK_ID,
                &exit_message,
            );

            assert!(unified_result.is_ok(), "Unified method should succeed");
            assert!(wrapper_result.is_ok(), "Wrapper method should succeed");
        })
        .await
        .expect("Task panicked");
    }

    #[test]
    fn send_exit_cause_for_compute_stage_maps_errors_correctly_when_http_request_fails() {
        let client = WorkerApiClient::new("http://invalid-url");
        let exit_message = ExitMessage::from(&ReplicateStatusCause::PreComputeFailedUnknownIssue);

        // Test that errors are mapped appropriately for each stage
        let pre_result = client.send_exit_cause_for_compute_stage(
            ComputeStage::PreCompute,
            "auth",
            "task-id",
            &exit_message,
        );

        let post_result = client.send_exit_cause_for_compute_stage(
            ComputeStage::PostCompute,
            "auth",
            "task-id",
            &exit_message,
        );

        // Both should fail with appropriate stage-specific errors
        assert_eq!(
            pre_result.unwrap_err(),
            ReplicateStatusCause::PreComputeFailedUnknownIssue
        );
        assert_eq!(
            post_result.unwrap_err(),
            ReplicateStatusCause::PostComputeFailedUnknownIssue
        );
    }

    #[test]
    fn send_exit_cause_wrapper_functions_produce_same_results_when_called_with_same_inputs() {
        // Ensure wrapper methods behave exactly like the unified implementation
        let client = WorkerApiClient::new("http://invalid-url");
        let exit_message = ExitMessage::from(&ReplicateStatusCause::PreComputeFailedUnknownIssue);

        let unified_result = client.send_exit_cause_for_compute_stage(
            ComputeStage::PreCompute,
            "auth",
            "task-id",
            &exit_message,
        );

        let wrapper_result =
            client.send_exit_cause_for_pre_compute_stage("auth", "task-id", &exit_message);

        // Both should produce the same error
        assert_eq!(unified_result.unwrap_err(), wrapper_result.unwrap_err());
    }
    // endregion
}
