use crate::compute::computed_file::ComputedFile;
use log::error;
use reqwest::{blocking::Client, header::AUTHORIZATION};
use shared::{errors::ReplicateStatusCause, worker_api::WorkerApiClient};

/// Thin wrapper around a [`Client`] that knows how to reach the iExec worker API.
///
/// This client can be created directly with a base URL using [`new()`], or
/// configured from environment variables using [`from_env()`].
///
/// # Example
///
/// ```
/// use tee_worker_post_compute::api::worker_api::ResultSenderApiClient;
///
/// let client = ResultSenderApiClient::new("http://worker:13100");
/// ```
pub struct ResultSenderApiClient {
    base_url: String,
    client: Client,
}

impl ResultSenderApiClient {
    /// Creates a new ResultSenderApiClient that shares the same configuration as a WorkerApiClient.
    ///
    /// This constructor allows reusing the base URL and HTTP client from an existing
    /// WorkerApiClient instance, ensuring consistent configuration across API clients.
    ///
    /// # Arguments
    ///
    /// * `worker_client` - The WorkerApiClient instance to copy configuration from
    ///
    /// # Returns
    ///
    /// * `ResultSenderApiClient` - A new client with the same base URL and HTTP client
    ///
    /// # Example
    ///
    /// ```
    /// use shared::worker_api::WorkerApiClient;
    /// use tee_worker_post_compute::api::result_sender_api_client::ResultSenderApiClient;
    ///
    /// let worker_client = WorkerApiClient::from_env();
    /// let result_sender = ResultSenderApiClient::new(&worker_client);
    /// ```
    pub fn new(worker_client: &WorkerApiClient) -> Self {
        ResultSenderApiClient {
            base_url: worker_client.base_url.to_string(),
            client: worker_client.client.clone(),
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
    /// use tee_worker_post_compute::api::worker_api::ResultSenderApiClient;
    /// use tee_worker_post_compute::compute::computed_file::ComputedFile;
    ///
    /// let client = ResultSenderApiClient::new("http://worker:13100");
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
    ) -> Result<(), ReplicateStatusCause> {
        let url = format!("{}/compute/post/{chain_task_id}/computed", self.base_url);
        match self
            .client
            .post(&url)
            .header(AUTHORIZATION, authorization)
            .json(computed_file)
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().unwrap_or_default();
                    error!(
                        "Failed to send computed file to worker: [status:{status:?}, body:{body:#?}]"
                    );
                    Err(ReplicateStatusCause::PostComputeSendComputedFileFailed)
                }
            }
            Err(e) => {
                error!("An error occured while sending computed file to worker: {e}");
                Err(ReplicateStatusCause::PostComputeSendComputedFileFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use shared::worker_api::WorkerApiClient;
    use testing_logger;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    const CHALLENGE: &str = "challenge";
    const CHAIN_TASK_ID: &str = "0x123456789abcdef";

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

        let expected_path = format!("/compute/post/{CHAIN_TASK_ID}/computed");
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
            let worker_client = WorkerApiClient::new(&server_uri);
            let client = ResultSenderApiClient::new(&worker_client);
            client.send_computed_file_to_host(CHALLENGE, CHAIN_TASK_ID, &computed_file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn should_fail_send_computed_file_on_server_error() {
        testing_logger::setup();
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let computed_file = ComputedFile {
            task_id: Some(CHAIN_TASK_ID.to_string()),
            result_digest: Some("0xdigest".to_string()),
            enclave_signature: Some("0xsignature".to_string()),
            ..Default::default()
        };
        let expected_path = format!("/compute/post/{CHAIN_TASK_ID}/computed");
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
            let worker_client = WorkerApiClient::new(&server_uri);
            let client = ResultSenderApiClient::new(&worker_client);
            let response =
                client.send_computed_file_to_host(CHALLENGE, CHAIN_TASK_ID, &computed_file);
            testing_logger::validate(|captured_logs| {
                let logs = captured_logs
                    .iter()
                    .filter(|c| c.level == log::Level::Error)
                    .collect::<Vec<&testing_logger::CapturedLog>>();

                assert_eq!(logs.len(), 1);
                assert!(logs[0].body.contains("status:500"));
            });
            response
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeSendComputedFileFailed)
        );
    }

    #[tokio::test]
    async fn should_handle_invalid_chain_task_id_in_url() {
        testing_logger::setup();
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let invalid_chain_task_id = "invalidTaskId";
        let computed_file = ComputedFile {
            task_id: Some(invalid_chain_task_id.to_string()),
            ..Default::default()
        };

        let result = tokio::task::spawn_blocking(move || {
            let worker_client = WorkerApiClient::new(&server_uri);
            let client = ResultSenderApiClient::new(&worker_client);
            let response =
                client.send_computed_file_to_host(CHALLENGE, invalid_chain_task_id, &computed_file);
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

        assert!(result.is_err(), "Should fail with invalid chain task ID");
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeSendComputedFileFailed)
        );
    }

    #[tokio::test]
    async fn should_send_computed_file_with_minimal_data() {
        let mock_server = MockServer::start().await;
        let server_uri = mock_server.uri();

        let computed_file = ComputedFile {
            task_id: Some(CHAIN_TASK_ID.to_string()),
            ..Default::default()
        };

        let expected_path = format!("/compute/post/{CHAIN_TASK_ID}/computed");
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
            let worker_client = WorkerApiClient::new(&server_uri);
            let client = ResultSenderApiClient::new(&worker_client);
            client.send_computed_file_to_host(CHALLENGE, CHAIN_TASK_ID, &computed_file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
    }
    // endregion
}
