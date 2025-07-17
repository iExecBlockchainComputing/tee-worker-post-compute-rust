use crate::api::worker_api::{ExitMessage, WorkerApiClient};
use crate::compute::{
    computed_file::{
        ComputedFile, build_result_digest_in_computed_file, read_computed_file, sign_computed_file,
    },
    errors::ReplicateStatusCause,
    signer::get_challenge,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
    web2_result::{Web2ResultInterface, Web2ResultService},
};
use log::{error, info};

/// Defines the interface for post-compute operations.
///
/// This trait encapsulates the core functionality needed for running post-compute operations.
/// Implementations of this trait can be used with the [`start_with_runner`] function to execute
/// the post-compute workflow.
pub trait PostComputeRunnerInterface {
    fn run_post_compute(&self, chain_task_id: &str) -> Result<(), ReplicateStatusCause>;
    fn get_challenge(&self, chain_task_id: &str) -> Result<String, ReplicateStatusCause>;
    fn send_exit_cause(
        &self,
        authorization: &str,
        chain_task_id: &str,
        exit_message: &ExitMessage,
    ) -> Result<(), ReplicateStatusCause>;
    fn send_computed_file(&self, computed_file: &ComputedFile) -> Result<(), ReplicateStatusCause>;
}

/// Production implementation of [`PostComputeRunnerInterface`]
///
/// This struct provides a concrete implementation of the [`PostComputeRunnerInterface`],
/// using the [`signer`] module for challenge generation and the owned [`WorkerApiClient`]
/// instance for error reporting.
pub struct DefaultPostComputeRunner {
    worker_api_client: WorkerApiClient,
}

impl DefaultPostComputeRunner {
    pub fn new() -> Self {
        Self {
            worker_api_client: WorkerApiClient::from_env(),
        }
    }
}

impl PostComputeRunnerInterface for DefaultPostComputeRunner {
    fn run_post_compute(&self, chain_task_id: &str) -> Result<(), ReplicateStatusCause> {
        let should_callback: bool = match get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageCallback,
            ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO: Update this error cause to a more specific one
        ) {
            Ok(value) => match value.parse::<bool>() {
                Ok(parsed_value) => parsed_value,
                Err(_) => {
                    error!(
                        "Failed to parse RESULT_STORAGE_CALLBACK environment variable as a boolean [callback_env_var:{}]",
                        value
                    );
                    return Err(ReplicateStatusCause::PostComputeFailedUnknownIssue);
                }
            },
            Err(e) => {
                error!("Failed to get RESULT_STORAGE_CALLBACK environment variable");
                return Err(e);
            }
        };

        let mut computed_file = read_computed_file(chain_task_id, "/iexec_out")?;
        build_result_digest_in_computed_file(&mut computed_file, should_callback)?;
        sign_computed_file(&mut computed_file)?;

        if !should_callback {
            Web2ResultService.encrypt_and_upload_result(&computed_file)?;
        }

        self.send_computed_file(&computed_file)?;

        Ok(())
    }

    fn get_challenge(&self, chain_task_id: &str) -> Result<String, ReplicateStatusCause> {
        get_challenge(chain_task_id)
    }

    fn send_exit_cause(
        &self,
        authorization: &str,
        chain_task_id: &str,
        exit_message: &ExitMessage,
    ) -> Result<(), ReplicateStatusCause> {
        self.worker_api_client
            .send_exit_cause_for_post_compute_stage(authorization, chain_task_id, exit_message)
    }

    fn send_computed_file(&self, computed_file: &ComputedFile) -> Result<(), ReplicateStatusCause> {
        info!(
            "send_computed_file stage started [computedFile:{:#?}]",
            &computed_file
        );
        let task_id = match computed_file.task_id.as_ref() {
            Some(id) => id,
            None => {
                error!("send_computed_file stage failed: task_id is missing in computed file");
                return Err(ReplicateStatusCause::PostComputeFailedUnknownIssue);
            }
        };
        let authorization = self.get_challenge(task_id)?;
        match self.worker_api_client.send_computed_file_to_host(
            &authorization,
            task_id,
            computed_file,
        ) {
            Ok(_) => {
                info!("send_computed_file stage completed");
                Ok(())
            }
            Err(_) => {
                error!("send_computed_file stage failed [task_id:{}]", task_id);
                Err(ReplicateStatusCause::PostComputeSendComputedFileFailed)
            }
        }
    }
}

/// Executes the post-compute workflow with a provided runner implementation.
///
/// This function orchestrates the full post-compute process, handling environment
/// variable checks, execution of the main post-compute logic, and error reporting.
/// It uses the provided runner to execute core operations and handles all the
/// workflow states and transitions.
///
/// # Arguments
///
/// * `runner` - An implementation of [`PostComputeRunnerInterface`] that will be used to execute the post-compute operations.
///
/// # Returns
///
/// * `i32` - An exit code indicating the result of the post-compute process:
///   - 0: Success - The post-compute completed successfully
///   - 1: Failure with reported cause - The post-compute failed but the cause was reported
///   - 2: Failure with unreported cause - The post-compute failed and the cause could not be reported
///   - 3: Failure due to missing taskID context - The post-compute could not start due to missing task ID
///
/// # Example
///
/// ```
/// use crate::app_runner::{start_with_runner, DefaultPostComputeRunner};
///
/// // Using the default runner
/// let exit_code = start_with_runner(&DefaultPostComputeRunner);
///
/// // Using a custom runner
/// let custom_runner = MyCustomRunner::new();
/// let exit_code = start_with_runner(&custom_runner);
/// ```
pub fn start_with_runner<R: PostComputeRunnerInterface>(runner: &R) -> i32 {
    println!("Tee worker post-compute started");
    let chain_task_id: String = match get_env_var_or_error(
        TeeSessionEnvironmentVariable::IexecTaskId,
        ReplicateStatusCause::PostComputeTaskIdMissing,
    ) {
        Ok(id) => id,
        Err(e) => {
            error!(
                "TEE post-compute cannot go further without taskID context [errorMessage:{:?}]",
                e
            );
            return 3; // Exit code for missing taskID context
        }
    };
    match runner.run_post_compute(&chain_task_id) {
        Ok(()) => {
            info!("TEE post-compute completed");
            0
        }
        Err(exit_cause) => {
            error!(
                "TEE post-compute failed with exit cause [errorMessage:{}]",
                &exit_cause
            );

            let authorization: String = match runner.get_challenge(&chain_task_id) {
                Ok(challenge) => challenge,
                Err(_) => {
                    error!(
                        "Failed to retrieve authorization [taskId:{}]",
                        &chain_task_id
                    );
                    return 2; // Exit code for unreported failure
                }
            };

            let exit_message = ExitMessage::from(&exit_cause);

            match runner.send_exit_cause(&authorization, &chain_task_id, &exit_message) {
                Ok(()) => 1, // Exit code for reported failure
                Err(_) => {
                    error!("Failed to report exit cause [exitCause:{}]", &exit_cause);
                    2 // Exit code for unreported failure
                }
            }
        }
    }
}

/// Starts the post-compute process using the [`DefaultPostComputeRunner`].
///
/// This is a convenience function that creates a [`DefaultPostComputeRunner`]
/// and passes it to [`start_with_runner`].
///
/// # Returns
///
/// * `i32` - An exit code indicating the result of the post-compute process.
///   See [`start_with_runner`] for details on the possible exit codes.
///
/// # Example
///
/// ```
/// use crate::app_runner::start;
///
/// let exit_code = start();
/// std::process::exit(exit_code);
/// ```
pub fn start() -> i32 {
    let runner = DefaultPostComputeRunner::new();
    start_with_runner(&runner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::{
        computed_file::ComputedFile, errors::ReplicateStatusCause,
        utils::env_utils::TeeSessionEnvironmentVariable,
    };
    use temp_env::with_vars;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    struct MockRunner {
        run_post_compute_success: bool,
        get_challenge_success: bool,
        send_exit_cause_success: bool,
        send_computed_file_success: bool,
        error_cause: Option<ReplicateStatusCause>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                run_post_compute_success: true,
                get_challenge_success: true,
                send_exit_cause_success: true,
                send_computed_file_success: true,
                error_cause: None,
            }
        }

        fn with_run_post_compute_failure(mut self, cause: Option<ReplicateStatusCause>) -> Self {
            self.run_post_compute_success = false;
            self.error_cause = cause;
            self
        }

        fn with_get_challenge_failure(mut self) -> Self {
            self.get_challenge_success = false;
            self
        }

        fn with_send_exit_cause_failure(mut self) -> Self {
            self.send_exit_cause_success = false;
            self
        }
    }

    impl PostComputeRunnerInterface for MockRunner {
        fn run_post_compute(&self, _chain_task_id: &str) -> Result<(), ReplicateStatusCause> {
            if self.run_post_compute_success {
                Ok(())
            } else if let Some(cause) = &self.error_cause {
                Err(cause.clone())
            } else {
                Err(ReplicateStatusCause::PostComputeFailedUnknownIssue)
            }
        }

        fn get_challenge(&self, _chain_task_id: &str) -> Result<String, ReplicateStatusCause> {
            if self.get_challenge_success {
                Ok("mock_challenge".to_string())
            } else {
                Err(ReplicateStatusCause::PostComputeTeeChallengePrivateKeyMissing)
            }
        }

        fn send_exit_cause(
            &self,
            _authorization: &str,
            _chain_task_id: &str,
            _exit_message: &ExitMessage,
        ) -> Result<(), ReplicateStatusCause> {
            if self.send_exit_cause_success {
                Ok(())
            } else {
                Err(ReplicateStatusCause::PostComputeFailedUnknownIssue)
            }
        }

        fn send_computed_file(
            &self,
            _exit_message: &ComputedFile,
        ) -> Result<(), ReplicateStatusCause> {
            if self.send_computed_file_success {
                Ok(())
            } else {
                Err(ReplicateStatusCause::PostComputeSendComputedFileFailed)
            }
        }
    }

    const TEST_TASK_ID: &str = "0x1234567890abcdef";

    // region start
    #[test]
    fn start_return_valid_exit_code_when_ran() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let result = start();
                assert!(
                    result == 0 || result == 1 || result == 2 || result == 3,
                    "start() should return a valid exit code"
                );
            },
        );
    }

    #[test]
    fn start_return_3_when_task_id_missing() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                None::<&str>,
            )],
            || {
                let runner = MockRunner::new();
                let result = start_with_runner(&runner);
                assert_eq!(result, 3, "Should return 3 when chain task ID is missing");
            },
        );
    }

    #[test]
    fn start_return_3_when_empty_task_id() {
        with_vars(
            vec![(TeeSessionEnvironmentVariable::IexecTaskId.name(), Some(""))],
            || {
                let runner = MockRunner::new();
                let result = start_with_runner(&runner);
                assert_eq!(result, 3, "Should return 3 when chain task ID is empty");
            },
        );
    }

    #[test]
    fn start_return_0_when_successful() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let runner = MockRunner::new();
                let result = start_with_runner(&runner);
                assert_eq!(result, 0, "Should return 0 on successful execution");
            },
        );
    }

    #[test]
    fn start_return_1_when_fail_with_known_cause() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let runner = MockRunner::new().with_run_post_compute_failure(Some(
                    ReplicateStatusCause::PostComputeInvalidTeeSignature,
                ));

                let result = start_with_runner(&runner);
                assert_eq!(
                    result, 1,
                    "Should return 1 when error is reported successfully"
                );
            },
        );
    }

    #[test]
    fn start_return_1_when_fail_with_unknown_cause() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let runner = MockRunner::new().with_run_post_compute_failure(None);

                let result = start_with_runner(&runner);
                assert_eq!(
                    result, 1,
                    "Should return 1 when unknown error is reported successfully"
                );
            },
        );
    }

    #[test]
    fn start_return_2_when_exit_cause_not_transmitted() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let runner = MockRunner::new()
                    .with_run_post_compute_failure(Some(
                        ReplicateStatusCause::PostComputeInvalidTeeSignature,
                    ))
                    .with_send_exit_cause_failure();

                let result = start_with_runner(&runner);
                assert_eq!(result, 2, "Should return 2 when error reporting fails");
            },
        );
    }

    #[test]
    fn start_return_2_when_get_challenge_fails() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let runner = MockRunner::new()
                    .with_run_post_compute_failure(Some(
                        ReplicateStatusCause::PostComputeInvalidTeeSignature,
                    ))
                    .with_get_challenge_failure();

                let result = start_with_runner(&runner);
                assert_eq!(result, 2, "Should return 2 when signer service fails");
            },
        );
    }
    // endregion

    // region send_computed_file
    const TEST_WORKER_ADDRESS: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_CHALLENGE: &str = "0x184afe6f0d4232c37623d203f4ec42b8281bd7a7f3655c66e65b23b7dbac266330db02efc9bc1bd682405cc1b8876806e086729e1ef7f880e5782aade94cd5741c";

    fn create_test_computed_file(task_id: Option<String>) -> ComputedFile {
        ComputedFile {
            task_id,
            result_digest: Some("0xresultdigest".to_string()),
            enclave_signature: Some("0xsignature".to_string()),
            deterministic_output_path: Some("/path/to/output".to_string()),
            callback_data: None,
            error_message: None,
        }
    }

    async fn send_compute_file_action(server_url: String) -> Result<(), ReplicateStatusCause> {
        tokio::task::spawn_blocking(move || {
            with_vars(
                vec![
                    (
                        TeeSessionEnvironmentVariable::SignWorkerAddress.name(),
                        Some(TEST_WORKER_ADDRESS),
                    ),
                    (
                        TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(),
                        Some(TEST_PRIVATE_KEY),
                    ),
                    (
                        TeeSessionEnvironmentVariable::WorkerHostEnvVar.name(),
                        Some(&server_url.replace("http://", "")),
                    ),
                ],
                || {
                    let runner = DefaultPostComputeRunner::new();
                    let computed_file = create_test_computed_file(Some(TEST_TASK_ID.to_string()));
                    runner.send_computed_file(&computed_file)
                },
            )
        })
        .await
        .expect("Task panicked")
    }

    #[tokio::test]
    async fn test_send_computed_file_success() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{}/computed", TEST_TASK_ID)))
            .and(header("Authorization", TEST_CHALLENGE))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = send_compute_file_action(server_url).await;
        assert!(result.is_ok(), "send_computed_file should succeed");
    }

    #[test]
    fn send_computed_file_fails_when_task_id_missing() {
        let runner = DefaultPostComputeRunner::new();
        let computed_file = create_test_computed_file(None);

        let result = runner.send_computed_file(&computed_file);

        assert!(result.is_err(), "Should fail when task_id is missing");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeFailedUnknownIssue,
            "Should return PostComputeFailedUnknownIssue when task_id is missing"
        );
    }

    #[test]
    fn send_computed_file_fails_when_get_challenge_fails() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::SignWorkerAddress.name(),
                None::<&str>,
            )],
            || {
                let runner = DefaultPostComputeRunner::new();
                let computed_file = create_test_computed_file(Some(TEST_TASK_ID.to_string()));
                let result = runner.send_computed_file(&computed_file);

                assert!(result.is_err(), "Should fail when get_challenge fails");
                assert_eq!(
                    result.unwrap_err(),
                    ReplicateStatusCause::PostComputeWorkerAddressMissing,
                    "Should propagate the error from get_challenge"
                );
            },
        );
    }

    #[tokio::test]
    async fn send_computed_file_fails_when_http_failrue() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{}/computed", TEST_TASK_ID)))
            .and(header("Authorization", TEST_CHALLENGE))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = send_compute_file_action(server_url).await;
        assert!(result.is_err(), "Should fail when HTTP request fails");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeSendComputedFileFailed,
            "Should return PostComputeSendComputedFileFailed when HTTP request fails"
        );
    }
    // endregion
}
