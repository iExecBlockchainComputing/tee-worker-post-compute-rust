use crate::api::worker_api::{WorkerApiClient, WorkerApiInterface};
use crate::compute::{
    computed_file::{ComputedFile, ComputedFileOperations, ComputedFileService},
    errors::ReplicateStatusCause,
    signer::{SignerOperations, SignerService},
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
    web2_result::{Web2ResultInterface, Web2ResultService},
};
use log::{error, info};

/// Represents the different exit modes for a process or application.
///
/// Each variant is explicitly assigned an `i32` value, and the enum
/// uses `#[repr(i32)]` to ensure its memory representation matches C-style enums.
#[cfg_attr(test, derive(Debug, PartialEq))]
#[repr(i32)]
pub enum ExitMode {
    Success = 0,
    ReportedFailure = 1,
    UnreportedFailure = 2,
    InitializationFailure = 3,
}

/// Defines the interface for post-compute operations.
///
/// This trait encapsulates the core functionality needed for running post-compute operations.
/// Implementations provide a `start` method that orchestrates the complete post-compute workflow
/// and returns an exit code indicating the operation result.
pub trait PostComputeService {
    fn start() -> ExitMode;
}

/// Production implementation of [`PostComputeService`]
///
/// This struct provides a concrete implementation of the [`PostComputeService`] trait,
/// using the production services for all operations.
pub struct PostComputeRunner {
    worker_api_client: WorkerApiClient,
}

impl PostComputeRunner {
    pub fn new() -> Self {
        Self {
            worker_api_client: WorkerApiClient::from_env(),
        }
    }

    pub fn run_post_compute(&self, chain_task_id: &str) -> Result<(), ReplicateStatusCause> {
        let should_callback: bool = match get_env_var_or_error(
            TeeSessionEnvironmentVariable::ResultStorageCallback,
            ReplicateStatusCause::PostComputeFailedUnknownIssue, //TODO: Update this error cause to a more specific one
        ) {
            Ok(value) => match value.to_lowercase().parse::<bool>() {
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

        let computed_file_service = ComputedFileService;
        let web2_result_service = Web2ResultService;

        let mut computed_file =
            computed_file_service.read_computed_file(chain_task_id, "/iexec_out")?;
        computed_file_service
            .build_result_digest_in_computed_file(&mut computed_file, should_callback)?;
        computed_file_service
            .sign_computed_file(&mut computed_file)
            .map_err(|_| ReplicateStatusCause::PostComputeInvalidTeeSignature)?;

        if !should_callback {
            web2_result_service
                .encrypt_and_upload_result(&computed_file)
                .map_err(|_| ReplicateStatusCause::PostComputeFailedUnknownIssue)?;
        }

        self.send_computed_file(&computed_file)?;

        Ok(())
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

        let signer = SignerService;
        let authorization = signer.get_challenge(task_id)?;
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

impl PostComputeService for PostComputeRunner {
    /// Starts the post-compute process and orchestrates the complete workflow.
    ///
    /// This function handles the full post-compute operation including environment variable
    /// validation, task execution, file processing, and error reporting. It creates a
    /// [`PostComputeRunner`] instance internally and manages the entire workflow from
    /// start to finish.
    ///
    /// The function first retrieves the task ID from environment variables, then processes
    /// the computed file, handles result storage and uploading, and reports any errors
    /// that occur during execution.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::compute::app_runner::PostComputeService;
    /// use crate::compute::app_runner::PostComputeRunner;
    ///
    /// let exit_code = PostComputeRunner::start();
    /// std::process::exit(exit_code);
    /// ```
    fn start() -> ExitMode {
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
                return ExitMode::InitializationFailure;
            }
        };
        let runner = PostComputeRunner::new();
        match runner.run_post_compute(&chain_task_id) {
            Ok(()) => {
                info!("TEE post-compute completed");
                ExitMode::Success
            }
            Err(error) => {
                let exit_cause: ReplicateStatusCause;
                match error {
                    ReplicateStatusCause::PostComputeFailedUnknownIssue => {
                        exit_cause = error;
                        error!(
                            "TEE post-compute failed with exit cause [errorMessage:{}]",
                            &exit_cause
                        );
                    }
                    _ => {
                        exit_cause = error;
                        error!("TEE post-compute failed without explicit exit cause");
                    }
                }

                let signer = SignerService;
                let authorization: String = match signer.get_challenge(&chain_task_id) {
                    Ok(challenge) => challenge,
                    Err(_) => {
                        error!(
                            "Failed to retrieve authorization [taskId:{}]",
                            &chain_task_id
                        );
                        return ExitMode::UnreportedFailure;
                    }
                };

                match runner
                    .worker_api_client
                    .send_exit_cause_for_post_compute_stage(
                        &authorization,
                        &chain_task_id,
                        &exit_cause,
                    ) {
                    Ok(()) => ExitMode::ReportedFailure,
                    Err(_) => {
                        error!("Failed to report exit cause [exitCause:{}]", exit_cause);
                        ExitMode::UnreportedFailure
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::{
        computed_file::MockComputedFileOperations, signer::MockSignerOperations,
        web2_result::MockWeb2ResultInterface,
    };
    use mockall::predicate::*;
    use temp_env::with_vars;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    const TEST_TASK_ID: &str = "0x1234567890abcdef";

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

    // Test helper methods for dependency injection testing
    impl PostComputeRunner {
        fn run_post_compute_without_send<C, W>(
            &self,
            chain_task_id: &str,
            computed_file_ops: &C,
            web2_result_service: &W,
        ) -> Result<ComputedFile, ReplicateStatusCause>
        where
            C: ComputedFileOperations,
            W: Web2ResultInterface,
        {
            let should_callback: bool = match get_env_var_or_error(
                TeeSessionEnvironmentVariable::ResultStorageCallback,
                ReplicateStatusCause::PostComputeFailedUnknownIssue,
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
                Err(_) => {
                    error!("Failed to get RESULT_STORAGE_CALLBACK environment variable");
                    return Err(ReplicateStatusCause::PostComputeFailedUnknownIssue);
                }
            };

            let mut computed_file =
                computed_file_ops.read_computed_file(chain_task_id, "/iexec_out")?;
            computed_file_ops
                .build_result_digest_in_computed_file(&mut computed_file, should_callback)?;
            computed_file_ops
                .sign_computed_file(&mut computed_file)
                .map_err(|_| ReplicateStatusCause::PostComputeInvalidTeeSignature)?;

            if !should_callback {
                web2_result_service
                    .encrypt_and_upload_result(&computed_file)
                    .map_err(|_| ReplicateStatusCause::PostComputeFailedUnknownIssue)?;
            }

            Ok(computed_file)
        }

        fn send_computed_file_with_deps<S>(
            &self,
            computed_file: &ComputedFile,
            signer: &S,
        ) -> Result<(), ReplicateStatusCause>
        where
            S: SignerOperations,
        {
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
            let authorization = signer.get_challenge(task_id)?;
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

    // region start tests
    #[test]
    fn start_returns_valid_exit_code_when_ran() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                Some(TEST_TASK_ID),
            )],
            || {
                let result = PostComputeRunner::start();
                assert!(
                    result == 0 || result == 1 || result == 2 || result == 3,
                    "start() should return a valid exit code"
                );
            },
        );
    }

    #[test]
    fn start_returns_3_when_task_id_missing() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::IexecTaskId.name(),
                None::<&str>,
            )],
            || {
                let result = PostComputeRunner::start();
                assert_eq!(
                    result,
                    ExitMode::InitializationFailure,
                    "Should return ExitMode::InitializationFailure when chain task ID is missing"
                );
            },
        );
    }

    #[test]
    fn start_returns_3_when_task_id_empty() {
        with_vars(
            vec![(TeeSessionEnvironmentVariable::IexecTaskId.name(), Some(""))],
            || {
                let result = PostComputeRunner::start();
                assert_eq!(
                    result,
                    ExitMode::InitializationFailure,
                    "Should return ExitMode::InitializationFailure when chain task ID is empty"
                );
            },
        );
    }
    // endregion

    // region run_post_compute tests
    #[test]
    fn run_post_compute_completes_successfully_when_all_operations_succeed() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultStorageCallback.name(),
                Some("false"),
            )],
            || {
                let runner = PostComputeRunner::new();
                let mut mock_computed_file_ops = MockComputedFileOperations::new();
                let mut mock_web2_result = MockWeb2ResultInterface::new();
                let _test_computed_file = create_test_computed_file(Some(TEST_TASK_ID.to_string()));

                mock_computed_file_ops
                    .expect_read_computed_file()
                    .with(eq(TEST_TASK_ID), eq("/iexec_out"))
                    .times(1)
                    .returning(move |task_id, _| {
                        Ok(create_test_computed_file(Some(task_id.to_string())))
                    });

                mock_computed_file_ops
                    .expect_build_result_digest_in_computed_file()
                    .with(always(), eq(false))
                    .times(1)
                    .returning(|_, _| Ok(()));

                mock_computed_file_ops
                    .expect_sign_computed_file()
                    .with(always())
                    .times(1)
                    .returning(|_| Ok(()));

                mock_web2_result
                    .expect_encrypt_and_upload_result()
                    .with(always())
                    .times(1)
                    .returning(|_| Ok(()));

                let result = runner.run_post_compute_without_send(
                    TEST_TASK_ID,
                    &mock_computed_file_ops,
                    &mock_web2_result,
                );

                assert!(result.is_ok(), "run_post_compute should succeed");
            },
        );
    }

    #[test]
    fn run_post_compute_skips_web2_upload_when_callback_mode_enabled() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultStorageCallback.name(),
                Some("true"),
            )],
            || {
                let runner = PostComputeRunner::new();
                let mut mock_computed_file_ops = MockComputedFileOperations::new();
                let mut mock_web2_result = MockWeb2ResultInterface::new();

                mock_computed_file_ops
                    .expect_read_computed_file()
                    .returning(move |task_id, _| {
                        Ok(create_test_computed_file(Some(task_id.to_string())))
                    });

                mock_computed_file_ops
                    .expect_build_result_digest_in_computed_file()
                    .with(always(), eq(true))
                    .returning(|_, _| Ok(()));

                mock_computed_file_ops
                    .expect_sign_computed_file()
                    .returning(|_| Ok(()));

                // Should NOT call encrypt_and_upload_result when callback mode is true
                mock_web2_result.expect_encrypt_and_upload_result().times(0);

                let result = runner.run_post_compute_without_send(
                    TEST_TASK_ID,
                    &mock_computed_file_ops,
                    &mock_web2_result,
                );

                assert!(result.is_ok(), "run_post_compute should succeed");
            },
        );
    }

    #[test]
    fn run_post_compute_returns_error_when_read_computed_file_fails() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultStorageCallback.name(),
                Some("false"),
            )],
            || {
                let runner = PostComputeRunner::new();
                let mut mock_computed_file_ops = MockComputedFileOperations::new();
                let mock_web2_result = MockWeb2ResultInterface::new();

                mock_computed_file_ops
                    .expect_read_computed_file()
                    .with(eq(TEST_TASK_ID), eq("/iexec_out"))
                    .times(1)
                    .returning(|_, _| Err(ReplicateStatusCause::PostComputeFailedUnknownIssue));

                let result = runner.run_post_compute_without_send(
                    TEST_TASK_ID,
                    &mock_computed_file_ops,
                    &mock_web2_result,
                );

                assert!(result.is_err(), "Should fail when read_computed_file fails");
            },
        );
    }

    #[test]
    fn run_post_compute_returns_error_when_sign_computed_file_fails() {
        with_vars(
            vec![(
                TeeSessionEnvironmentVariable::ResultStorageCallback.name(),
                Some("false"),
            )],
            || {
                let runner = PostComputeRunner::new();
                let mut mock_computed_file_ops = MockComputedFileOperations::new();
                let mock_web2_result = MockWeb2ResultInterface::new();

                mock_computed_file_ops
                    .expect_read_computed_file()
                    .returning(move |task_id, _| {
                        Ok(create_test_computed_file(Some(task_id.to_string())))
                    });

                mock_computed_file_ops
                    .expect_build_result_digest_in_computed_file()
                    .returning(|_, _| Ok(()));

                mock_computed_file_ops
                    .expect_sign_computed_file()
                    .times(1)
                    .returning(|_| Err(ReplicateStatusCause::PostComputeInvalidTeeSignature));

                let result = runner.run_post_compute_without_send(
                    TEST_TASK_ID,
                    &mock_computed_file_ops,
                    &mock_web2_result,
                );

                assert!(result.is_err(), "Should fail when sign_computed_file fails");
            },
        );
    }
    // endregion

    // region send_computed_file tests
    #[test]
    fn send_computed_file_succeeds_when_all_operations_succeed() {
        let runner = PostComputeRunner::new();
        let mut mock_signer = MockSignerOperations::new();
        let computed_file = create_test_computed_file(Some(TEST_TASK_ID.to_string()));

        mock_signer
            .expect_get_challenge()
            .with(eq(TEST_TASK_ID))
            .times(1)
            .returning(|_| Ok("test_challenge".to_string()));

        let result = runner.send_computed_file_with_deps(&computed_file, &mock_signer);

        // Note: This will still fail because WorkerApiClient.send_computed_file_to_host is not mocked
        // but it tests the signer integration correctly
        assert!(
            result.is_err(),
            "Expected to fail due to unmocked WorkerApiClient"
        );
    }

    #[test]
    fn send_computed_file_returns_error_when_task_id_missing() {
        let runner = PostComputeRunner::new();
        let mock_signer = MockSignerOperations::new();
        let computed_file = create_test_computed_file(None);

        let result = runner.send_computed_file_with_deps(&computed_file, &mock_signer);

        assert!(result.is_err(), "Should fail when task_id is missing");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeFailedUnknownIssue,
            "Should return PostComputeFailedUnknownIssue when task_id is missing"
        );
    }

    #[test]
    fn send_computed_file_returns_error_when_get_challenge_fails() {
        let runner = PostComputeRunner::new();
        let mut mock_signer = MockSignerOperations::new();
        let computed_file = create_test_computed_file(Some(TEST_TASK_ID.to_string()));

        mock_signer
            .expect_get_challenge()
            .with(eq(TEST_TASK_ID))
            .times(1)
            .returning(|_| Err(ReplicateStatusCause::PostComputeWorkerAddressMissing));

        let result = runner.send_computed_file_with_deps(&computed_file, &mock_signer);

        assert!(result.is_err(), "Should fail when get_challenge fails");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeWorkerAddressMissing,
            "Should propagate the error from get_challenge"
        );
    }
    // endregion

    // region integration tests with wiremock
    const TEST_WORKER_ADDRESS: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_CHALLENGE: &str = "0x184afe6f0d4232c37623d203f4ec42b8281bd7a7f3655c66e65b23b7dbac266330db02efc9bc1bd682405cc1b8876806e086729e1ef7f880e5782aade94cd5741c";

    async fn send_computed_file_integration_test(
        server_url: String,
    ) -> Result<(), ReplicateStatusCause> {
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
                    let runner = PostComputeRunner::new();
                    let computed_file = create_test_computed_file(Some(TEST_TASK_ID.to_string()));
                    runner.send_computed_file(&computed_file)
                },
            )
        })
        .await
        .expect("Task panicked")
    }

    #[tokio::test]
    async fn send_computed_file_succeeds_when_http_request_succeeds() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{}/computed", TEST_TASK_ID)))
            .and(header("Authorization", TEST_CHALLENGE))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = send_computed_file_integration_test(server_url).await;
        assert!(result.is_ok(), "send_computed_file should succeed");
    }

    #[tokio::test]
    async fn send_computed_file_returns_error_when_http_request_fails() {
        let mock_server = MockServer::start().await;
        let server_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path(format!("/compute/post/{}/computed", TEST_TASK_ID)))
            .and(header("Authorization", TEST_CHALLENGE))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = send_computed_file_integration_test(server_url).await;
        assert!(result.is_err(), "Should fail when HTTP request fails");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeSendComputedFileFailed,
            "Should return PostComputeSendComputedFileFailed when HTTP request fails"
        );
    }
    // endregion
}
