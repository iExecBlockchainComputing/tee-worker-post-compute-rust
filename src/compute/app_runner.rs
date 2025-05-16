use crate::api::worker_api::{ExitMessage, WorkerApiClient};
use crate::compute::{
    errors::{PostComputeError, ReplicateStatusCause},
    signer::get_challenge,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};
use log::{error, info};
use std::error::Error;

/// Defines the interface for post-compute operations.
///
/// This trait encapsulates the core functionality needed for running post-compute operations.
/// Implementations of this trait can be used with the [`start_with_runner`] function to execute
/// the post-compute workflow.
pub trait PostComputeRunnerInterface {
    fn run_post_compute(&self, chain_task_id: &str) -> Result<(), Box<dyn Error>>;
    fn get_challenge(&self, chain_task_id: &str) -> Result<String, PostComputeError>;
    fn send_exit_cause(
        &self,
        authorization: &str,
        chain_task_id: &str,
        exit_message: &ExitMessage,
    ) -> Result<(), reqwest::Error>;
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
    fn run_post_compute(&self, chain_task_id: &str) -> Result<(), Box<dyn Error>> {
        Err("run_post_compute not implemented yet".into())
    }

    fn get_challenge(&self, chain_task_id: &str) -> Result<String, PostComputeError> {
        get_challenge(chain_task_id)
    }

    fn send_exit_cause(
        &self,
        authorization: &str,
        chain_task_id: &str,
        exit_message: &ExitMessage,
    ) -> Result<(), reqwest::Error> {
        self.worker_api_client
            .send_exit_cause_for_post_compute_stage(authorization, chain_task_id, exit_message)
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
        TeeSessionEnvironmentVariable::IEXEC_TASK_ID,
        ReplicateStatusCause::PostComputeChainTaskIdMissing,
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
        Err(error) => {
            let exit_cause: &ReplicateStatusCause;
            match error.downcast_ref::<PostComputeError>() {
                Some(post_compute_error) => {
                    exit_cause = post_compute_error.exit_cause();
                    error!(
                        "TEE post-compute failed with exit cause [errorMessage:{}]",
                        &exit_cause
                    );
                }
                None => {
                    exit_cause = &ReplicateStatusCause::PostComputeFailedUnknownIssue;
                    error!("TEE post-compute failed without explicit exit cause");
                }
            }

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

            let exit_message = ExitMessage::from(exit_cause);

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

pub fn run_post_compute(chain_task_id: &str) -> Result<(), Box<dyn Error>> {
    let runner = DefaultPostComputeRunner::new();
    runner.run_post_compute(chain_task_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::worker_api::ExitMessage;
    use crate::compute::{
        errors::{PostComputeError, ReplicateStatusCause},
        utils::env_utils::TeeSessionEnvironmentVariable::*,
    };
    use std::error::Error;
    use temp_env::with_vars;

    struct MockRunner {
        run_post_compute_success: bool,
        get_challenge_success: bool,
        send_exit_cause_success: bool,
        error_cause: Option<ReplicateStatusCause>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                run_post_compute_success: true,
                get_challenge_success: true,
                send_exit_cause_success: true,
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
        fn run_post_compute(&self, _chain_task_id: &str) -> Result<(), Box<dyn Error>> {
            if self.run_post_compute_success {
                Ok(())
            } else if let Some(cause) = &self.error_cause {
                Err(Box::new(PostComputeError::new(cause.clone())))
            } else {
                Err("Mock error".into())
            }
        }

        fn get_challenge(&self, _chain_task_id: &str) -> Result<String, PostComputeError> {
            if self.get_challenge_success {
                Ok("mock_challenge".to_string())
            } else {
                Err(PostComputeError::new(
                    ReplicateStatusCause::PostComputeTeeChallengePrivateKeyMissing,
                ))
            }
        }

        fn send_exit_cause(
            &self,
            _authorization: &str,
            _chain_task_id: &str,
            _exit_message: &ExitMessage,
        ) -> Result<(), reqwest::Error> {
            if self.send_exit_cause_success {
                Ok(())
            } else {
                Err(reqwest::blocking::get("invalid_url").unwrap_err())
            }
        }
    }

    #[test]
    fn should_return_valid_exit_code() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some("0x123"))], || {
            let result = start();
            assert!(
                result == 0 || result == 1 || result == 2 || result == 3,
                "start() should return a valid exit code"
            );
        });
    }

    #[test]
    fn should_fail_since_no_task_id() {
        with_vars(vec![(IEXEC_TASK_ID.name(), None::<&str>)], || {
            let runner = MockRunner::new();
            let result = start_with_runner(&runner);
            assert_eq!(result, 3, "Should return 3 when chain task ID is missing");
        });
    }

    #[test]
    fn should_fail_with_empty_task_id() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some(""))], || {
            let runner = MockRunner::new();
            let result = start_with_runner(&runner);
            assert_eq!(result, 3, "Should return 3 when chain task ID is empty");
        });
    }

    #[test]
    fn should_start_post_compute() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some("0x0"))], || {
            let runner = MockRunner::new();
            let result = start_with_runner(&runner);
            assert_eq!(result, 0, "Should return 0 on successful execution");
        });
    }

    #[test]
    fn should_fail_with_known_cause() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some("0x0"))], || {
            let runner = MockRunner::new().with_run_post_compute_failure(Some(
                ReplicateStatusCause::PostComputeInvalidTeeSignature,
            ));

            let result = start_with_runner(&runner);
            assert_eq!(
                result, 1,
                "Should return 1 when error is reported successfully"
            );
        });
    }

    #[test]
    fn should_fail_with_unknown_cause() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some("0x0"))], || {
            let runner = MockRunner::new().with_run_post_compute_failure(None);

            let result = start_with_runner(&runner);
            assert_eq!(
                result, 1,
                "Should return 1 when unknown error is reported successfully"
            );
        });
    }

    #[test]
    fn should_not_transmit_cause() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some("0x0"))], || {
            let runner = MockRunner::new()
                .with_run_post_compute_failure(Some(
                    ReplicateStatusCause::PostComputeInvalidTeeSignature,
                ))
                .with_send_exit_cause_failure();

            let result = start_with_runner(&runner);
            assert_eq!(result, 2, "Should return 2 when error reporting fails");
        });
    }

    #[test]
    fn should_get_signer_service_exception() {
        with_vars(vec![(IEXEC_TASK_ID.name(), Some("0x0"))], || {
            let runner = MockRunner::new()
                .with_run_post_compute_failure(Some(
                    ReplicateStatusCause::PostComputeInvalidTeeSignature,
                ))
                .with_get_challenge_failure();

            let result = start_with_runner(&runner);
            assert_eq!(result, 2, "Should return 2 when signer service fails");
        });
    }
}
