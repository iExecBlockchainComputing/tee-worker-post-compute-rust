use crate::api::worker_api::{ExitMessage, get_worker_api_client};
use crate::post_compute::{
    errors::{PostComputeError, ReplicateStatusCause},
    signer::get_challenge,
};
use crate::utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error};
use std::error::Error;

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

pub struct DefaultPostComputeRunner;

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
        let worker_api_client = get_worker_api_client();
        worker_api_client.send_exit_cause_for_post_compute_stage(
            authorization,
            chain_task_id,
            exit_message,
        )
    }
}

/**
 * Exits:
 * - 0: Success
 * - 1: Failure; Reported cause (known or unknown)
 * - 2: Failure; Unreported cause since reporting issue failed
 * - 3: Failure; Unreported cause since missing taskID context
 */
pub fn start_with_runner<R: PostComputeRunnerInterface>(runner: &R) -> i32 {
    println!("Tee worker post-compute started");
    let chain_task_id: String = match get_env_var_or_error(
        TeeSessionEnvironmentVariable::IEXEC_TASK_ID,
        ReplicateStatusCause::PostComputeChainTaskIdMissing,
    ) {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "TEE post-compute cannot go further without taskID context [errorMessage:{}]",
                e.exit_cause()
            );
            return 3; // Exit code for missing taskID context
        }
    };

    match runner.run_post_compute(&chain_task_id) {
        Ok(()) => {
            println!("TEE post-compute completed");
            0
        }
        Err(error) => {
            let exit_cause: &ReplicateStatusCause;
            match error.downcast_ref::<PostComputeError>() {
                Some(post_compute_error) => {
                    exit_cause = post_compute_error.exit_cause();
                    eprintln!(
                        "TEE post-compute failed with exit cause [errorMessage:{}]",
                        &exit_cause
                    );
                }
                None => {
                    exit_cause = &ReplicateStatusCause::PostComputeFailedUnknownIssue;
                    eprintln!("TEE post-compute failed without explicit exit cause");
                }
            }

            let authorization: String = match runner.get_challenge(&chain_task_id) {
                Ok(challenge) => challenge,
                Err(_) => {
                    eprintln!(
                        "Failed to retrieve authorization [taskId:{}]",
                        &chain_task_id
                    );
                    return 2; // Exit code for unreported failure
                }
            };

            let exit_message = ExitMessage::from(exit_cause);

            match runner.send_exit_cause(&authorization, &chain_task_id, &exit_message) {
                Ok(()) => 1, // Exit code for reported failure
                Err(report_error) => {
                    eprintln!("Failed to report exit cause: {}", report_error);
                    2 // Exit code for unreported failure
                }
            }
        }
    }
}

pub fn start() -> i32 {
    start_with_runner(&DefaultPostComputeRunner)
}

pub fn run_post_compute(chain_task_id: &str) -> Result<(), Box<dyn Error>> {
    DefaultPostComputeRunner.run_post_compute(chain_task_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::worker_api::ExitMessage;
    use crate::post_compute::errors::{PostComputeError, ReplicateStatusCause};
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
    fn should_fail_since_no_task_id() {
        with_vars(vec![("IEXEC_TASK_ID", None::<String>)], || {
            let runner = MockRunner::new();
            let result = start_with_runner(&runner);
            assert_eq!(result, 3, "Should return 3 when chain task ID is missing");
        });
    }

    #[test]
    fn should_start_post_compute() {
        with_vars(vec![("IEXEC_TASK_ID", Some("0x0"))], || {
            let runner = MockRunner::new();
            let result = start_with_runner(&runner);
            assert_eq!(result, 0, "Should return 0 on successful execution");
        });
    }

    #[test]
    fn should_fail_with_known_cause() {
        with_vars(vec![("IEXEC_TASK_ID", Some("0x0"))], || {
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
        with_vars(vec![("IEXEC_TASK_ID", Some("0x0"))], || {
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
        with_vars(vec![("IEXEC_TASK_ID", Some("0x0"))], || {
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
        with_vars(vec![("IEXEC_TASK_ID", Some("0x0"))], || {
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
