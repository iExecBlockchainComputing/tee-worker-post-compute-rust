use crate::compute::pre_compute_app::{PreComputeApp, PreComputeAppTrait};
use shared::{
    errors::{ReplicateStatusCause, ComputeStage},
    signer::get_challenge_for_stage,
    utils::env_utils::{TeeSessionEnvironmentVariable::IexecTaskId, get_env_var_or_error},
    worker_api::{ExitMessage, WorkerApiClient},
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

/// Executes the pre-compute workflow with a provided PreComputeApp implementation.
///
/// This function orchestrates the full pre-compute process, handling environment
/// variable checks, execution of the main pre-compute logic, and error reporting.
/// It uses the provided app to execute core operations and handles all the
/// workflow states and transitions.
///
/// # Arguments
///
/// * `pre_compute_app` - An implementation of [`PreComputeAppTrait`] that will be used to execute the pre-compute operations.
///
/// # Note
///
/// This is an internal function that accepts a pre-compute application instance
/// and orchestrates the entire pre-compute workflow. Most users should use the
/// [`start`] convenience function instead.
pub fn start_with_app<A: PreComputeAppTrait>(pre_compute_app: &mut A) -> ExitMode {
    info!("TEE pre-compute started");

    let exit_cause = ReplicateStatusCause::PreComputeFailedUnknownIssue;
    let chain_task_id =
        match get_env_var_or_error(IexecTaskId, ReplicateStatusCause::PreComputeTaskIdMissing) {
            Ok(id) => id,
            Err(e) => {
                error!("TEE pre-compute cannot proceed without taskID context: {e:?}");
                return ExitMode::InitializationFailure;
            }
        };

    match pre_compute_app.run(&chain_task_id) {
        Ok(_) => {
            info!("TEE pre-compute completed");
            return ExitMode::Success;
        }
        Err(exit_cause) => {
            error!("TEE pre-compute failed with known exit cause [{exit_cause:?}]");
        }
    }

    let authorization = match get_challenge_for_stage(ComputeStage::PreCompute, &chain_task_id) {
        Ok(auth) => auth,
        Err(_) => {
            error!("Failed to sign exitCause message [{exit_cause:?}]");
            return ExitMode::UnreportedFailure;
        }
    };

    let exit_message = ExitMessage {
        cause: &exit_cause.clone(),
    };

    match WorkerApiClient::from_env().send_exit_cause_for_pre_compute_stage(
        &authorization,
        &chain_task_id,
        &exit_message,
    ) {
        Ok(_) => ExitMode::ReportedFailure,
        Err(_) => {
            error!("Failed to report exitCause [{exit_cause:?}]");
            ExitMode::UnreportedFailure
        }
    }
}

/// Starts the pre-compute process using the [`PreComputeApp`].
///
/// This is a convenience function that creates a [`PreComputeApp`]
/// and passes it to [`start_with_app`].
///
/// # Example
///
/// ```rust
/// use tee_worker_pre_compute::compute::app_runner::{start, ExitMode};
///
/// let exit_code = start();
/// // The function will return one of the ExitMode variants
/// match exit_code {
///     ExitMode::Success => println!("Pre-compute completed successfully"),
///     ExitMode::ReportedFailure => println!("Pre-compute failed (reported)"),
///     ExitMode::UnreportedFailure => println!("Pre-compute failed (unreported)"),
///     ExitMode::InitializationFailure => println!("Pre-compute initialization failed"),
/// }
/// ```
pub fn start() -> ExitMode {
    let mut pre_compute_app = PreComputeApp::new();
    start_with_app(&mut pre_compute_app)
}

#[cfg(test)]
mod pre_compute_start_with_app_tests {
    use super::*;
    use crate::compute::pre_compute_app::MockPreComputeAppTrait;
    use serde_json::json;
    use temp_env;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CHAIN_TASK_ID: &str = "0x123456789abcdef";
    const WORKER_ADDRESS: &str = "0xabcdef123456789";
    const ENCLAVE_CHALLENGE_PRIVATE_KEY: &str =
        "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";
    const ENV_IEXEC_TASK_ID: &str = "IEXEC_TASK_ID";
    const ENV_SIGN_WORKER_ADDRESS: &str = "SIGN_WORKER_ADDRESS";
    const ENV_SIGN_TEE_CHALLENGE_PRIVATE_KEY: &str = "SIGN_TEE_CHALLENGE_PRIVATE_KEY";
    const ENV_WORKER_HOST: &str = "WORKER_HOST_ENV_VAR";

    #[test]
    fn start_fails_when_task_id_missing() {
        temp_env::with_vars_unset(vec![ENV_IEXEC_TASK_ID], || {
            assert_eq!(
                start(),
                ExitMode::InitializationFailure,
                "Should return 3 if IEXEC_TASK_ID is missing"
            );
        });
    }

    #[test]
    fn start_fails_when_signer_address_missing() {
        let env_vars_to_set = vec![
            (ENV_IEXEC_TASK_ID, Some(CHAIN_TASK_ID)),
            (
                ENV_SIGN_TEE_CHALLENGE_PRIVATE_KEY,
                Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
            ),
        ];
        let env_vars_to_unset = vec![ENV_SIGN_WORKER_ADDRESS];

        let mut mock = MockPreComputeAppTrait::new();
        mock.expect_run()
            .withf(|chain_task_id| chain_task_id == CHAIN_TASK_ID)
            .returning(|_| Err(ReplicateStatusCause::PreComputeWorkerAddressMissing));

        temp_env::with_vars(env_vars_to_set, || {
            temp_env::with_vars_unset(env_vars_to_unset, || {
                assert_eq!(
                    start_with_app(&mut mock),
                    ExitMode::UnreportedFailure,
                    "Should return 2 if get_challenge fails due to missing signer address"
                );
            });
        });
    }

    #[test]
    fn start_fails_when_private_key_missing() {
        let env_vars_to_set = vec![
            (ENV_IEXEC_TASK_ID, Some(CHAIN_TASK_ID)),
            (ENV_SIGN_WORKER_ADDRESS, Some(WORKER_ADDRESS)),
        ];
        let env_vars_to_unset = vec![ENV_SIGN_TEE_CHALLENGE_PRIVATE_KEY];

        let mut mock = MockPreComputeAppTrait::new();
        mock.expect_run()
            .withf(|chain_task_id| chain_task_id == CHAIN_TASK_ID)
            .returning(|_| Err(ReplicateStatusCause::PreComputeTeeChallengePrivateKeyMissing));

        temp_env::with_vars(env_vars_to_set, || {
            temp_env::with_vars_unset(env_vars_to_unset, || {
                assert_eq!(
                    start_with_app(&mut mock),
                    ExitMode::UnreportedFailure,
                    "Should return 2 if get_challenge fails due to missing private key"
                );
            });
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_fails_when_send_exit_cause_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(format!("/compute/pre/{CHAIN_TASK_ID}/exit")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let mock_server_addr_string = mock_server.address().to_string();

        let mut mock = MockPreComputeAppTrait::new();
        mock.expect_run()
            .withf(|chain_task_id| chain_task_id == CHAIN_TASK_ID)
            .returning(|_| Err(ReplicateStatusCause::PreComputeTeeChallengePrivateKeyMissing));

        let result_code = tokio::task::spawn_blocking(move || {
            let env_vars = vec![
                (ENV_IEXEC_TASK_ID, Some(CHAIN_TASK_ID)),
                (ENV_SIGN_WORKER_ADDRESS, Some(WORKER_ADDRESS)),
                (
                    ENV_SIGN_TEE_CHALLENGE_PRIVATE_KEY,
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
                (ENV_WORKER_HOST, Some(mock_server_addr_string.as_str())),
            ];

            temp_env::with_vars(env_vars, || start_with_app(&mut mock))
        })
        .await
        .expect("Blocking task panicked");

        assert_eq!(
            result_code,
            ExitMode::UnreportedFailure,
            "Should return 2 if sending exit cause to worker API fails"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_succeeds_when_send_exit_cause_api_success() {
        let mock_server = MockServer::start().await;

        let expected_cause_enum = ReplicateStatusCause::PreComputeFailedUnknownIssue;
        let expected_exit_message_payload = json!({
            "cause": expected_cause_enum // Relies on ReplicateStatusCause's Serialize impl
        });

        // Mock the worker API to return success
        Mock::given(method("POST"))
            .and(path(format!("/compute/pre/{CHAIN_TASK_ID}/exit")))
            .and(body_json(expected_exit_message_payload))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let mock_server_addr_string = mock_server.address().to_string();

        let mut mock = MockPreComputeAppTrait::new();
        mock.expect_run()
            .withf(|chain_task_id| chain_task_id == CHAIN_TASK_ID)
            .returning(|_| Err(ReplicateStatusCause::PreComputeTeeChallengePrivateKeyMissing));

        // Move the blocking operations into spawn_blocking
        let result_code = tokio::task::spawn_blocking(move || {
            let env_vars = vec![
                (ENV_IEXEC_TASK_ID, Some(CHAIN_TASK_ID)),
                (ENV_SIGN_WORKER_ADDRESS, Some(WORKER_ADDRESS)),
                (
                    ENV_SIGN_TEE_CHALLENGE_PRIVATE_KEY,
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
                (ENV_WORKER_HOST, Some(mock_server_addr_string.as_str())),
            ];

            temp_env::with_vars(env_vars, || start_with_app(&mut mock))
        })
        .await
        .expect("Blocking task panicked");

        assert_eq!(
            result_code,
            ExitMode::ReportedFailure,
            "Should return 1 if sending exit cause to worker API succeeds"
        );
    }
}
