use crate::api::worker_api::{ExitMessage, get_worker_api_client};
use crate::post_compute::{
    errors::{PostComputeError, ReplicateStatusCause},
    signer::get_challenge,
};
use crate::utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error};
use std::error::Error;

/**
 * Exits:
 * - 0: Success
 * - 1: Failure; Reported cause (known or unknown)
 * - 2: Failure; Unreported cause since reporting issue failed
 * - 3: Failure; Unreported cause since missing taskID context
 */
pub fn start() -> i32 {
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

    match run_post_compute(&chain_task_id) {
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

            let authorization: String = match get_challenge(&chain_task_id) {
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

            let worker_api_client = get_worker_api_client();
            match worker_api_client.send_exit_cause_for_post_compute_stage(
                &authorization,
                &chain_task_id,
                &exit_message,
            ) {
                Ok(()) => 1, // Exit code for reported failure
                Err(report_error) => {
                    eprintln!("Failed to report exit cause: {}", report_error);
                    2 // Exit code for unreported failure
                }
            }
        }
    }
}

pub fn run_post_compute(chain_task_id: &str) -> Result<(), Box<dyn Error>> {
    Err("run_post_compute not implemented yet".into())
}
