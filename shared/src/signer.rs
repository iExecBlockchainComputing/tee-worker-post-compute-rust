use crate::{
    errors::{ReplicateStatusCause, ComputeStage, BaseErrorType},
    utils::{
        env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
        hash_utils::{concatenate_and_hash, hex_string_to_byte_array},
    },
};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;

/// Signs a message hash using the provided enclave challenge private key.
/// Generic implementation that works for both pre and post compute stages.
///
/// # Arguments
///
/// * `stage` - The compute stage (PreCompute or PostCompute) for appropriate error mapping
/// * `message_hash` - A hexadecimal string representing the hash to be signed
/// * `enclave_challenge_private_key` - A string containing the private key used for signing
///
/// # Returns
///
/// * `Ok(String)` - The signature as a hexadecimal string if successful
/// * `Err(ReplicateStatusCause)` - An error if the private key is invalid or if signing fails
///
/// # Errors
///
/// This function will return stage-appropriate errors:
/// * Invalid private key parsing → stage-specific private key error
/// * Signing operation failure → stage-specific signature error
pub fn sign_enclave_challenge_for_stage(
    stage: ComputeStage,
    message_hash: &str,
    enclave_challenge_private_key: &str,
) -> Result<String, ReplicateStatusCause> {
    let signer: PrivateKeySigner = enclave_challenge_private_key
        .parse::<PrivateKeySigner>()
        .map_err(|_| {
            // Use the appropriate error for the stage - note the special case for PostCompute
            match stage {
                ComputeStage::PreCompute => ReplicateStatusCause::PreComputeWorkerAddressMissing,
                ComputeStage::PostCompute => ReplicateStatusCause::PostComputeInvalidEnclaveChallengePrivateKey,
            }
        })?;

    let signature: Signature = signer
        .sign_message_sync(&hex_string_to_byte_array(message_hash))
        .map_err(|_| ReplicateStatusCause::map_error(stage, BaseErrorType::InvalidTeeSignature))?;

    Ok(signature.to_string())
}

/// Generates a challenge signature for a given chain task ID.
/// Generic implementation that works for both pre and post compute stages.
///
/// # Arguments
///
/// * `stage` - The compute stage (PreCompute or PostCompute) for appropriate error mapping
/// * `chain_task_id` - A string identifier for the chain task
///
/// # Returns
///
/// * `Ok(String)` - The challenge signature as a hexadecimal string if successful
/// * `Err(ReplicateStatusCause)` - An error if required environment variables are missing or if signing fails
///
/// # Errors
///
/// This function will return stage-appropriate errors:
/// * Missing worker address → stage-specific worker address error
/// * Missing private key → stage-specific private key error
/// * Signing failure → stage-specific signature error
pub fn get_challenge_for_stage(
    stage: ComputeStage,
    chain_task_id: &str,
) -> Result<String, ReplicateStatusCause> {
    let worker_address = get_env_var_or_error(
        TeeSessionEnvironmentVariable::SignWorkerAddress,
        ReplicateStatusCause::map_error(stage, BaseErrorType::WorkerAddressMissing),
    )?;

    let tee_challenge_private_key = get_env_var_or_error(
        TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey,
        ReplicateStatusCause::map_error(stage, BaseErrorType::TeeChallengePrivateKeyMissing),
    )?;

    let message_hash = concatenate_and_hash(&[chain_task_id, &worker_address]);
    sign_enclave_challenge_for_stage(stage, &message_hash, &tee_challenge_private_key)
}


#[cfg(test)]
mod tests {
    use super::*;
    use temp_env::with_vars;
    use crate::utils::{
        env_utils::TeeSessionEnvironmentVariable,
        hash_utils::concatenate_and_hash,
    };

    const CHAIN_TASK_ID: &str = "0x123456789abcdef";
    const WORKER_ADDRESS: &str = "0xabcdef123456789";
    const ENCLAVE_CHALLENGE_PRIVATE_KEY: &str =
        "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";
    const MESSAGE_HASH: &str = "0x5cd0e9c5180dd35e2b8285d0db4ded193a9b4be6fbfab90cbadccecab130acad";
    const EXPECTED_SIGNATURE: &str = "0xfcc6bce5eb04284c2eb1ed14405b943574343b1abda33628fbf94a374b18dd16541c6ebf63c6943d8643ff03c7aa17f1cb17b0a8d297d0fd95fc914bdd0e85f81b";

    // ========== UNIFIED SIGNATURE TESTS ==========

    #[test]
    fn sign_enclave_challenge_for_stage_returns_correct_signature_when_pre_compute_stage_and_valid_inputs_provided() {
        let result = sign_enclave_challenge_for_stage(
            ComputeStage::PreCompute,
            MESSAGE_HASH,
            ENCLAVE_CHALLENGE_PRIVATE_KEY,
        );
        assert!(result.is_ok(), "Pre-compute signing should succeed with valid inputs");
        assert_eq!(result.unwrap(), EXPECTED_SIGNATURE, "Pre-compute signature should match expected value");
    }

    #[test]
    fn sign_enclave_challenge_for_stage_returns_correct_signature_when_post_compute_stage_and_valid_inputs_provided() {
        let result = sign_enclave_challenge_for_stage(
            ComputeStage::PostCompute,
            MESSAGE_HASH,
            ENCLAVE_CHALLENGE_PRIVATE_KEY,
        );
        assert!(result.is_ok(), "Post-compute signing should succeed with valid inputs");
        assert_eq!(result.unwrap(), EXPECTED_SIGNATURE, "Post-compute signature should match expected value");
    }

    #[test]
    fn sign_enclave_challenge_for_stage_returns_error_when_pre_compute_stage_and_invalid_key_provided() {
        let result = sign_enclave_challenge_for_stage(
            ComputeStage::PreCompute,
            MESSAGE_HASH,
            "invalid_private_key",
        );
        assert!(result.is_err(), "Pre-compute signing should fail with invalid key");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PreComputeWorkerAddressMissing,
            "Pre-compute should return worker address missing error for invalid key"
        );
    }

    #[test]
    fn sign_enclave_challenge_for_stage_returns_error_when_post_compute_stage_and_invalid_key_provided() {
        let result = sign_enclave_challenge_for_stage(
            ComputeStage::PostCompute,
            MESSAGE_HASH,
            "invalid_private_key",
        );
        assert!(result.is_err(), "Post-compute signing should fail with invalid key");
        assert_eq!(
            result.unwrap_err(),
            ReplicateStatusCause::PostComputeInvalidEnclaveChallengePrivateKey,
            "Post-compute should return specific invalid enclave key error"
        );
    }

    // ========== UNIFIED CHALLENGE TESTS ==========

    #[test]
    fn get_challenge_for_stage_returns_correct_signature_when_pre_compute_stage_and_valid_env_vars_provided() {
        with_vars(
            vec![
                ("SIGN_WORKER_ADDRESS", Some(WORKER_ADDRESS)),
                ("SIGN_TEE_CHALLENGE_PRIVATE_KEY", Some(ENCLAVE_CHALLENGE_PRIVATE_KEY)),
            ],
            || {
                let result = get_challenge_for_stage(ComputeStage::PreCompute, CHAIN_TASK_ID);
                assert!(result.is_ok(), "Pre-compute challenge should succeed with valid env vars");

                // Verify it matches direct computation
                let expected_message_hash = concatenate_and_hash(&[CHAIN_TASK_ID, WORKER_ADDRESS]);
                let expected_signature = sign_enclave_challenge_for_stage(
                    ComputeStage::PreCompute,
                    &expected_message_hash,
                    ENCLAVE_CHALLENGE_PRIVATE_KEY,
                ).unwrap();
                assert_eq!(result.unwrap(), expected_signature, "Pre-compute challenge should match expected");
            },
        );
    }

    #[test]
    fn get_challenge_for_stage_returns_correct_signature_when_post_compute_stage_and_valid_env_vars_provided() {
        with_vars(
            vec![
                (TeeSessionEnvironmentVariable::SignWorkerAddress.name(), Some(WORKER_ADDRESS)),
                (TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(), Some(ENCLAVE_CHALLENGE_PRIVATE_KEY)),
            ],
            || {
                let result = get_challenge_for_stage(ComputeStage::PostCompute, CHAIN_TASK_ID);
                assert!(result.is_ok(), "Post-compute challenge should succeed with valid env vars");

                // Verify it matches direct computation
                let expected_message_hash = concatenate_and_hash(&[CHAIN_TASK_ID, WORKER_ADDRESS]);
                let expected_signature = sign_enclave_challenge_for_stage(
                    ComputeStage::PostCompute,
                    &expected_message_hash,
                    ENCLAVE_CHALLENGE_PRIVATE_KEY,
                ).unwrap();
                assert_eq!(result.unwrap(), expected_signature, "Post-compute challenge should match expected");
            },
        );
    }

    #[test]
    fn get_challenge_for_stage_returns_worker_address_missing_error_when_pre_compute_stage_and_worker_address_env_var_missing() {
        with_vars(
            vec![("SIGN_TEE_CHALLENGE_PRIVATE_KEY", Some(ENCLAVE_CHALLENGE_PRIVATE_KEY))],
            || {
                let result = get_challenge_for_stage(ComputeStage::PreCompute, CHAIN_TASK_ID);
                assert!(result.is_err(), "Pre-compute challenge should fail without worker address");
                assert_eq!(
                    result.unwrap_err(),
                    ReplicateStatusCause::PreComputeWorkerAddressMissing,
                    "Should return missing worker address error"
                );
            },
        );
    }

    #[test]
    fn get_challenge_for_stage_returns_worker_address_missing_error_when_post_compute_stage_and_worker_address_env_var_missing() {
        with_vars(
            vec![(TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(), Some(ENCLAVE_CHALLENGE_PRIVATE_KEY))],
            || {
                let result = get_challenge_for_stage(ComputeStage::PostCompute, CHAIN_TASK_ID);
                assert!(result.is_err(), "Post-compute challenge should fail without worker address");
                assert_eq!(
                    result.unwrap_err(),
                    ReplicateStatusCause::PostComputeWorkerAddressMissing,
                    "Should return missing worker address error"
                );
            },
        );
    }

    #[test]
    fn get_challenge_for_stage_returns_private_key_missing_error_when_pre_compute_stage_and_private_key_env_var_missing() {
        with_vars(
            vec![("SIGN_WORKER_ADDRESS", Some(WORKER_ADDRESS))],
            || {
                let result = get_challenge_for_stage(ComputeStage::PreCompute, CHAIN_TASK_ID);
                assert!(result.is_err(), "Pre-compute challenge should fail without private key");
                assert_eq!(
                    result.unwrap_err(),
                    ReplicateStatusCause::PreComputeTeeChallengePrivateKeyMissing,
                    "Should return missing private key error"
                );
            },
        );
    }

    #[test]
    fn get_challenge_for_stage_returns_private_key_missing_error_when_post_compute_stage_and_private_key_env_var_missing() {
        with_vars(
            vec![(TeeSessionEnvironmentVariable::SignWorkerAddress.name(), Some(WORKER_ADDRESS))],
            || {
                let result = get_challenge_for_stage(ComputeStage::PostCompute, CHAIN_TASK_ID);
                assert!(result.is_err(), "Post-compute challenge should fail without private key");
                assert_eq!(
                    result.unwrap_err(),
                    ReplicateStatusCause::PostComputeTeeChallengePrivateKeyMissing,
                    "Should return missing private key error"
                );
            },
        );
    }

    #[test]
    fn get_challenge_for_stage_returns_worker_address_missing_error_when_pre_compute_stage_and_both_env_vars_missing() {
        with_vars(Vec::<(&str, Option<&str>)>::new(), || {
            let result = get_challenge_for_stage(ComputeStage::PreCompute, CHAIN_TASK_ID);
            assert!(result.is_err(), "Pre-compute challenge should fail without any env vars");
            assert_eq!(
                result.unwrap_err(),
                ReplicateStatusCause::PreComputeWorkerAddressMissing,
                "Should return worker address missing error (first checked)"
            );
        });
    }

    #[test]
    fn get_challenge_for_stage_returns_worker_address_missing_error_when_post_compute_stage_and_both_env_vars_missing() {
        with_vars(Vec::<(&str, Option<&str>)>::new(), || {
            let result = get_challenge_for_stage(ComputeStage::PostCompute, CHAIN_TASK_ID);
            assert!(result.is_err(), "Post-compute challenge should fail without any env vars");
            assert_eq!(
                result.unwrap_err(),
                ReplicateStatusCause::PostComputeWorkerAddressMissing,
                "Should return worker address missing error (first checked)"
            );
        });
    }



    // ========== CONSISTENCY TESTS ==========

    #[test]
    fn sign_enclave_challenge_for_stage_produces_identical_signatures_when_same_inputs_provided_across_different_stages() {
        // Both stages should produce the same signature for the same input
        let pre_signature = sign_enclave_challenge_for_stage(
            ComputeStage::PreCompute,
            MESSAGE_HASH,
            ENCLAVE_CHALLENGE_PRIVATE_KEY,
        ).unwrap();

        let post_signature = sign_enclave_challenge_for_stage(
            ComputeStage::PostCompute,
            MESSAGE_HASH,
            ENCLAVE_CHALLENGE_PRIVATE_KEY,
        ).unwrap();

        assert_eq!(pre_signature, post_signature, "Both stages should produce identical signatures for same input");
        assert_eq!(pre_signature, EXPECTED_SIGNATURE, "Signatures should match known expected value");
    }

    #[test]
    fn get_challenge_for_stage_produces_deterministic_results_when_same_inputs_provided_multiple_times() {
        // Challenge generation should be deterministic for same inputs
        with_vars(
            vec![
                ("SIGN_WORKER_ADDRESS", Some(WORKER_ADDRESS)),
                ("SIGN_TEE_CHALLENGE_PRIVATE_KEY", Some(ENCLAVE_CHALLENGE_PRIVATE_KEY)),
            ],
            || {
                let challenge1 = get_challenge_for_stage(ComputeStage::PreCompute, CHAIN_TASK_ID).unwrap();
                let challenge2 = get_challenge_for_stage(ComputeStage::PreCompute, CHAIN_TASK_ID).unwrap();
                assert_eq!(challenge1, challenge2, "Challenge generation should be deterministic");

                let post_challenge1 = get_challenge_for_stage(ComputeStage::PostCompute, CHAIN_TASK_ID).unwrap();
                let post_challenge2 = get_challenge_for_stage(ComputeStage::PostCompute, CHAIN_TASK_ID).unwrap();
                assert_eq!(post_challenge1, post_challenge2, "Post-compute challenge generation should be deterministic");

                // Both stages should produce the same challenge for same inputs
                assert_eq!(challenge1, post_challenge1, "Both stages should produce same challenge for same inputs");
            },
        );
    }
}
