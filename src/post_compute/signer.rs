use crate::utils::hash_utils::{concatenate_and_hash, hex_string_to_byte_array};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use std::env;
use thiserror::Error;

const SIGN_WORKER_ADDRESS: &str = "SIGN_WORKER_ADDRESS";
const SIGN_TEE_CHALLENGE_PRIVATE_KEY: &str = "SIGN_TEE_CHALLENGE_PRIVATE_KEY";

#[derive(Error, Debug)]
pub enum PostComputeError {
    #[error("Failed to sign TeeEnclaveChallenge with the provided private key")]
    PostComputeInvalidTeeSignature,
    #[error("Failed to verify TeeEnclaveChallenge signature (exiting)")]
    PostComputeInvalidEnclaveChallengePrivateKey,
    #[error("Worker address related environment variable is missing")]
    PostComputeWorkerAddressMissing,
    #[error("Tee challenge private key related environment variable is missing")]
    PostComputeTeeChallengePrivateKeyMissing,
}

/// Signs the provided message hash using the enclave challenge private key.
///
/// **Arguments**
///
/// * `message_hash` - A byte slice representing the message hash to be signed.
/// * `enclave_challenge_private_key` - A hexadecimal string of the private key.
///
/// **Returns**
///
/// * `Ok(String)` containing the hexadecimal representation of the signature if successful.
/// * `Err(PostComputeError::PostComputeInvalidEnclaveChallengePrivateKey)` if the private key is invalid.
pub fn sign_enclave_challenge(
    message_hash: &str,
    enclave_challenge_private_key: &str,
) -> Result<String, PostComputeError> {
    // Parse the private key from the string
    let signer: PrivateKeySigner = enclave_challenge_private_key.parse::<PrivateKeySigner>()
        .map_err(|_| PostComputeError::PostComputeInvalidEnclaveChallengePrivateKey)?;

    // Sign the message hash
    let signature: Signature = signer.sign_message_sync(&hex_string_to_byte_array(&message_hash))
        .map_err(|_| PostComputeError::PostComputeInvalidTeeSignature)?;

    // Return the signature as a hexadecimal string
    Ok(format!("{}", signature.to_string()))
}

/// Generates an enclave challenge for the given chain task ID.
///
/// **Arguments**
///
/// * `chain_task_id` - A string slice representing the chain task ID.
///
/// **Returns**
///
/// * `Ok(String)` containing the hexadecimal representation of the challenge.
/// * `Err(PostComputeError)` if any error occurs during the process.
pub fn get_challenge(chain_task_id: &str) -> Result<String, PostComputeError> {
    let worker_address: String = match env::var(SIGN_WORKER_ADDRESS) {
        Ok(val) => val,
        Err(_) => Err(PostComputeError::PostComputeWorkerAddressMissing)?,
    };
    let tee_challenge_private_key = match env::var(SIGN_TEE_CHALLENGE_PRIVATE_KEY) {
        Ok(val) => val,
        Err(_) => Err(PostComputeError::PostComputeTeeChallengePrivateKeyMissing)?,
    };
    let message_hash: String = concatenate_and_hash(&[chain_task_id, &worker_address]);
    sign_enclave_challenge(&message_hash, &tee_challenge_private_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use temp_env::with_vars;

    const CHAIN_TASK_ID: &str = "0x123456789abcdef";
    const WORKER_ADDRESS: &str = "0xabcdef123456789";
    const ENCLAVE_CHALLENGE_PRIVATE_KEY: &str =
        "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";
    const MESSAGE_HASH: &str = "0x5cd0e9c5180dd35e2b8285d0db4ded193a9b4be6fbfab90cbadccecab130acad";
    const EXPECTED_SIGNATURE: &str = "0xfcc6bce5eb04284c2eb1ed14405b943574343b1abda33628fbf94a374b18dd16541c6ebf63c6943d8643ff03c7aa17f1cb17b0a8d297d0fd95fc914bdd0e85f81b";

    #[test]
    fn should_sign_enclave_challenge() {
        let result = sign_enclave_challenge(MESSAGE_HASH, ENCLAVE_CHALLENGE_PRIVATE_KEY);
        assert!(result.is_ok(), "Signing should succeed with valid inputs");
        assert_eq!(
            result.unwrap(),
            EXPECTED_SIGNATURE,
            "The signature should match the expected value exactly"
        );
    }

    #[test]
    fn should_not_sign_enclave_challenge_with_invalid_key() {
        let invalid_key = "invalid_private_key";
        let result = sign_enclave_challenge(MESSAGE_HASH, invalid_key);
        assert!(
            matches!(
                result,
                Err(PostComputeError::PostComputeInvalidEnclaveChallengePrivateKey)
            ),
            "Should return invalid private key error"
        );
    }

    #[test]
    fn should_get_challenge() {
        with_vars(
            vec![
                (SIGN_WORKER_ADDRESS, Some(WORKER_ADDRESS)),
                (
                    SIGN_TEE_CHALLENGE_PRIVATE_KEY,
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
            ],
            || {
                let expected_message_hash = concatenate_and_hash(&[CHAIN_TASK_ID, WORKER_ADDRESS]);
                let expected_signature =
                    sign_enclave_challenge(&expected_message_hash, ENCLAVE_CHALLENGE_PRIVATE_KEY)
                        .unwrap();

                let result = get_challenge(CHAIN_TASK_ID);
                assert!(
                    result.is_ok(),
                    "get_challenge should succeed with valid environment variables"
                );
                let signature = result.unwrap();
                assert_eq!(
                    signature, expected_signature,
                    "The challenge signature should match expected value"
                );
            },
        );
    }

    #[test]
    fn should_fail_on_missing_worker_address_env_var() {
        with_vars(
            vec![
                (SIGN_WORKER_ADDRESS, None),
                (
                    SIGN_TEE_CHALLENGE_PRIVATE_KEY,
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
            ],
            || {
                let result = get_challenge(CHAIN_TASK_ID);
                assert!(
                    matches!(
                        result,
                        Err(PostComputeError::PostComputeWorkerAddressMissing)
                    ),
                    "Should return missing worker address error"
                );
            },
        );
    }

    #[test]
    fn should_fail_on_missing_private_key_env_var() {
        with_vars(
            vec![
                (SIGN_WORKER_ADDRESS, Some(WORKER_ADDRESS)),
                (SIGN_TEE_CHALLENGE_PRIVATE_KEY, None),
            ],
            || {
                let result = get_challenge(CHAIN_TASK_ID);
                assert!(
                    matches!(
                        result,
                        Err(PostComputeError::PostComputeTeeChallengePrivateKeyMissing)
                    ),
                    "Should return missing private key error"
                );
            },
        );
    }
}
