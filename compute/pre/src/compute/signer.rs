use crate::compute::errors::ReplicateStatusCause;
use crate::compute::utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error};
use crate::compute::utils::hash_utils::{concatenate_and_hash, hex_string_to_byte_array};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;

/// Signs a message hash using the provided enclave challenge private key.
///
/// This function takes a message hash in hexadecimal string format, converts it to a byte array,
/// and signs it using the provided private key. The resulting signature is then converted back
/// to a string representation.
///
/// # Arguments
///
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
/// This function will return an error in the following situations:
/// * The provided private key cannot be parsed as a valid `PrivateKeySigner` (returns `PreComputeTeeChallengePrivateKeyMissing`)
/// * The signing operation fails (returns `PreComputeInvalidTeeSignature`)
///
/// # Example
///
/// ```rust
/// use tee_worker_pre_compute::compute::signer::sign_enclave_challenge;
///
/// let message_hash = "0x5cd0e9c5180dd35e2b8285d0db4ded193a9b4be6fbfab90cbadccecab130acad";
/// let private_key = "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";
///
/// match sign_enclave_challenge(message_hash, private_key) {
///     Ok(signature) => println!("Signature: {signature}"),
///     Err(e) => eprintln!("Error: {e:?}"),
/// }
/// ```
pub fn sign_enclave_challenge(
    message_hash: &str,
    enclave_challenge_private_key: &str,
) -> Result<String, ReplicateStatusCause> {
    let signer: PrivateKeySigner = enclave_challenge_private_key
        .parse::<PrivateKeySigner>()
        .map_err(|_| ReplicateStatusCause::PreComputeWorkerAddressMissing)?;

    let signature: Signature = signer
        .sign_message_sync(&hex_string_to_byte_array(message_hash))
        .map_err(|_| ReplicateStatusCause::PreComputeInvalidTeeSignature)?;

    Ok(signature.to_string())
}

/// Generates a challenge signature for a given chain task ID.
///
/// This function retrieves the worker address and TEE challenge private key from the environment,
/// then creates a message hash by concatenating and hashing the chain task ID and worker address.
/// Finally, it signs this message hash with the private key.
///
/// # Arguments
///
/// * `chain_task_id` - A string identifier for the chain task
///
/// # Returns
///
/// * `Ok(String)` - The challenge signature as a hexadecimal string if successful
/// * `Err(ReplicateStatusCause)` - An error if required environment variables are missing or if signing fails
///
/// # Errors
///
/// This function will return an error in the following situations:
/// * The worker address environment variable is missing (returns `PreComputeWorkerAddressMissing`)
/// * The TEE challenge private key environment variable is missing (returns `PreComputeTeeChallengePrivateKeyMissing`)
/// * The signing operation fails (returns `PreComputeInvalidTeeSignature`)
///
/// # Environment Variables
///
/// * `SIGN_WORKER_ADDRESS` - The worker's address used in message hash calculation
/// * `SIGN_TEE_CHALLENGE_PRIVATE_KEY` - The private key used for signing the challenge
///
/// # Example
///
/// ```rust
/// use tee_worker_pre_compute::compute::signer::get_challenge;
///
/// // Assuming the necessary environment variables are set:
/// // SIGN_WORKER_ADDRESS=0xabcdef123456789
/// // SIGN_TEE_CHALLENGE_PRIVATE_KEY=0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479
///
/// let chain_task_id = "0x123456789abcdef";
///
/// match get_challenge(chain_task_id) {
///     Ok(signature) => println!("Challenge signature: {signature}"),
///     Err(e) => eprintln!("Error generating challenge: {e:?}"),
/// }
/// ```
pub fn get_challenge(chain_task_id: &str) -> Result<String, ReplicateStatusCause> {
    let worker_address = get_env_var_or_error(
        TeeSessionEnvironmentVariable::SignWorkerAddress,
        ReplicateStatusCause::PreComputeWorkerAddressMissing,
    )?;

    let tee_challenge_private_key = get_env_var_or_error(
        TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey,
        ReplicateStatusCause::PreComputeTeeChallengePrivateKeyMissing,
    )?;

    let message_hash = concatenate_and_hash(&[chain_task_id, &worker_address]);
    sign_enclave_challenge(&message_hash, &tee_challenge_private_key)
}

#[cfg(test)]
mod env_utils_tests {
    use super::*;
    use temp_env::with_vars;

    const CHAIN_TASK_ID: &str = "0x123456789abcdef";
    const WORKER_ADDRESS: &str = "0xabcdef123456789";
    const ENCLAVE_CHALLENGE_PRIVATE_KEY: &str =
        "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";
    const MESSAGE_HASH: &str = "0x5cd0e9c5180dd35e2b8285d0db4ded193a9b4be6fbfab90cbadccecab130acad";
    const EXPECTED_CHALLENGE: &str = "0xfcc6bce5eb04284c2eb1ed14405b943574343b1abda33628fbf94a374b18dd16541c6ebf63c6943d8643ff03c7aa17f1cb17b0a8d297d0fd95fc914bdd0e85f81b";

    #[test]
    fn test_sign_enclave_challenge() {
        let result = sign_enclave_challenge(MESSAGE_HASH, ENCLAVE_CHALLENGE_PRIVATE_KEY).unwrap();
        assert_eq!(result, EXPECTED_CHALLENGE);
    }

    #[test]
    fn test_get_challenge() {
        with_vars(
            vec![
                ("SIGN_WORKER_ADDRESS", Some(WORKER_ADDRESS)),
                (
                    "SIGN_TEE_CHALLENGE_PRIVATE_KEY",
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
            ],
            || {
                let message_hash = concatenate_and_hash(&[CHAIN_TASK_ID, WORKER_ADDRESS]);
                let expected_signature =
                    sign_enclave_challenge(&message_hash, ENCLAVE_CHALLENGE_PRIVATE_KEY).unwrap();

                let actual_challenge = get_challenge(CHAIN_TASK_ID).unwrap();
                assert_eq!(actual_challenge, expected_signature);
            },
        );
    }

    #[test]
    fn error_when_worker_address_missing() {
        with_vars(
            vec![(
                "SIGN_TEE_CHALLENGE_PRIVATE_KEY",
                Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
            )],
            || {
                let err = get_challenge(CHAIN_TASK_ID).unwrap_err();
                assert_eq!(err, ReplicateStatusCause::PreComputeWorkerAddressMissing);
            },
        );
    }

    #[test]
    fn error_when_challenge_private_key_missing() {
        with_vars(vec![("SIGN_WORKER_ADDRESS", Some(WORKER_ADDRESS))], || {
            let err = get_challenge(CHAIN_TASK_ID).unwrap_err();
            assert_eq!(
                err,
                ReplicateStatusCause::PreComputeTeeChallengePrivateKeyMissing
            );
        });
    }
}
