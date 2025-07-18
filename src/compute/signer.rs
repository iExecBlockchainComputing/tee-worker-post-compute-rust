use crate::compute::{
    errors::ReplicateStatusCause,
    utils::{
        env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
        hash_utils::{concatenate_and_hash, hex_string_to_byte_array},
    },
};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
pub trait SignerOperations {
    fn get_challenge(&self, task_id: &str) -> Result<String, ReplicateStatusCause>;
    fn sign_enclave_challenge(
        &self,
        message_hash: &str,
        enclave_challenge_private_key: &str,
    ) -> Result<String, ReplicateStatusCause>;
}

pub struct SignerService;

impl SignerOperations for SignerService {
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
    /// * The worker address environment variable is missing (returns `PostComputeWorkerAddressMissing`)
    /// * The TEE challenge private key environment variable is missing (returns `PostComputeTeeChallengePrivateKeyMissing`)
    /// * The signing operation fails (returns `PostComputeInvalidTeeSignature`)
    ///
    /// # Environment Variables
    ///
    /// * `SIGN_WORKER_ADDRESS` - The worker's address used in message hash calculation
    /// * `SIGN_TEE_CHALLENGE_PRIVATE_KEY` - The private key used for signing the challenge
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming the necessary environment variables are set:
    /// // SIGN_WORKER_ADDRESS=0xabcdef123456789
    /// // SIGN_TEE_CHALLENGE_PRIVATE_KEY=0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479
    ///
    /// let chain_task_id = "0x123456789abcdef";
    /// let signer = SignerService;
    ///
    /// match signer.get_challenge(chain_task_id) {
    ///     Ok(signature) => println!("Challenge signature: {}", signature),
    ///     Err(e) => eprintln!("Error generating challenge: {:?}", e),
    /// }
    /// ```
    fn get_challenge(&self, chain_task_id: &str) -> Result<String, ReplicateStatusCause> {
        let worker_address: String = get_env_var_or_error(
            TeeSessionEnvironmentVariable::SignWorkerAddress,
            ReplicateStatusCause::PostComputeWorkerAddressMissing,
        )?;
        let tee_challenge_private_key: String = get_env_var_or_error(
            TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey,
            ReplicateStatusCause::PostComputeTeeChallengePrivateKeyMissing,
        )?;
        let message_hash: String = concatenate_and_hash(&[chain_task_id, &worker_address]);
        self.sign_enclave_challenge(&message_hash, &tee_challenge_private_key)
    }

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
    /// * The provided private key cannot be parsed as a valid `PrivateKeySigner` (returns `PostComputeInvalidEnclaveChallengePrivateKey`)
    /// * The signing operation fails (returns `PostComputeInvalidTeeSignature`)
    ///
    /// # Example
    ///
    /// ```
    /// let message_hash = "0x5cd0e9c5180dd35e2b8285d0db4ded193a9b4be6fbfab90cbadccecab130acad";
    /// let private_key = "0xdd3b993ec21c71c1f6d63a5240850e0d4d8dd83ff70d29e49247958548c1d479";
    /// let signer = SignerService;
    ///
    /// match signer.sign_enclave_challenge(message_hash, private_key) {
    ///     Ok(signature) => println!("Signature: {}", signature),
    ///     Err(e) => eprintln!("Error: {:?}", e),
    /// }
    /// ```
    fn sign_enclave_challenge(
        &self,
        message_hash: &str,
        enclave_challenge_private_key: &str,
    ) -> Result<String, ReplicateStatusCause> {
        let signer: PrivateKeySigner = enclave_challenge_private_key
            .parse::<PrivateKeySigner>()
            .map_err(|_| ReplicateStatusCause::PostComputeInvalidEnclaveChallengePrivateKey)?;

        let signature: Signature = signer
            .sign_message_sync(&hex_string_to_byte_array(message_hash))
            .map_err(|_| ReplicateStatusCause::PostComputeInvalidTeeSignature)?;

        Ok(signature.to_string())
    }
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

    // region sign_enclave_challenge
    #[test]
    fn sign_enclave_challenge_returns_signature_when_inputs_are_valid() {
        let signer = SignerService;
        let result = signer.sign_enclave_challenge(MESSAGE_HASH, ENCLAVE_CHALLENGE_PRIVATE_KEY);
        assert!(result.is_ok(), "Signing should succeed with valid inputs");
        assert_eq!(
            result.unwrap(),
            EXPECTED_SIGNATURE,
            "The signature should match the expected value exactly"
        );
    }

    #[test]
    fn sign_enclave_challenge_returns_invalid_private_key_error_when_private_key_is_invalid() {
        let signer = SignerService;
        let invalid_key = "invalid_private_key";
        let result = signer.sign_enclave_challenge(MESSAGE_HASH, invalid_key);
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeInvalidEnclaveChallengePrivateKey)
        );
    }
    // endregion

    // region get_challenge
    #[test]
    fn get_challenge_returns_signature_when_env_vars_are_valid() {
        let signer = SignerService;

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::SignWorkerAddress.name(),
                    Some(WORKER_ADDRESS),
                ),
                (
                    TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(),
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
            ],
            || {
                let result = signer.get_challenge(CHAIN_TASK_ID);
                assert!(
                    result.is_ok(),
                    "get_challenge should succeed with valid environment variables"
                );
                // We can't predict the exact signature since it depends on the concatenated hash,
                // but we can verify it's a valid signature format
                let signature = result.unwrap();
                assert!(
                    signature.starts_with("0x"),
                    "Signature should start with 0x"
                );
                assert_eq!(
                    signature.len(),
                    132,
                    "Signature should be 132 characters long (0x + 130 hex chars)"
                );
            },
        );
    }

    #[test]
    fn get_challenge_returns_worker_address_missing_error_when_worker_address_env_var_missing() {
        let signer = SignerService;
        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::SignWorkerAddress.name(),
                    None,
                ),
                (
                    TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(),
                    Some(ENCLAVE_CHALLENGE_PRIVATE_KEY),
                ),
            ],
            || {
                let result = signer.get_challenge(CHAIN_TASK_ID);
                assert_eq!(
                    result,
                    Err(ReplicateStatusCause::PostComputeWorkerAddressMissing)
                );
            },
        );
    }

    #[test]
    fn get_challenge_returns_private_key_missing_error_when_private_key_env_var_missing() {
        let signer = SignerService;
        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::SignWorkerAddress.name(),
                    Some(WORKER_ADDRESS),
                ),
                (
                    TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(),
                    None,
                ),
            ],
            || {
                let result = signer.get_challenge(CHAIN_TASK_ID);
                assert_eq!(
                    result,
                    Err(ReplicateStatusCause::PostComputeTeeChallengePrivateKeyMissing)
                );
            },
        );
    }

    #[test]
    fn get_challenge_returns_invalid_private_key_error_when_private_key_is_invalid() {
        let signer = SignerService;

        with_vars(
            vec![
                (
                    TeeSessionEnvironmentVariable::SignWorkerAddress.name(),
                    Some(WORKER_ADDRESS),
                ),
                (
                    TeeSessionEnvironmentVariable::SignTeeChallengePrivateKey.name(),
                    Some("invalid_private_key"),
                ),
            ],
            || {
                let result = signer.get_challenge(CHAIN_TASK_ID);
                assert_eq!(
                    result,
                    Err(ReplicateStatusCause::PostComputeInvalidEnclaveChallengePrivateKey)
                );
            },
        );
    }
    // endregion
}
