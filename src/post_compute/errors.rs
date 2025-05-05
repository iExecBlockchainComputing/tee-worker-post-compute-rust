use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum ReplicateStatusCause {
    #[error("Failed to verify TeeEnclaveChallenge signature (exiting)")]
    PostComputeInvalidTeeSignature,
    #[error("Invalid enclave challenge private key")]
    PostComputeInvalidEnclaveChallengePrivateKey,
    #[error("Worker address related environment variable is missing")]
    PostComputeWorkerAddressMissing,
    #[error("Tee challenge private key related environment variable is missing")]
    PostComputeTeeChallengePrivateKeyMissing,
}

#[derive(Debug, Error)]
#[error("Post-compute failed: {exit_cause}")]
pub struct PostComputeError {
    pub exit_cause: ReplicateStatusCause,
}

impl PostComputeError {
    pub fn new(cause: ReplicateStatusCause) -> Self {
        Self { exit_cause: cause }
    }

    pub fn exit_cause(&self) -> &ReplicateStatusCause {
        &self.exit_cause
    }
}