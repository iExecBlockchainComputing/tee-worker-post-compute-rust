use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, PartialEq, Clone, Error, Serialize, Deserialize)]
#[serde(rename_all(serialize = "SCREAMING_SNAKE_CASE"))]
#[allow(clippy::enum_variant_names)]
pub enum ReplicateStatusCause {
    #[error("Task ID related environment variable is missing")]
    PostComputeTaskIdMissing,
    #[error("Unexpected error occurred")]
    PostComputeFailedUnknownIssue,
    #[error("Invalid enclave challenge private key")]
    PostComputeInvalidEnclaveChallengePrivateKey,
    #[error("Invalid TEE signature")]
    PostComputeInvalidTeeSignature,
    #[error("Tee challenge private key related environment variable is missing")]
    PostComputeTeeChallengePrivateKeyMissing,
    #[error("Worker address related environment variable is missing")]
    PostComputeWorkerAddressMissing,
}
