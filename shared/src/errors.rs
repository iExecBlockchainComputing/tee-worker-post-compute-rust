use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Compute stage context for internal error handling
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ComputeStage {
    PreCompute,
    PostCompute,
}

/// Base error categories that can occur in either stage
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BaseErrorType {
    FailedUnknownIssue,
    InvalidTeeSignature,
    TaskIdMissing,
    TeeChallengePrivateKeyMissing,
    WorkerAddressMissing,
}

#[derive(Debug, PartialEq, Clone, Error, Serialize, Deserialize)]
#[serde(rename_all(serialize = "SCREAMING_SNAKE_CASE"))]
#[allow(clippy::enum_variant_names)]
pub enum ReplicateStatusCause {
    // Pre-compute errors
    #[error("At least one input file URL is missing")]
    PreComputeAtLeastOneInputFileUrlMissing,
    #[error("Dataset checksum related environment variable is missing")]
    PreComputeDatasetChecksumMissing,
    #[error("Failed to decrypt dataset")]
    PreComputeDatasetDecryptionFailed,
    #[error("Failed to download encrypted dataset file")]
    PreComputeDatasetDownloadFailed,
    #[error("Dataset filename related environment variable is missing")]
    PreComputeDatasetFilenameMissing,
    #[error("Dataset key related environment variable is missing")]
    PreComputeDatasetKeyMissing,
    #[error("Dataset URL related environment variable is missing")]
    PreComputeDatasetUrlMissing,
    #[error("Unexpected error occurred")]
    PreComputeFailedUnknownIssue,
    #[error("Invalid TEE signature")]
    PreComputeInvalidTeeSignature,
    #[error("IS_DATASET_REQUIRED environment variable is missing")]
    PreComputeIsDatasetRequiredMissing,
    #[error("Input files download failed")]
    PreComputeInputFileDownloadFailed,
    #[error("Input files number related environment variable is missing")]
    PreComputeInputFilesNumberMissing,
    #[error("Invalid dataset checksum")]
    PreComputeInvalidDatasetChecksum,
    #[error("Input files number related environment variable is missing")]
    PreComputeOutputFolderNotFound,
    #[error("Output path related environment variable is missing")]
    PreComputeOutputPathMissing,
    #[error("Failed to write plain dataset file")]
    PreComputeSavingPlainDatasetFailed,
    #[error("Task ID related environment variable is missing")]
    PreComputeTaskIdMissing,
    #[error("TEE challenge private key related environment variable is missing")]
    PreComputeTeeChallengePrivateKeyMissing,
    #[error("Worker address related environment variable is missing")]
    PreComputeWorkerAddressMissing,

    // Post-compute errors
    #[error("computed.json file missing")]
    PostComputeComputedFileNotFound,
    #[error("Failed to upload to Dropbox")]
    PostComputeDropboxUploadFailed,
    #[error("Encryption stage failed")]
    PostComputeEncryptionFailed,
    #[error("Encryption public key related environment variable is missing")]
    PostComputeEncryptionPublicKeyMissing,
    #[error("Unexpected error occurred")]
    PostComputeFailedUnknownIssue,
    #[error("Invalid enclave challenge private key")]
    PostComputeInvalidEnclaveChallengePrivateKey,
    #[error("Invalid TEE signature")]
    PostComputeInvalidTeeSignature,
    #[error("Failed to upload to IPFS")]
    PostComputeIpfsUploadFailed,
    #[error("Encryption public key is malformed")]
    PostComputeMalformedEncryptionPublicKey,
    #[error("Failed to zip result folder")]
    PostComputeOutFolderZipFailed,
    #[error("Empty resultDigest")]
    PostComputeResultDigestComputationFailed,
    #[error("Result file not found")]
    PostComputeResultFileNotFound,
    #[error("Failed to send computed file")]
    PostComputeSendComputedFileFailed,
    #[error("Storage token related environment variable is missing")]
    PostComputeStorageTokenMissing,
    #[error("Task ID related environment variable is missing")]
    PostComputeTaskIdMissing,
    #[error("Tee challenge private key related environment variable is missing")]
    PostComputeTeeChallengePrivateKeyMissing,
    #[error("Result file name too long")]
    PostComputeTooLongResultFileName,
    #[error("Worker address related environment variable is missing")]
    PostComputeWorkerAddressMissing,
}

impl ReplicateStatusCause {
    /// Creates a shared error for the specified stage
    pub fn map_error(stage: ComputeStage, error_type: BaseErrorType) -> Self {
        match (stage, error_type) {
            (ComputeStage::PreCompute, BaseErrorType::FailedUnknownIssue) => {
                Self::PreComputeFailedUnknownIssue
            }
            (ComputeStage::PreCompute, BaseErrorType::InvalidTeeSignature) => {
                Self::PreComputeInvalidTeeSignature
            }
            (ComputeStage::PreCompute, BaseErrorType::TaskIdMissing) => {
                Self::PreComputeTaskIdMissing
            }
            (ComputeStage::PreCompute, BaseErrorType::TeeChallengePrivateKeyMissing) => {
                Self::PreComputeTeeChallengePrivateKeyMissing
            }
            (ComputeStage::PreCompute, BaseErrorType::WorkerAddressMissing) => {
                Self::PreComputeWorkerAddressMissing
            }

            (ComputeStage::PostCompute, BaseErrorType::FailedUnknownIssue) => {
                Self::PostComputeFailedUnknownIssue
            }
            (ComputeStage::PostCompute, BaseErrorType::InvalidTeeSignature) => {
                Self::PostComputeInvalidTeeSignature
            }
            (ComputeStage::PostCompute, BaseErrorType::TaskIdMissing) => {
                Self::PostComputeTaskIdMissing
            }
            (ComputeStage::PostCompute, BaseErrorType::TeeChallengePrivateKeyMissing) => {
                Self::PostComputeTeeChallengePrivateKeyMissing
            }
            (ComputeStage::PostCompute, BaseErrorType::WorkerAddressMissing) => {
                Self::PostComputeWorkerAddressMissing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_string;

    #[test]
    fn map_error_creates_correct_variant_when_stage_and_type_provided() {
        let error1 = ReplicateStatusCause::map_error(
            ComputeStage::PreCompute,
            BaseErrorType::WorkerAddressMissing,
        );
        let error2 = ReplicateStatusCause::PreComputeWorkerAddressMissing;
        assert_eq!(error1, error2);
    }

    #[test]
    fn replicate_status_cause_serializes_to_screaming_snake_case_when_converted_to_json() {
        let error = ReplicateStatusCause::PreComputeWorkerAddressMissing;
        let serialized = to_string(&error).unwrap();
        assert!(serialized.contains("PRE_COMPUTE_WORKER_ADDRESS_MISSING"));
    }
}
