use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, PartialEq, Clone, Error, Serialize, Deserialize)]
#[serde(rename_all(serialize = "SCREAMING_SNAKE_CASE"))]
#[allow(clippy::enum_variant_names)]
pub enum ReplicateStatusCause {
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
}
