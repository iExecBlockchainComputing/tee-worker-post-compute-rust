use shared::{
    errors::ReplicateStatusCause,
    utils::env_utils::{TeeSessionEnvironmentVariable, get_env_var_or_error},
};

/// Represents parameters required for pre-compute tasks in a Trusted Execution Environment (TEE).
///
/// This structure aggregates configuration parameters from environment variables and task context,
/// providing a validated interface for subsequent computation phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreComputeArgs {
    pub output_dir: String,
    // Dataset related fields
    pub is_dataset_required: bool,
    pub encrypted_dataset_url: Option<String>,
    pub encrypted_dataset_base64_key: Option<String>,
    pub encrypted_dataset_checksum: Option<String>,
    pub plain_dataset_filename: Option<String>,
    // Input files
    pub input_files: Vec<String>,
}

impl PreComputeArgs {
    /// Constructs a validated `PreComputeArgs` instance by reading and validating environment variables.
    ///
    /// # Environment Variables
    /// This method reads the following environment variables:
    /// - Required for all tasks:
    ///   - `IEXEC_PRE_COMPUTE_OUT`: Output directory path
    ///   - `IEXEC_DATASET_REQUIRED`: Boolean ("true"/"false") indicating dataset requirement
    ///   - `IEXEC_INPUT_FILES_NUMBER`: Number of input files to load
    /// - Required when `IEXEC_DATASET_REQUIRED` = "true":
    ///   - `IEXEC_DATASET_URL`: Encrypted dataset URL
    ///   - `IEXEC_DATASET_KEY`: Base64-encoded dataset encryption key
    ///   - `IEXEC_DATASET_CHECKSUM`: Encrypted dataset checksum
    ///   - `IEXEC_DATASET_FILENAME`: Decrypted dataset filename
    /// - Input file URLs (`IEXEC_INPUT_FILE_URL_1`, `IEXEC_INPUT_FILE_URL_2`, etc.)
    ///
    /// # Errors
    /// Returns `ReplicateStatusCause` error variants for:
    /// - Missing required environment variables
    /// - Invalid boolean values in `IEXEC_DATASET_REQUIRED`
    /// - Invalid numeric format in `IEXEC_INPUT_FILES_NUMBER`
    /// - Missing dataset parameters when required
    /// - Missing input file URLs
    ///
    /// # Note
    ///
    /// This method is called internally during application initialization to parse
    /// all pre-compute configuration from environment variables.
    pub fn read_args() -> Result<Self, ReplicateStatusCause> {
        let output_dir = get_env_var_or_error(
            TeeSessionEnvironmentVariable::IexecPreComputeOut,
            ReplicateStatusCause::PreComputeOutputPathMissing,
        )?;

        let is_dataset_required_str = get_env_var_or_error(
            TeeSessionEnvironmentVariable::IsDatasetRequired,
            ReplicateStatusCause::PreComputeIsDatasetRequiredMissing,
        )?;
        let is_dataset_required = is_dataset_required_str
            .to_lowercase()
            .parse::<bool>()
            .map_err(|_| ReplicateStatusCause::PreComputeIsDatasetRequiredMissing)?;

        let mut encrypted_dataset_url = None;
        let mut encrypted_dataset_base64_key = None;
        let mut encrypted_dataset_checksum = None;
        let mut plain_dataset_filename = None;

        if is_dataset_required {
            encrypted_dataset_url = Some(get_env_var_or_error(
                TeeSessionEnvironmentVariable::IexecDatasetUrl,
                ReplicateStatusCause::PreComputeDatasetUrlMissing,
            )?);
            encrypted_dataset_base64_key = Some(get_env_var_or_error(
                TeeSessionEnvironmentVariable::IexecDatasetKey,
                ReplicateStatusCause::PreComputeDatasetKeyMissing,
            )?);
            encrypted_dataset_checksum = Some(get_env_var_or_error(
                TeeSessionEnvironmentVariable::IexecDatasetChecksum,
                ReplicateStatusCause::PreComputeDatasetChecksumMissing,
            )?);
            plain_dataset_filename = Some(get_env_var_or_error(
                TeeSessionEnvironmentVariable::IexecDatasetFilename,
                ReplicateStatusCause::PreComputeDatasetFilenameMissing,
            )?);
        }

        let input_files_nb_str = get_env_var_or_error(
            TeeSessionEnvironmentVariable::IexecInputFilesNumber,
            ReplicateStatusCause::PreComputeInputFilesNumberMissing,
        )?;
        let input_files_nb = input_files_nb_str
            .parse::<usize>()
            .map_err(|_| ReplicateStatusCause::PreComputeInputFilesNumberMissing)?;

        let mut input_files = Vec::with_capacity(input_files_nb);
        for i in 1..=input_files_nb {
            let url = get_env_var_or_error(
                TeeSessionEnvironmentVariable::IexecInputFileUrlPrefix(i),
                ReplicateStatusCause::PreComputeAtLeastOneInputFileUrlMissing,
            )?;
            input_files.push(url);
        }

        Ok(PreComputeArgs {
            output_dir,
            is_dataset_required,
            encrypted_dataset_url,
            encrypted_dataset_base64_key,
            encrypted_dataset_checksum,
            plain_dataset_filename,
            input_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::env_utils::TeeSessionEnvironmentVariable::*;
    use std::collections::HashMap;

    const OUTPUT_DIR: &str = "/iexec_out";
    const DATASET_URL: &str = "https://dataset.url";
    const DATASET_KEY: &str = "datasetKey123";
    const DATASET_CHECKSUM: &str = "0x123checksum";
    const DATASET_FILENAME: &str = "dataset.txt";

    fn setup_basic_env_vars() -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert(IexecPreComputeOut.name(), OUTPUT_DIR.to_string());
        vars.insert(IsDatasetRequired.name(), "true".to_string());
        vars.insert(IexecInputFilesNumber.name(), "0".to_string());
        vars
    }

    fn setup_dataset_env_vars() -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert(IexecDatasetUrl.name(), DATASET_URL.to_string());
        vars.insert(IexecDatasetKey.name(), DATASET_KEY.to_string());
        vars.insert(IexecDatasetChecksum.name(), DATASET_CHECKSUM.to_string());
        vars.insert(IexecDatasetFilename.name(), DATASET_FILENAME.to_string());
        vars
    }

    fn setup_input_files_env_vars(count: usize) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert(IexecInputFilesNumber.name(), count.to_string());

        for i in 1..=count {
            vars.insert(
                IexecInputFileUrlPrefix(i).name(),
                format!("https://input-{i}.txt"),
            );
        }
        vars
    }

    fn to_temp_env_vars(map: HashMap<String, String>) -> Vec<(String, Option<String>)> {
        map.into_iter().map(|(k, v)| (k, Some(v))).collect()
    }

    // region Required environment variables
    #[test]
    fn read_args_succeeds_when_no_dataset() {
        let mut env_vars = setup_basic_env_vars();
        env_vars.extend(setup_input_files_env_vars(1));
        env_vars.insert(IsDatasetRequired.name(), "false".to_string());
        temp_env::with_vars(to_temp_env_vars(env_vars), || {
            let result = PreComputeArgs::read_args();

            assert!(result.is_ok());
            let args = result.unwrap();

            assert_eq!(args.output_dir, OUTPUT_DIR);
            assert!(!args.is_dataset_required);
            assert_eq!(args.encrypted_dataset_url, None);
            assert_eq!(args.encrypted_dataset_base64_key, None);
            assert_eq!(args.encrypted_dataset_checksum, None);
            assert_eq!(args.plain_dataset_filename, None);
            assert_eq!(args.input_files.len(), 1);
            assert_eq!(args.input_files[0], "https://input-1.txt");
        });
    }

    #[test]
    fn read_args_succeeds_when_dataset_exists() {
        let mut env_vars = setup_basic_env_vars();

        // Add dataset environment variables
        env_vars.extend(setup_dataset_env_vars());

        temp_env::with_vars(to_temp_env_vars(env_vars), || {
            let result = PreComputeArgs::read_args();

            assert!(result.is_ok());
            let args = result.unwrap();

            assert_eq!(args.output_dir, OUTPUT_DIR);
            assert!(args.is_dataset_required);
            assert_eq!(args.encrypted_dataset_url, Some(DATASET_URL.to_string()));
            assert_eq!(
                args.encrypted_dataset_base64_key,
                Some(DATASET_KEY.to_string())
            );
            assert_eq!(
                args.encrypted_dataset_checksum,
                Some(DATASET_CHECKSUM.to_string())
            );
            assert_eq!(
                args.plain_dataset_filename,
                Some(DATASET_FILENAME.to_string())
            );
            assert_eq!(args.input_files.len(), 0);
        });
    }

    #[test]
    fn read_args_succeeds_when_multiple_inputs_exist() {
        let mut env_vars = setup_basic_env_vars();
        env_vars.insert(IsDatasetRequired.name(), "false".to_string());

        // Add input files environment variables
        env_vars.extend(setup_input_files_env_vars(3));

        temp_env::with_vars(to_temp_env_vars(env_vars), || {
            let result = PreComputeArgs::read_args();

            assert!(result.is_ok());
            let args = result.unwrap();

            assert_eq!(args.output_dir, OUTPUT_DIR);
            assert!(!args.is_dataset_required);
            assert_eq!(args.encrypted_dataset_url, None);
            assert_eq!(args.encrypted_dataset_base64_key, None);
            assert_eq!(args.encrypted_dataset_checksum, None);
            assert_eq!(args.plain_dataset_filename, None);
            assert_eq!(args.input_files.len(), 3);
            assert_eq!(args.input_files[0], "https://input-1.txt");
            assert_eq!(args.input_files[1], "https://input-2.txt");
            assert_eq!(args.input_files[2], "https://input-3.txt");
        });
    }
    // endregion

    // region parsing tests
    #[test]
    fn read_args_succeeds_when_insensitive_bool_parsing() {
        let test_values = vec!["false", "FALSE", "False", "fAlSe"];
        for value_str in test_values {
            let mut env_vars = setup_basic_env_vars();
            env_vars.insert(IsDatasetRequired.name(), value_str.to_string());

            temp_env::with_vars(to_temp_env_vars(env_vars), || {
                let result = PreComputeArgs::read_args();
                assert!(result.is_ok());
                let args = result.unwrap();
                assert!(!args.is_dataset_required);
            });
        }
    }

    #[test]
    fn read_args_fails_when_invalid_bool_format() {
        let mut env_vars = setup_basic_env_vars();
        env_vars.insert("IS_DATASET_REQUIRED".to_string(), "not-a-bool".to_string());

        temp_env::with_vars(to_temp_env_vars(env_vars), || {
            let result = PreComputeArgs::read_args();
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                ReplicateStatusCause::PreComputeIsDatasetRequiredMissing
            );
        });
    }

    #[test]
    fn read_args_fails_when_invalid_input_files_number_format() {
        let mut env_vars = setup_basic_env_vars();
        env_vars.insert(
            "IEXEC_INPUT_FILES_NUMBER".to_string(),
            "not-a-number".to_string(),
        );
        env_vars.insert(IsDatasetRequired.name(), "false".to_string());

        temp_env::with_vars(to_temp_env_vars(env_vars), || {
            let result = PreComputeArgs::read_args();
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                ReplicateStatusCause::PreComputeInputFilesNumberMissing
            );
        });
    }
    // endregion

    // region dataset environment variables
    #[test]
    fn read_args_fails_when_dataset_env_var_missing() {
        let missing_env_var_causes = vec![
            (
                IexecPreComputeOut,
                ReplicateStatusCause::PreComputeOutputPathMissing,
            ),
            (
                IsDatasetRequired,
                ReplicateStatusCause::PreComputeIsDatasetRequiredMissing,
            ),
            (
                IexecInputFilesNumber,
                ReplicateStatusCause::PreComputeInputFilesNumberMissing,
            ),
            (
                IexecDatasetUrl,
                ReplicateStatusCause::PreComputeDatasetUrlMissing,
            ),
            (
                IexecDatasetKey,
                ReplicateStatusCause::PreComputeDatasetKeyMissing,
            ),
            (
                IexecDatasetChecksum,
                ReplicateStatusCause::PreComputeDatasetChecksumMissing,
            ),
            (
                IexecDatasetFilename,
                ReplicateStatusCause::PreComputeDatasetFilenameMissing,
            ),
            (
                IexecInputFileUrlPrefix(1),
                ReplicateStatusCause::PreComputeAtLeastOneInputFileUrlMissing,
            ),
        ];
        for (env_var, error) in missing_env_var_causes {
            read_args_fails_when_required_env_var_missing(env_var, error);
        }
    }

    fn read_args_fails_when_required_env_var_missing(
        env_var: TeeSessionEnvironmentVariable,
        error: ReplicateStatusCause,
    ) {
        //Set up environment variables
        let mut env_vars = setup_basic_env_vars();
        env_vars.extend(setup_dataset_env_vars());
        env_vars.extend(setup_input_files_env_vars(1));
        env_vars.remove(&env_var.name());

        temp_env::with_vars(to_temp_env_vars(env_vars), || {
            let result = PreComputeArgs::read_args();
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), error);
        });
    }
    // endregion
}
