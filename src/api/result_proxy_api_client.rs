use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

const EMPTY_HEX_STRING_32: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";
const EMPTY_WEB3_SIG: &str = "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Represents a computation result that can be uploaded to IPFS via the iExec result proxy.
///
/// This struct encapsulates all the necessary information about a completed computation task
/// that needs to be stored permanently on IPFS. It includes task identification, metadata,
/// the actual result data, and cryptographic proofs of computation integrity.
///
/// The struct is designed to be serialized to JSON for transmission to the result proxy API,
/// with field names automatically converted to camelCase to match the expected API format.
///
/// # Fields
///
/// * `chain_task_id` - The unique identifier of the task on the blockchain
/// * `deal_id` - The identifier of the deal this task belongs to
/// * `task_index` - The index of this task within the deal (typically 0 for single-task deals)
/// * `image` - The Docker image used for computation (currently unused in uploads)
/// * `cmd` - The command executed during computation (currently unused in uploads)
/// * `zip` - The compressed result data as a byte array
/// * `deterministic_hash` - The cryptographic hash of the computation result
/// * `enclave_signature` - The TEE (Trusted Execution Environment) signature proving integrity
///
/// # Example
///
/// ```rust
/// use crate::api::result_proxy_api_client::ResultModel;
///
/// let result = ResultModel {
///     chain_task_id: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
///     deterministic_hash: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
///     enclave_signature: "0x789abc123def456789abc123def456789abc123d...".to_string(),
///     zip: vec![0x50, 0x4b, 0x03, 0x04], // ZIP file header
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultModel {
    pub chain_task_id: String,
    pub deal_id: String,
    pub task_index: u32,
    pub image: String,
    pub cmd: String,
    pub zip: Vec<u8>,
    pub deterministic_hash: String,
    pub enclave_signature: String,
}

impl Default for ResultModel {
    fn default() -> Self {
        Self {
            chain_task_id: String::from(EMPTY_HEX_STRING_32),
            deal_id: String::from(EMPTY_HEX_STRING_32),
            task_index: 0,
            image: String::new(),
            cmd: String::new(),
            zip: vec![],
            deterministic_hash: String::new(),
            enclave_signature: String::from(EMPTY_WEB3_SIG),
        }
    }
}

/// HTTP client for interacting with the iExec result proxy API.
///
/// This client can be created directly with a base URL using [`new()`].
///
/// # Example
///
/// ```rust
/// use crate::api::result_proxy_api_client::ResultProxyApiClient;
///
/// let client = ResultProxyApiClient::new("https://result-proxy.iex.ec");
/// ```
pub struct ResultProxyApiClient {
    base_url: String,
    client: Client,
}

impl ResultProxyApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: Client::new(),
        }
    }

    /// Uploads a computation result to IPFS via the result proxy service.
    ///
    /// This method sends a POST request to the result proxy's `/v1/results` endpoint with
    /// the provided result model. The result proxy validates the data, uploads it to IPFS,
    /// and returns the IPFS link for permanent storage.
    ///
    /// The upload process involves several steps handled by the result proxy:
    /// 1. Authentication and authorization validation
    /// 2. Result data validation (signatures, hashes, etc.)
    /// 3. IPFS upload and pinning
    /// 4. Registration of the result link on the blockchain
    ///
    /// # Arguments
    ///
    /// * `authorization` - The bearer token for authenticating with the result proxy
    /// * `result_model` - The [`ResultModel`] containing the computation result to upload
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The IPFS link where the result was uploaded (e.g., "ipfs://QmHash...")
    /// * `Err(reqwest::Error)` - HTTP client error or server-side error
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    /// * Network connectivity issues preventing the HTTP request
    /// * Authentication failures (invalid or expired token)
    /// * Server-side validation failures (invalid signatures, malformed data)
    /// * IPFS upload failures on the result proxy side
    /// * HTTP status codes indicating server errors (4xx, 5xx)
    ///
    /// # Example
    ///
    /// ```rust
    /// use crate::api::result_proxy_api_client::{ResultProxyApiClient, ResultModel};
    ///
    /// let client = ResultProxyApiClient::new("https://result-proxy.iex.ec");
    /// let result_model = ResultModel {
    ///     chain_task_id: "0x123...".to_string(),
    ///     zip: compressed_data,
    ///     deterministic_hash: computed_hash,
    ///     enclave_signature: tee_signature,
    ///     ..Default::default()
    /// };
    ///
    /// match client.upload_to_ipfs("Bearer token123", &result_model) {
    ///     Ok(ipfs_link) => {
    ///         println!("Successfully uploaded to: {}", ipfs_link);
    ///         // IPFS link can be used to retrieve the result later
    ///     }
    ///     Err(e) => {
    ///         eprintln!("Upload failed: {}", e);
    ///         // Handle error appropriately (retry, report, etc.)
    ///     }
    /// }
    /// ```
    pub fn upload_to_ipfs(
        &self,
        authorization: &str,
        result_model: &ResultModel,
    ) -> Result<String, reqwest::Error> {
        let url = format!("{}/v1/results", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Authorization", authorization)
            .json(result_model)
            .send()?;

        if response.status().is_success() {
            response.text()
        } else {
            Err(response.error_for_status().unwrap_err())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    // Test constants
    const TEST_TASK_ID: &str = "0x123";
    const TEST_DEAL_ID: &str = "0x456";
    const TEST_DETERMINISTIC_HASH: &str = "0xabc";
    const TEST_ENCLAVE_SIGNATURE: &str = "0xdef";
    const TEST_IMAGE: &str = "test-image";
    const TEST_CMD: &str = "test-cmd";
    const TEST_IPFS_LINK: &str = "ipfs://QmHash123";
    const TEST_TOKEN: &str = "test-token";

    // region ResultModel
    #[test]
    fn result_model_default_returns_correct_values_when_created() {
        let model = ResultModel::default();
        assert_eq!(model.chain_task_id, EMPTY_HEX_STRING_32);
        assert_eq!(model.deal_id, EMPTY_HEX_STRING_32);
        assert_eq!(model.task_index, 0);
        assert_eq!(model.image, "");
        assert_eq!(model.cmd, "");
        assert!(model.zip.is_empty());
        assert_eq!(model.deterministic_hash, "");
        assert_eq!(model.enclave_signature, EMPTY_WEB3_SIG);
    }

    #[test]
    fn result_model_serializes_to_camel_case_when_converted_to_json() {
        let model = ResultModel {
            chain_task_id: TEST_TASK_ID.to_string(),
            deal_id: TEST_DEAL_ID.to_string(),
            task_index: 5,
            image: TEST_IMAGE.to_string(),
            cmd: TEST_CMD.to_string(),
            zip: vec![1, 2, 3],
            deterministic_hash: TEST_DETERMINISTIC_HASH.to_string(),
            enclave_signature: TEST_ENCLAVE_SIGNATURE.to_string(),
        };

        let json = serde_json::to_value(&model).unwrap();

        // Verify camelCase field names
        assert!(json.get("chainTaskId").is_some());
        assert!(json.get("dealId").is_some());
        assert!(json.get("taskIndex").is_some());
        assert!(json.get("deterministicHash").is_some());
        assert!(json.get("enclaveSignature").is_some());

        // Verify snake_case fields are NOT present
        assert!(json.get("chain_task_id").is_none());
        assert!(json.get("deal_id").is_none());
        assert!(json.get("task_index").is_none());
        assert!(json.get("deterministic_hash").is_none());
        assert!(json.get("enclave_signature").is_none());

        // Verify values
        assert_eq!(json["chainTaskId"], TEST_TASK_ID);
        assert_eq!(json["dealId"], TEST_DEAL_ID);
        assert_eq!(json["taskIndex"], 5);
        assert_eq!(json["image"], TEST_IMAGE);
        assert_eq!(json["cmd"], TEST_CMD);
        assert_eq!(json["zip"], serde_json::json!([1, 2, 3]));
        assert_eq!(json["deterministicHash"], TEST_DETERMINISTIC_HASH);
        assert_eq!(json["enclaveSignature"], TEST_ENCLAVE_SIGNATURE);
    }

    #[test]
    fn result_model_deserializes_from_camel_case_when_parsing_json() {
        let json_str = format!(r#"{{
            "chainTaskId": "{}",
            "dealId": "{}",
            "taskIndex": 5,
            "image": "{}",
            "cmd": "{}",
            "zip": [1, 2, 3],
            "deterministicHash": "{}",
            "enclaveSignature": "{}"
        }}"#, TEST_TASK_ID, TEST_DEAL_ID, TEST_IMAGE, TEST_CMD, TEST_DETERMINISTIC_HASH, TEST_ENCLAVE_SIGNATURE);

        let model: ResultModel = serde_json::from_str(&json_str).unwrap();

        assert_eq!(model.chain_task_id, TEST_TASK_ID);
        assert_eq!(model.deal_id, TEST_DEAL_ID);
        assert_eq!(model.task_index, 5);
        assert_eq!(model.image, TEST_IMAGE);
        assert_eq!(model.cmd, TEST_CMD);
        assert_eq!(model.zip, vec![1, 2, 3]);
        assert_eq!(model.deterministic_hash, TEST_DETERMINISTIC_HASH);
        assert_eq!(model.enclave_signature, TEST_ENCLAVE_SIGNATURE);
    }
    //endregion

    // region ResultProxyApiClient
    #[test]
    fn result_proxy_api_client_new_creates_client_when_given_base_url() {
        let base_url = "http://localhost:8080";
        let client = ResultProxyApiClient::new(base_url);
        assert_eq!(client.base_url, base_url);
    }

    #[tokio::test]
    async fn upload_to_ipfs_returns_ipfs_link_when_server_responds_successfully() {
        let zip_content = b"test content";

        let expected_model = ResultModel {
            chain_task_id: TEST_TASK_ID.to_string(),
            deterministic_hash: TEST_DETERMINISTIC_HASH.to_string(),
            enclave_signature: TEST_ENCLAVE_SIGNATURE.to_string(),
            zip: zip_content.to_vec(),
            ..Default::default()
        };

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .and(header("Authorization", TEST_TOKEN))
            .and(body_json(json!({
                "chainTaskId": TEST_TASK_ID,
                "dealId": expected_model.deal_id,
                "taskIndex": 0,
                "image": "",
                "cmd": "",
                "zip": zip_content.to_vec(),
                "deterministicHash": TEST_DETERMINISTIC_HASH,
                "enclaveSignature": TEST_ENCLAVE_SIGNATURE
            })))
            .respond_with(ResponseTemplate::new(200).set_body_string(TEST_IPFS_LINK))
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let client = ResultProxyApiClient::new(&mock_server.uri());
            client.upload_to_ipfs(TEST_TOKEN, &expected_model)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TEST_IPFS_LINK);
    }

    #[tokio::test]
    async fn upload_to_ipfs_returns_error_when_server_returns_400() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let client = ResultProxyApiClient::new(&mock_server.uri());
            let model = ResultModel::default();
            client.upload_to_ipfs(TEST_TOKEN, &model)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("400"));
    }

    #[tokio::test]
    async fn upload_to_ipfs_returns_error_when_server_returns_500() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let model = ResultModel {
            chain_task_id: EMPTY_HEX_STRING_32.to_string(),
            ..Default::default()
        };

        let result = tokio::task::spawn_blocking(move || {
            let client = ResultProxyApiClient::new(&mock_server.uri());
            client.upload_to_ipfs(TEST_TOKEN, &model)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("500"));
    }
    // endregion
}
