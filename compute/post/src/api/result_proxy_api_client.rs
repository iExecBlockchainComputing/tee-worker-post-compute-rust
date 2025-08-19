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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultModel {
    /// Unique identifier of the task on the blockchain
    pub chain_task_id: String,
    /// Unique identifier of the deal this task belongs to
    pub deal_id: String,
    /// Index of the task within the deal
    pub task_index: u32,
    /// Compressed result data as a byte array
    pub zip: Vec<u8>,
    /// Cryptographic hash of the computation result
    pub determinist_hash: String,
    /// TEE (Trusted Execution Environment) signature proving integrity
    pub enclave_signature: String,
}

impl Default for ResultModel {
    fn default() -> Self {
        Self {
            chain_task_id: EMPTY_HEX_STRING_32.to_string(),
            deal_id: EMPTY_HEX_STRING_32.to_string(),
            task_index: 0,
            zip: vec![],
            determinist_hash: String::new(),
            enclave_signature: EMPTY_WEB3_SIG.to_string(),
        }
    }
}

pub struct ResultProxyApiClient {
    base_url: String,
    client: Client,
}

impl ResultProxyApiClient {
    /// Creates a new HTTP client for interacting with the iExec result proxy API.
    ///
    /// This function initializes a client with the provided base URL. The client can then be used
    /// to upload computation results to IPFS via the result proxy service.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the result proxy service (e.g., "https://result.v8-bellecour.iex.ec")
    ///
    /// # Returns
    ///
    /// A new `ResultProxyApiClient` instance configured with the provided base URL.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tee_worker_post_compute::api::result_proxy_api_client::ResultProxyApiClient;
    ///
    /// let client = ResultProxyApiClient::new("https://result.v8-bellecour.iex.ec");
    /// ```
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
    /// use tee_worker_post_compute::api::result_proxy_api_client::{ResultProxyApiClient, ResultModel};
    ///
    /// let client = ResultProxyApiClient::new("https://result-proxy.iex.ec");
    /// let result_model = ResultModel {
    ///     chain_task_id: "0x123...".to_string(),
    ///     zip: vec![0xde, 0xad, 0xbe, 0xef],
    ///     determinist_hash: "0xabc".to_string(),
    ///     enclave_signature: "0xdef".to_string(),
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
    const TEST_DETERMINIST_HASH: &str = "0xabc";
    const TEST_ENCLAVE_SIGNATURE: &str = "0xdef";
    const TEST_IPFS_LINK: &str = "ipfs://QmHash123";
    const TEST_TOKEN: &str = "test-token";

    // region ResultModel
    #[test]
    fn result_model_default_returns_correct_values_when_created() {
        let model = ResultModel::default();
        assert_eq!(model.chain_task_id, EMPTY_HEX_STRING_32);
        assert_eq!(model.deal_id, EMPTY_HEX_STRING_32);
        assert_eq!(model.task_index, 0);
        assert!(model.zip.is_empty());
        assert_eq!(model.determinist_hash, "");
        assert_eq!(model.enclave_signature, EMPTY_WEB3_SIG);
    }

    #[test]
    fn result_model_serializes_to_camel_case_when_converted_to_json() {
        let model = ResultModel {
            chain_task_id: TEST_TASK_ID.to_string(),
            deal_id: TEST_DEAL_ID.to_string(),
            task_index: 5,
            zip: vec![1, 2, 3],
            determinist_hash: TEST_DETERMINIST_HASH.to_string(),
            enclave_signature: TEST_ENCLAVE_SIGNATURE.to_string(),
        };

        let expected = json!({
            "chainTaskId": TEST_TASK_ID,
            "dealId": TEST_DEAL_ID,
            "taskIndex": 5,
            "zip": [1, 2, 3],
            "deterministHash": TEST_DETERMINIST_HASH,
            "enclaveSignature": TEST_ENCLAVE_SIGNATURE
        });

        let v = serde_json::to_value(model).unwrap();
        assert_eq!(v, expected);
    }

    #[test]
    fn result_model_deserializes_from_camel_case_when_parsing_json() {
        let value = json!({
            "chainTaskId": TEST_TASK_ID,
            "dealId": TEST_DEAL_ID,
            "taskIndex": 5,
            "zip": [1, 2, 3],
            "deterministHash": TEST_DETERMINIST_HASH,
            "enclaveSignature": TEST_ENCLAVE_SIGNATURE
        });

        let model: ResultModel = serde_json::from_value(value).unwrap();

        assert_eq!(model.chain_task_id, TEST_TASK_ID);
        assert_eq!(model.deal_id, TEST_DEAL_ID);
        assert_eq!(model.task_index, 5);
        assert_eq!(model.zip, vec![1, 2, 3]);
        assert_eq!(model.determinist_hash, TEST_DETERMINIST_HASH);
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
            determinist_hash: TEST_DETERMINIST_HASH.to_string(),
            enclave_signature: TEST_ENCLAVE_SIGNATURE.to_string(),
            zip: zip_content.to_vec(),
            ..Default::default()
        };

        let mock_server = MockServer::start().await;
        let json = serde_json::to_value(&expected_model).unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .and(header("Authorization", TEST_TOKEN))
            .and(body_json(json))
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
    async fn upload_to_ipfs_returns_error_for_all_error_codes() {
        let test_cases = vec![
            (400, "400", "Bad Request"),
            (401, "401", "Unauthorized"),
            (403, "403", "Forbidden"),
            (404, "404", "Not Found"),
            (500, "500", "Internal Server Error"),
            (502, "502", "Bad Gateway"),
            (503, "503", "Service Unavailable"),
        ];

        for (status_code, expected_error_contains, description) in test_cases {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/results"))
                .respond_with(
                    ResponseTemplate::new(status_code)
                        .set_body_string(format!("{status_code} Error")),
                )
                .mount(&mock_server)
                .await;

            let result = tokio::task::spawn_blocking(move || {
                let client = ResultProxyApiClient::new(&mock_server.uri());
                let model = ResultModel::default();
                client.upload_to_ipfs(TEST_TOKEN, &model)
            })
            .await
            .expect("Task panicked");

            assert!(
                result.is_err(),
                "Expected error for status code {status_code} ({description})"
            );
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains(expected_error_contains),
                "Error message should contain '{expected_error_contains}' for status code {status_code} ({description}), but got: {error}"
            );
        }
    }
    // endregion
}
