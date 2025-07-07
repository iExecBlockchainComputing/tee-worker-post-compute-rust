use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use reqwest::blocking::multipart;
use std::fs::File;           
use std::io::Write;       

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingResultModel {
    /// Unique identifier of the task on the blockchain
    pub chain_task_id: String,
    /// Unique identifier of the deal this task belongs to
    pub deal_id: String,
    /// Index of the task within the deal
    pub task_index: u32,
    /// Compressed result data as a byte array
    pub zip_file_path: String, // instead of the file content (Vec<u8>),
    /// Cryptographic hash of the computation result
    pub determinist_hash: String,
    /// TEE (Trusted Execution Environment) signature proving integrity
    pub enclave_signature: String,
}

impl Default for StreamingResultModel {
    fn default() -> Self {
        Self {
            chain_task_id: EMPTY_HEX_STRING_32.to_string(),
            deal_id: EMPTY_HEX_STRING_32.to_string(),
            task_index: 0,
            zip_file_path: String::new(),
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
    /// use crate::api::result_proxy_api_client::ResultProxyApiClient;
    ///
    /// let client = ResultProxyApiClient::new("https://result.v8-bellecour.iex.ec");
    /// ```
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: Client::new(),
        }
    }

    /// Uploads a computation result to IPFS via the result proxy service using a streaming multipart form.
    /// 
    /// This method sends a POST request to the result proxy's `/v1/results` endpoint using a
    /// multipart/form-data request body. It streams the compressed result file along with the
    /// associated metadata. The result proxy processes the data, uploads the file to IPFS,
    /// and returns the resulting IPFS link for permanent decentralized storage.
    /// 
    /// The upload process involves the following steps handled by the result proxy:
    /// 1. Authentication and authorization validation
    /// 2. Multipart form parsing and metadata validation (signatures, hashes, etc.)
    /// 3. IPFS file upload and pinning of the compressed result
    /// 4. Blockchain registration of the resulting IPFS link
    ///
    /// # Arguments
    ///
    /// * `authorization` - The bearer token for authenticating with the result proxy
    /// * `streaming_result_model` - The [`StreamingResultModel`] containing metadata for the result
    /// * `file` - The compressed result file to upload (e.g., a `.zip` file)
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The IPFS link where the result file was uploaded (e.g., `"ipfs://QmHash..."`)
    /// * `Err(reqwest::Error)` - HTTP client error or server-side failure
    ///
    /// # Errors
    ///
    /// This function may return an error in the following situations:
    /// * Network connectivity issues preventing the HTTP request
    /// * Authentication failures (e.g., missing or invalid bearer token)
    /// * File streaming issues (e.g., unreadable file descriptor)
    /// * Server-side validation failures (e.g., mismatched signature or hash)
    /// * IPFS upload or blockchain registration errors
    /// * HTTP error responses (status codes 4xx or 5xx)
    ///
    /// # Example
    ///
    /// ```rust
    /// use crate::api::result_proxy_api_client::{ResultProxyApiClient, StreamingResultModel};
    /// use std::fs::File;
    ///
    /// let client = ResultProxyApiClient::new("https://result-proxy.iex.ec");
    ///
    /// let model = StreamingResultModel {
    ///     chain_task_id: "0xabc123...".into(),
    ///     deal_id: "0xdeal456...".into(),
    ///     task_index: 0,
    ///     zip_file_path: "result.zip".into(),
    ///     determinist_hash: "deadbeef...".into(),
    ///     enclave_signature: "sgn123...".into(),
    /// };
    ///
    /// let file = File::open("result.zip")?;
    ///
    /// match client.upload_to_ipfs_streaming("Bearer token123", &model, file) {
    ///     Ok(ipfs_link) => println!("Uploaded to IPFS: {}", ipfs_link),
    ///     Err(e) => eprintln!("Upload failed: {}", e),
    /// }
    /// ```
    pub fn upload_to_ipfs_streaming(
        &self,
        authorization: &str,
        streaming_result_model: &StreamingResultModel,
        file: File,
    ) -> Result<String, reqwest::Error> {
        let url = format!("{}/v1/results", self.base_url);

        let zip_part = multipart::Part::reader(file)
            .file_name(streaming_result_model.zip_file_path.clone())
            .mime_str("application/zip")?;

        let form = multipart::Form::new()
            .text("chainTaskId", streaming_result_model.chain_task_id.clone())
            .text("dealId", streaming_result_model.deal_id.clone())
            .text("taskIndex", streaming_result_model.task_index.to_string())
            .text("deterministHash", streaming_result_model.determinist_hash.clone())
            .text("enclaveSignature", streaming_result_model.enclave_signature.clone())
            .part("zip", zip_part);

        let response = self
            .client
            .post(&url)
            .header("Authorization", authorization)
            .multipart(form)
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
    async fn upload_to_ipfs_streaming_returns_ipfs_link_when_server_responds_successfully() {
        let zip_content = b"test streaming content";
        
        let expected_model = StreamingResultModel {
            chain_task_id: TEST_TASK_ID.to_string(),
            deal_id: TEST_DEAL_ID.to_string(),
            task_index: 1,
            zip_file_path: "test_result.zip".to_string(),
            determinist_hash: TEST_DETERMINIST_HASH.to_string(),
            enclave_signature: TEST_ENCLAVE_SIGNATURE.to_string(),
        };

        // Create a temporary file for testing
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(zip_content).unwrap();
        temp_file.flush().unwrap();
        
        let mock_server = MockServer::start().await;
        
        // Capture the request body for validation
        let expected_content = zip_content.to_vec();
        
        Mock::given(method("POST"))
            .and(path("/v1/results"))
            .and(header("Authorization", TEST_TOKEN))
            .and(move |req: &wiremock::Request| {
                // Verify it's a multipart request
                let is_multipart = req.headers.get("content-type")
                    .map(|ct| ct.to_str().unwrap_or("").starts_with("multipart/form-data"))
                    .unwrap_or(false);
                
                if !is_multipart {
                    return false;
                }
                
                // Parse multipart body and check file content
                let body = std::str::from_utf8(&req.body).unwrap_or("");
                
                // Verify the form fields are present
                let has_chain_task_id = body.contains(&format!("name=\"chainTaskId\"\r\n\r\n{}", TEST_TASK_ID));
                let has_deal_id = body.contains(&format!("name=\"dealId\"\r\n\r\n{}", TEST_DEAL_ID));
                let has_task_index = body.contains("name=\"taskIndex\"\r\n\r\n1");
                let has_determinist_hash = body.contains(&format!("name=\"deterministHash\"\r\n\r\n{}", TEST_DETERMINIST_HASH));
                let has_enclave_signature = body.contains(&format!("name=\"enclaveSignature\"\r\n\r\n{}", TEST_ENCLAVE_SIGNATURE));
                
                // Verify the file content is present
                let file_content_str = std::str::from_utf8(&expected_content).unwrap();
                let has_file_content = body.contains(file_content_str);
                
                // Verify filename
                let has_filename = body.contains("filename=\"test_result.zip\"");
                
                // Verify content type
                let has_zip_content_type = body.contains("Content-Type: application/zip");
                
                has_chain_task_id && has_deal_id && has_task_index && 
                has_determinist_hash && has_enclave_signature && 
                has_file_content && has_filename && has_zip_content_type
            })
            .respond_with(ResponseTemplate::new(200).set_body_string(TEST_IPFS_LINK))
            .mount(&mock_server)
            .await;

        let result = tokio::task::spawn_blocking(move || {
            let client = ResultProxyApiClient::new(&mock_server.uri());
            let file = File::open(temp_file.path()).unwrap();
            client.upload_to_ipfs_streaming(TEST_TOKEN, &expected_model, file)
        })
        .await
        .expect("Task panicked");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TEST_IPFS_LINK);
    }
    
    #[tokio::test]
    async fn upload_to_ipfs_streaming_returns_error_for_all_error_codes() {
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
            let zip_content = b"test streaming content";
            
            // Create a temporary file for testing
            let mut temp_file = tempfile::NamedTempFile::new().unwrap();
            temp_file.write_all(zip_content).unwrap();
            temp_file.flush().unwrap();
            
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/results"))
                .respond_with(
                    ResponseTemplate::new(status_code)
                        .set_body_string(format!("{} Error", status_code)),
                )
                .mount(&mock_server)
                .await;

            let result = tokio::task::spawn_blocking(move || {
                let client = ResultProxyApiClient::new(&mock_server.uri());
                let model = StreamingResultModel::default();
                let file = File::open(temp_file.path()).unwrap();
                client.upload_to_ipfs_streaming(TEST_TOKEN, &model, file)
            })
            .await
            .expect("Task panicked");

            assert!(
                result.is_err(),
                "Expected error for status code {} ({})",
                status_code,
                description
            );
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains(expected_error_contains),
                "Error message should contain '{}' for status code {} ({}), but got: {}",
                expected_error_contains,
                status_code,
                description,
                error
            );
        }
    }
    // endregion
}

    