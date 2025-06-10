use serde::{Deserialize, Serialize};

const EMPTY_HEX_STRING_32: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";
const EMPTY_WEB3_SIG: &str = "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultModel {
    pub chain_task_id: String,
    pub deal_id: String,
    pub task_index: i32,
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

pub struct ResultProxyApiClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl ResultProxyApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: reqwest::blocking::Client::new(),
        }
    }

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
