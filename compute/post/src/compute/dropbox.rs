//! Dropbox upload service for handling file uploads to Dropbox storage.
//!
//! This module provides a small utility for uploading computation results to
//! Dropbox using the Content API "files/upload" HTTPS endpoint. It focuses on
//! correctness, explicit error mapping to `ReplicateStatusCause`, and testability
//! (the base URL is injectable for mocking).

use log::{error, info};
#[cfg(test)]
use mockall::automock;
use reqwest::blocking::Client;
use serde::Deserialize;
use shared::errors::ReplicateStatusCause;
use std::{fs, path::Path};

/// Default Dropbox Content API base URL used for uploads.
pub const DROPBOX_CONTENT_BASE_URL: &str = "https://content.dropboxapi.com";

/// REST path for the Dropbox "files/upload" endpoint.
const FILES_UPLOAD_PATH: &str = "/2/files/upload";

/// Service for handling Dropbox file uploads.
///
/// This is a lightweight utility type. Construct with `let service = DropboxService;` and call
/// [`DropboxService::upload_file`].
///
/// # Example
///
/// ```rust
/// use tee_worker_post_compute::compute::dropbox::{DropboxUploader, DropboxService, DROPBOX_CONTENT_BASE_URL};
///
/// let service = DropboxService;
/// let result = service.upload_file(
///     "your-access-token",
///     "/path/to/local/file.zip",
///     "/results/remote-file.zip",
///     DROPBOX_CONTENT_BASE_URL,
/// );
/// ```
pub struct DropboxService;

#[cfg_attr(test, automock)]
pub trait DropboxUploader {
    fn upload_file(
        &self,
        access_token: &str,
        local_file_path: &str,
        dropbox_path: &str,
        content_base_url: &str,
    ) -> Result<String, ReplicateStatusCause>;
}

#[derive(Deserialize, Debug)]
struct UploadResponse {
    path_display: Option<String>,
}

impl DropboxUploader for DropboxService {
    /// Uploads a file to Dropbox.
    ///
    /// Optimized for small to medium-sized files that can be sent in a single request.
    /// For very large files (> 150 MiB), use Dropbox upload sessions (chunked upload).
    ///
    /// # Arguments
    ///
    /// - `access_token`: Dropbox API access token (Bearer token)
    /// - `local_file_path`: Local path to the file to upload
    /// - `dropbox_path`: Destination path in Dropbox (e.g., "/results/file.zip")
    /// - `content_base_url`: Base URL for the Content API (override in tests)
    ///
    /// # Returns
    ///
    /// - `Ok(String)`: The display path of the uploaded file in Dropbox
    /// - `Err(ReplicateStatusCause)`: When any step of the upload fails
    ///
    /// # Errors
    ///
    /// Returns `PostComputeResultFileNotFound` if the local file does not exist.
    /// Returns `PostComputeDropboxUploadFailed` for any HTTP or API error (including 401).
    ///
    /// # Example
    ///
    /// ```rust
    /// use tee_worker_post_compute::compute::dropbox::{DropboxUploader, DropboxService, DROPBOX_CONTENT_BASE_URL};
    ///
    /// let service = DropboxService;
    /// let result = service.upload_file(
    ///     "access-token",
    ///     "/tmp/file.zip",
    ///     "/results/file.zip",
    ///     DROPBOX_CONTENT_BASE_URL,
    /// );
    /// // Handle result: Ok(path) | Err(cause)
    /// ```
    fn upload_file(
        &self,
        access_token: &str,
        local_file_path: &str,
        dropbox_path: &str,
        content_base_url: &str,
    ) -> Result<String, ReplicateStatusCause> {
        // Validate local file exists
        let path = Path::new(local_file_path);
        if !path.exists() {
            error!("Local file not found for Dropbox upload [path:{local_file_path}]");
            return Err(ReplicateStatusCause::PostComputeResultFileNotFound);
        }

        let content = fs::read(path).map_err(|e| {
            error!("Failed to read file for Dropbox upload [path:{local_file_path}, error:{e}]");
            ReplicateStatusCause::PostComputeDropboxUploadFailed
        })?;

        let api_arg_header = serde_json::json!({
            "autorename": false,
            "mode": "add",
            "mute": false,
            "path": dropbox_path,
            "strict_conflict": false
        })
        .to_string();

        let url = format!("{content_base_url}{FILES_UPLOAD_PATH}");
        let response = Client::new()
            .post(url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/octet-stream")
            .header("Dropbox-API-Arg", api_arg_header)
            .body(content)
            .send();

        match response {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    match resp.json::<UploadResponse>() {
                        Ok(meta) => {
                            let path = meta
                                .path_display
                                .unwrap_or_else(|| dropbox_path.to_string());
                            info!("Successfully uploaded to Dropbox [path:{path}]");
                            Ok(path)
                        }
                        Err(e) => {
                            error!("Failed to parse Dropbox response: {e}");
                            Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
                        }
                    }
                } else if status.as_u16() == 401 {
                    error!("Authentication failed - invalid or expired token");
                    Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
                } else {
                    let body = resp.text().unwrap_or_default();
                    error!("Dropbox upload failed [status:{status}, body:{body}]");
                    Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
                }
            }
            Err(e) => {
                error!("HTTP error calling Dropbox upload API: {e}");
                Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn create_test_computed_file() -> String {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test file content").unwrap();
        let (_file, path_buf) = temp_file.keep().unwrap();
        path_buf.to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn upload_returns_dropbox_path_when_server_returns_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "path_display": "/results/uploaded.zip",
        });

        Mock::given(method("POST"))
            .and(path(FILES_UPLOAD_PATH))
            .and(header("Authorization", "Bearer valid-token"))
            .and(header("Content-Type", "application/octet-stream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .mount(&mock_server)
            .await;

        let file_path = create_test_computed_file();

        let base = mock_server.uri();
        let result = tokio::task::spawn_blocking(move || {
            DropboxService.upload_file("valid-token", &file_path, "/results/uploaded.zip", &base)
        })
        .await
        .expect("The upload_file task panicked. Expected the DropboxService to successfully upload the file and return the Dropbox path, but the task did not complete as expected.");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/results/uploaded.zip");

        let requests = mock_server.received_requests().await.unwrap();
        assert!(!requests.is_empty());

        let expected_args = serde_json::json!({
            "mode": "add",
            "autorename": false,
            "mute": false,
            "path": "/results/uploaded.zip",
            "strict_conflict": false
        })
        .to_string();
        let arg_header = requests[0]
            .headers
            .get("Dropbox-API-Arg")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert_eq!(arg_header, expected_args);
    }

    #[test]
    fn upload_file_returns_error_when_local_file_not_found() {
        let service = DropboxService;
        let result = service.upload_file(
            "fake-token",
            "/non/existent/file.zip",
            "/results/test.zip",
            DROPBOX_CONTENT_BASE_URL,
        );
        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeResultFileNotFound)
        );
    }

    #[tokio::test]
    async fn upload_returns_error_when_server_returns_unauthorized() {
        let mock_server = MockServer::start().await;

        let error_response = serde_json::json!({
            "error_summary": "invalid_access_token",
            "error": { ".tag": "invalid_access_token" }
        });

        Mock::given(method("POST"))
            .and(path(FILES_UPLOAD_PATH))
            .and(header("Authorization", "Bearer invalid-token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("content-type", "application/json")
                    .set_body_json(error_response),
            )
            .mount(&mock_server)
            .await;

        let file_path = create_test_computed_file();

        let base = mock_server.uri();
        let result = tokio::task::spawn_blocking(move || {
            DropboxService.upload_file("invalid-token", &file_path, "/results/uploaded.zip", &base)
        })
        .await
        .expect("Task panicked: expected DropboxService.upload_file to return an error indicating unauthorized access (PostComputeDropboxUploadFailed), but the task did not complete successfully");

        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
        );
    }

    #[tokio::test]
    async fn upload_returns_error_when_server_returns_500() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(FILES_UPLOAD_PATH))
            .and(header("Authorization", "Bearer token"))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("content-type", "application/json")
                    .set_body_string("Internal Server Error"),
            )
            .mount(&mock_server)
            .await;

        let file_path = create_test_computed_file();

        let base = mock_server.uri();
        let result = tokio::task::spawn_blocking(move || {
            DropboxService.upload_file("token", &file_path, "/results/uploaded.zip", &base)
        })
        .await
        .expect("Task panicked: expected DropboxService.upload_file to return an error indicating a server error (PostComputeDropboxUploadFailed), but the task did not complete successfully");

        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
        );
    }

    #[tokio::test]
    async fn upload_returns_error_when_response_json_is_invalid() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(FILES_UPLOAD_PATH))
            .and(header("Authorization", "Bearer token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("not-json"),
            )
            .mount(&mock_server)
            .await;

        let file_path = create_test_computed_file();

        let base = mock_server.uri();
        let result = tokio::task::spawn_blocking(move || {
            DropboxService.upload_file("token", &file_path, "/results/bad.json", &base)
        })
        .await
        .expect("Task panicked: expected upload_file to return an error due to invalid JSON response, but the task did not complete successfully");

        assert_eq!(
            result,
            Err(ReplicateStatusCause::PostComputeDropboxUploadFailed)
        );
    }
}
