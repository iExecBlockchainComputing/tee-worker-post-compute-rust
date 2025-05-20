use crate::compute::utils::hash_utils::concatenate_and_hash;
use crate::compute::{computed_file::ComputedFile, utils::hash_utils::keccak256};
use log::error;
use sha256::digest;
use std::{
    fs::{self, DirEntry},
    io::Error,
    path::Path,
};

pub fn compute_web3_result_digest(computed_file: &ComputedFile) -> String {
    if computed_file.task_id.is_none() {
        return "".to_string();
    }

    let callback_data = match &computed_file.callback_data {
        Some(data) if !data.is_empty() => data,
        _ => {
            error!(
                "Failed to compute_web3_result_digest (callback_data empty) [chainTaskId:{}]",
                computed_file.task_id.as_ref().unwrap()
            );
            return "".to_string();
        }
    };

    keccak256(callback_data.clone())
}

pub fn compute_web2_result_digest(computed_file: &ComputedFile) -> String {
    let deterministic_output_path = match &computed_file.deterministic_output_path {
        Some(path) => {
            if path.is_empty() {
                error!(
                    "Failed to compute_web2_result_digest (deterministic_output_path empty) [chainTaskId:{}]",
                    computed_file.task_id.as_ref().unwrap()
                );
                return "".to_string();
            } else {
                path
            }
        }
        _ => {
            return "".to_string();
        }
    };

    let host_deterministic_output_path =
        Path::new(deterministic_output_path.trim_start_matches('/'));

    if !host_deterministic_output_path.exists() {
        error!(
            "Failed to compute_web2_result_digest (host_deterministic_output_path missing) [chainTaskId:{}]",
            computed_file.task_id.as_ref().unwrap()
        );
        return "".to_string();
    }

    get_file_tree_sha256(host_deterministic_output_path)
}

pub fn sha256_file(file_path: &Path) -> String {
    let data = match fs::read(file_path) {
        Ok(data) => {
            if data.is_empty() {
                error!(
                    "Null file content [file_path:{}]",
                    file_path.to_str().unwrap()
                );
                return "".to_string();
            } else {
                data
            }
        }
        Err(_) => {
            error!(
                "Failed to read file [file_path:{}]",
                file_path.to_str().unwrap()
            );
            return "".to_string();
        }
    };
    format!("0x{}", digest(&data))
}

pub fn get_file_tree_sha256(file_tree_path: &Path) -> String {
    if !file_tree_path.exists() {
        return "".to_string();
    }
    //fileTree is a leaf, a single file
    if !file_tree_path.is_dir() {
        return sha256_file(file_tree_path);
    }
    //fileTree is a tree, with multiple files
    let mut entries = match fs::read_dir(file_tree_path) {
        Ok(read_dir) => match read_dir.collect::<Result<Vec<DirEntry>, Error>>() {
            Ok(entries) => {
                if entries.is_empty() {
                    return "".to_string();
                } else {
                    entries
                }
            }
            Err(_) => return "".to_string(),
        },
        Err(_) => return "".to_string(),
    };
    // /!\ files MUST be sorted to ensure final concatenateAndHash(..) is always the same (order matters)
    entries.sort_by_key(|entry| entry.path());

    let mut hashes_vec = Vec::new();
    entries.iter().for_each(|entry| {
        let path = entry.path();
        let hash = sha256_file(&path);
        hashes_vec.push(hash);
    });
    let hashes: Vec<&str> = hashes_vec.iter().map(|s| s.as_str()).collect();
    let hashes = hashes.as_slice();
    concatenate_and_hash(hashes)
}
