use reqwest::{Client, Error, };
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use crate::encode::{ApiResponse, EncryptionMethod};

pub async fn fetch_next_challenge(client: &Client, base_url: &str, prefix_path: &str, path: &str, method: EncryptionMethod) -> Result<ApiResponse, Error> {

    // Decrypt the path first
    let decrypted_path = method.decrypt(path);

    let iter = utf8_percent_encode(&decrypted_path, NON_ALPHANUMERIC);
    let encoded: String = iter.collect();

    // Perform the GET request to the decrypted path
    let url = format!("{}{}{}", base_url, prefix_path, encoded);
    println!("[FETCH] URL for next task: {}", url);

    let response = client.get(&url).send().await?;
    println!("[FETCH] Response {}", response.status());

    return response.json::<ApiResponse>().await;
}


