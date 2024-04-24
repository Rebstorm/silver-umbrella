use reqwest::{Client, Error,};
use crate::{ApiResponse, EncryptionMethod};

pub async fn fetch_next_challenge(client: &Client, base_url: &str, prefix_path: &str, path: &str, method: EncryptionMethod) -> Result<ApiResponse, Error> {


    // Decrypt the path first
    let decrypted_path = method.decrypt(path);



    // Perform the GET request to the decrypted path
    let url = format!("{}{}{}", base_url, prefix_path, decrypted_path);
    println!("{}", url);
    client.get(&url).send().await?.json::<ApiResponse>().await
}