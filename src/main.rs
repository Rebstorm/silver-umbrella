use reqwest::{Client, Error};
use serde::{Deserialize, Serialize};
use serde::de::Unexpected::Str;
use tokio;

mod fetch;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_base64() {
        let encoded = "MTYxZjI4MDRmMzI3NTFhYjFiMjZhOTUxY2IxMDkzYzU="; // This is 'Hello, World!' in Base64
        let method = EncryptionMethod::from_str("base64");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "161f2804f32751ab1b26a951cb1093c5");
    }

    #[test]
    fn test_decrypt_swapped() {
        let encoded = "abcdefgh"; // This is 'Hello, World!' in Base64
        let method = EncryptionMethod::from_str("swapped pairs");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "badcfehg");
    }

    #[test]
    fn test_decrypt_minus8ascii() {
        let encoded = ",,]+111"; // This is 'Hello, World!' in Base64
        let method = EncryptionMethod::from_str("added -8 to ASCII value of each character");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "$$U#)))");
    }
}


#[derive(Debug, Deserialize, Serialize)]
struct ApiResponse {
    challenger: String,
    encrypted_path: String,
    encryption_method: String,
    expires_in: String,
    hint: String,
    instructions: String,
    level: i32,
}


#[derive(Debug)]
enum EncryptionMethod {
    None,
    Base64,
    SwappedPairs,
    SubtractEight,
    Unencrypted
}

impl EncryptionMethod {
    fn from_str(method: &str) -> Self {
        match method {
            "nothing" | "none" => EncryptionMethod::None,
            "encoded as base64" | "base64" => EncryptionMethod::Base64,
            "swapped every pair of characters" | "swapped pairs" => EncryptionMethod::SwappedPairs,
            "added -8 to ASCII value of each character" | "subtracted 8" => EncryptionMethod::SubtractEight,
            _ => EncryptionMethod::Unencrypted,
        }
    }

    fn decrypt(&self, encrypted: &str) -> String {
        match self {
            EncryptionMethod::None | EncryptionMethod::Unencrypted => encrypted.to_string(),
            EncryptionMethod::Base64 => {
                match base64::decode(encrypted.as_bytes()) {  // Here, `encrypted` is a &str
                    Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                    Err(_) => {
                        eprintln!("Error decoding base64 path.");
                        String::new()
                    },
                }
            },
            EncryptionMethod::SwappedPairs => {
                let mut swap = String::with_capacity(encrypted.len());
                let mut chars = encrypted.chars().peekable();

                while let Some(c1) = chars.next() {
                    if let Some(c2) = chars.next() {
                        // Swap the pairs of characters
                        swap.push(c2);
                        swap.push(c1);
                    } else {
                        // If there's an odd number of characters, append the last character as is
                        swap.push(c1);
                    }
                }

                swap
            },
            EncryptionMethod::SubtractEight => {
                encrypted.chars().map(|c| ((c as u8).wrapping_sub(8)) as char).collect()
            }

        }
    }
}



#[tokio::main]
async fn main() -> Result<(), Error> {
    let base_url = "https://ciphersprint.pulley.com/";
    let initial_path = "paul@jacks.se";
    let client = Client::new();

    // First call.
    let initial_response = fetch::fetch_next_challenge(&client, base_url, "", initial_path, EncryptionMethod::Unencrypted).await?;
    println!("[START] Initial response: {}", serde_json::to_string_pretty(&initial_response).unwrap());

    // First task.
    let first_response = fetch::fetch_next_challenge(&client, base_url, "" , &initial_response.encrypted_path, EncryptionMethod::None).await?;
    println!("[NONE] Next response after decryption: {}", serde_json::to_string_pretty(&first_response).unwrap());

    // Base64.
    let base64_question = EncryptionMethod::from_str(&first_response.encryption_method);
    let parsed_key_to_decrypt: Vec<&str> = first_response.encrypted_path.split("task_").collect();
    let base64encryption = fetch::fetch_next_challenge(&client, base_url, "task_", parsed_key_to_decrypt.get(1).unwrap(), base64_question).await?;
    println!("[BASE64] Next response after decryption: {}", serde_json::to_string_pretty(&base64encryption).unwrap());

    // Swapped Pairs.
    let swapped_question = EncryptionMethod::from_str(&base64encryption.encryption_method);
    let swapped_keys_to_decrypt: Vec<&str> = base64encryption.encrypted_path.split("task_").collect();
    let swapped_pairs = fetch::fetch_next_challenge(&client, base_url, "task_", swapped_keys_to_decrypt.get(1).unwrap(), swapped_question).await?;
    println!("[SWAPPED PAIRS] Next response after decryption: {}", serde_json::to_string_pretty(&swapped_pairs).unwrap());

    // -8 ASCII table
    let ascii_minus_8_question = EncryptionMethod::from_str(&base64encryption.encryption_method);
    let ascii_minus_8_to_decrypt: Vec<&str> = swapped_pairs.encrypted_path.split("task_").collect();
    let swapped_pairs = fetch::fetch_next_challenge(&client, base_url, "task_", ascii_minus_8_to_decrypt.get(1).unwrap(), ascii_minus_8_question).await?;
    println!("[MINUS 8 ASCII] Next response after decryption: {}", serde_json::to_string_pretty(&swapped_pairs).unwrap());



    Ok(())
}
