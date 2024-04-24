use reqwest::{Client, Error};
use tokio;
use encode::EncryptionMethod;

mod fetch;
mod encode;


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

    //  ASCII Shift table
    let ascii_shift_question = EncryptionMethod::from_str(&swapped_pairs.encryption_method);
    let ascii_shift_to_decrypt: Vec<&str> = swapped_pairs.encrypted_path.split("task_").collect();
    let ascii_shift = fetch::fetch_next_challenge(&client, base_url, "task_", ascii_shift_to_decrypt.get(1).unwrap(), ascii_shift_question).await?;
    println!("[ASCII SHIFTING] Next response after decryption: {}", serde_json::to_string_pretty(&ascii_shift).unwrap());

    // hex decoded, encrypted with XOR, hex encoded again. key: secret
    let ascii_shift_question = EncryptionMethod::from_str(&ascii_shift.encryption_method);
    let ascii_shift_to_decrypt: Vec<&str> = ascii_shift.encrypted_path.split("task_").collect();
    let complex_hex = fetch::fetch_next_challenge(&client, base_url, "task_", ascii_shift_to_decrypt.get(1).unwrap(), ascii_shift_question).await?;
    println!("[Complex: Hex->XOR->HEX w. key {}] Next response after decryption: {}", "secret", serde_json::to_string_pretty(&complex_hex).unwrap());

    Ok(())
}
