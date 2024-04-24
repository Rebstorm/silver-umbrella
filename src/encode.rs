use serde::{Deserialize, Serialize};
use rmp_serde;

#[cfg(test)]
mod tests {
    use crate::encode::EncryptionMethod;

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
    fn test_decrypt_ascii_shift() {
        let encoded = ",,]+111"; // This is 'Hello, World!' in Base64
        let method = EncryptionMethod::from_str("added -8 to ASCII value of each character");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "$$U#)))");
    }

    #[test]
    fn test_decrypt_ascii_shift_positive() {
        let encoded = ",,]+111"; // This is 'Hello, World!' in Base64
        let method = EncryptionMethod::from_str("added 8 to ASCII value of each character");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "44e3999");
    }

    #[test]
    fn test_decrypt_ascii_shift_neutral() {
        let encoded = ",,]+111"; // This is 'Hello, World!' in Base64
        let method = EncryptionMethod::from_str("added 0 to ASCII value of each character");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, ",,]+111");
    }


    #[test]
    fn test_decrypt_xor() {
        let encoded = "28b78c92032baa34fcdfc42c47ba81";  // This should be an actual hex-encoded string
        let method = EncryptionMethod::from_str("hex decoded, encrypted with XOR, hex encoded again. key: secret");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "5bd2efe0665fd9519fada15834dfe2");  // Adjust according to actual expected output
    }

    #[test]
    fn test_decrypt_scrambled() {
        let encoded = "ef48f1a4a89bb295deba12db70bde81";  // Placeholder, replace with actual scrambled data
        let method = EncryptionMethod::from_str("scrambled! original positions as base64 encoded messagepack: 3AAfFAcPFxYbAhgRAwAICgweBQEEDhwVGgYQEg0JGRMdCw==");
        let decoded = method.decrypt(encoded);

        assert_eq!(decoded, "9da8e5dfbbb120b4ba7ee1f84d21a89");  // Adjust expected output
    }

}


#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResponse {
    challenger: String,
    pub encrypted_path: String,
    pub encryption_method: String,
    expires_in: String,
    hint: String,
    instructions: String,
    level: i32,
}


#[derive(Debug)]
pub enum EncryptionMethod {
    None,
    Base64,
    SwappedPairs,
    AsciiManipulation(i32),
    XOR(String),
    Unencrypted,
    Scrambled(Vec<usize>)
}

impl EncryptionMethod {
    pub fn from_str(method: &str) -> Self {

        // Base64 Scrambled!
        if method.starts_with("scrambled!") {
            let data = method.trim_start_matches("scrambled! original positions as base64 encoded messagepack: ");
            let decoded_data = base64::decode(data).unwrap_or_default();
            let positions: Vec<usize> = rmp_serde::from_read_ref(&decoded_data).unwrap_or_default();
            return EncryptionMethod::Scrambled(positions);
        }

        // The weird bit shift challenge.
        if method.starts_with("added ") && method.ends_with(" to ASCII value of each character") {
            if let Some(amount_str) = method.strip_prefix("added ").and_then(|s| s.strip_suffix(" to ASCII value of each character")) {
                if let Ok(amount) = amount_str.parse::<i32>() {
                    return EncryptionMethod::AsciiManipulation(amount);
                }
            }
        }

        // Complex HEX->XOR->HEX w. Key
        if method.starts_with("hex decoded, encrypted with XOR, hex encoded again. key: ") {
            let key = method.trim_start_matches("hex decoded, encrypted with XOR, hex encoded again. key: ");
            return EncryptionMethod::XOR(key.to_string());
        }

        match method {
            "nothing" | "none" => EncryptionMethod::None,
            "encoded as base64" | "base64" => EncryptionMethod::Base64,
            "swapped every pair of characters" | "swapped pairs" => EncryptionMethod::SwappedPairs,
            _ => EncryptionMethod::Unencrypted,
        }
    }

    pub fn decrypt(&self, encrypted: &str) -> String {
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
            EncryptionMethod::AsciiManipulation(amount) => {
                encrypted
                    .chars()
                    .map(|c| {
                        let shifted = (c as u8 as i32 - amount) as u8; // Subtract the amount from the ASCII value
                        shifted as char
                    })
                    .collect()
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

            EncryptionMethod::XOR(key) => {
                // Step 1: Hex decode
                let bytes = hex::decode(encrypted).unwrap_or_default();  // Decode hex to bytes

                // Step 2: XOR decrypt using the key
                let key_bytes = key.as_bytes();
                let decrypted_bytes: Vec<u8> = bytes
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])  // Perform XOR with the key
                    .collect();


                // Step 3: Hex encode the result
                return hex::encode(decrypted_bytes)  // Re-encode to hex
            },

            EncryptionMethod::Scrambled(positions) => {
                if positions.len() != encrypted.len() {
                    return "Error: Length mismatch".to_string();
                }
                let mut result = vec![' '; encrypted.len()];  // Prepare a vector with spaces
                for (pos, &ch_index) in positions.iter().enumerate() {
                    result[ch_index] = encrypted.chars().nth(pos).unwrap_or_default();  // Place characters at their indexed positions
                }
                result.into_iter().collect()
            },
        }
    }
}
