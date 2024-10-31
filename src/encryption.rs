use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};
use zeroize::Zeroize;
use base64::{engine::general_purpose, Engine};
use regex::Regex;

// Derive encryption key using Argon2
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::b64_encode(salt).expect("Failed to generate salt string");
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");
    let hash_bytes = hash.hash.expect("Hash missing in PasswordHash structure");

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    key
}

// Encrypt the message using ChaCha20Poly1305
pub fn encrypt_message(plain_text: &str, password: &str) -> Result<String, &'static str> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_data = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|_| "Encryption error")?;

    key.zeroize();

    Ok(format!(
        "{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce_bytes),
        hex::encode(encrypted_data)
    ))
}

// Decrypt the message using ChaCha20Poly1305
pub fn decrypt_message(encrypted_text: &str, password: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted message format");
    }

    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error")?;
    let nonce_bytes = hex::decode(parts[1]).map_err(|_| "Decryption error")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error")?;

    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| "Decryption error")?;

    key.zeroize();

    String::from_utf8(decrypted_data).map_err(|_| "Decryption error")
}

/// Helper function to check if the message is a valid PGP-encrypted message or a public key block
pub fn is_message_encrypted(message: &str) -> bool {
    // Define markers for both types of blocks
    const MESSAGE_BEGIN_MARKER: &str = "-----BEGIN PGP MESSAGE-----";
    const MESSAGE_END_MARKER: &str = "-----END PGP MESSAGE-----";
    const KEY_BEGIN_MARKER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const KEY_END_MARKER: &str = "-----END PGP PUBLIC KEY BLOCK-----";

    // Determine which markers are present
    let begin_marker = if message.contains(MESSAGE_BEGIN_MARKER) {
        MESSAGE_BEGIN_MARKER
    } else if message.contains(KEY_BEGIN_MARKER) {
        KEY_BEGIN_MARKER
    } else {
        println!("Missing or unrecognized begin marker.");
        return false;
    };

    let end_marker = if message.contains(MESSAGE_END_MARKER) {
        MESSAGE_END_MARKER
    } else if message.contains(KEY_END_MARKER) {
        KEY_END_MARKER
    } else {
        println!("Missing or unrecognized end marker.");
        return false;
    };

    // Locate the markers
    let begin_marker_pos = message.find(begin_marker);
    let end_marker_pos = message.find(end_marker);

    if let (Some(begin), Some(end)) = (begin_marker_pos, end_marker_pos) {
        if begin < end {
            // Extract content between the markers
            let content = &message[begin + begin_marker.len()..end];

            // Remove whitespace and line breaks, and clean non-base64 chars
            let cleaned_content: String = content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join("");


            // Strip out any non-Base64 characters after the valid Base64 part
            let base64_content = cleaned_content.split('=').next().unwrap_or("");

            // Ensure padding is correct
            let padding = if base64_content.len() % 4 == 2 {
                "=="
            } else if base64_content.len() % 4 == 3 {
                "="
            } else {
                ""
            };

            // Append correct padding to the Base64 string
            let final_base64_content = format!("{}{}", base64_content, padding);

            // Validate the Base64 string using regex
            let base64_pattern = r"^[A-Za-z0-9+/]+={0,2}$";
            let is_valid_base64 = Regex::new(base64_pattern)
                .unwrap()
                .is_match(&final_base64_content);

            if !is_valid_base64 {
                println!("Invalid Base64 format detected.");
                return false;
            }

            // Attempt Base64 decoding
            return match general_purpose::STANDARD.decode(&final_base64_content) {
                Ok(_) => true,
                Err(err) => {
                    println!("Base64 decoding error: {}", err); // Debugging
                    false
                }
            };
        } else {
            println!("Markers out of order.");
        }
    } else {
        println!("Missing markers.");
    }

    false
}