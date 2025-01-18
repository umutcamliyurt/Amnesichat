use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Derive encryption key from room room_id using SHA-256
pub fn derive_key(room_id: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(room_id.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// Encrypt the message using ChaCha20Poly1305
pub fn encrypt_message(plain_text: &str, room_id: &str) -> Result<String, &'static str> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(room_id, &salt);
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
pub fn decrypt_message(encrypted_text: &str, room_id: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted message format");
    }

    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error")?;
    let nonce_bytes = hex::decode(parts[1]).map_err(|_| "Decryption error")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error")?;

    let mut key = derive_key(room_id, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| "Decryption error")?;

    key.zeroize();

    String::from_utf8(decrypted_data).map_err(|_| "Decryption error")
}

pub fn is_message_encrypted(message: &str) -> bool {
    // Define markers for both types of blocks
    const ENCRYPTED_BEGIN_MARKER: &str = "-----BEGIN ENCRYPTED MESSAGE-----";
    const ENCRYPTED_END_MARKER: &str = "-----END ENCRYPTED MESSAGE-----";
    const DILITHIUM_PUBLIC_KEY_PREFIX: &str = "DILITHIUM_PUBLIC_KEY:";
    const EDDSA_PUBLIC_KEY_PREFIX: &str = "EDDSA_PUBLIC_KEY:";
    const ECDH_KEY_EXCHANGE_PREFIX: &str = "ECDH_PUBLIC_KEY:";
    const KYBER_KEY_EXCHANGE_PREFIX: &str = "KYBER_PUBLIC_KEY:";

    // Check for key exchange prefixes and handle them separately
    if message.starts_with(DILITHIUM_PUBLIC_KEY_PREFIX)
        || message.starts_with(EDDSA_PUBLIC_KEY_PREFIX)
        || message.starts_with(ECDH_KEY_EXCHANGE_PREFIX)
        || message.starts_with(KYBER_KEY_EXCHANGE_PREFIX)
    {
        // Allow key exchange messages and return true
        return true;
    }

    // Determine which markers are present for PGP encryption or key block
    let begin_marker = if message.contains(ENCRYPTED_BEGIN_MARKER) { // Check for encrypted message
        ENCRYPTED_BEGIN_MARKER
    } else {
        println!("Missing or unrecognized begin marker.");
        return false;
    };

    let end_marker = if message.contains(ENCRYPTED_END_MARKER) { // Check for encrypted message
        ENCRYPTED_END_MARKER
    } else {
        println!("Missing or unrecognized end marker.");
        return false;
    };

    // Locate the markers
    let begin_marker_pos = message.find(begin_marker);
    let end_marker_pos = message.find(end_marker);

    if let (Some(begin), Some(end)) = (begin_marker_pos, end_marker_pos) {
        if begin < end {
            return true;
        } else {
            println!("Markers out of order.");
        }
    } else {
        println!("Missing markers.");
    }

    false
}