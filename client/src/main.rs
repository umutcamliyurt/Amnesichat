mod gui;
use crate::gui::run_gui;
use oqs::*;
use oqs::sig::{Sig, PublicKey, SecretKey, Algorithm as SigAlgorithm};
use oqs::kem::{Kem, Algorithm};
use std::fs::File;
use std::process::Command;
use std::{thread, time::Duration};
use base64::{Engine, engine::general_purpose};
use hex;
use std::io::{self, Write, Read};
use rpassword::read_password;
use reqwest::blocking::{Client, Response};
use std::result::Result;
use std::{
    collections::HashSet,
    error::Error,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey as Ed25519PrivateKey, VerifyingKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier as Ed25519Verifier};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

// Function to get the raw bytes from PublicKey
fn get_raw_bytes_public_key(pk: &PublicKey) -> &[u8] {
    pk.as_ref() // Directly return the raw bytes
}

// Function to get the raw bytes from SecretKey
fn get_raw_bytes_secret_key(sk: &SecretKey) -> &[u8] {
    sk.as_ref() // Directly return the raw bytes
}

fn save_dilithium_keys_to_file(public_key: &PublicKey, secret_key: &SecretKey, user: &str, password: &str) -> io::Result<()> {
    // Use safe methods to access the bytes
    let pub_bytes = get_raw_bytes_public_key(public_key);
    let sec_bytes = get_raw_bytes_secret_key(secret_key);

    // Base64 encode the keys before saving using the Engine::encode method
    let pub_base64 = general_purpose::STANDARD.encode(&pub_bytes);
    let sec_base64 = general_purpose::STANDARD.encode(&sec_bytes);

    // Encrypt the base64-encoded keys
    let encrypted_pub = encrypt_data(&pub_base64, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {}", e)))?;
    let encrypted_sec = encrypt_data(&sec_base64, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {}", e)))?;

    // Save the encrypted keys to files
    let mut pub_file = File::create(format!("{}_dilithium_public_key.enc", user))?;
    pub_file.write_all(encrypted_pub.as_bytes())?;

    let mut sec_file = File::create(format!("{}_dilithium_secret_key.enc", user))?;
    sec_file.write_all(encrypted_sec.as_bytes())?;

    Ok(())
}

fn load_dilithium_keys_from_file(sigalg: &Sig, user: &str, password: &str) -> io::Result<(PublicKey, SecretKey)> {
    // Load the encrypted public key from file
    let mut pub_file = File::open(format!("{}_dilithium_public_key.enc", user))?;
    let mut pub_encrypted = String::new();
    pub_file.read_to_string(&mut pub_encrypted)?;

    // Load the encrypted secret key from file
    let mut sec_file = File::open(format!("{}_dilithium_secret_key.enc", user))?;
    let mut sec_encrypted = String::new();
    sec_file.read_to_string(&mut sec_encrypted)?;

    // Decrypt the base64-encoded keys using the provided password
    let decrypted_pub = decrypt_data(&pub_encrypted, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {}", e)))?;
    let decrypted_sec = decrypt_data(&sec_encrypted, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {}", e)))?;

    // Decode the decrypted Base64-encoded keys
    let pub_bytes = general_purpose::STANDARD.decode(&decrypted_pub)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to decode public key"))?;
    let sec_bytes = general_purpose::STANDARD.decode(&decrypted_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to decode secret key"))?;

    // Create public and secret key objects from the byte data
    let public_key_ref = sigalg
        .public_key_from_bytes(&pub_bytes)
        .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid public key data"))?;
    let secret_key_ref = sigalg
        .secret_key_from_bytes(&sec_bytes)
        .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid secret key data"))?;

    // Clone the references to get owned keys
    let public_key = public_key_ref.to_owned();
    let secret_key = secret_key_ref.to_owned();

    Ok((public_key, secret_key))
}

pub fn save_eddsa_keys(
    username: &str, 
    signing_key: &Ed25519PrivateKey, 
    verifying_key: &Ed25519PublicKey,
    password: &str,
) {
    // Encode private and public keys to Base64
    let private_key_base64 = general_purpose::STANDARD.encode(signing_key.as_bytes());
    let public_key_base64 = general_purpose::STANDARD.encode(verifying_key.as_bytes());

    // Encrypt both keys using the password
    let encrypted_private_key = encrypt_data(&private_key_base64, password).unwrap();
    let encrypted_public_key = encrypt_data(&public_key_base64, password).unwrap();

    // Create file names
    let priv_file_name = format!("{}_eddsa_private_key.enc", username);
    let pub_file_name = format!("{}_eddsa_public_key.enc", username);

    // Save the encrypted keys to files
    let mut priv_file = File::create(&priv_file_name).unwrap();
    priv_file.write_all(encrypted_private_key.as_bytes()).unwrap();

    let mut pub_file = File::create(&pub_file_name).unwrap();
    pub_file.write_all(encrypted_public_key.as_bytes()).unwrap();
}

pub fn load_eddsa_keys(username: &str, password: &str) -> Result<(Ed25519PrivateKey, Ed25519PublicKey), Box<dyn std::error::Error>> {
    // Create file names
    let priv_file_name = format!("{}_eddsa_private_key.enc", username);
    let pub_file_name = format!("{}_eddsa_public_key.enc", username);

    // Load and decrypt private key from file
    let mut priv_file = File::open(&priv_file_name)?;
    let mut priv_key_encrypted = String::new();
    priv_file.read_to_string(&mut priv_key_encrypted)?;
    let priv_key_decrypted = decrypt_data(&priv_key_encrypted, password)?;

    // Decode decrypted private key
    let priv_key_bytes = general_purpose::STANDARD.decode(priv_key_decrypted.trim())?;
    let priv_key_array: [u8; 32] = priv_key_bytes
        .as_slice()
        .try_into()?;
    let signing_key = Ed25519PrivateKey::from_bytes(&priv_key_array);

    // Load and decrypt public key from file
    let mut pub_file = File::open(&pub_file_name)?;
    let mut pub_key_encrypted = String::new();
    pub_file.read_to_string(&mut pub_key_encrypted)?;
    let pub_key_decrypted = decrypt_data(&pub_key_encrypted, password)?;

    // Decode decrypted public key
    let pub_key_bytes = general_purpose::STANDARD.decode(pub_key_decrypted.trim())?;
    let pub_key_array: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()?;
    let verifying_key = Ed25519PublicKey::from_bytes(&pub_key_array)?;

    // Return keys as Result
    Ok((signing_key, verifying_key))
}

fn generate_dilithium_keys(sigalg: &Sig) -> Result<(sig::PublicKey, sig::SecretKey), Box<dyn std::error::Error>> {
    let (sig_pk, sig_sk) = sigalg.keypair()?;
    Ok((sig_pk, sig_sk))
}

/// Returns a tuple containing serialized signing key and verifying key.
pub fn generate_eddsa_keys() -> (Ed25519PrivateKey, Ed25519PublicKey) {
    // Create a cryptographically secure pseudorandom number generator.
    let mut csprng = OsRng;

    // Generate 32 random bytes for the private key.
    let mut secret_key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_key_bytes);

    // Create the signing key from the random bytes.
    let signing_key = Ed25519PrivateKey::from_bytes(&secret_key_bytes);

    // Serialize the signing key and verifying key to byte arrays.
    let signing_key_bytes = signing_key.clone().to_bytes(); // 32 bytes (private key)
    let verifying_key_bytes = signing_key.verifying_key(); // 32 bytes (public key)

    (signing_key_bytes.into(), verifying_key_bytes)
}

fn key_operations_dilithium(
    sigalg: &Sig,
    username: &str,
    password: &str,
) -> Result<(PublicKey, SecretKey), Box<dyn std::error::Error>> {
    // Check if we have already saved keys for the given username; if not, generate and save them
    match load_dilithium_keys_from_file(sigalg, username, password) {
        Ok((pk, sk)) => {
            println!("Loaded {}'s Dilithium5 keys from file.", username);
            Ok((pk, sk))
        },
        Err(_) => {
            let (pk, sk) = generate_dilithium_keys(sigalg)?;
            let _ = save_dilithium_keys_to_file(&pk, &sk, username, password); // Handle result
            Ok((pk, sk))
        }
    }
}

fn key_operations_eddsa(
    username: &str,
    password: &str,
) -> Result<(Ed25519PrivateKey, [u8; 32]), Box<dyn std::error::Error>> {
    // Try to load the keys, expecting Result type from load_eddsa_keys
    let result = load_eddsa_keys(username, password);

    // If loading fails, generate and save new keys, otherwise return the loaded keys
    match result {
        Ok((sk, pk)) => {
            // Successfully loaded keys
            println!("Loaded {}'s EdDSA keys from file.", username);
            Ok((sk, pk.to_bytes()))  // Return public key and private key bytes
        },
        Err(_) => {
            // If loading failed, generate new keys and save them
            let (sk, pk) = generate_eddsa_keys();
            
            // Save the newly generated keys
            save_eddsa_keys(username, &sk, &pk, password); // Pass password to save function
            
            // Return the newly generated keys
            Ok((sk, pk.to_bytes()))
        }
    }
}

// Function to create the reqwest blocking client with HTTP proxy support via Tor
fn create_client_with_proxy(proxy: &str) -> Client {
    // The proxy is where Tor's HTTP service is running, typically 127.0.0.1:8118

    // Now, create the reqwest client with custom transport handling the proxy
    let transport = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true) // Allow invalid certificates for testing
        .proxy(reqwest::Proxy::all(proxy).unwrap()) // Route through Tor proxy
        .build()
        .unwrap();

    transport
}

// Structures for public keys and ciphertext
#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    room_id: String,
}

fn fetch_kyber_pubkey(password: &str, server_url: &str) -> Option<String> {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);
    
    let url = format!("{}/messages?room_id={}", server_url, password);
    let mut retries = 0;
    let max_retries = 3;

    loop {
        let res: Response = match client.get(&url).send() {
            Ok(response) => response,
            Err(_) => {
                retries += 1;
                if retries > max_retries {
                    return None; // Return None after 3 failed attempts
                }
                println!("Error while fetching public key. Retrying...");
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(_) => {
                    retries += 1;
                    if retries > max_retries {
                        return None;
                    }
                    println!("Error while reading response body. Retrying...");
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            if let Some(public_key_start) = body.find("KYBER_PUBLIC_KEY:") {
                let public_key = &body[public_key_start + "KYBER_PUBLIC_KEY:".len()..]; // Remove marker
                if let Some(end_data) = public_key.find("[END DATA]") {
                    return Some(public_key[0..end_data].to_string()); // Remove [END DATA] marker
                }
            }
        }

        retries += 1;
        if retries > max_retries {
            return None; // Return None after 3 failed attempts
        }

        println!("Public key not found. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

fn fetch_dilithium_pubkeys(password: &str, server_url: &str) -> Vec<String> {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);
    let mut retries = 0;
    let max_retries = 3;

    loop {
        let res: Response = match client.get(&url).send() {
            Ok(response) => response,
            Err(_) => {
                retries += 1;
                if retries > max_retries {
                    eprintln!("Failed to fetch public keys after {} retries.", max_retries);
                    return Vec::new(); // Return an empty vector on failure
                }
                println!("Error while fetching public keys. Retrying...");
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(_) => {
                    retries += 1;
                    if retries > max_retries {
                        eprintln!("Failed to read response body after {} retries.", max_retries);
                        return Vec::new();
                    }
                    println!("Error while reading response body. Retrying...");
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            let mut public_keys = Vec::new();
            for key_data in body.split("DILITHIUM_PUBLIC_KEY:") {
                if let Some(end_data) = key_data.find("[END DATA]") {
                    let key = key_data[0..end_data].trim().to_string();
                    public_keys.push(key);
                }
            }

            if !public_keys.is_empty() {
                return public_keys; // Return all valid public keys
            }
        }

        retries += 1;
        if retries > max_retries {
            eprintln!("Public keys not found after {} retries.", max_retries);
            return Vec::new(); // Return an empty vector on failure
        }

        println!("No valid public keys found in response. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

fn fetch_eddsa_pubkeys(password: &str, server_url: &str) -> Vec<String> {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);
    let mut retries = 0;
    let max_retries = 3;

    loop {
        let res: Response = match client.get(&url).send() {
            Ok(response) => response,
            Err(_) => {
                retries += 1;
                if retries > max_retries {
                    eprintln!("Failed to fetch public keys after {} retries.", max_retries);
                    return Vec::new(); // Return an empty vector on failure
                }
                println!("Error while fetching public keys. Retrying...");
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(_) => {
                    retries += 1;
                    if retries > max_retries {
                        eprintln!("Failed to read response body after {} retries.", max_retries);
                        return Vec::new();
                    }
                    println!("Error while reading response body. Retrying...");
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            let mut public_keys = Vec::new();
            for key_data in body.split("EDDSA_PUBLIC_KEY:") {
                if let Some(end_data) = key_data.find("[END DATA]") {
                    let key = key_data[0..end_data].trim().to_string();
                    public_keys.push(key);
                }
            }

            if !public_keys.is_empty() {
                return public_keys; // Return all valid public keys
            }
        }

        retries += 1;
        if retries > max_retries {
            eprintln!("Public keys not found after {} retries.", max_retries);
            return Vec::new(); // Return an empty vector on failure
        }

        println!("No valid public keys found in response. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

fn fetch_ciphertext(password: &str, server_url: &str) -> String {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);

    loop {
        let res: Response = match client.get(&url).send() {
            Ok(response) => response,
            Err(err) => {
                println!("Error while fetching ciphertext: {}. Retrying...", err);
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(err) => {
                    println!("Error while reading response body: {}. Retrying...", err);
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            if let Some(ciphertext_start) = body.find("KYBER_PUBLIC_KEY:CIPHERTEXT:") {
                let ciphertext = &body[ciphertext_start + "KYBER_PUBLIC_KEY:CIPHERTEXT:".len()..]; // Remove marker
                if let Some(end_data) = ciphertext.find("[END DATA]") {
                    return ciphertext[0..end_data].to_string(); // Remove [END DATA] marker
                }
            }
        }

        // Wait for 2 seconds before retrying
        println!("Ciphertext not found. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

fn send_kyber_pubkey(room_id: &str, public_key: &str, url: &str) {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("KYBER_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res = client.post(&full_url).json(&message).send(); // Use the full URL

    match res {
        Ok(response) if response.status().is_success() => {
            println!("Kyber1024 public key sent successfully!");
        }
        Ok(response) => {
            println!("Failed to send public key. Status: {}", response.status());
        }
        Err(e) => {
            println!("Failed to send public key. Error: {}", e);
        }
    }
}

fn send_dilithium_pubkey(room_id: &str, public_key: &str, url: &str) {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("DILITHIUM_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res = client.post(&full_url).json(&message).send(); // Use the full URL

    match res {
        Ok(response) if response.status().is_success() => {
            println!("Dilithium5 public key sent successfully!");
        }
        Ok(response) => {
            println!("Failed to send public key. Status: {}", response.status());
        }
        Err(e) => {
            println!("Failed to send public key. Error: {}", e);
        }
    }
}

fn send_eddsa_pubkey(room_id: &str, public_key: &str, url: &str) {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("EDDSA_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res: Response = match client.post(&full_url).json(&message).send() {
        Ok(response) => response,
        Err(_) => {
            println!("Failed to send the public key.");
            return;
        }
    };

    if res.status().is_success() {
        println!("EdDSA public key sent successfully!");
    } else {
        println!("Failed to send public key.");
    }
}

fn send_ciphertext(room_id: &str, ciphertext: &str, url: &str) {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("KYBER_PUBLIC_KEY:CIPHERTEXT:{}[END DATA]", ciphertext),
        room_id: room_id.to_string(),
    };

    let res: Response = client.post(&full_url).json(&message).send().unwrap(); // Use the full URL

    if res.status().is_success() {
        println!("Ciphertext sent successfully!");
    } else {
        println!("Failed to send ciphertext");
    }
}


fn kyber_key_exchange(
    room_id: &str,
    dilithium_pks: &[oqs::sig::PublicKey],
    dilithium_sk: &oqs::sig::SecretKey,
    server_url: &str, // Added server URL parameter
) -> Result<String, Box<dyn Error>> {
    // Initialize KEM (Kyber1024)
    let kemalg = Kem::new(Algorithm::Kyber1024)?;

    // Generate the key pair once at the start (for both Alice and Bob)
    let (kem_pk, kem_sk) = kemalg.keypair()?;
    let kem_pk_hex = hex::encode(kem_pk.as_ref());

    let public_key = fetch_kyber_pubkey(room_id, server_url); // Pass server_url
    let is_alice = match public_key {
        Some(ref key) if !key.is_empty() => {
            println!("Fetched public key: {}", key);
            false
        }
        _ => {
            println!("No valid public key found. Sending own Kyber public key.");
            send_kyber_pubkey(room_id, &kem_pk_hex, server_url); // Pass server_url
            true
        }
    };

    let shared_secret_result = if is_alice {
        let ciphertext = fetch_ciphertext(room_id, server_url); // Pass server_url
        // Find the "-----BEGIN SIGNATURE-----" delimiter
        let start_pos = ciphertext.find("-----BEGIN SIGNATURE-----").ok_or("Signature start not found")?;
        // Extract the ciphertext before the signature part (i.e., before the "-----BEGIN SIGNATURE-----")
        let ciphertext_before_signature = &ciphertext[..start_pos].trim();

        // If the extracted ciphertext before the signature is hex-encoded, decode it
        let decoded_ct = hex::decode(ciphertext_before_signature)?;

        // Iterate over dilithium_pks to verify the signature
        let mut signature_verified = false;
        for dilithium_pk in dilithium_pks {
            if verify_signature_with_dilithium(ciphertext.as_bytes(), dilithium_pk).is_ok() {
                println!("Signature verified with Dilithium public key.");
                signature_verified = true;
                break;
            }
        }

        if !signature_verified {
            return Err("Failed to verify signature with any Dilithium public key.".into());
        }

        let ciphertext_obj = kemalg
            .ciphertext_from_bytes(&decoded_ct)
            .ok_or("Invalid ciphertext bytes")?;

        let shared_secret = kemalg.decapsulate(&kem_sk, &ciphertext_obj)?;
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_ref());
        let result = hasher.finalize();
        let shared_secret_result = hex::encode(result);

        shared_secret_result
    } else {
        let alice_pk_bytes = hex::decode(public_key.unwrap())?;
        let alice_pk_ref = kemalg
            .public_key_from_bytes(&alice_pk_bytes)
            .ok_or("Failed to convert Alice's public key")?;

        let (kem_ct, shared_secret) = kemalg.encapsulate(&alice_pk_ref)?;

        // Bob signs the ciphertext
        let ciphertext_signature = sign_data_with_dilithium(kem_ct.as_ref(), dilithium_sk)?;
        println!("Bob signed the ciphertext: {}", ciphertext_signature);

        send_ciphertext(room_id, &ciphertext_signature, server_url); // Pass server_url

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_ref());
        let result = hasher.finalize();
        let shared_secret_result = hex::encode(result);

        shared_secret_result
    };

    Ok(shared_secret_result)
}

fn sign_data_with_dilithium(data: &[u8], dilithium_sk: &oqs::sig::SecretKey) -> Result<String, Box<dyn Error>> {
    // Create the signature algorithm instance for Dilithium5
    let sigalg = Sig::new(oqs::sig::Algorithm::Dilithium5)?;

    // Sign the data using the secret key
    let signature = sigalg.sign(data, dilithium_sk)?;

    // Format the data and signature into a single combined string
    let combined = format!(
        "{}-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----",
        hex::encode(data), // Data encoded as hex
        hex::encode(signature) // Signature encoded as hex
    );

    Ok(combined)
}

fn verify_signature_with_dilithium(data: &[u8], dilithium_pk: &oqs::sig::PublicKey) -> Result<bool, Box<dyn Error>> {
    // Convert the data to a string for easier processing
    let data_str = String::from_utf8_lossy(data);

    // Find the "-----BEGIN SIGNATURE-----" delimiter
    let start_pos = data_str.find("-----BEGIN SIGNATURE-----").ok_or("Signature start not found")?;

    // Extract the data before the signature part (i.e., before the "-----BEGIN SIGNATURE-----")
    let data_before_signature = &data_str[..start_pos].trim();
    
    // If the extracted data before the signature is hex-encoded, decode it
    let data_bytes = hex::decode(data_before_signature)?;

    // Find the "-----END SIGNATURE-----" delimiter
    let end_pos = data_str.find("-----END SIGNATURE-----").ok_or("Signature end not found")?;

    // Extract the signature hex value and decode it
    let signature_hex = &data_str[start_pos + "-----BEGIN SIGNATURE-----".len()..end_pos].trim();
    let signature_bytes = hex::decode(signature_hex)?;

    // Initialize the Dilithium algorithm for signature verification
    let sigalg = Sig::new(oqs::sig::Algorithm::Dilithium5)?;
    
    // Attempt to convert the signature bytes to a valid signature
    let signature_ref = match (&sigalg).signature_from_bytes(&signature_bytes) {
        Some(sig) => sig,
        None => return Err("Invalid signature".into()),
    };

    // Verify the signature using the provided public key
    sigalg.verify(&data_bytes, &signature_ref, dilithium_pk)?;

    Ok(true)
}

fn sign_data_with_eddsa(data: &[u8], eddsa_sk: &Ed25519SecretKey) -> Result<String, Box<dyn Error>> {
    // Create a SigningKey using the SecretKey
    let signing_key = Ed25519PrivateKey::from(*eddsa_sk); // Create SigningKey from SecretKey

    // Sign the raw data using the EdDSA secret key
    let signature: Ed25519Signature = signing_key.sign(data);

    // Format the data and signature into a single combined string
    let combined = format!(
        "{}-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----",
        hex::encode(data), // Hex-encoded data
        hex::encode(signature.to_bytes()) // Signature encoded as hex
    );

    Ok(combined)
}

fn verify_signature_with_eddsa(signature_with_data: &str, eddsa_pk: &Ed25519PublicKey) -> Result<bool, Box<dyn Error>> {
    let start_pos = signature_with_data
        .find("-----BEGIN SIGNATURE-----")
        .ok_or("Signature start marker not found")?;
    let end_pos = signature_with_data
        .find("-----END SIGNATURE-----")
        .ok_or("Signature end marker not found")?;

    let signature_hex = &signature_with_data[start_pos + "-----BEGIN SIGNATURE-----".len()..end_pos].trim();
    let signature_bytes = hex::decode(signature_hex).map_err(|e| format!("Failed to decode signature: {}", e))?;

    let signature_array: &[u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Signature byte slice is not 64 bytes long")?;

    let signature = Ed25519Signature::from_bytes(signature_array);

    let data_before_signature = &signature_with_data[..start_pos].trim();

    let data_bytes = hex::decode(data_before_signature).map_err(|e| format!("Failed to decode data: {}", e))?;

    // Verify the signature with the original data
    let verification_result = eddsa_pk
        .verify(&data_bytes, &signature)
        .map_err(|_| "Signature verification failed");

    match verification_result {
        Ok(_) => println!("Signature verification successful."),
        Err(_) => println!("Signature verification failed."),
    }

    verification_result?;

    Ok(true)
}


#[derive(Serialize, Deserialize, Debug)] // Make sure it can be serialized and deserialized
struct MessageData {
    message: String,
    room_id: String,
}

fn fingerprint_dilithium_public_key(public_key: &PublicKey) -> String {
    // Access the raw bytes of the public key using as_ref()
    let raw_bytes = public_key.as_ref(); // This should return &[u8]
    let hashed = Sha256::digest(raw_bytes);
    hex::encode(hashed)
}

fn fingerprint_eddsa_public_key(public_key: &Ed25519PublicKey) -> String {
    // Hash the public key to generate a fingerprint (using SHA-256)
    let hashed = Sha256::digest(public_key);
    hex::encode(hashed)
}

fn request_user_confirmation(fingerprint: &str, own_fingerprint: &str) -> Result<bool, io::Error> {
    // If the fingerprint matches your own public key, auto-confirm
    if fingerprint == own_fingerprint {
        return Ok(true);
    }

    println!("The fingerprint of the received public key is: {}", fingerprint);
    print!("Do you confirm this fingerprint? (yes/no): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let response = input.trim().to_lowercase();
    
    match response.as_str() {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => {
            println!("Invalid input. Please enter 'yes' or 'no'.");
            request_user_confirmation(fingerprint, own_fingerprint) // Retry if invalid input
        }
    }
}

fn generate_random_room_id() -> String {
    const ID_LENGTH: usize = 16;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut rng = OsRng;
    let mut room_id = String::with_capacity(ID_LENGTH);

    for _ in 0..ID_LENGTH {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        room_id.push(CHARSET[idx] as char);
    }

    room_id
}

// The main function
fn main() -> Result<(), Box<dyn Error>> {
    use std::sync::{Arc, Mutex};
    use std::{io::{self, Write}, thread, time::Duration};

    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium5)?;

    // Get user input for the choice of interface
    let mut input = String::new();
    print!("Choose interface (CLI or GUI): ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let interface_choice = input.trim().to_string();
    input.clear();

    // Step 1: Ask user to either create a room ID or join one
    println!("Would you like to create a new room or join an existing one?");
    println!("Type 'create' to create a new room or 'join' to join an existing one.");
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let room_id = match choice {
        "create" => {
            let new_room_id = generate_random_room_id();
            println!("Generated new room ID: {}", new_room_id);
            new_room_id
        }
        "join" => {
            println!("Enter the room ID to join:");
            let mut room_input = String::new();
            io::stdin().read_line(&mut room_input)?;
            room_input.trim().to_string()
        }
        _ => {
            println!("Invalid choice. Please restart the program and choose 'create' or 'join'.");
            return Ok(());
        }
    };

    // Get the server URL
    print!("Enter the server URL: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let url = input.trim().to_string();
    input.clear();

    // Get the username
    print!("Enter your username: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let username = input.trim().to_string();
    input.clear();

    print!("Enter private key encryption password: ");
    io::stdout().flush()?;
    let private_password = read_password()?.to_string();

    println!("Is this a group chat? (yes/no): ");
    let mut is_group_chat = String::new();
    io::stdin().read_line(&mut is_group_chat)?;
    let is_group_chat = is_group_chat.trim().to_lowercase() == "yes";

    let room_password = if is_group_chat {
        // Loop to get a valid room password for group chat
        loop {
            print!("Enter room password (must be longer than 8 characters): ");
            io::stdout().flush()?; // Ensure the prompt is displayed immediately
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let password_input = input.trim();
            if password_input.len() > 8 {
                break password_input.to_string(); // Exit the loop with valid password
            } else {
                println!("Error: Password must be longer than 8 characters. Please try again.");
            }
        }
    } else {
        // For one-to-one chat, skip password setup
        String::new()
    };

    // Derive the key from the room password if it's a group chat
    let room_password = if is_group_chat {
        let salt = derive_salt_from_password(&room_password);
        let key = derive_key(&room_password, &salt);
        hex::encode(key)
    } else {
        String::new() // No room password required for one-to-one chat
    };

    // Skip key exchange and create hybrid_shared_secret if it's a group chat
    if is_group_chat {
        println!("Skipping key exchange. Using room password as shared secret.");
        let hybrid_shared_secret = room_password.clone();  // Use room password directly
        println!("Shared secret established.");
        println!("You can now start messaging!");

        // Shared data setup for messaging
        let shared_hybrid_secret = Arc::new(hybrid_shared_secret.clone());
        let shared_room_id = Arc::new(Mutex::new(room_id.clone()));
        let shared_url = Arc::new(Mutex::new(url.clone()));

        // Spawn message fetch thread
        let fetch_thread = {
            let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
            let shared_room_id = Arc::clone(&shared_room_id);
            let shared_url = Arc::clone(&shared_url);

            thread::spawn(move || loop {
                let room_id_locked = shared_room_id.lock().unwrap();
                let url_locked = shared_url.lock().unwrap();

                match receive_and_fetch_messages(
                    &room_id_locked,
                    &shared_hybrid_secret,
                    &url_locked,
                    true,
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Error fetching messages: {}", e);
                    }
                }
                thread::sleep(Duration::from_secs(10));
            })
        };

        // Handle GUI or CLI messaging
        if interface_choice.to_lowercase() == "gui" {
            let shared_hybrid_secret_for_gui = shared_hybrid_secret;
            let shared_room_id_for_gui: Arc<String> = {
                let locked = shared_room_id.lock().unwrap();
                Arc::new(locked.clone())
            };
            let shared_url_for_gui: Arc<String> = {
                let locked = shared_url.lock().unwrap();
                Arc::new(locked.clone())
            };
            let _ = run_gui(
                username.clone(),
                shared_hybrid_secret_for_gui,
                shared_room_id_for_gui,
                shared_url_for_gui,
            );
        } else {
            loop {
                let mut message = String::new();
                print!("Enter your message (or type 'exit' to quit): ");
                io::stdout().flush()?;
                io::stdin().read_line(&mut message)?;

                let message = message.trim();

                if message == "exit" {
                    println!("Exiting messaging session.");
                    break;
                }

                let message = format!("<strong>{}</strong>: {}", username, message);

                let encrypted_message = encrypt_data(&message, &hybrid_shared_secret)?;
                send_encrypted_message(&encrypted_message, &room_id, &url)?;
            }
        }

        if let Err(e) = fetch_thread.join() {
            eprintln!("Fetch thread terminated with error: {:?}", e);
        }

        return Ok(());
    }

    // Continue with the key exchange process for one-to-one chat
    // Step 2: Load or generate Dilithium5 and EdDSA keys for the user
    let dilithium_keys = key_operations_dilithium(&sigalg, &username, &private_password);
    let Ok((dilithium_pk, dilithium_sk)) = dilithium_keys else { todo!() };

    let eddsa_keys = key_operations_eddsa(&username, &private_password);
    let Ok((eddsa_sk, eddsa_pk)) = eddsa_keys else { todo!() };

    let encoded_dilithium_pk = hex::encode(&dilithium_pk);
    send_dilithium_pubkey(&room_id, &encoded_dilithium_pk, &url);

    let encoded_eddsa_pk = hex::encode(&eddsa_pk);
    send_eddsa_pubkey(&room_id, &encoded_eddsa_pk, &url);

    let fingerprint_dilithium = fingerprint_dilithium_public_key(&dilithium_pk);

    println!("Own Dilithium5 fingerprint: {}", fingerprint_dilithium);

    let fingerprint_eddsa = match Ed25519PublicKey::from_bytes(&eddsa_pk) {
        Ok(public_key) => fingerprint_eddsa_public_key(&public_key),
        Err(e) => {
            eprintln!("Failed to convert EdDSA public key: {}", e);
            return Err(Box::new(e));
        }
    };

    println!("Own EdDSA fingerprint: {}", fingerprint_eddsa);

    let mut processed_fingerprints: HashSet<String> = HashSet::new();
    processed_fingerprints.insert(fingerprint_dilithium.clone());
    processed_fingerprints.insert(fingerprint_eddsa.clone());

    let mut all_other_dilithium_keys: Vec<oqs::sig::PublicKey> = Vec::new();

    while all_other_dilithium_keys.len() < 1 {
        println!("Waiting for Dilithium public key...");
        thread::sleep(Duration::from_secs(5));
    
        let encoded_other_dilithium_pks = fetch_dilithium_pubkeys(&room_id, &url);
    
        for encoded_pk in encoded_other_dilithium_pks {
            if let Ok(decoded_pk) = hex::decode(&encoded_pk) {
    
                // Create a Sig instance for the "Dilithium5" algorithm
                let algorithm = SigAlgorithm::Dilithium5;
    
                // Create a Sig instance for the chosen algorithm
                let sig = Sig::new(algorithm).map_err(|_| "Failed to initialize signature scheme")?;
    
                // Convert the decoded public key to a PublicKey using public_key_from_bytes
                if let Some(public_key_ref) = sig.public_key_from_bytes(&decoded_pk) {
                    // Convert PublicKeyRef<'_> to PublicKey by calling to_owned()
                    let public_key = public_key_ref.to_owned();
    
                    let fetched_fingerprint = fingerprint_dilithium_public_key(&public_key);
    
                    if fetched_fingerprint == fingerprint_dilithium {
                        continue;
                    }
    
                    if processed_fingerprints.contains(&fetched_fingerprint) {
                        continue;
                    }
    
                    if request_user_confirmation(&fetched_fingerprint, &fingerprint_dilithium)? {
                        // Push the owned PublicKey to the list
                        all_other_dilithium_keys.push(public_key);
                        processed_fingerprints.insert(fetched_fingerprint);
                    } else {
                        eprintln!("User did not confirm the public key fingerprint.");
                    }
                } else {
                    eprintln!("Failed to decode valid public key.");
                }
            } else {
                eprintln!("Failed to convert decoded key to PublicKey.");
            }
        }
    }
    
    

    println!("Received Dilithium5 public key from the server.");

    let mut eddsa_key: Option<Ed25519PublicKey> = None;

    while eddsa_key.is_none() {
        println!("Waiting for EdDSA public key...");
        thread::sleep(Duration::from_secs(5));

        let encoded_other_eddsa_pks = fetch_eddsa_pubkeys(&room_id, &url);

        for encoded_pk in encoded_other_eddsa_pks {
            if let Ok(decoded_pk) = hex::decode(&encoded_pk) {
                if let Ok(public_key) = Ed25519PublicKey::from_bytes(
                    decoded_pk.as_slice().try_into().expect("Decoded public key must be 32 bytes long"),
                ) {
                    let fetched_fingerprint = fingerprint_eddsa_public_key(&public_key);

                    if fetched_fingerprint == fingerprint_eddsa {
                        continue;
                    }

                    if processed_fingerprints.contains(&fetched_fingerprint) {
                        continue;
                    }

                    if request_user_confirmation(&fetched_fingerprint, &fingerprint_eddsa)? {
                        eddsa_key = Some(public_key);
                        processed_fingerprints.insert(fetched_fingerprint);
                        break;
                    } else {
                        eprintln!("User did not confirm the public key fingerprint.");
                    }
                } else {
                    eprintln!("Failed to decode valid public key.");
                }
            } else {
                eprintln!("Failed to convert decoded key to PublicKey.");
            }
        }
    }

    println!("Received EdDSA public key from the server.");

    let mut all_dilithium_pks = vec![dilithium_pk];
    all_dilithium_pks.extend(all_other_dilithium_keys);

    let kyber_shared_secret = kyber_key_exchange(&room_id, &all_dilithium_pks, &dilithium_sk, &url)?;
    let ecdh_shared_secret = if let Some(ref eddsa_key) = eddsa_key {
        perform_ecdh_key_exchange(&room_id, &eddsa_sk.to_bytes(), eddsa_key, &url)?
    } else {
        return Err("EdDSA public key is missing".into());
    };

    let hybrid_shared_secret = combine_shared_secrets(&kyber_shared_secret, &ecdh_shared_secret)?;

    println!("Hybrid shared secret established.");
    println!("You can now start messaging!");

    let shared_hybrid_secret = Arc::new(hybrid_shared_secret.clone());  // Keep as Arc<String>
    let shared_room_id = Arc::new(Mutex::new(room_id.clone()));  // Wrap in Mutex
    let shared_url = Arc::new(Mutex::new(url.clone()));  // Wrap in Mutex
    
    let fetch_thread = {
        let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
        let shared_room_id = Arc::clone(&shared_room_id);
        let shared_url = Arc::clone(&shared_url);
    
        thread::spawn(move || loop {
            // Lock the Mutex to access the inner String
            let room_id_locked = shared_room_id.lock().unwrap();
            let url_locked = shared_url.lock().unwrap();
    
            // Pass the locked strings to the function
            match receive_and_fetch_messages(
                &room_id_locked,  // Pass the inner String
                &shared_hybrid_secret,
                &url_locked,  // Pass the inner String
                true,
            ) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error fetching messages: {}", e);
                }
            }
            thread::sleep(Duration::from_secs(10));
        })
    };
    
    if interface_choice.to_lowercase() == "gui" {
        // Wrap only for passing to run_gui
        let shared_hybrid_secret_for_gui = shared_hybrid_secret;
        
        let shared_room_id_for_gui: Arc<String> = {
            let locked = shared_room_id.lock().unwrap();
            Arc::new(locked.clone())
        };
        
        let shared_url_for_gui: Arc<String> = {
            let locked = shared_url.lock().unwrap();
            Arc::new(locked.clone())
        };
        
        // Pass the arguments
        let _ = run_gui(
            username.clone(),
            shared_hybrid_secret_for_gui,
            shared_room_id_for_gui,
            shared_url_for_gui,
        );
        
    } else {
        loop {
            let mut message = String::new();
            print!("Enter your message (or type 'exit' to quit): ");
            io::stdout().flush()?;
            io::stdin().read_line(&mut message)?;
    
            let message = message.trim();
    
            if message == "exit" {
                println!("Exiting messaging session.");
                break;
            }
    
            let message = format!("<strong>{}</strong>: {}", username, message);
    
            let encrypted_message = encrypt_data(&message, &hybrid_shared_secret)?;
            send_encrypted_message(&encrypted_message, &room_id, &url)?;
        }
    }
    
    if let Err(e) = fetch_thread.join() {
        eprintln!("Fetch thread terminated with error: {:?}", e);
    }
    


    Ok(())
}


fn combine_shared_secrets(
    kyber_secret: &str,
    ecdh_secret: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    use hex; // For hexadecimal encoding

    // Concatenate the secrets
    let combined = [kyber_secret.as_bytes(), ecdh_secret.as_bytes()].concat();

    // Hash the combined secrets to produce a fixed-length shared secret
    let mut hasher = Sha256::new();
    hasher.update(combined);

    // Convert the hash result to a hexadecimal string
    Ok(hex::encode(hasher.finalize()))
}

fn perform_ecdh_key_exchange(
    room_id: &str,
    eddsa_sk: &Ed25519SecretKey,
    eddsa_pk: &Ed25519PublicKey,
    server_url: &str, // Added parameter for server URL
) -> Result<String, Box<dyn std::error::Error>> {
    // Generate ECDH key pair using X25519 once at the start
    let secret_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = X25519PublicKey::from(&secret_key);

    let public_key_bytes = public_key.as_bytes();

    // Sign the public key using EdDSA
    let signed_public_key = sign_data_with_eddsa(public_key_bytes, eddsa_sk)?;

    // Format the signed public key with the proper markers
    let formatted_signed_public_key = format!("ECDH_PUBLIC_KEY:{}[END DATA]", signed_public_key);

    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    loop {
        // Send the formatted signed public key to the server
        let message = Message {
            message: formatted_signed_public_key.clone(),
            room_id: room_id.to_string(),
        };

        let send_url = format!("{}/send", server_url); // Use server_url for the send endpoint
        if let Err(err) = client.post(&send_url).json(&message).send() {
            eprintln!("Failed to send signed public key to the server: {}", err);
            continue; // Retry
        } else {
            println!("Successfully sent signed public key to the server.");
        }

        // Fetch the other party's signed public key
        let fetch_url = format!("{}/messages?room_id={}", server_url, room_id); // Use server_url for the fetch endpoint
        let res = match client.get(&fetch_url).send() {
            Ok(response) => response,
            Err(err) => {
                eprintln!("Failed to fetch the other party's public key: {}", err);
                continue; // Retry
            }
        };

        if !res.status().is_success() {
            eprintln!("Non-success status code while fetching messages: {}", res.status());
            continue; // Retry
        }

        let html_response = match res.text() {
            Ok(text) => text,
            Err(err) => {
                eprintln!("Failed to read response text: {}", err);
                continue; // Retry
            }
        };

        // Look for all the signed public keys in the response
        let start_tag = "ECDH_PUBLIC_KEY:";
        let end_tag = "[END DATA]";
        let mut keys_processed = false;

        let mut start = 0;
        while let Some(start_pos) = html_response[start..].find(start_tag) {
            start += start_pos + start_tag.len();
            if let Some(end_pos) = html_response[start..].find(end_tag) {
                let extracted_signed_key = &html_response[start..start + end_pos].trim();

                // Verify the other party's public key signature
                if let Err(err) = verify_signature_with_eddsa(extracted_signed_key, eddsa_pk) {
                    eprintln!("Failed to verify the signature: {}", err);
                    continue; // Retry if verification fails
                }

                // If verification is successful, extract the public key and proceed
                let extracted_key = extracted_signed_key.split("-----BEGIN SIGNATURE-----").next().unwrap().trim();

                // Ignore if it's the same as our own public key
                if extracted_key == formatted_signed_public_key {
                    println!("Ignoring our own public key.");
                    start += end_pos + end_tag.len(); // Move past the end tag to continue searching
                    keys_processed = true;
                    continue; // Skip processing if it's our own public key
                }

                match hex::decode(extracted_key) {
                    Ok(other_public_key_bytes) => {
                        if other_public_key_bytes.len() != 32 {
                            eprintln!("Invalid public key length: {}", other_public_key_bytes.len());
                            continue;
                        }

                        let other_public_key_bytes =
                            match <[u8; 32]>::try_from(other_public_key_bytes.as_slice()) {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    eprintln!("Failed to convert other public key bytes: {}", err);
                                    continue;
                                }
                            };

                        let other_public_key = X25519PublicKey::from(other_public_key_bytes);
                        let shared_secret = secret_key.diffie_hellman(&other_public_key);
                        let shared_secret_base64 = general_purpose::STANDARD.encode(shared_secret.as_bytes());
                        return Ok(shared_secret_base64);
                    }
                    Err(err) => {
                        eprintln!("Failed to decode other public key: {}", err);
                    }
                }

                // Move past the end tag
                start += end_pos + end_tag.len();
                keys_processed = true;
            } else {
                eprintln!("End tag not found after start tag. Skipping.");
                break;
            }
        }

        if !keys_processed {
            eprintln!("No valid other signed public keys found. Retrying...");
        }
    }
}

fn send_encrypted_message(
    encrypted_message: &str,
    room_id: &str,
    server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    // Format the encrypted message with the BEGIN and END markers
    let formatted_encrypted_message = format!(
        "-----BEGIN ENCRYPTED MESSAGE-----{}-----END ENCRYPTED MESSAGE-----",
        encrypted_message
    );

    // Create the message data to send
    let message_data = MessageData {
        message: formatted_encrypted_message,
        room_id: room_id.to_string(),
    };

    // Construct the full URL for sending the message
    let send_url = format!("{}/send", server_url);

    // Send the message via HTTP POST request
    let res = client
        .post(&send_url)
        .json(&message_data)
        .timeout(Duration::from_secs(5)) // Set a timeout for the request
        .send()?;

    // Check if the request was successful and print the result
    if res.status().is_success() {
        println!("Message sent successfully.");
    } else {
        eprintln!("Failed to send message: {}", res.status());
    }

    Ok(())
}

fn receive_and_fetch_messages(
    room_id: &str,
    shared_secret: &str,
    server_url: &str,
    gui: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // HTTP proxy setup
    let proxy = "127.0.0.1:8118"; // HTTP Proxy address
    let client = create_client_with_proxy(proxy);

    // Build the URL with the provided room password and server URL
    let url = format!("{}/messages?room_id={}", server_url, room_id);

    // Send a synchronous GET request to fetch messages
    let res = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5)) // Set a timeout for the request
        .send()?;

    // Declare the vector to store messages outside the response block
    let mut messages = Vec::new();

    // Check if the request was successful
    if res.status().is_success() {
        clear_screen();
        // Get the body of the HTML response
        let body = res.text()?;

        // Define a regular expression to capture messages between the markers
        let re = Regex::new(r"-----BEGIN ENCRYPTED MESSAGE-----\s*(.*?)\s*-----END ENCRYPTED MESSAGE-----")
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Iterate over all matches in the HTML body
        for cap in re.captures_iter(&body) {
            if let Some(encrypted_message) = cap.get(1) {
                // Step 1: Get the encrypted message without the markers
                let cleaned_message = encrypted_message.as_str().trim();

                // Step 2: Decrypt the message (ignore the markers, only pass the actual content)
                match decrypt_data(cleaned_message, shared_secret) {
                    Ok(decrypted_message) => {
                        // If gui is true, do not replace <strong> tags
                        let final_message = if gui {
                            decrypted_message.to_string()
                        } else {
                            // Step 3: Replace <strong> tags with ANSI escape codes for bold text
                            let strong_re = Regex::new(r"<strong>(.*?)</strong>").unwrap();
                            strong_re.replace_all(&decrypted_message, |caps: &regex::Captures| {
                                // Replace <strong>...</strong> with ANSI escape codes for bold text
                                format!("\x1b[1m{}\x1b[0m", &caps[1])
                            }).to_string()
                        };

                        // If gui is true, return the messages instead of printing them
                        if gui {
                            messages.push(final_message);
                        } else {
                            // Step 4: Print the decrypted message with the bold content
                            println!("{}", final_message);
                        }
                    }
                    Err(_e) => {
                        // Handle decryption failure (if needed)
                    }
                }
            }
        }
    } else {
        // Provide more detailed error info for failed requests
        eprintln!("Failed to fetch messages: {} - {}", res.status(), res.text()?);
    }

    // Return the collected messages if gui is true, otherwise return empty messages
    Ok(messages)
}


// Function to clear the screen before printing new messages
fn clear_screen() {
    if cfg!(target_os = "windows") {
        // Windows
        Command::new("cmd")
            .args(&["/C", "cls"])
            .output()
            .expect("Failed to clear screen on Windows");
    } else {
        // Linux/macOS or others
        print!("\x1b[2J\x1b[H");
        std::io::stdout().flush().unwrap(); // Ensure the command is executed immediately
    }
}

// Derive a salt from the password itself
fn derive_salt_from_password(password: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash_result = hasher.finalize();

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash_result[..16]); // Use the first 16 bytes of the hash as the salt
    salt
}

// Derive encryption key using Argon2
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(salt).expect("Failed to generate salt string");
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");
    let hash_bytes = hash.hash.expect("Hash missing in PasswordHash structure");

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    key
}

// Encrypt the data using ChaCha20Poly1305
pub fn encrypt_data(plain_text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Generate random salt for key derivation
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive encryption key using Argon2
    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    // Generate random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let encrypted_data = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|_| "Encryption error")?;

    // Clear the key from memory after usage
    key.zeroize();

    // Return the formatted encrypted message with salt, nonce, and encrypted data
    Ok(format!(
        "{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce_bytes),
        hex::encode(encrypted_data)
    ))
}

// Decrypt the data using ChaCha20Poly1305
pub fn decrypt_data(encrypted_text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Split the encrypted data into salt, nonce, and encrypted part
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted data format".into());
    }

    // Decode hex-encoded salt, nonce, and encrypted data
    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error: Invalid salt format")?;
    let nonce_bytes = hex::decode(parts[1]).map_err(|_| "Decryption error: Invalid nonce format")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error: Invalid encrypted data format")?;

    // Derive the decryption key using the password and salt
    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    // Ensure nonce is of the correct length (12 bytes for ChaCha20Poly1305)
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt the data
    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| "Decryption error: Failed to decrypt")?;

    // Clear the key from memory after usage
    key.zeroize();

    // Convert decrypted bytes into a string
    Ok(String::from_utf8(decrypted_data).map_err(|_| "Decryption error: Invalid UTF-8 data")?)
}