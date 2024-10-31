mod amnesichat;
use anyhow::{Context, Result};
use pgp::KeyType;
use pgp::{
    composed::{key::SecretKeyParamsBuilder},
    crypto::sym::SymmetricKeyAlgorithm,
    Deserializable,
    
};
use pgp::{SignedSecretKey, Message, ArmorOptions};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::CompressionAlgorithm;
use pgp::SubkeyParamsBuilder;
use pgp::types::KeyVersion;
use pgp::types::PublicKeyTrait;
use pgp::SignedPublicKey;
use pgp::types::SecretKeyTrait;
use pgp::types::Fingerprint;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use tokio::time::{Duration};
use tokio::sync::Mutex;
use tokio::fs as async_fs;
use tokio::process::Command;
use tokio::sync::mpsc;
use smallvec::*;
use std::{io::Cursor, io::Write};
use std::path::Path;
use std::fs::{self};
use std::io::{self};
use std::io::{Seek, SeekFrom};
use std::fs::OpenOptions;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};
use zeroize::Zeroize;
use hex;
use std::sync::Arc;
use rpassword::read_password;
use signal_hook::consts::signal::SIGINT;
use signal_hook::iterator::Signals;
use amnesichat::Amnesichat;

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
pub fn encrypt_data(plain_text: &str, password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_data = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|_| anyhow::anyhow!("Encryption error"))?;

    key.zeroize();

    Ok(format!(
        "{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce_bytes),
        hex::encode(encrypted_data)
    ))
}

// Decrypt the data using ChaCha20Poly1305
pub fn decrypt_data(encrypted_text: &str, password: &str) -> Result<String> {
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid encrypted data format"));
    }

    let salt = hex::decode(parts[0]).map_err(|_| anyhow::anyhow!("Decryption error"))?;
    let nonce_bytes = hex::decode(parts[1]).map_err(|_| anyhow::anyhow!("Decryption error"))?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| anyhow::anyhow!("Decryption error"))?;

    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption error"))?;

    key.zeroize();

    String::from_utf8(decrypted_data).map_err(|_| anyhow::anyhow!("Decryption error"))
}

pub async fn decrypt_private_key_from_file(sec_file: &str, password: &str) -> Result<SignedSecretKey> {
    // Read the encrypted secret key from the file
    let encrypted_secret_key = fs::read_to_string(sec_file)
        .context("Failed to read encrypted private key from file")?;

    // Decrypt the secret key using the provided password
    let decrypted_secret_key = decrypt_data(&encrypted_secret_key, password)
        .context("Failed to decrypt private key")?;

    // Parse the secret key using from_armor_single()
    let (ssk, _) = SignedSecretKey::from_armor_single(io::Cursor::new(decrypted_secret_key))
        .context("Failed to parse the decrypted key into SignedSecretKey")?;

    // Optionally verify the signed secret key
    ssk.verify()
        .context("Failed to verify the signed secret key")?;

    Ok(ssk)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create a signal iterator to listen for SIGINT (Ctrl+C)
    let mut signals = Signals::new(&[SIGINT])?;

    // Create a channel to notify the main loop when to exit
    let (exit_tx, mut exit_rx) = mpsc::channel(1);

    // Spawn a background thread to handle signals
    std::thread::spawn(move || {
        for _ in signals.forever() {
            println!("Caught exit signal. Performing cleanup...");
            // Send a signal to the main thread to exit
            exit_tx.blocking_send(()).expect("Failed to send exit signal");
        }
    });

    loop {
        println!("\nAmnesichat");
        println!("Please enter the server URL and port (e.g., http://localhost:8080):");

        let mut base_url = String::new();
        std::io::stdin().read_line(&mut base_url)?;
        let base_url = base_url.trim().to_string();

        if base_url.is_empty() {
            println!("Invalid URL. Please try again.");
            continue;
        }

        println!("Enter your username:");
        let mut username = String::new();
        std::io::stdin().read_line(&mut username)?;
        let username = username.trim().to_string();

        println!("Enter your room password:");
        let password = read_password()?;
        
        println!("Enter your private key password:");
        let private_password = read_password()?;

        println!("Enter your cookie (leave blank if none):");
        let mut cookie = String::new();
        std::io::stdin().read_line(&mut cookie)?;
        let cookie = if cookie.trim().is_empty() {
            None
        } else {
            Some(cookie.trim().to_string())
        };

        let amnesichat = Amnesichat {
            base_url,
            username,
            private_password: private_password.clone(),
            password,
            cookie,
        };

        // Wrap Amnesichat in tokio::sync::Mutex and Arc for safe sharing
        let amnesichat = Arc::new(Mutex::new(amnesichat));

        // Create a channel for message notifications
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(32);

        // Spawn a background task to fetch messages
        let amnesichat_clone = Arc::clone(&amnesichat); // Clone the Arc to pass into the task
        tokio::spawn(async move {
            loop {
                let amnesichat = amnesichat_clone.lock().await; // Lock asynchronously
                if let Err(e) = amnesichat.fetch_and_decrypt_messages().await {
                    eprintln!("Error fetching messages: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(60)).await; // Sleep for 60 seconds before fetching again
                let _ = tx.send(()).await; // Notify main thread
            }
        });

        loop {
            // Spawn a tokio task that returns Result
            let handle = tokio::spawn(async move {
                match get_key_fingerprints().await {
                    Ok(_) => return,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            });

            // Await the task and handle the result
            handle.await?; // Directly await the handle and propagate any errors
            println!("Enter your message or use commands(/exit, /generate_key_pair, /fingerprint):");
            std::io::stdout().flush()?;
    
            let mut choice = String::new();
            std::io::stdin().read_line(&mut choice)?;

            if choice.contains("/generate_key_pair")
            {
                generate_and_save_keys(&private_password).await?;
            }
            else if choice.contains("/fingerprint")
            {
                let handle = tokio::spawn(async move {
                    match get_key_fingerprints().await {
                        Ok(_) => return,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                        }
                    }
                });
                handle.await?; // Await the task
            }
            else if choice.contains("/exit")
            {
                // Perform cleanup before exiting
                cleanup_directories().await?;
                clear_screen();
                std::process::exit(0);  // Forcefully terminate the program
            }
            else
            {
                let message = choice.trim().to_string();

                let amnesichat = amnesichat.lock().await; // Lock asynchronously
                amnesichat.send_message(&message).await?;
            }

            // Check for new messages or a signal to exit
            tokio::select! {
                _ = rx.recv() => {
                    println!("Checked for new messages.");
                }
                _ = exit_rx.recv() => {
                    println!("Exit signal received. Exiting...");
                    cleanup_directories().await?;
                    clear_screen();
                    std::process::exit(0);  // Gracefully exit on signal
                }
            }
        }
    }
}

fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(&["/C", "cls"])
            .spawn()
            .expect("Failed to clear screen");
    } else {
        Command::new("clear")
            .spawn()
            .expect("Failed to clear screen");
    }
}

fn wipe_directory<P: AsRef<Path>>(dir: P) -> io::Result<()> {
    // Open the directory and read its contents
    let dir_path = dir.as_ref();
    
    if !dir_path.exists() {
        return Ok(());
    }

    let entries = fs::read_dir(dir_path)?;

    // Iterate over each entry in the directory
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            wipe_file(&path)?; // Overwrite and delete the file
        } else if path.is_dir() {
            wipe_directory(&path)?; // Recursively wipe subdirectories
        }
    }

    Ok(())
}

fn wipe_file(file_path: &Path) -> io::Result<()> {
    // Open the file for writing (this will open the file in write mode, overwriting the file's contents)
    let mut file = OpenOptions::new()
        .write(true)
        .open(file_path)?;

    let file_size = file.metadata()?.len();

    // Overwrite the file with zeroes
    let zero_buffer = vec![0u8; file_size as usize];
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&zero_buffer)?;

    // Optionally, truncate the file after zeroing
    file.set_len(0)?;

    // Delete the file after wiping
    fs::remove_file(file_path)?;

    Ok(())
}

async fn cleanup_directories() -> io::Result<()> {
    // Define the paths of the directories to wipe
    let messages_dir = "./messages";
    let pubkeys_dir = "./pubkeys";

    // Ensure directories exist before trying to wipe them
    if Path::new(messages_dir).exists() {
        wipe_directory(messages_dir)?;
    }

    if Path::new(pubkeys_dir).exists() {
        wipe_directory(pubkeys_dir)?;
    }

    println!("Sensitive data wiped from directories.");
    
    Ok(())
}

async fn get_key_fingerprints() -> Result<Vec<(String, Fingerprint)>> {
    let mut fingerprints: Vec<(String, Fingerprint)> = Vec::new();
    let pubkey_dir = Path::new("./yourkeys");

    // Ensure the directory exists asynchronously
    if !pubkey_dir.exists() {
        async_fs::create_dir_all(pubkey_dir).await.context("Failed to create the public keys directory")?;
    }

    // Read directory entries asynchronously
    let mut entries = async_fs::read_dir(pubkey_dir)
        .await
        .context("Failed to read the public keys directory")?;

    // Iterate over directory entries
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        // Process only .public files
        if let Some(extension) = path.extension() {
            if extension == "public" {
                // Read the public key file asynchronously as a string
                if let Ok(public_key) = async_fs::read_to_string(&path).await {
                    let cursor = Cursor::new(public_key.into_bytes());
                    
                    // Parse the public key and collect fingerprints
                    if let Ok((signed_public_keys, _)) = SignedPublicKey::from_armor_many(cursor) {
                        for signed_public_key in signed_public_keys {
                            if let Ok(key) = signed_public_key {
                                // Collect fingerprints for primary and subkeys
                                for subkey in &key.public_subkeys {
                                    fingerprints.push((
                                        path.to_string_lossy().to_string(),
                                        subkey.fingerprint(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Step 3: Display all available fingerprints
    println!("Your fingerprint(s):");
    for (i, (_, fingerprint)) in fingerprints.iter().enumerate() {
        println!("{}: {:?}", i + 1, fingerprint);
    }

    // Return the collected fingerprints
    Ok(fingerprints)
}

async fn generate_and_save_keys(private_password: &str) -> Result<()> {
    let yourkeys_dir = "./yourkeys";
    if !Path::new(yourkeys_dir).exists() {
        fs::create_dir_all(yourkeys_dir).context("Failed to create yourkeys directory")?;
    }

    let rng = ChaCha20Rng::from_entropy();
    let version = KeyVersion::V4;

    println!("Generating key pair...");
    let key_pair = generate_key_pair(rng, version)?; // Unwrap the result here

    println!("Enter a file name to save the public key: ");
    let pub_file = read_user_input()?;
    let pub_file_path = format!("{}/{}.public", yourkeys_dir, pub_file);

    println!("Enter a file name to save the secret key: ");
    let sec_file = read_user_input()?;
    let sec_file_path = format!("{}/{}.secret", yourkeys_dir, sec_file);

    // Pass the existing private password to save_keys_to_file
    save_keys_to_file(&key_pair, &pub_file_path, &sec_file_path, private_password)?;

    println!("Keys generated and saved successfully.");
    
    Ok(())
}

fn encrypt_user_message(message: &str, pkeys: &[&impl PublicKeyTrait]) -> Result<String> {
    let message = Message::new_literal("none", message);
    
    generate_armored_string(message, pkeys)
}

pub async fn decrypt_user_message(encrypted_file_path: &str, seckey: &SignedSecretKey) -> Result<String> {
    // Read the encrypted message file asynchronously
    let encrypted_msg = async_fs::read_to_string(encrypted_file_path)
        .await
        .context("Failed to read encrypted message file")?;
    
    // Prepare to parse the encrypted message
    let buf = Cursor::new(encrypted_msg);
    let (msg, _) = Message::from_armor_single(buf)
        .context("Failed to parse encrypted message")?;
    
    // Decrypt the message using the provided secret key
    let decryptor = msg
        .decrypt(|| String::new(), &[seckey])
        .context("Failed to decrypt the message")?;
    
    // Destructure the decryptor tuple
    let (decrypted_msg, _) = decryptor;

    // Get the content as bytes
    let content_result = decrypted_msg.get_content()
        .context("Failed to extract decrypted content")?;
    
    // Handle None gracefully
    let bytes = content_result.ok_or_else(|| anyhow::anyhow!("Decrypted content is empty"))?;

    // Convert the bytes into a UTF-8 string
    let clear_text = String::from_utf8(bytes)
        .context("Decrypted content is not valid UTF-8")?;
    
    // Return the decrypted message
    Ok(clear_text)
}

fn generate_key_pair<R: rand::Rng + rand::CryptoRng>(mut rng: R, version: KeyVersion) -> Result<KeyPair> {
    // The RFC 9580 key format variants based on Curve 25519 (X25519/Ed25519)

    // Create the key parameters for both Ed25519 and X25519
    let key_params = SecretKeyParamsBuilder::default()
        .version(version)
        .key_type(KeyType::Ed25519) // Signing key is Ed25519
        .can_certify(false)
        .can_sign(true)
        .primary_user_id("Anonymous <anon@example.com>".into())
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA3_512,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
        ])
        // Configure the subkey for encryption (X25519)
        .subkey(
            SubkeyParamsBuilder::default()
                .version(version) // Set the key version
                .key_type(KeyType::X25519)
                .can_certify(false)
                .can_sign(false)
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .unwrap(),
        )        
        .build()
        .unwrap();

    // Generate the secret key based on the parameters
    let key = key_params
        .generate(&mut rng)
        .context("failed to generate secret key")?;

    // Sign the key (Ed25519 is self-signed here)
    let signed_key = key
        .sign(&mut rng, || "".into())
        .context("failed to sign key")?;
    
    // Return the generated key pair (both private and public keys)
    Ok(KeyPair {
        signing_key: signed_key,
    })
}

fn save_keys_to_file(key_pair: &KeyPair, pub_file: &str, sec_file: &str, private_password: &str) -> Result<()> {
    // Serialize the secret key to armored format
    let armored_secret_key = key_pair
        .signing_key
        .to_armored_string(None.into()) // Convert `None` to `ArmorOptions`
        .context("Failed to serialize private key")?;

    // Encrypt the secret key using the provided password
    let encrypted_secret_key = encrypt_data(&armored_secret_key, private_password)
        .context("Failed to encrypt private key")?;

    // Write the encrypted private key to the specified file
    fs::write(sec_file, encrypted_secret_key).context("Failed to write encrypted private key to file")?;

    // Serialize the public key to armored format
    let public_key = key_pair
        .signing_key
        .public_key();

    // Create a SignedPublicKey from the public key and sign it
    let signed_public_key = public_key
        .sign(&mut OsRng, &key_pair.signing_key, || "".into())
        .context("Failed to sign public key")?;

    // Serialize the signed public key to armored format
    let armored_public_key = signed_public_key
        .to_armored_string(None.into()) // Convert to armored format
        .context("Failed to serialize public key")?;

    // Write the armored public key to the specified file
    fs::write(pub_file, armored_public_key).context("Failed to write public key to file")?;

    Ok(())
}

fn generate_armored_string(msg: Message, pubkeys: &[&impl PublicKeyTrait]) -> Result<String> {
    let mut rng = OsRng;

    // Use the slice of keys with `encrypt_to_keys_seipdv1`.
    let new_msg = msg.encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, pubkeys)?;

    // Convert to armored string
    Ok(new_msg.to_armored_string(ArmorOptions::default())?)
}


fn read_user_input() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[derive(Debug)]
pub struct KeyPair {
    pub signing_key: SignedSecretKey, // Signed signing key (Ed25519)
}
