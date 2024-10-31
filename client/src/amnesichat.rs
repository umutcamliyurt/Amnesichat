use crate::encrypt_user_message;
use crate::decrypt_user_message;
use crate::decrypt_private_key_from_file;
use crate::clear_screen;
use anyhow::{Context, Result};
use pgp::Deserializable;
use pgp::SignedPublicKey;
use pgp::types::PublicKeyTrait;
use pgp::types::Fingerprint;
use std::io::Cursor;
use regex::Regex;
use reqwest::header::HeaderMap;
use std::path::Path;
use std::fs::{self, File};
use std::io::{Read};
use std::collections::HashSet;
use uuid::Uuid;
use std::collections::HashMap;
use reqwest::Client;

#[derive(Debug)]
pub struct Amnesichat {
    pub base_url: String,
    pub username: String,
    pub private_password: String,
    pub password: String,
    pub cookie: Option<String>,
}

impl Amnesichat {

    pub async fn load_user_public_key(&self) -> Result<String> {
        let key_dir = Path::new("./yourkeys");
    
        if !key_dir.exists() {
            fs::create_dir_all(key_dir).context("Failed to create the yourkeys directory")?;
        }
    
        let entries = fs::read_dir(key_dir).map_err(|_| anyhow::anyhow!("Failed to read the directory ./yourkeys"))?;
        
        let mut public_key_data = String::new();
    
        for entry in entries {
            if let Err(_) = entry {
                continue;
            }
            let path = entry?.path();
    
            if path.extension().map(|e| e == "public").unwrap_or(false) {
                if let Err(_) = File::open(&path)
                    .map_err(|_| anyhow::anyhow!("Failed to open file: {:?}", path))
                    .and_then(|mut file| {
                        let mut contents = String::new();
                        file.read_to_string(&mut contents)
                            .map_err(|_| anyhow::anyhow!("Failed to read file: {:?}", path))?;
                        public_key_data.push_str(&contents);
                        public_key_data.push('\n');
                        Ok(())
                    })
                {
                    continue;
                }
            }
        }
    
        if public_key_data.is_empty() {
            return Err(anyhow::anyhow!("No public key files found in ./yourkeys").into());
        }
    
        Ok(public_key_data)
    }    
        
    pub async fn fetch_and_decrypt_messages(&self) -> Result<()> {
        clear_screen();
        let mut headers = HeaderMap::new();
        if let Some(cookie) = &self.cookie {
            headers.insert(reqwest::header::COOKIE, cookie.parse()?);
        }
    
        let client = Client::new();
        let url = format!("{}/messages", self.base_url);
    
        let response = client
            .get(&url)
            .query(&[("password", &self.password)])
            .headers(headers)
            .send()
            .await
            .context("Error fetching messages")?;
    
        if response.status().is_success() {
            let messages = response.text().await.context("Failed to read response text")?;
    
            // Handle extracted public keys
            let pgp_key_regex = r"(?s)(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)";
            let extracted_keys: Vec<&str> = Regex::new(pgp_key_regex)?
                .captures_iter(&messages)
                .map(|cap| cap.get(0).unwrap().as_str())
                .collect();
    
            if !extracted_keys.is_empty() {
                let pubkey_dir = Path::new("pubkeys");
                if !pubkey_dir.exists() {
                    fs::create_dir_all(pubkey_dir).context("Creating pubkeys directory")?;
                }
    
                // Load existing fingerprints
                let mut existing_fingerprints = HashSet::new();
                for entry in fs::read_dir(pubkey_dir)? {
                    let path = entry?.path();
                    if path.extension().map_or(false, |ext| ext == "asc") {
                        if let Ok(public_key) = fs::read_to_string(&path) {
                            let cursor = Cursor::new(public_key.into_bytes());
                            if let Ok((signed_public_keys, _)) = SignedPublicKey::from_armor_many(cursor) {
                                for key in signed_public_keys {
                                    if let Ok(parsed_key) = key {
                                        for subkey in &parsed_key.public_subkeys {
                                            existing_fingerprints.insert(subkey.fingerprint());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
    
                // Save only unique keys
                for (i, public_key) in extracted_keys.iter().enumerate() {
                    let cursor = Cursor::new(public_key.as_bytes());
                    if let Ok((signed_public_keys, _)) = SignedPublicKey::from_armor_many(cursor) {
                        let mut is_duplicate = false;
    
                        for key in signed_public_keys {
                            if let Ok(parsed_key) = key {
                                for subkey in &parsed_key.public_subkeys {
                                    if existing_fingerprints.contains(&subkey.fingerprint()) {
                                        is_duplicate = true;
                                        break;
                                    }
                                }
                            }
                            if is_duplicate {
                                break;
                            }
                        }
    
                        if !is_duplicate {
                            let pubkey_filename = pubkey_dir.join(format!("public_key_{}.asc", i + 1));
                            fs::write(&pubkey_filename, public_key).context("Error saving public key")?;
                        }
                    }
                }
            }
    
            // Extract encrypted PGP messages using regex
            let pgp_message_regex = r"(?s)(-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----)";
            let encrypted_messages: Vec<&str> = Regex::new(pgp_message_regex)?
                .captures_iter(&messages)
                .map(|cap| cap.get(0).unwrap().as_str())
                .collect();
    
            if encrypted_messages.is_empty() {
                println!("No encrypted messages found.");
            } else {
                // Ensure the messages directory exists
                let messages_dir = Path::new("messages");
                if !messages_dir.exists() {
                    fs::create_dir_all(messages_dir).context("Creating messages directory")?;
                }
    
                let mut files_to_delete = Vec::new();
    
                for encrypted_message in encrypted_messages {
                    // Generate random file name for the encrypted message
                    let random_file_name = format!("{}.pgp", Uuid::new_v4());
                    let file_path = messages_dir.join(random_file_name);
            
                    // Write the encrypted message to the file
                    fs::write(&file_path, encrypted_message.trim()).context("Writing encrypted message to file")?;
            
                    // Add the file to a list of files to delete later
                    files_to_delete.push(file_path.clone());
            
                    // Look for the keys directory and iterate over secret keys
                    let keys_dir = Path::new("./yourkeys");
                    if keys_dir.exists() {
                        for entry in fs::read_dir(keys_dir).context("Reading keys directory")? {
                            let entry = entry?;
                            let path = entry.path();
                            // Check if the file is a secret key (based on extension)
                            if path.is_file() && path.extension().map_or(false, |ext| ext == "secret") {
                                match decrypt_private_key_from_file(path.to_str().unwrap(), &self.private_password).await {
                                    Ok(decrypted_private_key) => {
                                        // Successfully decrypted the private key
                                        // Now, use the private key to decrypt the message
                                        match decrypt_user_message(file_path.to_str().unwrap(), &decrypted_private_key).await {
                                            Ok(decrypted_message) => {
                                                // If decryption is successful, format and display the message
                                                let decrypted_message = decrypted_message
                                                    .replace("<strong>", "\x1b[1;36m") // Bold cyan start
                                                    .replace("</strong>", "\x1b[0m");  // Reset formatting
            
                                                println!("{}", decrypted_message);
                                                break; // Stop after successfully decrypting the message
                                            }
                                            Err(_) => {
                                                // If decryption failed, continue checking other keys
                                                continue;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        // Handle private key decryption failure
                                        eprintln!("Failed to decrypt private key from {}: {}", path.display(), e);
                                    }
                                }
                            }
                        }
                    } else {
                        println!("Keys directory not found.");
                    }
                }            
    
                for file_path in files_to_delete {
                    fs::remove_file(file_path).context("Failed to remove encrypted message file")?;
                }
            }
    
        } else {
            println!("Failed to fetch messages: {}", response.status());
        }
        Ok(())
    }    

    pub async fn send_message(&self, message: &str) -> Result<()> {
        // Copy all `.public` files from ./yourkeys to ./pubkeys
        let yourkeys_dir = Path::new("./yourkeys");
        let pubkeys_dir = Path::new("./pubkeys");
    
        if yourkeys_dir.exists() {
            if !pubkeys_dir.exists() {
                fs::create_dir_all(pubkeys_dir).context("Failed to create the pubkeys directory")?;
            }
    
            let entries = fs::read_dir(yourkeys_dir)?
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().map(|ext| ext == "public").unwrap_or(false));
    
            for entry in entries {
                let source_path = entry.path();
                let destination_path = pubkeys_dir.join(source_path.file_name().unwrap());
    
                // Copy the file to the pubkeys directory
                fs::copy(&source_path, &destination_path).context(format!(
                    "Failed to copy file {:?} to {:?}",
                    source_path, destination_path
                ))?;
            }
        } else {
            println!("No public keys found in ./yourkeys");
        }
    
        // Step 1: Load the user's public key
        let user_public_key = self.load_user_public_key().await?;
        
        // Step 2: Prepare the public key payload for the first HTTP request
        let public_key_payload = HashMap::from([
            ("message", user_public_key),
            ("password", self.password.clone()),
        ]);

        // Step 3: Create an HTTP client
        let client = Client::new();
        let url = format!("{}/send", self.base_url);

        // Step 4: Prepare headers and include the cookie
        let mut headers = HeaderMap::new();
        if let Some(cookie) = &self.cookie {
            headers.insert(reqwest::header::COOKIE, cookie.parse().context("Invalid cookie format")?);
        } else {
            println!("Warning: No cookie is set. The server might reject the request.");
        }

        // Step 5: Send the public key to the server
        let response = client
            .post(&url)
            .headers(headers) // Attach headers with cookies
            .json(&public_key_payload)
            .send()
            .await
            .context("Error sending public key")?;

        // Step 6: Check if the public key was sent successfully
        if !response.status().is_success() {
            println!("Failed to send public key: {}", response.status());
            return Ok(()); // Exit if the request fails
        }
    
        if yourkeys_dir.exists() {
            if !pubkeys_dir.exists() {
                fs::create_dir_all(pubkeys_dir).context("Failed to create the pubkeys directory")?;
            }
    
            let entries = fs::read_dir(yourkeys_dir)?
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().map(|ext| ext == "public").unwrap_or(false));
    
            for entry in entries {
                let source_path = entry.path();
                let destination_path = pubkeys_dir.join(source_path.file_name().unwrap());
    
                // Copy the file to the pubkeys directory
                fs::copy(&source_path, &destination_path).context(format!(
                    "Failed to copy file {:?} to {:?}",
                    source_path, destination_path
                ))?;
            }
        } else {
            println!("No public keys found in ./yourkeys");
        }
    
        // Step 1: Retrieve fingerprints of all public keys
        let mut fingerprints: Vec<(String, Fingerprint)> = Vec::new();
        let mut seen_fingerprints = HashSet::new(); // To track unique fingerprints

        let pubkey_dir = Path::new("./pubkeys");
        if !pubkey_dir.exists() {
            fs::create_dir_all(pubkey_dir).context("Failed to create the pubkeys directory")?;
        }

        for entry in fs::read_dir(pubkey_dir)?.filter_map(Result::ok) {
            if let Some(ext) = entry.path().extension() {
                if ext == "asc" {
                    if let Ok(public_key) = fs::read_to_string(entry.path()) {
                        let cursor = Cursor::new(public_key.into_bytes());
                        if let Ok((signed_public_keys, _)) = SignedPublicKey::from_armor_many(cursor) {
                            for signed_public_key in signed_public_keys {
                                if let Ok(key) = signed_public_key {
                                    for subkey in &key.public_subkeys {
                                        let fingerprint = subkey.fingerprint();
                                        // Add to the list only if not already seen
                                        if seen_fingerprints.insert(fingerprint.clone()) {
                                            fingerprints.push((
                                                entry.path().to_string_lossy().to_string(),
                                                fingerprint,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Step 2: Display fingerprints to the user and collect choices
        println!("Available recipient fingerprint(s):");
        for (i, (_, fingerprint)) in fingerprints.iter().enumerate() {
            println!("[{}]: {:?}", i + 1, fingerprint); // Using Debug formatting
        }

        // Prompt the user for input
        println!(
            "Enter the numbers of the fingerprints to encrypt for, separated by commas (e.g., 1,3,5), \n\
            or specify a range (e.g., 1-5). You can combine both formats (e.g., 1-3,5,7):"
        );

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let selected_indices: Vec<usize> = input
            .trim()
            .split(',')
            .flat_map(|part| {
                if let Some((start, end)) = part.split_once('-') {
                    // Handle range input
                    if let (Ok(start), Ok(end)) = (start.trim().parse::<usize>(), end.trim().parse::<usize>()) {
                        // Create an inclusive range of indices
                        (start..=end).collect::<Vec<usize>>()
                    } else {
                        Vec::new() // Invalid range, ignore
                    }
                } else {
                    // Handle single index input
                    part.trim().parse::<usize>().ok().into_iter().collect()
                }
            })
            .map(|x| x - 1) // Convert to zero-based indexing
            .collect();

        let selected_keys: Vec<&Fingerprint> = selected_indices
            .into_iter()
            .filter_map(|i| fingerprints.get(i).map(|(_, fingerprint)| fingerprint))
            .collect();

        if selected_keys.is_empty() {
            println!("No valid fingerprints selected. Exiting.");
            return Ok(());
        }
    
        // Step 3: Encrypt the message for the selected fingerprints
        let message = format!("<strong>{}</strong>: {}", self.username, message);
        let mut encrypted_messages: Vec<String> = selected_keys
            .iter()
            .filter_map(|fingerprint| {
                let subkey = fingerprints
                    .iter()
                    .find(|(_, fp)| fp == *fingerprint)
                    .map(|(key_path, _)| key_path.clone());
    
                if let Some(key_path) = subkey {
                    if let Ok(public_key) = fs::read_to_string(key_path) {
                        let cursor = Cursor::new(public_key.into_bytes());
                        if let Ok((signed_public_keys, _)) = SignedPublicKey::from_armor_many(cursor) {
                            for signed_public_key in signed_public_keys {
                                if let Ok(key) = signed_public_key {
                                    for subkey in &key.public_subkeys {
                                        if subkey.fingerprint() == **fingerprint {
                                            if let Ok(encrypted_message) =
                                                encrypt_user_message(message.as_str(), &[subkey])
                                            {
                                                return Some(encrypted_message);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
    
                None
            })
            .collect();

        // Loop through all .public files
        for entry in fs::read_dir(pubkey_dir)?.filter_map(Result::ok) {
            if let Some(ext) = entry.path().extension() {
                if ext == "public" {
                    let key_path = entry.path();

                    if let Ok(public_key) = fs::read_to_string(&key_path) {
                        let cursor = Cursor::new(public_key.into_bytes());
                        if let Ok((signed_public_keys, _)) = SignedPublicKey::from_armor_many(cursor) {
                            for signed_public_key in signed_public_keys {
                                if let Ok(key) = signed_public_key {
                                    for subkey in &key.public_subkeys {
                                        // Encrypt the message using the current .public key
                                        if let Ok(encrypted_message) =
                                            encrypt_user_message(message.as_str(), &[subkey])
                                        {
                                            encrypted_messages.push(encrypted_message);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    
        if encrypted_messages.is_empty() {
            println!("No messages were encrypted.");
            return Ok(());
        }
    
        // Step 4: Send the encrypted messages
        let client = Client::new();
        let url = format!("{}/send", self.base_url);

        for encrypted_message in encrypted_messages {
            let payload = HashMap::from([
                ("message", encrypted_message),
                ("password", self.password.clone()),
            ]);

            // Include the cookie in the request headers
            let mut headers = HeaderMap::new();
            if let Some(cookie) = &self.cookie {
                headers.insert(reqwest::header::COOKIE, cookie.parse().context("Invalid cookie format")?);
            } else {
                println!("Warning: No cookie is set. The server might reject the request.");
            }

            let response = client
                .post(&url)
                .headers(headers) // Attach headers with cookies
                .json(&payload)
                .send()
                .await
                .context("Error sending encrypted message")?;

            if !response.status().is_success() {
                println!("Failed to send encrypted message: {}", response.status());
            }
        }
    
        Ok(())
    }    
    
}
