#[macro_use]
extern crate rocket;

use rocket::response::Redirect;
use rocket::serde::{Serialize, Deserialize};
use rocket::State;
use rocket::response::content::RawHtml;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use std::time::{SystemTime, UNIX_EPOCH};
use html_escape::encode_text;
use tokio::time::sleep;

// Import encryption dependencies
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::Rng;
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};

// Type alias for AES-256-CBC
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Constants for the encryption
const ENCRYPTION_IV_SIZE: usize = 16;

// Constants
const TIME_WINDOW: u64 = 60;
const REQUEST_LIMIT: u64 = 5;
const MAX_USERNAME_LENGTH: usize = 30;
const MAX_MESSAGE_LENGTH: usize = 200;
const RECENT_MESSAGE_LIMIT: usize = 1000; // Maximum number of messages
const MESSAGE_EXPIRY_DURATION: u64 = 86400; // 1 day

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    username: String,
    content: String,
    timestamp: u64,
}

#[derive(Debug)]
struct ChatState {
    messages: Arc<Mutex<Vec<Message>>>,
    user_request_timestamps: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    recent_messages: Arc<Mutex<HashSet<String>>>,
}

// Manually implement Clone for ChatState with Arc
impl Clone for ChatState {
    fn clone(&self) -> Self {
        ChatState {
            messages: Arc::clone(&self.messages),
            user_request_timestamps: Arc::clone(&self.user_request_timestamps),
            recent_messages: Arc::clone(&self.recent_messages),
        }
    }
}

// Encryption key derivation function with salt
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::b64_encode(salt).expect("Failed to generate salt string");  // Convert salt to SaltString format
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");

    let hash_bytes = hash.hash.expect("Hash missing in PasswordHash structure");  // Access the hash directly

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    key
}


// Encryption function
fn encrypt_message(plain_text: &str, password: &str) -> Result<String, &'static str> {
    let mut rng = rand::thread_rng();
    let iv: [u8; ENCRYPTION_IV_SIZE] = rng.gen();
    let salt: [u8; 16] = rng.gen();

    let key = derive_key(password, &salt); // Pass salt as an argument
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|_| "Encryption error")?;
    let encrypted_data = cipher.encrypt_vec(plain_text.as_bytes());

    Ok(format!("{}:{}:{}", hex::encode(salt), hex::encode(iv), hex::encode(encrypted_data)))
}



// Decryption function
fn decrypt_message(encrypted_text: &str, password: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted message format");
    }

    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error")?;
    let iv = hex::decode(parts[1]).map_err(|_| "Decryption error")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error")?;

    // Derive key using PBKDF2 with the extracted salt
    let key = derive_key(password, &salt);

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|_| "Decryption error")?;
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).map_err(|_| "Decryption error")?;

    String::from_utf8(decrypted_data).map_err(|_| "Decryption error")
}



// Helper function to format the timestamp into HH:MM:SS
fn format_timestamp(timestamp: u64) -> String {
    let seconds = timestamp % 60;
    let minutes = (timestamp / 60) % 60;
    let hours = (timestamp / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

// Check if a user is allowed to send a message based on rate-limiting
async fn is_request_allowed(username: &str, state: &ChatState) -> bool {
    let mut timestamps = state.user_request_timestamps.lock().await;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Check if the user has made requests before
    if let Some((last_request_time, request_count)) = timestamps.get_mut(username) {
        if current_time - *last_request_time > TIME_WINDOW {
            // Reset count if the time window has passed
            *last_request_time = current_time;
            *request_count = 1; // Reset count for the new time window
            true
        } else if *request_count < REQUEST_LIMIT {
            // Increment count if within limits
            *request_count += 1;
            true
        } else {
            // Rate limit exceeded
            false
        }
    } else {
        // New user, initialize their count
        timestamps.insert(username.to_string(), (current_time, 1));
        true
    }
}

// Function to check if the message is valid (length and total message count)
async fn is_message_valid(message: &str, state: &ChatState) -> bool {
    // Check if the message length exceeds the maximum limit
    if message.len() > MAX_MESSAGE_LENGTH {
        return false;
    }

    // Lock the messages state to access the total message count
    let mut messages = state.messages.lock().await;

    // Check if the total number of messages exceeds the limit
    if messages.len() >= RECENT_MESSAGE_LIMIT {
        // Wipe the content of the oldest message before removing it
        wipe_message_content(&mut messages[0]);
        messages.remove(0); // Remove the first message in the vector (oldest)
    }

    true
}

// Index route to render chat interface with decrypted messages
#[get("/?<username>&<password>")]
async fn index(username: Option<String>, password: Option<String>, state: &State<Arc<ChatState>>) -> RawHtml<String> {
    let messages = state.messages.lock().await;

    let mut html = String::from(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
            <meta http-equiv="refresh" content="60">
            <title>Amnesichat</title>
            <style>
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }
                body {
                    background-color: #000000;
                    color: #e0e0e0;
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    flex-direction: column;
                    min-height: 100vh;
                }
                h1 {
                    font-size: 1.5em;
                    text-align: center;
                    color: #ffffff;
                    margin-bottom: 10px;
                }
                #disclaimer {
                    font-size: 0.9em;
                    text-align: center;
                    margin-bottom: 15px;
                    font-style: italic;
                }
                #chat-container {
                    flex: 1;
                    background-color: #1e1e1e;
                    padding: 10px;
                    margin: 10px;
                    border-radius: 8px;
                    overflow-y: auto;
                    display: flex;
                    flex-direction: column;
                    max-height: 70vh;
                }
                #messages {
                    flex: 1;
                    overflow-y: auto;
                }
                #messages p {
                    background-color: #2e2e2e;
                    border-left: 4px solid #00c853;
                    padding: 10px;
                    margin-bottom: 10px;
                    border-radius: 6px;
                    line-height: 1.5;
                }
                #chat-form {
                    background-color: #1c1c1c;
                    padding: 10px;
                    border-radius: 8px;
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    box-shadow: 0 -4px 10px rgba(0, 0, 0, 0.5);
                }
                input[type="text"], input[type="password"], input[type="submit"] {
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 5px;
                    width: 100%;
                    max-width: 100%;
                    background-color: #2e2e2e;
                    color: #e0e0e0;
                    border: 1px solid #444;
                }
                input[type="submit"] {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    cursor: pointer;
                    transition: background-color 0.3s ease;
                }
                input[type="submit"]:hover {
                    background-color: #0056b3;
                }
                @media (max-width: 768px) {
                    h1 {
                        font-size: 1.2em;
                    }
                    #chat-container {
                        max-height: 60vh;
                        margin: 5px;
                    }
                    #chat-form {
                        padding: 10px;
                    }
                    input[type="text"], input[type="submit"], input[type="password"] {
                        font-size: 1em;
                        padding: 8px;
                    }
                }
                #footer {
                    text-align: center;
                    margin-top: 15px;
                }
                #footer a {
                    color: #007bff;
                    text-decoration: none;
                }
                #footer a:hover {
                    text-decoration: underline;
                }
                details {
                    background-color: #1c1c1c;
                    border-radius: 8px;
                    margin: 10px 0;
                    padding: 10px;
                }
                summary {
                    cursor: pointer;
                    outline: none;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <h1>Amnesichat</h1>
            <div id="disclaimer">Warning: By using this service, you agree to the terms of service and acknowledge that you will not use it for illegal activities. The developer is not responsible for any misuse of the tool.</div>
            <div id="chat-container">
                <h2>Messages:</h2>
                <div id="messages">
        "#,
    );

    for msg in messages.iter() {
        let timestamp = format_timestamp(msg.timestamp);
        
        // Decrypt the message content using the provided password
        let decrypted_content = match &password {
            Some(ref pw) => decrypt_message(&msg.content, pw), // Directly using the password
            None => Err("Password not provided"), // Handle missing password case
        };

        // Only push to HTML if decryption is successful
        if let Ok(content) = decrypted_content {
            html.push_str(&format!(
                "<p><strong>{}</strong> [{}]: {}</p>",
                encode_text(&msg.username), // Escape username
                timestamp,
                encode_text(&content) // Escape decrypted message content
            ));
        } // Ignore messages with decryption failure
    }

    html.push_str(
        r#"
                </div>
            </div>
            <div id="chat-form">
                <form action="/send" method="get">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required value="USERNAME_PLACEHOLDER"><br>
                    <label for="message">Message:</label>
                    <input type="text" id="message" name="message" required><br>
                    <label for="password">Pre-Shared Password (Optional):</label>
                    <input type="text" id="password" name="password" value="PASSWORD_PLACEHOLDER"><br> <!-- Allow empty value -->
                    <input type="submit" value="Send">
                </form>
            </div>
            <div id="footer">
                <p>
                    <a href="https://github.com/umutcamliyurt/Amnesichat" target="_blank">Source Code</a> |
                    <a href="monero:8495bkvsReJAvxm8YP5KUQ9BWxh6Ta63eZGjF4HqU4JcUXdQtXBeBGyWte8L95sSJUMUvh5GHD1RcTNebfTNmFgmRX4XJja">Donate Monero</a>
                </p>
                <details>
                    <summary>Privacy Policy</summary>
                    <p>Your privacy is of utmost importance to us. This Privacy Policy outlines how we handle your information when you use our services.</p>
                    <p>We do not collect, store, or share any personal information or chat logs from users. All messages are temporary and are deleted once the chat session ends.</p>
                    <p>All communication on Amnesichat is encrypted using industry-standard encryption protocols to ensure your conversations remain private and secure.</p>
                    <p>Our service does not use cookies or any tracking technologies to collect data about your usage. We do not monitor your activities on our platform.</p>
                    <p>We may update this Privacy Policy from time to time to reflect changes in our practices. We encourage you to periodically review this page for the latest information on our privacy practices.</p>
                    <p>If you have any questions about this Privacy Policy or our data practices, please contact us at nemesisuks@protonmail.com.</p>
                </details>

                <details>
                    <summary>Terms of Service</summary>
                    <p>By accessing or using Amnesichat, you agree to be bound by the following terms and conditions:</p>
                    <p>These Terms of Service govern your use of the Amnesichat service. If you do not agree to these terms, you should not use the service.</p>
                    <p>You agree to use Amnesichat solely for lawful purposes. Prohibited activities include, but are not limited to:</p>
                    <ul>
                        Engaging in any form of harassment, abuse, or harmful behavior towards others.
                        Sharing illegal content or engaging in illegal activities.
                        Attempting to access, interfere with, or disrupt the service or servers.
                        Impersonating any person or entity or misrepresenting your affiliation with a person or entity.
                    </ul>
                    <p>Amnesichat is not responsible for any loss, damage, or harm resulting from your use of the service or any third-party interactions. Use of the service is at your own risk.</p>
                    <p>We reserve the right to modify or discontinue the service at any time without notice. We will not be liable for any modification, suspension, or discontinuance of the service.</p>
                    <p>These Terms of Service shall be governed by and construed in accordance with the laws of Türkiye.</p>
                    <p>We may update these Terms of Service from time to time. We will notify users of any significant changes by posting a notice on our website. Continued use of the service after changes signifies your acceptance of the new terms.</p>
                    <p>If you have any questions regarding these Terms of Service, please contact us at nemesisuks@protonmail.com.</p>
                </details>

            </div>
        </body>
        </html>
        "#
    );

    let username_value = username.unwrap_or_else(|| "".to_string());
    let password_value = password.unwrap_or_else(|| "".to_string());
    let final_html = html
        .replace("USERNAME_PLACEHOLDER", &username_value)
        .replace("PASSWORD_PLACEHOLDER", &password_value);
    RawHtml(final_html)
}

// Route for sending a message with encryption
#[get("/send?<username>&<message>&<password>")]
async fn send(username: String, message: String, password: String, state: &State<Arc<ChatState>>) -> Result<Redirect, RawHtml<String>> {
    let username = username.trim();
    let message = message.trim();
    let password = password.trim();

    // Delay message processing by 10 seconds
    sleep(Duration::from_secs(10)).await;

    // Check if the username length exceeds the maximum limit
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(RawHtml("Username is too long. Please use a shorter username.".to_string()));
    }

    // Validate the request frequency limit
    if !is_request_allowed(username, state).await {
        return Err(RawHtml("You are sending messages too quickly. Please wait a moment.".to_string()));
    }

    // Check if the message is valid (length and total message count)
    if !is_message_valid(message, state).await {
        return Err(RawHtml("Invalid message. Make sure it's less than 200 characters.".to_string()));
    }

    // Lock the messages state
    let mut messages = state.messages.lock().await;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Encrypt the message using the provided password
    let encrypted_content = encrypt_message(message, password).map_err(|_| RawHtml("Encryption failed.".to_string()))?;

    // Store the encrypted message
    messages.push(Message {
        username: username.to_string(),
        content: encrypted_content,
        timestamp,
    });

    // Redirect to the main page, including the username and password in the URL
    Ok(Redirect::to(format!("/?username={}&password={}", username, password)))
}

// Function to wipe message content securely
fn wipe_message_content(message: &mut Message) {
    // Overwrite the message content with zeros
    let empty_content = vec![0u8; message.content.len()];
    message.content = String::from_utf8(empty_content).unwrap_or_default();
}

// Cleanup task to remove expired messages and securely wipe their contents
async fn message_cleanup_task(state: Arc<ChatState>) {
    let mut interval = interval(Duration::from_secs(1)); // Check every second

    loop {
        interval.tick().await; // Wait for the next tick of the interval

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Acquire the lock on messages
        let mut messages = state.messages.lock().await;

        // Check if there are messages that should be wiped
        if let Some(oldest_message_index) = messages.iter().position(|message| {
            current_time - message.timestamp >= MESSAGE_EXPIRY_DURATION
        }) {
            // Securely wipe the content of the oldest message
            wipe_message_content(&mut messages[oldest_message_index]);

            // Remove the oldest message
            messages.remove(oldest_message_index);
        }
    }
}

#[launch]
async fn rocket() -> _ {
    let chat_state = Arc::new(ChatState {
        messages: Arc::new(Mutex::new(vec![])),
        user_request_timestamps: Arc::new(Mutex::new(HashMap::new())),
        recent_messages: Arc::new(Mutex::new(HashSet::new())),
    });

    // Spawn the message cleanup task
    let cleanup_task_state = Arc::clone(&chat_state);
    tokio::spawn(message_cleanup_task(cleanup_task_state));

    rocket::build()
        .manage(chat_state)
        .mount("/", routes![index, send])
}
