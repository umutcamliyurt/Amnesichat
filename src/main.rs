#[macro_use]
extern crate rocket;

use rocket::response::{Redirect, content::RawHtml};
use rocket::serde::{Serialize, Deserialize};
use rocket::State;
use rocket::http::Status;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use std::time::{SystemTime, UNIX_EPOCH};
use html_escape::encode_text;
use tokio::time::sleep;
use zeroize::Zeroize;
use rocket::serde::json::Json;

mod encryption;
use crate::encryption::{encrypt_message, decrypt_message, is_message_encrypted};

// Constants
const TIME_WINDOW: u64 = 60;
const MESSAGE_LIMIT: usize = 20; // 20 messages in 60 seconds
const MAX_MESSAGE_LENGTH: usize = 10 * 1024 * 1024; // 10 megabytes
const RECENT_MESSAGE_LIMIT: usize = 100; // Maximum number of messages
const MESSAGE_EXPIRY_DURATION: u64 = 86400; // 1 day

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    content: String,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct MessageData {
    message: String,
    password: String,
}

#[derive(Debug)]
struct ChatState {
    messages: Arc<Mutex<Vec<Message>>>,
    user_request_timestamps: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    recent_messages: Arc<Mutex<HashSet<String>>>,
    global_message_timestamps: Arc<Mutex<Vec<u64>>>,
}

// Manually implement Clone for ChatState with Arc
impl Clone for ChatState {
    fn clone(&self) -> Self {
        ChatState {
            messages: Arc::clone(&self.messages),
            user_request_timestamps: Arc::clone(&self.user_request_timestamps),
            recent_messages: Arc::clone(&self.recent_messages),
            global_message_timestamps: Arc::clone(&self.global_message_timestamps),
        }
    }
}

// Helper function to format the timestamp into HH:MM:SS
fn format_timestamp(timestamp: u64) -> String {
    let seconds = timestamp % 60;
    let minutes = (timestamp / 60) % 60;
    let hours = (timestamp / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

// Function to check if the message count exceeds the limit globally
async fn check_message_limit(state: &ChatState) -> bool {
    let mut global_timestamps = state.global_message_timestamps.lock().await;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Remove messages older than the time window (60 seconds)
    global_timestamps.retain(|&timestamp| current_time - timestamp <= TIME_WINDOW);

    // Check if we have exceeded the message limit (20 messages in 60 seconds)
    if global_timestamps.len() >= MESSAGE_LIMIT {
        return false; // Exceeded the limit
    }

    // Record the current message timestamp
    global_timestamps.push(current_time);
    true
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

#[get("/messages?<password>")]
async fn messages(password: Option<String>, state: &State<Arc<ChatState>>) -> String {
    let chat_state = state.inner();
    let messages = chat_state.messages.lock().await;

    let mut html = String::new();
    for message in messages.iter() {
        // Format timestamp for display
        let timestamp = format_timestamp(message.timestamp);

        // Decrypt message content based on the provided password, if available
        let decrypted_content = match &password {
            Some(ref pw) => decrypt_message(&message.content, pw).unwrap_or_else(|_| {
                // Return nothing when decryption fails
                return String::new();  // Empty string will effectively remove the message from HTML
            }),
            None => String::new(),  // No password provided, return empty content
        };

        // If decryption fails (decrypted_content is empty), skip appending the message
        if decrypted_content.is_empty() {
            continue;  // Skip this message entirely
        }

        // Display the decrypted content, or nothing if decryption failed
        html.push_str(&format!(
            r#"<p>[{}]: {}</p>"#,
            timestamp,
            encode_text(&decrypted_content)
        ));
    }

    html
}

#[get("/?<password>")]
async fn index(password: Option<String>, state: &State<Arc<ChatState>>) -> Result<RawHtml<String>, Status> {
    // Read the static HTML template
    let mut html = tokio::fs::read_to_string("static/index.html")
        .await
        .map_err(|_error| Status::InternalServerError)?;

    // Get password, defaulting to empty string if not provided
    // Safely handle temporary value by assigning them to variable
    let password_value = password.clone().unwrap_or_else(|| "".to_string());

    // Safely encode them using encode_text.
    let encoded_password = encode_text(&password_value);

    // Replace placeholder with actual values
    html = html.replace("PASSWORD_PLACEHOLDER", &encoded_password);

    // Get current chat messages and generate HTML for them
    let messages = state.messages.lock().await;
    let mut messages_html = String::new();

    for msg in messages.iter() {
        let timestamp = format_timestamp(msg.timestamp);

        // Decrypt message content based on provided password
        let decrypted_content = if let Some(ref pw) = password {
            decrypt_message(&msg.content, pw).unwrap_or_else(|_| "Decryption failed".to_string())
        } else {
            "Password not provided".to_string()
        };

        // Add the message to the HTML string
        messages_html.push_str(&format!(
            "<p>[{}]: {}</p>",
            timestamp,
            encode_text(&decrypted_content)
        ));
    }

    // Insert messages into the HTML template
    html = html.replace("<!-- Messages will be dynamically inserted here -->", &messages_html);

    // Return the final HTML to the client
    Ok(RawHtml(html))
}

// Route for sending a message with encryption
#[post("/send", data = "<message_data>")]
async fn send(message_data: Json<MessageData>, state: &State<Arc<ChatState>>) -> Result<Redirect, RawHtml<String>> {
    let message = message_data.message.trim();
    let password = message_data.password.trim();

    // Delay message processing by 2 seconds
    sleep(Duration::from_secs(2)).await;

    // Check if the message limit has been exceeded globally
    if !check_message_limit(&state.inner()).await {
        return Err(RawHtml("Too many messages sent in a short period. Please wait for 2 minutes.".to_string()));
    }

    // Reject the request if the room password field is empty
    if password.is_empty() {
        return Err(RawHtml("Room password cannot be empty. Please provide a password.".to_string()));
    }

    // Check if the password is at least 8 characters long
    if password.len() < 8 {
        return Err(RawHtml("Room password must be at least 8 characters long.".to_string()));
    }

    // Check if the message is valid (length and total message count)
    if !is_message_valid(message, state).await {
        return Err(RawHtml("Invalid message. Make sure it's less than 10MB.".to_string()));
    }

    // Check if the message is encrypted
    if !is_message_encrypted(message) {
        return Err(RawHtml("Message is not encrypted. Please provide an encrypted message.".to_string()));
    }

    let mut messages = state.messages.lock().await;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let encrypted_content = encrypt_message(message, password).map_err(|_| RawHtml("Encryption failed.".to_string()))?;

    messages.push(Message {
        content: encrypted_content,
        timestamp,
    });

    Ok(Redirect::to(format!("/")))
}

// Function to wipe message content securely
fn wipe_message_content(message: &mut Message) {
    // Securely zero out the message content
    message.content.zeroize();
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
// Main function to launch the Rocket server
#[tokio::main]
async fn main() {
    let chat_state = Arc::new(ChatState {
        messages: Arc::new(Mutex::new(Vec::new())),
        user_request_timestamps: Arc::new(Mutex::new(HashMap::new())),
        recent_messages: Arc::new(Mutex::new(HashSet::new())),
        global_message_timestamps: Arc::new(Mutex::new(Vec::new())),
    });

    // Launch the message cleanup task
    tokio::spawn(message_cleanup_task(Arc::clone(&chat_state)));

    // Launch the Rocket application
    rocket::build()
        .manage(chat_state)
        .mount("/", routes![index, send, messages])
        .mount("/static", rocket::fs::FileServer::from("static"))
        .launch()
        .await
        .unwrap(); // Ensure the Rocket server is awaited and handle any errors
}
