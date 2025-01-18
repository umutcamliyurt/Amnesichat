use crate::encrypt_data;
use crate::receive_and_fetch_messages;
use crate::send_encrypted_message;
use eframe::egui;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use regex::Regex;

pub struct MessagingApp {
    username: String,
    message_input: String,
    messages: Arc<Mutex<Vec<String>>>,
    shared_hybrid_secret: Arc<std::string::String>,
    shared_room_id: Arc<String>,
    shared_url: Arc<String>,
}

impl MessagingApp {
    pub fn new(
        username: String,
        shared_hybrid_secret: Arc<std::string::String>,
        shared_room_id: Arc<String>,
        shared_url: Arc<String>,
    ) -> Self {
        let messages = Arc::new(Mutex::new(vec![]));
        let messages_clone = Arc::clone(&messages);
        let shared_hybrid_secret_clone = Arc::clone(&shared_hybrid_secret);
        let shared_room_id_clone = Arc::clone(&shared_room_id);
        let shared_url_clone = Arc::clone(&shared_url);

        thread::spawn(move || loop {
            match receive_and_fetch_messages(
                &shared_room_id_clone,
                &shared_hybrid_secret_clone,
                &shared_url_clone,
                true,
            ) {
                Ok(new_messages) => {
                    let mut msgs = messages_clone.lock().unwrap();
                    msgs.clear();
                    msgs.extend(new_messages);
                }
                Err(e) => {
                    eprintln!("Error fetching messages: {}", e);
                }
            }
            thread::sleep(Duration::from_secs(10));
        });

        MessagingApp {
            username,
            message_input: String::new(),
            messages,
            shared_hybrid_secret,
            shared_room_id,
            shared_url,
        }
    }
}

impl eframe::App for MessagingApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Main layout for the UI
            ui.vertical(|ui| {
                // Fixed height for the scrollable area (chat messages container)
                let chat_area_height = ui.available_height() - 80.0; // Reserve space for input box and padding

                // Scrollable area for messages within a fixed-size container
                egui::Frame::none()
                    .fill(egui::Color32::from_black_alpha(50))
                    .rounding(10.0)
                    .inner_margin(egui::style::Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.set_height(chat_area_height); // Limit the height of the chat area
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                let messages = self.messages.lock().unwrap();
                                let re = Regex::new(r"</?strong>").unwrap(); // Regex to remove <strong> tags

                                for message in messages.iter() {
                                    let cleaned_message = re.replace_all(message, ""); // Clean HTML tags

                                    // Display message directly in the chatbox without bubble styling
                                    ui.label(
                                        egui::RichText::new(cleaned_message.as_ref())
                                            .size(16.0)
                                            .color(egui::Color32::WHITE),
                                    );
                                }
                            });
                    });

                // Input box with modern styling and button improvements
                ui.horizontal(|ui| {
                    let input_box_width = ui.available_width() * 0.8;
                    let button_width = ui.available_width() * 0.18;

                    // Modern input box with a subtle border and soft background
                    let text_edit = egui::TextEdit::singleline(&mut self.message_input)
                        .hint_text("Type a message...")
                        .text_color(egui::Color32::WHITE)
                        .frame(true);
                    ui.add_sized([input_box_width, 40.0], text_edit);

                    // Send button with modern hover and pressed effects
                    if ui.add_sized([button_width, 40.0], egui::Button::new("Send"))
                        .clicked()
                    {
                        let message = format!("<strong>{}</strong>: {}", self.username, self.message_input);
                        if let Err(e) = send_encrypted_message(
                            &encrypt_data(&message, &self.shared_hybrid_secret).unwrap(),
                            &self.shared_room_id,
                            &self.shared_url,
                        ) {
                            eprintln!("Error sending message: {}", e);
                        } else {
                            self.message_input.clear(); // Clear the input field after sending
                        }
                    }
                });
            });
        });
    }
}

pub fn run_gui(
    username: String,
    shared_hybrid_secret: Arc<std::string::String>,
    shared_room_id: Arc<String>,
    shared_url: Arc<String>,
) -> Result<(), eframe::Error> {
    let app = MessagingApp::new(
        username,
        shared_hybrid_secret,
        shared_room_id,
        shared_url,
    );
    let native_options = eframe::NativeOptions {
        ..Default::default()
    };
    eframe::run_native("Amnesichat", native_options, Box::new(|_| Box::new(app)))
}
