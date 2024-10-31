import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import io
import itertools
import time
import re
import base64
from PIL import Image, ImageTk
from client_v2 import (
    send_request, key_exchange, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, encode_with_base64, decode_with_base64
)

# Global variables
shared_keys = {"lock": threading.Lock(), "keys": []}
username = ""
password = ""

class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Amnesichat")
        self.root.geometry("600x400")
        self.root.minsize(600, 400)

        # Set modern colors
        self.dark_bg = "#2E2E2E"
        self.dark_fg = "#FFFFFF"
        self.accent_color = "#4A90E2"  # Blue for all messages
        self.button_hover_color = "#2F80ED"
        self.text_color = "#E1E1E1"
        self.entry_bg = "#3C3C3C"

        # Configure root window background
        self.root.configure(bg=self.dark_bg)

        # Set modern font
        style = ttk.Style()
        style.theme_use("clam")

        # General styles
        style.configure("TLabel", background=self.dark_bg, foreground=self.dark_fg, font=("Segoe UI", 12))
        style.configure("TButton", background=self.accent_color, foreground=self.dark_fg, font=("Segoe UI", 12, "bold"), padding=10)
        style.map("TButton", background=[("active", self.button_hover_color)])
        style.configure("TEntry", foreground=self.text_color, fieldbackground=self.entry_bg, font=("Segoe UI", 12))
        style.configure("TFrame", background=self.dark_bg)

        # Username and password inputs
        self.setup_frame = ttk.Frame(root, padding="20")
        self.setup_frame.grid(column=0, row=0, sticky="NSEW")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        ttk.Label(self.setup_frame, text="Host:").grid(column=0, row=0, sticky="E", padx=5, pady=10)
        self.host_entry = ttk.Entry(self.setup_frame, width=40)
        self.host_entry.insert(0, "http://localhost:8080")
        self.host_entry.grid(column=1, row=0, sticky="W", padx=5, pady=10)

        ttk.Label(self.setup_frame, text="Username:").grid(column=0, row=1, sticky="E", padx=5, pady=10)
        self.username_entry = ttk.Entry(self.setup_frame, width=40)
        self.username_entry.grid(column=1, row=1, sticky="W", padx=5, pady=10)

        ttk.Label(self.setup_frame, text="Room Password:").grid(column=0, row=2, sticky="E", padx=5, pady=10)
        self.password_entry = ttk.Entry(self.setup_frame, show="*", width=40)
        self.password_entry.grid(column=1, row=2, sticky="W", padx=5, pady=10)

        ttk.Label(self.setup_frame, text="Encryption Password:").grid(column=0, row=3, sticky="E", padx=5, pady=10)
        self.encryption_password_entry = ttk.Entry(self.setup_frame, show="*", width=40)
        self.encryption_password_entry.grid(column=1, row=3, sticky="W", padx=5, pady=10)

        self.start_button = ttk.Button(self.setup_frame, text="Start Chat", command=self.start_chat)
        self.start_button.grid(column=0, row=4, columnspan=2, pady=20)

        # Chat frame
        self.chat_frame = ttk.Frame(root, padding="20")
        self.chat_frame.grid(column=0, row=0, sticky="NSEW")

        self.chat_frame.columnconfigure(0, weight=1)
        self.chat_frame.rowconfigure(0, weight=1)

        self.message_canvas = tk.Canvas(
            self.chat_frame,
            bg=self.dark_bg,
            highlightthickness=0
        )
        self.message_canvas.grid(column=0, row=0, columnspan=3, sticky="NSEW", padx=5, pady=5)

        self.message_frame = ttk.Frame(self.message_canvas)
        self.message_canvas.create_window((0, 0), window=self.message_frame, anchor="nw")

        self.message_frame.bind("<Configure>", lambda _: self.message_canvas.configure(scrollregion=self.message_canvas.bbox("all")))

        self.scrollbar = ttk.Scrollbar(self.chat_frame, orient="vertical", command=self.message_canvas.yview)
        self.scrollbar.grid(column=3, row=0, sticky="NS")
        self.message_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.message_entry = ttk.Entry(self.chat_frame, font=("Segoe UI", 12), width=50)
        self.message_entry.grid(column=0, row=1, sticky="EW", padx=5, pady=10)

        self.send_button = ttk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.grid(column=1, row=1, sticky="W", padx=5, pady=10)

        self.image_button = ttk.Button(self.chat_frame, text="Send Image", command=self.send_image)
        self.image_button.grid(column=2, row=1, sticky="W", padx=5, pady=10)

        # Hide the chat frame initially
        self.chat_frame.grid_remove()

        # Thread to receive messages periodically
        self.running = True
        self.message_thread = threading.Thread(target=self.receive_messages_periodically, daemon=True)

    def start_chat(self):
        global username, password, shared_keys

        host = self.host_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        encryption_password = self.encryption_password_entry.get().strip()

        if not host or not username or not password or not encryption_password:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            initial_keys = key_exchange(password, username, host, encryption_password)
            if not initial_keys:
                raise ValueError("Initial key exchange failed.")

            with shared_keys["lock"]:
                shared_keys["keys"] = initial_keys

            messagebox.showinfo("Success", "Connected successfully!")

            self.setup_frame.grid_remove()
            self.chat_frame.grid()

            if not self.message_thread.is_alive():
                self.message_thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start chat: {e}")

    def send_message(self):
        global shared_keys, username, password
        message = self.message_entry.get().strip()
        if not message:
            return

        self.process_and_send_message(f"<strong>{username}:</strong> {message}")

    def send_image(self):
        global shared_keys, username, password
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
        if not file_path:
            return

        try:
            with open(file_path, "rb") as image_file:
                image_data = base64.b64encode(image_file.read()).decode()
                message = f"IMAGE_DATA:{image_data}"
                self.process_and_send_message(message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send image: {e}")

    def process_and_send_message(self, content):
        global shared_keys, username, password

        with shared_keys["lock"]:
            current_keys = shared_keys["keys"]

        if not current_keys:
            messagebox.showerror("Error", "No keys available for encryption.")
            return

        current_key = next(itertools.cycle(current_keys))
        encrypted_message = chacha20_poly1305_encrypt(content.encode(), current_key)
        encrypted_message_b64 = encode_with_base64(encrypted_message)

        try:
            response = send_request(f"{self.host_entry.get()}/send", {
                "message": f"-----BEGIN ENCRYPTED MESSAGE-----\n{encrypted_message_b64}\n-----END ENCRYPTED MESSAGE-----",
                "password": password
            }, "POST")

            if response.status_code == 200:
                self.message_entry.delete(0, tk.END)
                if content.startswith("IMAGE_DATA:"):
                    self.add_image_bubble(content)
                else:
                    self.add_message_bubble(content)
            else:
                messagebox.showerror("Error", f"Failed to send message. HTTP {response.status_code}")
        except Exception as e:
            messagebox.showerror("Error", f"Error sending message: {e}")

    def receive_messages_periodically(self):
        while self.running:
            try:
                with shared_keys["lock"]:
                    current_keys = shared_keys["keys"]

                if not current_keys:
                    self.clear_message_area()
                    self.add_message_bubble("No keys available to decrypt messages.")
                    continue

                response = send_request(f"{self.host_entry.get()}/messages", {"password": password})
                if response.status_code != 200:
                    self.clear_message_area()
                    self.add_message_bubble(f"Failed to fetch messages. HTTP {response.status_code}")
                    continue

                self.clear_message_area()

                for match in re.finditer(r"-----BEGIN ENCRYPTED MESSAGE-----(.*?)-----END ENCRYPTED MESSAGE-----", response.text, re.DOTALL):
                    encrypted_data_b64 = match.group(1).strip()
                    encrypted_data = decode_with_base64(encrypted_data_b64)

                    decrypted_message = None
                    for key in current_keys:
                        try:
                            decrypted_message = chacha20_poly1305_decrypt(encrypted_data, key)
                            break
                        except:
                            continue

                    if decrypted_message:
                        decoded_message = decrypted_message.decode()
                        if decoded_message.startswith("IMAGE_DATA:"):
                            self.add_image_bubble(decoded_message)
                        else:
                            self.add_message_bubble(decoded_message)

            except Exception as e:
                self.clear_message_area()
                self.add_message_bubble(f"Error: {e}")

            time.sleep(5)

    def add_message_bubble(self, message):
        bubble_frame = ttk.Frame(self.message_frame)
        bubble_frame.pack(anchor="w", pady=5, padx=10, fill="x")  # Bubble frame with padding

        # Create a container for the colored background
        bubble_container = tk.Frame(
            bubble_frame,
            bg=self.accent_color,  # The blue background color
            padx=10,  # Symmetric padding inside the bubble
            pady=5,   # Symmetric padding inside the bubble
        )
        bubble_container.pack(anchor="w", padx=10, pady=5, fill="x")  # Outer padding and alignment

        # Split the message into parts for bold and normal text
        parts = re.split(r"(<strong>.*?</strong>)", message)
        for part in parts:
            if part.startswith("<strong>") and part.endswith("</strong>"):
                bold_text = part[8:-9]
                label = tk.Label(
                    bubble_container,
                    text=bold_text,
                    bg=self.accent_color,
                    fg=self.dark_fg,
                    wraplength=500,
                    font=("Segoe UI", 12, "bold"),
                    justify="left",
                )
            else:
                label = tk.Label(
                    bubble_container,
                    text=part,
                    bg=self.accent_color,
                    fg=self.dark_fg,
                    wraplength=500,
                    font=("Segoe UI", 12),
                    justify="left",
                )
            label.pack(side="left", anchor="w", padx=2)  # Slight padding between text parts


    def add_image_bubble(self, message):
        image_data = message[len("IMAGE_DATA:"):]
        bubble_frame = ttk.Frame(self.message_frame)
        bubble_frame.pack(anchor="w", pady=5, padx=10)

        try:
            image_bytes = base64.b64decode(image_data)
            image = Image.open(io.BytesIO(image_bytes))

            # Get screen dimensions
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()

            # Set maximum dimensions (90% of screen width and height)
            max_width = int(screen_width * 0.9)
            max_height = int(screen_height * 0.9)

            # Maintain aspect ratio
            image.thumbnail((max_width, max_height))

            photo = ImageTk.PhotoImage(image)

            label = tk.Label(bubble_frame, image=photo, bg=self.dark_bg)
            label.image = photo
            label.pack()
        except Exception as e:
            self.add_message_bubble(f"[Failed to load image: {e}]")

    def clear_message_area(self):
        for widget in self.message_frame.winfo_children():
            widget.destroy()

    def stop(self):
        self.running = False

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop(), root.destroy()))
    root.mainloop()
