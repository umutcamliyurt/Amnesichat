import os
import re
import requests
import gnupg
import time
import threading
from hashlib import sha512
import base64
import climage
import getpass
import atexit
import uuid
import tempfile


class AmnesichatClient:
    def __init__(self, base_url, port=None, cookie=None):
        self.base_url = f"{base_url}:{port}" if port else base_url
        # Use a temporary GPG directory to avoid affecting the main GPG keyring
        self.gpg = gnupg.GPG(gnupghome=tempfile.mkdtemp())
        self.private_key_fingerprint = None
        self.public_keys = []
        self.password = ""
        self.passphrase = ""
        self.cookie = cookie  # Store the cookie (if provided)

    def configure(self, password, passphrase, private_key_path, public_key_path):
        """Load keys and set credentials automatically."""
        self.set_password(password)
        self.set_passphrase(passphrase)
        self.load_private_key(private_key_path)
        self.load_public_key(public_key_path)
    
    def set_password(self, password):
        self.password = password

    def set_passphrase(self, passphrase):
        self.passphrase = passphrase

    def load_private_key(self, filepath):
        """Load private key from a file."""
        try:
            with open(filepath, 'r') as f:
                key_data = f.read()
            import_result = self.gpg.import_keys(key_data)
            if import_result.fingerprints:
                self.private_key_fingerprint = import_result.fingerprints[0]
                print("Private key loaded successfully.")
            else:
                print("Failed to load private key.")
        except Exception as e:
            print(f"Error loading private key: {e}")

    def load_public_key(self, filepath):
        """Load a single public key from a file and import it into the GPG keyring."""
        try:
            # Check if the file exists
            if not os.path.exists(filepath):
                print(f"Public key file {filepath} not found.")
                return
            
            # Read the public key from the file
            with open(filepath, 'r') as f:
                key_data = f.read()

            # Create a temporary directory to store the key (if needed)
            temp_key_dir = "temp_keys"
            os.makedirs(temp_key_dir, exist_ok=True)  # Create a temporary directory for keys

            # Generate a temporary filename for the public key
            temp_public_key_path = os.path.join(temp_key_dir, f"{uuid.uuid4()}.asc")
            
            # Save the public key to the temporary directory
            with open(temp_public_key_path, 'w') as temp_key_file:
                temp_key_file.write(key_data)
            
            # Import the public key into the GPG keyring
            gpg = gnupg.GPG()
            import_result = gpg.import_keys(key_data)
            
            if import_result.fingerprints:
                # Assuming you only want the first imported fingerprint (for a single key)
                self.public_keys.append(import_result.fingerprints[0])
                print(f"Loaded public key from {filepath} and saved it to {temp_public_key_path}")
            else:
                print(f"Failed to load public key from {filepath}")
        
        except Exception as e:
            print(f"Error loading public key from {filepath}: {e}")

    def generate_new_key_pair(self):
        """Generate a new PGP key pair and save it to the current directory."""
        print("Generating a new PGP key pair...")
        name = "Anonymous"
        email = "anon@example.com"
        passphrase = getpass.getpass("Enter a passphrase to encrypt the new private key: ").strip()

        input_data = self.gpg.gen_key_input(
            name_real=name,
            name_email=email,
            passphrase=passphrase
        )

        key = self.gpg.gen_key(input_data)
        if key:
            print("New key pair generated successfully.")
            self.private_key_fingerprint = key.fingerprint
            print(f"Private key fingerprint: {self.private_key_fingerprint}")

            # Export the key pair to files in the current directory
            private_key_path = f"{name}_private_key.asc"
            public_key_path = f"{name}_public_key.asc"

            # Export the private key, passing the passphrase to export it
            private_key = self.gpg.export_keys(self.private_key_fingerprint, secret=True, passphrase=passphrase)
            if private_key:
                with open(private_key_path, 'w') as private_file:
                    private_file.write(private_key)
                print(f"Private key saved to {private_key_path}")
            else:
                print("Failed to export private key.")

            # Export the public key (no passphrase required for public key export)
            public_key = self.gpg.export_keys(self.private_key_fingerprint)
            if public_key:
                with open(public_key_path, 'w') as public_file:
                    public_file.write(public_key)
                print(f"Public key saved to {public_key_path}")
            else:
                print("Failed to export public key.")
        else:
            print("Failed to generate the new key pair.")

    def fetch_and_decrypt_messages(self):
        """Fetch and decrypt all messages automatically."""
        headers = {}
        if self.cookie:
            headers['Cookie'] = self.cookie  # Add cookie to headers

        try:
            response = requests.get(f"{self.base_url}/messages", params={"password": self.password}, headers=headers)
            if response.ok:
                messages = response.text

                # Extract encrypted messages using regex
                pgp_message_regex = r"(-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----)"
                encrypted_messages = re.findall(pgp_message_regex, messages, re.DOTALL)

                # Extract public keys using regex
                pgp_key_regex = r"(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)"
                extracted_keys = re.findall(pgp_key_regex, messages, re.DOTALL)

                # Handle no messages
                if not encrypted_messages:
                    print("No encrypted messages found.")
                else:
                    for encrypted_message in encrypted_messages:
                        decrypted_message = self.decrypt_message(encrypted_message.strip())
                        if decrypted_message:
                            self.handle_decrypted_message(decrypted_message)

                # Handle any extracted public keys
                if extracted_keys:
                    # Ensure the pubkeys directory exists
                    if not os.path.exists("pubkeys"):
                        os.makedirs("pubkeys")
                        pubkey_filename = os.path.join("pubkeys", public_key_path)
                        with open(pubkey_filename, 'w') as pubkey_file:
                            pubkey_file.write(key_data)


                    for i, public_key in enumerate(extracted_keys):
                        try:
                            # Save the public key to a file in the pubkeys directory
                            public_key_filename = os.path.join("pubkeys", f"public_key_{i + 1}.asc")
                            with open(public_key_filename, 'w') as pubkey_file:
                                pubkey_file.write(public_key)
                        except Exception as e:
                            print(f"Error saving public key: {e}")
            else:
                print(f"Failed to fetch messages: {response.status_code}")
        except Exception as e:
            print(f"Error fetching and decrypting messages: {e}")

        print(f"Enter your message (or /exit to quit): ")


    def send_message(self, message):
        """Send the user's PGP public key as a separate unencrypted message, followed by the encrypted message."""
        
        # Step 1: Send the user's public key as a separate message
        user_public_key = self.gpg.export_keys(self.private_key_fingerprint)
        if not user_public_key:
            print("Error: Unable to retrieve public key. Ensure the private key is loaded correctly.")
            return
        
        public_key_payload = {
            "message": user_public_key,
            "password": self.password
        }
        
        headers = {}
        if self.cookie:
            headers['Cookie'] = self.cookie

        try:
            response = requests.post(f"{self.base_url}/send", json=public_key_payload, headers=headers)
            if response.ok:
                print("Public key sent successfully.")
            else:
                print(f"Failed to send public key: {response.status_code} {response.text}")
                return
        except Exception as e:
            print(f"Error sending public key: {e}")
            return

        # Step 2: Encrypt the message and send it to selected public keys
        try:
            if not os.path.exists("pubkeys"):
                os.makedirs("pubkeys")
            
            encrypted_messages = []

            public_key_files = [os.path.join("pubkeys", f) for f in os.listdir("pubkeys") if f.endswith(".asc")]

            if not public_key_files:
                print("No public keys found in the 'pubkeys' folder. Cannot encrypt message.")
                return

            gpg = gnupg.GPG()
            fingerprints = {}

            for public_key_file in public_key_files:
                with open(public_key_file, 'r') as f:
                    public_key = f.read()
                
                import_result = gpg.import_keys(public_key)
                if import_result.count == 0:
                    print(f"Failed to import public key from {public_key_file}")
                    continue
                
                imported_fingerprint = import_result.fingerprints[0].lower()  # Normalize to lowercase
                fingerprints[imported_fingerprint] = public_key_file

            if not fingerprints:
                print("No valid public keys were found.")
                return
            
            print("Available fingerprints of public keys:")
            for idx, fingerprint in enumerate(fingerprints.keys(), 1):
                print(f"{idx}. {fingerprint}")

            # Let the user choose keys using ranges and commas
            try:
                choices = input(
                    f"Choose public keys by entering the corresponding numbers separated by commas (1-{len(fingerprints)}): "
                ).strip()

                selected_fingerprints = set()

                for part in choices.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        if not (1 <= start <= len(fingerprints) and 1 <= end <= len(fingerprints)):
                            raise ValueError("Range out of bounds")
                        for idx in range(start, end + 1):
                            selected_fingerprints.add(list(fingerprints.keys())[idx - 1])
                    elif part.isdigit():
                        idx = int(part)
                        if not (1 <= idx <= len(fingerprints)):
                            raise ValueError("Index out of bounds")
                        selected_fingerprints.add(list(fingerprints.keys())[idx - 1])
                    else:
                        # Direct fingerprint match (case-insensitive)
                        normalized_fp = part.lower()
                        matching_fps = [fp for fp in fingerprints if fp.startswith(normalized_fp)]
                        if not matching_fps:
                            print(f"No match found for fingerprint prefix: {part}")
                        else:
                            selected_fingerprints.update(matching_fps)

                if not selected_fingerprints:
                    print("No valid keys selected. Exiting.")
                    return

                print("Selected fingerprints:")
                for fp in selected_fingerprints:
                    print(fp)

            except ValueError as e:
                print(f"Invalid input: {e}. Exiting.")
                return

            for selected_fingerprint in selected_fingerprints:
                selected_key_file = fingerprints[selected_fingerprint]

                with open(selected_key_file, 'r') as f:
                    selected_public_key = f.read()

                import_result = gpg.import_keys(selected_public_key)
                if import_result.count == 0:
                    print(f"Failed to import selected public key from {selected_key_file}")
                    continue

                encrypted_message = gpg.encrypt(f"<strong>{self.username}</strong>: {message}", selected_fingerprint, always_trust=True)
                if not encrypted_message.ok:
                    print(f"Encryption of message failed for key {selected_fingerprint}: {encrypted_message.status}")
                    continue
                else:
                    print(f"Message encrypted successfully for key {selected_fingerprint}.")
                    encrypted_messages.append(str(encrypted_message))

            if not encrypted_messages:
                print("No messages were encrypted successfully. Exiting.")
                return

            headers = {}
            if self.cookie:
                headers['Cookie'] = self.cookie

            for encrypted_message in encrypted_messages:
                encrypted_message_payload = {
                    "message": encrypted_message,
                    "password": self.password
                }

                try:
                    response = requests.post(f"{self.base_url}/send", json=encrypted_message_payload, headers=headers)
                    if response.ok:
                        pass
                    else:
                        print(f"Failed to send encrypted message: {response.status_code} {response.text}")
                except Exception as e:
                    print(f"Error sending encrypted message: {e}")

        except Exception as e:
            print(f"Error in send_message: {e}")
    
    def decrypt_message(self, encrypted_message):
        """Decrypt a single message."""
        try:
            decrypted = self.gpg.decrypt(encrypted_message, passphrase=self.passphrase)
            if decrypted.ok:
                return str(decrypted)
            else:
                return None
        except Exception as e:
            return None
    
    def handle_decrypted_message(self, decrypted_message):
        """Handles the decrypted message, checking for image data."""
        
        # Replace <strong>...</strong> tags with bold cyan color codes
        decrypted_message = decrypted_message.replace("<strong>", "\033[1;36m").replace("</strong>", "\033[0m")
        
        if decrypted_message.startswith("IMAGEDATA:"):
            # Extract base64 image data after the prefix 'IMAGEDATA:'
            image_data = decrypted_message[len("IMAGEDATA:"):].strip()
            try:
                # Decode the base64 string
                image_bytes = base64.b64decode(image_data)
                
                # Define the path where the image will be saved
                image_dir = "images"
                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)  # Create the directory if it doesn't exist
                
                # Generate a random filename using uuid
                random_filename = f"{uuid.uuid4()}.png"
                image_path = os.path.join(image_dir, random_filename)

                # Save the image to the defined path
                with open(image_path, "wb") as img_file:
                    img_file.write(image_bytes)

                # Display the image in the terminal using climage.convert()
                print("Displaying the image in terminal...")
                output = climage.convert(image_path)  # Convert the image for terminal output
                print(output)  # Print the image output to the terminal
            except Exception as e:
                print(f"Error handling image data: {e}")
        else:
            print(f"{decrypted_message}\n")

    def auto_fetch_messages(self):
        """Fetch messages automatically every 60 seconds in the background."""
        while True:
            self.fetch_and_decrypt_messages()
            time.sleep(60)  # Wait for 60 seconds before fetching again

    def cleanup_sensitive_data(self):
        """Clean up sensitive data before exiting."""
        print("Wiping sensitive data...")
        # Wipe password and passphrase with zeroes
        self.password = "0" * len(self.password)
        self.passphrase = "0" * len(self.passphrase)

        # Wipe images by overwriting them with zeroes
        image_dir = "images"
        if os.path.exists(image_dir):
            for filename in os.listdir(image_dir):
                file_path = os.path.join(image_dir, filename)
                if os.path.isfile(file_path):
                    with open(file_path, "wb") as f:
                        f.write(b"\x00" * os.path.getsize(file_path))  # Overwrite with zeroes
                    os.remove(file_path)  # Optionally remove the image file after overwriting

        # Clear the terminal screen after cleanup
        self.clear_screen()

        print("Cleanup complete.")

    def clear_screen(self):
        """Clear the terminal screen based on the operating system."""
        os.system('cls' if os.name == 'nt' else 'clear')

# Register cleanup function to be called on exit
atexit.register(lambda: client.cleanup_sensitive_data())

if __name__ == "__main__":
    print("Welcome to Amnesichat!")
    base_url = input("Enter the base URL: ").strip()
    port = input("Enter the port (leave blank for default): ").strip()

    # Ask for cookie value (optional)
    cookie = input("Enter a cookie (leave blank if not using): ").strip() or None

    client = AmnesichatClient(base_url, port if port else None, cookie=cookie)

    print("\n=== Initial Configuration ===")

    # Ask for the username early in the process
    client.username = input("Enter your username: ").strip()

    # Ask the user if they want to generate a new key pair or load existing keys
    generate_new_key = input("Do you want to generate a new PGP key pair? (y/n): ").strip().lower()
    
    if generate_new_key == 'y':
        client.generate_new_key_pair()
    # The following will securely load passwords using getpass
    client.password = getpass.getpass("Enter chatroom password: ").strip()
    client.passphrase = getpass.getpass("Enter private key encryption password: ").strip()
    private_key_path = input("Enter path to private key file: ").strip()
    public_key_path = input("Enter path to public key: ")

    client.configure(client.password, client.passphrase, private_key_path, public_key_path)

    # Start the auto-fetching messages in a separate thread
    fetch_thread = threading.Thread(target=client.auto_fetch_messages)
    fetch_thread.daemon = True  # Allow the thread to exit when the main program ends
    fetch_thread.start()

    # Main message loop
    while True:
        message = input("Enter your message (or /exit to quit): ").strip()

        # Check if the input is empty and skip if so
        if not message:
            continue  # Skip if no input is provided

        if message == "/exit":
            print("Goodbye!")
            break  # Exit the program
        else:
            client.send_message(message)  # Send the message
