import threading
import itertools
import getpass
import base64
from base64 import b64encode, b64decode
import binascii
import requests
import os
import ast
import re
import time
from time import strftime, localtime
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from argon2.low_level import hash_secret, Type
import hashlib
import oqs  # Post-quantum library for Kyber key exchange
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

SYSTEM_COLOR = '\033[93m'

# Helper functions
def derive_key_from_password(password, key_length=32, time_cost=4, memory_cost=102400, parallelism=8):
    """
    Derive a key from the password using Argon2id with a salt derived from the password itself.
    """
    # Derive a pseudo-salt by hashing the password with SHA-256
    pseudo_salt = hashlib.sha256(password.encode('utf-8')).digest()

    # Argon2id parameters
    password_bytes = password.encode('utf-8')
    key = hash_secret(
        secret=password_bytes,
        salt=pseudo_salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=Type.ID  # Argon2id type
    )
    # Now, SHA-512 hash the Argon2id key
    key = hashlib.sha512(key).hexdigest().encode()[:32]  # Take the first 32 bytes
    return key

def chacha20_poly1305_encrypt(data, key):
    """Encrypt data using ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long.")
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def chacha20_poly1305_decrypt(data, key):
    """Decrypt data using ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long.")
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def ecdh_shared_secret(private_key, public_key):
    """Generate the shared secret from ECDH."""
    shared_point = public_key.pointQ * private_key.d
    return SHA256.new(shared_point.x.to_bytes()).digest()

def generate_eddsa_keypair():
    """Generate Ed25519 keypair."""
    key = ECC.generate(curve='ed25519')
    return key

def key_fingerprint(public_key: [str, bytes]) -> str:
    """Generate a fingerprint for a public key."""
    digest = SHA256.new()
    
    # Convert to bytes if the input is a string
    if isinstance(public_key, str):
        public_key = public_key.encode()
    
    digest.update(public_key)
    return digest.hexdigest()

# Add a global session object
session = requests.Session()

def send_request(url, data=None, method="GET"):
    """Send HTTP requests with session cookies."""
    try:
        if method == "POST":
            response = session.post(url, json=data)
        else:
            response = session.get(url, params=data)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"[SYSTEM] HTTP request error: {e}")
        raise

def save_eddsa_keys(private_key, public_key, username, encryption_password):
    """Save EdDSA private and public keys as PEM files with username appended."""
    # Derive a key from the encryption password
    encryption_key = derive_key_from_password(encryption_password)

    # Export keys as PEM format
    private_pem = private_key.export_key(format='PEM')
    public_pem = public_key.export_key(format='PEM')

    # Encrypt the private key using ChaCha20-Poly1305 and the derived encryption key
    encrypted_private_key = chacha20_poly1305_encrypt(private_pem.encode(), encryption_key)
    encrypted_public_key = chacha20_poly1305_encrypt(public_pem.encode(), encryption_key)

    # Append username to the filenames
    private_filename = f"{username}_eddsa_private_key.pem"
    public_filename = f"{username}_eddsa_public_key.pem"

    with open(private_filename, "wb") as private_file:
        private_file.write(b64encode(encrypted_private_key))

    with open(public_filename, "wb") as public_file:
        public_file.write(b64encode(encrypted_public_key))


def load_eddsa_keys(username, encryption_password):
    """Load EdDSA keys from PEM files and decrypt them using the encryption password."""
    private_filename = f"{username}_eddsa_private_key.pem"
    public_filename = f"{username}_eddsa_public_key.pem"

    if os.path.exists(private_filename) and os.path.exists(public_filename):
        with open(private_filename, "rb") as private_file:
            encrypted_private_key_b64 = private_file.read().strip()
        with open(public_filename, "rb") as public_file:
            encrypted_public_key_b64 = public_file.read().strip()

        # Decode the Base64-encoded encrypted keys
        encrypted_private_key = b64decode(encrypted_private_key_b64)
        encrypted_public_key = b64decode(encrypted_public_key_b64)

        # Derive the encryption key from the encryption password
        encryption_key = derive_key_from_password(encryption_password)

        # Decrypt the private and public keys
        private_pem = chacha20_poly1305_decrypt(encrypted_private_key, encryption_key).decode()
        public_pem = chacha20_poly1305_decrypt(encrypted_public_key, encryption_key).decode()

        # Import the private and public keys from PEM format
        private_key = ECC.import_key(private_pem)
        public_key = ECC.import_key(public_pem)

        return private_key, public_key
    else:
        return None, None

def parse_html_response(html, exchange_type):
    """Extract key exchange and message data from raw HTML based on the exchange type."""
    # Define key exchange prefixes for different exchange types
    key_prefixes = {
        "KYBER": "KYBER_PUBLIC_KEY:",
        "ECDH": "ECDH_PUBLIC_KEY:",
        "EDDSA": "EDDSA_PUBLIC_KEY:",
        "DILITHIUM": "DILITHIUM_PUBLIC_KEY:"
    }

    # Validate if the exchange type is supported
    if exchange_type not in key_prefixes:
        raise ValueError(f"Unsupported exchange type: {exchange_type}")

    # Initialize lists for storing results
    public_keys = []
    messages = []

    # Regular expression to extract <p> elements
    paragraph_pattern = r'<p>(.*?)</p>'
    paragraphs = re.findall(paragraph_pattern, html, re.DOTALL)

    # Extractor for data
    def extract_data(paragraph, prefix):
        """
        Extract data from the paragraph if it matches the prefix.

        Args:
            paragraph (str): The paragraph to search.
            prefix (str): The prefix identifying the public key.

        Returns:
            str: The cleaned data, or None if not found.
        """
        if prefix in paragraph:
            key_data = paragraph.split(prefix, 1)[1].strip()
            if "[END DATA]" in key_data:
                return key_data.replace("[END DATA]", "").strip()
        return None

    # Process paragraphs to segregate keys and messages
    for para in paragraphs:
        public_key = extract_data(para, key_prefixes[exchange_type])
        if public_key:
            public_keys.append(public_key)
        else:
            messages.append(para.strip())

    return public_keys, messages

def save_dilithium_keys(private_key, public_key, username, encryption_password):
    """
    Save Dilithium5 keys for the given username as Base64-encoded strings.
    Encrypt the keys using a derived key from the encryption password.
    """
    # Derive a key from the encryption password
    encryption_key = derive_key_from_password(encryption_password)
    
    # Encrypt the private and public keys
    encrypted_private_key = chacha20_poly1305_encrypt(private_key.encode(), encryption_key)
    encrypted_public_key = chacha20_poly1305_encrypt(public_key.encode(), encryption_key)
    
    # Encode the encrypted keys to Base64 for storage
    private_key_path = f"{username}_dilithium_private.b64"
    public_key_path = f"{username}_dilithium_public.b64"
    
    with open(private_key_path, 'wb') as priv_file:
        priv_file.write(b64encode(encrypted_private_key))
    with open(public_key_path, 'wb') as pub_file:
        pub_file.write(b64encode(encrypted_public_key))


def load_dilithium_keys(username, encryption_password):
    """
    Load Dilithium5 keys for the given username and decrypt them using the encryption password.
    """
    private_key_path = f"{username}_dilithium_private.b64"
    public_key_path = f"{username}_dilithium_public.b64"
    
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, 'rb') as priv_file:
            encrypted_private_key_b64 = priv_file.read().strip()
        with open(public_key_path, 'rb') as pub_file:
            encrypted_public_key_b64 = pub_file.read().strip()
        
        # Decode the Base64-encoded keys
        encrypted_private_key = b64decode(encrypted_private_key_b64)
        encrypted_public_key = b64decode(encrypted_public_key_b64)
        
        # Derive the encryption key from the encryption password
        encryption_key = derive_key_from_password(encryption_password)
        
        # Decrypt the keys
        private_key = chacha20_poly1305_decrypt(encrypted_private_key, encryption_key).decode()
        public_key = chacha20_poly1305_decrypt(encrypted_public_key, encryption_key).decode()
        
        return private_key, public_key
    return None, None

# Function to encode the signature in base64
def encode_with_base64(data):
    return base64.b64encode(data).decode('utf-8')

# Function to decode the signature from base64
def decode_with_base64(data):
    return base64.b64decode(data.encode('utf-8'))

def encode_with_hex(data):
    """Encodes bytes data to a hexadecimal string."""
    if isinstance(data, str):  # If the data is a string, convert it to bytes
        data = data.encode('utf-8')  # Encoding string to bytes using utf-8
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes to encode to hex.")
    return binascii.hexlify(data).decode('utf-8')

def decode_with_hex(hex_data):
    """Decodes a hexadecimal string back to bytes."""
    if isinstance(hex_data, str):
        hex_data = hex_data.encode('ascii')  # Convert string hex_data to bytes
    return binascii.unhexlify(hex_data)

def extract_public_key(data):
    """Extracts the public key from signed data, decodes it from hex, and returns the decoded public key."""
    try:
        # Decode the hexadecimal string first
        decoded_data = decode_with_hex(data)
        
        # Now, split the decoded data at the signature delimiter and return the part before it
        public_key = decoded_data.split(b'-----BEGIN SIGNATURE-----')[0]
        
        # Convert the byte string to a regular string without the b' and '
        public_key_str = public_key.decode('utf-8', errors='ignore')
        
        return public_key_str
    except Exception as e:
        # Print the undecodable data and the error message
        print("Undecodable data:", data)
        raise ValueError("Failed to extract and decode public key: " + str(e))

def kyber_key_exchange(received_eddsa_keys, received_dilithium_keys, password, username, eddsa_private_key, dilithium_private_key, host):
    """Perform Kyber-based key exchange with EDDSA and Dilithium for signing and verification."""
    kemalg = "Kyber1024"

    client_public_key_cache = {"key": None, "secret_key": None}
    invalid_key_cache = set()

    def generate_keypair(kemalg):
        """Generate Client's keypair."""
        if client_public_key_cache["key"] is not None:
            return client_public_key_cache["key"], client_public_key_cache["secret_key"]

        while True:
            try:
                with oqs.KeyEncapsulation(kemalg) as client:
                    client_public_key = client.generate_keypair()
                    secret_key_client = client.export_secret_key()
                    expected_length = client.details['length_public_key']

                    if len(client_public_key) != expected_length:
                        raise ValueError("Public key length mismatch.")

                    client_public_key_cache["key"] = client_public_key
                    client_public_key_cache["secret_key"] = secret_key_client
                    return client_public_key, secret_key_client
            except Exception:
                time.sleep(5)

    def send_public_key(public_key, dilithium_private_key, eddsa_private_key, password, host, is_alice=True):
        """Send public key with EDDSA and Dilithium signatures."""
        while True:
            try:
                hex_public_key = encode_with_hex(public_key)
                signed_message_eddsa = eddsa_sign_message(eddsa_private_key, public_key)
                signed_message_dilithium = dilithium_sign_message(dilithium_private_key, encode_with_hex(signed_message_eddsa))
                signed_message_dilithium_hex = encode_with_hex(signed_message_dilithium)

                response = send_request(f"{host}/send", {
                    "message": f"KYBER_PUBLIC_KEY:{signed_message_dilithium_hex}[END DATA]",
                    "password": password
                }, "POST")

                if response.status_code != 200:
                    raise RuntimeError("Failed to send public key.")

                return signed_message_dilithium_hex, is_alice

            except Exception:
                time.sleep(5)

    client_public_key, secret_key_client = generate_keypair(kemalg)
    other_client_public_key = None
    hex_signed_message = None
    is_alice = True

    while not other_client_public_key:
        try:
            response = send_request(f"{host}/messages", {"password": password})

            if "CIPHERTEXT:" in response.text:
                break

            key_exchange_data, _ = parse_html_response(response.text, "KYBER")

            if key_exchange_data:
                key_exchange_data = [
                    data for data in key_exchange_data if data != hex_signed_message and data not in invalid_key_cache
                ]
                if len(key_exchange_data) > 0:
                    signed_data_original = key_exchange_data[0]
                    signed_data_original = decode_with_hex(signed_data_original).decode()

                    verified = False
                    for received_dilithium_key in received_dilithium_keys:
                        if dilithium_verify_message(received_dilithium_key, signed_data_original):
                            verified = True
                            break

                    if not verified:
                        invalid_key_cache.add(signed_data_original)
                        continue

                    if '-----BEGIN SIGNATURE-----' not in signed_data_original or '-----END SIGNATURE-----' not in signed_data_original:
                        return False

                    try:
                        signed_data_original, signature_base64 = signed_data_original.split('-----BEGIN SIGNATURE-----', 1)
                        signature_base64 = signature_base64.split('-----END SIGNATURE-----')[0].strip()
                    except ValueError:
                        return False

                    signed_data = decode_with_hex(signed_data_original)

                    verified = False
                    for received_eddsa_key in received_eddsa_keys:
                        if eddsa_verify_message(received_eddsa_key, signed_data):
                            verified = True
                            break

                    if not verified:
                        invalid_key_cache.add(signed_data)
                        continue

                    other_client_public_key = extract_public_key(signed_data_original)
                    is_alice = False

            if not other_client_public_key and is_alice:
                hex_signed_message, is_alice = send_public_key(client_public_key, dilithium_private_key, eddsa_private_key, password, host, is_alice)

            break

        except Exception:
            time.sleep(10)

    while True:
        try:
            with oqs.KeyEncapsulation(kemalg) as client:
                if is_alice:
                    response = send_request(f"{host}/messages", {"password": password})
                    received_ciphertext_data, _ = parse_html_response(response.text, "KYBER")

                    if len(received_ciphertext_data) < 2 or not received_ciphertext_data[1].startswith("CIPHERTEXT:") or received_ciphertext_data[1] == f"CIPHERTEXT:{encode_with_hex(client_public_key)}":
                        raise RuntimeError("No valid ciphertext from the server (excluding own ciphertext).")

                    signed_ciphertext_from_server = decode_with_hex(received_ciphertext_data[1].replace("CIPHERTEXT:", ""))
                    signed_ciphertext_from_server_decoded = signed_ciphertext_from_server.decode()

                    if '-----BEGIN SIGNATURE-----' not in signed_ciphertext_from_server_decoded or '-----END SIGNATURE-----' not in signed_ciphertext_from_server_decoded:
                        return False

                    try:
                        ciphertext_from_server, signature_base64 = signed_ciphertext_from_server_decoded.split('-----BEGIN SIGNATURE-----', 1)
                        signature_base64 = signature_base64.split('-----END SIGNATURE-----')[0].strip()
                    except ValueError:
                        return False

                    ciphertext_from_server_eddsa_signed = decode_with_hex(ciphertext_from_server)
                    ciphertext_from_server_eddsa_signed_decoded = ciphertext_from_server_eddsa_signed.decode()

                    if '-----BEGIN SIGNATURE-----' not in ciphertext_from_server_eddsa_signed_decoded or '-----END SIGNATURE-----' not in ciphertext_from_server_eddsa_signed_decoded:
                        return False

                    try:
                        ciphertext_from_server, signature_base64 = ciphertext_from_server_eddsa_signed_decoded.split('-----BEGIN SIGNATURE-----', 1)
                        signature_base64 = signature_base64.split('-----END SIGNATURE-----')[0].strip()
                    except ValueError:
                        return False

                    ciphertext_from_server = ast.literal_eval(ciphertext_from_server)
                    ciphertext_from_server_base64 = ciphertext_from_server.decode()
                    ciphertext_from_server = decode_with_base64(ciphertext_from_server_base64.strip())

                    client_alice = oqs.KeyEncapsulation(kemalg, secret_key_client)
                    shared_secret_responder = client_alice.decap_secret(ciphertext_from_server)

                    for received_eddsa_key in received_eddsa_keys:
                        if eddsa_verify_message(received_eddsa_key, ciphertext_from_server_base64 + '-----BEGIN SIGNATURE-----' + signature_base64 + '-----END SIGNATURE-----'):
                            break
                    else:
                        return False

                    for received_dilithium_key in received_dilithium_keys:
                        if dilithium_verify_message(received_dilithium_key, signed_ciphertext_from_server.decode()):
                            break
                    else:
                        return False

                    return shared_secret_responder

                else:
                    other_client_public_key = ast.literal_eval(other_client_public_key) if isinstance(other_client_public_key, str) else other_client_public_key

                    ciphertext, shared_secret_bob = client.encap_secret(other_client_public_key)

                    signed_ciphertext_eddsa = eddsa_sign_message(eddsa_private_key, encode_with_base64(ciphertext).encode())
                    signed_ciphertext_dilithium = dilithium_sign_message(dilithium_private_key, encode_with_hex(signed_ciphertext_eddsa))

                    response = send_request(f"{host}/send", {
                        "message": f"KYBER_PUBLIC_KEY:CIPHERTEXT:{encode_with_hex(signed_ciphertext_dilithium)}[END DATA]",
                        "password": password
                    }, "POST")

                    if response.status_code != 200:
                        raise RuntimeError("Failed to send ciphertext.")

                    return shared_secret_bob

        except Exception:
            time.sleep(10)

def eddsa_sign_message(private_key, message):
    """Sign a message using EdDSA and append the signature with a delimiter."""
    try:
        message_bytes = message

        # Create a new EdDSA signer object
        signer = eddsa.new(private_key, mode='rfc8032')

        # Hash the message using SHA-512
        h = SHA512.new(message_bytes)

        # Sign the hash
        signature = signer.sign(h)

        # Encode the signature in base64
        signature_base64 = encode_with_base64(signature)

        # Append the signature to the message with new delimiters
        return f"{message.strip()}-----BEGIN SIGNATURE-----{signature_base64}-----END SIGNATURE-----"
    except Exception as e:
        raise


def eddsa_verify_message(public_key, signed_message):
    """Verify the message signature using EdDSA."""
    try:
        # Ensure the input is a string
        if isinstance(signed_message, bytes):
            signed_message = signed_message.decode('utf-8')
        
        # Check for delimiters
        if '-----BEGIN SIGNATURE-----' not in signed_message or '-----END SIGNATURE-----' not in signed_message:
            return False

        # Split the signed message
        try:
            message, signature_base64 = signed_message.split('-----BEGIN SIGNATURE-----', 1)
            signature_base64 = signature_base64.split('-----END SIGNATURE-----')[0].strip()
        except ValueError as ve:
            return False

        # Decode the base64 signature
        signature = decode_with_base64(signature_base64)

        try:
            # Convert message to bytes
            message_bytes = ast.literal_eval(message.strip())
        except:
            message_bytes = message.strip().encode()
        # Create EdDSA verifier
        verifier = eddsa.new(public_key, mode='rfc8032')

        # Hash the message
        h = SHA512.new(message_bytes)

        # Verify the signature
        verifier.verify(h, signature)
        return True
    except Exception as e:
        return False

def dilithium_sign_message(private_key, message):
    """Sign a message using Dilithium5 and append the signature with delimiters."""
    try:
        # Convert the message to bytes if not already
        message_bytes = message.encode()

        private_key = decode_with_base64(private_key)

        # Create a Dilithium5 signer instance
        sigalg = "Dilithium5"
        with oqs.Signature(sigalg) as signer:
            # Set private key
            signer = oqs.Signature(sigalg, private_key)

            # Sign the message
            signature = signer.sign(message_bytes)

        # Encode the signature in base64
        signature_base64 = encode_with_base64(signature)

        # Append the signature to the message with delimiters
        signed_message = f"{message}-----BEGIN SIGNATURE-----{signature_base64}-----END SIGNATURE-----"
        return signed_message
    except Exception as e:
        raise RuntimeError("Signing the message failed.") from e

def dilithium_verify_message(public_key, signed_message):
    """Verify the message signature using Dilithium5."""
    try:
        # Check for delimiters
        if '-----BEGIN SIGNATURE-----' not in signed_message or '-----END SIGNATURE-----' not in signed_message:
            return False

        # Split the signed message
        try:
            message, signature_base64 = signed_message.split('-----BEGIN SIGNATURE-----', 1)
            signature_base64 = signature_base64.split('-----END SIGNATURE-----')[0].strip()
        except ValueError as ve:
            return False

        # Decode the base64 signature
        signature = decode_with_base64(signature_base64)

        # Convert the message to bytes
        message_bytes = message.encode()

        public_key = decode_with_base64(public_key)

        # Create a Dilithium verifier
        sigalg = "Dilithium5"
        with oqs.Signature(sigalg) as verifier:
            # Verify the signature
            is_valid = verifier.verify(message_bytes, signature, public_key)

        return is_valid
    except Exception as e:
        return False
        
def key_exchange(password, username, host, encryption_password):
    """Perform the complete key exchange (EdDSA, Kyber, ECDH, and Dilithium)."""

    def get_or_generate_eddsa_keys():
        eddsa_private, eddsa_public = load_eddsa_keys(username, encryption_password)
        if not (eddsa_private and eddsa_public):
            print("No EdDSA keys found. Generating new keypair...")
            eddsa_private = generate_eddsa_keypair()
            eddsa_public = eddsa_private.public_key()
            save_eddsa_keys(eddsa_private, eddsa_public, username, encryption_password)
        else:
            print("[SYSTEM] Loaded existing EdDSA keys.")
        return eddsa_private, eddsa_public

    def get_or_generate_dilithium_keys():
        """Get or generate Dilithium5 key pair for the user (used for signing)."""
        private_key, public_key = load_dilithium_keys(username, encryption_password)
        if not (private_key and public_key):
            print("No Dilithium5 keys found. Generating new keypair...")
            with oqs.Signature("Dilithium5") as signer:
                public_key = base64.b64encode(signer.generate_keypair()).decode('utf-8')
                private_key = base64.b64encode(signer.export_secret_key()).decode('utf-8')
            save_dilithium_keys(private_key, public_key, username, encryption_password)
        else:
            print("[SYSTEM] Loaded existing Dilithium5 keys.")
        return private_key, public_key

    def handle_key_exchange(url, message):
        message_with_delimiter = f"{message}[END DATA]"
        response = send_request(url, {"message": message_with_delimiter, "password": password}, "POST")
        if response.status_code != 200:
            raise RuntimeError("Error: Unable to send key.")
        return send_request(f"{host}/messages", {"password": password})

    def process_received_keys(key_data, process_func, own_fingerprint, skip_decoding=False):
        processed_keys = []
        for key_base64 in key_data:
            try:
                key_raw = key_base64 if skip_decoding else decode_with_base64(key_base64)
                key_obj = process_func(key_raw)
                fingerprint = key_fingerprint(key_base64 if skip_decoding else key_raw)

                if fingerprint == own_fingerprint:
                    processed_keys.append(key_obj)
                else:
                    print(f"Trust this key fingerprint {fingerprint}? (yes or no)")
                    if input().strip().lower() == 'yes':
                        print(f"✅ Trusted Key Fingerprint: {fingerprint}")
                        processed_keys.append(key_obj)
            except Exception as e:
                print(f"[ERROR] Failed to process received key: {e}")
        return processed_keys

    def process_eddsa_key(key):
        return ECC.import_key(key)

    def process_dilithium_key(key):
        return key

    # Step 1: Get or generate EdDSA keys
    eddsa_private_key, eddsa_public_key = get_or_generate_eddsa_keys()
    if not isinstance(eddsa_public_key, ECC.EccKey):
        raise TypeError("eddsa_public_key must be an ECC key.")
    eddsa_public_key_client = eddsa_public_key.export_key(format='PEM')
    eddsa_fingerprint = key_fingerprint(eddsa_public_key_client)
    dilithium_private_key, dilithium_public_key = get_or_generate_dilithium_keys()
    dilithium_public_key_client = dilithium_public_key
    dilithium_fingerprint = key_fingerprint(dilithium_public_key_client)
    print(f"Own EdDSA Fingerprint: {eddsa_fingerprint}")
    print(f"Own Dilithium Fingerprint: {dilithium_fingerprint}")

    # Step 2: Send the EdDSA public key only once
    response = handle_key_exchange(
        f"{host}/send",
        f"EDDSA_PUBLIC_KEY:{encode_with_base64(eddsa_public_key_client.encode())}"
    )

    # Step 3: Handle key exchange with EdDSA public key (retry until at least two different keys are found)
    while True:
        response = send_request(f"{host}/messages", {"password": password})
        key_exchange_data, _ = parse_html_response(response.text, "EDDSA")

        if key_exchange_data:
            received_fingerprints = [key_fingerprint(key) for key in key_exchange_data]
            unique_fingerprints = set(received_fingerprints)

            if len(unique_fingerprints) >= 2:  # Ensure at least two different keys are received
                break

        print("[SYSTEM] Retrying for EdDSA keys...")
        time.sleep(1)

    allowed_received_eddsa_keys = process_received_keys(
        key_exchange_data,
        process_eddsa_key,
        eddsa_fingerprint
    )

    if not allowed_received_eddsa_keys:
        print("[ERROR] No trusted EdDSA keys received.")
        return None

    # Step 4: Send the Dilithium public key only once
    response = handle_key_exchange(
        f"{host}/send",
        f"DILITHIUM_PUBLIC_KEY:{dilithium_public_key_client}"
    )

    # Step 5: Handle key exchange with Dilithium public key (retry until at least two different keys are found)
    while True:
        response = send_request(f"{host}/messages", {"password": password})
        key_exchange_data, _ = parse_html_response(response.text, "DILITHIUM")

        if key_exchange_data:
            received_fingerprints = [key_fingerprint(key) for key in key_exchange_data]
            unique_fingerprints = set(received_fingerprints)

            if len(unique_fingerprints) >= 2:  # Ensure at least two different keys are received
                break

        print("[SYSTEM] Retrying for Dilithium5 keys...")
        time.sleep(1)

    allowed_dilithium_keys = process_received_keys(
        key_exchange_data,
        process_dilithium_key,
        dilithium_fingerprint,
        skip_decoding=True
    )

    if not allowed_dilithium_keys:
        print("[ERROR] No valid Dilithium keys received.")
        return None

    # Step 6: Proceed with Kyber exchange with all EdDSA and Dilithium keys
    shared_secrets_kyber = kyber_key_exchange(
        allowed_received_eddsa_keys,
        allowed_dilithium_keys,
        password, 
        username, 
        eddsa_private_key, 
        dilithium_private_key,
        host
    )

    if not isinstance(shared_secrets_kyber, list):
        shared_secrets_kyber = [shared_secrets_kyber]

    if not shared_secrets_kyber:
        print("[ERROR] Kyber exchange did not return any shared secrets.")
        return None

    print("[SYSTEM] Kyber shared secrets established.")

    # Step 7: Perform the ECDH key exchange
    symmetric_keys_ecdh = perform_ecdh_key_exchange(password, eddsa_private_key, allowed_received_eddsa_keys, host)

    if not symmetric_keys_ecdh:
        print("[ERROR] Failed to establish symmetric keys.")
        return None

    print("[SYSTEM] Symmetric keys established.")

    # Step 8: Combine Kyber and ECDH secrets
    combined_secrets = []
    for kyber_secret, ecdh_secret in zip(shared_secrets_kyber, symmetric_keys_ecdh):
        combined_hash = hashlib.sha512(kyber_secret + ecdh_secret).digest()
        combined_secrets.append(combined_hash[:32])

    print("[SYSTEM] Combined secrets established.")

    return combined_secrets

def perform_ecdh_key_exchange(password, private_key_eddsa, public_keys_eddsa, host):
    """Perform the ECDH key exchange, sign the public key with EdDSA, and return the symmetric keys."""
    # ECDH key exchange
    dh_key_client = ECC.generate(curve='P-256')
    dh_public_key_client = dh_key_client.public_key()

    # Store your public key for comparison
    dh_public_key_client_pem = dh_public_key_client.export_key(format='PEM').encode()

    # Sign the ECDH public key with EdDSA
    signed_public_key = eddsa_sign_message(private_key_eddsa, dh_public_key_client_pem)
    
    print("[SYSTEM] ECDH public key signed with EdDSA.")

    # Send signed public key to the server
    response = send_request(f"{host}/send", {
        "message": f"ECDH_PUBLIC_KEY:{signed_public_key}[END DATA]",
        "password": password
    }, "POST")

    # Retrieve the key exchange data from the server
    key_exchange_data = []
    while True:
        response = send_request(f"{host}/messages", {"password": password})
        response_text = response.text
        key_exchange_data, _ = parse_html_response(response_text, "ECDH")

        if key_exchange_data:
            # Skip any key exchange data that matches your signed public key
            key_exchange_data = [
                data for data in key_exchange_data
                if signed_public_key not in data
            ]
            if key_exchange_data:
                break
        else:
            print("[SYSTEM] No ECDH key exchange data received, retrying...")
            time.sleep(1)

    if not key_exchange_data:
        print("[ERROR] No ECDH key exchange data received after waiting.")
        return None

    shared_secrets_dh_client = []  # Initialize shared_secrets_dh_client as a list
    for received_key_data in key_exchange_data:
        # Try to verify with each of the EdDSA public keys
        verification_successful = False
        for public_key_eddsa in public_keys_eddsa:
            if eddsa_verify_message(public_key_eddsa, received_key_data):
                print("[SYSTEM] Received ECDH public key successfully verified with EdDSA.")
                verification_successful = True
                break
            else:
                print("[ERROR] Received ECDH public key signature verification failed with one of the public keys.")

        if not verification_successful:
            # Skip to the next received key if verification fails with all public keys
            print("[ERROR] All EdDSA public key verifications failed. Skipping this key.")
            continue

        try:
            if '-----BEGIN SIGNATURE-----' not in received_key_data or '-----END SIGNATURE-----' not in received_key_data:
                return False
            try:
                received_key_data, signature_base64 = received_key_data.split('-----BEGIN SIGNATURE-----', 1)
                signature_base64 = signature_base64.split('-----END SIGNATURE-----')[0].strip()
            except ValueError as ve:
                return False
            received_key_data = ast.literal_eval(received_key_data)
            dh_public_key_received = ECC.import_key(received_key_data.decode())
        except ValueError as e:
            print(f"[ERROR] Failed to import received ECDH public key: {e}")
            continue

        shared_secret_dh_client = ecdh_shared_secret(dh_key_client, dh_public_key_received)
        if not isinstance(shared_secret_dh_client, bytes):
            raise TypeError("ECDH shared secret must be a bytes object.")
        shared_secrets_dh_client.append(shared_secret_dh_client)
        print("[SYSTEM] Shared ECDH secret established with a received key.")

    if not shared_secrets_dh_client:
        print("[ERROR] No shared secrets received from ECDH exchange.")
        return None

    return shared_secrets_dh_client

# Initialize shared_keys with a lock and empty keys list
shared_keys = {
    "lock": threading.Lock(),
    "keys": []
}

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_system_message(message):
    """Print system messages in cyan."""
    print(f"{Fore.CYAN}[SYSTEM] {message}{Style.RESET_ALL}")

def print_error_message(message):
    """Print error messages in red."""
    print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")

def print_success_message(message):
    """Print success messages in green."""
    print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")

def print_header():
    """Print the main header of the chat client."""
    clear_screen()
    print(f"{Fore.RED}==== Welcome to Amnesichat ===={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Type '/about' for info, '/exit' to quit.{Style.RESET_ALL}")
    print("=" * 40)

def receive_messages_periodically(host, password, shared_keys, username):
    """ Function to call receive_messages every 30 seconds. """

    while True:
        clear_screen()
        print_header()
        
        # Check if there are any keys to decrypt messages
        with shared_keys["lock"]:
            current_keys = shared_keys["keys"]

        if current_keys:
            receive_messages(current_keys, password, host)
            print(f"\n{Fore.WHITE}{username}: {Style.RESET_ALL}")
        else:
            print_error_message("No symmetric keys available to decrypt messages.")

        # Wait for 30 seconds before the next message fetch
        time.sleep(30)

def receive_messages(symmetric_keys, password, host):
    """Fetch and decrypt messages from the server using multiple symmetric keys."""
    try:
        response = send_request(f"{host}/messages", {"password": password})
        if response.status_code != 200:
            print_error_message(f"Failed to fetch messages: {response.status_code}")
            return

        response_text = response.text

        for match in re.finditer(r"(-----BEGIN ENCRYPTED MESSAGE-----.*?-----END ENCRYPTED MESSAGE-----)", response_text, re.DOTALL):
            encrypted_block = match.group(0)
            encrypted_message = re.search(r"-----BEGIN ENCRYPTED MESSAGE-----\s*(.*?)\s*-----END ENCRYPTED MESSAGE-----", encrypted_block, re.DOTALL)
            if encrypted_message:
                encrypted_data = decode_with_base64(encrypted_message.group(1))

                # Attempt to decrypt using each symmetric key
                decrypted_message = None
                for symmetric_key in symmetric_keys:
                    try:
                        decrypted_message = chacha20_poly1305_decrypt(encrypted_data, symmetric_key)
                        break
                    except Exception as e:
                        print_error_message(f"Decryption failed with a key: {e}")
                        continue  # Try the next key

                if decrypted_message:
                    decrypted_message_str = decrypted_message.decode()

                    # Apply bold formatting for <strong> tags
                    formatted_message = re.sub(r'<strong>(.*?)</strong>', '\033[1m\\1\033[0m', decrypted_message_str)

                    print(formatted_message)
                else:
                    print_error_message("Decryption failed with all keys.")

    except requests.exceptions.RequestException as e:
        print_error_message(f"Request failed: {e}")
    except Exception as e:
        print_error_message(f"An error occurred: {e}")

def chat_client(host='localhost', password='passwordhere', shared_keys=None, username=None, encryption_password=None):
    """Start the client and handle the chat."""

    if shared_keys is None:
        shared_keys = {
            "lock": threading.Lock(),
            "keys": []
        }
    
    if username is None:
        username = input(f"{Fore.WHITE}Enter your username: {Style.RESET_ALL}").strip()

    # Perform the initial key exchange
    initial_keys = key_exchange(password, username, host, encryption_password=encryption_password)
    if not initial_keys:
        print_error_message("Initial key exchange failed. Exiting.")
        return

    # Update the shared state with the initial keys
    with shared_keys["lock"]:
        shared_keys["keys"] = initial_keys

    print_system_message("Initial key exchange completed. Start chatting!")

    # Start the message receiver in a background thread
    threading.Thread(target=receive_messages_periodically, args=(host, password, shared_keys, username), daemon=True).start()

    # Start the chat loop
    try:
        # Create a cycle iterator to rotate through the keys
        key_cycle = itertools.cycle(shared_keys["keys"])

        while True:
            # Prompt the user for input
            message = input().strip()

            if message == "/exit":
                print_system_message("Exiting chat client...")
                break
            
            if message == "/about":
                print_system_message("Amnesichat - An encrypted, small and anti-forensic messenger.")
                print_system_message("Amnesichat Protocol supports only one-to-one conversations at the moment.")
                print_system_message("GitHub: https://github.com/umutcamliyurt/Amnesichat")
                time.sleep(15)
                continue
             
            if message:
                message = f"<strong>{username}:</strong> {message}"

                # Use the current key from the shared state
                with shared_keys["lock"]:
                    current_keys = shared_keys["keys"]

                if not current_keys:
                    print_error_message("No available keys for encryption.")
                    continue

                current_key = next(itertools.cycle(current_keys))
                ciphertext = chacha20_poly1305_encrypt(message.encode(), current_key)
                encrypted_message = encode_with_base64(ciphertext)

                response = send_request(f"{host}/send", {
                    "message": f"-----BEGIN ENCRYPTED MESSAGE-----\n{encrypted_message}\n-----END ENCRYPTED MESSAGE-----",
                    "password": password
                }, "POST")

                if response.status_code == 200:
                    print_success_message("Message sent successfully.")
                else:
                    print_error_message(f"Error sending message. HTTP Status: {response.status_code}")
                
                clear_screen()
                print_header()

                # Check if there are any keys to decrypt messages
                with shared_keys["lock"]:
                    current_keys = shared_keys["keys"]

                if current_keys:
                    receive_messages(current_keys, password, host)
                    print(f"\n{Fore.WHITE}{username}: {Style.RESET_ALL}")
                else:
                    print_error_message("No symmetric keys available to decrypt messages.")

    except KeyboardInterrupt:
        print_system_message("Chat client shutting down.")
    except Exception as e:
        print_error_message(f"Chat client encountered an error: {e}")

if __name__ == "__main__":
    print_header()
    
    host = input(f"{Fore.WHITE}Enter host (default: http://localhost:8080): {Style.RESET_ALL}").strip() or "http://localhost:8080"
    
    # Use getpass to securely get the password
    password = getpass.getpass(f"{Fore.WHITE}Enter room password: {Style.RESET_ALL}").strip()
    
    # Use getpass for the private key encryption password as well
    encryption_password = getpass.getpass(f"{Fore.WHITE}Enter private key encryption password: {Style.RESET_ALL}").strip()
    
    # Set cookie before starting the chat client
    cookie_name = input(f"{Fore.WHITE}Enter cookie name (default: none): {Style.RESET_ALL}").strip()
    cookie_value = input(f"{Fore.WHITE}Enter cookie value (default: none): {Style.RESET_ALL}").strip()
    session.cookies.set(cookie_name, cookie_value)
    
    # Initialize shared_keys
    shared_keys = {
        "lock": threading.Lock(),
        "keys": []
    }

    # Start the chat client
    chat_client(host, password, shared_keys=shared_keys, encryption_password=encryption_password)
