import os
import hashlib
# pip install pycryptodome
from Crypto.Cipher import AES
import multiprocessing


# Create an event for synchronization
key_generation_event = multiprocessing.Event()


# Variables to hold inputs from prog1 and prog2
inputs = []

def set_input(input_data):
    inputs.append(input_data)
    if len(inputs) == 2:
        key_generation_event.set()

def generate_keys(sender_nonce, receiver_nonce):
    
    # Wait until both inputs have been received
    key_generation_event.wait()
    
    combined_nonce = None
    
    for i in inputs: 
        # Concatenate sender and receiver nonces
        combined_nonce += i
    
    # Apply a hash function (e.g., SHA-256) to derive the key
    key = hashlib.sha256(combined_nonce).digest()
    
    return key

def encrypt_payload(payload, key):
    # Pad the payload to fit AES block size
    while len(payload) % 16 != 0:
        payload += b'\x00'
    
    # Initialize AES cipher in CBC mode with IV
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the payload
    ciphertext = cipher.encrypt(payload)
    
    # Calculate HMAC-SHA256
    hmac = hashlib.sha256(ciphertext).digest()
    
    # Return ESP packet with IV, ciphertext, and HMAC
    esp_packet = iv + ciphertext + hmac
    return esp_packet


def decrypt_packet(esp_packet, key):
    # Extract IV, ciphertext, and HMAC from ESP packet
    iv = esp_packet[:16]
    ciphertext = esp_packet[16:-32]  # Exclude IV and HMAC
    received_hmac = esp_packet[-32:]

    # Initialize AES cipher in CBC mode with IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_payload = cipher.decrypt(ciphertext)

    # Calculate HMAC-SHA256 over the decrypted payload
    computed_hmac = hashlib.sha256(ciphertext).digest()

    # Verify integrity
    if received_hmac != computed_hmac:
        raise ValueError("HMAC verification failed. Possible tampering.")

    return decrypted_payload.rstrip(b'\x00')  # Remove padding before returning
