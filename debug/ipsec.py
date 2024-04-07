import os
import hashlib
# pip install pycryptodome
from Crypto.Cipher import AES
# import multiprocessing
import csv
# import threading
import time

inputs = []

def check_csv():
    while True:
        with open("nonces.txt", 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                inputs.append(row)
        if len(inputs) > 2:
            return True

def clean_csv():
    with open("nonces.txt", 'w', newline='') as csvfile:
        pass

def generate_key():
    
    # Wait until both inputs have been received
    # key_generation_event.wait()
    check_csv()
    
    # CSV at this point is ready
    combined_nonce = ""
    try:
        with open("nonces.txt", 'r') as file_reader:
            combined_nonce = ''.join(file_reader.readlines())
    except FileNotFoundError:
        print("Error: File not found.")
    except IOError:
        print("Error: Unable to read the file.")
    
    
    # Apply a hash function (e.g., SHA-256) to derive the key
    key = hashlib.sha256(combined_nonce.encode()).digest()
    
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
