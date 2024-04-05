import os
import hashlib
# pip install pycryptodome
from Crypto.Cipher import AES
import multiprocessing
import csv
import threading
import time

key_generation_event = multiprocessing.Event()

# Variables to hold nonces from two programs
inputs = []


def check_csv():
    while True:
        with open("nonces.csv", 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                inputs.append(row)
        if len(inputs) > 2:
            key_generation_event.set()
        print("Going to sleep")
        time.sleep(10)
    
# def set_input(input_data):
#     inputs.append(input_data)
#     if len(inputs) == 2:
#         key_generation_event.set()
#     print(len(inputs))
#     print(input_data)

def generate_key():
    
    # Wait until both inputs have been received
    key_generation_event.wait()
    
    combined_nonce = None
    
    for i in inputs: 
        # Concatenate sender and receiver nonces
        combined_nonce += i
    
    # Apply a hash function (e.g., SHA-256) to derive the key
    key = hashlib.sha256(combined_nonce).digest()
    
    inputs = []
    with open("nonces.csv", 'w', newline='') as csvfile:
        pass
    
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

check_thread = threading.Thread(target=check_csv)
check_thread.daemon = True  # Daemonize the thread so it automatically stops when the main program exits
check_thread.start()

# Main program continues...
try:
    while True:
        time.sleep(1)  # Keep the main thread alive
except KeyboardInterrupt:
    print("Program terminated.")