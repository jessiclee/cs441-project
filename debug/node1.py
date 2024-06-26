import socket
import struct
import threading
import ipsec
import secrets
import time

IDS = {
    "N1": (0x1A,  b'N1'),
    "N2": (0x2A, b'R1'),
    "N3": (0x2B, b'R1')
    # Add more mappings as needed
}

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
IP = 0x1A
MAC = b"N1"
MAX_LEN = 256
exit_flag = False
key = None
wrong_key = b'\xd8c\xa6\xdd\r\xf5@\xd6&Y\x96\xc1\xd0\xf6d\x87\xe81\x07\x0c\xde\xbbN"\xa4\xf3\x9c\x83\x9d5t3'


def create_packet(message, ipdest, mac, protocol, length, key):
    esp_packet = ipsec.encrypt_payload(message, key)
    # print(esp_packet)
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + esp_packet
    # print("ip pack created:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    # print("final packet:", packet)
    return packet

def create_packet_key_gen(message, ipdest, mac, protocol, length):
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + message
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    return packet

def append_to_txt(data):
    try:
        with open("nonces.txt", 'r') as file_reader:
            existing_entries = file_reader.readlines()
    except FileNotFoundError:
        existing_entries = []
        
    if len(existing_entries) == 0:
        with open("nonces.txt", 'a') as csvfile:
            csvfile.write(data)
            
    if len(existing_entries) == 1:
        with open("nonces.txt", 'a') as csvfile:
            csvfile.write("\n" + data)

def val_in_dict(val,pos, diction):
    for key, value in diction.items():
        # Check if the second element of the value matches the given value
        if value[pos] == val:
            return True, key
    return False, "NIL"

def listen_for_messages(conn):
    global exit_flag
    while True:
        try:
            data = conn.recv(1024)
            if data[9:] == b"N1:Zq6,eS2yN%sUTF)k":
                time.sleep(2)
                # ipsec.set_input(secrets.token_hex(16))
                append_to_txt(secrets.token_hex(16))
                key = ipsec.generate_key()
                print("Current Key is: ", key)
                
                # Ensure sender has enough time to retrieve the key
                time.sleep(2)
                
                # Revert CSV to a clean state
                ipsec.clean_csv()
            elif data[9:] == b"N2:Zq6,eS2yN%sUTF)k" or data[9:] == b"N3:Zq6,eS2yN%sUTF)k":
                # Do noting because the key is not theirs
                pass
            else:
                macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
                if macdst == MAC:
                    ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                    exists, source = val_in_dict(ipsrc, 0, IDS)
                    print("Received message from: ", source, " with IP address ", ipsrc, " and MAC address:", macsrc)
                    print("Message: ", data[9:])
                    print("Ciphertext Message is: ", data[9:])     
                    if protocol == 1:
                        exit_flag = True
                        break
                    elif protocol == 0:
                        if key:
                            decrypted_payload = ipsec.decrypt_packet(data[9:], key)
                            print("Plaintext Message: ", decrypted_payload)
                            packet = create_packet(decrypted_payload, ipsrc, macsrc, 3, len, key)
                            conn.sendall(packet)
                        else:
                            # packet = create_packet(data[9:], ipsrc, macsrc, 3, len)
                            # print("proto 0, sending back")
                            # conn.sendall(packet)
                            print("Decryption Failed")
                else:
                    print("Received message is for: ", macdst, " from ", macsrc)
                    print("Dropping packet")
            if not data:
                break
        except ConnectionResetError:
            print("Error: Connection closed")
            exit_flag = True
            break

def send_messages(conn):
    while not exit_flag: 
        while True:
            message = input("Enter message: ").encode('utf-8')
            length = len(message)
            # print(length)
            if length > MAX_LEN:
                print ("Please input a message within the character limit " + MAX_LEN)
            else:
                break
        while True:
            proto = input("Choose protocol (0/1): ")
            if (proto == "0" or proto == "1"):
                break
            else:
                print("Please input a valid protocol, 0 (Ping Protocol) or 1 (Kill Protocol)")
                
        while True:
            dest = input("Choose recipient (N2/N3): ")
            if (dest == "N2" or dest == "N3"):
                break
            else:
                print("Please input a valid node (N2/N3)")
        try:
            node = IDS[dest]
            
            # Random String s.t. an adversary would not be able to craft a fake key gen message
            # Unless he knows the secret hardcoded information
            key_gen_msg = dest + ":" + "Zq6,eS2yN%sUTF)k"
            key_gen_packet = create_packet_key_gen(key_gen_msg.encode('utf-8'), node[0], node[1], int(proto), length)
            print(key_gen_msg.encode('utf-8'))
            conn.sendall(key_gen_packet)
            
            # Contribute in the key generation after that
            append_to_txt(secrets.token_hex(16))
            time.sleep(2)
            key = ipsec.generate_key()
            
            # To check if the key is different everytime
            print("Current Key is: ", key)
            
            # Send the actual packet
            packet = create_packet(message, node[0], node[1], int(proto), length, key)
            conn.sendall(packet)
        except KeyError:
            print("Error: Sender not found")
            pass

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    #thread to listen for messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(s,), daemon=True)
    listener_thread.start()

    #thread to send messages
    sending_thread = threading.Thread(target=send_messages, args=(s,), daemon=True)
    sending_thread.start()

    #main function to keep it running until it is killed
    while not exit_flag:
        continue

s.close()