import socket
import struct
import threading
from ipsec import generate_key, encrypt_payload, decrypt_packet 
import secrets
import csv

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
# key = b'kQ\xd41\xdf]\x7f\x14\x1c\xbe\xce\xcc\xf7\x9e\xdf=\xd8a\xc3\xb4\x06\x9f\x0b\x11f\x1a>\xef\xac\xbb\xa9\x18'
key = None


def create_packet(message, ipdest, mac, protocol, length, key):
    esp_packet = encrypt_payload(message, key)
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

def append_to_csv(data):
    with open("nonces.csv", 'a') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(data)

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
                append_to_csv(secrets.token_hex(16))
                key = generate_key()
            elif data == b"N2:Zq6,eS2yN%sUTF)k" or data.decode() == b"N3:Zq6,eS2yN%sUTF)k":
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
                            decrypted_payload = decrypt_packet(data[9:], key)
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
            print(type(message))
            # Random String s.t. an adversary would not be able to craft a fake key gen message
            # Unless he knows the secret hardcoded information
            key_gen_msg = dest + ":" + "Zq6,eS2yN%sUTF)k"
            key_gen_packet = create_packet_key_gen(key_gen_msg.encode('utf-8'), node[0], node[1], int(proto), length)
            print(key_gen_msg.encode('utf-8'))
            conn.sendall(key_gen_packet)
            
            # Contribute in the key generation after that
            append_to_csv(secrets.token_hex(16))
            # ipsec.set_input()
            key = generate_key()
            
            # To check if the key is different everytime
            print(key)
            
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