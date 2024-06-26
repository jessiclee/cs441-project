import socket
import struct
import threading
import ipsec
import secrets
import time

IDs = {
    "N1": (0x1A,  b'R2'),
    "N2": (0x2A, b'N2'),
    "N3": (0x2B, b'N3')
    # Add more mappings as needed
}

BLOCKed = {}

HOST = "localhost"  # Standard loopback interface address (localhost) *172.0.1.0 doesn't work for me
PORT = 8000  # Port to listen on (non-privileged ports are > 1023)
IP = 0x2B
MAC = b"N3"
MAX_LEN = 256
exit_flag = False
wrong_key = b'\xd8c\xa6\xdd\r\xf5@\xd6&Y\x96\xc1\xd0\xf6d\x87\xe81\x07\x0c\xde\xbbN"\xa4\xf3\x9c\x83\x9d5t3'
# key = b'kQ\xd41\xdf]\x7f\x14\x1c\xbe\xce\xcc\xf7\x9e\xdf=\xd8a\xc3\xb4\x06\x9f\x0b\x11f\x1a>\xef\xac\xbb\xa9\x18'
key = None


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
            if data[9:] == b'N3:Zq6,eS2yN%sUTF)k':
                time.sleep(2)
                append_to_txt(secrets.token_hex(16))
                key = ipsec.generate_key()
                print("Current Key is: ", key)
                
                # Ensure sender has enough time to retrieve the key
                time.sleep(2)
                
                # Revert CSV to a clean state
                ipsec.clean_csv()
            elif data[9:] == b'N2:Zq6,eS2yN%sUTF)k' or data[9:] == b'N1:Zq6,eS2yN%sUTF)k':
                # Do noting because the key is not theirs
                pass
            else:
                macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
                is_blocked, k = val_in_dict(macsrc, 1, BLOCKed)
                if is_blocked:
                    print(f"Dropping packet as sender is in blocked list {k}")
                    continue
                elif macdst == MAC:
                    ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
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
                    print("Received message is for ", macdst, " from ", macsrc)
                    print("Dropping packet")
            if not data:
                break
        except ConnectionResetError:
            print("Error: Connection closed")
            exit_flag = True
            break

def send_messages(conn):
        while True:
            message = input("Enter message: \t").encode('utf-8')
            length = len(message)
            print(length)
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
            dest = input("Choose recipient (N1/N2): ")
            if (dest == "N2" or dest == "N1"):
                break
            else:
                print("Please input a valid node (N1/N2)")
        try:
            node = IDs[dest]
            
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

def manage_firewall():
    print("Firewall currently accepts packets from the following sources:\n")
    print(IDs)
    print("Firewall currently blocks packets from the following sources:\n")
    print(BLOCKed)
    while True:
        choice = input("Select action:\n 0. Return to menu \n 1. Block a source\n 2. Unblock a source\n")
        if choice == "0":
            return
        elif choice == '1':
            choice2 = input("Enter source to block: ")
            if choice2 in IDs:
                #remove it from the recieving list
                info = IDs.pop(choice2)
                #enter it into block list
                BLOCKed[choice2] = (info[0], info[1])
                print("Updated block list")
                print(BLOCKed)
                print("Updated accept list")
                print(IDs)
            else: 
                print(f"Error: {choice2} is not in the list")
        elif choice == '2':
            choice2 = input("Enter source to unblock: ")
            if choice2 in BLOCKed:
                #remove it from the blocklist
                info = BLOCKed.pop(choice2)
                #enter it to normal list
                IDs[choice2] = (info[0], info[1])
                print("Updated block list")
                print(BLOCKed)
                print("Updated accept list")
                print(IDs)
            else: 
                print(f"Error: {choice2} is not in the list")
        else: 
            print("Error: Invalid choice")

def do_actions(conn):
    while not exit_flag: 
        action = input("Select action:\n 1. Send message\n 2. Configure firewall\n")
        if action == "1":
            send_messages(conn)
        elif action == "2":
            manage_firewall()
        else:
            print("Error: Invalid choice")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    #thread to listen for messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(s,), daemon=True)
    listener_thread.start()

    #thread to send messages
    sending_thread = threading.Thread(target=do_actions, args=(s,), daemon=True)
    sending_thread.start()

    #main function to keep it running until it is killed
    while not exit_flag:
        continue

s.close()