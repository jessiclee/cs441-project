import socket
import struct
import threading
import ipsec
import secrets
import time

IDS = {
    "N1": (0x1A,  b'R2'),
    "N2": (0x2A, b'N2'),
    "N3": (0x2B, b'N3')
    # Add more mappings as needed
}

HOST = "localhost"  # Standard loopback interface address (localhost)
PORT = 8000  # Port to listen on (non-privileged ports are > 1023)
IP = 0x2A
MAC = b"N2"
MAX_LEN = 256
SNIFF = False
exit_flag = False
wrong_key = b'\xd8c\xa6\xdd\r\xf5@\xd6&Y\x96\xc1\xd0\xf6d\x87\xe81\x07\x0c\xde\xbbN"\xa4\xf3\x9c\x83\x9d5t3'
keys = {
    0x1A: b'\xed\x08\xb6a\x02\xd9\xd8\xf9\xa4\xba\xac\x90\xa7\xfb!9\xaa\x93C\xbb\xec\x16\xf6m\tS\xabq\xe714\x1a',
    0x2B: b'\xf4\x9e\xf7~T\xc3P^\xa4\n\xe8\xbb]\xe1\x97\xe3\xa4\x1cf6U\xf0=\xe2\x15\xcc\xd8\xf1\xe8\x14\xaa\xcd'
}
attack_num = 0
attack_performed = False


def create_packet(message, ipsrc, ipdest, mac, protocol, length, key):
    esp_packet = ipsec.encrypt_payload(message, key)
    print("\nEncrypted Packet:", esp_packet)
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + esp_packet
    print("IP Packet w/ Encrypted Packet:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    print("Final Packet w/ MAC address:", packet , "\n")
    return packet


def create_packet_key_gen(message, ipsrc, ipdest, mac, protocol, length):
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + message
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    return packet


def val_in_dict(val,pos, diction):
    for key, value in diction.items():
        # Check if the second element of the value matches the given value
        if value[pos] == val:
            return True, key
    return False, "NIL"


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


def listen_for_messages(conn):
    global exit_flag
    while True:
        try:
            data = conn.recv(1024)
            if data[9:] == b"N2:Zq6,eS2yN%sUTF)k":
                time.sleep(2)
                append_to_txt(secrets.token_hex(16))
                key = ipsec.generate_key()
                print("Current Key is: ", key)
                
                # Update Key Dictionary
                ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                keys[ipsrc] = key
                
                # Ensure sender has enough time to retrieve the key
                time.sleep(2)
                
                # Revert CSV to a clean state
                ipsec.clean_csv()
            elif data[9:] == b"N1:Zq6,eS2yN%sUTF)k" or data[9:] == b"N3:Zq6,eS2yN%sUTF)k":
                # Do noting because the key is not theirs
                pass
            else:
                macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
                ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                print(ipsrc, ipdst, protocol, len)
                if macdst == MAC:
                    print("\n Packet w/ MAC address:", data)
                    
                    exists, source = val_in_dict(ipsrc, 0, IDS)
                    print("Received message from: ", source, " with IP address ", ipsrc, " and MAC address:", macsrc)
                    # ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                    print("\n Packet w/ IP address:", data[5:])
                    print("Encrypted packet is: ", data[9:])
                    if protocol == 1:
                        exit_flag = True
                        break
                    elif protocol == 0:
                        try:
                            key = keys[ipsrc]
                            # key = wrong_key
                            decrypted_payload = ipsec.decrypt_packet(data[9:], key)
                            print("Plaintext Message: ", decrypted_payload)
                            packet = create_packet(decrypted_payload, ipdst, ipsrc, macsrc, 3, len, key)  # 3 is hardcoded bc if 1 it will ping to everyone
                            conn.sendall(packet)
                        except KeyError:
                            print(ipsrc, type(ipsrc))
                            print("Key not found")
                elif ipdst == IDS["N3"][0] and SNIFF == True:
                    print("Intercepted traffic from", macsrc, "to", macdst)
                    print("Message:", data[9:])
                else:
                    print("Received message is for ", macdst, " from ", macsrc)
                    print("Dropping packet")
            if not data:
                break
        except ConnectionResetError:
            print("Error: Connection closed")
            exit_flag = True
            break

def send_messages(conn,action):
    # while not exit_flag:
    # action = input("What do you want to do?\n 1.Send message\n 2.Send a spoofed message\n")
    if action =='2':
        spoofdest = input("Enter the ID that you want to spoof (N1/N3):")
        spoofnode = IDS.get(spoofdest)
        ipsrc = spoofnode[0]
    elif action == "1":
        ipsrc = IP
    while True:
        message = input("Enter message: ").encode('utf-8')
        length = len(message)
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
        dest = input("Choose recipient (N1/N3): ")
        if (dest == "N1" or dest == "N3"):
            break
        else:
            print("Please input a valid node (N1/N3)")
    try:
        node = IDS[dest]
        
        # Random String s.t. an adversary would not be able to craft a fake key gen message
        # Unless he knows the secret hardcoded information
        key_gen_msg = dest + ":" + "Zq6,eS2yN%sUTF)k"
        key_gen_packet = create_packet_key_gen(key_gen_msg.encode('utf-8'), ipsrc, node[0], node[1], int(proto), length)
        conn.sendall(key_gen_packet)
        
        # Contribute in the key generation after that
        append_to_txt(secrets.token_hex(16))
        time.sleep(2)
        key = ipsec.generate_key()
        
        # To check if the key is different everytime
        print("Current Key is: ", key)
        
        # Update Key in the Dictionary
        keys[node[0]] = key
        
        packet = create_packet(message, ipsrc, node[0], node[1], int(proto), length, key)
        conn.sendall(packet)
    except KeyError:
        print("Error: Sender not found")
        pass

def dos_attack(conn, target, attack_limit):
    global attack_num
    node = IDS[target]
    key  = keys[node[0]]
    # key = wrong_key
    attack_message = "DOS attack".encode('utf-8')
    while attack_num < attack_limit:
        packet = create_packet_key_gen(attack_message, IP, node[0], node[1], 1, len(attack_message))
        conn.sendall(packet)
        attack_num += 1
        print("DOS attack count:", attack_num, "Thread ID:", threading.get_ident())

def do_actions(conn):
    global attack_performed
    while not exit_flag: 
        prompt = "\nSelect action:\n 1. Send message\n 2. Send a spoofed message\n 3. Configure sniffing\n"
        if not attack_performed:
            prompt += "4. Perform DOS attack\n"
        action = input(prompt)
        if action == "1" or action == '2':
            send_messages(conn, action)
        elif action == "3":
            while True:
                option = input("Select action:\n 1. Start sniffing\n 2. Stop sniffing \n")
                global SNIFF
                if option == "1" and SNIFF == False:
                    SNIFF = True
                    print("Sniffing started")
                    break
                elif option == "1" and SNIFF == True:
                    print("Sniffing already started")
                    continue
                elif option == "2" and SNIFF == True:
                    SNIFF = False
                    print("Sniffing stopped")
                    break
                elif option == "2" and SNIFF == False:
                    print("Sniffing already stopped")
                    continue
        elif action == "4" and not attack_performed:
            target = str(input("Enter target (N1/N3): "))
            if not (target == "N1" or target == "N3"):
                print("Error: Invalid target")
            else:
                try:
                    attack_limit = int(input("Enter number of packets to send: "))
                    thread_count = int(input("Enter number of threads to create: "))
                    for i in range(thread_count):
                        thread = threading.Thread(target=dos_attack, args=(conn, target, attack_limit))
                        thread.start()
                    while attack_num < attack_limit:
                        time.sleep(1) # delay for threads to complete running
                    print("DOS attack complete")
                    attack_performed = True
                except ValueError:
                    print("Error: Invalid input, please enter an integer")
        else:
            print("Error: Invalid action")

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