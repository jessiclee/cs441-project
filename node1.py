import socket
import struct
import threading
import ipsec
import time
import secrets

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
arp_poisoning = False

BROADCASTMAC = b"FF"

wrong_key = b'\xd8c\xa6\xdd\r\xf5@\xd6&Y\x96\xc1\xd0\xf6d\x87\xe81\x07\x0c\xde\xbbN"\xa4\xf3\x9c\x83\x9d5t3'
keys = {
    0x2A: b'\xed\x08\xb6a\x02\xd9\xd8\xf9\xa4\xba\xac\x90\xa7\xfb!9\xaa\x93C\xbb\xec\x16\xf6m\tS\xabq\xe714\x1a',
    0x2B: b'}1I\xf0\xc3l\xbe\xc3\xf9_\xd1\x00\xe9\xbf\x01\x9b\x9e\xaa\x04!\x01\xaeP\x8b\xf8\xc4\x05h\xba\xb8>W'
}

def create_packet(message, ipsrc, ipdest, mac, protocol, length, key):
    esp_packet = ipsec.encrypt_payload(message, key)
    print("\nEncrypted Packet:", esp_packet)
    ippack = struct.pack('!BBBB', ipsrc, ipdest, protocol, length) + esp_packet
    print("IP Packet w/ Encrypted Packet:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    print("Final Packet w/ MAC address:", packet , "\n")
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
    global arp_poisoning
    while True:
        try:
            data = conn.recv(1024)
            macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
            ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
            print("\nmacdst is:", macdst)
            if macdst == MAC:
                print("received message from: ", macsrc, " unpack ip packet...")
                # ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                print("message is:", data[9:])
                if protocol == 1:
                    exit_flag = True
                    break
                elif protocol == 0:
                    packet = create_packet(data[9:], ipdst, ipsrc, macsrc, 5, len)
                    print("proto 0, sending back")
                    conn.sendall(packet)
                elif protocol == 2:
                    print("received ARP reply\n")
                    print("sending gratitous ARP\n")
                    packet = create_packet(data[9:], ipdst, ipsrc, macsrc, 3, len)
            elif macdst == BROADCASTMAC and arp_poisoning == True:
                print ("detected ARP message from", hex(ipsrc), "to", hex(ipdst))
                print("sending gratitous ARP\n")
                message = "".encode('utf-8')
                packet1 = create_packet(message, ipsrc, ipdst, BROADCASTMAC, 3, 0) # N2 = ipdst, N3 = ipsrc, this is packet to N2 #not real broadcast, manually send since we the ipsrc is diff for each node
                packet2 = create_packet(message, ipdst, ipsrc, BROADCASTMAC, 3, 0) #this is packet to N3 from "N2"
                conn.sendall(packet1)
                conn.sendall(packet2)
                break
            if data[9:] == b"N1:Zq6,eS2yN%sUTF)k":
                time.sleep(2)
                # ipsec.set_input(secrets.token_hex(16))
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
            elif data[9:] == b"N2:Zq6,eS2yN%sUTF)k" or data[9:] == b"N3:Zq6,eS2yN%sUTF)k":
                # Do nothing because the key is not theirs
                pass
            else:
                macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
                if macdst == MAC:
                    print("\n Packet w/ MAC address:", data)
                    ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                    
                    print("\n Packet w/ IP address:", data[5:])
                    
                    exists, source = val_in_dict(ipsrc, 0, IDS)
                    print("Received message from: ", source, " with IP address ", ipsrc, " and MAC address:", macsrc)
                    print("Encrypted packet is: ", data[9:])
                    if protocol == 1:
                        exit_flag = True
                        break
                    elif protocol == 0:
                        try:
                            key = keys[ipsrc]
                            if data[9:19] == b'DOS attack':
                                decrypted_payload = b'DOS attack'
                            else:
                                decrypted_payload = ipsec.decrypt_packet(data[9:], key)
                            print("Plaintext Message: ", decrypted_payload)
                            packet = create_packet(decrypted_payload, ipsrc, macsrc, 3, len, key)
                            conn.sendall(packet)
                        except KeyError:
                            print("Key not found")
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
    while True:
        message = input("Enter message: \n").encode('utf-8')
        length = len(message)
        print(length)
        if length > MAX_LEN:
            print ("message too long, needs to be less than" + MAX_LEN + "try again!")
        else:
            break
    proto = input("Choose protocol: \n")
    dest = input("Who do you want to send it to?: \n")
    try:
        node = IDS[dest]
        packet = create_packet(message, IP, node[0], node[1], int(proto), length)
        conn.sendall(packet)
    except KeyError:
        print("sender not found, back to begining")
        pass
        
def do_actions(conn):
    while not exit_flag: 
        action = input("What do you want to do?\n 1.Send message\n 2.start/stop arp poisoning\n")
        if action == "1":
            send_messages(conn)
        elif action == "2":
            global arp_poisoning 
            if arp_poisoning == True:
                print("arp poisoning stopped\n")
                arp_poisoning = False
            else:
                print("arp poisoning started\n")
                arp_poisoning = True 
        else:
            print("invalid choice!")
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
            conn.sendall(key_gen_packet)
            
            # Contribute in the key generation after that
            append_to_txt(secrets.token_hex(16))
            time.sleep(2)
            key = ipsec.generate_key()
            
            # To check if the key is different everytime
            print("Current Key is: ", key)
            
            # Update Key in the Dictionary
            keys[node[0]] = key
            
            # Send the actual packet
            packet = create_packet(message, node[0], node[1], int(proto), length, key)
            conn.sendall(packet)
            # Update key
            # key = keys[node[0]]
            # if key:
            #     packet = create_packet(message, node[0], node[1], int(proto), length, key)
            #     conn.sendall(packet)
            # if not key:
            #     print("Key not found")
        except KeyError:
            print("Error: Sender not found")
            pass

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