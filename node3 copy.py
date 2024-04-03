import socket
import struct
import threading
import ipsec

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
key = b'kQ\xd41\xdf]\x7f\x14\x1c\xbe\xce\xcc\xf7\x9e\xdf=\xd8a\xc3\xb4\x06\x9f\x0b\x11f\x1a>\xef\xac\xbb\xa9\x18'

def create_packet(message, ipdest, mac, protocol, length, key):
    esp_packet = ipsec.encrypt_payload(message, key)
    # print(esp_packet)
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + esp_packet
    # print("ip pack created:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    # print("final packet:", packet)
    return packet

def val_in_block(val):
    for key, value in BLOCKed.items():
        # Check if the second element of the value matches the given value
        if value[1] == val:
            return True, key
    return False, "NIL"

def listen_for_messages(conn):
    global exit_flag
    while True:
        try:
            data = conn.recv(1024)
            macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
            is_blocked, k = val_in_block(macsrc)
            if is_blocked:
                print(f"drop packet, is from {k} which is part of the block list")
                continue
            elif macdst == MAC:
                print("received message from: ", macsrc, " unpack ip packet...")
                ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                print("message is:", data[9:])
                if protocol == 1:
                    exit_flag = True
                    break
                elif protocol == 0:
                    if key:
                        decrypted_payload = ipsec.decrypt_packet(data[9:], key)
                        print(decrypted_payload)
                        packet = create_packet(decrypted_payload, ipsrc, macsrc, 3, len, key)
                        conn.sendall(packet)
                    else:
                        # packet = create_packet(data[9:], ipsrc, macsrc, 3, len)
                        # print("proto 0, sending back")
                        # conn.sendall(packet)
                        print("Decryption Failed")
            else:
                print("received message is for:", macdst, " from ", macsrc)
                print("drop packet, not for me")
            if not data:
                break
        except ConnectionResetError:
            print("connection closed")
            exit_flag = True
            break

def send_messages(conn):
        while True:
            message = input("Enter message: \t").encode('utf-8')
            length = len(message)
            print(length)
            if length > MAX_LEN:
                print ("message too long, needs to be less than" + MAX_LEN + "try again!")
            else:
                break
        while True:
            proto = input("Choose protocol: ")
            if (proto == "0" or proto == "1"):
                break
            else:
                print("Please input 0 (Ping Protocol) or 1 (Kill Protocol)\n")
                
        while True:
            dest = input("Who do you want to send it to?: ")
            if (dest == "N2" or dest == "N1"):
                break
            else:
                print("Please input a valid node (N1/N2)\n")
        try:
            node = IDs[dest]
            packet = create_packet(message, node[0], node[1], int(proto), length, key)
            conn.sendall(packet)
        except KeyError:
            print("sender not found, back to begining")
            pass

def manage_firewall():
    print("Currently accepts packets from the following:\n")
    print(IDs)
    print("currently blocks packets from the following:\n")
    print(BLOCKed)
    while True:
        choice = input("What do you want to do?\n 0. return to menu \n 1. Block a source\n 2. Unblock a source\n")
        if choice == "0":
            return
        elif choice == '1':
            choice2 = input("Who do you want to block?\n")
            if choice2 in IDs:
                #remove it from the recieving list
                info = IDs.pop(choice2)
                #enter it into block list
                BLOCKed[choice2] = (info[0], info[1])
                print("updated block list")
                print(BLOCKed)
                print("updated accept list")
                print(IDs)
            else: 
                print(f"{choice2} is not within the list! Try again!")
        elif choice == '2':
            choice2 = input("Who do you want to unblock?\n")
            if choice2 in BLOCKed:
                #remove it from the blocklist
                info = BLOCKed.pop(choice2)
                #enter it to normal list
                IDs[choice2] = (info[0], info[1])
                print("updated block list: ")
                print(BLOCKed)
                print("updated accept list: ")
                print(IDs)
            else: 
                print(f"{choice2} is not within the list! Try again!")
        else: 
            print("invalid choice :(")

def do_actions(conn):
    while not exit_flag: 
        action = input("What do you want to do?\n 1.Send message\n 2.Configure firewall\n")
        if action == "1":
            send_messages(conn)
        elif action == "2":
            manage_firewall()
        else:
            print("invalid choice!")


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