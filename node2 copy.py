import socket
import struct
import threading
import ipsec

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
key = b'kQ\xd41\xdf]\x7f\x14\x1c\xbe\xce\xcc\xf7\x9e\xdf=\xd8a\xc3\xb4\x06\x9f\x0b\x11f\x1a>\xef\xac\xbb\xa9\x18'


def create_packet(message, ipsrc, ipdest, mac, protocol, length, key):
    esp_packet = ipsec.encrypt_payload(message, key)
    # print(esp_packet)
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + esp_packet
    # print("ip pack created:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    # print("final packet:", packet)
    return packet

def listen_for_messages(conn):
    global exit_flag
    while True:
        try:
            data = conn.recv(1024)
            macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
            ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
            print(ipsrc, ipdst, protocol, len)
            if macdst == MAC:
                print("received message from: ", macsrc, " unpack ip packet...")
                # ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                print("Ciphertext Message is: ", data[9:])
                if protocol == 1:
                    exit_flag = True
                    break
                elif protocol == 0:
                    if key:
                        decrypted_payload = ipsec.decrypt_packet(data[9:], key)
                        print("Plaintext Message: ", decrypted_payload)
                        packet = create_packet(decrypted_payload, ipsrc, ipdst, macsrc, 3, len, key)  # 3 is hardcoded bc if 1 it will ping to everyone
                        conn.sendall(packet)
                    else:
                        # packet = create_packet(data[9:], ipsrc, macsrc, 3, len)
                        # print("proto 0, sending back")
                        # conn.sendall(packet)
                        print("Decryption Failed")
            elif ipdst == IDS["N3"][0] and SNIFF == True:
                print("Intercepted traffic from",macsrc, "to", macdst)
                print("message is:", data[9:])
            else:
                print("received message is for:", macdst, " from ", macsrc)
                print("drop packet, not for me")
            if not data:
                break
        except ConnectionResetError:
            print("connection closed")
            exit_flag = True
            break

def send_messages(conn,action):
    # while not exit_flag:
    # action = input("What do you want to do?\n 1.Send message\n 2.Send a spoofed message\n")
    if action =='2':
        spoofdest = input("Enter the ID that you want to spoof (N1/N3)\n")
        spoofnode = IDS.get(spoofdest)
        ipsrc = spoofnode[0]
    elif action == "1":
        ipsrc = IP
    while True:
        message = input("Enter message: ").encode('utf-8')
        length = len(message)
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
        if (dest == "N1" or dest == "N3"):
            break
        else:
            print("Please input a valid node (N1/N3)\n")
    try:
        node = IDS[dest]
        packet = create_packet(message, ipsrc, node[0], node[1], int(proto), length, key)
        conn.sendall(packet)
    except KeyError:
        print("sender not found, back to begining")
        pass


def do_actions(conn):
    while not exit_flag: 
        action = input("What do you want to do?\n 1.Send message\n 2.Send a spoofed message\n 3.configure sniffing\n")
        if action == "1" or action == '2':
            send_messages(conn, action)
        elif action == "3":
            while True:
                option = input("choose:\n 1.start sniffing\n 2.stop sniffing \n")
                global SNIFF
                if option == "1" and SNIFF == False:
                    SNIFF = True
                    print("sniffing starts\n")
                    break
                elif option == "1" and SNIFF == True:
                    print("sniffing already started")
                    continue
                elif option == "2" and SNIFF == True:
                    SNIFF = False
                    print("sniffing stopped")
                    break
                elif option == "2" and SNIFF == False:
                    print("sniffing already stopped")
                    continue
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