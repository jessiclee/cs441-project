import socket
import struct
import threading
import ipsec
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
key = b'kQ\xd41\xdf]\x7f\x14\x1c\xbe\xce\xcc\xf7\x9e\xdf=\xd8a\xc3\xb4\x06\x9f\x0b\x11f\x1a>\xef\xac\xbb\xa9\x18'

def create_packet(message, ipdest, mac, protocol, length, key):
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
            if macdst == MAC:
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
    while not exit_flag: 
        while True:
            message = input("Enter message: ").encode('utf-8')
            length = len(message)
            # print(length)
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
            if (dest == "N2" or dest == "N3"):
                break
            else:
                print("Please input a valid node (N2/N3)\n")
        try:
            node = IDS[dest]
            # ipsec.set_input(secrets.token_hex(16))
            # key = ipsec.generate_keys()
            packet = create_packet(message, node[0], node[1], int(proto), length, key)
            conn.sendall(packet)
        except KeyError:
            print("sender not found, back to begining")
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