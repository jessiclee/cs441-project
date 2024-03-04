# echo-server.py

import socket
import struct
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
IP1 = 0x11
IP2 = 0x21
MAC1 = b"R1"
MAC2 = b"R2"
MAX_LEN = 256

IDS = {
    "N1": (0x1A,  b'N1'),
    "N2": (0x2A, b'N2'),
    "N3": (0x2B, b'N3')
    # Add more mappings as needed
}

def create_packet(message, ipdest, mac, length):
    frame = struct.pack('!2s2sB', MAC1, mac, length) + message
    print("frame created:", frame)
    packet = struct.pack('!BBBB', IP1, ipdest, 0, length+5) + frame
    print("final packet:", packet)
    return packet

def extract_message(packet):
    macsrc, macdst, len = struct.unpack('!2s2sB', packet[:5])
    #code below technichally irrelevant but here for checking
    print("macsrc: ", macsrc)
    print("macdst: ", macdst)
    print("len: ", len)
    return packet[5:], macsrc

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.bind((HOST, PORT))
s.listen()
conn, addr = s.accept()

with conn:
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        ipsrc, ipdst, protocol, data_len = struct.unpack('!BBBB', data[:4])
        print("msg recieved from: ", ipdst)
        if protocol == 0: 
            msg, macsrc = extract_message(data[4:])
            print(msg)
            ret_packet = create_packet(msg, ipsrc, macsrc, data_len-5)
            conn.sendall(ret_packet)
        if not data:
            break
