# echo-client.py

import socket
import struct

IDS = {
    "N1": (0x1A,  b'N1'),
    "N2": (0x2A, b'N2'),
    "N3": (0x2B, b'N3')
    # Add more mappings as needed
}

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
IP = 0x1A
MAC = b"N1"
MAX_LEN = 256

def create_packet(message, ipdest, mac, length):
    frame = struct.pack('!2s2sB', MAC, mac, length) + message
    print("frame created:", frame)
    packet = struct.pack('!BBBB', IP, ipdest, 0, length+5) + frame
    print("final packet:", packet)
    return packet

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True: 
        while True:
            message = input("Enter message: \n").encode('utf-8')
            length = len(message)
            print(length)
            if length > MAX_LEN:
                print ("message too long, needs to be less than" + MAX_LEN + "try again!")
            else:
                break

        dest = input("Who do you want to send it to?: \n")
        try:
            node = IDS[dest]
            packet = create_packet(message, node[0], node[1], length)
            s.sendall(packet)
            data = s.recv(1024)
            print(f"Received {data!r}")
        except KeyError:
            print("sender not found, back to begining")
            pass
        
       