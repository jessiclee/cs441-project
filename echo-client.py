# echo-client.py

import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
IP = "1A"
MAC = "N1"

def create_packet(message, ipdest, mac, length):
    packet = IP + ipdest + str(length+5) + MAC + mac + str(length) + message
    return packet

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True: 
        message = input("Enter message: \n")
        ipdest = input("Enter destination ip: \n")
        macdest = input("Enter destination mac: \n")
        length = len(message)
        packet = create_packet(message, ipdest, macdest, length)
        s.sendall(bytes(packet, 'utf-8') )
        data = s.recv(1024)
        print(f"Received {data!r}")