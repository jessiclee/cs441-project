# imports
import socket
import struct
import threading

HOST1 = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT1 = 65432  # Port to listen on (non-privileged ports are > 1023)
IP1 = 0x11
MAC1 = b"R1"

HOST2 = "127.0.1.0"  # Standard loopback interface address (localhost)
PORT2 = 8000  # Port to listen on (non-privileged ports are > 1023)
IP2 = 0x21
MAC2 = b"R1"

R1_IDS = {
    0x1A: b'N1',
    # Add more mappings as needed
}

R2_IDS = { 
    0x2A: b'N2',
    0x2B: b'N3',
}

s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s1.bind((HOST1, PORT1))
s1.listen()
print("s1")
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s2.bind((HOST2, PORT2))
s2.listen()
print("s2")
# s.listen()
# conn, addr = s.accept()
n1 = None
n2 = None
n3 = None
msg = None 

def handle_packet(data, src_address, dst_address):
    if dst_address in R1_IDS:
        print(f"sending message from {hex(src_address)} to {hex(dst_address)} on interface R1")
        n1.sendall(data)
    elif dst_address in R2_IDS:
        print(f"sending message from {hex(src_address)} to {hex(dst_address)} on interface R2")
        n2.sendall(data)
        n3.sendall(data)
    else:
        print("something went wrong")
        print("debugging info:", data)
        print("src and dst:", src_address, dst_address)
        print(R1_IDS)
        print(R2_IDS)
    

def receive_packets(interface_socket):
    while True:
        try:
            data = interface_socket.recv(1024)
            if not data:
                break
            ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[:4])
            print(f"Received packet from {hex(ipsrc)}: {data}")
            threading.Thread(target=handle_packet, args=(data, ipsrc, ipdst)).start()
        except ConnectionResetError:
            print("connection closed")
            break

while (n1 == None):
    client, address = s1.accept()
    n1 = client
    print(f"Connected Node1 through {address}")
    threading.Thread(target=receive_packets, args=(n1,), daemon=True).start()

while (n2 == None or n3 == None):
    client, address = s2.accept()
    if(n2 == None):
        n2 = client
        threading.Thread(target=receive_packets, args=(n2,), daemon=True).start()
        print(f"Connected Node2 through {address}")
        print("Client 2 is online")
    elif(n3 == None):
        n3 = client
        threading.Thread(target=receive_packets, args=(n3,), daemon=True).start()
        print(f"Connected Node3 through {address}")
        print("Client 3 is online")


while msg == None:
    kill_code = input("Type anything to kill: \n")
    if kill_code != None:
        msg = 1