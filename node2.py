import socket
import struct
import threading

IDS = {
    "N1": (0x1A,  b'N1'),
    "N2": (0x2A, b'N2'),
    "N3": (0x2B, b'N3')
    # Add more mappings as needed
}

HOST = "127.0.1.0"  # Standard loopback interface address (localhost)
PORT = 8000  # Port to listen on (non-privileged ports are > 1023)
IP = 0x2A
MAC = b"N2"
MAX_LEN = 256

def listen_for_messages(conn):
    while True:
        data = conn.recv(1024)
        ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[:4])
        if ipdst == IP:
            print("recieved message for:", hex(ipsrc))
            print("message is:", data[9:])
            if protocol == 1:
                break
        else:
            print("recieved message from:", hex(ipdst))
            print("drop packet, not for me")
        if not data:
            break

def create_packet(message, ipdest, mac, length):
    frame = struct.pack('!2s2sB', MAC, mac, length) + message
    print("frame created:", frame)
    packet = struct.pack('!BBBB', IP, ipdest, 0, length+5) + frame
    print("final packet:", packet)
    return packet

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    #thread to listen for messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(s,), daemon=True)
    listener_thread.start()

    #main function where there is a prompt to send messages
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
        except KeyError:
            print("sender not found, back to begining")
            pass