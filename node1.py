import socket
import struct
import threading

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

def create_packet(message, ipdest, mac, protocol, length):
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + message
    print("IP Pack created: ", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    print("Final packet: ", packet)
    return packet

def val_in_dict(val,pos, diction):
    for key, value in diction.items():
        # Check if the second element of the value matches the given value
        if value[pos] == val:
            return True, key
    return False, "NIL"

def listen_for_messages(conn):
    global exit_flag
    while True:
        try:
            data = conn.recv(1024)
            macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
            if macdst == MAC:
                ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                exists, source = val_in_dict(ipsrc, 0, IDS)
                print("Received message from: ", source, " with IP address ", ipsrc, " and MAC address:", macsrc)
                print("Message: ", data[9:])
                if protocol == 1:
                    exit_flag = True
                    break
                elif protocol == 0:
                    packet = create_packet(data[9:], ipsrc, macsrc, 3, len)
                    print("Protocol 0, sending back")
                    conn.sendall(packet)
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
    while not exit_flag: 
        while True:
            message = input("Enter message: ").encode('utf-8')
            length = len(message)
            # print(length)
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
            packet = create_packet(message, node[0], node[1], int(proto), length)
            conn.sendall(packet)
        except KeyError:
            print("Error: Sender not found")
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