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
arp_poisoning = False

BROADCASTMAC = b"FF"

def create_packet(message, ipsrc, ipdest, mac, protocol, length):
    ippack = struct.pack('!BBBB', ipsrc, ipdest, protocol, length) + message
    print("ip pack created:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    print("final packet:", packet)
    return packet
                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
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