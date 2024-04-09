import socket
import struct
import threading

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

BROADCASTMAC = b"FF"

def create_packet(message, ipsrc, ipdest, mac, protocol, length):
    ippack = struct.pack('!BBBB', ipsrc, ipdest, protocol, length) + message
    print("ip pack created:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    print("final packet:", packet)
    return packet

def listen_for_messages(conn):
    global exit_flag
    while True:
        try:
            data = conn.recv(1024)
            macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
            ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
            if macsrc in BLOCKed:
                print(f"drop packet, is from {macsrc} which is part of the block list")
                continue
            elif macdst == MAC:
                print("received message from: ", macsrc, " unpack ip packet...")
                print("message is:", data[9:])
                if protocol == 1:
                    exit_flag = True
                    break
                elif protocol == 0:
                    print(macsrc)
                    packet = create_packet(data[9:], IP, ipsrc, macsrc, 5, len)
                    print("proto 0, sending back")
                    conn.sendall(packet)
            elif macdst == BROADCASTMAC and ipdst == IP and protocol == 3:
                print("Received gratitous ARP from ",hex(ipsrc))
                print("ids table before:", IDs)
                for node, (ip, mac) in IDs.items():
                    # Check if the MAC address matches the target MAC
                    if ip == ipsrc:
                        #updated the MAC address of N2 to N1
                        IDs[node] = (ipsrc, b"R2") #hardcoded slightly
                        break  
                # print("updated information: \nip:", hex(ipsrc), "\n MAC:", macsrc)
                print("ids table after:", IDs)
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
            node = IDs[dest]
            packet = create_packet(message, IP, node[0], node[1], int(proto), length)
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
        choice = input("Enter any of the IDs (N1, N2, N3 etc.) to block packets from them or enter 0 to go back to menu")
        if choice == "0":
            return
        elif choice in IDs:
            #remove it from the recieving list
            info = IDs.pop(choice)
            #enter it into block list
            BLOCKed[info[1]] = info[0]
            print("updated block list")
            print(BLOCKed)
            print("updated accept list")
            print(IDs)
            break
        else:
            print(f"{choice} is not within the list! Try again!")
            continue
        
def send_arp_request(conn):
    dest = input("who are we sending the request to?\n")
    node = IDs[dest]
    print("sending ARP request")
    message = "".encode('utf-8')
    packet = create_packet(message, IP, node[0], BROADCASTMAC, 2, 0)
    conn.sendall(packet)

def do_actions(conn):
    while not exit_flag: 
        action = input("What do you want to do?\n 1.Send message\n 2.Configure firewall\n 3.Send ARP request\n")
        if action == "1":
            send_messages(conn)
        elif action == "2":
            manage_firewall()
        elif action == "3":
            send_arp_request(conn)
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