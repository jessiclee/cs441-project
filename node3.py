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

def create_packet(message, ipdest, mac, protocol, length):
    ippack = struct.pack('!BBBB', IP, ipdest, protocol, length) + message
    print("IP Pack created:", ippack)
    packet = struct.pack('!2s2sB', MAC, mac, length+4) + ippack
    print("Final packet:", packet)
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
            is_blocked, k = val_in_dict(macsrc, 1, BLOCKed)
            if is_blocked:
                print(f"Dropping packet as sender is in blocked list {k}")
                continue
            elif macdst == MAC:
                ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
                exists, source = val_in_dict(ipsrc, 0, IDs)
                print("Received message from: ", source, " with IP address ", ipsrc, " and MAC address:", macsrc)
                print("Message:", data[9:])
                if protocol == 1:
                    exit_flag = True
                    break
                elif protocol == 0:
                    print(macsrc)
                    packet = create_packet(data[9:], ipsrc, macsrc, 3, len)
                    print("Protocol 0, sending back")
                    conn.sendall(packet)
            else:
                print("Received message is for ", macdst, " from ", macsrc)
                print("Dropping packet")
            if not data:
                break
        except ConnectionResetError:
            print("Error: Connection closed")
            exit_flag = True
            break

def send_messages(conn):
        while True:
            message = input("Enter message: \t").encode('utf-8')
            length = len(message)
            print(length)
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
            dest = input("Choose recipient (N1/N2): ")
            if (dest == "N2" or dest == "N1"):
                break
            else:
                print("Please input a valid node (N1/N2)")
        try:
            node = IDs[dest]
            packet = create_packet(message, node[0], node[1], int(proto), length)
            conn.sendall(packet)
        except KeyError:
            print("Error: Sender not found")
            pass

def manage_firewall():
    print("Firewall currently accepts packets from the following sources:\n")
    print(IDs)
    print("Firewall currently blocks packets from the following sources:\n")
    print(BLOCKed)
    while True:
        choice = input("Select action:\n 0. Return to menu \n 1. Block a source\n 2. Unblock a source\n")
        if choice == "0":
            return
        elif choice == '1':
            choice2 = input("Enter source to block: ")
            if choice2 in IDs:
                #remove it from the recieving list
                info = IDs.pop(choice2)
                #enter it into block list
                BLOCKed[choice2] = (info[0], info[1])
                print("Updated block list")
                print(BLOCKed)
                print("Updated accept list")
                print(IDs)
            else: 
                print(f"Error: {choice2} is not in the list")
        elif choice == '2':
            choice2 = input("Enter source to unblock: ")
            if choice2 in BLOCKed:
                #remove it from the blocklist
                info = BLOCKed.pop(choice2)
                #enter it to normal list
                IDs[choice2] = (info[0], info[1])
                print("Updated block list")
                print(BLOCKed)
                print("Updated accept list")
                print(IDs)
            else: 
                print(f"Error: {choice2} is not in the list")
        else: 
            print("Error: Invalid choice")

def do_actions(conn):
    while not exit_flag: 
        action = input("Select action:\n 1. Send message\n 2. Configure firewall\n")
        if action == "1":
            send_messages(conn)
        elif action == "2":
            manage_firewall()
        else:
            print("Error: Invalid choice")


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