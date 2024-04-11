# imports
import socket
import struct
import threading

HOST1 = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT1 = 65432  # Port to listen on (non-privileged ports are > 1023)
IP1 = 0x11
MAC1 = b"R1"

HOST2 = "localhost"  # Standard loopback interface address (localhost)
PORT2 = 8000  # Port to listen on (non-privileged ports are > 1023)
IP2 = 0x21
MAC2 = b"R2"

R1_IDs = {
    0x1A: b'N1',
    # Add more mappings as needed
}

R2_IDs = { 
    0x2A: b'N2',
    0x2B: b'N3',
}

BROADCASTMAC = b"FF"
 
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s1.bind((HOST1, PORT1))
s1.listen()
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s2.bind((HOST2, PORT2))
s2.listen()
n1 = None
n2 = None
n3 = None
msg = None 

def create_ether_frame(data, srcmac, dstmac, length):
    packet = struct.pack('!2s2sB', srcmac, dstmac, length+4) + data
    return packet

def local_broadcast(data):
    n2.sendall(data)
    n3.sendall(data)

def broadcast(data):
    print("Sending broadcast: ", data)
    n1.sendall(data)
    n2.sendall(data)
    n3.sendall(data)

def handle_ip_packet(data, macsrc, local):
    ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[:4])
    try:
        if local == 1:
            dstmac = R1_IDs[ipdst]
            pack = create_ether_frame(data, MAC1, dstmac, len)
            print( f"Sending packet through R1 interface to N1 with headers: ipsrc {ipsrc}, ipdst {ipdst} and macsrc {MAC1} macdst {dstmac}" )
            n1.sendall(pack)
        elif local == 2:
            dstmac = R2_IDs[ipdst]
            pack = create_ether_frame(data, MAC2, dstmac, len)
            print( f"Sending through R2 interface to N2/3 with headers: ipsrc {ipsrc}, ipdst {ipdst} and macsrc {MAC1} macdst {dstmac}")
            n2.sendall(pack)
            n3.sendall(pack)
    except KeyError:
        print(f"Something went wrong: ipdst {ipdst} ipsrc {ipsrc} local{local}")
        print(R1_IDs)
        print(R2_IDs)

def receive_packets(interface_socket):
    while True:
        try:
            data = interface_socket.recv(1024)
            if not data:
                break
            # Unpack ethernet frame and check destination MAC to know which interface to forward to
            macsrc, macdst, leng = struct.unpack('!2s2sB', data[:5])
            ipsrc, ipdst, protocol, len = struct.unpack('!BBBB', data[5:9])
            print(f"Received packet from {macsrc}: {data}\n")
            if macdst == BROADCASTMAC:
                # print("sending broadcast\n")
                threading.Thread(target=broadcast, args=(data, )).start()
                if protocol == 2: 
                    print("ARP request from: ", hex(ipsrc), " searching for :", data[9:])
                elif protocol == 3:
                    print("Gratitous ARP: ", hex(ipsrc), " is now associated with macsrc: ", macsrc)
                    if ipsrc in R1_IDs:
                        print("R1 table before: ", R1_IDs)
                        # Update the MAC address for N3 to N1
                        R1_IDs[ipsrc] = macsrc 
                        print("R1 table after: ", R1_IDs)
                    elif ipsrc in R2_IDs:
                        print("R2 table before: ", R2_IDs)
                        # Update the MAC address for N3 to N2
                        R2_IDs[ipsrc] = macsrc 
                        print("R2 table after: ", R2_IDs)
            elif macdst == MAC1:
                threading.Thread(target=handle_ip_packet, args=(data[5:], macsrc, 2)).start()
            elif macdst == MAC2:
                threading.Thread(target=handle_ip_packet, args=(data[5:], macsrc, 1)).start()
            elif macdst in R2_IDs.values():
                print("Sending local broadcast\n")
                threading.Thread(target=local_broadcast, args=(data, )).start()
            
        except ConnectionResetError:
            print("Error: Connection closed")
            break

while (n1 == None):
    client, address = s1.accept()
    n1 = client
    # print(n1)
    print(f"Connected Node 1 through {address}")
    threading.Thread(target=receive_packets, args=(n1,), daemon=True).start()

while (n2 == None or n3 == None):
    client, address = s2.accept()
    if(n2 == None):
        n2 = client
        # print(n2)
        threading.Thread(target=receive_packets, args=(n2,), daemon=True).start()
        print(f"Connected Node 2 through {address}")
    elif(n3 == None):
        n3 = client
        # print(n3)
        threading.Thread(target=receive_packets, args=(n3,), daemon=True).start()
        print(f"Connected Node 3 through {address}")


while msg == None:
    kill_code = input("Type anything to kill: \n")
    if kill_code != None:
        msg = 1