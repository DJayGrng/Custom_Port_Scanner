#This script performs TCP stealth scanning when you specify T and UDP scanning when you specify U
#IP address and ports should also be specified.


import random
import sys
from scapy.all import *


def tcpScan(target, ports):
    print("Protocol TCP")
    print("Target "+target)
    print("Ports "+ports)
    print("TCP scanning starts...")
    ports=ports[:]
    ports=ports.split('-')
    SYN_ACK=0x012
    RST=0x04
    if len(ports) == 2:
        ports=list(range(int(ports[0]),int(ports[1])))
        random.shuffle(ports)
        for port in ports:
            pkt = sr1(IP(dst=target)/TCP(flags="S", dport=port), timeout=2, verbose=0)
            if pkt == None:
                print("Port: [" + str(port) + "]\tStatus: Filtered\t\tReason: No response")
            else:
                if pkt.haslayer(ICMP):
                    print("Port: [" + str(port) + "]\tStatus: Filtered\t\tReason: ICMP Port Unreachable")
                elif pkt.haslayer(TCP): 
                    if (pkt.getlayer(TCP).flags & RST):
                        print("Port: [" + str(port) + "]\tStatus: Closed\t\tReason: Received TCP RST")
                    elif (pkt.getlayer(TCP).flags & SYN_ACK):                        
                        send(IP(dst=target)/TCP(flags="R", dport=port),verbose=0)
                        print("Port: [" + str(port) + "]\tStatus: Open\t\tReason: Received TCP SYN-ACK")

    else:
        port=int(ports[0])
        pkt = sr1(IP(dst=target)/TCP(sport=port, dport=port), timeout=2, verbose=0)
        if pkt == None:
            print("Port: [" + str(port) + "]\tStatus: Filtered\t\tReason: No response")
        else:
            if pkt.haslayer(ICMP):
                print("Port: [" + str(port) + "]\tStatus: Filtered\t\tReason: ICMP Port Unreachable")
            elif pkt.haslayer(TCP): 
                    if (pkt.getlayer(TCP).flags & RST):
                        print("Port: [" + str(port) + "]\tStatus: Closed\t\tReason: Received TCP RST")
                    elif (pkt.getlayer(TCP).flags & SYN_ACK):                        
                        send(IP(dst=target)/TCP(flags="R", dport=port),verbose=0)
                        print("Port: [" + str(port) + "]\tStatus: Open\t\tReason: Received TCP SYN-ACK")


       

def udpScan(target, ports):
    print("Protocol UDP")
    print("Target "+target)
    print("Ports "+ports)
    print("UDP scanning starts...")
    ports=ports[:]
    ports=ports.split('-')
    if len(ports) == 2:
        ports=list(range(int(ports[0]),int(ports[1])))
        random.shuffle(ports)
        for port in ports:
            pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
            if pkt == None:
                print("Port: [" + str(port) + "]\tStatus: Open|Filtered\tReason: No response")
            else:
                if pkt.haslayer(ICMP):
                    print("Port: [" + str(port) + "]\tStatus: Closed\tReason: ICMP Port Unreachable")
                elif pkt.haslayer(UDP): 
                    print("Port: [" + str(port) + "]\tStatus: Open\tReason: Received UDP packet")

    else:
        port=int(ports[0])
        pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
        if pkt == None:
            print("Port: [" + str(port) + "]\tStatus: Open|Filtered\tReason: No response")
        else:
            if pkt.haslayer(ICMP):
                print("Port: [" + str(port) + "]\tStatus: Closed\tReason: ICMP Port Unreachable")
            elif pkt.haslayer(UDP): 
                print("Port: [" + str(port) + "]\tStatus: Open\tReason: Received UDP packet")

    

if __name__ == "__main__":
    try:
        prot=str(sys.argv[1])
        ip=str(sys.argv[2])
        port=str(sys.argv[3])
        if prot != 'T' and prot != 'U':
            print("Wrong Prototocol Entered !!")
            exit(1)
        temp=ip[:]
        temp=temp.split('.')
        if len(temp) !=4:
            print("Input is not a valid IP Address")
            exit(1)
        for t in temp:
            if not t.isdigit() :
                print("Input is not a valid IP Address")
                exit(1)
        temp=port[:]
        temp=port.split('-')
        if len(temp) >2 :
            print("Input is not a valid port number")
            exit(1)
        for t in temp:
            if not t.isdigit() or len(temp)>2:
                print("Input is not a valid Port Number")
                exit(1)

    except:
        print("3 arguments must be given.")
        print("1. Protocol Name('T' for TCP or 'U' for UDP)")
        print("2. IP address(version 4) of target machine")
        print("3. Port number(s)(Format should be '23' or '23-59') ")
        print("Exiting ....")
        exit(1)


    if prot == 'T':
        tcpScan(ip,port)
    else:
        udpScan(ip,port)

