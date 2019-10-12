from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from random import randint
from datetime import datetime
from time import strftime

try:
    target = input("[*] Enter Target IP Address: ")
    min_port = input("[*] Enter Minumum Port Number: ")
    max_port = input("[*] Enter Maximum Port Number: ")
    try:
        if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) <= 65535 and int(max_port) >= int(min_port):
            pass
        else:
            print ("\n[!] Invalid Range of Ports")
            print ("[!] Exiting ...")
            sys.exit(1)
    except Exception:
        print ("\n[!] Invalid Range of Ports")
        print ("[!] Exiting ...")
        sys.exit(1)
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown...")
    print("[*] Exiting... ")
    sys.exit(1)

ports = range(int(min_port),int(max_port)+1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

def checkhost(ip):
    #conf.verb = 0
    try:
        ip_id=randint(1,65535)
        icmp_id=randint(1,65535)
        icmp_seq=randint(1,65535)
        packet=IP(dst=ip,ttl=64,id=ip_id)/ICMP(id=icmp_id,seq=icmp_seq)
        ping=sr1(packet,timeout=2,verbose=False)
        if ping:
            print("\n[*] Target is Up ...")
        else:
            print("\n[!] Couldn't Resolve Target")
            os._exit(3)
    except Exception:
        print ("\n[!] Couldn't Resolve Target")
        print("[!] Exiting ...")
        sys.exit(1)
def scanport(port):
    #print("scanning "+str(port))
    srcport = RandShort()
    conf.verb=0   
    SYNACKpkt = sr1(IP(dst=target)/TCP(sport = srcport,dport = port,flags="S"))
    pktflags = SYNACKpkt.getlayer(TCP).flags
    if pktflags == SYNACK:
        return True
    else:
        return False
    RSTpkt = IP(dst=target)/TCP(sport = srcport,dport = port,flags="R")
    send(RSTpkt)


checkhost(target)

print("[*] Scanning Started at "+ strftime("%H:%M:%S")+"!\n")
for port in ports:
    status = scanport(port)
    if status == True:
        print("Port"+str(port)+": Open")

stop_clock = datetime.now()
total_time = stop_clock - start_clock
print("\n[*] Scanning Finished!")
print("[*] Total Scan Duration: " + str(total_time))