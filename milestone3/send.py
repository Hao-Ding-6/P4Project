#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import bind_layers
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.layers.inet import _IPOption_HDR

class ECMP(Packet):
    name = "ECMP"
    fields_desc = [ShortField("is_load_balance", 1),
                    ShortField("type", 0),
                    ShortField("is_track", 0),
                    IntField("port2_bytes", 0),
                    IntField("port3_bytes", 0),
                    IntField("seq", 0)]  

# bind ECMP class with other layers
bind_layers(Ether, ECMP, type=0x1234)
bind_layers(ECMP, IP, type=0x1234)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))

    for i in range(200):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        # load balance layer
        pkt = pkt / ECMP(is_load_balance = 1, is_track = 1) 
        pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,49163)) / sys.argv[2]
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()