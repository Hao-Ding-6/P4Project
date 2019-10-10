#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import bind_layers
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.layers.inet import _IPOption_HDR

import collections

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

flowDict = collections.defaultdict(list)
localInversionDict = collections.defaultdict(int)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if TCP in pkt and ECMP in pkt:
        if len(flowDict[pkt[TCP].sport]) > 0 and flowDict[pkt[TCP].sport][-1] > pkt[ECMP].seq:
            localInversionDict[pkt[TCP].sport] += 1
        flowDict[pkt[TCP].sport].append(pkt[ECMP].seq)
        print "arrived packets: ", flowDict

        for key in localInversionDict.keys():
            print "Flow from port ", key, " has ", localInversionDict[key], " lcoal inversion(s)"

    print "got a packet"
    # pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    arrived_pkts = []
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
