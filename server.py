#module that will run a sniff for UDP packets via Scapy

import sys
import socket
from scapy.all import *

PRIV_KEY_SIXTEEN = b'i\x99\xa94Q\xdcE\xa4\x9c\xf0\xc4\x95\x17um\x94'
IV_SIXTEEN = b'\xb6\xfeiW\x12[\xee\xa3q\x8d\xefZ\xc0\r\xcan'

def packet_handler(pkt):
    print(pkt.IP().id)

sniff(filter="udp and port 5000", prn=lambda pkt: print(pkt[IP].id))

