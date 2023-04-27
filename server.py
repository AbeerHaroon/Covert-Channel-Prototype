#! /usr/bin/env/python3

#module that will run a sniff for UDP packets via Scapy

import sys
import socket

from scapy.all import *

PRIV_KEY_SIXTEEN = b'i\x99\xa94Q\xdcE\xa4\x9c\xf0\xc4\x95\x17um\x94'
IV_SIXTEEN = b'\xb6\xfeiW\x12[\xee\xa3q\x8d\xefZ\xc0\r\xcan'

#file_output = open("output.txt", "w", encoding="ascii")

def packet_handler(p):
    c = chr(p[IP].id)
    print(c)
    f = open("output.txt", "a", encoding="ascii")
    f.write(c)
    f.close()


#sniff(filter="udp and port 5000", prn=lambda pkt: data_read.append(chr(pkt[IP].id)))

sniff(filter="udp and port 5000", prn=lambda pkt: packet_handler(pkt))
