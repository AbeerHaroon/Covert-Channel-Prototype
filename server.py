#! /usr/bin/env/python3

#module that will run a sniff for UDP packets via Scapy

import sys
import socket
import base64

from scapy.all import *

from Crypto.Cipher import AES
from Crypto.Util import *

PRIV_KEY_SIXTEEN = b'i\x99\xa94Q\xdcE\xa4\x9c\xf0\xc4\x95\x17um\x94'
IV_SIXTEEN = b'\xb6\xfeiW\x12[\xee\xa3q\x8d\xefZ\xc0\r\xcan'
PORT = 5000
PACKETNUM = 1

#file_output = open("output.txt", "w", encoding="ascii")

ip_mode = 0
e_mode = 0

def printHelp():
    print("usage (order matters)")
    print(" sudo python3 server.py [\"-i\" or \"-e\"] -p [port num]")
    print(" -p is optional. Default port is 5000. Must be stated as last argument")
    sys.exit(1)

if len(sys.argv) < 2:
    printHelp()
    sys.exit(1)

if "-i" in sys.argv[1]:
    ip_mode = 1
elif "-e" in sys.argv[1]:
    e_mode = 1
else:
    print("usage (order matters)")
    print(" sudo python3 server.py [\"-i\" or \"-e\"] -p [port num]")
    print(" -p is optional. Default port is 5000. Must be stated as last argument")
    sys.exit(1)

if "-p" in sys.argv:
    PORT = int(sys.argv[3])

def e_mode_handler(p):
    cipher = AES.new(key=PRIV_KEY_SIXTEEN, mode=AES.MODE_ECB)
    d = p[Raw].load #get bytes string object
    d1 = base64.b64decode(d)

    Padding.unpad(padded_data=d1,block_size=AES.block_size)
    #print(d.decode())
    #dec = Padding.unpad(cipher.decrypt(d),AES.block_size)
    decrypted = cipher.decrypt(d)
    s = decrypted.decode()
    f = open("output_aes.txt", "w")
    f.write(s)
    f.close()

def packet_handler(p):
    c = chr(p[IP].id)
    print(c)
    f = open("output.txt", "a", encoding="ascii")
    f.write(c)
    f.close()




#sniff(filter="udp and port 5000", prn=lambda pkt: data_read.append(chr(pkt[IP].id)))

if ip_mode == 1:
    sniff(filter=f"udp and port {PORT}", prn=lambda pkt: packet_handler(pkt))
elif e_mode == 1:
    sniff(filter=f"udp and port {PORT}",prn=lambda pkt: e_mode_handler(pkt))