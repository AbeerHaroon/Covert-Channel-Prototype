#standard python modules
import sys

#scapy and other libraries
from scapy.all import *
from Crypto.Util import *
#from Crypto.Cipher import AES

#user modules
import msgEncoder
import sessionKeyGen

dst_ip="192.168.1.83"
 
#first method
#id property in IP() packet can carry 16 bits according to RFC
#first method, insert encrypted information into the id property of IP() layer in a UDP packet
#packets are made IP()/UDP() thanks to scapy
sample_pkt = IP(id=ord("H"),dst=dst_ip)/UDP(dport=5000)
print(sample_pkt[IP].id, "port: ",sample_pkt[UDP].dport)
send(sample_pkt)

#2nd method
#client sends IP/UDP packet to bounce server
#bounce server sends to main server (who is expecting message from bounce server)
#whatever information bounce server gets back, let it udp it to client probe


