#! /usr/bin/python3

import socket

#scapy and other libraries
from scapy.all import *

THIS_PC_NAME = socket.gethostname()
THIS_IP = socket.gethostbyname(THIS_PC_NAME) #ipv4 address type

#return the last number from ipv4 adress 
def thisMachine():
    ip_str = str(THIS_IP)
    lastDot = ip_str.rfind(".") #return index of last occurrence of dot
    lastNum = ip_str[(lastDot+1):len(ip_str)] #string format
    return lastNum


