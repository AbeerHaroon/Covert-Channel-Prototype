#module to process a text file. One character at a time
#Applies a crypto function on the message
#ONLY WORKS ON ASCII Characters

import sys
import io
import codecs
import base64 
from Crypto.Cipher import AES
from Crypto.Util import Padding

PRIV_KEY_SIXTEEN = b'i\x99\xa94Q\xdcE\xa4\x9c\xf0\xc4\x95\x17um\x94'
IV_SIXTEEN = b'\xb6\xfeiW\x12[\xee\xa3q\x8d\xefZ\xc0\r\xcan'
FILENAME = "msg.txt" #file name which contains our plain text

def readAll():
    with open(FILENAME,"r",encoding="ascii") as f:
        d = f.read()
        return d

def encryptFull(str_msg):    
    cipher = AES.new(key=PRIV_KEY_SIXTEEN, mode=AES.MODE_ECB)
    msgBytes = str_msg.encode()
    encrypted = cipher.encrypt(Padding.pad(msgBytes,AES.block_size)) 
    return encrypted #return byte string

#returns list of string
def readFile():
    char_list = []
    f = open(FILENAME, "r",  encoding="ascii") #sticking with single byte characters for now
    reading = 1
    while reading == 1:
        try:
            read_char = f.read(1) #read 1 byte
            if not read_char: #end of file
                f.close()
                reading = 0
            else:
                char_list.append(read_char)
        except IOError:
            print("perhaps file contains non ASCII characters")
            sys.exit()
#   
    if f.closed is False:
        f.close() #close file stream if file not flosed properly
#
    return char_list #return str

#parameter is a lsit of strings read from ascii encoding
#the list itself is just single characters in each index
#return list of byte objects
def strToBytes(paramStrList):
    byte_char = []
    for s in paramStrList :
        char_byte = s.encode()
        byte_char.append(char_byte)
#
    return byte_char


# function that will return a list.
# each index corresponds to plaintext list that is the parameter
# using Crypto.Cipher.AES = uses 128 bit data block
# ID field in IP datagram header is 16 bits (2 bytes)
def encryptMessage(paramByteList):
    cipher = AES.new(key=PRIV_KEY_SIXTEEN, mode=AES.MODE_CBC, iv=IV_SIXTEEN)
    cipherList = []
    for b in paramByteList:
        encrypted = cipher.encrypt(Padding.pad(b,AES.block_size)) #have to check for bugs here
        cipherList.append(encrypted)
    return cipherList

#main function of this module
#return the cipher text as a list
def getCipher_individual():
    plainText = readFile() #list of strings
    plain_bytes = strToBytes(plainText)
    cipherText = encryptMessage(plain_bytes)
    return cipherText

#driver function to test functions
def main():
    s2 = base64.b64encode(PRIV_KEY_SIXTEEN).decode()
    s = codecs.encode(PRIV_KEY_SIXTEEN,encoding="hex")
    print("output from pyCryptodome get_random_bytes: ", PRIV_KEY_SIXTEEN)
    print("codecs module: ", s)
    print("base64 module: ", s2)
    print("codecs module after decode(): ",s.decode())

    plainText = readFile() #lsit of strings
    print("PlainText: ", plainText)
    plain_bytes = strToBytes(plainText)
    cipherText = encryptMessage(plain_bytes)
    i = 0
    while i < len(cipherText):
        print("Plaintext: ", plainText[i])
        print("Ciphertext: ", cipherText[i])
        i = i + 1

if __name__ == "__main__":
    main()