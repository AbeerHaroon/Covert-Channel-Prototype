#module to generate a key using PyCryptoDome
#use the output as a constant for programs

import time
import base64
import Crypto.Random



def genKey() :
    #Crypto.Cipher.AES = uses 128 bit data block
    #ret = Random.random.getrandbits(128) #128 bit key (16 bytes)
    retMain = Crypto.Random.get_random_bytes(16) #returns byte string
    return retMain

def main():
    generated = genKey()
    now = time.gmtime()
    print("Generating a Cryptographically secure key...")
    print("random key: ", generated, 
    "\ngenerated at: \n","year: ", now.tm_year,"\nmonth: ", now.tm_mon,"\nday: ", now.tm_mday,
    "\nhour", now.tm_hour,"\n minute: ",now.tm_min, "\nseconds: ",now.tm_sec)

if __name__ == '__main__':
    main()