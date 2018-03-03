'''
Created on 3 Mar 2018

@author: Kevin
'''
from Crypto.Cipher import AES
import os

data = b'This is some sample data which is to be encrypted by Entity 1 and read by Entity 2'

#generate a new secret key 32 bytes long
print('Generating a new 32-byte secret key..')
try:
    key = os.urandom(32)
    print('\n\nSecret Key succesfully generated')
except:
    print("\n\nCouldn't generate a secret key")
    exit()
    

print("\nWriting the secret key to a file..")
try:
    with open("AESkey.bin", "wb") as f:
        f.write(key)
except:
    print("\n\nError opening or writing key to file")
    exit()
    

'''
create a new instance of AES object for encryption

input params:-

key:
    this is the unique secret key generated above using urandom()
    
mode:
    specifies the mode for AES Encryption 
    EAX mode achieves privacy and autentication
'''
encryption = AES.new(key, AES.MODE_EAX)

#nonce required in EAX mode
nonce = encryption.nonce

#encrypt the data and assign to ciphertext and tag variables.
ciphertext, tag = encryption.encrypt_and_digest(data)

#write the nonce,tag,ciphertext triple to a file
try:
    with open("cipher_file.bin", "wb") as f:
        for x in (nonce, tag, ciphertext):
            f.write(x)
except:
    print("Error writing [nonce,tag,ciphertext] triple to file")
    exit()
 