'''
Created on 3 Mar 2018

@author: Kevin
'''
from Crypto.Cipher import AES
import os
import hashlib

#read the AES secret key from the file already created
try:
    with open("AESkey.bin", "rb") as f:
        print("Reading the AES secret key from file..")
        key = f.read()
except:
    print("Error reading key from file")
    exit()

#read triple from the ciphertext file
try:
    with open("cipher_file.bin", "rb") as f:
        print("\nObtaining the [nonce,tag,ciphertext] triple from the file..\n..")
        nonce, tag, ciphertext = [ f.read(x) for x in (16, 16, -1) ]
except:
    print("Error reading the [nonce,tag,ciphertext] triple from the file")
    exit()

'''
create an instance of AES object in order to decrypt the ciphertext
key:
    use the key read from the file above in this instantiation
mode:
    same mode as was used to encrypt
'''
print("Creating a new AES object with the secret key for decryption..\n..")
decryption = AES.new(key, AES.MODE_EAX, nonce)

'''
    decrypt the ciphertext and assign to 'data' variable
    use the tag in order to verify the decryption
'''
try:
    data = decryption.decrypt_and_verify(ciphertext, tag)
    print("\nDecryption successful! \n")
    print("Decrypted data: \n" + data)
except:
    print("\nDecrpytion failed at line 43")
    exit()

