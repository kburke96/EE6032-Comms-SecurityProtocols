"""
Created on Sat Mar 03 17:27:37 2018

@author: Kevin
"""

from Crypto.PublicKey import RSA

secret_code = "Unguessable"
key = RSA.generate(2048)
encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

file_out = open("rsa_key.bin", "wb")
file_out.write(encrypted_key)

print(key.publickey().exportKey())
print("\n\n")

print(key.exportKey())
