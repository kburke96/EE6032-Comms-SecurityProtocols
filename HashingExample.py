'''
Created on 27 Feb 2018

@author: Kevin

Adapted from tutorial available online:
https://www.blog.pythonlibrary.org/2016/05/18/python-3-an-intro-to-encryption/

'''

import hashlib, base64


##Create a simple SHA-1 Hash of a sentence and print the result
teststring = b"This is a simple test string of bytes"
print("**The string to be hashed is: \n" + str(teststring))

#create a new instance of sha1 object from haslib
sha1 = hashlib.sha1()
#pass sha1 the bytes of test string to be hashed
sha1.update(teststring)
print("\nSHA-1 Result of hashing the string (hexadecimal format): ")
print(sha1.hexdigest())

#create a new instance of the sha256 object from hashlib
sha256 = hashlib.sha256()
#pass the bytes to be hashed to the object instance
sha256.update(teststring)
print("\nSHA-256 Result of hashing the string (hexadecimal format): ")
print(sha256.hexdigest())