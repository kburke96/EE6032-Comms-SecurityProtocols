'''
Created on 15 Feb 2018
@author: Kevin
'''


"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto import Random
import os

# -*- coding: utf-8 -*-
'''
accept_incoming_connection() sets up handling for incoming clients

inputs:
    none
    
operation:
    accepts the clients requesting to connect via the server socket
    gets client name, adds to array of clients and starts a new thread,
    Threads then runs the handle_client() method
'''
def accept_incoming_connections():
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Please type your name and press enter!", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()



'''
handle_client() takes care of each individual client connections

arguments:
    client  - The single client socket to be handled

operation:
    General client setup tasks, inserts client name into chat.
    Handles the receiving of messages on client-->server socket and the
    distribution of the message to all connected clients on the server--> client
    sockets
    
    Also checks for the start and end of file markers. These trigger isFile 
    variable. If true, the message is broadcast without the client name prepended,
    else the client name is appended to the message and subsequently added to
    the chat history (this is done in receive() in Chat_Client.py)
'''
def handle_client(client): 
    name = client.recv(BUFSIZ).decode("utf8")
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    client.send(bytes(welcome, "utf8"))
    msg = "%s has joined the chat!" % name
    broadcast(bytes(msg, "utf8"))
    clients[client] = name
    isFile=False
    isSetup=False
    try:
        print("Server sending its public key to client..")
        with open("rsa_publickey.bin", "rb") as f:
            while True:
                data = f.read(BUFSIZ)
                client.send(data)
                if not data:
                    f.close()
                    break
    except:
        print("Error opening or sending the server's public key..")

    while True:
        msg = client.recv(BUFSIZ)
        
        if b"This is the start of the file" in msg:
            isFile = True
            
        if b"This is the end of the file" in msg:
            #broadcast(msg, "")              #Message broadcast w/o Client Name
            isFile = False
            #break

        if b"---BEGIN PUBLIC KEY" in msg:
            isSetup=True
            with open("publickey_" + name + ".bin", "wb") as f:
                f.write(msg)
            

        if msg.startswith(b"***Protocol beginning now ***"):
            isSetup=True
            try:
                #open the client public key file here
                clientPublicKey = RSA.import_key(open("publickey_"+name+".bin").read())
            except Exception as e:
                print("Failed to open the Client's public key file")
                print(e)

            encryptedMessage = client.recv(1024)
            #unencrypt the message
            decryptAndVerify(encryptedMessage, name)
        
        if isSetup==True:
            break

        if isFile:
            broadcast(msg, "")              #Message broadcast w/o Client Name
        else:
            if (isFile==False) and (msg != bytes("{quit}", "utf8")):
                broadcast(msg, name+": ")   #Message broadcast w/ Client Name
            elif msg==bytes("{quit}", "utf8"):
                client.close()
                del clients[client]
                broadcast(bytes("%s has left the chat." % name, "utf8"))
                break
            else:
                break




def sendPublicKey(pathToKeyFile, client):
    if pathToKeyFile.startswith(b'C:\\'):
        path = pathToKeyFile
        try:
            f = open(path,'rb')
            while True:
                l = f.read(BUFSIZ)             
                client.send(l)
                if not l:
                    f.close()
                    break
        except IOError:
            msg="No such file or directory"
            msg_list.insert(tkinter.END, msg)

'''
decryptAndVerify() handles the message received from client which has been encrypted with
server's public key.

arguments:
            encryptedMessage - this is the message received from client which has been encrypted
                               with server's public key

            name             - the name of the client being communicated with (needed in order to
                               open public key file)

operation:
            1 - Open the server's private key and save to variable
            2 - Instantiate a new RSA object for decrpytion with server's private key
            3 - Decrypt the message
            4 - Take PassA from message (first 16 bytes)
            5 - Open Client's public key
            6 - Hash PassA using SHA256
            7 - Verify the Hash of PassA against the signed portion of the decrypted message
'''
def decryptAndVerify(encryptedMessage, name):
    name=name
    try:
        serverPrivateKey = RSA.import_key(open("rsa_privatekey.der").read(), passphrase=RSAPassphrase)
        print("Own private key read successfully")
    except:
        print("Error reading own private key..")
    
    try:
        rsa_privatedecryptor = PKCS1_OAEP.new(serverPrivateKey)
        print("Decryptor object created with own private Key")
    except:
        print("Error creating the decryptor object with own private key")
    try:
        decrypted = rsa_privatedecryptor.decrypt(encryptedMessage)
        print("Data succesfully decrypted")
        #print("Decrypted data: \n\n" + decrypted.decode())
    except Exception as e:
        print("Error decrypting the encrypted message")
        print(e)
    
    try:
        passA = decrypted[:16]
    except:
        print("Error splitting up decrypted data")
    try:
        signedAndHashed = decrypted[16:]
    except:
        print("Error getting signed and hashed part of decrypted message")
    
    clientPublicKey = RSA.import_key(open("publickey_"+name+".bin").read())
    hash = SHA256.new(passA)
    try:
        pkcs1_15.new(clientPublicKey).verify(hash, signedAndHashed)
        print("Data successfully verified")
    except (ValueError, TypeError):
        print("Error verifying data")




'''
broadcast() sends a message from server-->client sockets

arguments:
    msg    - The message to be sent out to clients
    
    prefix - Client Name to be prepended to msg
'''
def broadcast(msg, prefix=""):
    for sock in clients:
        sock.send(bytes(prefix, "utf8")+msg)
        

def generateKeys():
    key = RSA.generate(4096)
    private_key = key.exportKey(passphrase=RSAPassphrase, pkcs=8, protection="scryptAndAES128-CBC")
    try:
        file_out = open("rsa_privatekey.der", "wb")
        file_out.write(private_key)
        file_out2 = open("rsa_publickey.bin", "wb")
        file_out2.write(key.publickey().exportKey())
        #client_socket.send(b"RSA Keypair generated")
    except:
        print("Error writing keypair to file")
    

clients = {}
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)                     #Create a tuple of host and port to run server on

RSAPassphrase = os.urandom(32)

SERVER = socket(AF_INET, SOCK_STREAM)   #Create a new server socket
SERVER.bind(ADDR)                       #Bind the new server socket to defined host and port tuple

if __name__ == "__main__":
    generateKeys()
    SERVER.listen(5)                    #Server will accept up to 5 connections
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
                                        #Create a new thread and run the function to accept clients
    ACCEPT_THREAD.start()               #Start the new thread
    ACCEPT_THREAD.join()                #Block operation until thread terminates
SERVER.close() #Close the server socket