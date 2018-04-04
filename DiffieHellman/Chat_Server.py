'''
Created on 15 Feb 2018
EE6032 - Communications & Security Protocols

Group   -   Kevin Burke     14155893
            Paul Lynch      16123778  
            Ciaran Carroll  13113259

Chat_Server.py

Usage:          >> python Chat_Server.py

Requirements:   Tested and working on Python 3.6
                NaCl Cryptography Library

This script implements a server for the secure chat application.
Threading is used to allow multiple clients to connect to this
server. Each client is started in a new thread. 
By default, the server runs on LOCALHOST on port 33000.

The basic operation of the server for chat messages is as follows:
    - Server receives an encrypted message from one of its clients
    - It decrypts this message using the session key for that client
    - In order to broadcast the decrypted message, it must encrypt 
      it with the appropriate session key and send it to all clients
'''


"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from diffiehellman2 import DiffieHellman
import nacl.utils
import nacl.secret


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
        #client.send(bytes("Please type your name and press enter!", "utf8"))
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
    try:
        clientPublicKey = open("clientPublicKey.bin").read() #Read clients session key
        print("Client public key read successfully..")
    except Exception as e:
        print("Failed to read client public key..")
        print(e)
    sessionKey=''
    try:
        serverEntity.genKey(clientPublicKey)            #Generate a session key using clients public key
        #print("Server generated a session key for this client successfully..")
        sessionKey = serverEntity.getKey()              #Save session key for this client
        print(sessionKey)
        #print(len(sessionKey))
    except Exception as e:
        print("Failed to generate session key..")
        print(e)
    decryptor = nacl.secret.SecretBox(sessionKey)       #Create an instance of SecretBox for decryption
    name = client.recv(BUFSIZ)                          #First message received is stored as name
    decryptedname= decryptor.decrypt(name)              #Decrypt using decryptor object
    says = " said:".encode("ascii")
    decryptednamestr= decryptedname+says
    clients.append((client,sessionKey))
    isFile=False

    while True:
        msg = client.recv(BUFSIZ)                       #Receive encrypted message from client via socket
        decryptedMessage = decryptor.decrypt(msg)       #Decrypt message, store in variable

        if b"This is the start of the file" in decryptedMessage:
            isFile = True
            
        if b"This is the end of the file" in decryptedMessage:
            isFile = False

        if isFile:
            broadcast(msg, "")                          #Message broadcast w/o Client Name
        else:
            if (isFile==False) and (msg != bytes("{quit}", "utf8")):
                #broadcast(decryptednamestr)   #Message broadcast w/ Client Name
                #print("Broadcasting message for " + decryptedname.decode("utf8"))
                #print("The encrypted message is: ")
                #print(msg)
                #print("The msg (encrypted) is:")
                #print(msg)
                #print("The decrypted message is:")
                #print(decryptedMessage)
                broadcast(decryptedMessage, decryptedname.decode("utf8")+": ")  #Send decrypted message and
                                                                                #name to broadcast()
            elif msg==bytes("{quit}", "utf8"):          #If message is {quit}, leave the chat
                client.close()
                del clients[client]
                broadcast(bytes("%s has left the chat." % decryptedname, "utf8"))
                break
            else:
                break

'''
broadcast() sends a message from server-->client sockets

arguments:
    msg    - The message to be sent out to clients
    prefix - Client Name to be prepended to msg

operation:
    Broadcast iterates through all clients currently connected
    i.e Those in the clients[] list.
    It encrypts the message passed to the function using the
    session key associated with each client socket.
    Then sends the encrypted message over the specified socket
    to the client.
'''
def broadcast(msg, prefix=""):
    for (sock,key) in clients:                          #Use client list to get socket and session key
        #print("This is iteration number: ")
        #print(iteration)
        #print("This is the sock,key tuple:")
        #print(sock,key)
        #print("Sending this message through the socket:")
        #print(sock)
        #print("using session key to encrypt: ")
        #print(key)
        #print("The unencrypted version is:")
        #print(msg)
        encryptor = nacl.secret.SecretBox(key)          #Create an instance of SecretBox for encryption
        encryptedMessage = encryptor.encrypt(msg)       #Encrypt the message passed to broadcast()
        #print("encrypted message being sent from server to client is:")
        #print(encryptedMessage)
        #sock.send(bytes(prefix, "utf8"))
        sock.send(bytes(prefix, "utf8") + encryptedMessage) #Send the encrypted message to client via socket
      
clients = []                                            #This list holds tuples of (clientSocket, sessionKey)
addresses = {}                                          #Holds client addresses

HOST = ''                                               #Default host: localhost
PORT = 33000                                            #Default port: 33000
BUFSIZ = 1024                                           #1024 bytes for receiving messages through socket
ADDR = (HOST, PORT)                                     #Create a tuple of host and port to run server on

serverEntity = DiffieHellman()                          #Create a new DiffieHellman() object for the server

with open("serverPublicKey.bin", "wb") as f:            #Write the server's public key to a file
    f.write(bytes(str(serverEntity.publicKey), "utf8"))


SERVER = socket(AF_INET, SOCK_STREAM)                   #Create a new server socket
SERVER.bind(ADDR)                                       #Bind the new server socket to defined host and port tuple

if __name__ == "__main__":
    SERVER.listen(5)                                    #Server will accept up to 5 connections
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
                                                        #Create a new thread and run the function to accept clients
    ACCEPT_THREAD.start()                               #Start the new thread
    ACCEPT_THREAD.join()                                #Block operation until thread terminates
SERVER.close()                                          #Close the server socket