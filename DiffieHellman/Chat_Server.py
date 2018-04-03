'''
Created on 15 Feb 2018
@author: Kevin
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
    try:
        clientPublicKey = open("clientPublicKey.bin").read()
        print("Client public key read successfully..")
    except Exception as e:
        print("Failed to read client public key..")
        print(e)
    sessionKey=''
    try:
        serverEntity.genKey(clientPublicKey)
        print("Server generated a session key for this client successfully..")
        sessionKey = serverEntity.getKey()
        print(sessionKey)
        #print(len(sessionKey))
    except Exception as e:
        print("Failed to generate session key..")
        print(e)
    decryptor = nacl.secret.SecretBox(sessionKey) 
    name = client.recv(BUFSIZ)#.decode("utf8")

    decryptedname= decryptor.decrypt(name)
    says = " said:".encode("ascii")
    decryptednamestr= decryptedname+says
    #welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    #client.send(bytes(welcome, "utf8"))
    #msg = "%s has joined the chat!" % name
    #broadcast(bytes(msg, "utf8"))
    clients.append((client,sessionKey))

    isFile=False

    while True:
        msg = client.recv(BUFSIZ)
        
        if b"This is the start of the file" in msg:
            isFile = True
            
        if b"This is the end of the file" in msg:
            #broadcast(msg, "")              #Message broadcast w/o Client Name
            isFile = False
            #break

        if isFile:
            broadcast(msg, "")              #Message broadcast w/o Client Name
        else:
            if (isFile==False) and (msg != bytes("{quit}", "utf8")):

              #  broadcast(decryptednamestr)   #Message broadcast w/ Client Name
               # print("Broadcasting message for " + decryptedname.decode("utf8"))
                print("The encrypted message is: ")
                print(msg)
                decryptedMessage = decryptor.decrypt(msg)
                #print("The msg (encrypted) is:")
                #print(msg)
                print("The decrypted message is:")
                print(decryptedMessage)
                broadcast(decryptedMessage, decryptedname.decode("utf8")+": ")
            elif msg==bytes("{quit}", "utf8"):
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
'''
def broadcast(msg, prefix=""):
    iteration = 0
    for (sock,key) in clients: 
        iteration = iteration + 1
        print("This is iteration number: ")
        print(iteration)
        #print("This is the sock,key tuple:")
        #print(sock,key)
        print("Sending this message through the socket:")
        print(sock)
        print("using session key to encrypt: ")
        print(key)
        print("The unencrypted version is:")
        print(msg)
        encryptor = nacl.secret.SecretBox(key)
        encryptedMessage = encryptor.encrypt(msg)
        print("encrypted message being sent from server to client is:")
        print(encryptedMessage)
        #sock.send(bytes(prefix, "utf8"))
        sock.send(bytes(prefix, "utf8") + encryptedMessage)
      #  sock.send(encryptedMessage)
      
clients = []
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)                     #Create a tuple of host and port to run server on

serverEntity = DiffieHellman()
#print(serverEntity.publicKey)
with open("serverPublicKey.bin", "wb") as f:
    f.write(bytes(str(serverEntity.publicKey), "utf8"))
#enter = input("Press Enter to continue...")
'''
clientPublicKey = open("clientPublicKey.bin").read()
try:
    serverEntity.genKey(clientPublicKey)
    print("Server generated a sesssion key successfully..")
    sessionKey = serverEntity.getKey()
    print(sessionKey)
except Exception as e:
    print("Failed to generate session key..")
    print(e)
'''
SERVER = socket(AF_INET, SOCK_STREAM)   #Create a new server socket
SERVER.bind(ADDR)                       #Bind the new server socket to defined host and port tuple

if __name__ == "__main__":
    SERVER.listen(5)                    #Server will accept up to 5 connections
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
                                        #Create a new thread and run the function to accept clients
    ACCEPT_THREAD.start()               #Start the new thread
    ACCEPT_THREAD.join()                #Block operation until thread terminates
SERVER.close() #Close the server socket