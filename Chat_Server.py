'''
Created on 15 Feb 2018
@author: Kevin
'''


"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread



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
                broadcast(msg, name+": ")   #Message broadcast w/ Client Name
            elif msg==bytes("{quit}", "utf8"):
                client.close()
                del clients[client]
                broadcast(bytes("%s has left the chat." % name, "utf8"))
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
    for sock in clients:
        sock.send(bytes(prefix, "utf8")+msg)
        

        
clients = {}
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)                     #Create a tuple of host and port to run server on

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