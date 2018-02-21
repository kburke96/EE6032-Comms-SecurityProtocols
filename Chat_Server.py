'''
Created on 15 Feb 2018

@author: Kevin
'''


"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Please type your name and press enter!", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""

    name = client.recv(BUFSIZ).decode("utf8")
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    client.send(bytes(welcome, "utf8"))
    msg = "%s has joined the chat!" % name
    broadcast(bytes(msg, "utf8"))
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ)
        if msg != bytes("{quit}", "utf8"):
            broadcast(msg, name+": ")
        else:
            client.send(bytes("{quit}", "utf8"))
            client.close()
            del clients[client]
            broadcast(bytes("%s has left the chat." % name, "utf8"))
            break


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""

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
    SERVER.close()                      #Close the server socket 