'''
Created on 15 Feb 2018
  
EE6032 - Communications & Security Protocols

Group   -   Kevin Burke     14155893
            Paul Lynch      16123778  
            Ciaran Carroll  13113259

Chat_Client.py

Usage:          >> python Chat_Client.py
                Note: Server script must be already running

Requirements:   Tested and working with Python 3.6
                tkinter GUI library
                NaCl cryptography library

This script implements a client for the secure chat application.
Threads are used to allow multiple clients to be run and to 
communicate with one another via the server.

The basic operation for message sending is as follow:
    - The send() function is called when the Send button in GUI 
      is pressed.
    - It takes the message, encrypts it using the session key and
      sends it via the socket to the server

In order to receive messages the following occurs:
    - The message is received via the client socket from the server
    - It is decrypted using the session key agreed with the server
    - The decrypted message is added to the message list on the GUI
'''

"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from tkinter.filedialog import askopenfilename
from diffiehellman2 import DiffieHellman
import tkinter
import sys
import nacl.utils
import nacl.secret


fileToSend=''


'''
receive() handles the receiving of messages on server-->client socket
operation:
            reads 1024 bytes at a time from the socket connected to the server
            splits each message away from the attached client name
            check each message to see if it starts with a file location
            if it does, open a new file and write contents to it
            else, write the message to the chat box in the GUI
'''
def receive():
    welcome = "Welcome %s , type {quit} at any time to exit" % NAME         #Welcome message to be sent at startup of a new client
    msg_list.insert(tkinter.END, bytes(welcome, "utf8"))                    
    insertName = "Please enter your username and press SEND"
    msg_list.insert(tkinter.END, bytes(insertName, "utf8"))
    while True:                                                             #Enter a loop in order to receive messages
        try:
            msg = client_socket.recv(BUFSIZ)                                #Save messages from socket in 1024 bytes
            try:
                clientname, message = msg.split(b" ", 1)                    #Parse buffer read to split client name from message
            except:
                message = msg                                               #If no client name exists
            
            '''
            if b'Welcome' in message:
                print("Got to if message statement..")
                msg_list.insert(tkinter.END, message)
                return
            
            if b'has joined the chat!' in message:
                print("Got to if has joined chat statement..")
                msg_list.insert(tkinter.END, message)
                return
            '''
            '''
            print("Trying to decrypt..:")
            print(message)
            print("Type of msg is:")
            print(type(msg))
            '''
            decryptedMessage = decryptor.decrypt(message)                   #Decrypt and save the message using session key
            '''
            print("This is the decrypted message: ")
            print(clientname+decryptedMessage)
            print("Decrypted using session key:")
            print(sessionKey)
            '''

            '''
            if b"---BEGIN PUBLIC KEY---" in msg:
                with open("serverPublicKey.pem", "wb") as f:
                    k=1
                    while True:
                        if k==1:
                            message = client_socket.recv(BUFSIZ)
                            f.write(message)
                            k=0
                        else:
                            f.close()
                            break
            '''
            '''
            if decryptedMessage.startswith(b"C:/"):                         #Message is a filepath, need to receive file.
                filepath, extension = decryptedMessage.split(b".")          #parse the message to get the file extension
                with open('received_file.' + str(extension, 'utf8'), 'wb') as f:
                    print('file opened')
                    while True:
                        data = client_socket.recv(BUFSIZ)
                        decryptedData = decryptor.decrypt(data)
            '''
            '''
                        if b"This is the start of the file" in data:
                            startofFile, startdata = decryptedData.split(b"This is the start of the file", 1)
                            f.write(startdata)
                        elif b"This is the end of the file" in data:
                            realdata, EndOfFile = decryptedData.split(b"This is the end of the file", 1)
                            f.write(realdata)
                            f.close()
                            break
                        elif not data:
                            f.close()
                            print('file close()')
                            break
                        else:
                            f.write(decryptedData)
            '''
            msg_list.insert(tkinter.END, clientname+decryptedMessage)       #Display decrypted message on GUI

        except OSError:  # Possibly client has left the chat.
            break



'''
send() handles sending of messages on client-->server socket
operation:
            fetches messages from input box and clears input box.
            sends message to server through socket
            checks if message is {quit}, which allows user to leave the chat
            checks if message starts with file location, if yes, it attempts
            to open the specified file.
            Contents are sent via socket to the server
            
            File contents are prepended with "This is the start of the file"
            and appended with "This is the end of the file" in order to act as
            beginning and ending markers.
'''  
def send(event=None):  # event is passed by binders.
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.


    ##This is where the message gets sent to the server for distribution
    ##Need to encrypt the message here and use client_socket.send() to 
    ##send the encrypted bytes to the server
    ##Note: socket.send() function only takes bytes as a parameter
    #print("Encrypting the plaintext: ")
    #print(msg)
    
    #print("The encrypted version is:")
    #print(encryptedMessage)
    
    if msg == "{quit}":
        client_socket.close()
        msg_frame.quit()
      
    if msg.startswith('C:/'):
        path = msg
        try:
            f = open(path,'rb')
            #startFile = encryptor.encrypt(bytes("This is the start of the file", "utf8"))
            #client_socket.send(startFile)
            while True:
                l = f.read(BUFSIZ)
                #encryptedL = encryptor.encrypt(l)
                while (l):                  
                    client_socket.send(l)
                    l = f.read(BUFSIZ)
                    #encryptedL = encryptor.encrypt(l)
                    if not l:
                        client_socket.send(b"This is the end of the file")
                        f.close()
                        break
        except IOError:
            msg="No such file or directory"
            msg_list.insert(tkinter.END, msg)
    else:
        encryptedMessage = encryptor.encrypt(bytes(msg, "utf8"))
        client_socket.send(encryptedMessage)
        print("ecnrypted message sent (should match with servers received version):")
        print(encryptedMessage)
        print("\n")
    
            
def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()
    root.destroy()
    sys.exit()


''' This is where we lauch the file manager bar. '''
def OpenFile():
    name = askopenfilename(initialdir="C:/Users",
                           filetypes =(("JPEG", "*.JPG"),("All Files","*.*")),
                           title = "Choose an attachment"
                           )
    #Using try in case user chooses unknown file or closes without choosing a file.
    try:
        fileToSend = name
        my_msg.set(fileToSend)
    except:
        print("No file exists")



''' Create tkinter root which will hold the GUI frames and components '''  
root=tkinter.Tk()
root.title("EE6032 Secure Chat Application")
root.geometry("600x500")
root.protocol("WM_DELETE_WINDOW", on_closing)
  
'''
**THIS SECTION CAN POSSIBLY BE IMPLEMENTED AT A LATER STAGE**
config_frame = tkinter.Frame(root, relief=tkinter.GROOVE, borderwidth=3)
config_frame.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=1)
tkinter.Label(config_frame, text="Your IP Address", relief=tkinter.GROOVE, width=25).grid(row=1,column=1)
tkinter.Label(config_frame, text="Status", relief=tkinter.GROOVE, width=25).grid(row=2,column=1)
tkinter.Label(config_frame, text="Port Number", relief=tkinter.GROOVE, width=25).grid(row=3,column=1)
#tkinter.Label(config_frame, textvariable=socket.gethostbyname(socket.gethostname()), relief=tkinter.GROOVE, width=25).grid(row=1,column=2)
'''
  
''' Create the message frame, which holds the list box of previous messages exchanged '''
msg_frame = tkinter.Frame(root, relief=tkinter.GROOVE, borderwidth=3)
msg_frame.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=1)
msg_frame.pack(padx=10, pady=10)
msg_frame.pack()

''' Create the text frame, which holds the message entry, encrypt checkbox
    and Send button '''
txt_frame = tkinter.Frame(root, relief=tkinter.GROOVE, borderwidth=1)
txt_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X, expand=1)
txt_frame.pack(padx=10, pady=0)
txt_frame.pack()

my_msg = tkinter.StringVar()                                                # For the messages to be sent.
my_msg.set("Type your messages here.")

                                                                            
scrollbar = tkinter.Scrollbar(msg_frame)                                    # X and Y Scrollbars config for the msg_frame 
scrollbar2 = tkinter.Scrollbar(msg_frame, orient=tkinter.HORIZONTAL)        # To navigate through past messages.

''' This listbox will contain the chat history, previous messages, files
    sent etc.  '''
msg_list = tkinter.Listbox(msg_frame, yscrollcommand=scrollbar.set, xscrollcommand=scrollbar2.set)

''' More scrollbar config '''
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
scrollbar.config(command=msg_list.yview)
scrollbar2.pack(side=tkinter.BOTTOM, fill=tkinter.X)
scrollbar2.config(command=msg_list.xview)

msg_list.pack(side=tkinter.BOTTOM, fill=tkinter.BOTH, pady=5, padx=5, expand=1)
msg_list.pack()
msg_frame.pack()
  
''' Entry field for inputting messages, variable gets read by send()
    Bind function attaches functionality for send() to be called when the
    return button is pressed   '''
entry_field = tkinter.Entry(txt_frame, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack(side=tkinter.LEFT, ipady=10, padx=10, fill=tkinter.X, expand=1)

''' Checkbox which turns encryption on and off. '''
encrypt_var=''
encrypt_button = tkinter.Checkbutton(txt_frame, text="Encrypt", variable=encrypt_var)
encrypt_button.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=10)

''' Simple button to add file. Calls OpenFile() which allows user to browse
    and select a file to send   '''
addButton = tkinter.Button(txt_frame, text="Add File", command=OpenFile)
addButton.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=5)

''' Send button which calls send() function  '''
send_button = tkinter.Button(txt_frame, text="Send", command=send, bg='#128C7E')
send_button.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=5)
  

HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000                                            #Make default port 33000
else:
    PORT = int(PORT)
NAME = input('Enter name: ')
BUFSIZ = 1024                                               #Standard Buffer Size of 1024 bytes for reading
ADDR = (HOST, PORT)                                         #Create a tuple of user inputted host and post

clientEntity = DiffieHellman()                              #New DiffieHellman() object for the client script
with open("clientPublicKey.bin", "wb") as f:                #Write the clients public key to a file
    f.write(bytes(str(clientEntity.publicKey), "utf8"))

serverPublicKey = open("serverPublicKey.bin").read()        #Read and store the servers public key from file
clientEntity.genKey(serverPublicKey)                        #Generate key for client using serverPublicKey
print("Client generated a sesssion key successfully..")
sessionKey = clientEntity.getKey()                          #Store session key
print(sessionKey)

encryptor = nacl.secret.SecretBox(sessionKey)               #Create instance of SecretBox for encryption
decryptor = nacl.secret.SecretBox(sessionKey)               #Instance for decryption (Can't use same instance for both)

client_socket = socket(AF_INET, SOCK_STREAM)                #Create a new socket on the specified host and port and connect
client_socket.connect(ADDR)

                                                           
receive_thread = Thread(target=receive)                     #Begin a new thread for this specific client
receive_thread.start()

tkinter.mainloop()                                          #This line starts up the tkinter GUI execution