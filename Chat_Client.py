'''
Created on 15 Feb 2018
  
@author: Kevin
'''

"""Script for Tkinter GUI chat client."""

# -*- coding: utf-8 -*-
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import sys
from tkinter.filedialog import askopenfilename
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
from Crypto.PublicKey import RSA
import hashlib, base64

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
    generateKeys()
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)#.decode("utf8")
             
            '''parse each read from buffer to split message and client name'''
            clientname, message = msg.split(b" ", 1)
            #filepath=''
            
            if b"---BEGIN PUBLIC KEY---" in msg:
                with open("serverPublicKey.pem", "wb") as f:
                    k=1
                    while True:
                        if k==1:
                            f.write(message)
                            k=0
                        else:
                            f.close()
                            break
      

            if message.startswith(b"C:/"):
                ''' parse the message to get the file extension '''
                filepath, extension = message.split(b".")
                with open('received_file.' + str(extension, 'utf8'), 'wb') as f:
                    print('file opened')
                    while True:
                        data = client_socket.recv(BUFSIZ)
                        '''
                        need to check whether the designated start and end of file placeholders
                        are present.
                        If so, they need to be removed before the data is written 
                        to the file
                        '''
                        if b"This is the start of the file" in data:
                            startofFile, startdata = data.split(b"This is the start of the file", 1)
                            f.write(startdata)
                        elif b"This is the end of the file" in data:
                            realdata, EndOfFile = data.split(b"This is the end of the file", 1)
                            f.write(realdata)
                            f.close()
                            break
                        elif not data:
                            f.close()
                            print('file close()')
                            break
                        else:
                            f.write(data)
                
             
            msg_list.insert(tkinter.END, msg)

        except OSError:  # Possibly client has left the chat.
            break


'''
def receivePublicKey(pathReceived):
    #filepath, extension = pathReceived.split(b".")
    with open("otherPublicKey" + USERNAME +".bin", 'wb') as f:
        print("Key file opened")
        while True:
            data = client_socket.recv(BUFSIZ)
            if b"-----END PUBLIC KEY-----" in data:
                print("Gets to the end public key if statement")
                f.write(data)
                f.close()
                break
            else:
                f.write(data)
'''     


    

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
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        msg_frame.quit()
    '''
    if encrypt_var == 1:
        encrypt(msg)
    '''   
    if msg.startswith('C:/'):
        path = msg
        try:
            f = open(path,'rb')
            client_socket.send(b"This is the start of the file")
            while True:
                l = f.read(BUFSIZ)
                while (l):                  
                    client_socket.send(l)
                    l = f.read(BUFSIZ)
                    if not l:
                        client_socket.send(b"This is the end of the file")
                        f.close()
                        break
        except IOError:
            msg="No such file or directory"
            msg_list.insert(tkinter.END, msg)

def sendPublicKey(pathToKeyFile):
    if pathToKeyFile.startswith(b'C:\\'):
        path = pathToKeyFile
        try:
            f = open(path,'rb')
            while True:
                l = f.read(BUFSIZ)             
                client_socket.send(l)
                if not l:
                    f.close()
                    break
        except IOError:
            msg="No such file or directory"
            msg_list.insert(tkinter.END, msg)
    
    generateSessionKey()

def generateSessionKey():
    serverPublicKey = RSA.import_key(open("serverPublicKey.pem").read())
    clientPrivateKey = RSA.import_key(open("rsa_privatekey.der").read(), passphrase=RSAPassphrase)
    rsa_publicencryptor = PKCS1_OAEP.new(serverPublicKey)                     #instantiate the encryption object using the receivers (servers) public key
    #Create hash of randomPassA
    #Sign hash with own private key
    #Append signed hash to randomPassA and encrypt with servers public
    #send encrypted version to server
    hashedPassA = SHA256.new(randomPassA)                                   #create a hash of passA -> INTEGRITY
    signedHashedPassA = pkcs1_15.new(clientPrivateKey).sign(hashedPassA)    #sign the hash with own (clients) private key -> DIGITAL SIGNATURE 
    client_socket.send(b"***Protocol beginning now ***")
    appendedMessage = randomPassA + signedHashedPassA
    try:
        encryptedMessage = rsa_publicencryptor.encrypt(appendedMessage)
        print("Message successfully encrypted with servers public key..\n")
        client_socket.send(encryptedMessage)
    except Exception as e:
        print("Encryption with servers public key failed..")
        print(e)



def encryptButtonFunction():
    sendPublicKey(os.path.dirname(os.path.abspath(__file__)).encode() + b"\\rsa_publickey.bin")

            
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
    #Using try in case user types in unknown file or closes without choosing a file.
    try:
        fileToSend = name
        my_msg.set(fileToSend)
    except:
        print("No file exists")

def generateKeys():    
    key = RSA.generate(2048)
    private_key = key.exportKey(passphrase=RSAPassphrase, pkcs=8, protection="scryptAndAES128-CBC")
    try:
        file_out = open("rsa_privatekey.der", "wb")
        file_out.write(private_key)
        file_out2 = open("rsa_publickey.bin", "wb")
        file_out2.write(key.publickey().exportKey())
    except:
        print("Error writing keypair to file")

'''
def encrypt(message):
    data = message
    ciphertext, tag = encryption.encrypt_and_digest(data)
    for x in (nonce, tag, ciphertext):
        client_socket.send(x)
'''
'''
def sendPublicKey():
    #Need to send public key file here
    #open it first using OpenFile (?)
    #then send automatically
    #pathToPublicKey = os.path.dirname(os.path.abspath(__file__)).encode() + "\rsa_publickey.bin"
    client_socket.send(b"C:/Users/Kevin/Desktop/OriginalWeek7Files/rsa_publickey.bin")
'''

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

my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")

''' X and Y Scrollbars config for the msg_frame '''
scrollbar = tkinter.Scrollbar(msg_frame)  # To navigate through past messages.
scrollbar2 = tkinter.Scrollbar(msg_frame, orient=tkinter.HORIZONTAL)

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
encrypt_var= tkinter.IntVar()
encrypt_button = tkinter.Checkbutton(txt_frame, text="Encrypt", variable=encrypt_var, onvalue=1, offvalue=0, command=encryptButtonFunction)
encrypt_button.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=10)

''' Simple button to add file. Calls OpenFile() which allows user to browse
    and select a file to send   '''
addButton = tkinter.Button(txt_frame, text="Add File", command=OpenFile)
addButton.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=5)

''' Send button which calls send() function  '''
send_button = tkinter.Button(txt_frame, text="Send", command=send, bg='#128C7E')
send_button.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=5)
  
  
#----Now comes the sockets part----
HOST = input('Enter host: ')
PORT = input('Enter port: ')
USERNAME = input('Enter username: ')
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

''' Standard Buffer Size of 1024 bytes for reading '''
BUFSIZ = 1024
''' Create a tuple of user inputted host and post '''
ADDR = (HOST, PORT)

RSAPassphrase = os.urandom(32)
randomPassA = get_random_bytes(16)


''' Create a new socket on the specified host and port and connect '''
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

''' Begin a new thread for this specific client '''
receive_thread = Thread(target=receive)
receive_thread.start()

''' This line starts up the tkinter GUI execution '''
tkinter.mainloop()