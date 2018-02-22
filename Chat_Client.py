'''
Created on 15 Feb 2018
  
@author: Kevin
'''
 
 
  
"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import sys
  
def receive():
    """Handles receiving of messages."""
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)#.decode("utf8")
             
            ##might need some kind of parsing around here?
            ##split the message away from the client name
            ##then check if the message starts with "."
            ##if yes, do all the stuff below
            ##if no, put the client and msg parts back together and insert
            clientname, message = msg.split(b" ", 1)
            
            ##need to identify some kind of end of file operator and stop
            ##writing to file when this is seen by the receeive() method.
            
            ##also need to remove client name from the start of every message
            ##this is what is corrupting the image
             
            if message.startswith(b"."):
                ##msg_list.insert(tkinter.END, "TST MESSAGE")
                with open('received_file', 'wb') as f:
                    print('file opened')
                    while True:
                        #print('receiving data...')
                        data = client_socket.recv(BUFSIZ)
                        if b"This is the start of the file" in data:
                            startofFile, startdata = data.split(b"This is the start of the file", 1)
                            f.write(startdata)
                        #print('data=%s', (data))
                        if b"This is the end of the file" in data:
                            realdata, EndOfFile = data.split(b"This is the end of the file", 1)
                            f.write(realdata)
                            f.close()
                            break
                        if not data:
                            f.close()
                            print('file close()')
                            break
                        # write data to a file
                        f.write(data)
             
            msg_list.insert(tkinter.END, msg)
            '''
            if msg.startswith(b"."):
                msg_list.insert(tkinter.END, "If loop is successful")
                with open('received_file', 'wb') as f:
                    print('file opened')
                    while True:
                        #print('receiving data...')
                        data = client_socket.recv(BUFSIZ)
                        #print('data=%s', (data))
                        if not data:
                            f.close()
                            print('file close()')
                            break
                        # write data to a file
                        f.write(data)
            '''
        except OSError:  # Possibly client has left the chat.
            break
  
  
def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        msg_frame.quit()
      
    if msg.startswith("."):
        sign, path = msg.split(".", 1)
        try:
            f = open(path,'rb')
            client_socket.send(b"This is the start of the file")
            while True:
                l = f.read(BUFSIZ)
                while (l):                  
                    client_socket.send(l)
                    ##print('Sent ',l)
                    l = f.read(BUFSIZ)
                    if not l:
                        #Test to see if it puts this at the end of the file
                        client_socket.send(b"This is the end of the file")
                        f.close()
                        break
        except IOError:
            msg="No such file or directory"
            msg_list.insert(tkinter.END, msg)
  
def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()
    root.destroy()
    sys.exit()
  
#This section creates a client facing GUI using Tkinter module
  
root=tkinter.Tk()
root.title("EE6032 Secure Chat Application")
#root.resizable(0,0)
root.geometry("600x500")
root.protocol("WM_DELETE_WINDOW", on_closing)
  
'''
config_frame = tkinter.Frame(root, relief=tkinter.GROOVE, borderwidth=3)
config_frame.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=1)
tkinter.Label(config_frame, text="Your IP Address", relief=tkinter.GROOVE, width=25).grid(row=1,column=1)
tkinter.Label(config_frame, text="Status", relief=tkinter.GROOVE, width=25).grid(row=2,column=1)
tkinter.Label(config_frame, text="Port Number", relief=tkinter.GROOVE, width=25).grid(row=3,column=1)
#tkinter.Label(config_frame, textvariable=socket.gethostbyname(socket.gethostname()), relief=tkinter.GROOVE, width=25).grid(row=1,column=2)
'''
  
#Create the message frame, which holds the previous messages exchanged
msg_frame = tkinter.Frame(root, relief=tkinter.GROOVE, borderwidth=3)
msg_frame.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=1)
msg_frame.pack(padx=10, pady=10)
msg_frame.pack()
  
# Create the text frame, which holds the message entry, encrypt checkbox
# and Send button 
txt_frame = tkinter.Frame(root, relief=tkinter.GROOVE, borderwidth=1)
txt_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X, expand=1)
txt_frame.pack(padx=10, pady=0)
txt_frame.pack()
  
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(msg_frame)  # To navigate through past messages.
scrollbar2 = tkinter.Scrollbar(msg_frame, orient=tkinter.HORIZONTAL)
# Following will contain the messages.
msg_list = tkinter.Listbox(msg_frame, yscrollcommand=scrollbar.set, xscrollcommand=scrollbar2.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
scrollbar.config(command=msg_list.yview)
scrollbar2.pack(side=tkinter.BOTTOM, fill=tkinter.X)
scrollbar2.config(command=msg_list.xview)
msg_list.pack(side=tkinter.BOTTOM, fill=tkinter.BOTH, pady=5, padx=5, expand=1)
msg_list.pack()
msg_frame.pack()
  
#entry_frame = tkinter.Frame(bottom, relief=tkinter.RAISED, borderwidth=1)
entry_field = tkinter.Entry(txt_frame, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack(side=tkinter.LEFT, ipady=10, padx=10, fill=tkinter.X, expand=1)
  
encrypt_var=''
encrypt_button = tkinter.Checkbutton(txt_frame, text="Encrpyt", variable=encrypt_var)
encrypt_button.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=10)
  
  
send_button = tkinter.Button(txt_frame, text="Send", command=send, bg='#128C7E')
send_button.pack(side=tkinter.LEFT, ipady=10, ipadx=10, pady=10, padx=5)
  
  
#----Now comes the sockets part----
HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)
  
BUFSIZ = 1024
ADDR = (HOST, PORT)
  
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
  
receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.