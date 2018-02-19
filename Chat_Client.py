'''
Created on 15 Feb 2018

@author: Kevin
'''

"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter


def receive():
    """Handles receiving of messages."""
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            msg_list.insert(tkinter.END, msg)
        except OSError:  # Possibly client has left the chat.
            break


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        top.quit()


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()

#This section creates a GUI using Tkinter module
root = tkinter.Tk()
root.title("EE6032 Secure Chat Application")

top = tkinter.Frame(root, relief=tkinter.RAISED, borderwidth=1)
top.pack(side=tkinter.TOP, fill=tkinter.X, expand=1)
bottom = tkinter.Frame(root, relief=tkinter.RAISED, borderwidth=1)
bottom.pack(side=tkinter.BOTTOM, fill=tkinter.X, expand=1)

my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(top)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(top, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
top.pack()

#entry_frame = tkinter.Frame(bottom, relief=tkinter.RAISED, borderwidth=1)
entry_field = tkinter.Entry(bottom, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack(side=tkinter.LEFT, ipady=10, padx=10, fill=tkinter.X, expand=1)
send_button = tkinter.Button(bottom, text="Send", command=send)
send_button.pack(side=tkinter.RIGHT, ipady=10, ipadx=10, pady=10)

root.geometry("600x500")
root.protocol("WM_DELETE_WINDOW", on_closing)

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