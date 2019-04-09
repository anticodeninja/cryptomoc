#!/usr/bin/env python3
import socket


def start_server(filename='', passwd='', port=int()):
    s = socket.socket()
    host = socket.gethostname()
    s.bind((host, port))
    s.listen(1)

    # while True:
    conn, addr = s.accept()  # Establish connection with client.
    conn.settimeout(10)
    print(addr)
    data = conn.recv(1024)
    print('Server received', repr(data))

    f = open(filename, 'rb')
    l = f.read(1024)
    while (l):
        conn.send(l)
        print('Sent ', repr(l))
        l = f.read(1024)
    f.close()

    print('Done sending')
    conn.send(('Here your password '+ passwd).encode('utf-8'))
    conn.close()
    return