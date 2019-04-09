#!/usr/bin/env python3
import socket


def start_client(port):
    s = socket.socket()
    host = socket.gethostname()

    s.connect((host, port))
    s.send(b"Hello server!")

    with open('received_file', 'wb') as f:
        while True:
            print('receiving data...')
            data = s.recv(1024)
            print('data=%s', (data))
            if not data:
                break
            f.write(data)

    f.close()
    print('Successfully get the file')
    s.close()
    print('connection closed')