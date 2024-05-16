#!/usr/bin/eng python3
import socket


HOST = '10.0.0.1'
PORT = 80

static_page = b"""HTTP/1.1 200 OK
Server: custom
Content-Length: 106
Date: Mon, 5 Mar 2024 14:17:30 GMT
Content-Type: text/html

<html>
<head>
	<title>Hello World</title>
</head>
<body>
	<pl>This is the best!</pl>
</body>
</html>
""" 

def main():
    print(f"Setting up server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            print(f"Recieved connection from {addr}")
            # data = conn.recv(1024)
            # print(data)
            conn.send(static_page)
            conn.close()

if __name__ == '__main__':
    main()