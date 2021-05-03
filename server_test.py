import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(b"test", ("10.128.206.236", 8002))
