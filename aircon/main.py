import packet
import socket

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

while True:
    f = s.recv(256)
    p = packet.packet(f)
    print(p.packet)