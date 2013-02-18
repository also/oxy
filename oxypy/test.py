import socket
import struct
import oxypy

def to_ip_addr_string(i):
  return socket.inet_ntoa(struct.pack("I", socket.htonl(i)))

oxypy.connect()

while True:
  cookie, pid, host, port = oxypy.recv()
  oxypy.send(cookie, 0, host, port)
  print "pid %d connecting to %s:%d" % (pid, to_ip_addr_string(host), port)
