import socket
import errno

SOL_OXY = 0x4F585859 # oxy.h

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

try:
  v = s.getsockopt(SOL_OXY, 0)
  print "Oxy version %d is looking at your sockets!" % v
except socket.error as e:
  if e.errno is errno.EINVAL:
    print "Oxy not running."
  else:
    raise
