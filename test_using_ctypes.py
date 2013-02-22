import os
import socket
from ctypes import *

libc = CDLL('libc.dylib', use_errno=True)

s = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
if s < 0:
  print os.strerror(get_errno())
  exit(1)

value = c_int()
length = c_int(sizeof(value))

result = libc.getsockopt(s, 0x4F585859, 0, byref(value), byref(length))
if result is not 0:
  print os.strerror(get_errno())
  exit(1)

print 'Oxy version %d is looking at your sockets!' % value.value
