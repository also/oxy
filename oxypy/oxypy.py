import socket
import struct
from _oxypy import *


def ntoa(i):
  return socket.inet_ntoa(struct.pack("I", socket.htonl(i)))


def aton(s):
  return socket.ntohl(struct.unpack("I", socket.inet_aton(s))[0])


class ConnectionRequest(object):
  def __init__(self, cookie, pid, host, port):
    self.cookie = cookie
    self.pid = pid
    self.host = host
    self.port = port

  def _send(self, flags, host, port):
    send(self.cookie, flags, host, port)

  def reject(self):
    self._send(CONNECTION_REJECT, self.host, self.port)

  def allow(self):
    self._send(CONNECTION_IGNORE, 0, 0)

  def modify(self, host=None, port=None):
    if host is None:
      host = self.host
    elif isinstance(host, basestring):
      host = aton(host)

    if port is None:
      port = self.port

    self._send(CONNECTION_MODIFY, host, port)


def recv_request():
  return ConnectionRequest(*recv())
