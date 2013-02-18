import oxypy


GOOGLE = oxypy.aton('8.8.8.8')
RYAN = oxypy.aton('173.45.224.61')


oxypy.connect()


while True:
  r = oxypy.recv_request()
  print "pid %d connecting to %s:%d" % (r.pid, oxypy.ntoa(r.host), r.port)

  if r.host == GOOGLE and r.port == 22:
    print "what are you doing?"
    r.modify(host=RYAN)
  elif r.host == RYAN:
    print "rejecting connection to www.ryanberdeen.com"
    r.reject()
  else:
    r.allow()
