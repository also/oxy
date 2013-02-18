Oxy
===

Oxy lets you do weird things to OS X sockets. Right now, this includes __watching__, __modifying__, and __rejecting__ outgoing `connect()` calls.

Check out this hotness
----------------------

```python
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
```

Developing
----------

```bash
xcodebuild -configuration Debug
# this builds build/Debug/Oxy.kext
# kexts need to be owned by root:wheel
sudo cp -R build/Debug/Oxy.kext /tmp
# check it
kextutil -n -print-diagnostics /tmp/Oxy.kext
# "No kernel file specified, using '/mach_kernel'" is OK
# "The following symbols are unresolved for this kext" means we haven't
# declared all bundled libraries in Oxy-Info.plist.
# kextlibs -xml build/Debug/Oxy.kext
# will return the necessary snippet
```

Network Kernel Extensions:
https://developer.apple.com/library/mac/#documentation/Darwin/Conceptual/NKEConceptual/intro/intro.html

Building:
https://developer.apple.com/library/mac/#documentation/Darwin/Conceptual/KEXTConcept/KEXTConceptKEXT/kext_tutorial.html

Debugging:
https://developer.apple.com/library/mac/#documentation/Darwin/Conceptual/KEXTConcept/KEXTConceptDebugger/debug_tutorial.html

