Oxy
===

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

