# reversing-tools

This is a collection of tools (scripts, programs, recipes etc)
for reverse engineering applications.

## [golang](./golang)

Tools for messing with programs written in golang.

* [disable_verify_hostname.py](./golang/disable_verify_hostname.py) is a [Frida](frida.re) script to disable hostname checking in TLS connection allowing MITM.
* [tls_secrets.py](./golang/tls_secrets.py) will dump NSS key log formatted TLS secrets allowing network traces to be decoded in Wireshark.