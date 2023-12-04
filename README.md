# reversing-tools

This is a collection of tools (scripts, programs, recipes etc)
for reverse engineering applications.

## [android](./android)

Tools for poking about in the internals of android app.

* [ble.js](./android/ble.js) [Frida](https://frida.re) script for monitoring BLE comms.
  * see [./android/ble-reversing-non-rooted-android.md](./android/ble-reversing-non-rooted-android.md) for an example of reverse engineering a BLE control protocol

## [golang](./golang)

Tools for messing with programs written in golang.

* [disable_verify_hostname.py](./golang/disable_verify_hostname.py) is a [Frida](https://frida.re) script to disable hostname checking in TLS connection allowing MITM.
* [tls_secrets.py](./golang/tls_secrets.py) will dump NSS key log formatted TLS secrets allowing network traces to be decoded in Wireshark.
