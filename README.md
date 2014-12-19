SimpleSNIProxy
==============

Replace of https://github.com/dlundquist/sniproxy . written with Go Language.
sniproxy is well works. but It's written with C/C++. so It's hard to modify.
Go Language's Performanace is not bad for network server, so written in Go Language.

This code is came from the sub-product of Macadamia(L4/L7 Loadbanacer with Go).

Installation
============

Just build run.

Issue
=====

There's no security options. so, you must use firewall(ex:iptables..).

You can build your own Smart-DNS Proxy with this SimpleSNIProxy and PyDNSProxy (it has HTTPS SNIProxy Feature, but slow and buggy. so you can disable it's Proxy Server.).

Special Thanks
==============

SNIProxy(HTTPS) code came from 'stupid-proxy' https://github.com/gpjt/stupid-proxy/


