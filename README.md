# packetdrill
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13944/badge.svg)](https://scan.coverity.com/projects/packetdrill-nplab)

A fork of [packetdrill](https://code.google.com/p/packetdrill/) which adds support for
* UDPLite as specified in [RFC 3828](https://tools.ietf.org/html/rfc3828)
* SCTP as specified in [RFC 4960](https://tools.ietf.org/html/rfc4960),  [RFC 4820](https://tools.ietf.org/html/rfc4820), [RFC 6458](https://tools.ietf.org/html/rfc6458), and [RFC 7053](https://tools.ietf.org/html/rfc7053)

and generic bugfixes, espcially several fixes required to get packetdrill working on FreeBSD.
MacOS (El Capitan and higher) is also supported.

## Information
There are some papers ([;login: October 2013](https://www.usenix.org/system/files/login/articles/10_cardwell-online.pdf), [USENIX ATC '13](https://www.usenix.org/system/files/conference/atc13/atc13-cardwell.pdf)) and a presentation ([ICCRG IETF87](https://www.ietf.org/proceedings/87/slides/slides-87-iccrg-1.pdf)) describing packetdrill.

## Installation
### MacOS (El Capitan and higer)
Download the sources, compile them and install the binary:
```
git clone https://github.com/nplab/packetdrill.git
cd packetdrill/gtests/net/packetdrill/
./configure
make
sudo cp packetdrill /usr/bin
```
### Linux (Ubuntu)
For installing the required packages run:
```
sudo apt-get install make git libsctp-dev bison flex
```
Then download the sources, compile them and install the binary:
```
git clone https://github.com/nplab/packetdrill.git
cd packetdrill/gtests/net/packetdrill/
./configure
make
sudo cp packetdrill /usr/bin
```
### FreeBSD
For installing the required packages run:
```
sudo pkg install git bison
```
Then download the sources, compile them and install the binary:
```
git clone https://github.com/nplab/packetdrill.git
cd packetdrill/gtests/net/packetdrill/
./configure
make
sudo cp packetdrill /usr/local/bin
```
To be able to run packetdrill in combination with `sudo` run
```
sudo sysctl -w vm.old_mlock=1
```
or add
```
vm.old_mlock=1
```
to `/etc/sysctl.conf` and reboot.
##  Continous Integration
The status of continous integration testing is available from [grid](http://212.201.121.110:38010/grid) and [waterfall](http://212.201.121.110:38010/waterfall).
If you are only interested in a single branch, just append `?branch=BRANCHNAME` to the URL, for example [waterfall](http://212.201.121.110:38010/waterfall?branch=master).
