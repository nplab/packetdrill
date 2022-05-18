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
sudo apt-get install make git libsctp-dev bison flex python
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
sudo pkg install git bison python
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

### Windows (Windows 11)
packetdrill has no Windows support, but the packetdrill remote mode works inside the Windows Subsystem for Linux version 1 (WSL1). Note, WSL1 maps Linux system calls to Windows system calls, whereas WSL2 is basically a Linux VM. To test the Windows implementation, WSL1 is required.

Follow the Linux instructions for installation.

The packetdrill remote mode requires two hosts, the wire\_client (i.e., the system under test, Windows) and the wire\_server (i.e., the system that captures the packets, e.g. Ubuntu).

To start the wire\_server with interface enp0s5f0 connecting to wire\_client.
```
sudo packetdrill --wire_server --wire_server_dev=enp0s5f0
```
To start the wire\_client on Windows, first start a cmd as Administrator and run wsl within it. Inside the wsl, run
```
sudo packetdrill --wire_client --wire_client_dev=eth1 --wire_server_ip=10.1.2.3 <script_path>
```
where eth1 is wsl's interface to the wire\_server and 10.1.2.3 is the real IP address of wire\_server's enp0s5f0 interface.

##  Continous Integration
The status of continous integration testing is available from [Buildbot](http://buildbot.nplab.de:38010/#/console).
