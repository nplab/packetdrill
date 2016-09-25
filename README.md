# packetdrill
A fork of [packetdrill](https://code.google.com/p/packetdrill/) which adds support for
* UDPLite as specified in [RFC 3828](https://tools.ietf.org/html/rfc3828)
* SCTP as specified in [RFC 4960](https://tools.ietf.org/html/rfc4960),  [RFC 4820](https://tools.ietf.org/html/rfc4820) and [RFC 7053](https://tools.ietf.org/html/rfc7053)

and generic bugfixes, espcially several fixes required to get packetdrill working on FreeBSD.

## Information
There are some papers ([;login: October 2013](https://www.usenix.org/system/files/login/articles/10_cardwell-online.pdf), [USENIX ATC '13](https://www.usenix.org/system/files/conference/atc13/atc13-cardwell.pdf)) and a presentation ([ICCRG IETF87](https://www.ietf.org/proceedings/87/slides/slides-87-iccrg-1.pdf)) describing packetdrill.

## Installation
### Linux (Ubuntu)
For installing the required packages run:
```
sudo apt-get install git libsctp-dev bison flex
```
Then download the sources, compile them and install the files:
```
git clone https://github.com/nplab/packetdrill.git
cd packetdrill/gtests/net/packetdrill/
./configure
make
```
### FreeBSD
For installing the required packages run:
```
sudo pkg install ???
```
Then download the sources, compile them and install the files:
```
git clone https://github.com/nplab/packetdrill.git
cd packetdrill/gtests/net/packetdrill/
./configure
gmake
```
##  Continous Integration
The status of continous integration testing is available from [grid](http://212.201.121.110:38010/grid) and [waterfall](http://212.201.121.110:38010/waterfall).
If you are only interested in a single branch, just append `?branch=BRANCHNAME` to the URL, for example [waterfall](http://212.201.121.110:38010/waterfall?branch=master).
