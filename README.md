# packetdrill
A fork of [packetdrill](https://code.google.com/p/packetdrill/) which adds support for
* UDPLite as specified in [RFC 3828](https://tools.ietf.org/html/rfc3828)
* SCTP as specified in [RFC 4960](https://tools.ietf.org/html/rfc4960),  [RFC 4820](https://tools.ietf.org/html/rfc4820) and [RFC 7053](https://tools.ietf.org/html/rfc7053)

and generic bugfixes. This version especially fixes some bugs showing up when running packetdrill on FreeBSD. Currently it only supports single-homing.
