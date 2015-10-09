# Status of the socket API support

## SCTP cmsgs

## SCTP Notifications

## SCTP Socket Options

|Name                        | API Spec                                                      | Protocol Spec | packetdrill | Linux | FreeBSD |
|:---------------------------|:-------------------------------------------------------------:|:-------------:|:-----------:|:-----:|:-------:|
|SCTP_RTOINFO                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.1)  |               | TBD         | TBD   | TBD     |
|SCTP_ASSOCINFO              | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.2)  |               | TBD         | TBD   | TBD     |
|SCTP_INITMSG                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.3)  |               | TBD         | TBD   | TBD     |
|SCTP_NODELAY                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.5)  |               | TBD         | TBD   | TBD     |
|SCTP_AUTOCLOSE              | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.8)  |               | TBD         | TBD   | TBD     |
|SCTP_PRIMARY_ADDR           | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.9)  |               | TBD         | TBD   | TBD     |
|SCTP_ADAPTATION_LAYER       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.10) |               | TBD         | TBD   | TBD     |
|SCTP_DISABLE_FRAGMENTS      | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.11) |               | TBD         | TBD   | TBD     |
|SCTP_PEER_ADDR_PARAMS       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.12) |               | TBD         | TBD   | TBD     |
|SCTP_DEFAULT_SEND_PARAM     | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.13) |               | TBD         | TBD   | TBD     |
|SCTP_EVENTS                 | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.14) |               | TBD         | TBD   | TBD     |
|SCTP_I_WANT_MAPPED_V4_ADDR  | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.15) |               | TBD         | TBD   | TBD     |
|SCTP_MAXSEG                 | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.16) |               | TBD         | TBD   | TBD     |
|SCTP_HMAC_IDENT             | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.17) |               | TBD         | TBD   | TBD     |
|SCTP_AUTH_ACTIVE_KEY        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.18) |               | TBD         | TBD   | TBD     |
|SCTP_DELAYED_SACK           | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.19) |               | TBD         | TBD   | TBD     |
|SCTP_FRAGMENT_INTERLEAVE    | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.20) |               | TBD         | TBD   | TBD     |
|SCTP_PARTIAL_DELIVERY_POINT | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.21) |               | TBD         | TBD   | TBD     |
|SCTP_USE_EXT_RCVINFO        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.22) |               | TBD         | TBD   | TBD     |
|SCTP_AUTO_ASCONF            | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.23) |               | TBD         | TBD   | TBD     |
|SCTP_MAX_BURST              | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.24) |               | TBD         | TBD   | TBD     |
|SCTP_CONTEXT                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.25) |               | TBD         | TBD   | TBD     |
|SCTP_EXPLICIT_EOR           | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.26) |               | TBD         | TBD   | TBD     |
|SCTP_REUSE_PORT             | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.27) |               | TBD         | TBD   | TBD     |
|SCTP_EVENT                  | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.28) |               | TBD         | TBD   | TBD     |
|SCTP_RECVRCVINFO            | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.29) |               | TBD         | TBD   | TBD     |
|SCTP_RECVNXTINFO            | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.30) |               | TBD         | TBD   | TBD     |
|SCTP_DEFAULT_SNDINFO        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.31) |               | TBD         | TBD   | TBD     |
|SCTP_DEFAULT_PRINFO         | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.32) |               | TBD         | TBD   | TBD     |
|SCTP_STATUS                 | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.1)  |               | TBD         | TBD   | TBD     |
|SCTP_GET_PEER_ADDR_INFO     | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.2)  |               | TBD         | TBD   | TBD     |
|SCTP_PEER_AUTH_CHUNKS       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.3)  |               | TBD         | TBD   | TBD     |
|SCTP_LOCAL_AUTH_CHUNKS      | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.4)  |               | TBD         | TBD   | TBD     |
|SCTP_GET_ASSOC_NUMBER       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.5)  |               | TBD         | TBD   | TBD     |
|SCTP_GET_ASSOC_ID_LIST      | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.6)  |               | TBD         | TBD   | TBD     |
|SCTP_SET_PEER_PRIMARY_ADDR  | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.1)  |               | TBD         | TBD   | TBD     |
|SCTP_AUTH_CHUNK             | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.2)  |               | TBD         | TBD   | TBD     |
|SCTP_AUTH_KEY               | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.3)  |               | TBD         | TBD   | TBD     |
|SCTP_AUTH_DEACTIVATE_KEY    | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.4)  |               | TBD         | TBD   | TBD     |
|SCTP_AUTH_DELETE_KEY        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.5)  |               | TBD         | TBD   | TBD     |


## SCTP Functions
