# Status of the socket API support

## SCTP cmsgs

## SCTP Notifications

## SCTP Socket Options

|Name                        | API Spec                                                      | Protocol Spec                                  | packetdrill | Linux               | FreeBSD   |
|:---------------------------|:-------------------------------------------------------------:|:----------------------------------------------:|:-----------:|:-------------------:|:---------:|
|SCTP_RTOINFO                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.1)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_ASSOCINFO              | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.2)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_INITMSG                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.3)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_NODELAY                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.5)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_AUTOCLOSE              | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.8)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_PRIMARY_ADDR           | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.9)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_ADAPTATION_LAYER       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.10) | [RFC5061](https://tools.ietf.org/html/rfc5061) | TBD         | supported           | supported |
|SCTP_DISABLE_FRAGMENTS      | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.11) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_PEER_ADDR_PARAMS       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.12) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | old structure       | supported |
|SCTP_DEFAULT_SEND_PARAM     | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.13) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_EVENTS                 | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.14) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_I_WANT_MAPPED_V4_ADDR  | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.15) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_MAXSEG                 | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.16) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | Check structure     | supported |
|SCTP_HMAC_IDENT             | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.17) | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |
|SCTP_AUTH_ACTIVE_KEY        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.18) | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |
|SCTP_DELAYED_SACK           | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.19) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_FRAGMENT_INTERLEAVE    | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.20) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_PARTIAL_DELIVERY_POINT | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.21) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_USE_EXT_RCVINFO        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.22) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_AUTO_ASCONF            | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.23) | [RFC5061](https://tools.ietf.org/html/rfc5061) | TBD         | unsupported         | supported |
|SCTP_MAX_BURST              | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.24) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | Check structure     | supported |
|SCTP_CONTEXT                | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.25) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_EXPLICIT_EOR           | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.26) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_REUSE_PORT             | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.27) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_EVENT                  | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.28) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_RECVRCVINFO            | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.29) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_RECVNXTINFO            | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.30) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_DEFAULT_SNDINFO        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.31) | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_DEFAULT_PRINFO         | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.1.32) | [RFC3758](https://tools.ietf.org/html/rfc3758) | TBD         | unsupported         | supported |
|SCTP_STATUS                 | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.1)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_GET_PEER_ADDR_INFO     | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.2)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_PEER_AUTH_CHUNKS       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.3)  | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |
|SCTP_LOCAL_AUTH_CHUNKS      | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.4)  | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |
|SCTP_GET_ASSOC_NUMBER       | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.5)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | supported           | supported |
|SCTP_GET_ASSOC_ID_LIST      | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.2.6)  | [RFC4960](https://tools.ietf.org/html/rfc4960) | TBD         | unsupported         | supported |
|SCTP_SET_PEER_PRIMARY_ADDR  | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.1)  | [RFC5061](https://tools.ietf.org/html/rfc5061) | TBD         | supported           | supported |
|SCTP_AUTH_CHUNK             | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.2)  | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |
|SCTP_AUTH_KEY               | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.3)  | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |
|SCTP_AUTH_DEACTIVATE_KEY    | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.4)  | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | unsupported         | supported |
|SCTP_AUTH_DELETE_KEY        | [RFC6458](https://tools.ietf.org/html/rfc6458#section-8.3.5)  | [RFC4895](https://tools.ietf.org/html/rfc4895) | TBD         | supported           | supported |


## SCTP Functions
