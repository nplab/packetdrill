/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Definitions of strace-style symbols for FreeBSD.
 * Allows us to map from symbolic strings to integers for system call inputs.
 */

#if defined(__FreeBSD__)

#include "symbols.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include "tcp.h"

/* A table of platform-specific string->int mappings. */
struct int_symbol platform_symbols_table[] = {

	/* /usr/include/sys/socket.h */
	{ SO_DEBUG,                         "SO_DEBUG"                        },
	{ SO_ACCEPTCONN,                    "SO_ACCEPTCONN"                   },
	{ SO_REUSEADDR,                     "SO_REUSEADDR"                    },
	{ SO_KEEPALIVE,                     "SO_KEEPALIVE"                    },
	{ SO_DONTROUTE,                     "SO_DONTROUTE"                    },
	{ SO_BROADCAST,                     "SO_BROADCAST"                    },
	{ SO_USELOOPBACK,                   "SO_USELOOPBACK"                  },
	{ SO_LINGER,                        "SO_LINGER"                       },
	{ SO_OOBINLINE,                     "SO_OOBINLINE"                    },
	{ SO_REUSEPORT,                     "SO_REUSEPORT"                    },
	{ SO_TIMESTAMP,                     "SO_TIMESTAMP"                    },
	{ SO_NOSIGPIPE,                     "SO_NOSIGPIPE"                    },
	{ SO_ACCEPTFILTER,                  "SO_ACCEPTFILTER"                 },
	{ SO_BINTIME,                       "SO_BINTIME"                      },
	{ SO_NO_OFFLOAD,                    "SO_NO_OFFLOAD"                   },
	{ SO_NO_DDP,                        "SO_NO_DDP"                       },
#ifdef SO_REUSEPORT_LB
	{ SO_REUSEPORT_LB,                  "SO_REUSEPORT_LB"                 },
#endif
	{ SO_SNDBUF,                        "SO_SNDBUF"                       },
	{ SO_RCVBUF,                        "SO_RCVBUF"                       },
	{ SO_SNDLOWAT,                      "SO_SNDLOWAT"                     },
	{ SO_RCVLOWAT,                      "SO_RCVLOWAT"                     },
	{ SO_SNDTIMEO,                      "SO_SNDTIMEO"                     },
	{ SO_RCVTIMEO,                      "SO_RCVTIMEO"                     },
	{ SO_ERROR,                         "SO_ERROR"                        },
	{ SO_TYPE,                          "SO_TYPE"                         },
	{ SO_LABEL,                         "SO_LABEL"                        },
	{ SO_PEERLABEL,                     "SO_PEERLABEL"                    },
	{ SO_LISTENQLIMIT,                  "SO_LISTENQLIMIT"                 },
	{ SO_LISTENQLEN,                    "SO_LISTENQLEN"                   },
	{ SO_LISTENINCQLEN,                 "SO_LISTENINCQLEN"                },
	{ SO_SETFIB,                        "SO_SETFIB"                       },
#ifdef SO_USER_COOKIE
	{ SO_USER_COOKIE,                   "SO_USER_COOKIE"                  },
#endif
#ifdef SO_PROTOCOL
	{ SO_PROTOCOL,                      "SO_PROTOCOL"                     },
#endif
#ifdef SO_PROTOTYPE
	{ SO_PROTOTYPE,                     "SO_PROTOTYPE"                    },
#endif
#ifdef SO_TS_CLOCK
	{ SO_TS_CLOCK,                      "SO_TS_CLOCK"                     },
#endif
#ifdef SO_MAX_PACING_RATE
	{ SO_MAX_PACING_RATE,               "SO_MAX_PACING_RATE"              },
#endif
#ifdef SO_DOMAIN
	{ SO_DOMAIN,                        "SO_DOMAIN"                       },
#endif

	/* /usr/include/sys/sockio.h */
	{ SIOCSHIWAT,                       "SIOCSHIWAT"                      },
	{ SIOCGHIWAT,                       "SIOCGHIWAT"                      },
	{ SIOCSLOWAT,                       "SIOCSLOWAT"                      },
	{ SIOCGLOWAT,                       "SIOCGLOWAT"                      },
	{ SIOCATMARK,                       "SIOCATMARK"                      },
	{ SIOCSPGRP,                        "SIOCSPGRP"                       },
	{ SIOCGPGRP,                        "SIOCGPGRP"                       },

	/* /usr/include/netinet/in.h */
	{ IP_OPTIONS,                       "IP_OPTIONS"                      },
	{ IP_HDRINCL,                       "IP_HDRINCL"                      },
	{ IP_TOS,                           "IP_TOS"                          },
	{ IP_TTL,                           "IP_TTL"                          },
	{ IP_RECVOPTS,                      "IP_RECVOPTS"                     },
	{ IP_RECVRETOPTS,                   "IP_RECVRETOPTS"                  },
	{ IP_RECVDSTADDR,                   "IP_RECVDSTADDR"                  },
	{ IP_SENDSRCADDR,                   "IP_SENDSRCADDR"                  },
	{ IP_RETOPTS,                       "IP_RETOPTS"                      },
	{ IP_PORTRANGE,                     "IP_PORTRANGE"                    },
	{ IP_RECVIF,                        "IP_RECVIF"                       },
#ifdef IP_RSS_LISTEN_BUCKET
	{ IP_RSS_LISTEN_BUCKET,             "IP_RSS_LISTEN_BUCKET"            },
#endif
	{ IP_RECVTTL,                       "IP_RECVTTL"                      },
	{ IP_MINTTL,                        "IP_MINTTL,"                      },
	{ IP_DONTFRAG,                      "IP_DONTFRAG"                     },
	{ IP_RECVTOS,                       "IP_RECVTOS"                      },
#ifdef IP_FLOWID
	{ IP_FLOWID,                        "IP_FLOWID"                       },
#endif
#ifdef IP_FLOWTYPE
	{ IP_FLOWTYPE,                      "IP_FLOWTYPE"                     },
#endif
#ifdef IP_RSSBUCKETID
	{ IP_RSSBUCKETID,                   "IP_RSSBUCKETID"                  },
#endif
#ifdef IP_RECVFLOWID
	{ IP_RECVFLOWID,                    "IP_RECVFLOWID"                   },
#endif
#ifdef IP_RECVRSSBUCKETID
	{ IP_RECVRSSBUCKETID,               "IP_RECVRSSBUCKETID"              },
#endif

	/* /usr/include/netinet/ip.h */
	{ IPTOS_DSCP_CS0,                   "IPTOS_DSCP_CS0"                  },
	{ IPTOS_DSCP_CS1,                   "IPTOS_DSCP_CS1"                  },
	{ IPTOS_DSCP_AF11,                  "IPTOS_DSCP_AF11"                 },
	{ IPTOS_DSCP_AF12,                  "IPTOS_DSCP_AF12"                 },
	{ IPTOS_DSCP_AF13,                  "IPTOS_DSCP_AF13"                 },
	{ IPTOS_DSCP_CS2,                   "IPTOS_DSCP_CS2"                  },
	{ IPTOS_DSCP_AF21,                  "IPTOS_DSCP_AF21"                 },
	{ IPTOS_DSCP_AF22,                  "IPTOS_DSCP_AF22"                 },
	{ IPTOS_DSCP_AF23,                  "IPTOS_DSCP_AF23"                 },
	{ IPTOS_DSCP_CS3,                   "IPTOS_DSCP_CS3"                  },
	{ IPTOS_DSCP_AF31,                  "IPTOS_DSCP_AF31"                 },
	{ IPTOS_DSCP_AF32,                  "IPTOS_DSCP_AF32"                 },
	{ IPTOS_DSCP_AF33,                  "IPTOS_DSCP_AF33"                 },
	{ IPTOS_DSCP_CS4,                   "IPTOS_DSCP_CS4"                  },
	{ IPTOS_DSCP_AF41,                  "IPTOS_DSCP_AF41"                 },
	{ IPTOS_DSCP_AF42,                  "IPTOS_DSCP_AF42"                 },
	{ IPTOS_DSCP_AF43,                  "IPTOS_DSCP_AF43"                 },
	{ IPTOS_DSCP_CS5,                   "IPTOS_DSCP_CS5"                  },
	{ IPTOS_DSCP_VA,                    "IPTOS_DSCP_VA"                   },
	{ IPTOS_DSCP_EF,                    "IPTOS_DSCP_EF"                   },
	{ IPTOS_DSCP_CS6,                   "IPTOS_DSCP_CS6"                  },
	{ IPTOS_DSCP_CS7,                   "IPTOS_DSCP_CS7"                  },

	/* /usr/include/netinet6/in6.h */
	{ IPV6_UNICAST_HOPS,                "IPV6_UNICAST_HOPS"               },
	{ IPV6_PORTRANGE,                   "IPV6_PORTRANGE"                  },
	{ IPV6_CHECKSUM,                    "IPV6_CHECKSUM"                   },
	{ IPV6_V6ONLY,                      "IPV6_V6ONLY"                     },
	{ IPV6_RECVPKTINFO,                 "IPV6_RECVPKTINFO"                },
	{ IPV6_RECVHOPLIMIT,                "IPV6_RECVHOPLIMIT"               },
	{ IPV6_RECVRTHDR,                   "IPV6_RECVRTHDR"                  },
	{ IPV6_RECVHOPOPTS,                 "IPV6_RECVHOPOPTS"                },
	{ IPV6_RECVDSTOPTS,                 "IPV6_RECVDSTOPTS"                },
	{ IPV6_USE_MIN_MTU,                 "IPV6_USE_MIN_MTU"                },
	{ IPV6_RECVPATHMTU,                 "IPV6_RECVPATHMTU"                },
	{ IPV6_PATHMTU,                     "IPV6_PATHMTU"                    },
	{ IPV6_HOPLIMIT,                    "IPV6_HOPLIMIT"                   },
	{ IPV6_RECVTCLASS,                  "IPV6_RECVTCLASS"                 },
	{ IPV6_AUTOFLOWLABEL,               "IPV6_AUTOFLOWLABEL"              },
	{ IPV6_TCLASS,                      "IPV6_TCLASS"                     },
	{ IPV6_DONTFRAG,                    "IPV6_DONTFRAG"                   },
#ifdef IPV6_RSS_LISTEN_BUCKET
	{ IPV6_RSS_LISTEN_BUCKET,           "IPV6_RSS_LISTEN_BUCKET"          },
#endif
#ifdef IPV6_FLOWID
	{ IPV6_FLOWID,                      "IPV6_FLOWID"                     },
#endif
#ifdef IPV6_FLOWTYPE
	{ IPV6_FLOWTYPE,                    "IPV6_FLOWTYPE"                   },
#endif
#ifdef IPV6_RSSBUCKETID
	{ IPV6_RSSBUCKETID,                 "IPV6_RSSBUCKETID"                },
#endif
#ifdef IPV6_RECVFLOWID
	{ IPV6_RECVFLOWID,                  "IPV6_RECVFLOWID"                 },
#endif
#ifdef IPV6_RECVRSSBUCKETID
	{ IPV6_RECVRSSBUCKETID,             "IPV6_RECVRSSBUCKETID"            },
#endif

	/* /usr/include/netinet/sctp.h and /usr/include/netinet/sctp_uio.h */
	{ SCTP_RTOINFO,                     "SCTP_RTOINFO"                    },
	{ SCTP_ASSOCINFO,                   "SCTP_ASSOCINFO"                  },
	{ SCTP_INITMSG,                     "SCTP_INITMSG"                    },
	{ SCTP_INIT,                        "SCTP_INIT"                       },
	{ SCTP_NODELAY,                     "SCTP_NODELAY"                    },
	{ SCTP_AUTOCLOSE,                   "SCTP_AUTOCLOSE"                  },
	{ SCTP_PRIMARY_ADDR,                "SCTP_PRIMARY_ADDR"               },
	{ SCTP_ADAPTATION_LAYER,            "SCTP_ADAPTATION_LAYER"           },
	{ SCTP_DISABLE_FRAGMENTS,           "SCTP_DISABLE_FRAGMENTS"          },
	{ SCTP_DEFAULT_SEND_PARAM,          "SCTP_DEFAULT_SEND_PARAM"         },
	{ SCTP_I_WANT_MAPPED_V4_ADDR,       "SCTP_I_WANT_MAPPED_V4_ADDR"      },
	{ SCTP_MAXSEG,                      "SCTP_MAXSEG"                     },
	{ SCTP_HMAC_IDENT,                  "SCTP_HMAC_IDENT"                 },
	{ SCTP_AUTH_ACTIVE_KEY,             "SCTP_AUTH_ACTIVE_KEY"            },
	{ SCTP_DELAYED_SACK,                "SCTP_DELAYED_SACK"               },
	{ SCTP_PARTIAL_DELIVERY_POINT,      "SCTP_PARTIAL_DELIVERY_POINT"     },
	{ SCTP_AUTO_ASCONF,                 "SCTP_AUTO_ASCONF"                },
	{ SCTP_MAX_BURST,                   "SCTP_MAX_BURST"                  },
	{ SCTP_CONTEXT,                     "SCTP_CONTEXT"                    },
	{ SCTP_PEER_ADDR_PARAMS,            "SCTP_PEER_ADDR_PARAMS"           },
	{ SCTP_EVENT,                       "SCTP_EVENT"                      },
	{ SCTP_EXPLICIT_EOR,                "SCTP_EXPLICIT_EOR"               },
	{ SCTP_REUSE_PORT,                  "SCTP_REUSE_PORT"                 },
	{ SCTP_EVENTS,                      "SCTP_EVENTS"                     },
	{ SCTP_DEFAULT_SNDINFO,             "SCTP_DEFAULT_SNDINFO"            },
	{ SCTP_DEFAULT_PRINFO,              "SCTP_DEFAULT_PRINFO"             },
	{ SCTP_STATUS,                      "SCTP_STATUS"                     },
	{ SCTP_GET_PEER_ADDR_INFO,          "SCTP_GET_PEER_ADDR_INFO"         },
	{ SCTP_PEER_AUTH_CHUNKS,            "SCTP_PEER_AUTH_CHUNKS"           },
	{ SCTP_LOCAL_AUTH_CHUNKS,           "SCTP_LOCAL_AUTH_CHUNKS"          },
	{ SCTP_GET_ASSOC_NUMBER,            "SCTP_GET_ASSOC_NUMBER"           },
	{ SCTP_GET_ASSOC_ID_LIST,           "SCTP_GET_ASSOC_ID_LIST"          },
	{ SCTP_SET_PEER_PRIMARY_ADDR,       "SCTP_SET_PEER_PRIMARY_ADDR"      },
	{ SCTP_AUTH_CHUNK,                  "SCTP_AUTH_CHUNK"                 },
	{ SCTP_AUTH_KEY,                    "SCTP_AUTH_KEY"                   },
	{ SCTP_AUTH_DEACTIVATE_KEY,         "SCTP_AUTH_DEACTIVATE_KEY"        },
	{ SCTP_AUTH_DELETE_KEY,             "SCTP_AUTH_DELETE_KEY"            },
	{ SCTP_FRAGMENT_INTERLEAVE,         "SCTP_FRAGMENT_INTERLEAVE"        },
	{ SCTP_EXPLICIT_EOR,                "SCTP_EXPLICIT_EOR"               },
#if defined(SCTP_INTERLEAVING_SUPPORTED)
	{ SCTP_INTERLEAVING_SUPPORTED,      "SCTP_INTERLEAVING_SUPPORTED"     },
#endif
	{ SCTP_REMOTE_UDP_ENCAPS_PORT,      "SCTP_REMOTE_UDP_ENCAPS_PORT"     },
#if defined(SCTP_ACCEPT_ZERO_CHECKSUM)
	{ SCTP_ACCEPT_ZERO_CHECKSUM,        "SCTP_ACCEPT_ZERO_CHECKSUM"       },
#endif
	{ SCTP_CLOSED,                      "SCTP_CLOSED"                     },
	{ SCTP_BOUND,                       "SCTP_BOUND"                      },
	{ SCTP_LISTEN,                      "SCTP_LISTEN"                     },
	{ SCTP_COOKIE_WAIT,                 "SCTP_COOKIE_WAIT"                },
	{ SCTP_COOKIE_ECHOED,               "SCTP_COOKIE_ECHOED"              },
	{ SCTP_ESTABLISHED,                 "SCTP_ESTABLISHED"                },
	{ SCTP_SHUTDOWN_SENT,               "SCTP_SHUTDOWN_SENT"              },
	{ SCTP_SHUTDOWN_RECEIVED,           "SCTP_SHUTDOWN_RECEIVED"          },
	{ SCTP_SHUTDOWN_ACK_SENT,           "SCTP_SHUTDOWN_ACK_SENT"          },
	{ SCTP_SHUTDOWN_PENDING,            "SCTP_SHUTDOWN_PENDING"           },
	/* The following is a typo in FreeBSD's sctp.h */
#if defined(SCTP_STREAM_SCHEDULER)
	{ SCTP_STREAM_SCHEDULER,            "SCTP_STREAM_SCHEDULER"           },
#endif
#if defined(SCTP_STREAM_SCHEDULER)
	{ SCTP_STREAM_SCHEDULER_VALUE,      "SCTP_STREAM_SCHEDULER_VALUE"     },
#endif
#if defined(SCTP_SS_DEFAULT)
	{ SCTP_SS_DEFAULT,                  "SCTP_SS_DEFAULT"                 },
#endif
#if defined(SCTP_SS_FCFS)
	{ SCTP_SS_FCFS,                     "SCTP_SS_FCFS"                    },
#endif
#if defined(SCTP_SS_RR)
	{ SCTP_SS_RR,                       "SCTP_SS_RR"                      },
#endif
#if defined(SCTP_SS_RR_PKT)
	{ SCTP_SS_RR_PKT,                   "SCTP_SS_RR_PKT"                  },
#endif
#if defined(SCTP_SS_PRIO)
	{ SCTP_SS_PRIO,                     "SCTP_SS_PRIO"                    },
#endif
#if defined(SCTP_SS_FB)
	{ SCTP_SS_FB,                       "SCTP_SS_FB"                      },
#endif
#if defined(SCTP_SS_WFQ)
	{ SCTP_SS_WFQ,                      "SCTP_SS_WFQ"                     },
#endif
	{ SCTP_UNCONFIRMED,                 "SCTP_UNCONFIRMED"                },
	{ SCTP_ACTIVE,                      "SCTP_ACTIVE"                     },
	{ SCTP_INACTIVE,                    "SCTP_INACTIVE"                   },
	{ SPP_HB_ENABLE,                    "SPP_HB_ENABLE"                   },
	{ SPP_HB_DISABLE,                   "SPP_HB_DISABLE"                  },
	{ SPP_HB_DEMAND,                    "SPP_HB_DEMAND"                   },
	{ SPP_HB_TIME_IS_ZERO,              "SPP_HB_TIME_IS_ZERO"             },
	{ SPP_PMTUD_ENABLE,                 "SPP_PMTUD_ENABLE"                },
	{ SPP_PMTUD_DISABLE,                "SPP_PMTUD_DISABLE"               },
	{ SPP_IPV6_FLOWLABEL,               "SPP_IPV6_FLOWLABEL"              },
	{ SPP_DSCP,                         "SPP_DSCP"                        },
	{ SCTP_ASSOC_CHANGE,                "SCTP_ASSOC_CHANGE"               },
	{ SCTP_PEER_ADDR_CHANGE,            "SCTP_PEER_ADDR_CHANGE"           },
	{ SCTP_REMOTE_ERROR,                "SCTP_REMOTE_ERROR"               },
	{ SCTP_SEND_FAILED,                 "SCTP_SEND_FAILED"                },
	{ SCTP_SHUTDOWN_EVENT,              "SCTP_SHUTDOWN_EVENT"             },
	{ SCTP_SENDER_DRY_EVENT,            "SCTP_SENDER_DRY_EVENT"           },
	{ SCTP_SEND_FAILED_EVENT,           "SCTP_SEND_FAILED_EVENT"          },
	{ SCTP_ADAPTATION_INDICATION,       "SCTP_ADAPTATION_INDICATION"      },
	{ SCTP_ADAPTION_INDICATION,         "SCTP_ADAPTION_INDICATION"        },
	{ SCTP_PARTIAL_DELIVERY_EVENT,      "SCTP_PARTIAL_DELIVERY_EVENT"     },
	{ SCTP_AUTHENTICATION_EVENT,        "SCTP_AUTHENTICATION_EVENT"       },
	{ SCTP_NOTIFICATIONS_STOPPED_EVENT, "SCTP_NOTIFICATIONS_STOPPED_EVENT"},
	{ SCTP_SEND_FAILED_EVENT,           "SCTP_SEND_FAILED_EVENT"          },
	{ SCTP_UNORDERED,                   "SCTP_UNORDERED"                  },
	{ SCTP_COMPLETE,                    "SCTP_COMPLETE"                   },
	{ SCTP_ADDR_OVER,                   "SCTP_ADDR_OVER"                  },
	{ SCTP_ABORT,                       "SCTP_ABORT"                      },
	{ SCTP_EOF,                         "SCTP_EOF"                        },
	{ SCTP_SENDALL,                     "SCTP_SENDALL"                    },
	{ SCTP_EOR,                         "SCTP_EOR"                        },
	{ SCTP_NEXT_MSG_AVAIL,              "SCTP_NEXT_MSG_AVAIL"             },
	{ SCTP_NEXT_MSG_ISCOMPLETE,         "SCTP_NEXT_MSG_ISCOMPLETE"        },
	{ SCTP_NEXT_MSG_IS_UNORDERED,       "SCTP_NEXT_MSG_IS_UNORDERED"      },
	{ SCTP_NEXT_MSG_IS_NOTIFICATION,    "SCTP_NEXT_MSG_IS_NOTIFICATION"   },
	{ SCTP_SACK_IMMEDIATELY,            "SCTP_SACK_IMMEDIATELY"           },
	{ SCTP_PR_SCTP_NONE,                "SCTP_PR_SCTP_NONE"               },
	{ SCTP_PR_SCTP_TTL,                 "SCTP_PR_SCTP_TTL"                },
	{ SCTP_PR_SCTP_RTX,                 "SCTP_PR_SCTP_RTX"                },
	{ SCTP_PR_SCTP_PRIO,                "SCTP_PR_SCTP_PRIO"               },
	{ SCTP_BINDX_ADD_ADDR,              "SCTP_BINDX_ADD_ADDR"             },
	{ SCTP_BINDX_REM_ADDR,              "SCTP_BINDX_REM_ADDR"             },
	{ SCTP_SENDV_NOINFO,                "SCTP_SENDV_NOINFO"               },
	{ SCTP_SENDV_SNDINFO,               "SCTP_SENDV_SNDINFO"              },
	{ SCTP_SENDV_PRINFO,                "SCTP_SENDV_PRINFO"               },
	{ SCTP_SENDV_AUTHINFO,              "SCTP_SENDV_AUTHINFO"             },
	{ SCTP_SENDV_SPA,                   "SCTP_SENDV_SPA"                  },
	{ SCTP_SEND_SNDINFO_VALID,          "SCTP_SEND_SNDINFO_VALID"         },
	{ SCTP_SEND_PRINFO_VALID,           "SCTP_SEND_PRINFO_VALID"          },
	{ SCTP_SEND_AUTHINFO_VALID,         "SCTP_SEND_AUTHINFO_VALID"        },
	{ SCTP_RECVV_NOINFO,                "SCTP_RECVV_NOINFO"               },
	{ SCTP_RECVV_RCVINFO,               "SCTP_RECVV_RCVINFO"              },
	{ SCTP_RECVV_NXTINFO,               "SCTP_RECVV_NXTINFO"              },
	{ SCTP_RECVV_RN,                    "SCTP_RECVV_RN"                   },
	{ SCTP_RECVRCVINFO,                 "SCTP_RECVRCVINFO"                },
	{ SCTP_RECVNXTINFO,                 "SCTP_RECVNXTINFO"                },
	{ SCTP_DATA_SENT,                   "SCTP_DATA_SENT"                  },
	{ SCTP_DATA_UNSENT,                 "SCTP_DATA_UNSENT"                },
	{ SCTP_COMM_UP,                     "SCTP_COMM_UP"                    },
	{ SCTP_COMM_LOST,                   "SCTP_COMM_LOST"                  },
	{ SCTP_RESTART,                     "SCTP_RESTART"                    },
	{ SCTP_SHUTDOWN_COMP,               "SCTP_SHUTDOWN_COMP"              },
	{ SCTP_CANT_STR_ASSOC,              "SCTP_CANT_STR_ASSOC"             },
	{ SCTP_AUTH_NEW_KEY,                "SCTP_AUTH_NEW_KEY"               },
	{ SCTP_AUTH_NO_AUTH,                "SCTP_AUTH_NO_AUTH"               },
	{ SCTP_AUTH_FREE_KEY,               "SCTP_AUTH_FREE_KEY"              },
	{ SCTP_ASSOC_SUPPORTS_PR,           "SCTP_ASSOC_SUPPORTS_PR"          },
	{ SCTP_ASSOC_SUPPORTS_AUTH,         "SCTP_ASSOC_SUPPORTS_AUTH"        },
	{ SCTP_ASSOC_SUPPORTS_ASCONF,       "SCTP_ASSOC_SUPPORTS_ASCONF"      },
	{ SCTP_ASSOC_SUPPORTS_MULTIBUF,     "SCTP_ASSOC_SUPPORTS_MULTIBUF"    },
	{ SCTP_PARTIAL_DELIVERY_ABORTED,    "SCTP_PARTIAL_DELIVERY_ABORTED"   },
	{ SCTP_ADDR_AVAILABLE,              "SCTP_ADDR_AVAILABLE"             },
	{ SCTP_ADDR_UNREACHABLE,            "SCTP_ADDR_UNREACHABLE"           },
	{ SCTP_ADDR_REMOVED,                "SCTP_ADDR_REMOVED"               },
	{ SCTP_ADDR_MADE_PRIM,              "SCTP_ADDR_MADE_PRIM"             },
	{ SCTP_SNDRCV,                      "SCTP_SNDRCV"                     },
	{ SCTP_SNDINFO,                     "SCTP_SNDINFO"                    },
	{ SCTP_RCVINFO,                     "SCTP_RCVINFO"                    },
	{ SCTP_NXTINFO,                     "SCTP_NXTINFO"                    },
	{ SCTP_PRINFO,                      "SCTP_PRINFO"                     },
	{ SCTP_AUTHINFO,                    "SCTP_AUTHINFO"                   },
	{ SCTP_DSTADDRV4,                   "SCTP_DSTADDRV4"                  },
	{ SCTP_DSTADDRV6,                   "SCTP_DSTADDRV6"                  },
	{ SCTP_EXTRCV,                      "SCTP_EXTRCV"                     },
	{ SCTP_USE_EXT_RCVINFO,             "SCTP_USE_EXT_RCVINFO"            },
	{ SCTP_AUTH_HMAC_ID_SHA1,           "SCTP_AUTH_HMAC_ID_SHA1"          },
	{ SCTP_AUTH_HMAC_ID_SHA256,         "SCTP_AUTH_HMAC_ID_SHA256"        },

	/* sctp stream reconfiguration */
	{ SCTP_ENABLE_STREAM_RESET,         "SCTP_ENABLE_STREAM_RESET"        },
	{ SCTP_ENABLE_RESET_STREAM_REQ,     "SCTP_ENABLE_RESET_STREAM_REQ"    },
	{ SCTP_ENABLE_RESET_ASSOC_REQ,      "SCTP_ENABLE_RESET_ASSOC_REQ"     },
	{ SCTP_ENABLE_CHANGE_ASSOC_REQ,     "SCTP_ENABLE_CHANGE_ASSOC_REQ"    },
	{ SCTP_RESET_STREAMS,               "SCTP_RESET_STREAMS"              },
	{ SCTP_STREAM_RESET_INCOMING,       "SCTP_STREAM_RESET_INCOMING"      },
	{ SCTP_STREAM_RESET_OUTGOING,       "SCTP_STREAM_RESET_OUTGOING"      },
	{ SCTP_RESET_ASSOC,                 "SCTP_RESET_ASSOC"                },
	{ SCTP_ADD_STREAMS,                 "SCTP_ADD_STREAMS"                },
	{ SCTP_STREAM_RESET_EVENT,          "SCTP_STREAM_RESET_EVENT"         },
	{ SCTP_STREAM_RESET_INCOMING_SSN,   "SCTP_STREAM_RESET_INCOMING_SSN"  },
	{ SCTP_STREAM_RESET_OUTGOING_SSN,   "SCTP_STREAM_RESET_OUTGOING_SSN"  },
	{ SCTP_STREAM_RESET_DENIED,         "SCTP_STREAM_RESET_DENIED"        },
	{ SCTP_STREAM_RESET_FAILED,         "SCTP_STREAM_RESET_FAILED"        },
	{ SCTP_ASSOC_RESET_EVENT,           "SCTP_ASSOC_RESET_EVENT"          },
	{ SCTP_ASSOC_RESET_DENIED,          "SCTP_ASSOC_RESET_DENIED"         },
	{ SCTP_ASSOC_RESET_FAILED,          "SCTP_ASSOC_RESET_FAILED"         },
	{ SCTP_STREAM_CHANGE_EVENT,         "SCTP_STREAM_CHANGE_EVENT"        },
	{ SCTP_STREAM_CHANGE_DENIED,        "SCTP_STREAM_CHANGE_DENIED"       },
	{ SCTP_STREAM_CHANGE_FAILED,        "SCTP_STREAM_CHANGE_FAILED"       },

	/* /usr/include/netinet/tcp.h */
	{ TCP_NODELAY,                      "TCP_NODELAY"                     },
	{ TCP_MAXSEG,                       "TCP_MAXSEG"                      },
	{ TCP_NOPUSH,                       "TCP_NOPUSH"                      },
	{ TCP_NOOPT,                        "TCP_NOOPT"                       },
	{ TCP_MD5SIG,                       "TCP_MD5SIG"                      },
	{ TCP_INFO,                         "TCP_INFO"                        },
	{ TCP_STATS,                        "TCP_STATS"                       },
#if defined(TCP_LOG)
	{ TCP_LOG,                          "TCP_LOG"                         },
#endif
#if defined(TCP_LOGBUF)
	{ TCP_LOGBUF,                       "TCP_LOGBUF"                      },
#endif
#if defined(TCP_LOGID)
	{ TCP_LOGID,                        "TCP_LOGID"                       },
#endif
#if defined(TCP_LOGDUMP)
	{ TCP_LOGDUMP,                      "TCP_LOGDUMP"                     },
#endif
#if defined(TCP_LOGDUMPID)
	{ TCP_LOGDUMPID,                    "TCP_LOGDUMPID"                   },
#endif
#if defined(TCP_TXTLS_ENABLE)
	{ TCP_TXTLS_ENABLE,                 "TCP_TXTLS_ENABLE"                },
#endif
#if defined(TCP_TXTLS_MODE)
	{ TCP_TXTLS_MODE,                   "TCP_TXTLS_MODE"                  },
#endif
#if defined(TCP_RXTLS_ENABLE)
	{ TCP_RXTLS_ENABLE,                 "TCP_RXTLS_ENABLE"                },
#endif
#if defined(TCP_RXTLS_MODE)
	{ TCP_RXTLS_MODE,                   "TCP_RXTLS_MODE"                  },
#endif
#if defined(TCP_IWND_NB)
	{ TCP_IWND_NB,                      "TCP_IWND_NB"                     },
#endif
#if defined(TCP_IWND_NSEG)
	{ TCP_IWND_NSEG,                    "TCP_IWND_NSEG"                   },
#endif
#if defined(TCP_LOGID_CNT)
	{ TCP_LOGID_CNT,                    "TCP_LOGID_CNT"                   },
#endif
#if defined(TCP_LOG_TAG)
	{ TCP_LOG_TAG,                      "TCP_LOG_TAG"                     },
#endif
#if defined(TCP_USER_LOG)
	{ TCP_USER_LOG,                     "TCP_USER_LOG"                    },
#endif
	{ TCP_CONGESTION,                   "TCP_CONGESTION"                  },
#if defined(TCP_CCALGOOPT)
	{ TCP_CCALGOOPT,                    "TCP_CCALGOOPT"                   },
#endif
#if defined(TCP_MAXUNACKTIME)
	{ TCP_MAXUNACKTIME,                 "TCP_MAXUNACKTIME"                },
#endif
#if defined(TCP_MAXPEAKRATE)
	{ TCP_MAXPEAKRATE,                  "TCP_MAXPEAKRATE"                 },
#endif
#if defined(TCP_IDLE_REDUCE)
	{ TCP_IDLE_REDUCE,                  "TCP_IDLE_REDUCE"                 },
#endif
#if defined(TCP_REMOTE_UDP_ENCAPS_PORT)
	{ TCP_REMOTE_UDP_ENCAPS_PORT,       "TCP_REMOTE_UDP_ENCAPS_PORT"      },
#endif
#if defined(TCP_DELACK)
	{ TCP_DELACK,                       "TCP_DELACK"                      },
#endif
#if defined(TCP_FIN_IS_RST)
	{ TCP_FIN_IS_RST,                   "TCP_FIN_IS_RST"                  },
#endif
#if defined(TCP_LOG_LIMIT)
	{ TCP_LOG_LIMIT,                    "TCP_LOG_LIMIT"                   },
#endif
#if defined(TCP_SHARED_CWND_ALLOWED)
	{ TCP_SHARED_CWND_ALLOWED,          "TCP_SHARED_CWND_ALLOWED"         },
#endif
#if defined(TCP_PROC_ACCOUNTING)
	{ TCP_PROC_ACCOUNTING,              "TCP_PROC_ACCOUNTING"             },
#endif
#if defined(TCP_USE_CMP_ACKS)
	{ TCP_USE_CMP_ACKS,                 "TCP_USE_CMP_ACKS"                },
#endif
#if defined(TCP_PERF_INFO)
	{ TCP_PERF_INFO,                    "TCP_PERF_INFO"                   },
#endif
#if defined(TCP_LRD)
	{ TCP_LRD,                          "TCP_LRD"                         },
#endif
	{ TCP_KEEPINIT,                     "TCP_KEEPINIT"                    },
	{ TCP_KEEPIDLE,                     "TCP_KEEPIDLE"                    },
	{ TCP_KEEPINTVL,                    "TCP_KEEPINTVL"                   },
	{ TCP_KEEPCNT,                      "TCP_KEEPCNT"                     },
#if defined(TCP_FASTOPEN)
	{ TCP_FASTOPEN,                     "TCP_FASTOPEN"                    },
#endif
	{ TCP_PCAP_OUT,                     "TCP_PCAP_OUT"                    },
	{ TCP_PCAP_IN,                      "TCP_PCAP_IN"                     },
#if defined(TCP_FUNCTION_BLK)
	{ TCP_FUNCTION_BLK,                 "TCP_FUNCTION_BLK"                },
#endif
#if defined(TCP_FUNCTION_ALIAS)
	{ TCP_FUNCTION_ALIAS,               "TCP_FUNCTION_ALIAS"              },
#endif
#if defined(TCP_REUSPORT_LB_NUMA)
	{ TCP_REUSPORT_LB_NUMA,             "TCP_REUSPORT_LB_NUMA"            },
#endif
#if defined(TCP_RACK_MBUF_QUEUE)
	{ TCP_RACK_MBUF_QUEUE,              "TCP_RACK_MBUF_QUEUE"             },
#endif
#if defined(TCP_RACK_PROP)
	{ TCP_RACK_PROP,                    "TCP_RACK_PROP"                   },
#endif
#if defined(TCP_RACK_TLP_REDUCE)
	{ TCP_RACK_TLP_REDUCE,              "TCP_RACK_TLP_REDUCE"             },
#endif
#if defined(TCP_RACK_PACE_REDUCE)
	{ TCP_RACK_PACE_REDUCE,             "TCP_RACK_PACE_REDUCE"            },
#endif
#if defined(TCP_RACK_PACE_MAX_SEG)
	{ TCP_RACK_PACE_MAX_SEG,            "TCP_RACK_PACE_MAX_SEG"           },
#endif
#if defined(TCP_RACK_PACE_ALWAYS)
	{ TCP_RACK_PACE_ALWAYS,             "TCP_RACK_PACE_ALWAYS"            },
#endif
#if defined(TCP_RACK_PROP_RATE)
	{ TCP_RACK_PROP_RATE,               "TCP_RACK_PROP_RATE"              },
#endif
#if defined(TCP_RACK_PRR_SENDALOT)
	{ TCP_RACK_PRR_SENDALOT,            "TCP_RACK_PRR_SENDALOT"           },
#endif
#if defined(TCP_RACK_MIN_TO)
	{ TCP_RACK_MIN_TO,                  "TCP_RACK_MIN_TO"                 },
#endif
#if defined(TCP_RACK_EARLY_RECOV)
	{ TCP_RACK_EARLY_RECOV,             "TCP_RACK_EARLY_RECOV"            },
#endif
#if defined(TCP_RACK_EARLY_SEG)
	{ TCP_RACK_EARLY_SEG,               "TCP_RACK_EARLY_SEG"              },
#endif
#if defined(TCP_RACK_REORD_THRESH)
	{ TCP_RACK_REORD_THRESH,            "TCP_RACK_REORD_THRESH"           },
#endif
#if defined(TCP_RACK_REORD_FADE)
	{ TCP_RACK_REORD_FADE,              "TCP_RACK_REORD_FADE"             },
#endif
#if defined(TCP_RACK_TLP_THRESH)
	{ TCP_RACK_TLP_THRESH,              "TCP_RACK_TLP_THRESH"             },
#endif
#if defined(TCP_RACK_PKT_DELAY)
	{ TCP_RACK_PKT_DELAY,               "TCP_RACK_PKT_DELAY"              },
#endif
#if defined(TCP_RACK_TLP_INC_VAR)
	{ TCP_RACK_TLP_INC_VAR,             "TCP_RACK_TLP_INC_VAR"            },
#endif
#if defined(TCP_BBR_IWINTSO)
	{ TCP_BBR_IWINTSO,                  "TCP_BBR_IWINTSO"                 },
#endif
#if defined(TCP_BBR_RECFORCE)
	{ TCP_BBR_RECFORCE,                 "TCP_BBR_RECFORCE"                },
#endif
#if defined(TCP_BBR_STARTUP_PG)
	{ TCP_BBR_STARTUP_PG,               "TCP_BBR_STARTUP_PG"              },
#endif
#if defined(TCP_BBR_DRAIN_PG)
	{ TCP_BBR_DRAIN_PG,                 "TCP_BBR_DRAIN_PG"                },
#endif
#if defined(TCP_BBR_RWND_IS_APP)
	{ TCP_BBR_RWND_IS_APP,              "TCP_BBR_RWND_IS_APP"             },
#endif
#if defined(TCP_BBR_PROBE_RTT_INT)
	{ TCP_BBR_PROBE_RTT_INT,            "TCP_BBR_PROBE_RTT_INT"           },
#endif
#if defined(TCP_BBR_ONE_RETRAN)
	{ TCP_BBR_ONE_RETRAN,               "TCP_BBR_ONE_RETRAN"              },
#endif
#if defined(TCP_BBR_STARTUP_LOSS_EXIT)
	{ TCP_BBR_STARTUP_LOSS_EXIT,        "TCP_BBR_STARTUP_LOSS_EXIT"       },
#endif
#if defined(TCP_BBR_USE_LOWGAIN)
	{ TCP_BBR_USE_LOWGAIN,              "TCP_BBR_USE_LOWGAIN"             },
#endif
#if defined(TCP_BBR_LOWGAIN_THRESH)
	{ TCP_BBR_LOWGAIN_THRESH,           "TCP_BBR_LOWGAIN_THRESH"          },
#endif
#if defined(TCP_BBR_TSLIMITS)
	{ TCP_BBR_TSLIMITS,                 "TCP_BBR_TSLIMITS"                },
#endif
#if defined(TCP_BBR_LOWGAIN_HALF)
	{ TCP_BBR_LOWGAIN_HALF,             "TCP_BBR_LOWGAIN_HALF"            },
#endif
#if defined(TCP_BBR_PACE_OH)
	{ TCP_BBR_PACE_OH,                  "TCP_BBR_PACE_OH"                 },
#endif
#if defined(TCP_BBR_LOWGAIN_FD)
	{ TCP_BBR_LOWGAIN_FD,               "TCP_BBR_LOWGAIN_FD"              },
#endif
#if defined(TCP_BBR_HOLD_TARGET)
	{ TCP_BBR_HOLD_TARGET,              "TCP_BBR_HOLD_TARGET"             },
#endif
#if defined(TCP_BBR_USEDEL_RATE)
	{ TCP_BBR_USEDEL_RATE,              "TCP_BBR_USEDEL_RATE"             },
#endif
#if defined(TCP_BBR_MIN_RTO)
	{ TCP_BBR_MIN_RTO,                  "TCP_BBR_MIN_RTO"                 },
#endif
#if defined(TCP_BBR_MAX_RTO)
	{ TCP_BBR_MAX_RTO,                  "TCP_BBR_MAX_RTO"                 },
#endif
#if defined(TCP_BBR_REC_OVER_HPTS)
	{ TCP_BBR_REC_OVER_HPTS,            "TCP_BBR_REC_OVER_HPTS"           },
#endif
#if defined(TCP_BBR_UNLIMITED)
	{ TCP_BBR_UNLIMITED,                "TCP_BBR_UNLIMITED"               },
#endif
#if defined(TCP_BBR_ALGORITHM)
	{ TCP_BBR_ALGORITHM,                "TCP_BBR_ALGORITHM"               },
#endif
#if defined(TCP_BBR_DRAIN_INC_EXTRA)
	{ TCP_BBR_DRAIN_INC_EXTRA,          "TCP_BBR_DRAIN_INC_EXTRA"         },
#endif
#if defined(TCP_BBR_STARTUP_EXIT_EPOCH)
	{ TCP_BBR_STARTUP_EXIT_EPOCH ,      "TCP_BBR_STARTUP_EXIT_EPOCH"      },
#endif
#if defined(TCP_BBR_PACE_PER_SEC)
	{ TCP_BBR_PACE_PER_SEC,             "TCP_BBR_PACE_PER_SEC"            },
#endif
#if defined(TCP_BBR_PACE_DEL_TAR)
	{ TCP_BBR_PACE_DEL_TAR,             "TCP_BBR_PACE_DEL_TAR"            },
#endif
#if defined(TCP_BBR_PACE_SEG_MAX)
	{ TCP_BBR_PACE_SEG_MAX,             "TCP_BBR_PACE_SEG_MAX"            },
#endif
#if defined(TCP_BBR_PACE_SEG_MIN)
	{ TCP_BBR_PACE_SEG_MIN,             "TCP_BBR_PACE_SEG_MIN"            },
#endif
#if defined(TCP_BBR_PACE_CROSS)
	{ TCP_BBR_PACE_CROSS,               "TCP_BBR_PACE_CROSS"              },
#endif
#if defined(TCP_RACK_IDLE_REDUCE_HIGH)
	{ TCP_RACK_IDLE_REDUCE_HIGH,        "TCP_RACK_IDLE_REDUCE_HIGH"       },
#endif
#if defined(TCP_RACK_MIN_PACE)
	{ TCP_RACK_MIN_PACE,                "TCP_RACK_MIN_PACE"               },
#endif
#if defined(TCP_RACK_MIN_PACE_SEG)
	{ TCP_RACK_MIN_PACE_SEG,            "TCP_RACK_MIN_PACE_SEG"           },
#endif
#if defined(TCP_RACK_GP_INCREASE)
	{ TCP_RACK_GP_INCREASE,             "TCP_RACK_GP_INCREASE"            },
#endif
#if defined(TCP_RACK_TLP_USE)
	{ TCP_RACK_TLP_USE,                 "TCP_RACK_TLP_USE"                },
#endif
#if defined(TCP_BBR_ACK_COMP_ALG)
	{ TCP_BBR_ACK_COMP_ALG,             "TCP_BBR_ACK_COMP_ALG"            },
#endif
#if defined(TCP_BBR_TMR_PACE_OH)
	{ TCP_BBR_TMR_PACE_OH,              "TCP_BBR_TMR_PACE_OH"             },
#endif
#if defined(TCP_BBR_EXTRA_GAIN)
	{ TCP_BBR_EXTRA_GAIN,               "TCP_BBR_EXTRA_GAIN"              },
#endif
#if defined(TCP_RACK_DO_DETECTION)
	{ TCP_RACK_DO_DETECTION,            "TCP_RACK_DO_DETECTION"           },
#endif
#if defined(TCP_BBR_RACK_RTT_USE)
	{ TCP_BBR_RACK_RTT_USE,             "TCP_BBR_RACK_RTT_USE"            },
#endif
#if defined(TCP_BBR_RETRAN_WTSO)
	{ TCP_BBR_RETRAN_WTSO,              "TCP_BBR_RETRAN_WTSO"             },
#endif
#if defined(TCP_DATA_AFTER_CLOSE)
	{ TCP_DATA_AFTER_CLOSE,             "TCP_DATA_AFTER_CLOSE"            },
#endif
#if defined(TCP_BBR_PROBE_RTT_GAIN)
	{ TCP_BBR_PROBE_RTT_GAIN,           "TCP_BBR_PROBE_RTT_GAIN"          },
#endif
#if defined(TCP_BBR_PROBE_RTT_LEN)
	{ TCP_BBR_PROBE_RTT_LEN,            "TCP_BBR_PROBE_RTT_LEN"           },
#endif
#if defined(TCP_BBR_SEND_IWND_IN_TSO)
	{ TCP_BBR_SEND_IWND_IN_TSO,         "TCP_BBR_SEND_IWND_IN_TSO"        },
#endif
#if defined(TCP_BBR_USE_RACK_RR)
	{ TCP_BBR_USE_RACK_RR,              "TCP_BBR_USE_RACK_RR"             },
#endif
#if defined(TCP_BBR_USE_RACK_CHEAT)
	{ TCP_BBR_USE_RACK_CHEAT,           "TCP_BBR_USE_RACK_CHEAT"          },
#endif
#if defined(TCP_BBR_HDWR_PACE)
	{ TCP_BBR_HDWR_PACE,                "TCP_BBR_HDWR_PACE"               },
#endif
#if defined(TCP_BBR_UTTER_MAX_TSO)
	{ TCP_BBR_UTTER_MAX_TSO,            "TCP_BBR_UTTER_MAX_TSO"           },
#endif
#if defined(TCP_BBR_EXTRA_STATE)
	{ TCP_BBR_EXTRA_STATE,              "TCP_BBR_EXTRA_STATE"             },
#endif
#if defined(TCP_BBR_FLOOR_MIN_TSO)
	{ TCP_BBR_FLOOR_MIN_TSO,            "TCP_BBR_FLOOR_MIN_TSO"           },
#endif
#if defined(TCP_BBR_MIN_TOPACEOUT)
	{ TCP_BBR_MIN_TOPACEOUT,            "TCP_BBR_MIN_TOPACEOUT"           },
#endif
#if defined(TCP_BBR_TSTMP_RAISES)
	{ TCP_BBR_TSTMP_RAISES,             "TCP_BBR_TSTMP_RAISES"            },
#endif
#if defined(TCP_BBR_POLICER_DETECT)
	{ TCP_BBR_POLICER_DETECT,           "TCP_BBR_POLICER_DETECT"          },
#endif
#if defined(TCP_BBR_RACK_INIT_RATE)
	{ TCP_BBR_RACK_INIT_RATE,           "TCP_BBR_RACK_INIT_RATE"          },
#endif
#if defined(TCP_RACK_RR_CONF)
	{ TCP_RACK_RR_CONF,                 "TCP_RACK_RR_CONF"                },
#endif
#if defined(TCP_RACK_CHEAT_NOT_CONF_RATE)
	{ TCP_RACK_CHEAT_NOT_CONF_RATE,     "TCP_RACK_CHEAT_NOT_CONF_RATE"    },
#endif
#if defined(TCP_RACK_GP_INCREASE_CA)
	{ TCP_RACK_GP_INCREASE_CA,          "TCP_RACK_GP_INCREASE_CA"         },
#endif
#if defined(TCP_RACK_GP_INCREASE_SS)
	{ TCP_RACK_GP_INCREASE_SS,          "TCP_RACK_GP_INCREASE_SS"         },
#endif
#if defined(TCP_RACK_GP_INCREASE_REC)
	{ TCP_RACK_GP_INCREASE_REC,         "TCP_RACK_GP_INCREASE_REC"        },
#endif
#if defined(TCP_RACK_FORCE_MSEG)
	{ TCP_RACK_FORCE_MSEG,              "TCP_RACK_FORCE_MSEG"             },
#endif
#if defined(TCP_RACK_PACE_RATE_CA)
	{ TCP_RACK_PACE_RATE_CA,            "TCP_RACK_PACE_RATE_CA"           },
#endif
#if defined(TCP_RACK_PACE_RATE_SS)
	{ TCP_RACK_PACE_RATE_SS,            "TCP_RACK_PACE_RATE_SS"           },
#endif
#if defined(TCP_RACK_PACE_RATE_REC)
	{ TCP_RACK_PACE_RATE_REC,           "TCP_RACK_PACE_RATE_REC"          },
#endif
#if defined(TCP_NO_PRR)
	{ TCP_NO_PRR,                       "TCP_NO_PRR"                      },
#endif
#if defined(TCP_RACK_NONRXT_CFG_RATE)
	{ TCP_RACK_NONRXT_CFG_RATE,         "TCP_RACK_NONRXT_CFG_RATE"        },
#endif
#if defined(TCP_SHARED_CWND_ENABLE)
	{ TCP_SHARED_CWND_ENABLE,           "TCP_SHARED_CWND_ENABLE"          },
#endif
#if defined(TCP_TIMELY_DYN_ADJ)
	{ TCP_TIMELY_DYN_ADJ,               "TCP_TIMELY_DYN_ADJ"              },
#endif
#if defined(TCP_RACK_NO_PUSH_AT_MAX)
	{ TCP_RACK_NO_PUSH_AT_MAX,          "TCP_RACK_NO_PUSH_AT_MAX"         },
#endif
#if defined(TCP_RACK_PACE_TO_FILL)
	{ TCP_RACK_PACE_TO_FILL,            "TCP_RACK_PACE_TO_FILL"           },
#endif
#if defined(TCP_SHARED_CWND_TIME_LIMIT)
	{ TCP_SHARED_CWND_TIME_LIMIT,       "TCP_SHARED_CWND_TIME_LIMIT"      },
#endif
#if defined(TCP_RACK_PROFILE)
	{ TCP_RACK_PROFILE,                 "TCP_RACK_PROFILE"                },
#endif
#if defined(TCP_HDWR_RATE_CAP)
	{ TCP_HDWR_RATE_CAP,                "TCP_HDWR_RATE_CAP"               },
#endif
#if defined(TCP_PACING_RATE_CAP)
	{ TCP_PACING_RATE_CAP,              "TCP_PACING_RATE_CAP"             },
#endif
#if defined(TCP_HDWR_UP_ONLY)
	{ TCP_HDWR_UP_ONLY,                 "TCP_HDWR_UP_ONLY"                },
#endif
#if defined(TCP_RACK_ABC_VAL)
	{ TCP_RACK_ABC_VAL,                 "TCP_RACK_ABC_VAL"                },
#endif
#if defined(TCP_REC_ABC_VAL)
	{ TCP_REC_ABC_VAL,                  "TCP_REC_ABC_VAL"                 },
#endif
#if defined(TCP_RACK_MEASURE_CNT)
	{ TCP_RACK_MEASURE_CNT,             "TCP_RACK_MEASURE_CNT"            },
#endif
#if defined(TCP_DEFER_OPTIONS)
	{ TCP_DEFER_OPTIONS,                "TCP_DEFER_OPTIONS"               },
#endif
#if defined(TCP_FAST_RSM_HACK)
	{ TCP_FAST_RSM_HACK,                "TCP_FAST_RSM_HACK"               },
#endif
#if defined(TCP_RACK_PACING_BETA)
	{ TCP_RACK_PACING_BETA,             "TCP_RACK_PACING_BETA"            },
#endif
#if defined(TCP_RACK_PACING_BETA_ECN)
	{ TCP_RACK_PACING_BETA_ECN,         "TCP_RACK_PACING_BETA_ECN"        },
#endif
#if defined(TCP_RACK_TIMER_SLOP)
	{ TCP_RACK_TIMER_SLOP,              "TCP_RACK_TIMER_SLOP"             },
#endif
#if defined(TCP_RACK_DSACK_OPT)
	{ TCP_RACK_DSACK_OPT,               "TCP_RACK_DSACK_OPT"              },
#endif
#if defined(TCP_RACK_ENABLE_HYSTART)
	{ TCP_RACK_ENABLE_HYSTART,          "TCP_RACK_ENABLE_HYSTART"         },
#endif
#if defined(TCP_RACK_SET_RXT_OPTIONS)
	{ TCP_RACK_SET_RXT_OPTIONS,         "TCP_RACK_SET_RXT_OPTIONS"        },
#endif
#if defined(TCP_RACK_HI_BETA)
	{ TCP_RACK_HI_BETA,                 "TCP_RACK_HI_BETA"                },
#endif
#if defined(TCP_RACK_SPLIT_LIMIT)
	{ TCP_RACK_SPLIT_LIMIT,             "TCP_RACK_SPLIT_LIMIT"            },
#endif
#if defined(TCP_RACK_PACING_DIVISOR)
	{ TCP_RACK_PACING_DIVISOR,          "TCP_RACK_PACING_DIVISOR"         },
#endif
#if defined(TCP_RACK_PACE_MIN_SEG)
	{ TCP_RACK_PACE_MIN_SEG,            "TCP_RACK_PACE_MIN_SEG"           },
#endif
#if defined(TCP_RACK_DGP_IN_REC)
	{ TCP_RACK_DGP_IN_REC,              "TCP_RACK_DGP_IN_REC"             },
#endif
#if defined(TCP_RXT_CLAMP)
	{ TCP_RXT_CLAMP,                    "TCP_RXT_CLAMP"                   },
#endif
#if defined(TCP_HYBRID_PACING)
	{ TCP_HYBRID_PACING,                "TCP_HYBRID_PACING"               },
#endif
#if defined(TCP_PACING_DND)
	{ TCP_PACING_DND,                   "TCP_PACING_DND"                  },
#endif

	/* /usr/include/netinet/tcp_log_buf.h */
#if defined(TCP_LOG)
	/* The following constants are enum tcp_log_states. */
	{ TCP_LOG_STATE_CLEAR,              "TCP_LOG_STATE_CLEAR"             },
	{ TCP_LOG_STATE_OFF,                "TCP_LOG_STATE_OFF"               },
	{ TCP_LOG_STATE_TAIL,               "TCP_LOG_STATE_TAIL"              },
	{ TCP_LOG_STATE_HEAD,               "TCP_LOG_STATE_HEAD"              },
	{ TCP_LOG_STATE_HEAD_AUTO,          "TCP_LOG_STATE_HEAD_AUTO"         },
	{ TCP_LOG_STATE_CONTINUAL,          "TCP_LOG_STATE_CONTINUAL"         },
	{ TCP_LOG_STATE_TAIL_AUTO,          "TCP_LOG_STATE_TAIL_AUTO"         },
#if __FreeBSD_version >= 1400000
	{ TCP_LOG_VIA_BBPOINTS,             "TCP_LOG_VIA_BBPOINTS"            },
#endif
#endif

#if defined(UDPLITE_RECV_CSCOV) && defined(UDPLITE_SEND_CSCOV)
	/* /usr/include/netinet/udplite.h */
	{ UDPLITE_RECV_CSCOV,               "UDPLITE_RECV_CSCOV"              },
	{ UDPLITE_SEND_CSCOV,               "UDPLITE_SEND_CSCOV"              },
#endif

	/* /usr/include/sys/fcntl.h */
	{ O_RDONLY,                         "O_RDONLY"                        },
	{ O_WRONLY,                         "O_WRONLY"                        },
	{ O_RDWR,                           "O_RDWR"                          },
	{ O_ACCMODE,                        "O_ACCMODE"                       },
	{ FREAD,                            "FREAD"                           },
	{ FWRITE,                           "FWRITE"                          },
	{ O_NONBLOCK,                       "O_NONBLOCK"                      },
	{ O_APPEND,                         "O_APPEND"                        },
	{ O_SHLOCK,                         "O_SHLOCK"                        },
	{ O_EXLOCK,                         "O_EXLOCK"                        },
	{ O_ASYNC,                          "O_ASYNC"                         },
	{ O_FSYNC,                          "O_FSYNC"                         },
	{ O_SYNC,                           "O_SYNC"                          },
	{ O_NOFOLLOW,                       "O_NOFOLLOW"                      },
	{ O_CREAT,                          "O_CREAT"                         },
	{ O_TRUNC,                          "O_TRUNC"                         },
	{ O_EXCL,                           "O_EXCL"                          },
	{ O_NOCTTY,                         "O_NOCTTY"                        },
	{ O_DIRECT,                         "O_DIRECT"                        },
	{ O_DIRECTORY,                      "O_DIRECTORY"                     },
	{ O_EXEC,                           "O_EXEC"                          },
	{ O_TTY_INIT,                       "O_TTY_INIT"                      },
	{ O_CLOEXEC,                        "O_CLOEXEC"                       },
	{ FAPPEND,                          "FAPPEND"                         },
	{ FASYNC,                           "FASYNC"                          },
	{ FFSYNC,                           "FFSYNC"                          },
	{ FNONBLOCK,                        "FNONBLOCK"                       },
	{ FNDELAY,                          "FNDELAY"                         },
	{ O_NDELAY,                         "O_NDELAY"                        },
	{ FRDAHEAD,                         "FRDAHEAD"                        },
	{ AT_FDCWD,                         "AT_FDCWD"                        },
	{ AT_EACCESS,                       "AT_EACCESS"                      },
	{ AT_SYMLINK_NOFOLLOW,              "AT_SYMLINK_NOFOLLOW"             },
	{ AT_SYMLINK_FOLLOW,                "AT_SYMLINK_FOLLOW"               },
	{ AT_REMOVEDIR,                     "AT_REMOVEDIR"                    },
	{ F_DUPFD,                          "F_DUPFD"                         },
	{ F_GETFD,                          "F_GETFD"                         },
	{ F_SETFD,                          "F_SETFD"                         },
	{ F_GETFL,                          "F_GETFL"                         },
	{ F_SETFL,                          "F_SETFL"                         },
	{ F_GETOWN,                         "F_GETOWN"                        },
	{ F_SETOWN,                         "F_SETOWN"                        },
	{ F_OGETLK,                         "F_OGETLK"                        },
	{ F_OSETLK,                         "F_OSETLK"                        },
	{ F_OSETLKW,                        "F_OSETLKW"                       },
	{ F_DUP2FD,                         "F_DUP2FD"                        },
	{ F_GETLK,                          "F_GETLK"                         },
	{ F_SETLK,                          "F_SETLK"                         },
	{ F_SETLKW,                         "F_SETLKW"                        },
	{ F_SETLK_REMOTE,                   "F_SETLK_REMOTE"                  },
	{ F_READAHEAD,                      "F_READAHEAD"                     },
	{ F_RDAHEAD,                        "F_RDAHEAD"                       },
	{ FD_CLOEXEC,                       "FD_CLOEXEC"                      },
	{ F_RDLCK,                          "F_RDLCK"                         },
	{ F_UNLCK,                          "F_UNLCK"                         },
	{ F_WRLCK,                          "F_WRLCK"                         },
	{ F_UNLCKSYS,                       "F_UNLCKSYS"                      },
	{ F_CANCEL,                         "F_CANCEL"                        },
	{ LOCK_SH,                          "LOCK_SH"                         },
	{ LOCK_EX,                          "LOCK_EX"                         },
	{ LOCK_NB,                          "LOCK_NB"                         },
	{ LOCK_UN,                          "LOCK_UN"                         },
	{ SF_NODISKIO,                      "SF_NODISKIO"                     },
	{ SF_MNOWAIT,                       "SF_MNOWAIT"                      },
#ifdef SF_NOCACHE
	{ SF_NOCACHE,                       "SF_NOCACHE"                      },
#endif
	{ SF_SYNC,                          "SF_SYNC"                         },

	/* /usr/include/sys/unistd.h */
	{ SEEK_SET,                         "SEEK_SET"                        },
	{ SEEK_CUR,                         "SEEK_CUR"                        },
	{ SEEK_END,                         "SEEK_END"                        },

	/* /usr/include/sys/socket.h */
	{ MSG_OOB,                          "MSG_OOB"                         },
	{ MSG_PEEK,                         "MSG_PEEK"                        },
	{ MSG_DONTROUTE,                    "MSG_DONTROUTE"                   },
	{ MSG_EOR,                          "MSG_EOR"                         },
	{ MSG_TRUNC,                        "MSG_TRUNC"                       },
	{ MSG_CTRUNC,                       "MSG_CTRUNC"                      },
	{ MSG_WAITALL,                      "MSG_WAITALL"                     },
	{ MSG_NOTIFICATION,                 "MSG_NOTIFICATION"                },
	{ MSG_DONTWAIT,                     "MSG_DONTWAIT"                    },
	{ MSG_EOF,                          "MSG_EOF"                         },
	{ MSG_NBIO,                         "MSG_NBIO"                        },
	{ MSG_COMPAT,                       "MSG_COMPAT"                      },
	{ MSG_NOSIGNAL,                     "MSG_NOSIGNAL"                    },

	/* /usr/include/sys/filio.h */
	{ FIOCLEX,                          "FIOCLEX"                         },
	{ FIONCLEX,                         "FIONCLEX"                        },
	{ FIONREAD,                         "FIONREAD"                        },
	{ FIONBIO,                          "FIONBIO"                         },
	{ FIOASYNC,                         "FIOASYNC"                        },
	{ FIOSETOWN,                        "FIOSETOWN"                       },
	{ FIOGETOWN,                        "FIOGETOWN"                       },
	{ FIODTYPE,                         "FIODTYPE"                        },
	{ FIOGETLBA,                        "FIOGETLBA"                       },
	{ FIODGNAME,                        "FIODGNAME"                       },
	{ FIONWRITE,                        "FIONWRITE"                       },
	{ FIONSPACE,                        "FIONSPACE"                       },
	{ FIOSEEKDATA,                      "FIOSEEKDATA"                     },
	{ FIOSEEKHOLE,                      "FIOSEEKHOLE"                     },

	/* /usr/include/sys/poll.h */
	{ POLLIN,                           "POLLIN"                          },
	{ POLLPRI,                          "POLLPRI"                         },
	{ POLLOUT,                          "POLLOUT"                         },
	{ POLLRDNORM,                       "POLLRDNORM"                      },
	{ POLLWRNORM,                       "POLLWRNORM"                      },
	{ POLLRDBAND,                       "POLLRDBAND"                      },
	{ POLLWRBAND,                       "POLLWRBAND"                      },
	{ POLLINIGNEOF,                     "POLLINIGNEOF"                    },
	{ POLLERR,                          "POLLERR"                         },
	{ POLLHUP,                          "POLLHUP"                         },
	{ POLLNVAL,                         "POLLNVAL"                        },

	/* /usr/include/sys/errno.h */
	{ EPERM,                            "EPERM"                           },
	{ ENOENT,                           "ENOENT"                          },
	{ ESRCH,                            "ESRCH"                           },
	{ EINTR,                            "EINTR"                           },
	{ EIO,                              "EIO"                             },
	{ ENXIO,                            "ENXIO"                           },
	{ E2BIG,                            "E2BIG"                           },
	{ ENOEXEC,                          "ENOEXEC"                         },
	{ EBADF,                            "EBADF"                           },
	{ ECHILD,                           "ECHILD"                          },
	{ EDEADLK,                          "EDEADLK"                         },
	{ ENOMEM,                           "ENOMEM"                          },
	{ EACCES,                           "EACCES"                          },
	{ EFAULT,                           "EFAULT"                          },
	{ ENOTBLK,                          "ENOTBLK"                         },
	{ EBUSY,                            "EBUSY"                           },
	{ EEXIST,                           "EEXIST"                          },
	{ EXDEV,                            "EXDEV"                           },
	{ ENODEV,                           "ENODEV"                          },
	{ ENOTDIR,                          "ENOTDIR"                         },
	{ EISDIR,                           "EISDIR"                          },
	{ EINVAL,                           "EINVAL"                          },
	{ ENFILE,                           "ENFILE"                          },
	{ EMFILE,                           "EMFILE"                          },
	{ ENOTTY,                           "ENOTTY"                          },
	{ ETXTBSY,                          "ETXTBSY"                         },
	{ EFBIG,                            "EFBIG"                           },
	{ ENOSPC,                           "ENOSPC"                          },
	{ ESPIPE,                           "ESPIPE"                          },
	{ EROFS,                            "EROFS"                           },
	{ EMLINK,                           "EMLINK"                          },
	{ EPIPE,                            "EPIPE"                           },
	{ EDOM,                             "EDOM"                            },
	{ ERANGE,                           "ERANGE"                          },
	{ EAGAIN,                           "EAGAIN"                          },
	{ EWOULDBLOCK,                      "EWOULDBLOCK"                     },
	{ EINPROGRESS,                      "EINPROGRESS"                     },
	{ EALREADY,                         "EALREADY"                        },
	{ ENOTSOCK,                         "ENOTSOCK"                        },
	{ EDESTADDRREQ,                     "EDESTADDRREQ"                    },
	{ EMSGSIZE,                         "EMSGSIZE"                        },
	{ EPROTOTYPE,                       "EPROTOTYPE"                      },
	{ ENOPROTOOPT,                      "ENOPROTOOPT"                     },
	{ EPROTONOSUPPORT,                  "EPROTONOSUPPORT"                 },
	{ ESOCKTNOSUPPORT,                  "ESOCKTNOSUPPORT"                 },
	{ EOPNOTSUPP,                       "EOPNOTSUPP"                      },
	{ ENOTSUP,                          "ENOTSUP"                         },
	{ EPFNOSUPPORT,                     "EPFNOSUPPORT"                    },
	{ EAFNOSUPPORT,                     "EAFNOSUPPORT"                    },
	{ EADDRINUSE,                       "EADDRINUSE"                      },
	{ EADDRNOTAVAIL,                    "EADDRNOTAVAIL"                   },
	{ ENETDOWN,                         "ENETDOWN"                        },
	{ ENETUNREACH,                      "ENETUNREACH"                     },
	{ ENETRESET,                        "ENETRESET"                       },
	{ ECONNABORTED,                     "ECONNABORTED"                    },
	{ ECONNRESET,                       "ECONNRESET"                      },
	{ ENOBUFS,                          "ENOBUFS"                         },
	{ EISCONN,                          "EISCONN"                         },
	{ ENOTCONN,                         "ENOTCONN"                        },
	{ ESHUTDOWN,                        "ESHUTDOWN"                       },
	{ ETOOMANYREFS,                     "ETOOMANYREFS"                    },
	{ ETIMEDOUT,                        "ETIMEDOUT"                       },
	{ ECONNREFUSED,                     "ECONNREFUSED"                    },
	{ ELOOP,                            "ELOOP"                           },
	{ ENAMETOOLONG,                     "ENAMETOOLONG"                    },
	{ EHOSTDOWN,                        "EHOSTDOWN"                       },
	{ EHOSTUNREACH,                     "EHOSTUNREACH"                    },
	{ ENOTEMPTY,                        "ENOTEMPTY"                       },
	{ EPROCLIM,                         "EPROCLIM"                        },
	{ EUSERS,                           "EUSERS"                          },
	{ EDQUOT,                           "EDQUOT"                          },
	{ ESTALE,                           "ESTALE"                          },
	{ EREMOTE,                          "EREMOTE"                         },
	{ EBADRPC,                          "EBADRPC"                         },
	{ ERPCMISMATCH,                     "ERPCMISMATCH"                    },
	{ EPROGUNAVAIL,                     "EPROGUNAVAIL"                    },
	{ EPROGMISMATCH,                    "EPROGMISMATCH"                   },
	{ EPROCUNAVAIL,                     "EPROCUNAVAIL"                    },
	{ ENOLCK,                           "ENOLCK"                          },
	{ ENOSYS,                           "ENOSYS"                          },
	{ EFTYPE,                           "EFTYPE"                          },
	{ EAUTH,                            "EAUTH"                           },
	{ ENEEDAUTH,                        "ENEEDAUTH"                       },
	{ EIDRM,                            "EIDRM"                           },
	{ ENOMSG,                           "ENOMSG"                          },
	{ EOVERFLOW,                        "EOVERFLOW"                       },
	{ ECANCELED,                        "ECANCELED"                       },
	{ EILSEQ,                           "EILSEQ"                          },
	{ ENOATTR,                          "ENOATTR"                         },
	{ EDOOFUS,                          "EDOOFUS"                         },
	{ EBADMSG,                          "EBADMSG"                         },
	{ EMULTIHOP,                        "EMULTIHOP"                       },
	{ ENOLINK,                          "ENOLINK"                         },
	{ EPROTO,                           "EPROTO"                          },
	{ ENOTCAPABLE,                      "ENOTCAPABLE"                     },
#ifdef ECAPMODE
	{ ECAPMODE,                         "ECAPMODE"                        },
#endif

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

struct int_symbol *platform_symbols(void)
{
	return platform_symbols_table;
}

#endif  /* __FreeBSD__ */
