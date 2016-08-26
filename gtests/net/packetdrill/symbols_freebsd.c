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
	{ SO_USER_COOKIE,                   "SO_USER_COOKIE"                  },

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
	/* The following constants are from
	 * https://tools.ietf.org/html/draft-ietf-tsvwg-sctp-ndata-04
	 * The old symbols currently being deployed are also provided.
	 */
	{ SCTP_PLUGGABLE_SS,                "SCTP_PLUGGABLE_SS"               },
	{ SCTP_SS_VALUE,                    "SCTP_SS_VALUE"                   },
	{ SCTP_SS_DEFAULT,                  "SCTP_SS_DEFAULT"                 },
	{ SCTP_SS_ROUND_ROBIN,              "SCTP_SS_ROUND_ROBIN"             },
	{ SCTP_SS_ROUND_ROBIN_PACKET,       "SCTP_SS_ROUND_ROBIN_PACKET"      },
	{ SCTP_SS_PRIORITY,                 "SCTP_SS_PRIORITY"                },
	/* The following is a typo in FreeBSD's sctp.h */
	{ SCTP_SS_FAIR_BANDWITH,            "SCTP_SS_FAIR_BANDWITH"           },
	{ SCTP_SS_FIRST_COME,               "SCTP_SS_FIRST_COME"              },
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
#if defined(SCTP_SS_RR_INTER)
	{ SCTP_SS_RR_INTER,                 "SCTP_SS_RR_INTER"                },
#endif
#if defined(SCTP_SS_RR_PKT_INTER)
	{ SCTP_SS_RR_PKT_INTER,             "SCTP_SS_RR_PKT_INTER"            },
#endif
#if defined(SCTP_SS_PRIO_INTER)
	{ SCTP_SS_PRIO_INTER,               "SCTP_SS_PRIO_INTER"              },
#endif
#if defined(SCTP_SS_FB_INTER)
	{ SCTP_SS_FB_INTER,                 "SCTP_SS_FB_INTER"                },
#endif
#if defined(SCTP_SS_WFQ_INTER)
	{ SCTP_SS_WFQ_INTER,                "SCTP_SS_WFQ_INTER"               },
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
	{ TCP_CONGESTION,                   "TCP_CONGESTION"                  },
#if __FreeBSD_version >=1100000
	{ TCP_CCALGOOPT,                    "TCP_CCALGOOPT"                   },
#endif
	{ TCP_KEEPINIT,                     "TCP_KEEPINIT"                    },
	{ TCP_KEEPIDLE,                     "TCP_KEEPIDLE"                    },
	{ TCP_KEEPINTVL,                    "TCP_KEEPINTVL"                   },
	{ TCP_KEEPCNT,                      "TCP_KEEPCNT"                     },
#if __FreeBSD_version >= 1003000
	{ TCP_FASTOPEN,                     "TCP_FASTOPEN"                    },
#endif

#if __FreeBSD_version >= 1002000
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
	{ ECAPMODE,                         "ECAPMODE"                        },

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

struct int_symbol *platform_symbols(void)
{
	return platform_symbols_table;
}

#endif  /* __FreeBSD__ */
