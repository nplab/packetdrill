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
 * Type definitions for data structures to represent a parsed test script.
 */

#ifndef __SCRIPT_H__
#define __SCRIPT_H__

#include "types.h"

#include <sys/time.h>
#include "packet.h"

/* The types of expressions in a script */
enum expression_t {
	EXPR_NONE,
	EXPR_NULL,	          /* Expression to handle NULL */
	EXPR_ELLIPSIS,		  /* ... but no value */
	EXPR_INTEGER,		  /* integer in 'num' */
	EXPR_LINGER,		  /* struct linger for SO_LINGER */
	EXPR_WORD,		  /* unquoted word in 'string' */
	EXPR_STRING,		  /* double-quoted string in 'string' */
	EXPR_SOCKET_ADDRESS_IPV4, /* sockaddr_in in 'socket_address_ipv4' */
	EXPR_SOCKET_ADDRESS_IPV6, /* sockaddr_in6 in 'socket_address_ipv6' */
	EXPR_BINARY,		  /* binary expression, 2 sub-expressions */
	EXPR_LIST,		  /* list of expressions */
	EXPR_IOVEC,		  /* expression tree for an iovec struct */
	EXPR_MSGHDR,		  /* expression tree for a msghdr struct */
	EXPR_CMSGHDR,             /* expression tree for a cmsghdr struct */
	EXPR_POLLFD,		  /* expression tree for a pollfd struct */
	EXPR_SCTP_RTOINFO,	  /* struct sctp_rtoinfo for SCTP_RTOINFO */
	EXPR_SCTP_INITMSG,	  /* struct sctp_initmsg for SCTP_INITMSG */
	EXPR_SCTP_ASSOC_VALUE,	  /* struct sctp_assoc_value */
	EXPR_SCTP_SACKINFO,	  /* struct sctp_sack_info_expr for */
	EXPR_SCTP_STATUS,	  /* struct sctp_status for SCTP_STATUS */
	EXPR_SCTP_PADDRINFO,
	EXPR_SCTP_STREAM_VALUE,	  /* struct sctp_stream_value for SCTP_SS_VALUE */
	EXPR_SCTP_PEER_ADDR_PARAMS,	 /* struct for sctp_paddrparams for SCTP_PEER_ADDR_PARAMS */
	EXPR_SCTP_ASSOCPARAMS,    /* struct sctp_assocparams for SCTP_ASSOCINFO */
	EXPR_SCTP_EVENT,	  /* struct sctp_event for SCTP_EVENT */
	EXPR_SCTP_EVENT_SUBSCRIBE,/* struct sctp_event_subscribe for SCTP_EVENTS */
	EXPR_SCTP_SNDINFO,	  /* struct sctp_sndinfo for SCTP_DEFAULT_SNDINFO */
	EXPR_SCTP_SETPRIM,        /* expression tree for sctp_setprim SCTP_PRIMARY_ADDR */
	EXPR_SCTP_SETADAPTATION,  /* struct sctp_setadaptation for SCTP_ADATTATION_LAYER */
	EXPR_SCTP_SNDRCVINFO,     /* struct sctp_sndrcvinfo for syscall sctp_recvmsg */
	EXPR_SCTP_PRINFO,	  /* struct sctp_prinfo for syscall sctp_sendv */
	EXPR_SCTP_DEFAULT_PRINFO, /* expression tree for struct sctp_default_prinfo for syscall [gs]etsockopt */
	EXPR_SCTP_AUTHINFO,	  /* struct sctp_authinfo for syscall sctp_sendv */
	EXPR_SCTP_SENDV_SPA,	  /* struct sctp_sendv_spa for syscall sctp_sendv */
	EXPR_SCTP_RCVINFO,        /* struct sctp_rcvinfo for syscall sctp_recvv */
	EXPR_SCTP_NXTINFO,        /* struct sctp_nxtinfo for syscall sctp_recvv */
	EXPR_SCTP_RECVV_RN,       /* struct sctp_recvv_rn for syscall sctp_recvv */
	EXPR_SCTP_ASSOC_CHANGE,   /* expression tree for sctp_assoc_change_event */
	EXPR_SCTP_PADDR_CHANGE,   /* expression tree for sctp_peer_addr_change */
	EXPR_SCTP_REMOTE_ERROR,   /* expression tree for sctp_remote_error_event */
	EXPR_SCTP_SEND_FAILED,     /* expression tree for sctp_send_failed event (DEPRICATED) */
	EXPR_SCTP_SHUTDOWN_EVENT, /* expression tree for sctp_shutdown_event */
	EXPR_SCTP_ADAPTATION_EVENT, /* expression tree for sctp_adaptation_event */
	EXPR_SCTP_PDAPI_EVENT,    /* expression tree for sctp_partial_delivery_event */
	EXPR_SCTP_AUTHKEY_EVENT,  /* expression tree for sctp_authentication_event */
	EXPR_SCTP_SENDER_DRY_EVENT, /* expression tree for sctp_sender_dry_event */
	EXPR_SCTP_SEND_FAILED_EVENT, /* expression tree for sctp_send_failed_event */
	EXPR_SCTP_TLV,            /* expression tree for sctp_notifications_stopped_event */
	EXPR_SCTP_EXTRCVINFO,     /* expression tree for sctp_extrcvinfo struct in cmsghdr */
	NUM_EXPR_TYPES,
};
/* Convert an expression type to a human-readable string */
const char *expression_type_to_string(enum expression_t type);

/* An expression in a script */
struct expression {
	enum expression_t type;
	union {
		s64 num;
		char *string;
		struct linger_expr *linger;
		struct sockaddr_in *socket_address_ipv4;
		struct sockaddr_in6 *socket_address_ipv6;
		struct binary_expression *binary;
		struct expression_list *list;
		struct iovec_expr *iovec;
		struct msghdr_expr *msghdr;
		struct cmsghdr_expr *cmsghdr;
		struct pollfd_expr *pollfd;
		struct sctp_rtoinfo_expr *sctp_rtoinfo;
		struct sctp_initmsg_expr *sctp_initmsg;
		struct sctp_assoc_value_expr *sctp_assoc_value;
		struct sctp_sack_info_expr *sctp_sack_info;
		struct sctp_status_expr *sctp_status;
		struct sctp_paddrinfo_expr *sctp_paddrinfo;
		struct sctp_paddrparams_expr *sctp_paddrparams;
		struct sctp_stream_value_expr *sctp_stream_value;
		struct sctp_assocparams_expr *sctp_assocparams;
		struct sctp_event_expr *sctp_event;
		struct sctp_event_subscribe_expr *sctp_event_subscribe;
		struct sctp_sndinfo_expr *sctp_sndinfo;
		struct sctp_setprim_expr *sctp_setprim;
		struct sctp_setadaptation_expr *sctp_setadaptation;
		struct sctp_sndrcvinfo_expr *sctp_sndrcvinfo;
		struct sctp_prinfo_expr *sctp_prinfo;
		struct sctp_default_prinfo_expr *sctp_default_prinfo;
		struct sctp_authinfo_expr *sctp_authinfo;
		struct sctp_sendv_spa_expr *sctp_sendv_spa;
		struct sctp_rcvinfo_expr *sctp_rcvinfo;
		struct sctp_nxtinfo_expr *sctp_nxtinfo;
		struct sctp_recvv_rn_expr *sctp_recvv_rn;
		struct sctp_assoc_change_expr *sctp_assoc_change;
		struct sctp_paddr_change_expr *sctp_paddr_change;
		struct sctp_remote_error_expr *sctp_remote_error;
		struct sctp_send_failed_expr *sctp_send_failed;
		struct sctp_shutdown_event_expr *sctp_shutdown_event;
		struct sctp_adaptation_event_expr *sctp_adaptation_event;
		struct sctp_pdapi_event_expr *sctp_pdapi_event;
		struct sctp_authkey_event_expr *sctp_authkey_event;
		struct sctp_sender_dry_event_expr *sctp_sender_dry_event;
		struct sctp_send_failed_event_expr *sctp_send_failed_event;
		struct sctp_tlv_expr *sctp_tlv;
		struct sctp_extrcvinfo_expr *sctp_extrcvinfo;
	} value;
	const char *format;	/* the printf format for printing the value */
};

/* Two expressions combined via a binary operator */
struct binary_expression {
	char *op;			/* binary operator */
	struct expression *lhs;	/* left hand side expression */
	struct expression *rhs;	/* right hand side expression */
};

/* A list of expressions, e.g. a list of actual parameters in function call,
 * or list of elements in an array.
 */
struct expression_list {
	struct expression *expression;
	struct expression_list *next;
};

/* Parse tree for a iovec struct in a writev/readv/sendmsg/recvmsg syscall. */
struct iovec_expr {
	struct expression *iov_base;
	struct expression *iov_len;
};

/* Parse tree for a msghdr struct in a sendmsg/recvmsg syscall. */
struct msghdr_expr {
	struct expression *msg_name;
	struct expression *msg_namelen;
	struct expression *msg_iov;
	struct expression *msg_iovlen;
	struct expression *msg_control;
	struct expression *msg_controllen;
	struct expression *msg_flags;
};

/* Parse tree for a cmsghdr struct in a struct msghdr. */
struct cmsghdr_expr {
	struct expression *cmsg_len;
	struct expression *cmsg_level;
	struct expression *cmsg_type;
	struct expression *cmsg_data;
};

/* Parse tree for a pollfd struct in a poll syscall. */
struct pollfd_expr {
	struct expression *fd;		/* file descriptor */
	struct expression *events;	/* requested events */
	struct expression *revents;	/* returned events */
};

/* Handle values for socketoption SO_Linger with inputtypes and values*/
struct linger_expr {
	struct expression *l_onoff;
	struct expression *l_linger;
};

/* Parse tree for a sctp_rtoinfo struct in a [gs]etsockopt syscall. */
struct sctp_rtoinfo_expr {
	struct expression *srto_assoc_id;
	struct expression *srto_initial;
	struct expression *srto_max;
	struct expression *srto_min;
};

/* Parse tree for a sctp_initmsg struct in a [gs]etsockopt syscall. */
struct sctp_initmsg_expr {
	struct expression *sinit_num_ostreams;
	struct expression *sinit_max_instreams;
	struct expression *sinit_max_attempts;
	struct expression *sinit_max_init_timeo;
};

/* Parse tree for a sctp_assoc_value struct in a [gs]etsockopt syscall. */
struct sctp_assoc_value_expr {
	struct expression *assoc_id;
	struct expression *assoc_value;
};

/* Parse tree for a sctp_stream_value struct in a [gs]etsockopt syscall. */
struct sctp_stream_value_expr {
	struct expression *stream_id;
	struct expression *stream_value;
};

/* Parse tree for a sctp_sack_info struct in a [gs]etsockopt syscall. */
struct sctp_sack_info_expr {
	struct expression *sack_assoc_id;
	struct expression *sack_delay;
	struct expression *sack_freq;
};

/* Parse tree for a sctp_status struct in a [gs]etsockopt syscall. */
struct sctp_status_expr {
	struct expression *sstat_assoc_id;
	struct expression *sstat_state;
	struct expression *sstat_rwnd;
	struct expression *sstat_unackdata;
	struct expression *sstat_penddata;
	struct expression *sstat_instrms;
	struct expression *sstat_outstrms;
	struct expression *sstat_fragmentation_point;
	struct expression *sstat_primary;
};

/* Parse tree for a sctp_paddrinfo struct in a [gs]etsockopt syscall. */
struct sctp_paddrinfo_expr {
	struct expression *spinfo_address;
	struct expression *spinfo_state;
	struct expression *spinfo_cwnd;
	struct expression *spinfo_srtt;
	struct expression *spinfo_rto;
	struct expression *spinfo_mtu;
};

/* Parse tree for a sctp_paddrparams struct in a [gs]etsockopt syscall. */
struct sctp_paddrparams_expr {
	struct expression *spp_assoc_id;
	struct expression *spp_address;
	struct expression *spp_hbinterval;
	struct expression *spp_pathmaxrxt;
	struct expression *spp_pathmtu;
	struct expression *spp_flags;
	struct expression *spp_ipv6_flowlabel;
	struct expression *spp_dscp;
};

/* Parse tree for sctp_assocparams struct in [gs]etsockopt syscall. */
struct sctp_assocparams_expr {
	struct expression *sasoc_assoc_id;
	struct expression *sasoc_asocmaxrxt;
	struct expression *sasoc_number_peer_destinations;
	struct expression *sasoc_peer_rwnd;
	struct expression *sasoc_local_rwnd;
	struct expression *sasoc_cookie_life;
};

/* Parse tree for sctp_event struct in [gs]etsockopt syscall. */
struct sctp_event_expr {
	struct expression *se_assoc_id;
	struct expression *se_type;
	struct expression *se_on;
};

/* Parse tree for sctp_event_subscribe struct in [gs]etsockopt syscall. */
struct sctp_event_subscribe_expr {
	struct expression *sctp_data_io_event;
	struct expression *sctp_association_event;
	struct expression *sctp_address_event;
	struct expression *sctp_send_failure_event;
	struct expression *sctp_peer_error_event;
	struct expression *sctp_shutdown_event;
	struct expression *sctp_partial_delivery_event;
	struct expression *sctp_adaptation_layer_event;
	struct expression *sctp_authentication_event;
	struct expression *sctp_sender_dry_event;
};

/* Parse tree for sctp_sndinfo struct in [gs]etsockopt syscall. */
struct sctp_sndinfo_expr {
	struct expression *snd_sid;
	struct expression *snd_flags;
	struct expression *snd_ppid;
	struct expression *snd_context;
	struct expression *snd_assoc_id;
};

/* Parse tree for sctp_setadaptation struct in [gs]etsockopt syscall. */
struct sctp_setprim_expr {
	struct expression *ssp_assoc_id;
	struct expression *ssp_addr;
};

/* Parse tree for sctp_setadaptation struct in [gs]etsockopt syscall. */
struct sctp_setadaptation_expr {
	struct expression *ssb_adaptation_ind;
};

/* Parse tree for sctp_sndrcvinfo in sctp_recvmsg syscall. */
struct sctp_sndrcvinfo_expr {
	struct expression *sinfo_stream;
	struct expression *sinfo_ssn;
	struct expression *sinfo_flags;
	struct expression *sinfo_ppid;
	struct expression *sinfo_context;
	struct expression *sinfo_timetolive;
	struct expression *sinfo_tsn;
	struct expression *sinfo_cumtsn;
	struct expression *sinfo_assoc_id;
};

/* Parse tree for sctp_prinfo in sctp_sendv syscall. */
struct sctp_prinfo_expr {
	struct expression *pr_policy;
	struct expression *pr_value;
};

/* Parse tree for sctp_default_prinfo in [gs]etsockopt syscall. */
struct sctp_default_prinfo_expr {
	struct expression *pr_policy;
	struct expression *pr_value;
	struct expression *pr_assoc_id;
};

/* Parse tree for sctp_authinfo in sctp_sendv syscall. */
struct sctp_authinfo_expr {
	struct expression *auth_keynumber;
};

/* Parse tree for sctp_sendv_spa in sctp_sendv syscall. */
struct sctp_sendv_spa_expr {
	struct expression *sendv_flags;
	struct expression *sendv_sndinfo;
	struct expression *sendv_prinfo;
	struct expression *sendv_authinfo;
};

/* Parse tree for sctp_rcvinfo in sctp_recvv syscall. */
struct sctp_rcvinfo_expr {
	struct expression *rcv_sid;
	struct expression *rcv_ssn;
	struct expression *rcv_flags;
	struct expression *rcv_ppid;
	struct expression *rcv_tsn;
	struct expression *rcv_cumtsn;
	struct expression *rcv_context;
	struct expression *rcv_assoc_id;
};

/* Parse tree for sctp_nxtinfo in sctp_recvv syscall. */
struct sctp_nxtinfo_expr {
	struct expression *nxt_sid;
	struct expression *nxt_flags;
	struct expression *nxt_ppid;
	struct expression *nxt_length;
	struct expression *nxt_assoc_id;
};

/* Parse tree for sctp_recvv_rn in sctp_recvv syscall. */
struct sctp_recvv_rn_expr {
	struct expression *recvv_rcvinfo;
	struct expression *recvv_nxtinfo;
};

/* Parse tree for sctp_assoc_change for notifications. */
struct sctp_assoc_change_expr {
	struct expression *sac_type;
	struct expression *sac_flags;
	struct expression *sac_length;
	struct expression *sac_state;
	struct expression *sac_error;
	struct expression *sac_outbound_streams;
	struct expression *sac_inbound_streams;
	struct expression *sac_assoc_id;
	struct expression *sac_info;
};

/* Parse tree for sctp_paddr_change for notifications. */
struct sctp_paddr_change_expr {
	struct expression *spc_type;
	struct expression *spc_flags;
	struct expression *spc_length;
	struct expression *spc_aaddr;
	struct expression *spc_state;
	struct expression *spc_error;
	struct expression *spc_assoc_id;
};

/* Parse tree for sctp_remote_error_event for notifications. */
struct sctp_remote_error_expr {
	struct expression *sre_type;
	struct expression *sre_flags;
	struct expression *sre_length;
	struct expression *sre_error;
	struct expression *sre_assoc_id;
	struct expression *sre_data;
};

/* Parse tree for sctp_shutdown_event for notifications. */
struct sctp_send_failed_expr {
	struct expression *ssf_type;
	struct expression *ssf_flags;
	struct expression *ssf_length;
	struct expression *ssf_error;
	struct expression *ssf_info;
	struct expression *ssf_assoc_id;
	struct expression *ssf_data;
};

/* Parse tree for sctp_shutdown_event for notifications. */
struct sctp_shutdown_event_expr {
	struct expression *sse_type;
	struct expression *sse_flags;
	struct expression *sse_length;
	struct expression *sse_assoc_id;
};

/* Parse tree for sctp_adaptation_event for notifications. */
struct sctp_adaptation_event_expr {
	struct expression *sai_type;
	struct expression *sai_flags;
	struct expression *sai_length;
	struct expression *sai_adaptation_ind;
	struct expression *sai_assoc_id;
};

/* Parse tree for sctp_partial_delivery_event for notifications. */
struct sctp_pdapi_event_expr {
	struct expression *pdapi_type;
	struct expression *pdapi_flags;
	struct expression *pdapi_length;
	struct expression *pdapi_indication;
	struct expression *pdapi_stream;
	struct expression *pdapi_seq;
	struct expression *pdapi_assoc_id;
};

/* Parse tree for sctp_authentication_event for notifications. */
struct sctp_authkey_event_expr {
	struct expression *auth_type;
	struct expression *auth_flags;
	struct expression *auth_length;
	struct expression *auth_keynumber;
	struct expression *auth_indication;
	struct expression *auth_assoc_id;
};

/* Parse tree for sctp_sender_dry_event for notifications. */
struct sctp_sender_dry_event_expr {
	struct expression *sender_dry_type;
	struct expression *sender_dry_flags;
	struct expression *sender_dry_length;
	struct expression *sender_dry_assoc_id;
};

/* Parse tree for sctp_send_failed_event for notifications. */
struct sctp_send_failed_event_expr {
	struct expression *ssfe_type;
	struct expression *ssfe_flags;
	struct expression *ssfe_length;
	struct expression *ssfe_error;
	struct expression *ssfe_info;
	struct expression *ssfe_assoc_id;
	struct expression *ssfe_data;
};

/* Parse tree for sctp_tlv for notifications. */
struct sctp_tlv_expr {
	struct expression *sn_type;
	struct expression *sn_flags;
	struct expression *sn_length;
};

/* Parse tree for sctp_extrcvinfo struct for cmsg. */
struct sctp_extrcvinfo_expr {
	struct expression *sinfo_stream;
	struct expression *sinfo_ssn;
	struct expression *sinfo_flags;
	struct expression *sinfo_ppid;
	struct expression *sinfo_context;
	struct expression *sinfo_pr_value;
	struct expression *sinfo_tsn;
	struct expression *sinfo_cumtsn;
	struct expression *serinfo_next_flags;
	struct expression *serinfo_next_stream;
	struct expression *serinfo_next_aid;
	struct expression *serinfo_next_length;
	struct expression *serinfo_next_ppid;
	struct expression *sinfo_assoc_id;
};

/* The errno-related info from strace to summarize a system call error */
struct errno_spec {
	const char *errno_macro;	/* errno symbol (C macro name) */
	const char *strerror;		/* strerror translation of errno */
};

/* A system call and its expected result. System calls that should
 * return immediately have an end_usecs value of SYSCALL_NON_BLOCKING.
 * System calls that block for some non-zero time have a non-negative
 * end_usecs indicating the time at which the system call should
 * return.
 */
struct syscall_spec {
	const char *name;			/* name of system call */
	struct expression_list *arguments;	/* arguments to system call */
	struct expression *result;		/* expected result from call */
	struct errno_spec *error;		/* errno symbol or NULL */
	char *note;				/* extra note from strace */
	s64 end_usecs;				/* finish time, if it blocks */
};
#define SYSCALL_NON_BLOCKING  -1		/* end_usecs if non-blocking */

static inline bool is_blocking_syscall(struct syscall_spec *syscall)
{
	return syscall->end_usecs != SYSCALL_NON_BLOCKING;
}

/* A shell command line to execute using system(3) */
struct command_spec {
	const char *command_line;	/* executed with /bin/sh */
};

/* An ASCII text snippet of code to insert in the post-processing
 * output. This can be, for example, a snippet of Python to execute.
 */
struct code_spec {
	const char *text;	/* snippet of post-processing code */
};

/* Types of events in a script */
enum event_t {
	INVALID_EVENT = 0,
	PACKET_EVENT,
	SYSCALL_EVENT,
	COMMAND_EVENT,
	CODE_EVENT,
	NUM_EVENT_TYPES,
};

/* Types of event times */
enum event_time_t {
	ABSOLUTE_TIME = 0,
	RELATIVE_TIME,
	ANY_TIME,
	ABSOLUTE_RANGE_TIME,
	RELATIVE_RANGE_TIME,
	NUM_TIME_TYPES,
};

/* An event in a script */
struct event {
	int line_number;	/* location in test script file */
	s64 time_usecs;		/* event time in microseconds */
	s64 time_usecs_end;	/* event time range end (or NO_TIME_RANGE) */
	s64 offset_usecs;	/* relative event time offset from script start
				 * (or NO_TIME_RANGE) */
	enum event_time_t time_type; /* type of time */
	enum event_t type;	/* type of the event */
	union {
		struct packet	*packet;
		struct syscall_spec	*syscall;
		struct command_spec	*command;
		struct code_spec	*code;
	} event;		/* pointer to the event */
	struct event *next;	/* next in linked list of events */
};
#define NO_TIME_RANGE	-1		/* time_usecs_end if no range */

static inline bool is_event_time_absolute(struct event *event)
{
	return ((event->time_type == ABSOLUTE_TIME) ||
		(event->time_type == ABSOLUTE_RANGE_TIME));
}

/* A --name=value option in a script */
struct option_list {
	char *name;
	char *value;
	struct option_list *next;
};

/* A parsed script. The script owns all of the data to which
 * it points. TODO: add a script_free() to free everything when we are
 * done executing the script, instead of leaking all that memory.
 */
struct script {
	struct option_list *option_list;    /* linked list of options */
	struct command_spec *init_command;  /* untimed initialization command */
	struct event	*event_list;	    /* linked list of all events */
	char		*buffer;	    /* raw input text of the script */
	int		length;		    /* number of bytes in the script */
};

/* A table entry mapping a bit mask to its human-readable name.
 * A table of such mappings must be terminated with a struct with a
 * NULL name.
 */
struct flag_name {
	u64		flag;	/* a flag with one bit set */
	const char	*name;	/* human-readable ASCII name for this bit */
};

/* Initialize a script object */
extern void init_script(struct script *script);

/* Look up the value of the given symbol, and fill it in. On success,
 * return STATUS_OK; if the symbol cannot be found, return
 * STATUS_ERR and fill in an error message in *error.
 */
extern int symbol_to_int(const char *input_symbol, s64 *output_integer,
			 char **error);

/* Convert the given bit flags to a human-readable ASCII bit-wise OR
 * ('|') expression and return the resulting malloc-allocated
 * string. Caller must free() the memory.
 */
extern struct flag_name poll_flags[];
char *flags_to_string(struct flag_name *flags_array, u64 flags);

/* Do a deep deallocation of a heap-allocated expression list,
 * including any other space that it points too.
 */
extern void free_expression(struct expression *expression);

/* Do a deep deallocation of a heap-allocated expression list,
 * including any other space that it points too.
 */
extern void free_expression_list(struct expression_list *list);

/* Return a copy of the given expression list with each expression
 * evaluated (e.g. symbols resolved to ints). On success, returns
 * STATUS_OK. On error return STATUS_ERR and fill in *error.
 */
extern int evaluate_expression_list(struct expression_list *in_list,
				    struct expression_list **out_list,
				    char **error);

#endif /* __SCRIPT_H__ */
