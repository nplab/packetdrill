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
 * Implementation of functions to help interpret a test script.
 */

#include "script.h"

#include <assert.h>
#include <poll.h>
#include <stdlib.h>

#include "symbols.h"

/* Fill in a value representing the given expression in
 * fully-evaluated form (e.g. symbols resolved to ints). On success,
 * returns STATUS_OK. On error return STATUS_ERR and fill in *error.
 */
static int evaluate(struct expression *in,
		    struct expression **out_ptr, char **error);

/* Initialize script object */
void init_script(struct script *script)
{
	memset(script, 0, sizeof(*script));
	script->option_list = NULL;
	script->init_command = NULL;
	script->event_list = NULL;
}

/* This table maps expression types to human-readable strings */
struct expression_type_entry {
	enum expression_t type;
	const char *name;
};
struct expression_type_entry expression_type_table[] = {
	{ EXPR_NONE,                 "none" },
	{ EXPR_NULL,		     "null" },
	{ EXPR_ELLIPSIS,             "ellipsis" },
	{ EXPR_INTEGER,              "integer" },
	{ EXPR_WORD,                 "word" },
	{ EXPR_STRING,               "string" },
	{ EXPR_SOCKET_ADDRESS_IPV4,  "sockaddr_in" },
	{ EXPR_SOCKET_ADDRESS_IPV6,  "sockaddr_in6" },
	{ EXPR_LINGER,               "linger" },
	{ EXPR_BINARY,               "binary_expression" },
	{ EXPR_LIST,                 "list" },
	{ EXPR_IOVEC,                "iovec" },
	{ EXPR_MSGHDR,               "msghdr" },
	{ EXPR_POLLFD,               "pollfd" },
	{ EXPR_SCTP_RTOINFO,         "sctp_rtoinfo"},
	{ EXPR_SCTP_INITMSG,         "sctp_initmsg"},
	{ EXPR_SCTP_ASSOC_VALUE,     "sctp_assoc_value"},
	{ EXPR_SCTP_SACKINFO,        "sctp_sackinfo"},
	{ EXPR_SCTP_STATUS,          "sctp_status"},
	{ EXPR_SCTP_PADDRINFO,	     "sctp_paddrinfo"},
	{ EXPR_SCTP_PEER_ADDR_PARAMS,"sctp_peer_addr_params"},
	{ EXPR_SCTP_STREAM_VALUE,    "sctp_stream_value"},
	{ EXPR_SCTP_ASSOCPARAMS,     "sctp_assocparams"},
	{ EXPR_SCTP_EVENT,	     "sctp_event"      },
	{ EXPR_SCTP_EVENT_SUBSCRIBE, "sctp_event_subscribe"},
	{ EXPR_SCTP_SNDINFO,         "sctp_sndinfo"    },
	{ EXPR_SCTP_SETADAPTATION,   "sctp_setadaptation"},
	{ EXPR_SCTP_SNDRCVINFO,      "sctp_sndrcvinfo" },
	{ EXPR_SCTP_PRINFO,          "sctp_prinfo"     },
	{ EXPR_SCTP_AUTHINFO,        "sctp_authinfo"   },
	{ EXPR_SCTP_SENDV_SPA,       "sctp_sendv_spa"  },
	{ EXPR_SCTP_RCVINFO,         "sctp_rcvinfo"    },
	{ EXPR_SCTP_NXTINFO,         "sctp_nxtinfo"    },
	{ EXPR_SCTP_RECVV_RN,        "sctp_recvv_rn "  },
	{ EXPR_SCTP_SHUTDOWN_EVENT,  "sctp_shutdown_event"},
	{ EXPR_SCTP_SENDER_DRY_EVENT,"sctp_sender_dry_event"},
	{ EXPR_SCTP_SEND_FAILED_EVENT,"sctp_send_failed_event"},
	{ NUM_EXPR_TYPES,            NULL}
};

const char *expression_type_to_string(enum expression_t type)
{
	int i = 0;
	assert(ARRAY_SIZE(expression_type_table) == NUM_EXPR_TYPES + 1);
	for (i = 0; expression_type_table[i].name != NULL; ++i)
		if (expression_type_table[i].type == type)
			return expression_type_table[i].name;
	return "UNKNOWN_TYPE";
}

/* Cross-platform symbols. */
struct int_symbol cross_platform_symbols[] = {
	{ AF_INET,                          "AF_INET"                         },
	{ AF_INET6,                         "AF_INET6"                        },

	{ PF_INET,                          "PF_INET"                         },
	{ PF_INET6,                         "PF_INET6"                        },

	{ SOCK_STREAM,                      "SOCK_STREAM"                     },
	{ SOCK_DGRAM,                       "SOCK_DGRAM"                      },

	{ IPPROTO_IP,                       "IPPROTO_IP"                      },
	{ IPPROTO_IPV6,                     "IPPROTO_IPV6"                    },
	{ IPPROTO_ICMP,                     "IPPROTO_ICMP"                    },
	{ IPPROTO_SCTP,                     "IPPROTO_SCTP"                    },
	{ IPPROTO_TCP,                      "IPPROTO_TCP"                     },
	{ IPPROTO_UDP,                      "IPPROTO_UDP"                     },
	{ IPPROTO_UDPLITE,                  "IPPROTO_UDPLITE"                 },

	{ SHUT_RD,                          "SHUT_RD"                         },
	{ SHUT_WR,                          "SHUT_WR"                         },
	{ SHUT_RDWR,                        "SHUT_RDWR"                       },

	{ SOL_SOCKET,                       "SOL_SOCKET"                      },

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

/* Do a symbol->int lookup, and return true iff we found the symbol. */
static bool lookup_int_symbol(const char *input_symbol, s64 *output_integer,
			      struct int_symbol *symbols)
{
	int i;
	for (i = 0; symbols[i].name != NULL ; ++i) {
		if (strcmp(input_symbol, symbols[i].name) == 0) {
			*output_integer = symbols[i].value;
			return true;
		}
	}
	return false;
}

int symbol_to_int(const char *input_symbol, s64 *output_integer,
		  char **error)
{
	if (lookup_int_symbol(input_symbol, output_integer,
			      cross_platform_symbols))
		return STATUS_OK;

	if (lookup_int_symbol(input_symbol, output_integer,
			      platform_symbols()))
		return STATUS_OK;

	asprintf(error, "unknown symbol: '%s'", input_symbol);
	return STATUS_ERR;
}

/* Names for the events and revents bit mask flags for poll() system call */
struct flag_name poll_flags[] = {

	{ POLLIN,	"POLLIN" },
	{ POLLPRI,	"POLLPRI" },
	{ POLLOUT,	"POLLOUT" },

#ifdef POLLRDNORM
	{ POLLRDNORM,	"POLLRDNORM" },
#endif
#ifdef POLLRDBAND
	{ POLLRDBAND,	"POLLRDBAND" },
#endif
#ifdef POLLWRNORM
	{ POLLWRNORM,	"POLLWRNORM" },
#endif
#ifdef POLLWRBAND
	{ POLLWRBAND,	"POLLWRBAND" },
#endif

#ifdef POLLMSG
	{ POLLMSG,	"POLLMSG" },
#endif
#ifdef POLLREMOVE
	{ POLLREMOVE,	"POLLREMOVE" },
#endif
#ifdef POLLRDHUP
	{ POLLRDHUP,	"POLLRDHUP" },
#endif

#ifdef POLLINIGNEOF
	{ POLLINIGNEOF, "POLLINIGNEOF"                    },
#endif

	{ POLLERR,	"POLLERR" },
	{ POLLHUP,	"POLLHUP" },
	{ POLLNVAL,	"POLLNVAL" },

	{ 0, "" },
};

/* Return the human-readable ASCII string corresponding to a given
 * flag value, or "???" if none matches.
 */
static const char *flag_name(struct flag_name *flags_array, u64 flag)
{
	while (flags_array->name && flags_array->flag != flag)
		flags_array++;
	if (flags_array->flag == flag)
		return flags_array->name;
	else
		return "???";
}

char *flags_to_string(struct flag_name *flags_array, u64 flags)
{
	u64 bit_mask = 1;
	int i = 0;
	char *out = strdup("");

	for (i = 0; i < 64; ++i) {
		if (flags & bit_mask) {
			char *tmp = NULL;
			asprintf(&tmp, "%s%s%s",
				 out,
				 out[0] ? "|" : "",
				 flag_name(flags_array, bit_mask));
			free(out);
			out = tmp;
		}
		bit_mask <<= 1;
	}
	return out;
}

/* Fill in 'out' with an unescaped version of the input string. On
 * success, return STATUS_OK; on error, return STATUS_ERR and store
 * an error message in *error.
 */
static int unescape_cstring_expression(const char *input_string,
				       struct expression *out, char **error)
{
	int bytes = strlen(input_string);
	out->type = EXPR_STRING;
	out->value.string = (char *)malloc(bytes);
	const char *c_in = input_string;
	char *c_out = out->value.string;
	while (*c_in != '\0') {
		if (*c_in == '\\') {
			++c_in;
			switch (*c_in) {
			case '\\':
				*c_out = '\\';
			case '"':
				*c_out = '"';
			case 'f':
				*c_out = '\f';
				break;
			case 'n':
				*c_out = '\n';
				break;
			case 'r':
				*c_out = '\r';
				break;
			case 't':
				*c_out = '\t';
				break;
			case 'v':
				*c_out = '\v';
				break;
			default:
				asprintf(error, "unsupported escape code: '%c'",
					 *c_in);
				return STATUS_ERR;
			}
		} else {
			*c_out = *c_in;
		}
		++c_in;
		++c_out;
	}
	return STATUS_OK;
}

void free_expression(struct expression *expression)
{
	if (expression == NULL)
		return;
	if ((expression->type <= EXPR_NONE) ||
	    (expression->type >= NUM_EXPR_TYPES))
		assert(!"bad expression type");
	switch (expression->type) {
	case EXPR_NULL:
	case EXPR_ELLIPSIS:
	case EXPR_INTEGER:
		break;
	case EXPR_LINGER:
		assert(expression->value.linger);
		free_expression(expression->value.linger->l_onoff);
		free_expression(expression->value.linger->l_linger);
		break;
	case EXPR_SCTP_RTOINFO:
		assert(expression->value.sctp_rtoinfo);
		free_expression(expression->value.sctp_rtoinfo->srto_initial);
		free_expression(expression->value.sctp_rtoinfo->srto_max);
		free_expression(expression->value.sctp_rtoinfo->srto_min);
		break;
	case EXPR_SCTP_ASSOC_VALUE:
		assert(expression->value.sctp_assoc_value);
		free_expression(expression->value.sctp_assoc_value->assoc_value);
		break;
	case EXPR_SCTP_INITMSG:
		assert(expression->value.sctp_initmsg);
		free_expression(expression->value.sctp_initmsg->sinit_num_ostreams);
		free_expression(expression->value.sctp_initmsg->sinit_max_instreams);
		free_expression(expression->value.sctp_initmsg->sinit_max_attempts);
		free_expression(expression->value.sctp_initmsg->sinit_max_init_timeo);
		break;
	case EXPR_SCTP_SACKINFO:
		assert(expression->value.sctp_sack_info);
		free_expression(expression->value.sctp_sack_info->sack_delay);
		free_expression(expression->value.sctp_sack_info->sack_freq);		
		break;
	case EXPR_SCTP_PADDRINFO:
		assert(expression->value.sctp_paddrinfo);
		free_expression(expression->value.sctp_paddrinfo->spinfo_address);
		free_expression(expression->value.sctp_paddrinfo->spinfo_state);
		free_expression(expression->value.sctp_paddrinfo->spinfo_cwnd);
		free_expression(expression->value.sctp_paddrinfo->spinfo_srtt);
		free_expression(expression->value.sctp_paddrinfo->spinfo_rto);
		free_expression(expression->value.sctp_paddrinfo->spinfo_mtu);
		break;
	case EXPR_SCTP_STATUS:
		assert(expression->value.sctp_status);
		free_expression(expression->value.sctp_status->sstat_state);
		free_expression(expression->value.sctp_status->sstat_rwnd);
		free_expression(expression->value.sctp_status->sstat_unackdata);
		free_expression(expression->value.sctp_status->sstat_penddata);
		free_expression(expression->value.sctp_status->sstat_instrms);
		free_expression(expression->value.sctp_status->sstat_outstrms);
		free_expression(expression->value.sctp_status->sstat_fragmentation_point);
		free_expression(expression->value.sctp_status->sstat_primary);
		break;
	case EXPR_SCTP_PEER_ADDR_PARAMS:
		assert(expression->value.sctp_paddrparams);
		free_expression(expression->value.sctp_paddrparams->spp_address);
		free_expression(expression->value.sctp_paddrparams->spp_hbinterval);
		free_expression(expression->value.sctp_paddrparams->spp_pathmaxrxt);
		free_expression(expression->value.sctp_paddrparams->spp_pathmtu);
		free_expression(expression->value.sctp_paddrparams->spp_flags);
		free_expression(expression->value.sctp_paddrparams->spp_ipv6_flowlabel);
		free_expression(expression->value.sctp_paddrparams->spp_dscp);
		break;
	case EXPR_SCTP_STREAM_VALUE:
		assert(expression->value.sctp_stream_value);
		free_expression(expression->value.sctp_stream_value->stream_id);
		free_expression(expression->value.sctp_stream_value->stream_value);
		break;
	case EXPR_SCTP_ASSOCPARAMS:
		free_expression(expression->value.sctp_assocparams->sasoc_asocmaxrxt);
		free_expression(expression->value.sctp_assocparams->sasoc_number_peer_destinations);
		free_expression(expression->value.sctp_assocparams->sasoc_peer_rwnd);
		free_expression(expression->value.sctp_assocparams->sasoc_local_rwnd);
		free_expression(expression->value.sctp_assocparams->sasoc_cookie_life);
		break;
	case EXPR_SCTP_EVENT:
		free_expression(expression->value.sctp_event->se_type);
		free_expression(expression->value.sctp_event->se_on);
		break;
	case EXPR_SCTP_EVENT_SUBSCRIBE:
		free_expression(expression->value.sctp_event_subscribe->sctp_data_io_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_association_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_address_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_send_failure_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_peer_error_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_shutdown_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_partial_delivery_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_adaptation_layer_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_authentication_event);
		free_expression(expression->value.sctp_event_subscribe->sctp_sender_dry_event);
		break;		
	case EXPR_SCTP_SNDINFO:
		free_expression(expression->value.sctp_sndinfo->snd_sid);
		free_expression(expression->value.sctp_sndinfo->snd_flags);
		free_expression(expression->value.sctp_sndinfo->snd_ppid);
		free_expression(expression->value.sctp_sndinfo->snd_context);
		break;		
	case EXPR_SCTP_SETADAPTATION:
		free_expression(expression->value.sctp_setadaptation->ssb_adaptation_ind);
		break;
	case EXPR_SCTP_SNDRCVINFO:
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_stream);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_ssn);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_flags);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_ppid);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_context);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_timetolive);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_tsn);
		free_expression(expression->value.sctp_sndrcvinfo->sinfo_cumtsn);
		break;
	case EXPR_SCTP_PRINFO:
		free_expression(expression->value.sctp_prinfo->pr_policy);
		free_expression(expression->value.sctp_prinfo->pr_value);
		break;		
	case EXPR_SCTP_AUTHINFO:
		free_expression(expression->value.sctp_authinfo->auth_keynumber);
		break;
	case EXPR_SCTP_SENDV_SPA:
		free_expression(expression->value.sctp_sendv_spa->sendv_flags);
		free_expression(expression->value.sctp_sendv_spa->sendv_sndinfo);
		free_expression(expression->value.sctp_sendv_spa->sendv_prinfo);
		free_expression(expression->value.sctp_sendv_spa->sendv_authinfo);
		break;
	case EXPR_SCTP_RCVINFO:
		free_expression(expression->value.sctp_rcvinfo->rcv_sid);
		free_expression(expression->value.sctp_rcvinfo->rcv_ssn);
		free_expression(expression->value.sctp_rcvinfo->rcv_flags);
		free_expression(expression->value.sctp_rcvinfo->rcv_ppid);
		free_expression(expression->value.sctp_rcvinfo->rcv_tsn);
		free_expression(expression->value.sctp_rcvinfo->rcv_cumtsn);
		free_expression(expression->value.sctp_rcvinfo->rcv_context);
		break;
	case EXPR_SCTP_NXTINFO:
		free_expression(expression->value.sctp_nxtinfo->nxt_sid);
		free_expression(expression->value.sctp_nxtinfo->nxt_flags);
		free_expression(expression->value.sctp_nxtinfo->nxt_ppid);
		free_expression(expression->value.sctp_nxtinfo->nxt_length);
		break;
	case EXPR_SCTP_RECVV_RN:
		free_expression(expression->value.sctp_recvv_rn->recvv_rcvinfo);
		free_expression(expression->value.sctp_recvv_rn->recvv_nxtinfo);
		break;
	case EXPR_SCTP_SHUTDOWN_EVENT:
		free_expression(expression->value.sctp_shutdown_event->sse_type);
		free_expression(expression->value.sctp_shutdown_event->sse_flags);
		free_expression(expression->value.sctp_shutdown_event->sse_length);
		break;
	case EXPR_SCTP_SENDER_DRY_EVENT:
		free_expression(expression->value.sctp_sender_dry_event->sender_dry_type);
		free_expression(expression->value.sctp_sender_dry_event->sender_dry_flags);
		free_expression(expression->value.sctp_sender_dry_event->sender_dry_length);
		free_expression(expression->value.sctp_sender_dry_event->sender_dry_assoc_id);
		break;
	case EXPR_SCTP_SEND_FAILED_EVENT:
		free_expression(expression->value.sctp_send_failed_event->ssfe_type);
		free_expression(expression->value.sctp_send_failed_event->ssfe_flags);
		free_expression(expression->value.sctp_send_failed_event->ssfe_length);
		free_expression(expression->value.sctp_send_failed_event->ssfe_error);
		free_expression(expression->value.sctp_send_failed_event->ssfe_info);
		free_expression(expression->value.sctp_send_failed_event->ssfe_assoc_id);
		free_expression(expression->value.sctp_send_failed_event->ssfe_data);
		break;
	case EXPR_WORD:
		assert(expression->value.string);
		free(expression->value.string);
		break;
	case EXPR_STRING:
		assert(expression->value.string);
		free(expression->value.string);
		break;
	case EXPR_SOCKET_ADDRESS_IPV4:
		assert(expression->value.socket_address_ipv4);
		free(expression->value.socket_address_ipv4);
		break;
	case EXPR_SOCKET_ADDRESS_IPV6:
		assert(expression->value.socket_address_ipv6);
		free(expression->value.socket_address_ipv6);
		break;
	case EXPR_BINARY:
		assert(expression->value.binary);
		free(expression->value.binary->op);
		free_expression(expression->value.binary->lhs);
		free_expression(expression->value.binary->rhs);
		free(expression->value.binary);
		break;
	case EXPR_LIST:
		free_expression_list(expression->value.list);
		break;
	case EXPR_IOVEC:
		assert(expression->value.iovec);
		free_expression(expression->value.iovec->iov_base);
		free_expression(expression->value.iovec->iov_len);
		break;
	case EXPR_MSGHDR:
		assert(expression->value.msghdr);
		free_expression(expression->value.msghdr->msg_name);
		free_expression(expression->value.msghdr->msg_namelen);
		free_expression(expression->value.msghdr->msg_iov);
		free_expression(expression->value.msghdr->msg_iovlen);
		free_expression(expression->value.msghdr->msg_flags);
		break;
	case EXPR_POLLFD:
		assert(expression->value.pollfd);
		free_expression(expression->value.pollfd->fd);
		free_expression(expression->value.pollfd->events);
		free_expression(expression->value.pollfd->revents);
		break;
	case EXPR_NONE:
	case NUM_EXPR_TYPES:
		break;
	/* missing default case so compiler catches missing cases */
	}
	memset(expression, 0, sizeof(*expression));  /* paranoia */
	free(expression);
}

void free_expression_list(struct expression_list *list)
{
	while (list != NULL) {
		free_expression(list->expression);
		struct expression_list *dead = list;
		list = list->next;
		free(dead);
	}
}

static int evaluate_binary_expression(struct expression *in,
				      struct expression *out, char **error)
{
	int result = STATUS_ERR;
	assert(in->type == EXPR_BINARY);
	assert(in->value.binary);
	out->type = EXPR_INTEGER;

	struct expression *lhs = NULL;
	struct expression *rhs = NULL;
	if (evaluate(in->value.binary->lhs, &lhs, error))
		goto error_out;
	if (evaluate(in->value.binary->rhs, &rhs, error))
		goto error_out;
	if (strcmp("|", in->value.binary->op) == 0) {
		if (lhs->type != EXPR_INTEGER) {
			asprintf(error, "left hand side of | not an integer");
		} else if (rhs->type != EXPR_INTEGER) {
			asprintf(error, "right hand side of | not an integer");
		} else {
			out->value.num = lhs->value.num | rhs->value.num;
			result = STATUS_OK;
		}
	} else {
		asprintf(error, "bad binary operator '%s'",
			 in->value.binary->op);
	}
error_out:
	free_expression(rhs);
	free_expression(lhs);
	return result;
}

static int evaluate_list_expression(struct expression *in,
				    struct expression *out, char **error)
{
	assert(in->type == EXPR_LIST);
	assert(out->type == EXPR_LIST);

	out->value.list = NULL;
	return evaluate_expression_list(in->value.list,
					&out->value.list, error);
}

static int evaluate_iovec_expression(struct expression *in,
				     struct expression *out, char **error)
{
	struct iovec_expr *in_iov;
	struct iovec_expr *out_iov;

	assert(in->type == EXPR_IOVEC);
	assert(in->value.iovec);
	assert(out->type == EXPR_IOVEC);

	out->value.iovec = calloc(1, sizeof(struct iovec_expr));

	in_iov = in->value.iovec;
	out_iov = out->value.iovec;
	if (evaluate(in_iov->iov_base,		&out_iov->iov_base,	error))
		return STATUS_ERR;
	if (evaluate(in_iov->iov_len,		&out_iov->iov_len,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_msghdr_expression(struct expression *in,
				      struct expression *out, char **error)
{
	struct msghdr_expr *in_msg;
	struct msghdr_expr *out_msg;

	assert(in->type == EXPR_MSGHDR);
	assert(in->value.msghdr);
	assert(out->type == EXPR_MSGHDR);

	out->value.msghdr = calloc(1, sizeof(struct msghdr_expr));

	in_msg = in->value.msghdr;
	out_msg = out->value.msghdr;

	if (evaluate(in_msg->msg_name,		&out_msg->msg_name,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_namelen,	&out_msg->msg_namelen,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_iov,		&out_msg->msg_iov,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_iovlen,	&out_msg->msg_iovlen,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_flags,		&out_msg->msg_flags,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_pollfd_expression(struct expression *in,
				      struct expression *out, char **error)
{
	struct pollfd_expr *in_pollfd;
	struct pollfd_expr *out_pollfd;

	assert(in->type == EXPR_POLLFD);
	assert(in->value.pollfd);
	assert(out->type == EXPR_POLLFD);

	out->value.pollfd = calloc(1, sizeof(struct pollfd_expr));

	in_pollfd = in->value.pollfd;
	out_pollfd = out->value.pollfd;

	if (evaluate(in_pollfd->fd,		&out_pollfd->fd,	error))
		return STATUS_ERR;
	if (evaluate(in_pollfd->events,		&out_pollfd->events,	error))
		return STATUS_ERR;
	if (evaluate(in_pollfd->revents,	&out_pollfd->revents,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_rtoinfo_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
	struct sctp_rtoinfo_expr *in_rtoinfo;
	struct sctp_rtoinfo_expr *out_rtoinfo;

	assert(in->type == EXPR_SCTP_RTOINFO);
	assert(in->value.sctp_rtoinfo);
	assert(out->type == EXPR_SCTP_RTOINFO);

	out->value.sctp_rtoinfo = calloc(1, sizeof(struct sctp_rtoinfo_expr));

	in_rtoinfo = in->value.sctp_rtoinfo;
	out_rtoinfo = out->value.sctp_rtoinfo;

	if (evaluate(in_rtoinfo->srto_initial,
	             &out_rtoinfo->srto_initial,
	             error))
		return STATUS_ERR;
	if (evaluate(in_rtoinfo->srto_max,
	             &out_rtoinfo->srto_max,
	             error))
		return STATUS_ERR;
	if (evaluate(in_rtoinfo->srto_min,
	             &out_rtoinfo->srto_min,
	             error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_initmsg_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
	struct sctp_initmsg_expr *in_initmsg;
	struct sctp_initmsg_expr *out_initmsg;

	assert(in->type == EXPR_SCTP_INITMSG);
	assert(in->value.sctp_initmsg);
	assert(out->type == EXPR_SCTP_INITMSG);

	out->value.sctp_initmsg = calloc(1, sizeof(struct sctp_initmsg_expr));

	in_initmsg = in->value.sctp_initmsg;
	out_initmsg = out->value.sctp_initmsg;

	if (evaluate(in_initmsg->sinit_num_ostreams,
		     &out_initmsg->sinit_num_ostreams,
		     error))
		return STATUS_ERR;
	if (evaluate(in_initmsg->sinit_max_instreams,
		     &out_initmsg->sinit_max_instreams,
		     error))
		return STATUS_ERR;
	if (evaluate(in_initmsg->sinit_max_attempts,
		     &out_initmsg->sinit_max_attempts,
		     error))
		return STATUS_ERR;
	if (evaluate(in_initmsg->sinit_max_init_timeo,
		     &out_initmsg->sinit_max_init_timeo,
		     error))
		return STATUS_ERR;
	return STATUS_OK;
}

static int evaluate_sctp_assoc_value_expression(struct expression *in,
						struct expression *out,
						char **error)
{
	struct sctp_assoc_value_expr *in_value;
	struct sctp_assoc_value_expr *out_value;

	assert(in->type == EXPR_SCTP_ASSOC_VALUE);
	assert(in->value.sctp_assoc_value);
	assert(out->type == EXPR_SCTP_ASSOC_VALUE);

	out->value.sctp_assoc_value = calloc(1, sizeof(struct sctp_assoc_value_expr));

	in_value = in->value.sctp_assoc_value;
	out_value = out->value.sctp_assoc_value;

	if (evaluate(in_value->assoc_value,
	             &out_value->assoc_value,
	             error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_sack_info_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
	struct sctp_sack_info_expr *in_sack_info;
	struct sctp_sack_info_expr *out_sack_info;

	assert(in->type == EXPR_SCTP_SACKINFO);
	assert(in->value.sctp_sack_info);
	assert(out->type == EXPR_SCTP_SACKINFO);

	out->value.sctp_sack_info = calloc(1, sizeof(struct sctp_sack_info_expr));

	in_sack_info = in->value.sctp_sack_info;
	out_sack_info = out->value.sctp_sack_info;

	if (evaluate(in_sack_info->sack_delay,
		     &out_sack_info->sack_delay,
		     error))
		return STATUS_ERR;
	if (evaluate(in_sack_info->sack_freq,
		     &out_sack_info->sack_freq,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_paddrinfo_expression(struct expression *in,
					      struct expression *out,
					      char **error)
{
	struct sctp_paddrinfo_expr *in_paddrinfo;
	struct sctp_paddrinfo_expr *out_paddrinfo;

	assert(in->type == EXPR_SCTP_PADDRINFO);
	assert(in->value.sctp_paddrinfo);
	assert(out->type == EXPR_SCTP_PADDRINFO);

	out->value.sctp_paddrinfo = calloc(1, sizeof(struct sctp_paddrinfo_expr));

	in_paddrinfo = in->value.sctp_paddrinfo;
	out_paddrinfo = out->value.sctp_paddrinfo;

	if (evaluate(in_paddrinfo->spinfo_address,
	             &out_paddrinfo->spinfo_address,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrinfo->spinfo_state,
	             &out_paddrinfo->spinfo_state,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrinfo->spinfo_cwnd,
	             &out_paddrinfo->spinfo_cwnd,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrinfo->spinfo_srtt,
	             &out_paddrinfo->spinfo_srtt,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrinfo->spinfo_rto,
	             &out_paddrinfo->spinfo_rto,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrinfo->spinfo_mtu,
	             &out_paddrinfo->spinfo_mtu,
	             error))
		return STATUS_ERR;

	return STATUS_OK;
}


static int evaluate_sctp_status_expression(struct expression *in,
					   struct expression *out, char **error)
{
	struct sctp_status_expr *in_status;
	struct sctp_status_expr *out_status;

	assert(in->type == EXPR_SCTP_STATUS);
	assert(in->value.sctp_status);
	assert(out->type == EXPR_SCTP_STATUS);

	out->value.sctp_status = calloc(1, sizeof(struct sctp_status_expr));

	in_status = in->value.sctp_status;
	out_status = out->value.sctp_status;

	if (evaluate(in_status->sstat_state,
	             &out_status->sstat_state,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_rwnd,
	             &out_status->sstat_rwnd,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_unackdata,
	             &out_status->sstat_unackdata,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_penddata,
	             &out_status->sstat_penddata,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_instrms,
	             &out_status->sstat_instrms,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_outstrms,
	             &out_status->sstat_outstrms,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_fragmentation_point,
	             &out_status->sstat_fragmentation_point,
	             error))
		return STATUS_ERR;
	if (evaluate(in_status->sstat_primary,
	             &out_status->sstat_primary,
	             error))
		return STATUS_ERR;
	return STATUS_OK;
}

static int evaluate_sctp_peer_addr_param_expression(struct expression *in,
						    struct expression *out,
						    char **error)
{
	struct sctp_paddrparams_expr *in_paddrparams;
	struct sctp_paddrparams_expr *out_paddrparams;

	assert(in->type == EXPR_SCTP_PEER_ADDR_PARAMS);
	assert(in->value.sctp_paddrparams);
	assert(out->type == EXPR_SCTP_PEER_ADDR_PARAMS);

	out->value.sctp_paddrparams = calloc(1, sizeof(struct sctp_paddrparams_expr));

	in_paddrparams = in->value.sctp_paddrparams;
	out_paddrparams = out->value.sctp_paddrparams;

	if (evaluate(in_paddrparams->spp_address,
	             &out_paddrparams->spp_address,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrparams->spp_hbinterval,
	             &out_paddrparams->spp_hbinterval,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrparams->spp_pathmaxrxt,
	             &out_paddrparams->spp_pathmaxrxt,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrparams->spp_pathmtu,
	             &out_paddrparams->spp_pathmtu,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrparams->spp_flags,
	             &out_paddrparams->spp_flags,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrparams->spp_ipv6_flowlabel,
	             &out_paddrparams->spp_ipv6_flowlabel,
	             error))
		return STATUS_ERR;
	if (evaluate(in_paddrparams->spp_dscp,
	             &out_paddrparams->spp_dscp,
	             error))
		return STATUS_ERR;
	return STATUS_OK;
}

static int evaluate_sctp_stream_value_expression(struct expression *in,
						 struct expression *out,
						 char **error)
{
	struct sctp_stream_value_expr *in_value;
	struct sctp_stream_value_expr *out_value;

	assert(in->type == EXPR_SCTP_STREAM_VALUE);
	assert(in->value.sctp_stream_value);
	assert(out->type == EXPR_SCTP_STREAM_VALUE);

	out->value.sctp_stream_value = calloc(1, sizeof(struct sctp_stream_value_expr));

	in_value = in->value.sctp_stream_value;
	out_value = out->value.sctp_stream_value;

	if (evaluate(in_value->stream_id,
	             &out_value->stream_id,
	             error))
		return STATUS_ERR;
	if (evaluate(in_value->stream_value,
	             &out_value->stream_value,
	             error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_event_expression(struct expression *in,
						 struct expression *out,
						 char **error)
{
	struct sctp_event_expr *in_event;
	struct sctp_event_expr *out_event;

	assert(in->type == EXPR_SCTP_EVENT);
	assert(in->value.sctp_event);
	assert(out->type == EXPR_SCTP_EVENT);

	out->value.sctp_event = calloc(1, sizeof(struct sctp_event_expr));

	in_event = in->value.sctp_event;
	out_event = out->value.sctp_event;

	if (evaluate(in_event->se_type,
		    &out_event->se_type,
		    error))
		return STATUS_ERR;
 	if (evaluate(in_event->se_on,
		    &out_event->se_on,
		    error))
		return STATUS_ERR;

	return STATUS_OK; 
}

static int evaluate_sctp_event_subscribe_expression(struct expression *in,
						    struct expression *out,
						    char **error)
{
	struct sctp_event_subscribe_expr *in_event;
	struct sctp_event_subscribe_expr *out_event;

	assert(in->type == EXPR_SCTP_EVENT_SUBSCRIBE);
	assert(in->value.sctp_event_subscribe);
	assert(out->type == EXPR_SCTP_EVENT_SUBSCRIBE);

	out->value.sctp_event_subscribe = calloc(1, sizeof(struct sctp_event_subscribe_expr));

	in_event = in->value.sctp_event_subscribe;
	out_event = out->value.sctp_event_subscribe;

	if (evaluate(in_event->sctp_data_io_event,
		    &out_event->sctp_data_io_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_association_event,
		    &out_event->sctp_association_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_address_event,
		    &out_event->sctp_address_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_send_failure_event,
		    &out_event->sctp_send_failure_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_peer_error_event,
		    &out_event->sctp_peer_error_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_shutdown_event,
		    &out_event->sctp_shutdown_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_partial_delivery_event,
		    &out_event->sctp_partial_delivery_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_adaptation_layer_event,
		    &out_event->sctp_adaptation_layer_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_authentication_event,
		    &out_event->sctp_authentication_event,
		    error))
		return STATUS_ERR;
	if (evaluate(in_event->sctp_sender_dry_event,
		    &out_event->sctp_sender_dry_event,
		    error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_accocparams_expression(struct expression *in,
						struct expression *out,
						char **error)
{
	struct sctp_assocparams_expr *in_params;
	struct sctp_assocparams_expr *out_params;

	assert(in->type == EXPR_SCTP_ASSOCPARAMS);
	assert(in->value.sctp_assocparams);
	assert(out->type == EXPR_SCTP_ASSOCPARAMS);

	out->value.sctp_assocparams = calloc(1, sizeof(struct sctp_assocparams_expr));

	in_params = in->value.sctp_assocparams;
	out_params = out->value.sctp_assocparams;

	if (evaluate(in_params->sasoc_asocmaxrxt,
		     &out_params->sasoc_asocmaxrxt,
		     error))
		return STATUS_ERR;
	if (evaluate(in_params->sasoc_number_peer_destinations,
		     &out_params->sasoc_number_peer_destinations,
		     error))
		return STATUS_ERR;
	if (evaluate(in_params->sasoc_peer_rwnd,
		     &out_params->sasoc_peer_rwnd,
		     error))
		return STATUS_ERR;
	if (evaluate(in_params->sasoc_local_rwnd,
		     &out_params->sasoc_local_rwnd,
		     error))
		return STATUS_ERR;
	if (evaluate(in_params->sasoc_cookie_life,
		     &out_params->sasoc_cookie_life,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_sndinfo_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
	struct sctp_sndinfo_expr *in_sndinfo;
	struct sctp_sndinfo_expr *out_sndinfo;

	assert(in->type == EXPR_SCTP_SNDINFO);
	assert(in->value.sctp_sndinfo);
	assert(out->type == EXPR_SCTP_SNDINFO);

	out->value.sctp_sndinfo = calloc(1, sizeof(struct sctp_sndinfo_expr));

	in_sndinfo = in->value.sctp_sndinfo;
	out_sndinfo = out->value.sctp_sndinfo;

	if (evaluate(in_sndinfo->snd_sid,
		     &out_sndinfo->snd_sid,
		     error))
		return STATUS_ERR;
	if (evaluate(in_sndinfo->snd_flags,
		     &out_sndinfo->snd_flags,
		     error))
		return STATUS_ERR;
	if (evaluate(in_sndinfo->snd_ppid,
		     &out_sndinfo->snd_ppid,
		     error))
		return STATUS_ERR;
	if (evaluate(in_sndinfo->snd_context,
		     &out_sndinfo->snd_context,
		     error))
		return STATUS_ERR;
	return STATUS_OK;
}

static int evaluate_sctp_setadaptation_expression(struct expression *in,
						  struct expression *out,
						  char **error)
{
        struct sctp_setadaptation_expr *in_adaptation;
        struct sctp_setadaptation_expr *out_adaptation;

        assert(in->type == EXPR_SCTP_SETADAPTATION);
        assert(in->value.sctp_setadaptation);
        assert(out->type == EXPR_SCTP_SETADAPTATION);

        out->value.sctp_setadaptation = calloc(1, sizeof(struct sctp_setadaptation_expr));
                     
        in_adaptation = in->value.sctp_setadaptation;
        out_adaptation = out->value.sctp_setadaptation;
                     
        if (evaluate(in_adaptation->ssb_adaptation_ind,
		     &out_adaptation->ssb_adaptation_ind,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_sndrcvinfo_expression(struct expression *in,
						  struct expression *out,
						  char **error)
{
        struct sctp_sndrcvinfo_expr *in_info;
        struct sctp_sndrcvinfo_expr *out_info;

        assert(in->type == EXPR_SCTP_SNDRCVINFO);
        assert(in->value.sctp_sndrcvinfo);
        assert(out->type == EXPR_SCTP_SNDRCVINFO);

        out->value.sctp_sndrcvinfo = calloc(1, sizeof(struct sctp_sndrcvinfo_expr));
                     
        in_info = in->value.sctp_sndrcvinfo;
        out_info = out->value.sctp_sndrcvinfo;
                     
        if (evaluate(in_info->sinfo_stream,
		     &out_info->sinfo_stream,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_ssn,
		     &out_info->sinfo_ssn,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_flags,
		     &out_info->sinfo_flags,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_ppid,
		     &out_info->sinfo_ppid,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_context,
		     &out_info->sinfo_context,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_timetolive,
		     &out_info->sinfo_timetolive,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_tsn,
		     &out_info->sinfo_tsn,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->sinfo_cumtsn,
		     &out_info->sinfo_cumtsn,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_prinfo_expression(struct expression *in,
					   struct expression *out,
					   char **error)
{
        struct sctp_prinfo_expr *in_info;
        struct sctp_prinfo_expr *out_info;

        assert(in->type == EXPR_SCTP_PRINFO);
        assert(in->value.sctp_prinfo);
        assert(out->type == EXPR_SCTP_PRINFO);

        out->value.sctp_prinfo = calloc(1, sizeof(struct sctp_prinfo_expr));
                     
        in_info = in->value.sctp_prinfo;
        out_info = out->value.sctp_prinfo;
                     
        if (evaluate(in_info->pr_policy,
		     &out_info->pr_policy,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->pr_value,
		     &out_info->pr_value,
		     error))
		return STATUS_ERR;

	return STATUS_OK;	
}

static int evaluate_sctp_authinfo_expression(struct expression *in,
					     struct expression *out,
					     char **error)
{
        struct sctp_authinfo_expr *in_info;
        struct sctp_authinfo_expr *out_info;

        assert(in->type == EXPR_SCTP_AUTHINFO);
        assert(in->value.sctp_authinfo);
        assert(out->type == EXPR_SCTP_AUTHINFO);

        out->value.sctp_authinfo = calloc(1, sizeof(struct sctp_authinfo_expr));
                     
        in_info = in->value.sctp_authinfo;
        out_info = out->value.sctp_authinfo;
                     
        if (evaluate(in_info->auth_keynumber,
		     &out_info->auth_keynumber,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_sendv_spa_expression(struct expression *in,
					      struct expression *out,
					      char **error)
{
        struct sctp_sendv_spa_expr *in_spa;
        struct sctp_sendv_spa_expr *out_spa;

        assert(in->type == EXPR_SCTP_SENDV_SPA);
        assert(in->value.sctp_sendv_spa);
        assert(out->type == EXPR_SCTP_SENDV_SPA);

        out->value.sctp_sendv_spa = calloc(1, sizeof(struct sctp_sendv_spa_expr));
                     
        in_spa = in->value.sctp_sendv_spa;
        out_spa = out->value.sctp_sendv_spa;
                     
        if (evaluate(in_spa->sendv_flags,
		     &out_spa->sendv_flags,
		     error))
		return STATUS_ERR;
        if (evaluate(in_spa->sendv_sndinfo,
		     &out_spa->sendv_sndinfo,
		     error))
		return STATUS_ERR;
        if (evaluate(in_spa->sendv_prinfo,
		     &out_spa->sendv_prinfo,
		     error))
		return STATUS_ERR;
        if (evaluate(in_spa->sendv_authinfo,
		     &out_spa->sendv_authinfo,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_rcvinfo_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
        struct sctp_rcvinfo_expr *in_info;
        struct sctp_rcvinfo_expr *out_info;

        assert(in->type == EXPR_SCTP_RCVINFO);
        assert(in->value.sctp_rcvinfo);
        assert(out->type == EXPR_SCTP_RCVINFO);

        out->value.sctp_rcvinfo = calloc(1, sizeof(struct sctp_rcvinfo_expr));
                     
        in_info = in->value.sctp_rcvinfo;
        out_info = out->value.sctp_rcvinfo;
                     
        if (evaluate(in_info->rcv_sid,
		     &out_info->rcv_sid,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->rcv_ssn,
		     &out_info->rcv_ssn,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->rcv_flags,
		     &out_info->rcv_flags,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->rcv_ppid,
		     &out_info->rcv_ppid,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->rcv_tsn,
		     &out_info->rcv_tsn,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->rcv_cumtsn,
		     &out_info->rcv_cumtsn,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->rcv_context,
		     &out_info->rcv_context,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_nxtinfo_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
        struct sctp_nxtinfo_expr *in_info;
        struct sctp_nxtinfo_expr *out_info;

        assert(in->type == EXPR_SCTP_NXTINFO);
        assert(in->value.sctp_nxtinfo);
        assert(out->type == EXPR_SCTP_NXTINFO);

        out->value.sctp_nxtinfo = calloc(1, sizeof(struct sctp_nxtinfo_expr));
                     
        in_info = in->value.sctp_nxtinfo;
        out_info = out->value.sctp_nxtinfo;
                     
        if (evaluate(in_info->nxt_sid,
		     &out_info->nxt_sid,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->nxt_flags,
		     &out_info->nxt_flags,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->nxt_ppid,
		     &out_info->nxt_ppid,
		     error))
		return STATUS_ERR;
        if (evaluate(in_info->nxt_length,
		     &out_info->nxt_length,
		     error))
		return STATUS_ERR;
	return STATUS_OK;
}

static int evaluate_sctp_recvv_rn_expression(struct expression *in,
					    struct expression *out,
					    char **error)
{
	struct sctp_recvv_rn_expr *in_rn;
	struct sctp_recvv_rn_expr *out_rn;

	assert(in->type == EXPR_SCTP_RECVV_RN);
	assert(in->value.sctp_recvv_rn);
	assert(out->type == EXPR_SCTP_RECVV_RN);

	out->value.sctp_recvv_rn = calloc(1, sizeof(struct sctp_recvv_rn_expr));
	in_rn = in->value.sctp_recvv_rn;
	out_rn = out->value.sctp_recvv_rn;

	if (evaluate(in_rn->recvv_rcvinfo,
		     &out_rn->recvv_rcvinfo,
		     error))
		return STATUS_ERR;
        if (evaluate(in_rn->recvv_nxtinfo,
		     &out_rn->recvv_nxtinfo,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_shutdown_event_expression(struct expression *in,
						   struct expression *out,
						   char **error)
{
	struct sctp_shutdown_event_expr *in_event;
	struct sctp_shutdown_event_expr *out_event;

	assert(in->type == EXPR_SCTP_SHUTDOWN_EVENT);
	assert(in->value.sctp_shutdown_event);
	assert(out->type == EXPR_SCTP_SHUTDOWN_EVENT);

	out->value.sctp_shutdown_event = calloc(1, sizeof(struct sctp_shutdown_event_expr));

	in_event = in->value.sctp_shutdown_event;
	out_event = out->value.sctp_shutdown_event;

	if (evaluate(in_event->sse_type,
		     &out_event->sse_type,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->sse_flags,
		     &out_event->sse_flags,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->sse_length,
		     &out_event->sse_length,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_sender_dry_event_expression(struct expression *in,
						     struct expression *out,
						     char **error)
{
	struct sctp_sender_dry_event_expr *in_event;
	struct sctp_sender_dry_event_expr *out_event;

	assert(in->type == EXPR_SCTP_SENDER_DRY_EVENT);
	assert(in->value.sctp_sender_dry_event);
	assert(out->type == EXPR_SCTP_SENDER_DRY_EVENT);

	out->value.sctp_sender_dry_event = calloc(1, sizeof(struct sctp_sender_dry_event_expr));

	in_event = in->value.sctp_sender_dry_event;
	out_event = out->value.sctp_sender_dry_event;

	if (evaluate(in_event->sender_dry_type,
		     &out_event->sender_dry_type,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->sender_dry_flags,
		     &out_event->sender_dry_flags,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->sender_dry_length,
		     &out_event->sender_dry_length,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->sender_dry_assoc_id,
		     &out_event->sender_dry_assoc_id,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sctp_send_failed_event_expression(struct expression *in,
						      struct expression *out,
						      char **error)
{
	struct sctp_send_failed_event_expr *in_event;
	struct sctp_send_failed_event_expr *out_event;

	assert(in->type == EXPR_SCTP_SEND_FAILED_EVENT);
	assert(in->value.sctp_send_failed_event);
	assert(out->type == EXPR_SCTP_SEND_FAILED_EVENT);

	out->value.sctp_send_failed_event = calloc(1, sizeof(struct sctp_send_failed_event_expr));

	in_event = in->value.sctp_send_failed_event;
	out_event = out->value.sctp_send_failed_event;

	if (evaluate(in_event->ssfe_type,
		     &out_event->ssfe_type,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->ssfe_flags,
		     &out_event->ssfe_flags,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->ssfe_length,
		     &out_event->ssfe_length,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->ssfe_error,
		     &out_event->ssfe_error,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->ssfe_info,
		     &out_event->ssfe_info,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->ssfe_assoc_id,
		     &out_event->ssfe_assoc_id,
		     error))
		return STATUS_ERR;
	if (evaluate(in_event->ssfe_data,
		     &out_event->ssfe_data,
		     error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate(struct expression *in,
		    struct expression **out_ptr, char **error)
{
	int result = STATUS_OK;
	struct expression *out = calloc(1, sizeof(struct expression));
	*out_ptr = out;
	out->type = in->type;	/* most types of expression stay the same */

	if ((in->type <= EXPR_NONE) ||
	    (in->type >= NUM_EXPR_TYPES)) {
		asprintf(error, "bad expression type: %d", in->type);
		return STATUS_ERR;
	}
	switch (in->type) {
	case EXPR_NULL:
		break;
	case EXPR_ELLIPSIS:
		break;
	case EXPR_INTEGER:		/* copy as-is */
		out->value.num = in->value.num;
		break;
	case EXPR_LINGER:		/* copy as-is */
		memcpy(&out->value.linger, &in->value.linger,
		       sizeof(in->value.linger));
		break;
	case EXPR_SCTP_RTOINFO:
		result = evaluate_sctp_rtoinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_ASSOCPARAMS:
		result = evaluate_sctp_accocparams_expression(in, out, error);
		break;
	case EXPR_SCTP_INITMSG:
		result = evaluate_sctp_initmsg_expression(in, out, error);
		break;
	case EXPR_SCTP_ASSOC_VALUE:
		result = evaluate_sctp_assoc_value_expression(in, out, error);
		break;
	case EXPR_SCTP_SACKINFO:
		result = evaluate_sctp_sack_info_expression(in, out, error);	
		break;
	case EXPR_SCTP_PADDRINFO:
		result = evaluate_sctp_paddrinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_STATUS:
		result = evaluate_sctp_status_expression(in, out, error);
		break;
	case EXPR_SCTP_PEER_ADDR_PARAMS:
		result = evaluate_sctp_peer_addr_param_expression(in, out, error);
		break;
	case EXPR_SCTP_STREAM_VALUE:
		result = evaluate_sctp_stream_value_expression(in, out, error);
		break;
	case EXPR_SCTP_EVENT:
		result = evaluate_sctp_event_expression(in, out, error);
		break;
	case EXPR_SCTP_EVENT_SUBSCRIBE:
		result = evaluate_sctp_event_subscribe_expression(in, out, error);
		break;
	case EXPR_SCTP_SNDINFO:
		result = evaluate_sctp_sndinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_SETADAPTATION:
		result = evaluate_sctp_setadaptation_expression(in, out, error);
		break;
	case EXPR_SCTP_SNDRCVINFO:
		result = evaluate_sctp_sndrcvinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_PRINFO:
		result = evaluate_sctp_prinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_AUTHINFO:
		result = evaluate_sctp_authinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_SENDV_SPA:
		result = evaluate_sctp_sendv_spa_expression(in, out, error);
		break;
	case EXPR_SCTP_RCVINFO:
		result = evaluate_sctp_rcvinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_NXTINFO:
		result = evaluate_sctp_nxtinfo_expression(in, out, error);
		break;
	case EXPR_SCTP_RECVV_RN:
		result = evaluate_sctp_recvv_rn_expression(in, out, error);
		break;
	case EXPR_SCTP_SHUTDOWN_EVENT:
		result = evaluate_sctp_shutdown_event_expression(in, out, error);
		break;
	case EXPR_SCTP_SENDER_DRY_EVENT:
		result = evaluate_sctp_sender_dry_event_expression(in, out, error);
		break;
	case EXPR_SCTP_SEND_FAILED_EVENT:
		result = evaluate_sctp_send_failed_event_expression(in, out, error);
		break;
	case EXPR_WORD:
		out->type = EXPR_INTEGER;
		if (symbol_to_int(in->value.string,
				  &out->value.num, error))
			return STATUS_ERR;
		break;
	case EXPR_STRING:
		if (unescape_cstring_expression(in->value.string, out, error))
			return STATUS_ERR;
		break;
	case EXPR_SOCKET_ADDRESS_IPV4:	/* copy as-is */
		out->value.socket_address_ipv4 =
			malloc(sizeof(struct sockaddr_in));
		memcpy(out->value.socket_address_ipv4,
		       in->value.socket_address_ipv4,
		       sizeof(*(out->value.socket_address_ipv4)));
		break;
	case EXPR_SOCKET_ADDRESS_IPV6:	/* copy as-is */
		out->value.socket_address_ipv6 =
			malloc(sizeof(struct sockaddr_in6));
		memcpy(out->value.socket_address_ipv6,
		       in->value.socket_address_ipv6,
		       sizeof(*(out->value.socket_address_ipv6)));
		break;
	case EXPR_BINARY:
		result = evaluate_binary_expression(in, out, error);
		break;
	case EXPR_LIST:
		result = evaluate_list_expression(in, out, error);
		break;
	case EXPR_IOVEC:
		result = evaluate_iovec_expression(in, out, error);
		break;
	case EXPR_MSGHDR:
		result = evaluate_msghdr_expression(in, out, error);
		break;
	case EXPR_POLLFD:
		result = evaluate_pollfd_expression(in, out, error);
		break;
	case EXPR_NONE:
	case NUM_EXPR_TYPES:
		break;
	/* missing default case so compiler catches missing cases */
	}

	return result;
}

/* Return a copy of the given expression list with each expression
 * evaluated (e.g. symbols resolved to ints). On failure, return NULL
 * and fill in *error.
 */
int evaluate_expression_list(struct expression_list *in_list,
			     struct expression_list **out_list,
			     char **error)
{
	struct expression_list **node_ptr = out_list;
	while (in_list != NULL) {
		struct expression_list *node =
			calloc(1, sizeof(struct expression_list));
		*node_ptr = node;
		if (evaluate(in_list->expression,
			     &node->expression, error)) {
			free_expression_list(*out_list);
			*out_list = NULL;
			return STATUS_ERR;
		}
		node_ptr = &(node->next);
		in_list = in_list->next;
	}
	return STATUS_OK;
}
