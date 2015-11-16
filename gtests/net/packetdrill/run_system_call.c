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
 * A module to execute a system call from a test script.
 */

#include "run_system_call.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include "logging.h"
#include "run.h"
#include "script.h"

static int to_live_fd(struct state *state, int script_fd, int *live_fd,
		      char **error);
#if defined(linux)
struct sctp_tlv {
        u16 sn_type;
        u16 sn_flags;
        u32 sn_length;
};
#endif
#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_notification(struct iovec *iov, struct expression *iovec_expr,
				   char **error);
static int parse_expression_to_sctp_initmsg(struct expression *expr, struct sctp_initmsg *init,
				            char **error);
static int parse_expression_to_sctp_sndrcvinfo(struct expression *expr, struct sctp_sndrcvinfo *info,
					       bool send, char **error);
#endif
#if defined(__FreeBSD__)
static int parse_expression_to_sctp_sndinfo(struct expression *expr, struct sctp_sndinfo *info,
				            char **error);
static int parse_expression_to_sctp_prinfo(struct expression *expr, struct sctp_prinfo *info,
				            char **error);
static int parse_expression_to_sctp_authinfo(struct expression *expr, struct sctp_authinfo *info,
				             char **error);
#endif
#if defined(SCTP_DEFAULT_SNDINFO) || defined(SCTP_SNDINFO)
static int check_sctp_sndinfo(struct sctp_sndinfo_expr *expr, struct sctp_sndinfo *sctp_sndinfo,
			      char **error);
#endif
#if defined(SCTP_INITMSG) || defined(SCTP_INIT)
static int check_sctp_initmsg(struct sctp_initmsg_expr *expr, struct sctp_initmsg *sctp_initmsg,
			      char **error);
#endif
#if defined(__FreeBSD__)
static int check_sctp_extrcvinfo(struct sctp_extrcvinfo_expr *expr, struct sctp_extrcvinfo *sctp_info,
				 char **error);
#endif
#if defined(__FreeBSD__)
static int check_sctp_rcvinfo(struct sctp_rcvinfo_expr *expr, struct sctp_rcvinfo *sctp_rcvinfo,
				 char** error);
#endif
#if defined(__FreeBSD__)
static int check_sctp_nxtinfo(struct sctp_nxtinfo_expr *expr, struct sctp_nxtinfo *sctp_nxtinfo,
			      char **error);
#endif
#if defined(linux) || defined(__FreeBSD__)
static int check_sctp_sndrcvinfo(struct sctp_sndrcvinfo_expr *expr,
				 struct sctp_sndrcvinfo *sctp_sndrcvinfo,
				 char** error);
#endif

/* Provide a wrapper for the Linux gettid() system call (glibc does not). */
static pid_t gettid(void)
{
#ifdef linux
	return syscall(__NR_gettid);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	/* TODO(ncardwell): Implement me. XXX */
	return 0;
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)*/
}

/* Read a whole file into the given buffer of the given length. */
static void read_whole_file(const char *path, char *buffer, int max_bytes)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		die_perror("open");

	int bytes = read(fd, buffer, max_bytes);
	if (bytes < 0)
		die_perror("read");
	else if (bytes == max_bytes)
		die("%s file too large to read\n", path);

	if (close(fd) < 0)
		die_perror("close");
}

/* Return true iff the given thread is sleeping. */
static bool is_thread_sleeping(pid_t process_id, pid_t thread_id)
{
	/* Read the entire thread state file, using the buffer size ps uses. */
	char *proc_path = NULL;
	asprintf(&proc_path, "/proc/%d/task/%d/stat", process_id, thread_id);
	const int STATE_BUFFER_BYTES = 1023;
	char *state = calloc(STATE_BUFFER_BYTES, 1);
	read_whole_file(proc_path, state, STATE_BUFFER_BYTES - 1);
	state[STATE_BUFFER_BYTES - 1] = '\0';

	/* Parse the thread state from the third space-delimited field. */
	const int THREAD_STATE_INDEX = 3;
	const char *field = state;
	int i = 0;
	for (i = 0; i < THREAD_STATE_INDEX - 1; i++) {
		field = strchr(field, ' ');
		if (field == NULL)
			die("unable to parse %s\n", proc_path);
		++field;
	}
	bool is_sleeping = (field[0] == 'S');

	free(proc_path);
	free(state);

	return is_sleeping;
}

/* Returns number of expressions in the list. */
static int expression_list_length(struct expression_list *list)
{
	int count = 0;
	while (list != NULL) {
		list = list->next;
		++count;
	}
	return count;
}

static int get_arg_count(struct expression_list *args)
{
	return expression_list_length(args);
}

/* Verify that the expression list has the expected number of
 * expressions. Returns STATUS_OK on success; on failure returns
 * STATUS_ERR and sets error message.
 */
static int check_arg_count(struct expression_list *args, int expected,
			   char **error)
{
	assert(expected >= 0);
	int actual = get_arg_count(args);
	if (actual != expected) {
		asprintf(error, "Expected %d args but got %d", expected,
			 actual);
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Returns the argument with the given index. Returns the argument on
 * success; on failure returns NULL and sets error message.
 */
static struct expression *get_arg(struct expression_list *args,
				   int index, char **error)
{
	assert(index >= 0);
	int current = 0;
	while ((args != NULL) && (current < index)) {
		args = args->next;
		++current;
	}
	if ((args != NULL) && (current == index)) {
		if (!args->expression)
			asprintf(error, "Unknown expression at index %d",
				 index);
		return args->expression;
	} else {
		asprintf(error, "Argument list too short");
		return NULL;
	}
}

/* Return STATUS_OK if the expression is of the expected
 * type. Otherwise fill in the error with a human-readable error
 * message about the mismatch and return STATUS_ERR.
 */
static int check_type(struct expression *expression,
		      enum expression_t expected_type,
		      char **error)
{
	if (expression->type == expected_type) {
		return STATUS_OK;
	} else {
		asprintf(error, "Bad type; actual: %s expected: %s",
			 expression_type_to_string(expression->type),
			 expression_type_to_string(expected_type));
		return STATUS_ERR;
	}
}

/* Sets the value from the expression argument, checking that it is a
 * valid size_t, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_socklen_t(struct expression *expression,
		         socklen_t *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if (expression->value.num < 0) {
		asprintf(error,
			 "Value out of range for socklen_t: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}

#ifdef linux
/* Sets the value from the expression argument, checking that it is a
 * valid size_t, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_size_t(struct expression *expression,
		      size_t *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if (expression->value.num < 0) {
		asprintf(error,
			 "Value out of range for size_t: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}
#endif

/* Sets the value from the expression argument, checking that it is a
 * valid u32, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_u32(struct expression *expression,
		   u32 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > UINT32_MAX) ||
	    (expression->value.num < 0)) {
		asprintf(error,
			 "Value out of range for 32-bit unsigned integer: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}

/* Sets the value from the expression argument, checking that it is a
 * valid s32 or u32, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_s32(struct expression *expression,
		   s32 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > UINT_MAX) ||
	    (expression->value.num < INT_MIN)) {
		asprintf(error,
			 "Value out of range for 32-bit integer: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}

#if defined(SCTP_STATUS) || defined(SCTP_PEER_ADDR_PARAMS) || defined(SCTP_SS_VALUE)
/* Sets the value from the expression argument, checking that it is a
 * valid u16, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_u16(struct expression *expression,
		   u16 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > UINT16_MAX) ||
	    (expression->value.num < 0)) {
		asprintf(error,
			 "Value out of range for 16-bit unsigned integer: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}
#endif

#if 0
/* Sets the value from the expression argument, checking that it is a
 * valid s16, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_s16(struct expression *expression,
		   s16 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > INT16_MAX) ||
		(expression->value.num < INT16_MIN)) {
		asprintf(error,
			"Value out of range for 16-bit integer: %lld",
			expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}
#endif

#if defined(SCTP_PEER_ADDR_PARAMS)
/* Sets the value from the expression argument, checking that it is a
 * valid u8, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_u8(struct expression *expression,
		  u8 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > UINT8_MAX) ||
		(expression->value.num < 0)) {
		asprintf(error,
			 "Value out of range for 8-bit unsigned integer: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}
#endif

#if 0
/* Sets the value from the expression argument, checking that it is a
 * valid s8, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_s8(struct expression *expression,
		  s8 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > INT8_MAX) ||
		(expression->value.num < INT8_MIN)) {
		asprintf(error,
			 "Value out of range for 8-bit integer: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}
#endif

/* Return the value of the argument with the given index, and verify
 * that it has the expected type.
 */
static int s32_arg(struct expression_list *args,
		   int index, s32 *value, char **error)
{
	struct expression *expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	return get_s32(expression, value, error);
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type: a list with a single integer.
 */
static int s32_bracketed_arg(struct expression_list *args,
			     int index, s32 *value, char **error)
{
	struct expression_list *list;
	struct expression *expression;

	expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	if (check_type(expression, EXPR_LIST, error))
		return STATUS_ERR;
	list = expression->value.list;
	if (expression_list_length(list) != 1) {
		asprintf(error,
			 "Expected [<integer>] but got multiple elements");
		return STATUS_ERR;
	}
	return get_s32(list->expression, value, error);
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type: a list with a single integer.
 */
#ifdef __FreeBSD__
static int u32_bracketed_arg(struct expression_list *args,
			     int index, u32 *value, char **error)
{
	struct expression_list *list;
	struct expression *expression;

	expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	if (check_type(expression, EXPR_LIST, error))
		return STATUS_ERR;
	list = expression->value.list;
	if (expression_list_length(list) != 1) {
		asprintf(error,
			 "Expected [<integer>] but got multiple elements");
		return STATUS_ERR;
	}
	return get_u32(list->expression, value, error);
}
#endif

/* Return STATUS_OK iff the argument with the given index is an
 * ellipsis (...).
 */
static int ellipsis_arg(struct expression_list *args, int index, char **error)
{
	struct expression *expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	if (check_type(expression, EXPR_ELLIPSIS, error))
		return STATUS_ERR;
	return STATUS_OK;
}

#if defined(SCTP_GET_PEER_ADDR_INFO) || defined(SCTP_PEER_ADDR_PARAMS)
/* Return STATUS_OK if the argument in from type sockaddr_in or
 * sockaddr_in6
 */
static int get_sockstorage_arg(struct expression *arg, struct sockaddr_storage *addr, int live_fd)
{
	if (arg->type == EXPR_ELLIPSIS) {
		socklen_t len;

		len = (socklen_t)sizeof(struct sockaddr_storage);
		if (getpeername(live_fd, (struct sockaddr *)addr, &len)) {
			return STATUS_ERR;
		}
	} else if (arg->type == EXPR_SOCKET_ADDRESS_IPV4) {
		memcpy(addr, arg->value.socket_address_ipv4, sizeof(struct sockaddr_in));
	} else if (arg->type == EXPR_SOCKET_ADDRESS_IPV6) {
		memcpy(addr, arg->value.socket_address_ipv6, sizeof(struct sockaddr_in6));
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sockaddr(struct expression *sockaddr_expr, struct sockaddr *live_addr, char **error) {

	if (sockaddr_expr->type != EXPR_ELLIPSIS) {
		struct sockaddr *script_addr;
		if (sockaddr_expr->type == EXPR_SOCKET_ADDRESS_IPV4) {
			script_addr = (struct sockaddr*)sockaddr_expr->value.socket_address_ipv4;
		} else if (sockaddr_expr->type == EXPR_SOCKET_ADDRESS_IPV6) {
			script_addr = (struct sockaddr*)sockaddr_expr->value.socket_address_ipv6;
		} else {
			asprintf(error, "Bad type for sockaddr");
			return STATUS_ERR;
		}
		if (script_addr->sa_family != live_addr->sa_family) {
			asprintf(error, "sockaddr sa_family expected: %d actual: %d",
				 script_addr->sa_family, live_addr->sa_family);
			return STATUS_ERR;
		}
		switch(script_addr->sa_family) {
		case AF_INET:
			{
				struct sockaddr_in *script_sockaddr = (struct sockaddr_in*)script_addr;
				struct sockaddr_in *live_sockaddr = (struct sockaddr_in*)live_addr;
				if (live_sockaddr->sin_port != script_sockaddr->sin_port) {
					asprintf(error, "sockaddr_in from.sinport. expected: %d actual %d",
						ntohs(script_sockaddr->sin_port), ntohs(live_sockaddr->sin_port));
					return STATUS_ERR;
				}
				if (live_sockaddr->sin_addr.s_addr != script_sockaddr->sin_addr.s_addr) {
					int len = strnlen(inet_ntoa(script_sockaddr->sin_addr), 16);
					char *expected_addr = malloc(sizeof(char) * len);
					memcpy(expected_addr, inet_ntoa(script_sockaddr->sin_addr), len);
					asprintf(error, "sockaddr_in from.sin_addr. expected: %s actual %s",
						expected_addr, inet_ntoa(live_sockaddr->sin_addr));
					free(expected_addr);
					return STATUS_ERR;
				}
			}
			break;
		case AF_INET6:
			{
				struct sockaddr_in6 *script_sockaddr = (struct sockaddr_in6*)script_addr;
				struct sockaddr_in6 *live_sockaddr = (struct sockaddr_in6*)live_addr;
				if (live_sockaddr->sin6_port != script_sockaddr->sin6_port) {
					asprintf(error, "sockaddr_in6 from.sinport. expected: %d actual %d",
						ntohs(script_sockaddr->sin6_port), ntohs(live_sockaddr->sin6_port));
					return STATUS_ERR;
				}
				if (live_sockaddr->sin6_addr.s6_addr != script_sockaddr->sin6_addr.s6_addr) {
					char expected_addr[INET6_ADDRSTRLEN];
					char live_addr[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, &script_sockaddr->sin6_addr, expected_addr, INET6_ADDRSTRLEN);
					inet_ntop(AF_INET6, &live_sockaddr->sin6_addr, live_addr, INET6_ADDRSTRLEN);
					asprintf(error, "sockaddr_in6 from.sin6_addr. expected: %s actual %s",
						 expected_addr, live_addr);
					return STATUS_ERR;
				}
			}
			break;
		}
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
int check_u8_expr(struct expression *expr, u8 value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		u8 script_val;

		if (get_u8(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (script_val != value) {
			asprintf(error, "%s: expected: %hhu actual: %hhu", val_name, script_val, value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
int check_u16_expr(struct expression *expr, u16 value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		u16 script_val;

		if (get_u16(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (script_val != value) {
			asprintf(error, "%s: expected: %hu actual: %hu", val_name, script_val, value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

int check_s32_expr(struct expression *expr, s16 value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		s32 script_val;

		if (get_s32(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (script_val != value) {
			asprintf(error, "%s: expected: %d actual: %d", val_name, script_val, value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

int check_u32_hton_expr(struct expression *expr, u32 value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		u32 script_val;

		if (get_u32(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (htonl(value) != htonl(script_val)) {
			asprintf(error, "%s: expected: %u actual: %u", val_name,
				 htonl(script_val), htonl(value));
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

int check_u32_expr(struct expression *expr, u32 value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		u32 script_val;

		if (get_u32(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (script_val != value) {
			asprintf(error, "%s: expected: %u actual: %u", val_name, script_val, value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

int check_socklen_t_expr(struct expression *expr, socklen_t value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		socklen_t script_val;

		if (get_socklen_t(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (script_val != value) {
			asprintf(error, "%s: expected: %u actual: %u", val_name, script_val, value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

#ifdef linux
int check_size_t_expr(struct expression *expr, size_t value, char *val_name, char **error) {
	if (expr->type != EXPR_ELLIPSIS) {
		size_t script_val;

		if (get_size_t(expr, &script_val, error)) {
			return STATUS_ERR;
		}
		if (script_val != value) {
			asprintf(error, "%s: expected: %zu actual: %zu", val_name, script_val, value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_u8array_expr(struct expression *expr_list, u8 *data, size_t data_len, char *val_name, char **error) {
	if ( expr_list->type != EXPR_ELLIPSIS) {
		struct expression *expr = NULL;
		unsigned int i;

		switch(expr_list->type) {
		case EXPR_LIST:
			if (data_len != expression_list_length(expr_list->value.list)) {
				asprintf(error, "%s length: expected: %u actual %zu",
					 val_name, expression_list_length(expr_list->value.list), data_len);
				return STATUS_ERR;
			}
			for (i = 0; i < data_len; i++) {
				expr = get_arg(expr_list->value.list, i, error);
				if (expr->type != EXPR_ELLIPSIS) {
					u8 script_val;

					if (get_u8(expr, &script_val, error)) {
						return STATUS_ERR;
					}
					if (script_val != data[i]) {
						asprintf(error, "%s[%d]: expected: %hhu actual: %hhu",
							val_name, i, script_val, data[i]);
						return STATUS_ERR;
					}
				}
			}
			break;
		case EXPR_NULL:
			if (data != NULL)
				return STATUS_ERR;
			break;
		default: asprintf(error, "Bad expressiontype for %s", val_name);
			return STATUS_ERR;
			break;
		}
	}
	return STATUS_OK;
}
#endif

/* Free all the space used by the given iovec. */
static void iovec_free(struct iovec *iov, size_t iov_len)
{
	int i;

	if (iov == NULL)
		return;

	for (i = 0; i < iov_len; ++i)
		free(iov[i].iov_base);
	free(iov);
}

/* Allocate and fill in an iovec described by the given expression.
 * Return STATUS_OK if the expression is a valid iovec. Otherwise
 * fill in the error with a human-readable error message and return
 * STATUS_ERR.
 */
static int iovec_new(struct expression *expression,
		     struct iovec **iov_ptr, size_t *iov_len_ptr,
		     char **error)
{
	int status = STATUS_ERR;
	int i;
	struct expression_list *list;	/* input expression from script */
	size_t iov_len = 0;
	struct iovec *iov = NULL;	/* live output */

	if (check_type(expression, EXPR_LIST, error))
		goto error_out;

	list = expression->value.list;

	iov_len = expression_list_length(list);
	iov = calloc(iov_len, sizeof(struct iovec));

	for (i = 0; i < iov_len; ++i, list = list->next) {
		size_t len;
		struct iovec_expr *iov_expr;

		if (check_type(list->expression, EXPR_IOVEC, error))
			goto error_out;

		iov_expr = list->expression->value.iovec;

		assert(iov_expr->iov_base->type == EXPR_ELLIPSIS ||
		       iov_expr->iov_base->type == EXPR_SCTP_ASSOC_CHANGE ||
		       iov_expr->iov_base->type == EXPR_SCTP_PADDR_CHANGE ||
		       iov_expr->iov_base->type == EXPR_SCTP_REMOTE_ERROR ||
		       iov_expr->iov_base->type == EXPR_SCTP_SEND_FAILED ||
		       iov_expr->iov_base->type == EXPR_SCTP_SHUTDOWN_EVENT ||
		       iov_expr->iov_base->type == EXPR_SCTP_ADAPTATION_EVENT ||
		       iov_expr->iov_base->type == EXPR_SCTP_PDAPI_EVENT ||
		       iov_expr->iov_base->type == EXPR_SCTP_AUTHKEY_EVENT ||
		       iov_expr->iov_base->type == EXPR_SCTP_SENDER_DRY_EVENT ||
		       iov_expr->iov_base->type == EXPR_SCTP_SEND_FAILED_EVENT ||
		       iov_expr->iov_base->type == EXPR_SCTP_TLV);
		assert(iov_expr->iov_len->type == EXPR_INTEGER);

		len = iov_expr->iov_len->value.num;

		iov[i].iov_len = len;
		iov[i].iov_base = calloc(len, 1);
	}

	status = STATUS_OK;

error_out:
	*iov_ptr = iov;
	*iov_len_ptr = iov_len;
	return status;
}

/* Allocate and fill in an cmsghdr described by the given expression.
 * Return STATUS_OK if the expression is a valid cmsghdr. Otherwise
 * fill in the error with a human-readable error message and return
 * STATUS_ERR.
 */
#ifdef linux
static int cmsg_new(struct expression *expression,
		    void **cmsg_ptr, size_t *cmsg_len_ptr,
		    bool send, char **error)
#else
static int cmsg_new(struct expression *expression,
		    void **cmsg_ptr, socklen_t *cmsg_len_ptr,
		    bool send, char **error)
#endif
{
	struct expression_list *list;
	int list_len = 0, i = 0;
	size_t cmsg_size = 0;
	struct cmsghdr *cmsg;

	if (check_type(expression, EXPR_LIST, error))
		return STATUS_ERR;
	list = expression->value.list;
	list_len = expression_list_length(list);
	//calc size of cmsg in list
	if (list_len == 0){
		cmsg_ptr = NULL;
		return STATUS_OK;
	}
	for (i = 0; i < list_len; i++) {
		struct expression *cmsg_expr;
		cmsg_expr = get_arg(list, i, error);
		switch (cmsg_expr->value.cmsghdr->cmsg_data->type) {
#if defined(SCTP_INIT)
		case EXPR_SCTP_INITMSG:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_initmsg));
			break;
#endif
#if defined(SCTP_SNDRCV)
		case EXPR_SCTP_SNDRCVINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
			break;
#endif
#if defined(SCTP_EXTRCV)
		case EXPR_SCTP_EXTRCVINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_extrcvinfo));
			break;
#endif
#if defined(SCTP_SNDINFO)
		case EXPR_SCTP_SNDINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_sndinfo));
			break;
#endif
#if defined(SCTP_RCVINFO)
		case EXPR_SCTP_RCVINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_rcvinfo));
			break;
#endif
#if defined(SCTP_NXTINFO)
		case EXPR_SCTP_NXTINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_nxtinfo));
			break;
#endif
#if defined(SCTP_PRINFO)
		case EXPR_SCTP_PRINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_prinfo));
			break;
#endif
#if defined(SCTP_AUTHINFO)
		case EXPR_SCTP_AUTHINFO:
			cmsg_size += CMSG_SPACE(sizeof(struct sctp_authinfo));
			break;
#endif
#if defined(SCTP_DSTADDRV4)
		case EXPR_SOCKET_ADDRESS_IPV4:
			cmsg_size += CMSG_SPACE(sizeof(struct in_addr));
			break;
#endif
#if defined(SCTP_DSTADDRV6)
		case EXPR_SOCKET_ADDRESS_IPV6:
			cmsg_size += CMSG_SPACE(sizeof(struct in6_addr));
			break;
#endif
		default:
			asprintf(error,"cmsg %d type not valid", i);
			return STATUS_ERR;
		}
	}
#ifndef linux
	*cmsg_len_ptr = (socklen_t)cmsg_size;
#endif
	cmsg = calloc(1, cmsg_size);
	*cmsg_ptr = (void *)cmsg;

	for (i = 0; i < list_len; i++) {
		struct expression *expr;
		struct cmsghdr_expr *cmsg_expr;

		expr = get_arg(list, i, error);
		if(check_type(expr, EXPR_CMSGHDR, error))
			goto error_out;
		cmsg_expr = expr->value.cmsghdr;
#ifdef linux
		if (get_size_t(cmsg_expr->cmsg_len, &cmsg->cmsg_len, error))
#else
		if (get_socklen_t(cmsg_expr->cmsg_len, &cmsg->cmsg_len, error))
#endif
			goto error_out;
		if (get_s32(cmsg_expr->cmsg_level, &cmsg->cmsg_level, error))
			goto error_out;
		if (get_s32(cmsg_expr->cmsg_type, &cmsg->cmsg_type, error))
			goto error_out;

		switch(cmsg_expr->cmsg_data->type) {
#if defined(SCTP_INIT)
		case EXPR_SCTP_INITMSG: {
			struct sctp_initmsg init;
			if (parse_expression_to_sctp_initmsg(cmsg_expr->cmsg_data, &init, error)) {
				goto error_out;
			}
			memcpy(CMSG_DATA(cmsg), &init, sizeof(struct sctp_initmsg));
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_initmsg)));
			break;
		}
#endif
#if defined(SCTP_SNDRCV)
		case EXPR_SCTP_SNDRCVINFO: {
			struct sctp_sndrcvinfo info;
			if (parse_expression_to_sctp_sndrcvinfo(cmsg_expr->cmsg_data, &info, send, error)) {
				goto error_out;
			}
			memcpy(CMSG_DATA(cmsg), &info, sizeof(struct sctp_sndrcvinfo));
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)));
			break;
		}
#endif
#if defined(SCTP_EXTRCV)
		case EXPR_SCTP_EXTRCVINFO: {
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_extrcvinfo)));
			break;
		}
#endif
#if defined(SCTP_SNDINFO)
		case EXPR_SCTP_SNDINFO: {
			struct sctp_sndinfo info;
			if (parse_expression_to_sctp_sndinfo(cmsg_expr->cmsg_data, &info, error)) {
				goto error_out;
			}
			memcpy(CMSG_DATA(cmsg), &info, sizeof(struct sctp_sndinfo));
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_sndinfo)));
			break;
		}
#endif
#if defined(SCTP_RCVINFO)
		case EXPR_SCTP_RCVINFO:
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_rcvinfo)));
			break;
#endif
#if defined(SCTP_NXTINFO)
		case EXPR_SCTP_NXTINFO:
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_nxtinfo)));
			break;
#endif
#if defined(SCTP_PRINFO)
		case EXPR_SCTP_PRINFO: {
			struct sctp_prinfo info;
			if (parse_expression_to_sctp_prinfo(cmsg_expr->cmsg_data, &info, error)) {
				goto error_out;
			}
			memcpy(CMSG_DATA(cmsg), &info, sizeof(struct sctp_prinfo));
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_prinfo)));
			break;
		}
#endif
#if defined(SCTP_AUTHINFO)
		case EXPR_SCTP_AUTHINFO: {
			struct sctp_authinfo info;
			if (parse_expression_to_sctp_authinfo(cmsg_expr->cmsg_data, &info, error)) {
				goto error_out;
			}
			memcpy(CMSG_DATA(cmsg), &info, sizeof(struct sctp_authinfo));
			cmsg = (struct cmsghdr *) ((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_authinfo)));
			break;
		}
#endif
#if defined(SCTP_DSTADDRV4)
		case EXPR_SOCKET_ADDRESS_IPV4:
			memcpy(CMSG_DATA(cmsg), &cmsg_expr->cmsg_data->value.socket_address_ipv4->sin_addr, sizeof(struct in_addr));
			cmsg = (struct cmsghdr *)((caddr_t)cmsg + CMSG_SPACE(sizeof(struct in_addr)));
			break;
#endif
#if defined(SCTP_DSTADDRV6)
		case EXPR_SOCKET_ADDRESS_IPV6:
			memcpy(CMSG_DATA(cmsg), &cmsg_expr->cmsg_data->value.socket_address_ipv6->sin6_addr, sizeof(struct in6_addr));
			cmsg = (struct cmsghdr *)((caddr_t)cmsg + CMSG_SPACE(sizeof(struct in6_addr)));
			break;
#endif
		default:
			asprintf(error,"cmsg.cmsg_data %d type not valid", i);
			goto error_out;
		}
	}

	return STATUS_OK;
error_out:
	free(*cmsg_ptr);
	*cmsg_ptr = NULL;
	*cmsg_len_ptr = 0;
	return STATUS_ERR;
}

static int check_cmsghdr(struct expression *expr_list, struct msghdr *msg, char  **error) {
	struct expression_list *list;
	struct expression *cmsg_expr;
	struct cmsghdr *cmsg_ptr;
	int cnt = 0;
	int list_len = 0;

	assert(expr_list->type == EXPR_LIST);

	list = expr_list->value.list;
	list_len = expression_list_length(list);
	for (cmsg_ptr = CMSG_FIRSTHDR(msg); cmsg_ptr != NULL; cmsg_ptr = CMSG_NXTHDR(msg, cmsg_ptr)) {
		cmsg_expr = get_arg(list, cnt, error);
		if (cmsg_expr->type != EXPR_ELLIPSIS) {
			struct cmsghdr_expr *expr;
			expr = cmsg_expr->value.cmsghdr;
			if (check_s32_expr(expr->cmsg_type, cmsg_ptr->cmsg_type,
					   "cmsghdr.cmsg_type", error))
				return STATUS_ERR;
#ifdef linux
			if (check_size_t_expr(expr->cmsg_len, cmsg_ptr->cmsg_len,
					         "cmsghdr.cmsg_len", error))
#else
			if (check_socklen_t_expr(expr->cmsg_len, cmsg_ptr->cmsg_len,
				              "cmsghdr.cmsg_len", error))
#endif
				return STATUS_ERR;
			if (check_s32_expr(expr->cmsg_level, cmsg_ptr->cmsg_level,
					   "cmsghdr.cmsg_level", error))
				return STATUS_ERR;

			if (expr->cmsg_data->type == EXPR_ELLIPSIS) {
				continue;
			}
			switch(cmsg_ptr->cmsg_type) {
#ifdef SCTP_INIT
			case SCTP_INIT:
				if (check_sctp_initmsg(expr->cmsg_data->value.sctp_initmsg,
						       (struct sctp_initmsg *) CMSG_DATA(cmsg_ptr),
						       error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_SNDRCV
			case SCTP_SNDRCV:
				if (check_sctp_sndrcvinfo(expr->cmsg_data->value.sctp_sndrcvinfo,
							  (struct sctp_sndrcvinfo *) CMSG_DATA(cmsg_ptr),
							  error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_EXTRCV
			case SCTP_EXTRCV:
				if (check_sctp_extrcvinfo(expr->cmsg_data->value.sctp_extrcvinfo,
							  (struct sctp_extrcvinfo *) CMSG_DATA(cmsg_ptr),
							  error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_SNDINFO
			case SCTP_SNDINFO:
				if (check_sctp_sndinfo(expr->cmsg_data->value.sctp_sndinfo,
						       (struct sctp_sndinfo *) CMSG_DATA(cmsg_ptr),
						       error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_RCVINFO
			case SCTP_RCVINFO:
				if (check_sctp_rcvinfo(expr->cmsg_data->value.sctp_rcvinfo,
						       (struct sctp_rcvinfo *) CMSG_DATA(cmsg_ptr),
						       error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_NXTINFO
			case SCTP_NXTINFO:
				if (check_sctp_nxtinfo(expr->cmsg_data->value.sctp_nxtinfo,
						       (struct sctp_nxtinfo *) CMSG_DATA(cmsg_ptr),
						       error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_PRINFO
			case SCTP_PRINFO:
				if (check_u16_expr(expr->cmsg_data->value.sctp_prinfo->pr_policy,
					   ((struct sctp_prinfo *)CMSG_DATA(cmsg_ptr))->pr_policy,
					   "prinfo.pr_policy", error)) {
					return STATUS_ERR;
				}
				if (check_u32_expr(expr->cmsg_data->value.sctp_prinfo->pr_value,
					   ((struct sctp_prinfo *)CMSG_DATA(cmsg_ptr))->pr_value,
					   "prinfo.pr_value", error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_AUTHINFO
			case SCTP_AUTHINFO:
				if (check_u16_expr(expr->cmsg_data->value.sctp_authinfo->auth_keynumber,
					   ((struct sctp_authinfo *)CMSG_DATA(cmsg_ptr))->auth_keynumber,
					   "authinfo.auth_keynumber", error)) {
					return STATUS_ERR;
				}
				break;
#endif
#ifdef SCTP_DSTADDRV4
			case SCTP_DSTADDRV4:
				if (expr->cmsg_data->type != EXPR_ELLIPSIS) {
					struct sockaddr_in *addr = expr->cmsg_data->value.socket_address_ipv4;
					struct in_addr *cmsg_addr = (struct in_addr *) CMSG_DATA(cmsg_ptr);
					if (addr->sin_addr.s_addr != cmsg_addr->s_addr) {
						asprintf(error, "cmsg_data for SCTP_DSTADDRV4: expected: %s actual: %s",
							 inet_ntoa(addr->sin_addr),
							 inet_ntoa(*cmsg_addr));
						return STATUS_ERR;
					}
				}
				break;
#endif
#ifdef SCTP_DSTADDRV6
			case SCTP_DSTADDRV6:
				if (expr->cmsg_data->type != EXPR_ELLIPSIS) {
					struct sockaddr_in6 *addr = expr->cmsg_data->value.socket_address_ipv6;
					struct in6_addr *cmsg_addr = (struct in6_addr *) CMSG_DATA(cmsg_ptr);
					if (memcmp(&addr->sin6_addr, cmsg_addr, sizeof(struct in6_addr))) {
						char expected_addr[INET6_ADDRSTRLEN];
						char live_addr[INET6_ADDRSTRLEN];
						inet_ntop(AF_INET6, &addr->sin6_addr, expected_addr, INET6_ADDRSTRLEN);
						inet_ntop(AF_INET6, cmsg_addr, live_addr, INET6_ADDRSTRLEN);
						asprintf(error, "sockaddr_in6 from.sin6_addr. expected: %s actual %s",
							 expected_addr, live_addr);
						return STATUS_ERR;
					}
				}
				break;
#endif
			default:
				asprintf(error, "can't check cmsg type");
				return STATUS_ERR;
			}
		}
		cnt++;
	}
	if (cnt != list_len) {
		asprintf(error, "Return cmsg count is unqual to expected list len. actual %u, expected %u", cnt, list_len);
		return STATUS_ERR;
	}
	return STATUS_OK;
}


/* Free all the space used by the given msghdr. */
static void msghdr_free(struct msghdr *msg, size_t iov_len)
{
	if (msg == NULL)
		return;

	free(msg->msg_name);
	iovec_free(msg->msg_iov, iov_len);
	free(msg->msg_control);
}

/* Allocate and fill in a msghdr described by the given expression. */
static int msghdr_new(struct expression *expression,
		      struct msghdr **msg_ptr, size_t *iov_len_ptr,
		      bool send, char **error)
{
	int status = STATUS_ERR;
	s32 s32_val = 0;
	struct msghdr_expr *msg_expr;	/* input expression from script */
	socklen_t name_len = sizeof(struct sockaddr_storage);
	struct msghdr *msg = NULL;	/* live output */
#ifdef linux
	size_t cmsg_len = 0;
#else
	socklen_t cmsg_len = 0;
#endif

	if (check_type(expression, EXPR_MSGHDR, error))
		goto error_out;

	msg_expr = expression->value.msghdr;

	msg = calloc(1, sizeof(struct msghdr));

	if (msg_expr->msg_name != NULL) {
		assert(msg_expr->msg_name->type == EXPR_ELLIPSIS);
		msg->msg_name = calloc(1, name_len);
	}

	if (msg_expr->msg_namelen != NULL) {
		assert(msg_expr->msg_namelen->type == EXPR_ELLIPSIS);
		msg->msg_namelen = name_len;
	}

	if (msg_expr->msg_iov != NULL) {
		if (iovec_new(msg_expr->msg_iov, &msg->msg_iov, iov_len_ptr,
			      error))
			goto error_out;
	}

	if (msg_expr->msg_iovlen != NULL) {
		if (get_s32(msg_expr->msg_iovlen, &s32_val, error))
			goto error_out;
		msg->msg_iovlen = s32_val;
	}

	if (msg->msg_iovlen != *iov_len_ptr) {
		asprintf(error,
			 "msg_iovlen %d does not match %d-element iovec array",
			 (int)msg->msg_iovlen, (int)*iov_len_ptr);
		goto error_out;
	}

	if (msg_expr->msg_control != NULL) {
		if (cmsg_new(msg_expr->msg_control, &msg->msg_control, &cmsg_len, send, error))
			goto error_out;
	}

	if (msg_expr->msg_controllen != NULL) {
#ifdef linux
		if (get_size_t(msg_expr->msg_controllen, &msg->msg_controllen, error))
#else
		if (get_socklen_t(msg_expr->msg_controllen, &msg->msg_controllen, error))
#endif
			goto error_out;
	}

	if (msg->msg_controllen != cmsg_len) {
		asprintf(error,
			 "msg_controllen %zu does not match %zu size of cmsghdr array",
			 (size_t)msg->msg_controllen, (size_t)cmsg_len);
		goto error_out;
	}

	if (msg_expr->msg_flags != NULL) {
		if (get_s32(msg_expr->msg_flags, &s32_val, error))
			goto error_out;
		msg->msg_flags = s32_val;
	}

	status = STATUS_OK;

error_out:
	*msg_ptr = msg;
	return status;
}

/* Allocate and fill in a pollfds array described by the given
 * fds_expression. Return STATUS_OK if the expression is a valid
 * pollfd struct array. Otherwise fill in the error with a
 * human-readable error message and return STATUS_ERR.
 */
static int pollfds_new(struct state *state,
		       struct expression *fds_expression,
		       struct pollfd **fds_ptr, size_t *fds_len_ptr,
		       char **error)
{
	int status = STATUS_ERR;
	int i;
	struct expression_list *list;	/* input expression from script */
	size_t fds_len = 0;
	struct pollfd *fds = NULL;	/* live output */

	if (check_type(fds_expression, EXPR_LIST, error))
		goto error_out;

	list = fds_expression->value.list;

	fds_len = expression_list_length(list);
	fds = calloc(fds_len, sizeof(struct pollfd));

	for (i = 0; i < fds_len; ++i, list = list->next) {
		struct pollfd_expr *fds_expr;

		if (check_type(list->expression, EXPR_POLLFD, error))
			goto error_out;

		fds_expr = list->expression->value.pollfd;

		if (check_type(fds_expr->fd, EXPR_INTEGER, error))
			goto error_out;
		if (check_type(fds_expr->events, EXPR_INTEGER, error))
			goto error_out;
		if (check_type(fds_expr->revents, EXPR_INTEGER, error))
			goto error_out;

		if (to_live_fd(state, fds_expr->fd->value.num,
			       &fds[i].fd, error))
			goto error_out;

		fds[i].events = fds_expr->events->value.num;
		fds[i].revents = fds_expr->revents->value.num;
	}

	status = STATUS_OK;

error_out:
	*fds_ptr = fds;
	*fds_len_ptr = fds_len;
	return status;
}

/* Check the results of a poll() system call: check that the output
 * revents fields in the fds array match those in the script. Return
 * STATUS_OK if they match. Otherwise fill in the error with a
 * human-readable error message and return STATUS_ERR.
 */
static int pollfds_check(struct expression *fds_expression,
			 const struct pollfd *fds, size_t fds_len,
			 char **error)
{
	struct expression_list *list;	/* input expression from script */
	int i;

	assert(fds_expression->type == EXPR_LIST);
	list = fds_expression->value.list;

	for (i = 0; i < fds_len; ++i, list = list->next) {
		struct pollfd_expr *fds_expr;
		int expected_revents, actual_revents;

		assert(list->expression->type == EXPR_POLLFD);
		fds_expr = list->expression->value.pollfd;

		assert(fds_expr->fd->type == EXPR_INTEGER);
		assert(fds_expr->events->type == EXPR_INTEGER);
		assert(fds_expr->revents->type == EXPR_INTEGER);

		expected_revents = fds_expr->revents->value.num;
		actual_revents = fds[i].revents;
		if (actual_revents != expected_revents) {
			char *expected_revents_string =
				flags_to_string(poll_flags,
							expected_revents);
			char *actual_revents_string =
				flags_to_string(poll_flags,
							actual_revents);
			asprintf(error,
				 "Expected revents of %s but got %s "
				 "for pollfd %d",
				 expected_revents_string,
				 actual_revents_string,
				 i);
			free(expected_revents_string);
			free(actual_revents_string);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

/* For blocking system calls, give up the global lock and wake the
 * main thread so it can continue test execution. Callers should call
 * this function immediately before calling a system call in order to
 * release the global lock immediately before a system call that the
 * script expects to block.
 */
static void begin_syscall(struct state *state, struct syscall_spec *syscall)
{
	if (is_blocking_syscall(syscall)) {
		assert(state->syscalls->state == SYSCALL_ENQUEUED);
		state->syscalls->state = SYSCALL_RUNNING;
		run_unlock(state);
		DEBUGP("syscall thread: begin_syscall signals dequeued\n");
		if (pthread_cond_signal(&state->syscalls->dequeued) != 0)
			die_perror("pthread_cond_signal");
	}
}

/* Verify that the system call returned the expected result code and
 * errno value. Returns STATUS_OK on success; on failure returns
 * STATUS_ERR and sets error message. Callers should call this function
 * immediately after returning from a system call in order to immediately
 * re-grab the global lock if this is a blocking call.
 */
enum result_check_t {
	CHECK_EXACT,		/* check that result matches exactly */
	CHECK_NON_NEGATIVE,	/* check that result is non-negative */
	CHECK_ALLOW_MAPPING,	/* checks for results after accept-syscall */
};
static int end_syscall(struct state *state, struct syscall_spec *syscall,
		       enum result_check_t mode, int actual, char **error)
{
	int actual_errno = errno;	/* in case we clobber this later */
	s32 expected = 0;

	/* For blocking calls, advance state and reacquire the global lock. */
	if (is_blocking_syscall(syscall)) {
		s64 live_end_usecs = now_usecs();
		DEBUGP("syscall thread: end_syscall grabs lock\n");
		run_lock(state);
		state->syscalls->live_end_usecs = live_end_usecs;
		assert(state->syscalls->state == SYSCALL_RUNNING);
		state->syscalls->state = SYSCALL_DONE;
	}

	/* Compare actual vs expected return value */
	if (get_s32(syscall->result, &expected, error))
		return STATUS_ERR;
	if (mode == CHECK_NON_NEGATIVE) {
		if (actual < 0) {
			asprintf(error,
				 "Expected non-negative result but got %d with errno %d (%s)",
				 actual, actual_errno, strerror(actual_errno));
			return STATUS_ERR;
		}
	} else if (mode == CHECK_EXACT) {
		if (actual != expected) {
			if (actual < 0)
				asprintf(error,
					 "Expected result %d but got %d with errno %d (%s)",
					 expected,
					 actual,
					 actual_errno, strerror(actual_errno));
			else
				asprintf(error,
					 "Expected result %d but got %d",
					 expected, actual);
			return STATUS_ERR;
		}
	} else if (mode == CHECK_ALLOW_MAPPING) {
		if ((expected >= 0)  && (actual < 0)) {
			asprintf(error,
				 "Expected non-negative result but got %d with errno %d (%s)",
				 actual, actual_errno, strerror(actual_errno));
			return STATUS_ERR;
		} else if ((expected < 0) && (actual != expected)) {
			asprintf(error,
				 "Expected result %d but got %d",
				 expected, actual);
			return STATUS_ERR;
		}
	} else {
		assert(!"bad mode");
	}

	/* Compare actual vs expected errno */
	if (syscall->error != NULL) {
		s64 expected_errno = 0;
		if (symbol_to_int(syscall->error->errno_macro,
				  &expected_errno, error))
			return STATUS_ERR;
		if (actual_errno != expected_errno) {
			char *exp_error, *act_error;

			asprintf(&exp_error, "%s", strerror(expected_errno));
			asprintf(&act_error, "%s", strerror(actual_errno));
			asprintf(error,
				 "Expected errno %d (%s) but got %d (%s)",
				 (int)expected_errno, exp_error,
				 actual_errno, act_error);
			free(exp_error);
			free(act_error);
			return STATUS_ERR;
		}
	}

	return STATUS_OK;
}

/* Return a pointer to the socket with the given script fd, or NULL. */
static struct socket *find_socket_by_script_fd(
	struct state *state, int script_fd)
{
	struct socket *socket = NULL;
	for (socket = state->sockets; socket != NULL; socket = socket->next)
		if (!socket->is_closed && (socket->script.fd == script_fd)) {
			assert(socket->live.fd >= 0);
			assert(socket->script.fd >= 0);
			return socket;
		}
	return NULL;
}

/* Return a pointer to the socket with the given live fd, or NULL. */
static struct socket *find_socket_by_live_fd(
	struct state *state, int live_fd)
{
	struct socket *socket = NULL;
	for (socket = state->sockets; socket != NULL; socket = socket->next)
		if (!socket->is_closed && (socket->live.fd == live_fd)) {
			assert(socket->live.fd >= 0);
			assert(socket->script.fd >= 0);
			return socket;
		}
	return NULL;
}

/* Find the live fd corresponding to the fd in a script. Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int to_live_fd(struct state *state, int script_fd, int *live_fd,
		      char **error)
{
	struct socket *socket = find_socket_by_script_fd(state, script_fd);
	if (socket != NULL) {
		*live_fd = socket->live.fd;
		return STATUS_OK;
	} else {
		*live_fd = -1;
		asprintf(error, "unable to find socket with script fd %d",
			 script_fd);
		return STATUS_ERR;
	}
}

/****************************************************************************
 * Here we have the "backend" post-processing and pre-processing that
 * we perform after and/or before each of the system calls that
 * we support...
 */

/* The app called socket() in the script and we did a live reenactment
 * socket() call. Create a struct socket to track the new socket.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_socket(struct state *state, int address_family,
			      int protocol, int script_fd, int live_fd,
			      char **error)
{
	/* Validate fd values. */
	if (script_fd < 0) {
		asprintf(error, "invalid socket fd %d in script", script_fd);
		return STATUS_ERR;
	}
	if (live_fd < 0) {
		asprintf(error, "invalid live socket fd %d", live_fd);
		return STATUS_ERR;
	}

	/* Look for sockets with conflicting fds. Should not happen if
	   the script is valid and this program is bug-free. */
	if (find_socket_by_script_fd(state, script_fd)) {
		asprintf(error, "duplicate socket fd %d in script",
			 script_fd);
		return STATUS_ERR;
	}
	if (find_socket_by_live_fd(state, live_fd)) {
		asprintf(error, "duplicate live socket fd %d", live_fd);
		return STATUS_ERR;
	}

	/* These fd values are kosher, so store them. */
	struct socket *socket = socket_new(state);
	socket->state		= SOCKET_NEW;
	socket->address_family	= address_family;
	socket->protocol	= protocol;
	socket->script.fd	= script_fd;
	socket->live.fd		= live_fd;

	/* Any later packets in the test script will now be mapped here. */
	state->socket_under_test = socket;

	DEBUGP("socket() creating new socket: script_fd: %d live_fd: %d\n",
	       socket->script.fd, socket->live.fd);
	return STATUS_OK;
}

/* Handle a close() call for the given socket.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_close(struct state *state, int script_fd,
			     int live_fd, char **error)
{
	struct socket *socket = find_socket_by_script_fd(state, script_fd);
	if ((socket == NULL) || (socket->live.fd != live_fd))
		goto error_out;

	socket->is_closed = true;
	return STATUS_OK;

error_out:
	asprintf(error,
		 "unable to find socket with script fd %d and live fd %d",
		 script_fd, live_fd);
	return STATUS_ERR;
}

/* Fill in the live_addr and live_addrlen for a bind() call.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_bind(struct state *state,
			    struct sockaddr *live_addr,
			    socklen_t *live_addrlen, char **error)
{
	DEBUGP("run_syscall_bind\n");

	/* Fill in the live address we want to bind to */
	ip_to_sockaddr(&state->config->live_bind_ip,
		       state->config->live_bind_port,
		       live_addr, live_addrlen);

	return STATUS_OK;
}

/* Handle a listen() call for the given socket.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_listen(struct state *state, int script_fd,
			      int live_fd, char **error)
{
	struct socket *socket = NULL;
	socket = find_socket_by_script_fd(state, script_fd);
	if (socket != NULL) {
		assert(socket->script.fd == script_fd);
		assert(socket->live.fd == live_fd);
		if (socket->state != SOCKET_NEW) {
			asprintf(error,
				 "bad listen(); script fd %d in state %d",
				 script_fd, socket->state);
			return STATUS_ERR;
		}
		socket->state = SOCKET_PASSIVE_LISTENING;
		return STATUS_OK;
	} else {
		asprintf(error, "unable to find socket with script fd %d",
			 script_fd);
		return STATUS_ERR;
	}
}

/* Handle an accept() call creating a new socket with the given file
 * descriptors.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_accept(struct state *state,
			      int script_accepted_fd,
			      int live_accepted_fd,
			      struct sockaddr *live_addr,
			      int live_addrlen, char **error)
{
	struct socket *socket = NULL;
	struct ip_address ip;
	u16 port = 0;
	DEBUGP("run_syscall_accept\n");

	/* Parse the sockaddr into a nice multi-protocol ip_address struct. */
	ip_from_sockaddr(live_addr, live_addrlen, &ip, &port);

	/* For ipv4-mapped-ipv6: if ip is IPv4-mapped IPv6, map it to IPv4. */
	if (ip.address_family == AF_INET6) {
		struct ip_address ipv4;
		if (ipv6_map_to_ipv4(ip, &ipv4) == STATUS_OK)
			ip = ipv4;
	}

	for (socket = state->sockets; socket != NULL; socket = socket->next) {
		if (DEBUG_LOGGING) {
			char remote_string[ADDR_STR_LEN];
			DEBUGP("socket state=%d script addr: %s:%d\n",
			       socket->state,
			       ip_to_string(&socket->script.remote.ip,
					    remote_string),
			       socket->script.remote.port);
		}

		if ((socket->state == SOCKET_PASSIVE_SYNACK_SENT) ||  /* TFO */
		    (socket->state == SOCKET_PASSIVE_SYNACK_ACKED) ||
		    (socket->state == SOCKET_PASSIVE_COOKIE_ECHO_RECEIVED)) {
			assert(is_equal_ip(&socket->live.remote.ip, &ip));
			assert(is_equal_port(socket->live.remote.port,
					     htons(port)));
			socket->script.fd	= script_accepted_fd;
			socket->live.fd		= live_accepted_fd;
			return STATUS_OK;
		}
	}

	if (!state->config->is_wire_client) {
		asprintf(error, "unable to find socket matching accept() call");
		return STATUS_ERR;
	}

	/* If this is a wire client, then this process just
	 * sees the system call action for this socket. Create a child
	 * passive socket for this accept call, and fill in what we
	 * know about the socket. Any further packets in the test
	 * script will be directed to this child socket.
	 */
	socket = socket_new(state);
	state->socket_under_test = socket;
	assert(socket->state == SOCKET_INIT);
	socket->address_family		= ip.address_family;

	socket->live.remote.ip		= ip;
	socket->live.remote.port	= port;
	socket->live.local.ip		= state->config->live_local_ip;
	socket->live.local.port		= htons(state->config->live_bind_port);

	socket->live.fd			= live_accepted_fd;
	socket->script.fd		= script_accepted_fd;

	if (DEBUG_LOGGING) {
		char local_string[ADDR_STR_LEN];
		char remote_string[ADDR_STR_LEN];
		DEBUGP("live: local: %s.%d\n",
		       ip_to_string(&socket->live.local.ip, local_string),
		       ntohs(socket->live.local.port));
		DEBUGP("live: remote: %s.%d\n",
		       ip_to_string(&socket->live.remote.ip, remote_string),
		       ntohs(socket->live.remote.port));
	}
	return STATUS_OK;
}

/* Handle an connect() or sendto() call initiating a connect to a
 * remote address. Fill in the live_addr and live_addrlen for the live
 * connect(). Returns STATUS_OK on success; on failure returns
 * STATUS_ERR and sets error message.
 */
static int run_syscall_connect(struct state *state,
			       int script_fd,
			       bool must_be_new_socket,
			       struct sockaddr *live_addr,
			       socklen_t *live_addrlen,
			       char **error)
{
	struct socket *socket	= NULL;
	DEBUGP("run_syscall_connect\n");

	/* Fill in the live address we want to connect to */
	ip_to_sockaddr(&state->config->live_connect_ip,
		       state->config->live_connect_port,
		       live_addr, live_addrlen);

	socket = find_socket_by_script_fd(state, script_fd);
	assert(socket != NULL);
	if (socket->state != SOCKET_NEW) {
		if (must_be_new_socket) {
			asprintf(error, "socket is not new");
			return STATUS_ERR;
		} else {
			return STATUS_OK;
		}
	}

	socket->state				= SOCKET_ACTIVE_CONNECTING;
	ip_reset(&socket->script.remote.ip);
	ip_reset(&socket->script.local.ip);
	socket->script.remote.port		= 0;
	socket->script.local.port		= 0;
	socket->live.remote.ip   = state->config->live_remote_ip;
	socket->live.remote.port = htons(state->config->live_connect_port);	
	DEBUGP("success: setting socket to state %d\n", socket->state);
	return STATUS_OK;
}

static int run_syscall_sctp_peeloff(struct state *state,
				    int script_copy_fd,
				    int script_new_fd,
				    int live_new_fd,
				    char **error) {
	struct socket *copy_socket = NULL, *new_socket, *temp_socket;
	copy_socket = find_socket_by_script_fd(state, script_copy_fd);
	assert(copy_socket != NULL);
	if (copy_socket->state == SOCKET_NEW) {
		asprintf(error, "socket is not new");
		return STATUS_ERR;
	}
	new_socket = find_socket_by_script_fd(state, script_new_fd);
	assert(new_socket == NULL);
	new_socket = socket_new(state);
	temp_socket = new_socket->next;

	memcpy(new_socket, copy_socket, sizeof(struct socket));
	new_socket->next = temp_socket;
	new_socket->live.fd		= live_new_fd;
	new_socket->script.fd		= script_new_fd;
	DEBUGP("success: setting socket to state %d\n", new_socket->state);
	return STATUS_OK;
}


/****************************************************************************
 * Here we have the parsing and invocation of the system calls that
 * we support...
 */

static int syscall_socket(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int domain, type, protocol, live_fd, script_fd, result;
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 0, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &type, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &protocol, error))
		return STATUS_ERR;

	domain = state->config->socket_domain;

	begin_syscall(state, syscall);

	result = socket(domain, type, protocol);

	if (end_syscall(state, syscall, CHECK_NON_NEGATIVE, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		live_fd = result;
		if (get_s32(syscall->result, &script_fd, error))
			return STATUS_ERR;
		if (run_syscall_socket(state, domain, protocol,
				       script_fd, live_fd, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_bind(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen;

	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 2, error))
		return STATUS_ERR;
	if (run_syscall_bind(
		    state,
		    (struct sockaddr *)&live_addr, &live_addrlen, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = bind(live_fd, (struct sockaddr *)&live_addr, live_addrlen);

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_listen(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, backlog, result;

	if (check_arg_count(args, 2, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &backlog, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = listen(live_fd, backlog);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	if (run_syscall_listen(state, script_fd, live_fd, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int syscall_accept(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, live_accepted_fd, script_accepted_fd, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 2, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = accept(live_fd, (struct sockaddr *)&live_addr, &live_addrlen);

	if (end_syscall(state, syscall, CHECK_ALLOW_MAPPING, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		live_accepted_fd = result;
		if (get_s32(syscall->result, &script_accepted_fd, error))
			return STATUS_ERR;
		if (run_syscall_accept(
			    state, script_accepted_fd, live_accepted_fd,
			    (struct sockaddr *)&live_addr, live_addrlen,
			    error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_connect(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int live_fd, script_fd, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 2, error))
		return STATUS_ERR;

	if (run_syscall_connect(
		    state, script_fd, true,
		    (struct sockaddr *)&live_addr, &live_addrlen, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = connect(live_fd, (struct sockaddr *)&live_addr, live_addrlen);

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_read(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, result;
	char *buf = NULL;
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	buf = malloc(count);
	assert(buf != NULL);

	begin_syscall(state, syscall);

	result = read(live_fd, buf, count);

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_readv(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, iov_count, result;
	struct expression *iov_expression = NULL;
	struct iovec *iov = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;

	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	iov_expression = get_arg(args, 1, error);
	if (iov_expression == NULL)
		goto error_out;
	if (iovec_new(iov_expression, &iov, &iov_len, error))
		goto error_out;

	if (s32_arg(args, 2, &iov_count, error))
		goto error_out;

	if (iov_count != iov_len) {
		asprintf(error,
			 "iov_count %d does not match %d-element iovec array",
			 iov_count, (int)iov_len);
		goto error_out;
	}

	begin_syscall(state, syscall);

	result = readv(live_fd, iov, iov_count);

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

error_out:
	iovec_free(iov, iov_len);
	return status;
}

static int syscall_recv(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	char *buf = NULL;
	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	buf = malloc(count);
	assert(buf != NULL);

	begin_syscall(state, syscall);

	result = recv(live_fd, buf, count, flags);

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_recvfrom(struct state *state, struct syscall_spec *syscall,
			    struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	char *buf = NULL;
	if (check_arg_count(args, 6, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 4, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 5, error))
		return STATUS_ERR;
	buf = malloc(count);
	assert(buf != NULL);

	begin_syscall(state, syscall);

	result = recvfrom(live_fd, buf, count, flags,
			  (struct sockaddr *)&live_addr, &live_addrlen);

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_recvmsg(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int live_fd, script_fd, flags, result;
	struct expression *msg_expression = NULL;
	struct msghdr *msg = NULL;
	size_t iov_len = 0;
	int expected_msg_flags = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;
	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	msg_expression = get_arg(args, 1, error);
	if (msg_expression == NULL)
		goto error_out;
	if (msghdr_new(msg_expression, &msg, &iov_len, false, error))
		goto error_out;

	if (s32_arg(args, 2, &flags, error))
		goto error_out;

	expected_msg_flags = msg->msg_flags;

	begin_syscall(state, syscall);

	result = recvmsg(live_fd, msg, flags);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if (msg->msg_flags != expected_msg_flags) {
		asprintf(error, "Expected msg_flags 0x%08X but got 0x%08X",
			 expected_msg_flags, msg->msg_flags);
		goto error_out;
	}
#if defined(__FreeBSD__) || defined(linux)
	if (msg->msg_flags & MSG_NOTIFICATION) {
		if (check_sctp_notification(msg->msg_iov, msg_expression->value.msghdr->msg_iov, error))
			goto error_out;
	}
#endif
	status = check_cmsghdr(msg_expression->value.msghdr->msg_control, msg, error);

error_out:
	msghdr_free(msg, iov_len);
	return status;
}

static int syscall_write(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, result;
	char *buf = NULL;
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	buf = calloc(count, 1);
	assert(buf != NULL);

	begin_syscall(state, syscall);

	result = write(live_fd, buf, count);

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_writev(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, iov_count, result;
	struct expression *iov_expression = NULL;
	struct iovec *iov = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;

	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	iov_expression = get_arg(args, 1, error);
	if (iov_expression == NULL)
		goto error_out;
	if (iovec_new(iov_expression, &iov, &iov_len, error))
		goto error_out;

	if (s32_arg(args, 2, &iov_count, error))
		goto error_out;

	if (iov_count != iov_len) {
		asprintf(error,
			 "iov_count %d does not match %d-element iovec array",
			 iov_count, (int)iov_len);
		goto error_out;
	}

	begin_syscall(state, syscall);

	result = writev(live_fd, iov, iov_count);

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

error_out:
	iovec_free(iov, iov_len);
	return status;
}

static int syscall_send(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	char *buf = NULL;
	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	buf = calloc(count, 1);
	assert(buf != NULL);

	begin_syscall(state, syscall);

	result = send(live_fd, buf, count, flags);

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_sendto(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	char *buf = NULL;
	if (check_arg_count(args, 6, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 4, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 5, error))
		return STATUS_ERR;

	if (run_syscall_connect(
		    state, script_fd, false,
		    (struct sockaddr *)&live_addr, &live_addrlen, error))
		return STATUS_ERR;

	buf = calloc(count, 1);
	assert(buf != NULL);

	begin_syscall(state, syscall);

	result = sendto(live_fd, buf, count, flags,
			(struct sockaddr *)&live_addr, live_addrlen);

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_sendmsg(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int live_fd, script_fd, flags, result;
	struct expression *msg_expression = NULL;
	struct msghdr *msg = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;
	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	msg_expression = get_arg(args, 1, error);
	if (msg_expression == NULL)
		goto error_out;
	if (msghdr_new(msg_expression, &msg, &iov_len, true, error))
		goto error_out;

	if (s32_arg(args, 2, &flags, error))
		goto error_out;

	if ((msg->msg_name != NULL) &&
	    run_syscall_connect(state, script_fd, false,
				msg->msg_name, &msg->msg_namelen, error))
		goto error_out;
	if (msg->msg_flags != 0) {
		asprintf(error, "sendmsg ignores msg_flags field in msghdr");
		goto error_out;
	}

	begin_syscall(state, syscall);

	result = sendmsg(live_fd, msg, flags);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	status = check_cmsghdr(msg_expression->value.msghdr->msg_control, msg, error);

error_out:
	msghdr_free(msg, iov_len);
	return status;
}

static int syscall_fcntl(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, command, result;

	/* fcntl is an odd system call - it can take either 2 or 3 args. */
	int actual_arg_count = get_arg_count(args);
	if ((actual_arg_count != 2) && (actual_arg_count != 3)) {
		asprintf(error, "fcntl expected 2-3 args but got %d",
			 actual_arg_count);
		return STATUS_ERR;
	}

	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &command, error))
		return STATUS_ERR;

	if (actual_arg_count == 2) {
		begin_syscall(state, syscall);

		result = fcntl(live_fd, command);
	} else if (actual_arg_count == 3) {
		s32 arg;
		if (s32_arg(args, 2, &arg, error))
			return STATUS_ERR;
		begin_syscall(state, syscall);

		result = fcntl(live_fd, command, arg);
	} else {
		assert(0);	/* not reached */
	}

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_ioctl(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, command, result;

	/* ioctl is an odd system call - it can take either 2 or 3 args. */
	int actual_arg_count = get_arg_count(args);
	if ((actual_arg_count != 2) && (actual_arg_count != 3)) {
		asprintf(error, "ioctl expected 2-3 args but got %d",
			 actual_arg_count);
		return STATUS_ERR;
	}

	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &command, error))
		return STATUS_ERR;

	if (actual_arg_count == 2) {
		begin_syscall(state, syscall);

		result = ioctl(live_fd, command);

		return end_syscall(state, syscall, CHECK_EXACT, result, error);

	} else if (actual_arg_count == 3) {
		s32 script_optval, live_optval;

		if (s32_bracketed_arg(args, 2, &script_optval, error))
			return STATUS_ERR;

		begin_syscall(state, syscall);

		result = ioctl(live_fd, command, &live_optval);

		if (end_syscall(state, syscall, CHECK_EXACT, result, error))
			return STATUS_ERR;

		if (live_optval != script_optval) {
			asprintf(error,
				 "Bad ioctl optval: expected: %d actual: %d",
				 (int)script_optval, (int)live_optval);
			return STATUS_ERR;
		}

		return STATUS_OK;
	} else {
		assert(0);	/* not reached */
	}
	return STATUS_ERR;
}

static int syscall_close(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, result;
	if (check_arg_count(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = close(live_fd);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	if (run_syscall_close(state, script_fd, live_fd, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int syscall_shutdown(struct state *state, struct syscall_spec *syscall,
			    struct expression_list *args, char **error)
{
	int live_fd, script_fd, how, result;
	if (check_arg_count(args, 2, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &how, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = shutdown(live_fd, how);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int check_linger(struct linger_expr *expr,
			struct linger *linger, char **error)
{
	if (check_s32_expr(expr->l_onoff, linger->l_onoff,
			   "linger.l_onoff", error))
		return STATUS_ERR;
	if (check_s32_expr(expr->l_linger, linger->l_linger,
			   "linger.l_linger", error))
		return STATUS_ERR;

	return STATUS_OK;
}

#ifdef SCTP_RTOINFO
static int check_sctp_rtoinfo(struct sctp_rtoinfo_expr *expr,
			      struct sctp_rtoinfo *sctp_rtoinfo, char **error)
{
	if (check_u32_expr(expr->srto_initial, sctp_rtoinfo->srto_initial,
			   "sctp_rtoinfo.srto_initial", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->srto_max, sctp_rtoinfo->srto_max,
			   "sctp_rtoinfo.srto_max", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->srto_min, sctp_rtoinfo->srto_min,
			   "sctp_rtoinfo.srto_min", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(SCTP_INITMSG) || defined(SCTP_INIT)
static int check_sctp_initmsg(struct sctp_initmsg_expr *expr,
			      struct sctp_initmsg *sctp_initmsg, char **error)
{
	if (check_u16_expr(expr->sinit_num_ostreams, sctp_initmsg->sinit_num_ostreams,
			   "sctp_initmsg.sinit_num_ostreams", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinit_max_instreams, sctp_initmsg->sinit_max_instreams,
			   "sctp_initmsg.sinit_max_instreams", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinit_max_attempts, sctp_initmsg->sinit_max_attempts,
			   "sctp_initmsg.sinit_max_attempts", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinit_max_init_timeo, sctp_initmsg->sinit_max_init_timeo,
			   "sctp_initmsg.sinit_max_init_timeo", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_DELAYED_SACK
static int check_sctp_sack_info(struct sctp_sack_info_expr *expr,
				struct sctp_sack_info *sctp_sack_info,
				char **error)
{
	if (check_u32_expr(expr->sack_delay, sctp_sack_info->sack_delay,
			   "sctp_sack_info.sack_delay", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sack_freq, sctp_sack_info->sack_freq,
			   "sctp_sack_info.sack_freq", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(SCTP_GET_PEER_ADDR_INFO) || defined(SCTP_STATUS)
static int check_sctp_paddrinfo(struct sctp_paddrinfo_expr *expr,
				struct sctp_paddrinfo *sctp_paddrinfo,
				char **error)
{
	if (check_s32_expr(expr->spinfo_state, sctp_paddrinfo->spinfo_state,
			   "sctp_paddrinfo.spinfo_state", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spinfo_cwnd, sctp_paddrinfo->spinfo_cwnd,
			   "sctp_paddrinfo.spinfo_cwnd", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spinfo_srtt, sctp_paddrinfo->spinfo_srtt,
			   "sctp_paddrinfo.spinfo_srtt", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spinfo_rto, sctp_paddrinfo->spinfo_rto,
			   "sctp_paddrinfo.spinfo_rto", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spinfo_mtu, sctp_paddrinfo->spinfo_mtu,
			   "sctp_paddrinfo.spinfo_mtu", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_STATUS
static int check_sctp_status(struct sctp_status_expr *expr,
			     struct sctp_status *sctp_status,
			     char **error)
{
	if (check_s32_expr(expr->sstat_state, sctp_status->sstat_state,
			   "sctp_status.sstat_state", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sstat_rwnd, sctp_status->sstat_rwnd,
			   "sctp_status.sstat_rwnd", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sstat_unackdata, sctp_status->sstat_unackdata,
			   "sctp_status.sstat_unackdata", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sstat_penddata, sctp_status->sstat_penddata,
			   "sctp_status.sstat_penddata", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sstat_instrms, sctp_status->sstat_instrms,
			   "sctp_status.sstat_instrms", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sstat_outstrms, sctp_status->sstat_outstrms,
			   "sctp_status.sstat_outstrms", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sstat_fragmentation_point, sctp_status->sstat_fragmentation_point,
			   "sctp_status.sstat_fragmentation_point", error))
		return STATUS_ERR;
	if (expr->sstat_primary->type != EXPR_ELLIPSIS) {
		if (check_sctp_paddrinfo(expr->sstat_primary->value.sctp_paddrinfo,
					 &sctp_status->sstat_primary, error)) {
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_PEER_ADDR_PARAMS
static int check_sctp_paddrparams(struct sctp_paddrparams_expr *expr,
				  struct sctp_paddrparams *sctp_paddrparams,
				  char **error)
{
	if (check_u32_expr(expr->spp_hbinterval, sctp_paddrparams->spp_hbinterval,
			   "sctp_paddrparams.spp_hbinterval", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->spp_pathmaxrxt, sctp_paddrparams->spp_pathmaxrxt,
			   "sctp_paddrparams.spp_pathmaxrxt", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spp_pathmtu, sctp_paddrparams->spp_pathmtu,
			   "sctp_paddrparams.spp_pathmtu", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spp_flags, sctp_paddrparams->spp_flags,
			   "sctp_paddrparams.spp_flags", error))
		return STATUS_ERR;

	if (expr->spp_ipv6_flowlabel->type != EXPR_ELLIPSIS) {
#ifdef linux
		asprintf(error, "linux doesn't support sctp_paddrparams.spp_ipv6_flowlabel");
		return STATUS_ERR;
#else
		if (check_u32_expr(expr->spp_ipv6_flowlabel, sctp_paddrparams->spp_ipv6_flowlabel,
				   "sctp_paddrparams.spp_ipv6_flowlabel", error))
			return STATUS_ERR;
#endif
	}
	if (expr->spp_dscp->type != EXPR_ELLIPSIS) {
#ifdef linux
		asprintf(error, "linux doesn't support sctp_paddrparams.spp_dscp");
		return STATUS_ERR;
#else
		if (check_u8_expr(expr->spp_dscp, sctp_paddrparams->spp_dscp,
				   "sctp_paddrparams.spp_dscp", error))
			return STATUS_ERR;
#endif
	}
	return STATUS_OK;
}
#endif

#if defined(SCTP_MAXSEG) || defined(SCTP_MAX_BURST) || defined(SCTP_INTERLEAVING_SUPPORTED)
static int check_sctp_assoc_value(struct sctp_assoc_value_expr *expr,
				  struct sctp_assoc_value *sctp_assoc_value,
				  char **error)
{
	if (check_u16_expr(expr->assoc_value, sctp_assoc_value->assoc_value,
			   "sctp_assoc_value.stream_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_SS_VALUE
static int check_sctp_stream_value(struct sctp_stream_value_expr *expr,
				   struct sctp_stream_value *sctp_stream_value,
				   char **error)
{
	if (check_u16_expr(expr->stream_id, sctp_stream_value->stream_id,
			   "sctp_stream_value.stream_id", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->stream_value, sctp_stream_value->stream_value,
			   "sctp_stream_value.stream_value", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_ASSOCINFO
static int check_sctp_assocparams(struct sctp_assocparams_expr *expr,
			     struct sctp_assocparams *sctp_assocparams,
			     char **error)
{
	if (check_u16_expr(expr->sasoc_asocmaxrxt, sctp_assocparams->sasoc_asocmaxrxt,
			   "sctp_assocparams.sasoc_asocmaxrxt", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sasoc_number_peer_destinations, sctp_assocparams->sasoc_number_peer_destinations,
			   "sctp_assocparams.sasoc_number_peer_destinations", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sasoc_peer_rwnd, sctp_assocparams->sasoc_peer_rwnd,
			   "sctp_assocparams.sasoc_peer_rwnd", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sasoc_local_rwnd, sctp_assocparams->sasoc_local_rwnd,
			   "sctp_assocparams.sasoc_local_rwnd", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sasoc_cookie_life, sctp_assocparams->sasoc_cookie_life,
			   "sctp_assocparams.sasoc_cookie_life", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_EVENT
static int check_sctp_event(struct sctp_event_expr *expr,
			    struct sctp_event *sctp_event,
			    char **error)
{
	if (check_u16_expr(expr->se_type, sctp_event->se_type,
			   "sctp_event.se_type", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->se_on, sctp_event->se_on,
			   "sctp_event.se_on", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_EVENTS
static int check_sctp_event_subscribe(struct sctp_event_subscribe_expr *expr,
				      struct sctp_event_subscribe *sctp_events,
				      char **error)
{
	if (check_u8_expr(expr->sctp_data_io_event, sctp_events->sctp_data_io_event,
			   "sctp_event_subscribe.sctp_data_io_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_association_event, sctp_events->sctp_association_event,
			   "sctp_event_subscribe.sctp_association_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_address_event, sctp_events->sctp_address_event,
			   "sctp_event_subscribe.sctp_address_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_send_failure_event, sctp_events->sctp_send_failure_event,
			   "sctp_event_subscribe.sctp_send_failure_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_peer_error_event, sctp_events->sctp_peer_error_event,
			   "sctp_event_subscribe.sctp_peer_error_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_shutdown_event, sctp_events->sctp_shutdown_event,
			   "sctp_event_subscribe.sctp_shutdown_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_partial_delivery_event, sctp_events->sctp_partial_delivery_event,
			   "sctp_event_subscribe.sctp_partial_delivery_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_adaptation_layer_event, sctp_events->sctp_adaptation_layer_event,
			   "sctp_event_subscribe.sctp_adaptation_layer_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_authentication_event, sctp_events->sctp_authentication_event,
			   "sctp_event_subscribe.sctp_authentication_event", error))
		return STATUS_ERR;
	if (check_u8_expr(expr->sctp_sender_dry_event, sctp_events->sctp_sender_dry_event,
			   "sctp_event_subscribe.sctp_sender_dry_event", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(SCTP_DEFAULT_SNDINFO) || defined(SCTP_SNDINFO)
static int check_sctp_sndinfo(struct sctp_sndinfo_expr *expr,
			      struct sctp_sndinfo *sctp_sndinfo,
			      char **error)
{
	if (check_u16_expr(expr->snd_sid, sctp_sndinfo->snd_sid,
			   "sctp_sndinfo.snd_sid", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->snd_flags, sctp_sndinfo->snd_flags,
			   "sctp_sndinfo.snd_flags", error))
		return STATUS_ERR;
	if (expr->snd_ppid->type != EXPR_ELLIPSIS) {
		u32 snd_ppid;

		if (get_u32(expr->snd_ppid, &snd_ppid, error)) {
			return STATUS_ERR;
		}
		if (sctp_sndinfo->snd_ppid != snd_ppid) {
			asprintf(error, "sctp_sndinfo.snd_ppid: expected: %u actual: %u",
				 snd_ppid, sctp_sndinfo->snd_ppid);
			return STATUS_ERR;
		}
	}
	if (check_u32_expr(expr->snd_context, sctp_sndinfo->snd_context,
			   "sctp_sndinfo.snd_context", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->snd_assoc_id, sctp_sndinfo->snd_assoc_id,
			   "sctp_sndinfo.snd_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#ifdef SCTP_ADAPTATION_LAYER
static int check_sctp_setadaptation(struct sctp_setadaptation_expr *expr,
				    struct sctp_setadaptation *sctp_setadaptation,
				    char **error)
{
	if (check_u32_expr(expr->ssb_adaptation_ind, sctp_setadaptation->ssb_adaptation_ind,
			   "sctp_setadptation.ssb_adaptation_ind", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

static int syscall_getsockopt(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args, char **error)
{
	int script_fd, live_fd, level, optname, live_result, result = STATUS_OK;
	s32 script_optval, script_optlen, expected;
	void *live_optval;
	socklen_t live_optlen;
	struct expression *val_expression;

	if (check_arg_count(args, 5, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &level, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &optname, error))
		return STATUS_ERR;
	if (s32_bracketed_arg(args, 4, &script_optlen, error))
		return STATUS_ERR;
	if (get_s32(syscall->result, &expected, error))
		return STATUS_ERR;
	val_expression = get_arg(args, 3, error);
	if (val_expression == NULL) {
		return STATUS_ERR;
	}
	switch (val_expression->type) {
	case EXPR_LINGER:
		live_optval = malloc(sizeof(struct linger));
		live_optlen = (socklen_t)sizeof(struct linger);
		break;
#ifdef SCTP_RTOINFO
	case EXPR_SCTP_RTOINFO:
		live_optval = malloc(sizeof(struct sctp_rtoinfo));
		live_optlen = (socklen_t)sizeof(struct sctp_rtoinfo);
		((struct sctp_rtoinfo*)live_optval)->srto_assoc_id = 0;
		break;
#endif
#ifdef SCTP_ASSOCINFO
	case EXPR_SCTP_ASSOCPARAMS:
		live_optval = malloc(sizeof(struct sctp_assocparams));
		live_optlen = (socklen_t)sizeof(struct sctp_assocparams);
		((struct sctp_assocparams*) live_optval)->sasoc_assoc_id = 0;
		break;
#endif
#ifdef SCTP_INITMSG
	case EXPR_SCTP_INITMSG:
		live_optval = malloc(sizeof(struct sctp_initmsg));
		live_optlen = (socklen_t)sizeof(struct sctp_initmsg);
		break;
#endif
#ifdef SCTP_DELAYED_SACK
	case EXPR_SCTP_SACKINFO:
		live_optval = malloc(sizeof(struct sctp_sack_info));
		live_optlen = (socklen_t)sizeof(struct sctp_sack_info);
		((struct sctp_sack_info*) live_optval)->sack_assoc_id = 0;
		break;
#endif
#ifdef SCTP_STATUS
	case EXPR_SCTP_STATUS:
		live_optval = malloc(sizeof(struct sctp_status));
		live_optlen = (socklen_t)sizeof(struct sctp_status);
		((struct sctp_status*) live_optval)->sstat_assoc_id = 0;
		break;
#endif
#ifdef SCTP_GET_PEER_ADDR_INFO
	case EXPR_SCTP_PADDRINFO: {
		struct sctp_paddrinfo_expr *expr_paddrinfo = val_expression->value.sctp_paddrinfo;
		struct sctp_paddrinfo *live_paddrinfo = malloc(sizeof(struct sctp_paddrinfo));
		live_optlen = (socklen_t)sizeof(struct sctp_paddrinfo);
		memset(live_paddrinfo, 0, sizeof(struct sctp_paddrinfo));
		live_paddrinfo->spinfo_assoc_id = 0;
		if (get_sockstorage_arg(expr_paddrinfo->spinfo_address,
					&(live_paddrinfo->spinfo_address), live_fd)) {
			asprintf(error, "can't determine spinfo_address");
			free(live_paddrinfo);
			return STATUS_ERR;
		}
		live_optval = live_paddrinfo;
		break;
	}
#endif
#ifdef SCTP_PEER_ADDR_PARAMS
	case EXPR_SCTP_PEER_ADDR_PARAMS: {
		struct sctp_paddrparams_expr *expr_params = val_expression->value.sctp_paddrparams;
		struct sctp_paddrparams *live_params = malloc(sizeof(struct sctp_paddrparams));
		memset(live_params, 0, sizeof(struct sctp_paddrparams));
		live_optlen = sizeof(struct sctp_paddrparams);
		if (get_sockstorage_arg(expr_params->spp_address, &live_params->spp_address,
					live_fd)) {
			asprintf(error, "can't determine spp_address");
			free(live_params);
			return STATUS_ERR;
		}
		live_params->spp_assoc_id = 0;
		live_optval = live_params;
		break;
	}
#endif
#if defined(SCTP_MAXSEG) || defined(SCTP_MAX_BURST) || defined(SCTP_INTERLEAVING_SUPPORTED)
	case EXPR_SCTP_ASSOC_VALUE:
		live_optval = malloc(sizeof(struct sctp_assoc_value));
		live_optlen = (socklen_t)sizeof(struct sctp_assoc_value);
		((struct sctp_assoc_value *) live_optval)->assoc_id = 0;
		break;
#endif
#ifdef SCTP_SS_VALUE
	case EXPR_SCTP_STREAM_VALUE:
		live_optval = malloc(sizeof(struct sctp_stream_value));
		live_optlen = (socklen_t)sizeof(struct sctp_stream_value);
		((struct sctp_stream_value *) live_optval)->assoc_id = 0;
		if (get_u16(val_expression->value.sctp_stream_value->stream_id,
			    &((struct sctp_stream_value *)live_optval)->stream_id,
			    error)) {
			free(live_optval);
			return STATUS_ERR;
		}
		break;
#endif
#ifdef SCTP_EVENT
	case EXPR_SCTP_EVENT:
		live_optval = malloc(sizeof(struct sctp_event));
		live_optlen = sizeof(struct sctp_event);
		((struct sctp_event *)live_optval)->se_assoc_id = 0;
		if (get_u16(val_expression->value.sctp_event->se_type,
			    &((struct sctp_event *)live_optval)->se_type,
			    error)) {
			free(live_optval);
			return STATUS_ERR;
		}
		break;
#endif
#ifdef SCTP_EVENTS
	case EXPR_SCTP_EVENT_SUBSCRIBE:
		live_optval = malloc(sizeof(struct sctp_event_subscribe));
		live_optlen = sizeof(struct sctp_event_subscribe);
		break;
#endif
#ifdef SCTP_DEFAULT_SNDINFO
	case EXPR_SCTP_SNDINFO:
		live_optval = malloc(sizeof(struct sctp_sndinfo));
		live_optlen = sizeof(struct sctp_sndinfo);
		if (get_u32(val_expression->value.sctp_sndinfo->snd_assoc_id,
			    &((struct sctp_sndinfo *)live_optval)->snd_assoc_id,
			    error)) {
			free(live_optval);
			return STATUS_ERR;
		}
		break;
#endif
#ifdef SCTP_ADAPTATION_LAYER
	case EXPR_SCTP_SETADAPTATION:
		live_optval = malloc(sizeof(struct sctp_setadaptation));
		live_optlen = sizeof(struct sctp_setadaptation);
		break;
#endif
	case EXPR_LIST:
		s32_bracketed_arg(args, 3, &script_optval, error);
		live_optval = malloc(sizeof(int));
		live_optlen = (socklen_t)sizeof(int);
		break;
	default:
		asprintf(error, "unsupported value type: %s",
			 expression_type_to_string(val_expression->type));
		return STATUS_ERR;
		break;
	}

	begin_syscall(state, syscall);

	live_result = getsockopt(live_fd, level, optname, live_optval, &live_optlen);

	if (end_syscall(state, syscall, CHECK_NON_NEGATIVE, live_result, error)) {
		return STATUS_ERR;
	}

	if (live_optlen != script_optlen) {
		asprintf(error, "optlen: expected: %d actual: %d",
			 (int)script_optlen, (int)live_optlen);
		free(live_optval);
		return STATUS_ERR;
	}

	switch (val_expression->type) {
	case EXPR_LINGER:
		result = check_linger(val_expression->value.linger, live_optval, error);
		break;
#ifdef SCTP_RTOINFO
	case EXPR_SCTP_RTOINFO:
		result = check_sctp_rtoinfo(val_expression->value.sctp_rtoinfo, live_optval, error);
		break;
#endif
#ifdef SCTP_ASSOCINFO
	case EXPR_SCTP_ASSOCPARAMS:
		result = check_sctp_assocparams(val_expression->value.sctp_assocparams, live_optval, error);
		break;
#endif
#ifdef SCTP_INITMSG
	case EXPR_SCTP_INITMSG:
		result = check_sctp_initmsg(val_expression->value.sctp_initmsg, live_optval, error);
		break;
#endif
#ifdef SCTP_DELAYED_SACK
	case EXPR_SCTP_SACKINFO:
		result = check_sctp_sack_info(val_expression->value.sctp_sack_info, live_optval, error);
		break;
#endif
#ifdef SCTP_STATUS
	case EXPR_SCTP_STATUS:
		result = check_sctp_status(val_expression->value.sctp_status, live_optval, error);
		break;
#endif
#ifdef SCTP_GET_PEER_ADDR_INFO
	case EXPR_SCTP_PADDRINFO:
		result = check_sctp_paddrinfo(val_expression->value.sctp_paddrinfo, live_optval, error);
		break;
#endif
#ifdef SCTP_PEER_ADDR_PARAMS
	case EXPR_SCTP_PEER_ADDR_PARAMS:
		result = check_sctp_paddrparams(val_expression->value.sctp_paddrparams, live_optval, error);
		break;
#endif
#if defined(SCTP_MAXSEG) || defined(SCTP_MAX_BURST) || defined(SCTP_INTERLEAVING_SUPPORTED)
	case EXPR_SCTP_ASSOC_VALUE:
		result = check_sctp_assoc_value(val_expression->value.sctp_assoc_value, live_optval, error);
		break;
#endif
#ifdef SCTP_SS_VALUE
	case EXPR_SCTP_STREAM_VALUE:
		result = check_sctp_stream_value(val_expression->value.sctp_stream_value, live_optval, error);
		break;
#endif
#ifdef SCTP_EVENT
	case EXPR_SCTP_EVENT:
		result = check_sctp_event(val_expression->value.sctp_event, live_optval, error);
		break;
#endif
#ifdef SCTP_EVENTS
	case EXPR_SCTP_EVENT_SUBSCRIBE:
		result = check_sctp_event_subscribe(val_expression->value.sctp_event_subscribe, live_optval, error);
		break;
#endif
#ifdef SCTP_DEFAULT_SNDINFO
	case EXPR_SCTP_SNDINFO:
		result = check_sctp_sndinfo(val_expression->value.sctp_sndinfo, live_optval, error);
		break;
#endif
#ifdef SCTP_ADAPTATION_LAYER
	case EXPR_SCTP_SETADAPTATION:
		result = check_sctp_setadaptation(val_expression->value.sctp_setadaptation, live_optval, error);
		break;
#endif
	case EXPR_LIST:
		if (*(int*)live_optval != script_optval) {
			asprintf(error, "optval: expected: %d actual: %d",
				(int)script_optval, *(int*)live_optval);
			result = STATUS_ERR;
		}
		break;
	default:
		asprintf(error, "Cannot check value type: %s",
			 expression_type_to_string(val_expression->type));
		break;
	}
	free(live_optval);
	return result;
}

static int syscall_setsockopt(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int script_fd, live_fd, level, optname, optval_s32, optlen, result;
	void *optval = NULL;
	struct expression *val_expression;
	struct linger linger;
#ifdef SCTP_RTOINFO
	struct sctp_rtoinfo rtoinfo;
#endif
#ifdef SCTP_ASSOCINFO
	struct sctp_assocparams assocparams;
#endif
#ifdef SCTP_INITMSG
	struct sctp_initmsg initmsg;
#endif
#if defined(SCTP_MAXSEG) || defined(SCTP_MAX_BURST) || defined(SCTP_INTERLEAVING_SUPPORTED)
	struct sctp_assoc_value assoc_value;
#endif
#ifdef SCTP_DELAYED_SACK
	struct sctp_sack_info sack_info;
#endif
#ifdef SCTP_STATUS
	struct sctp_status status;
#endif
#ifdef SCTP_GET_PEER_ADDR_INFO
	struct sctp_paddrinfo paddrinfo;
#endif
#if defined(SCTP_SS_VALUE)
	struct sctp_stream_value stream_value;
#endif
#ifdef SCTP_EVENT
	struct sctp_event event;
#endif
#ifdef SCTP_EVENTS
	struct sctp_event_subscribe event_subscribe;
#endif
#ifdef SCTP_DEFAULT_SNDINFO
	struct sctp_sndinfo sndinfo;
#endif
#ifdef SCTP_ADAPTATION_LAYER
	struct sctp_setadaptation setadaptation;
#endif
#ifdef SCTP_PEER_ADDR_PARAMS
	struct sctp_paddrparams paddrparams;
#ifdef linux
	u32 spp_ipv6_flowlabel;
	u8 spp_dscp;
#endif
#endif
	if (check_arg_count(args, 5, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &level, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &optname, error))
		return STATUS_ERR;
	if (s32_arg(args, 4, &optlen, error))
		return STATUS_ERR;

	val_expression = get_arg(args, 3, error);
	if (val_expression == NULL)
		return STATUS_ERR;
	switch (val_expression->type) {
	case EXPR_LINGER:
		get_s32(val_expression->value.linger->l_onoff,
			&linger.l_onoff, error);
		get_s32(val_expression->value.linger->l_linger,
			&linger.l_linger, error);
		optval = &linger;
		break;
	case EXPR_STRING:
		optval = val_expression->value.string;
		break;
	case EXPR_LIST:
		if (s32_bracketed_arg(args, 3, &optval_s32, error))
			return STATUS_ERR;
		optval = &optval_s32;
		break;
#ifdef SCTP_RTOINFO
	case EXPR_SCTP_RTOINFO:
		rtoinfo.srto_assoc_id = 0;
		if (get_u32(val_expression->value.sctp_rtoinfo->srto_initial,
			    &rtoinfo.srto_initial, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_rtoinfo->srto_max,
			    &rtoinfo.srto_max, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_rtoinfo->srto_min,
			    &rtoinfo.srto_min, error)) {
			return STATUS_ERR;
		}
		optval = &rtoinfo;
		break;
#endif
#ifdef SCTP_ASSOCINFO
	case EXPR_SCTP_ASSOCPARAMS:
		assocparams.sasoc_assoc_id = 0;
		if (get_u16(val_expression->value.sctp_assocparams->sasoc_asocmaxrxt,
			    &assocparams.sasoc_asocmaxrxt, error)) {
			return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_assocparams->sasoc_number_peer_destinations,
			    &assocparams.sasoc_number_peer_destinations, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_assocparams->sasoc_peer_rwnd,
			    &assocparams.sasoc_peer_rwnd, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_assocparams->sasoc_local_rwnd,
			    &assocparams.sasoc_local_rwnd, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_assocparams->sasoc_cookie_life,
			    &assocparams.sasoc_cookie_life, error)) {
			return STATUS_ERR;
		}
		optval = &assocparams;
		break;
#endif
#ifdef SCTP_INITMSG
	case EXPR_SCTP_INITMSG:
		if(parse_expression_to_sctp_initmsg(val_expression, &initmsg, error)) {
			return STATUS_ERR;
		}
		optval = &initmsg;
		break;
#endif
#if defined(SCTP_MAXSEG) || defined(SCTP_MAX_BURST) || defined(SCTP_INTERLEAVING_SUPPORTED)
	case EXPR_SCTP_ASSOC_VALUE:
		assoc_value.assoc_id = 0;
		if (get_u32(val_expression->value.sctp_assoc_value->assoc_value,
			    &assoc_value.assoc_value, error)) {
			return STATUS_ERR;
		}
		optval = &assoc_value;
		break;
#endif
#ifdef SCTP_SS_VALUE
	case EXPR_SCTP_STREAM_VALUE:
		stream_value.assoc_id = 0;
		if (get_u16(val_expression->value.sctp_stream_value->stream_id,
			    &stream_value.stream_id, error)) {
			return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_stream_value->stream_value,
			    &stream_value.stream_value, error)) {
			return STATUS_ERR;
		}
		optval = &stream_value;
		break;
#endif
#ifdef SCTP_DELAYED_SACK
	case EXPR_SCTP_SACKINFO:
		sack_info.sack_assoc_id = 0;
		if (get_u32(val_expression->value.sctp_sack_info->sack_delay,
			    &sack_info.sack_delay, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_sack_info->sack_freq,
			    &sack_info.sack_freq, error)) {
			return STATUS_ERR;
		}
		optval = &sack_info;
		break;
#endif
#ifdef SCTP_STATUS
	case EXPR_SCTP_STATUS:
		status.sstat_assoc_id = 0;
		optval = &status;
		break;
#endif
#ifdef SCTP_GET_PEER_ADDR_INFO
	case EXPR_SCTP_PADDRINFO:
		paddrinfo.spinfo_assoc_id = 0;
		if (get_sockstorage_arg(val_expression->value.sctp_paddrinfo->spinfo_address,
					&paddrinfo.spinfo_address, live_fd)) {
			asprintf(error, "can't determine spp_address");
			return STATUS_ERR;
		}
		optval = &paddrinfo;
		break;
#endif
#ifdef SCTP_EVENT
	case EXPR_SCTP_EVENT:
		event.se_assoc_id = 0;
		if (get_u16(val_expression->value.sctp_event->se_type,
			    &event.se_type, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event->se_on,
			    &event.se_on, error)) {
			return STATUS_ERR;
		}
		optval = &event;
		break;
#endif
#ifdef SCTP_EVENTS
	case EXPR_SCTP_EVENT_SUBSCRIBE:
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_data_io_event,
			    &event_subscribe.sctp_data_io_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_association_event,
			    &event_subscribe.sctp_association_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_address_event,
			    &event_subscribe.sctp_address_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_send_failure_event,
			    &event_subscribe.sctp_send_failure_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_peer_error_event,
			    &event_subscribe.sctp_peer_error_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_shutdown_event,
			    &event_subscribe.sctp_shutdown_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_partial_delivery_event,
			    &event_subscribe.sctp_partial_delivery_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_adaptation_layer_event,
			    &event_subscribe.sctp_adaptation_layer_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_authentication_event,
			    &event_subscribe.sctp_authentication_event, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_event_subscribe->sctp_sender_dry_event,
			    &event_subscribe.sctp_sender_dry_event, error)) {
			return STATUS_ERR;
		}
		optval = &event_subscribe;
		break;
#endif
#ifdef SCTP_DEFAULT_SNDINFO
	case EXPR_SCTP_SNDINFO:
		if (get_u16(val_expression->value.sctp_sndinfo->snd_sid,
			    &sndinfo.snd_sid, error)) {
			return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_sndinfo->snd_flags,
			    &sndinfo.snd_flags, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_sndinfo->snd_ppid,
			    &sndinfo.snd_ppid, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_sndinfo->snd_context,
			    &sndinfo.snd_context, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_sndinfo->snd_assoc_id,
			    &sndinfo.snd_assoc_id, error)) {
			return STATUS_ERR;
		}
		optval = &sndinfo;
		break;
#endif
#ifdef SCTP_ADAPTATION_LAYER
	case EXPR_SCTP_SETADAPTATION:
		if (get_u32(val_expression->value.sctp_setadaptation->ssb_adaptation_ind,
			   &setadaptation.ssb_adaptation_ind, error)) {
			return STATUS_ERR;
		}
		optval = &setadaptation;
		break;
#endif
#ifdef SCTP_PEER_ADDR_PARAMS
	case EXPR_SCTP_PEER_ADDR_PARAMS:
		paddrparams.spp_assoc_id = 0;
		if (get_sockstorage_arg(val_expression->value.sctp_paddrparams->spp_address,
					&paddrparams.spp_address, live_fd)) {
			asprintf(error, "can't determine spp_address");
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_paddrparams->spp_hbinterval,
			    &paddrparams.spp_hbinterval, error)) {
			return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_paddrparams->spp_pathmaxrxt,
			    &paddrparams.spp_pathmaxrxt, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_paddrparams->spp_pathmtu,
			    &paddrparams.spp_pathmtu, error)) {
			return STATUS_ERR;
		}
		if (get_u32(val_expression->value.sctp_paddrparams->spp_flags,
			    &paddrparams.spp_flags, error)) {
			return STATUS_ERR;
		}
#ifdef __FreeBSD__
		if (get_u32(val_expression->value.sctp_paddrparams->spp_ipv6_flowlabel,
			    &paddrparams.spp_ipv6_flowlabel, error)) {
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_paddrparams->spp_dscp,
			   &paddrparams.spp_dscp, error)) {
			return STATUS_ERR;
		}
#endif
#ifdef linux
		if (get_u32(val_expression->value.sctp_paddrparams->spp_ipv6_flowlabel,
			    &spp_ipv6_flowlabel, error)) {
			return STATUS_ERR;
		} else if (spp_ipv6_flowlabel != 0) {
			asprintf(error, "Linux doesn't support paddrparams.spp_ipv6_flowlabel");
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_paddrparams->spp_dscp,
			   &spp_dscp, error)) {
			return STATUS_ERR;
		} else if (spp_dscp != 0) {
			asprintf(error, "Linux doesn't support paddrparams.spp_dscp");
			return STATUS_ERR;
		}
		paddrparams.spp_sackdelay = 0;
#endif
		optval = &paddrparams;
		break;
#endif
	default:
		asprintf(error, "unsupported value type: %s",
			 expression_type_to_string(val_expression->type));
		return STATUS_ERR;
		break;
	}
	begin_syscall(state, syscall);

	result = setsockopt(live_fd, level, optname, optval, optlen);

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_poll(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	struct expression *fds_expression = NULL;
	struct pollfd *fds = NULL;
	size_t fds_len;
	int nfds, timeout, result;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;

	fds_expression = get_arg(args, 0, error);
	if (fds_expression == NULL)
		goto error_out;
	if (pollfds_new(state, fds_expression, &fds, &fds_len, error))
		goto error_out;

	if (s32_arg(args, 1, &nfds, error))
		goto error_out;
	if (s32_arg(args, 2, &timeout, error))
		goto error_out;

	if (nfds != fds_len) {
		asprintf(error,
			 "nfds %d does not match %d-element pollfd array",
			 nfds, (int)fds_len);
		goto error_out;
	}

	begin_syscall(state, syscall);

	result = poll(fds, nfds, timeout);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if (pollfds_check(fds_expression, fds, fds_len, error))
		goto error_out;

	status = STATUS_OK;

error_out:
	free(fds);
	return status;
}

static int syscall_sctp_sendmsg(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
#if defined(__FreeBSD__) || defined(linux)
	int result, script_fd, live_fd, len;
	void *msg = NULL;
	struct sockaddr_storage to;
	struct sockaddr_storage *to_ptr = &to;
	socklen_t tolen = 0;
	u32 ppid, flags, timetolive, context;
	u16 stream_no;
	struct expression *sockaddr_expr, *tolen_expr, *ppid_expr, *flags_expr, *ttl_expr, *stream_no_expr, *context_expr;

	if (check_arg_count(args, 10, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &len, error))
		return STATUS_ERR;
	sockaddr_expr = get_arg(args, 3, error);
	if (sockaddr_expr->type == EXPR_ELLIPSIS) {
		socklen_t len = (socklen_t)sizeof(struct sockaddr_storage);
		if (getpeername(live_fd, (struct sockaddr *)to_ptr, &len)) {
			return STATUS_ERR;
		}
		tolen = len;
	} else if (sockaddr_expr->type == EXPR_NULL) {
		to_ptr = NULL;
		tolen = 0;
	} else {
		if (sockaddr_expr->type == EXPR_SOCKET_ADDRESS_IPV4) {
			memcpy(to_ptr, sockaddr_expr->value.socket_address_ipv4, sizeof(struct sockaddr_in));
			tolen = sizeof(struct sockaddr_in);
		} else if (sockaddr_expr->type == EXPR_SOCKET_ADDRESS_IPV6) {
			memcpy(to_ptr, sockaddr_expr->value.socket_address_ipv6, sizeof(struct sockaddr_in6));
			tolen = sizeof(struct sockaddr_in6);
		} else {
			asprintf(error, "Bad input for receiver in sctp_sendmsg");
			return STATUS_ERR;
		}
	}
	tolen_expr = get_arg(args, 4, error);
	if (tolen_expr->type != EXPR_ELLIPSIS)
		if (get_u32(tolen_expr, &tolen, error))
			return STATUS_ERR;
	ppid_expr = get_arg(args, 5, error);
	if (get_u32(ppid_expr, &ppid, error))
		return STATUS_ERR;
	flags_expr = get_arg(args, 6, error);
	if (get_u32(flags_expr, &flags, error))
		return STATUS_ERR;
	stream_no_expr =get_arg(args, 7, error);
	if (get_u16(stream_no_expr, &stream_no, error))
		return STATUS_ERR;
	ttl_expr = get_arg(args, 8, error);
	if (get_u32(ttl_expr, &timetolive, error))
		return STATUS_ERR;
	context_expr = get_arg(args, 9, error);
	if (get_u32(context_expr, &context, error))
		return STATUS_ERR;

	msg = calloc(len, 1);
	assert(msg != NULL);

	begin_syscall(state, syscall);
	result = sctp_sendmsg(live_fd, msg, (size_t)len, (struct sockaddr *) to_ptr,
			      tolen, ppid, flags, stream_no, timetolive, context);

	free(msg);
	if (end_syscall(state, syscall, CHECK_EXACT, result, error)) {
		return STATUS_ERR;
	}
	return STATUS_OK;
#else
	asprintf(error, "sctp_sendmsg is not supported");
	return STATUS_ERR;
#endif
}

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_sndrcvinfo(struct sctp_sndrcvinfo_expr *expr,
				 struct sctp_sndrcvinfo *sctp_sndrcvinfo,
				 char** error) {
	if (check_u16_expr(expr->sinfo_stream, sctp_sndrcvinfo->sinfo_stream,
			   "sctp_sndrcvinfo.sinfo_stream", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinfo_ssn, sctp_sndrcvinfo->sinfo_ssn,
			   "sctp_sndrcvinfo.sinfo_ssn", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinfo_flags, sctp_sndrcvinfo->sinfo_flags,
			   "sctp_sndrcvinfo.sinfo_flags", error))
		return STATUS_ERR;
	if (check_u32_hton_expr(expr->sinfo_ppid, sctp_sndrcvinfo->sinfo_ppid,
			   "sctp_sndrcvinfo.sinfo_ppid", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_context, sctp_sndrcvinfo->sinfo_context,
			   "sctp_sndrcvinfo.sinfo_context", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_timetolive, sctp_sndrcvinfo->sinfo_timetolive,
			   "sctp_sndrcvinfo.sinfo_timetolive", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_tsn, sctp_sndrcvinfo->sinfo_tsn,
			   "sctp_sndrcvinfo.sinfo_tsn", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_cumtsn, sctp_sndrcvinfo->sinfo_cumtsn,
			   "sctp_sndrcvinfo.sinfo_cumtsn", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_assoc_id, sctp_sndrcvinfo->sinfo_assoc_id,
			   "sctp_sndrcvinfo.sinfo_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__)
static int check_sctp_extrcvinfo(struct sctp_extrcvinfo_expr *expr,
				 struct sctp_extrcvinfo *sctp_extrcvinfo,
				 char** error) {
	if (check_u16_expr(expr->sinfo_stream, sctp_extrcvinfo->sinfo_stream,
			   "sctp_extrcvinfo.sinfo_stream", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinfo_ssn, sctp_extrcvinfo->sinfo_ssn,
			   "sctp_extrcvinfo.sinfo_ssn", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sinfo_flags, sctp_extrcvinfo->sinfo_flags,
			   "sctp_extrcvinfo.sinfo_flags", error))
		return STATUS_ERR;
	if (check_u32_hton_expr(expr->sinfo_ppid, sctp_extrcvinfo->sinfo_ppid,
			   "sctp_extrcvinfo.sinfo_ppid", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_context, sctp_extrcvinfo->sinfo_context,
			   "sctp_extrcvinfo.sinfo_context", error))
		return STATUS_ERR;
#if __FreeBSD_version >= 1003000
	if (check_u32_expr(expr->sinfo_pr_value, sctp_extrcvinfo->sinfo_pr_value,
			   "sctp_extrcvinfo.sinfo_pr_value", error))
		return STATUS_ERR;
#else
	if (check_u32_expr(expr->sinfo_pr_value, sctp_extrcvinfo->sinfo_timetolive,
			   "sctp_extrcvinfo.sinfo_pr_value", error))
		return STATUS_ERR;
#endif
	if (check_u32_expr(expr->sinfo_tsn, sctp_extrcvinfo->sinfo_tsn,
			   "sctp_extrcvinfo.sinfo_tsn", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sinfo_cumtsn, sctp_extrcvinfo->sinfo_cumtsn,
			   "sctp_extrcvinfo.sinfo_cumtsn", error))
		return STATUS_ERR;
#if __FreeBSD_version >= 1003000
	if (check_u16_expr(expr->serinfo_next_flags, sctp_extrcvinfo->serinfo_next_flags,
			   "sctp_extrcvinfo.serinfo_next_flags", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->serinfo_next_stream, sctp_extrcvinfo->serinfo_next_stream,
			   "sctp_extrcvinfo.serinfo_next_stream", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->serinfo_next_aid, sctp_extrcvinfo->serinfo_next_aid,
			   "sctp_extrcvinfo.serinfo_next_aid", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->serinfo_next_length, sctp_extrcvinfo->serinfo_next_length,
			   "sctp_extrcvinfo.serinfo_next_length", error))
		return STATUS_ERR;
	if (check_u32_hton_expr(expr->serinfo_next_ppid, sctp_extrcvinfo->serinfo_next_ppid,
			   "sctp_extrcvinfo.serinfo_next_ppid", error))
		return STATUS_ERR;
#else
	if (check_u16_expr(expr->serinfo_next_flags, sctp_extrcvinfo->sreinfo_next_flags,
			   "sctp_extrcvinfo.serinfo_next_flags", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->serinfo_next_stream, sctp_extrcvinfo->sreinfo_next_stream,
			   "sctp_extrcvinfo.serinfo_next_stream", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->serinfo_next_aid, sctp_extrcvinfo->sreinfo_next_aid,
			   "sctp_extrcvinfo.serinfo_next_aid", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->serinfo_next_length, sctp_extrcvinfo->sreinfo_next_length,
			   "sctp_extrcvinfo.serinfo_next_length", error))
		return STATUS_ERR;
	if (check_u32_hton_expr(expr->serinfo_next_ppid, sctp_extrcvinfo->sreinfo_next_ppid,
			   "sctp_extrcvinfo.serinfo_next_ppid", error))
		return STATUS_ERR;
#endif
	if (check_u32_expr(expr->sinfo_assoc_id, sctp_extrcvinfo->sinfo_assoc_id,
			   "sctp_extrcvinfo.sinfo_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

static int syscall_sctp_recvmsg(struct state *state, struct syscall_spec *syscall,
				struct expression_list *args,
				char **error)
{
#if defined(__FreeBSD__) || defined(linux)
	int script_fd, live_fd, live_msg_flags, result;
	void *msg;
	u32 len;
	struct sockaddr live_from;
	socklen_t live_fromlen;
	struct sctp_sndrcvinfo live_sinfo;
	struct expression *len_expr, *script_sinfo_expr, *script_msg_flags_expr;
	struct expression *script_fromlen_expr, *script_from_expr;

	if (check_arg_count(args, 7, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	len_expr = get_arg(args, 2, error);
	if (get_u32(len_expr, &len, error))
		return STATUS_ERR;

	msg = calloc(len, 1);
	assert(msg != NULL);

	begin_syscall(state, syscall);
	result = sctp_recvmsg(live_fd, msg, len, (struct sockaddr*) &live_from,
			      &live_fromlen, &live_sinfo, &live_msg_flags);
	free(msg);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error)) {
		return STATUS_ERR;
	}

	script_from_expr = get_arg(args, 3, error);
	if (check_sockaddr(script_from_expr, &live_from, error))
		return STATUS_ERR;

	script_fromlen_expr = get_arg(args, 4, error);
	if (script_fromlen_expr->type != EXPR_ELLIPSIS) {
		int script_fromlen;
		if (get_s32(script_fromlen_expr, &script_fromlen, error))
			return STATUS_ERR;
		if (script_fromlen != live_fromlen) {
			asprintf(error, "sctp_recvmsg fromlen: expected: %d actual: %d",
				 script_fromlen, live_fromlen);
			return STATUS_ERR;
		}
	}

	script_sinfo_expr = get_arg(args, 5, error);
	if (script_sinfo_expr->type != EXPR_ELLIPSIS) {
		if (check_sctp_sndrcvinfo(script_sinfo_expr->value.sctp_sndrcvinfo, &live_sinfo, error)) {
			return STATUS_ERR;
		}
	}
	script_msg_flags_expr = get_arg(args, 6, error);
	if (script_msg_flags_expr->type != EXPR_ELLIPSIS) {
		int script_msg_flags;
		if (get_s32(script_msg_flags_expr, &script_msg_flags, error))
			return STATUS_ERR;
		if (script_msg_flags != live_msg_flags) {
			asprintf(error, "sctp_recvmsg msg_flags: expected: %d actual: %d",
				 script_msg_flags, live_msg_flags);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
#else
	asprintf(error, "sctp_sendmsg is not supported");
	return STATUS_ERR;
#endif
}

#if defined(__FreeBSD__) || defined(linux)
static int parse_expression_to_sctp_initmsg(struct expression *expr, struct sctp_initmsg *init, char **error) {
	if (expr->type == EXPR_SCTP_INITMSG) {
		struct sctp_initmsg_expr *init_expr = expr->value.sctp_initmsg;

		if (get_u16(init_expr->sinit_num_ostreams, &init->sinit_num_ostreams, error)) {
			return STATUS_ERR;
		}
		if (get_u16(init_expr->sinit_max_instreams, &init->sinit_max_instreams, error)) {
			return STATUS_ERR;
		}
		if (get_u16(init_expr->sinit_max_attempts, &init->sinit_max_attempts, error)) {
			return STATUS_ERR;
		}
		if (get_u16(init_expr->sinit_max_init_timeo, &init->sinit_max_init_timeo, error)) {
			return STATUS_ERR;
		}
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int parse_expression_to_sctp_sndrcvinfo(struct expression *expr,
                                               struct sctp_sndrcvinfo *info,
                                               bool send, char **error) {
	if (expr->type == EXPR_SCTP_SNDRCVINFO) {
		struct sctp_sndrcvinfo_expr *sndrcvinfo_expr = expr->value.sctp_sndrcvinfo;

		if (sndrcvinfo_expr->sinfo_stream->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_stream must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_stream = 0;
			}
		} else {
			if (get_u16(sndrcvinfo_expr->sinfo_stream, &info->sinfo_stream, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_ssn->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_ssn must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_ssn = 0;
			}
		} else {
			if (get_u16(sndrcvinfo_expr->sinfo_ssn, &info->sinfo_ssn, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_flags->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_flags must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_flags = 0;
			}
		} else {
			if (get_u16(sndrcvinfo_expr->sinfo_flags, &info->sinfo_flags, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_ppid->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_ppid must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_ppid = 0;
			}
		} else {
			if (get_u32(sndrcvinfo_expr->sinfo_ppid, &info->sinfo_ppid, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_context->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_context must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_context = 0;
			}
		} else {
			if (get_u32(sndrcvinfo_expr->sinfo_context, &info->sinfo_context, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_timetolive->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_timetolive must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_timetolive = 0;
			}
		} else {
			if (get_u32(sndrcvinfo_expr->sinfo_timetolive, &info->sinfo_timetolive, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_tsn->type == EXPR_ELLIPSIS) {
			info->sinfo_tsn = 0;
		} else {
			if (get_u32(sndrcvinfo_expr->sinfo_tsn, &info->sinfo_tsn, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_cumtsn->type == EXPR_ELLIPSIS) {
			info->sinfo_cumtsn = 0;
		} else {
			if (get_u32(sndrcvinfo_expr->sinfo_cumtsn, &info->sinfo_cumtsn, error)) {
				return STATUS_ERR;
			}
		}
		if (sndrcvinfo_expr->sinfo_assoc_id->type == EXPR_ELLIPSIS) {
			if (send) {
				asprintf(error, "sinfo_assoc_id must be specified");
				return STATUS_ERR;
			} else {
				info->sinfo_assoc_id = 0;
			}
		} else {
			if (get_u32(sndrcvinfo_expr->sinfo_assoc_id, (u32 *)&info->sinfo_assoc_id, error)) {
				return STATUS_ERR;
			}
		}
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__)
static int parse_expression_to_sctp_sndinfo(struct expression *expr, struct sctp_sndinfo *info, char **error) {
	if (expr->type == EXPR_SCTP_SNDINFO) {
		struct sctp_sndinfo_expr *sndinfo_expr = expr->value.sctp_sndinfo;
		if (get_u16(sndinfo_expr->snd_sid, &info->snd_sid, error)) {
			return STATUS_ERR;
		}
		if (get_u16(sndinfo_expr->snd_flags, &info->snd_flags, error)) {
			return STATUS_ERR;
		}
		if (get_u32(sndinfo_expr->snd_ppid, &info->snd_ppid, error)) {
			return STATUS_ERR;
		}
		if (get_u32(sndinfo_expr->snd_context, &info->snd_context, error)) {
			return STATUS_ERR;
		}
		if (get_u32(sndinfo_expr->snd_assoc_id, &info->snd_assoc_id, error)) {
			return STATUS_ERR;
		}
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int parse_expression_to_sctp_authinfo(struct expression *expr, struct sctp_authinfo *info, char **error) {
	if (expr->type == EXPR_SCTP_AUTHINFO) {
		struct sctp_authinfo_expr *auth_expr = expr->value.sctp_authinfo;

		if (get_u16(auth_expr->auth_keynumber, &info->auth_keynumber, error)) {
			return STATUS_ERR;
		}
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int parse_expression_to_sctp_prinfo(struct expression *expr, struct sctp_prinfo *info, char **error) {
	if (expr->type == EXPR_SCTP_PRINFO) {
		struct sctp_prinfo_expr *prinfo_expr = expr->value.sctp_prinfo;

		if (get_u16(prinfo_expr->pr_policy, &info->pr_policy, error)) {
			return STATUS_ERR;
		}
		if (get_u32(prinfo_expr->pr_value, &info->pr_value, error)) {
			return STATUS_ERR;
		}
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int parse_expression_to_sctp_sendv_spa(struct expression *expr, struct sctp_sendv_spa *info, char **error) {
	if (expr->type == EXPR_SCTP_SENDV_SPA) {
		struct sctp_sendv_spa_expr *spa_expr = expr->value.sctp_sendv_spa;

		if (get_u32(spa_expr->sendv_flags, &info->sendv_flags, error)) {
			return STATUS_ERR;
		}
		if (spa_expr->sendv_sndinfo->type != EXPR_ELLIPSIS) {
			if (parse_expression_to_sctp_sndinfo(spa_expr->sendv_sndinfo, &info->sendv_sndinfo, error))
				return STATUS_ERR;
		}
		if (spa_expr->sendv_sndinfo->type != EXPR_ELLIPSIS) {
			if (parse_expression_to_sctp_prinfo(spa_expr->sendv_prinfo, &info->sendv_prinfo, error))
				return STATUS_ERR;
		}
		if (spa_expr->sendv_sndinfo->type != EXPR_ELLIPSIS) {
			if (parse_expression_to_sctp_authinfo(spa_expr->sendv_authinfo, &info->sendv_authinfo, error))
				return STATUS_ERR;
		}
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__)
static int get_sockaddr_from_list(struct expression *expr, size_t *addr_size, struct sockaddr **addrs, char **error) {
	if (expr->type == EXPR_LIST) {
		struct expression_list *addrs_expr_list = (struct expression_list *)expr->value.list;
		struct expression *temp;
		int addrlen = expression_list_length(addrs_expr_list);
		int i = 0;
		size_t size = 0;
		char *addr_ptr;
		for (i = 0; i < addrlen; i++) {
			temp = get_arg(addrs_expr_list, i, error);
			if (temp->type == EXPR_SOCKET_ADDRESS_IPV4) {
				size += sizeof(struct sockaddr_in);
			} else if (temp->type == EXPR_SOCKET_ADDRESS_IPV6) {
				size += sizeof(struct sockaddr_in6);
			} else {
				*addrs = NULL;
				*addr_size = 0;
				return STATUS_ERR;
			}
		}
		*addr_size = size;
		*addrs = malloc(size);
		addr_ptr = (char *)*addrs;
		for (i = 0; i < addrlen; i++) {
			expr = get_arg(addrs_expr_list, i, error);
			if (expr->type == EXPR_SOCKET_ADDRESS_IPV4) {
				size = sizeof(struct sockaddr_in);
				memcpy(addr_ptr, expr->value.socket_address_ipv4, size);
				addr_ptr += size;
			} else if (expr->type == EXPR_SOCKET_ADDRESS_IPV6) {
				size = sizeof(struct sockaddr_in6);
				memcpy(addr_ptr, expr->value.socket_address_ipv6, size);
				addr_ptr += size;
			} else {
				*addr_size = 0;
				free(*addrs);
				return STATUS_ERR;
			}
		}
		return STATUS_OK;
	} else {
		addr_size = 0;
		*addrs = NULL;
		return STATUS_ERR;
	}	
}
#endif

static int syscall_sctp_send(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args,
			      char **error)
{
#if defined(__FreeBSD__) || defined(linux)
	int script_fd, live_fd, flags, result;
	size_t len;
	void *msg;
	struct expression *len_expr, *info_expr;
	struct sctp_sndrcvinfo info;

	if (check_arg_count(args, 5, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	len_expr = get_arg(args, 2, error);
	if (get_u32(len_expr, &len, error)) {
		 return STATUS_ERR;
	}
	info_expr = get_arg(args, 3, error);
	if (check_type(info_expr, EXPR_SCTP_SNDRCVINFO, error)) {
		return STATUS_ERR;
	}
	if (parse_expression_to_sctp_sndrcvinfo(info_expr, &info, true, error)) {
		return STATUS_ERR;
	}
	if (s32_arg(args, 4, &flags, error)) {
		return STATUS_ERR;
	}
	msg = calloc(len, 1);
	assert(msg != NULL);

	begin_syscall(state, syscall);

	result = sctp_send(live_fd, msg, len, &info, flags);
	free(msg);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error)) {
		return STATUS_ERR;
	}
	if (check_sctp_sndrcvinfo(info_expr->value.sctp_sndrcvinfo, &info, error)) {
		return STATUS_ERR;
	}

	return STATUS_OK;
#else
	asprintf(error, "sctp_send is not supported");
	return STATUS_ERR;
#endif
}

static int syscall_sctp_sendx(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args,
			      char **error)
{
#if defined(__FreeBSD__) || defined(linux)
	int script_fd, live_fd, flags, addrcnt, result;
	size_t len;
	void *msg = NULL;
	struct sockaddr *addrs = NULL;
	struct sctp_sndrcvinfo info;
	struct expression *info_expr, *len_expr, *addrs_expr;

	if (check_arg_count(args, 7, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	len_expr = get_arg(args, 2, error);
	if (get_u32(len_expr, &len, error)) {
		 return STATUS_ERR;
	}
	addrs_expr = get_arg(args, 3, error);
	if (addrs_expr->type == EXPR_NULL) {
		addrs = NULL;
	} else if (addrs_expr->type == EXPR_SOCKET_ADDRESS_IPV4 ||
		   addrs_expr->type == EXPR_SOCKET_ADDRESS_IPV6 ||
		   addrs_expr->type == EXPR_ELLIPSIS) {
		addrs = malloc(sizeof(struct sockaddr_storage));
		get_sockstorage_arg(addrs_expr, (struct sockaddr_storage *)addrs, live_fd);
	} else if (addrs_expr->type == EXPR_LIST) {
		size_t size;
		if (get_sockaddr_from_list(addrs_expr,  &size, &addrs, error)) {
			goto error_out;
		}
	} else {
		goto error_out;
	}
	if (s32_arg(args, 4, &addrcnt, error))
		goto error_out;
	info_expr = get_arg(args, 5, error);
	if (check_type(info_expr, EXPR_SCTP_SNDRCVINFO, error)) {
		goto error_out;
	}
	if (parse_expression_to_sctp_sndrcvinfo(info_expr, &info, true, error)) {
		goto error_out;
	}
	if (s32_arg(args, 6, &flags, error)) {
		goto error_out;
	}
	msg = calloc(len, 1);
	assert(msg != NULL);

	begin_syscall(state, syscall);

	result = sctp_sendx(live_fd, msg, len, addrs, addrcnt, &info, flags);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error)) {
		goto error_out;
	}
	if (check_sctp_sndrcvinfo(info_expr->value.sctp_sndrcvinfo, &info, error)) {
		goto error_out;
	}

	free(msg);
	free(addrs);
	return STATUS_OK;
error_out:
	free(msg);
	free(addrs);
	return STATUS_ERR;
#else
	asprintf(error, "sctp_send is not supported");
	return STATUS_ERR;
#endif
}


static int syscall_sctp_sendv(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args,
			      char **error)
{
#if defined(__FreeBSD__)
	int script_fd, live_fd, iovcnt, addrcnt, result, flags;
	u32 infotype;
	size_t script_iovec_list_len = 0;
	socklen_t infolen;
	struct sockaddr *addrs = NULL;
	void *info;
	struct iovec *iov = NULL;
	struct expression *iovec_expr_list, *iovcnt_expr, *addrs_expr, *addrcnt_expr;
	struct expression *info_expr, *infolen_expr, *infotype_expr, *flags_expr;
	struct sctp_sndinfo sndinfo;
	struct sctp_prinfo prinfo;
	struct sctp_authinfo authinfo;
	struct sctp_sendv_spa spa;

	if (check_arg_count(args, 9, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	iovec_expr_list = get_arg(args, 1, error);
	iovec_new(iovec_expr_list, &iov,  &script_iovec_list_len, error);
	iovcnt_expr = get_arg(args, 2, error);
	if (get_s32(iovcnt_expr, &iovcnt, error))
		return STATUS_ERR;
	addrs_expr = get_arg(args, 3, error);
	if (addrs_expr->type == EXPR_NULL) {
		addrs = NULL;
	} else if (addrs_expr->type == EXPR_SOCKET_ADDRESS_IPV4 ||
		   addrs_expr->type == EXPR_SOCKET_ADDRESS_IPV6 ||
		   addrs_expr->type == EXPR_ELLIPSIS) {
		addrs = malloc(sizeof(struct sockaddr_storage));
		get_sockstorage_arg(addrs_expr, (struct sockaddr_storage *)addrs, live_fd);
	} else if (addrs_expr->type == EXPR_LIST) {
		size_t size;
		if (get_sockaddr_from_list(addrs_expr,  &size, &addrs, error)) {
			goto error_out;
		}
	} else {
		goto error_out;
	}
	addrcnt_expr = get_arg(args, 4, error);
	if (get_s32(addrcnt_expr, &addrcnt, error))
		goto error_out;
	info_expr = get_arg(args, 5, error);
	if (info_expr->type == EXPR_SCTP_SNDINFO) {
		if (parse_expression_to_sctp_sndinfo(info_expr, &sndinfo, error))
			goto error_out;
		info = &sndinfo;
	} else if (info_expr->type == EXPR_SCTP_PRINFO) {
		info = malloc(sizeof(struct sctp_prinfo));
		if (parse_expression_to_sctp_prinfo(info_expr, &prinfo, error))
			goto error_out;
		info = &prinfo;
	} else if (info_expr->type == EXPR_SCTP_AUTHINFO) {
		if (parse_expression_to_sctp_authinfo(info_expr, &authinfo, error))
			goto error_out;
		info = &authinfo;
	} else if (info_expr->type == EXPR_SCTP_SENDV_SPA) {
		if (parse_expression_to_sctp_sendv_spa(info_expr, &spa, error))
			goto error_out;
		info = &spa;
	} else if (info_expr->type == EXPR_NULL) {
		info = NULL;
	} else {
		asprintf(error, "Bad input for info");
		goto error_out;
	}
	infolen_expr = get_arg(args, 6, error);
	if (get_u32(infolen_expr, &infolen, error))
		goto error_out;
	infotype_expr = get_arg(args, 7, error);
	if (get_u32(infotype_expr, &infotype, error))
		goto error_out;
	flags_expr = get_arg(args, 8, error);
	if (get_s32(flags_expr, &flags, error))
		goto error_out;

	begin_syscall(state, syscall);

	result = sctp_sendv(live_fd, iov, iovcnt, addrs, addrcnt, info, infolen, infotype, flags);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error)) {
		free(addrs);
		iovec_free(iov, script_iovec_list_len);
		return STATUS_ERR;
	}
	free(addrs);
	iovec_free(iov, script_iovec_list_len);

	return STATUS_OK;
error_out:
	if (iov != NULL)
		iovec_free(iov, script_iovec_list_len);	
	free(addrs);
	return STATUS_ERR;
#else
	asprintf(error, "sctp_sendv is not supported");
	return STATUS_ERR;
#endif
}

#if defined(__FreeBSD__)
static int check_sctp_rcvinfo(struct sctp_rcvinfo_expr *expr,
			      struct sctp_rcvinfo *sctp_rcvinfo,
			      char **error)
{
	if (check_u16_expr(expr->rcv_sid, sctp_rcvinfo->rcv_sid, "sctp_rcvinfo.rcv_sid", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->rcv_ssn, sctp_rcvinfo->rcv_ssn, "sctp_rcvinfo.rcv_ssn", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->rcv_flags, sctp_rcvinfo->rcv_flags, "sctp_rcvinfo.rcv_flags", error))
		return STATUS_ERR;
	if (check_u32_hton_expr(expr->rcv_ppid, sctp_rcvinfo->rcv_ppid, "sctp_rcvinfo.rcv_ppid", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->rcv_tsn, sctp_rcvinfo->rcv_tsn,
			   "sctp_rcvinfo.rcv_tsn", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->rcv_cumtsn, sctp_rcvinfo->rcv_cumtsn,
			   "sctp_rcvinfo.rcv_cumtsn", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->rcv_context, sctp_rcvinfo->rcv_context,
			   "sctp_rcvinfo.rcv_context", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->rcv_assoc_id, sctp_rcvinfo->rcv_assoc_id,
			   "sctp_rcvinfo.rcv_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__)
static int check_sctp_nxtinfo(struct sctp_nxtinfo_expr *expr,
			      struct sctp_nxtinfo *sctp_nxtinfo,
			      char **error)
{
	if (check_u16_expr(expr->nxt_sid, sctp_nxtinfo->nxt_sid, "sctp_nxtinfo.nxt_sid", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->nxt_flags, sctp_nxtinfo->nxt_flags, "sctp_nxtinfo.nxt_flags", error))
		return STATUS_ERR;
	if (check_u32_hton_expr(expr->nxt_ppid, sctp_nxtinfo->nxt_ppid, "sctp_nxtinfo.nxt_ppid", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->nxt_length, sctp_nxtinfo->nxt_length, "sctp_nxtinfo.nxt_length", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->nxt_assoc_id, sctp_nxtinfo->nxt_assoc_id, "sctp_nxtinfo.nxt_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_assoc_change(struct sctp_assoc_change_expr *expr,
				   struct sctp_assoc_change *sctp_event,
				   char **error) {
	if (check_u16_expr(expr->sac_type, sctp_event->sac_type,
			   "sctp_assoc_change.sac_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sac_flags, sctp_event->sac_flags,
			   "sctp_assoc_change.sac_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sac_length, sctp_event->sac_length,
			   "sctp_assoc_change.sac_length", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sac_state, sctp_event->sac_state,
			   "sctp_assoc_change.sac_state", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sac_error, sctp_event->sac_error,
			   "sctp_assoc_change.sac_error", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sac_outbound_streams, sctp_event->sac_outbound_streams,
			   "sctp_assoc_change.sac_outbound_streams", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sac_inbound_streams, sctp_event->sac_inbound_streams,
			   "sctp_assoc_change.sac_inbound_streams", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sac_assoc_id, sctp_event->sac_assoc_id,
			   "sctp_assoc_change.sac_assoc_id", error))
		return STATUS_ERR;
	if (check_u8array_expr(expr->sac_info, sctp_event->sac_info, sctp_event->sac_length - sizeof(struct sctp_assoc_change),
			       "sctp_assoc_change.sac_info", error))
			return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_paddr_change(struct sctp_paddr_change_expr *expr,
				   struct sctp_paddr_change *sctp_event,
				   char **error) {
	if (check_u16_expr(expr->spc_type, sctp_event->spc_type,
			   "sctp_paddr_change.spc_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->spc_flags, sctp_event->spc_flags,
			   "sctp_paddr_change.spc_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spc_length, sctp_event->spc_length,
			   "sctp_paddr_change.spc_length", error))
		return STATUS_ERR;
	if (check_sockaddr(expr->spc_aaddr,
			   (struct sockaddr *)&sctp_event->spc_aaddr, error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spc_state, sctp_event->spc_state,
			   "sctp_paddr_change.spc_state", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spc_error, sctp_event->spc_error,
			   "sctp_paddr_change.spc_error", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->spc_assoc_id, sctp_event->spc_assoc_id,
			   "sctp_paddr_change.spc_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_remote_error(struct sctp_remote_error_expr *expr,
				   struct sctp_remote_error *sctp_event,
				   char **error) {
	if (check_u16_expr(expr->sre_type, sctp_event->sre_type,
			   "sctp_remote_error.sre_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sre_flags, sctp_event->sre_flags,
			   "sctp_remote_error.sre_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sre_length, sctp_event->sre_length,
			   "sctp_remote_error.sre_length", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sre_error, sctp_event->sre_error,
			   "sctp_remote_error.sre_error", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sre_assoc_id, sctp_event->sre_assoc_id,
			   "sctp_remote_error.sre_assoc_id", error))
		return STATUS_ERR;
	if (check_u8array_expr(expr->sre_data, sctp_event->sre_data, sctp_event->sre_length - sizeof(struct sctp_remote_error),
			       "sctp_remote_error.sre_data", error))
			return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_send_failed(struct sctp_send_failed_expr *expr,
				  struct sctp_send_failed *sctp_event,
				  char **error) {

	if (check_u16_expr(expr->ssf_type, sctp_event->ssf_type,
			   "sctp_send_failed.ssf_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->ssf_flags, sctp_event->ssf_flags,
			   "sctp_send_failed.ssf_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->ssf_length, sctp_event->ssf_length,
			   "sctp_send_failed.ssf_length", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->ssf_error, sctp_event->ssf_error,
			   "sctp_send_failed.ssf_error", error))
		return STATUS_ERR;
	if (expr->ssf_info->type != EXPR_ELLIPSIS) {
		if (check_sctp_sndrcvinfo(expr->ssf_info->value.sctp_sndrcvinfo,
					  &sctp_event->ssf_info, error))
			return STATUS_ERR;
	}
	if (check_u32_expr(expr->ssf_assoc_id, sctp_event->ssf_assoc_id,
			   "sctp_send_failed.ssf_assoc_id", error))
		return STATUS_ERR;
	if (check_u8array_expr(expr->ssf_data, sctp_event->ssf_data, sctp_event->ssf_length - sizeof(struct sctp_send_failed),
			       "sctp_send_failed.ssf_data", error))
			return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_shutdown_event(struct sctp_shutdown_event_expr *expr,
				     struct sctp_shutdown_event *sctp_event,
				     char **error) {

	if (check_u16_expr(expr->sse_type, sctp_event->sse_type,
			   "sctp_shutdown_event.sse_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sse_flags, sctp_event->sse_flags,
			   "sctp_shutdown_event.sse_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sse_length, sctp_event->sse_length,
			   "sctp_shutdown_event.sse_length", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_adaptation_event(struct sctp_adaptation_event_expr *expr,
				       struct sctp_adaptation_event *sctp_event,
				       char **error) {

	if (check_u16_expr(expr->sai_type, sctp_event->sai_type,
			   "sctp_adaptation_event.sai_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sai_flags, sctp_event->sai_flags,
			   "sctp_adaptation_event.sai_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sai_length, sctp_event->sai_length,
			   "sctp_adaptation_event.sai_length", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sai_adaptation_ind, sctp_event->sai_adaptation_ind,
			   "sctp_adaptation_event.sai_adaptation_ind", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sai_assoc_id, sctp_event->sai_assoc_id,
			   "sctp_adaptation_event.sai_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_pdapi_event(struct sctp_pdapi_event_expr *expr,
				  struct sctp_pdapi_event *sctp_event,
				  char **error) {

	if (check_u16_expr(expr->pdapi_type, sctp_event->pdapi_type,
			   "sctp_pdapi_event.pdapi_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->pdapi_flags, sctp_event->pdapi_flags,
			   "sctp_pdapi_event.pdapi_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->pdapi_length, sctp_event->pdapi_length,
			   "sctp_pdapi_event.pdapi_length", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->pdapi_indication, sctp_event->pdapi_indication,
			   "sctp_pdapi_event.pdapi_indication", error))
		return STATUS_ERR;
#if defined(linux)
	if (expr->pdapi_stream->type != EXPR_ELLIPSIS) {
		asprintf(error, "Linux doesn't support sctp_pdapi_event.pdapi_stream");
		return STATUS_ERR;
	}
#else
	if (check_u32_expr(expr->pdapi_stream, sctp_event->pdapi_stream,
			   "sctp_pdapi_event.pdapi_stream", error))
		return STATUS_ERR;
#endif
#if defined(linux)
	if (expr->pdapi_seq->type != EXPR_ELLIPSIS) {
		asprintf(error, "Linux doesn't support sctp_pdapi_event.pdapi_seq");
		return STATUS_ERR;
	}
#else
	if (check_u32_expr(expr->pdapi_seq, sctp_event->pdapi_seq,
			   "sctp_pdapi_event.pdapi_seq", error))
		return STATUS_ERR;
#endif
	if (check_u32_expr(expr->pdapi_assoc_id, sctp_event->pdapi_assoc_id,
			   "sctp_pdapi_event.pdapi_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_authkey_event(struct sctp_authkey_event_expr *expr,
				     struct sctp_authkey_event *sctp_event,
				     char **error) {

	if (check_u16_expr(expr->auth_type, sctp_event->auth_type,
			   "sctp_authkey_event.auth_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->auth_flags, sctp_event->auth_flags,
			   "sctp_authkey_event.auth_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->auth_length, sctp_event->auth_length,
			   "sctp_authkey_event.auth_length", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->auth_keynumber, sctp_event->auth_keynumber,
			   "sctp_authkey_event.auth_keynumber", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->auth_indication, sctp_event->auth_indication,
			   "sctp_authkey_event.auth_indication", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->auth_assoc_id, sctp_event->auth_assoc_id,
			   "sctp_authkey_event.auth_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_sender_dry_event(struct sctp_sender_dry_event_expr *expr,
				       struct sctp_sender_dry_event *sctp_event,
				       char **error) {

	if (check_u16_expr(expr->sender_dry_type, sctp_event->sender_dry_type,
			   "sctp_sender_dry.sender_dry_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sender_dry_flags, sctp_event->sender_dry_flags,
			   "sctp_sender_dry.sender_dry_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sender_dry_length, sctp_event->sender_dry_length,
			   "sctp_sender_dry.sender_dry_length", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sender_dry_assoc_id, sctp_event->sender_dry_assoc_id,
			   "sctp_sender_dry.sender_dry_assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__)
static int check_sctp_send_failed_event(struct sctp_send_failed_event_expr *expr,
				       struct sctp_send_failed_event *sctp_event,
				       char **error) {
	if (check_u16_expr(expr->ssfe_type, sctp_event->ssfe_type,
			   "sctp_send_failed.ssfe_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->ssfe_flags, sctp_event->ssfe_flags,
			   "sctp_send_failed.ssfe_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->ssfe_length, sctp_event->ssfe_length,
			   "sctp_send_failed.ssfe_length", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->ssfe_error, sctp_event->ssfe_error,
			   "sctp_send_failed.ssfe_error", error))
		return STATUS_ERR;
	if (expr->ssfe_info->type != EXPR_ELLIPSIS) {
		if (check_sctp_sndinfo(expr->ssfe_info->value.sctp_sndinfo, &sctp_event->ssfe_info, error))
			return STATUS_ERR;
	}
	if (check_u32_expr(expr->ssfe_assoc_id, sctp_event->ssfe_assoc_id,
			   "sctp_send_failed.ssfe_assoc_id", error))
		return STATUS_ERR;
	if (check_u8array_expr(expr->ssfe_data, sctp_event->ssfe_data,
			       sctp_event->ssfe_length - sizeof(struct sctp_send_failed_event),
			       "sctp_send_failed_event.ssfe_data", error))
			return STATUS_ERR;

	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_tlv(struct sctp_tlv_expr *expr, struct sctp_tlv *sctp_tlv, char **error) {
	if (check_u16_expr(expr->sn_type, sctp_tlv->sn_type,
			   "sctp_tlv.sn_type", error))
		return STATUS_ERR;
	if (check_u16_expr(expr->sn_flags, sctp_tlv->sn_flags,
			   "sctp_tlv.sn_flags", error))
		return STATUS_ERR;
	if (check_u32_expr(expr->sn_length, sctp_tlv->sn_length,
			   "sctp_tlv.sn_length", error))
		return STATUS_ERR;
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__) || defined(linux)
static int check_sctp_notification(struct iovec *iov,
				   struct expression *iovec_expr,
				   char **error) {
	struct expression_list *iovec_expr_list;
	struct expression *script_iov, *script_iov_base;
	if (iovec_expr == NULL)
		return STATUS_ERR;
	if (check_type(iovec_expr, EXPR_LIST, error))
		return STATUS_ERR;
	iovec_expr_list = iovec_expr->value.list;
	int i=0;
	while (iovec_expr_list != NULL) {
		script_iov = iovec_expr_list->expression;
		if (check_type(script_iov, EXPR_IOVEC, error))
			return STATUS_ERR;
		script_iov_base = script_iov->value.iovec->iov_base;
		switch (script_iov_base->type) {
		case EXPR_SCTP_ASSOC_CHANGE:
			if (check_sctp_assoc_change(script_iov_base->value.sctp_assoc_change,
						    (struct sctp_assoc_change *) iov[i].iov_base,
						    error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_PADDR_CHANGE:
			if (check_sctp_paddr_change(script_iov_base->value.sctp_paddr_change,
						    (struct sctp_paddr_change *) iov[i].iov_base,
						    error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_REMOTE_ERROR:
			if (check_sctp_remote_error(script_iov_base->value.sctp_remote_error,
						    (struct sctp_remote_error *) iov[i].iov_base,
						    error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_SEND_FAILED:
			if (check_sctp_send_failed(script_iov_base->value.sctp_send_failed,
						   (struct sctp_send_failed *) iov[i].iov_base,
						   error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_SHUTDOWN_EVENT:
			if (check_sctp_shutdown_event(script_iov_base->value.sctp_shutdown_event,
						      (struct sctp_shutdown_event *) iov[i].iov_base,
						      error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_ADAPTATION_EVENT:
			if (check_sctp_adaptation_event(script_iov_base->value.sctp_adaptation_event,
						        (struct sctp_adaptation_event *) iov[i].iov_base,
						        error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_PDAPI_EVENT:
			if (check_sctp_pdapi_event(script_iov_base->value.sctp_pdapi_event,
						      (struct sctp_pdapi_event *) iov[i].iov_base,
						      error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_AUTHKEY_EVENT:
			if (check_sctp_authkey_event(script_iov_base->value.sctp_authkey_event,
						     (struct sctp_authkey_event *) iov[i].iov_base,
						     error))
				return STATUS_ERR;
			break;
		case EXPR_SCTP_SENDER_DRY_EVENT:
			if (check_sctp_sender_dry_event(script_iov_base->value.sctp_sender_dry_event,
						       (struct sctp_sender_dry_event *) iov[i].iov_base,
						       error))
				return STATUS_ERR;
			break;
#if defined(__FreeBSD__)
		case EXPR_SCTP_SEND_FAILED_EVENT:
			if (check_sctp_send_failed_event(script_iov_base->value.sctp_send_failed_event,
						        (struct sctp_send_failed_event *) iov[i].iov_base,
						        error))
				return STATUS_ERR;
			break;
#endif
		case EXPR_SCTP_TLV:
			if (check_sctp_tlv(script_iov_base->value.sctp_tlv,
					   (struct sctp_tlv *) iov[i].iov_base,
					    error))
				return STATUS_ERR;
			break;
		case EXPR_ELLIPSIS:
			break;
		default:
			asprintf(error, "Bad type for iov_base. Can't check type %s",
				expression_type_to_string(script_iov_base->type));
			return STATUS_ERR;
			break;
		}
		i++;
		iovec_expr_list = iovec_expr_list->next;
	}
	return STATUS_OK;
}
#endif

#if defined(__FreeBSD__)
static int check_sctp_recvv_rn(struct sctp_recvv_rn_expr *expr,
			       struct sctp_recvv_rn *sctp_recvv_rn,
			       char **error)
{
	if (expr->recvv_rcvinfo->type != EXPR_ELLIPSIS) {
		if (check_type(expr->recvv_rcvinfo, EXPR_SCTP_RCVINFO, error))
			return STATUS_ERR;
		if (check_sctp_rcvinfo(expr->recvv_rcvinfo->value.sctp_rcvinfo,
				       &(sctp_recvv_rn->recvv_rcvinfo), error))
			return STATUS_ERR;
	}
	if (expr->recvv_nxtinfo->type != EXPR_ELLIPSIS) {
		if (check_type(expr->recvv_nxtinfo, EXPR_SCTP_NXTINFO, error))
			return STATUS_ERR;
		if (check_sctp_nxtinfo(expr->recvv_nxtinfo->value.sctp_nxtinfo,
				       &(sctp_recvv_rn->recvv_nxtinfo), error))
			return STATUS_ERR;
	}
	return STATUS_OK;
}
#endif

static int syscall_sctp_recvv(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args,
			      char **error)
{
#if defined(__FreeBSD__)
	int flags, iovlen, script_fd, live_fd, result;
	size_t script_iovec_list_len = 0;
	unsigned int infotype = 0;
	socklen_t infolen, fromlen;
	void *info;
	struct iovec *iov;
	struct sockaddr *from = NULL;
	struct expression *iovec_expr_list, *iovcnt_expr, *addr_expr, *fromlen_expr;
	struct expression *info_expr, *infotype_expr, *flags_expr;
	struct sctp_recvv_rn recvv_rn;
	struct sctp_rcvinfo rcvinfo;
	struct sctp_nxtinfo nxtinfo;

	if (check_arg_count(args, 9, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	iovec_expr_list = get_arg(args, 1, error);
	iovec_new(iovec_expr_list, &iov,  &script_iovec_list_len, error);
	iovcnt_expr = get_arg(args, 2, error);
	if (get_s32(iovcnt_expr, &iovlen, error))
		return STATUS_ERR;
	fromlen_expr = get_arg(args, 4, error);
	if (get_u32(fromlen_expr, &fromlen, error))
		return STATUS_ERR;

	info_expr = get_arg(args, 5, error);
	if (info_expr->type == EXPR_NULL) {
		info = NULL;
	} else if (info_expr->type == EXPR_SCTP_RCVINFO) {
		info = &rcvinfo;
	} else if (info_expr->type == EXPR_SCTP_NXTINFO) {
		info = &nxtinfo;
	} else if (info_expr->type == EXPR_SCTP_RECVV_RN) {
		info = &recvv_rn;
	} else {
		goto error_out;
	}
	if (u32_bracketed_arg(args, 6, &infolen, error)) {
		goto error_out;
	}
	infotype = 0;
	flags = 0;
	addr_expr = get_arg(args, 3, error);
	if (addr_expr->type == EXPR_NULL) {
		from = NULL;
	} else {
		from = malloc(fromlen);
	}

	begin_syscall(state, syscall);

	result = sctp_recvv(live_fd, iov, iovlen, (struct sockaddr *)from, &fromlen, info, &infolen, &infotype, &flags);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if (from != NULL) {
		if (check_sockaddr(addr_expr, from, error))
			goto error_out;
	}
	free(from);

	infotype_expr = get_arg(args, 7, error);
	if (infotype_expr->type != EXPR_ELLIPSIS) {
		s32 script_infotype;
		if (s32_bracketed_arg(args, 7, &script_infotype, error))
			goto error_out;

		if (infotype != script_infotype) {
			asprintf(error, "sctp_recvv infotype: expected: %u actual: %u",
				 script_infotype, infotype);
			goto error_out;
		}
	}
	switch(infotype) {
	case SCTP_RECVV_NOINFO:
		if (infolen != 0) {
			asprintf(error, "infolen returned bad size for null. expected 0, actual %u", infolen);
			goto error_out;
		}
		break;
	case SCTP_RECVV_RCVINFO:
		if (infolen != sizeof(struct sctp_rcvinfo)) {
			asprintf(error, "infolen returned bad size for sctp_rcvinfo. expected %zu, actual %u",
				 sizeof(struct sctp_rcvinfo), infolen);
			goto error_out;
		}
		if (check_sctp_rcvinfo(info_expr->value.sctp_rcvinfo, info, error))
			goto error_out;
		break;
	case SCTP_RECVV_NXTINFO:
		if (infolen != sizeof(struct sctp_nxtinfo)) {
			asprintf(error, "infolen returned bad size for sctp_nxtinfo. expected %zu, actual %u",
				 sizeof(struct sctp_nxtinfo), infolen);
			goto error_out;
		}
		if (check_sctp_nxtinfo(info_expr->value.sctp_nxtinfo, info, error))
			goto error_out;
		break;
	case SCTP_RECVV_RN:
		if (infolen != sizeof(struct sctp_recvv_rn)) {
			asprintf(error, "infolen returned bad size for sctp_recvv_rn. expected %zu, actual %u",
				 sizeof(struct sctp_recvv_rn), infolen);
			goto error_out;
		}
		if (check_sctp_recvv_rn(info_expr->value.sctp_recvv_rn, info, error))
			goto error_out;
		break;
	default:
		goto error_out;
		break;
	}
	flags_expr = get_arg(args, 8, error);
	if (flags_expr->type != EXPR_ELLIPSIS) {
		s32 script_flags;
		if (s32_bracketed_arg(args, 8, &script_flags, error))
			goto error_out;
		if (flags != script_flags) {
			asprintf(error, "sctp_recvv flags bad return value. expected %d, actual %d",
				 script_flags, flags);
			goto error_out;
		} else if (flags & MSG_NOTIFICATION) {
			if (check_sctp_notification(iov, iovec_expr_list, error))
				goto error_out;
		}
	}
	iovec_free(iov, script_iovec_list_len);
	return STATUS_OK;
error_out:
	free(from);
	iovec_free(iov, script_iovec_list_len);
	return STATUS_ERR;
#else
	asprintf(error, "sctp_recvv is not supported");
	return STATUS_ERR;
#endif
}

static int syscall_sctp_bindx(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args,
			      char **error)
{
#if defined(__FreeBSD__) || defined(linux)
	int live_fd, script_fd, addrcnt, flags, result;
	struct sockaddr_storage addrs;
	struct expression *addr_list;
	socklen_t addrlen = sizeof(addrs);

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &addrcnt, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	addr_list = get_arg(args, 1, error);
	if (check_type(addr_list, EXPR_LIST, error))
		return STATUS_ERR;
	if (ellipsis_arg(addr_list->value.list, 0, error))
		return STATUS_ERR;
	//TODO: Modify run_syscall_bind for multihoming
	if (run_syscall_bind(
		    state,
		    (struct sockaddr *)&addrs, &addrlen, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = sctp_bindx(live_fd, (struct sockaddr *)&addrs, addrcnt, flags);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error)) {
		return STATUS_ERR;
	}

	return STATUS_OK;
#else
	asprintf(error, "sctp_bindx is not supported");
	return STATUS_ERR;
#endif
}

static int syscall_sctp_connectx(struct state *state, struct syscall_spec *syscall,
				 struct expression_list *args, char **error)
{
#if defined(__FreeBSD__)
	int live_fd, script_fd, addrcnt, result;
	struct sockaddr_storage live_addr;
	struct expression *addrs_expr, *assoc_expr;
	socklen_t live_addrlen = sizeof(live_addr);
	sctp_assoc_t live_associd;

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	addrs_expr = get_arg(args, 1, error);
	if (check_type(addrs_expr, EXPR_LIST, error))
		return STATUS_ERR;
	if (ellipsis_arg(addrs_expr->value.list, 0, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &addrcnt, error))
		return STATUS_ERR;
	//TODO: modify for Multihoming
	if (run_syscall_connect(
		    state, script_fd, true,
		    (struct sockaddr *)&live_addr, &live_addrlen, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = sctp_connectx(live_fd, (struct sockaddr *)&live_addr, addrcnt, &live_associd);

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	assoc_expr = get_arg(args, 3, error);
	if (check_type(assoc_expr, EXPR_LIST, error))
		return STATUS_ERR;
	if (check_arg_count(assoc_expr->value.list, 1, error))
		return STATUS_ERR;
	assoc_expr = get_arg(assoc_expr->value.list, 0, error);
	if (check_u32_expr(assoc_expr, (u32)live_associd,
			   "sctp_connectx assoc_id", error))
		return STATUS_ERR;

	return STATUS_OK;
#else
	asprintf(error, "sctp_connectx is not supported");
	return STATUS_ERR;
#endif
}

static int syscall_sctp_peeloff(struct state *state, struct syscall_spec *syscall,
			        struct expression_list *args,
			        char **error)
{
#if defined(__FreeBSD__) || defined(linux)
	int live_fd, script_fd, result, script_new_fd;
	sctp_assoc_t assoc_id;
	struct expression *expr_assoc;
	if (check_arg_count(args, 2, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	expr_assoc = get_arg(args, 1, error);
	if (get_u32(expr_assoc, &assoc_id, error))
		return STATUS_ERR;

	//check connection Type and set assoc_id if one-to-many style socket
	
	begin_syscall(state, syscall);

	result = sctp_peeloff(live_fd, assoc_id);

	if (end_syscall(state, syscall, CHECK_NON_NEGATIVE, result, error))
		return STATUS_ERR;

	if (get_s32(syscall->result, &script_new_fd, error))
		return STATUS_ERR;
	if (run_syscall_sctp_peeloff(state, script_fd, script_new_fd, result, error)) {
		asprintf(error, "can't copy socket definition");
		return STATUS_ERR;
	}

	return STATUS_OK;
#else
	asprintf(error, "sctp_connectx is not supported");
	return STATUS_ERR;
#endif
}

/* A dispatch table with all the system calls that we support... */
struct system_call_entry {
	const char *name;
	int (*function) (struct state *state,
			 struct syscall_spec *syscall,
			 struct expression_list *args,
			 char **error);
};

struct system_call_entry system_call_table[] = {
	{"socket",     syscall_socket},
	{"bind",       syscall_bind},
	{"listen",     syscall_listen},
	{"accept",     syscall_accept},
	{"connect",    syscall_connect},
	{"read",       syscall_read},
	{"readv",      syscall_readv},
	{"recv",       syscall_recv},
	{"recvfrom",   syscall_recvfrom},
	{"recvmsg",    syscall_recvmsg},
	{"write",      syscall_write},
	{"writev",     syscall_writev},
	{"send",       syscall_send},
	{"sendto",     syscall_sendto},
	{"sendmsg",    syscall_sendmsg},
	{"fcntl",      syscall_fcntl},
	{"ioctl",      syscall_ioctl},
	{"close",      syscall_close},
	{"shutdown",   syscall_shutdown},
	{"getsockopt", syscall_getsockopt},
	{"setsockopt", syscall_setsockopt},
	{"poll",       syscall_poll},
	{"sctp_send",     syscall_sctp_send},
	{"sctp_sendx",    syscall_sctp_sendx},
	{"sctp_sendmsg",  syscall_sctp_sendmsg},
	{"sctp_recvmsg",  syscall_sctp_recvmsg},
	{"sctp_sendv",    syscall_sctp_sendv},
	{"sctp_recvv",    syscall_sctp_recvv},
	{"sctp_bindx",    syscall_sctp_bindx},
	{"sctp_connectx", syscall_sctp_connectx},
	{"sctp_peeloff",  syscall_sctp_peeloff}
};

/* Evaluate the system call arguments and invoke the system call. */
static void invoke_system_call(
	struct state *state, struct event *event, struct syscall_spec *syscall)
{
	DEBUGP("%d: invoke call: %s\n", event->line_number, syscall->name);

	char *error = NULL, *script_path = NULL;
	const char *name = syscall->name;
	struct expression_list *args = NULL;
	int i = 0;
	int result = 0;

	/* Wait for the right time before firing off this event. */
	wait_for_event(state);

	/* Find and invoke the handler for this system call. */
	for (i = 0; i < ARRAY_SIZE(system_call_table); ++i)
		if (strcmp(name, system_call_table[i].name) == 0)
			break;
	if (i == ARRAY_SIZE(system_call_table)) {
		asprintf(&error, "Unknown system call: '%s'", name);
		goto error_out;
	}

	/* Evaluate script symbolic expressions to get live numeric args for
	 * system calls.
	 */
	if (evaluate_expression_list(syscall->arguments, &args, &error))
		goto error_out;

	/* Run the system call. */
	result = system_call_table[i].function(state, syscall, args, &error);

	free_expression_list(args);

	if (result == STATUS_ERR)
		goto error_out;
	return;

error_out:
	script_path = strdup(state->config->script_path);
	state_free(state);
	die("%s:%d: runtime error in %s call: %s\n",
	    script_path, event->line_number,
	    syscall->name, error);
	free(script_path);
	free(error);
}

/* Wait for the system call thread to go idle. To avoid mystifying
 * hangs when scripts specify overlapping time ranges for blocking
 * system calls, we limit the duration of our waiting to 1 second.
 */
static int await_idle_thread(struct state *state)
{
	struct timespec end_time = { .tv_sec = 0, .tv_nsec = 0 };
	const int MAX_WAIT_SECS = 1;
	while (state->syscalls->state != SYSCALL_IDLE) {
		/* On the first time through the loop, calculate end time. */
		if (end_time.tv_sec == 0) {
			if (clock_gettime(CLOCK_REALTIME, &end_time) != 0)
				die_perror("clock_gettime");
			end_time.tv_sec += MAX_WAIT_SECS;
		}
		/* Wait for a signal or our timeout end_time to arrive. */
		DEBUGP("main thread: awaiting idle syscall thread\n");
		int status = pthread_cond_timedwait(&state->syscalls->idle,
						    &state->mutex, &end_time);
		if (status == ETIMEDOUT)
			return STATUS_ERR;
		else if (status != 0)
			die_perror("pthread_cond_timedwait");
	}
	return STATUS_OK;
}

static int yield(void)
{
#if defined(linux)
	return pthread_yield();
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	pthread_yield();
	return 0;
#elif defined(__NetBSD__)
	return sched_yield();
#endif  /* defined(__NetBSD__) */
}

/* Enqueue the system call for the syscall thread and wake up the thread. */
static void enqueue_system_call(
	struct state *state, struct event *event, struct syscall_spec *syscall)
{
	char *error = NULL, *script_path = NULL;
	bool done = false;

	/* Wait if there are back-to-back blocking system calls. */
	if (await_idle_thread(state)) {
		asprintf(&error, "blocking system call while another blocking "
			 "system call is already in progress");
		goto error_out;
	}

	/* Enqueue the system call info and wake up the syscall thread. */
	DEBUGP("main thread: signal enqueued\n");
	state->syscalls->state = SYSCALL_ENQUEUED;
	if (pthread_cond_signal(&state->syscalls->enqueued) != 0)
		die_perror("pthread_cond_signal");

	/* Wait for the syscall thread to dequeue and start the system call. */
	while (state->syscalls->state == SYSCALL_ENQUEUED) {
		DEBUGP("main thread: waiting for dequeued signal; "
		       "state: %d\n", state->syscalls->state);
		if (pthread_cond_wait(&state->syscalls->dequeued,
				      &state->mutex) != 0) {
			die_perror("pthread_cond_wait");
		}
	}

	/* Wait for the syscall thread to block or finish the call. */
	while (!done) {
		/* Unlock and yield so the system call thread can make
		 * the system call in a timely fashion.
		 */
		DEBUGP("main thread: unlocking and yielding\n");
		pid_t thread_id = state->syscalls->thread_id;
		run_unlock(state);
		if (yield() != 0)
			die_perror("yield");

		DEBUGP("main thread: checking syscall thread state\n");
		if (is_thread_sleeping(getpid(), thread_id))
			done = true;

		/* Grab the lock again and see if the thread is idle. */
		DEBUGP("main thread: locking and reading state\n");
		run_lock(state);
		if (state->syscalls->state == SYSCALL_IDLE)
			done = true;
	}
	DEBUGP("main thread: continuing after syscall\n");
	return;

error_out:
	script_path = strdup(state->config->script_path);
	state_free(state);
	die("%s:%d: runtime error in %s call: %s\n",
	    script_path, event->line_number,
	    syscall->name, error);
	free(script_path);
	free(error);
}

void run_system_call_event(
	struct state *state, struct event *event, struct syscall_spec *syscall)
{
	DEBUGP("%d: system call: %s\n", event->line_number, syscall->name);

	if (is_blocking_syscall(syscall))
		enqueue_system_call(state, event, syscall);
	else
		invoke_system_call(state, event, syscall);
}

/* The code executed by our system call thread, which executes
 * blocking system calls.
 */
static void *system_call_thread(void *arg)
{
	struct state *state = (struct state *)arg;
	char *error = NULL;
	struct event *event = NULL;
	struct syscall_spec *syscall = NULL;
	bool done = false;

	DEBUGP("syscall thread: starting and locking\n");
	run_lock(state);

	state->syscalls->thread_id = gettid();
	if (state->syscalls->thread_id < 0)
		die_perror("gettid");

	while (!done) {
		DEBUGP("syscall thread: in state %d\n",
		       state->syscalls->state);

		switch (state->syscalls->state) {
		case SYSCALL_IDLE:
			DEBUGP("syscall thread: waiting\n");
			if (pthread_cond_wait(&state->syscalls->enqueued,
					      &state->mutex)) {
				die_perror("pthread_cond_wait");
			}
			break;

		case SYSCALL_RUNNING:
		case SYSCALL_DONE:
			assert(0);	/* should not be reached */
			break;

		case SYSCALL_ENQUEUED:
			DEBUGP("syscall thread: invoking syscall\n");
			/* Remember the syscall event, since below we
			 * release the global lock and the main thread
			 * will move on to other, later events.
			 */
			event = state->event;
			syscall = event->event.syscall;
			assert(event->type == SYSCALL_EVENT);
			state->syscalls->event = event;
			state->syscalls->live_end_usecs = -1;

			/* Make the system call. Note that our callees
			 * here will release the global lock before
			 * making the actual system call and then
			 * re-acquire it after the system call returns
			 * and before returning to us.
			 */
			invoke_system_call(state, event, syscall);

			/* Check end time for the blocking system call. */
			assert(state->syscalls->live_end_usecs >= 0);
			if (verify_time(state,
						event->time_type,
						syscall->end_usecs, 0,
						state->syscalls->live_end_usecs,
						"system call return", &error)) {
				die("%s:%d: %s\n",
				    state->config->script_path,
				    event->line_number,
				    error);
			}

			/* Mark our thread idle and wake the main
			 * thread if it's waiting for this call to
			 * finish.
			 */
			assert(state->syscalls->state == SYSCALL_DONE);
			state->syscalls->state = SYSCALL_IDLE;
			state->syscalls->event = NULL;
			state->syscalls->live_end_usecs = -1;
			DEBUGP("syscall thread: now idle\n");
			if (pthread_cond_signal(&state->syscalls->idle) != 0)
				die_perror("pthread_cond_signal");
			break;

		case SYSCALL_EXITING:
			done = true;
			break;
		/* omitting default so compiler will catch missing cases */
		}
	}
	DEBUGP("syscall thread: unlocking and exiting\n");
	run_unlock(state);

	return NULL;
}

struct syscalls *syscalls_new(struct state *state)
{
	struct syscalls *syscalls = calloc(1, sizeof(struct syscalls));

	syscalls->state = SYSCALL_IDLE;

	if (pthread_create(&syscalls->thread, NULL, system_call_thread,
			   state) != 0) {
		die_perror("pthread_create");
	}

	if ((pthread_cond_init(&syscalls->idle, NULL) != 0) ||
	    (pthread_cond_init(&syscalls->enqueued, NULL) != 0) ||
	    (pthread_cond_init(&syscalls->dequeued, NULL) != 0)) {
		die_perror("pthread_cond_init");
	}

	return syscalls;
}

void syscalls_free(struct state *state, struct syscalls *syscalls)
{
	/* Wait a bit for the thread to go idle. */
	if (await_idle_thread(state)) {
		die("%s:%d: runtime error: exiting while "
		    "a blocking system call is in progress\n",
		    state->config->script_path,
		    syscalls->event->line_number);
	}

	/* Send a request to terminate the thread. */
	DEBUGP("main thread: signaling syscall thread to exit\n");
	syscalls->state = SYSCALL_EXITING;
	if (pthread_cond_signal(&syscalls->enqueued) != 0)
		die_perror("pthread_cond_signal");

	/* Release the lock briefly and wait for syscall thread to finish. */
	run_unlock(state);
	DEBUGP("main thread: unlocking, waiting for syscall thread exit\n");
	void *thread_result = NULL;
	if (pthread_join(syscalls->thread, &thread_result) != 0)
		die_perror("pthread_cancel");
	DEBUGP("main thread: joined syscall thread; relocking\n");
	run_lock(state);

	if ((pthread_cond_destroy(&syscalls->idle) != 0) ||
	    (pthread_cond_destroy(&syscalls->enqueued) != 0) ||
	    (pthread_cond_destroy(&syscalls->dequeued) != 0)) {
		die_perror("pthread_cond_destroy");
	}

	memset(syscalls, 0, sizeof(*syscalls));  /* to help catch bugs */
	free(syscalls);
}
