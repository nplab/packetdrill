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

#if defined(SCTP_RTOINFO) || defined(SCTP_STATUS) || defined(SCTP_PEER_ADDR_PARAMS) || defined(SCTP_MAXSEG) || defined(SCTP_MAX_BURST) || defined(SCTP_INTERLEAVING_SUPPORTED)
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
#endif

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
static int get_sockstorage_arg(struct expression *arg, struct sockaddr_storage *sock_addr, int live_fd, char **error)
{
	if (arg->type == EXPR_ELLIPSIS) {
		socklen_t len_addr;
		if (getpeername(live_fd, (struct sockaddr*) sock_addr, &len_addr)) {
			asprintf(error, "Bad setsockopt, bad get primary peer address");
			return STATUS_ERR;
		}
	} else if (arg->type == EXPR_SOCKET_ADDRESS_IPV4) {
		memcpy(sock_addr, arg->value.socket_address_ipv4, sizeof(struct sockaddr_in));
	} else if (arg->type == EXPR_SOCKET_ADDRESS_IPV6) {
		memcpy(sock_addr, arg->value.socket_address_ipv6, sizeof(struct sockaddr_in6));
	} else {
		return STATUS_ERR;
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

		assert(iov_expr->iov_base->type == EXPR_ELLIPSIS);
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
		      char **error)
{
	int status = STATUS_ERR;
	s32 s32_val = 0;
	struct msghdr_expr *msg_expr;	/* input expression from script */
	socklen_t name_len = sizeof(struct sockaddr_storage);
	struct msghdr *msg = NULL;	/* live output */

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

	if (msg_expr->msg_flags != NULL) {
		if (get_s32(msg_expr->msg_flags, &s32_val, error))
			goto error_out;
		msg->msg_flags = s32_val;
	}

	/* TODO(ncardwell): msg_control, msg_controllen */

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
				 "Expected non-negative result but got %d"
				 "with errno %d (%s)",
				 actual, actual_errno, strerror(actual_errno));
			return STATUS_ERR;
		}
	} else if (mode == CHECK_EXACT) {
		if (actual != expected) {
			if (actual < 0)
				asprintf(error,
					 "Expected result %d but got %d "
					 "with errno %d (%s)",
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
				 "Expected non-negative result but got %d "
				 "with errno %d (%s)",
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
	if (msghdr_new(msg_expression, &msg, &iov_len, error))
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

	status = STATUS_OK;

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
	if (msghdr_new(msg_expression, &msg, &iov_len, error))
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

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

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
	if (expr->l_onoff->type != EXPR_ELLIPSIS) {
		int l_onoff;

		if (get_s32(expr->l_onoff, &l_onoff, error)) {
			return STATUS_ERR;
		}
		if (linger->l_onoff != l_onoff) {
			asprintf(error, "Bad getsockopt linger.l_onoff: expected: %d actual: %d",
				 l_onoff, linger->l_onoff);
			return STATUS_ERR;
		}
	}
	if (expr->l_linger->type != EXPR_ELLIPSIS) {
		int l_linger;

		if (get_s32(expr->l_linger, &l_linger, error)) {
			return STATUS_ERR;
		}
		if (linger->l_linger != l_linger) {
			asprintf(error, "Bad getsockopt linger.l_linger: expected: %d actual: %d",
				 l_linger, linger->l_linger);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

#ifdef SCTP_RTOINFO
static int check_sctp_rtoinfo(struct sctp_rtoinfo_expr *expr,
			      struct sctp_rtoinfo *sctp_rtoinfo, char **error)
{
	if (expr->srto_initial->type != EXPR_ELLIPSIS) {
		u32 srto_initial;

		if (get_u32(expr->srto_initial, &srto_initial, error)) {
			return STATUS_ERR;
		}
		if (sctp_rtoinfo->srto_initial != srto_initial) {
			asprintf(error, "Bad getsockopt sctp_rtoinfo.srto_initial: expected: %u actual: %u",
				 srto_initial, sctp_rtoinfo->srto_initial);
			return STATUS_ERR;
		}
	}
	if (expr->srto_max->type != EXPR_ELLIPSIS) {
		u32 srto_max;

		if (get_u32(expr->srto_max, &srto_max, error)) {
			return STATUS_ERR;
		}
		if (sctp_rtoinfo->srto_max != srto_max) {
			asprintf(error, "Bad getsockopt sctp_rtoinfo.srto_max: expected: %u actual: %u",
				 srto_max, sctp_rtoinfo->srto_max);
			return STATUS_ERR;
		}
	}
	if (expr->srto_min->type != EXPR_ELLIPSIS) {
		u32 srto_min;

		if (get_u32(expr->srto_min, &srto_min, error)) {
			return STATUS_ERR;
		}
		if (sctp_rtoinfo->srto_min != srto_min) {
			asprintf(error, "Bad getsockopt sctp_rtoinfo.srto_min: expected: %u actual: %u",
				srto_min, sctp_rtoinfo->srto_min);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_INITMSG
static int check_sctp_initmsg(struct sctp_initmsg_expr *expr,
			      struct sctp_initmsg *sctp_initmsg, char **error)
{
	if (expr->sinit_num_ostreams->type != EXPR_ELLIPSIS) {
		u16 sinit_num_ostreams;

		if (get_u16(expr->sinit_num_ostreams, &sinit_num_ostreams, error)) {
			return STATUS_ERR;
		}
		if (sctp_initmsg->sinit_num_ostreams != sinit_num_ostreams) {
			asprintf(error, "Bad getsockopt sctp_initmsg.sinit_num_ostreams: expected: %hu actual: %hu",
				 sinit_num_ostreams, sctp_initmsg->sinit_num_ostreams);
			return STATUS_ERR;
		}
	}
	if (expr->sinit_max_instreams->type != EXPR_ELLIPSIS) {
		u16 sinit_max_instreams;

		if (get_u16(expr->sinit_max_instreams, &sinit_max_instreams, error)) {
			return STATUS_ERR;
		}
		if (sctp_initmsg->sinit_max_instreams != sinit_max_instreams) {
			asprintf(error, "Bad getsockopt sctp_initmsg.sinit_max_instreams: expected: %hu actual: %hu",
				 sinit_max_instreams, sctp_initmsg->sinit_max_instreams);
			return STATUS_ERR;
		}
	}
	if (expr->sinit_max_attempts->type != EXPR_ELLIPSIS) {
		u16 sinit_max_attempts;

		if (get_u16(expr->sinit_max_attempts, &sinit_max_attempts, error)) {
			return STATUS_ERR;
		}
		if (sctp_initmsg->sinit_max_attempts != sinit_max_attempts) {
			asprintf(error, "Bad getsockopt sctp_initmsg.sinit_max_attempts: expected: %hu actual: %hu",
				 sinit_max_attempts, sctp_initmsg->sinit_max_attempts);
			return STATUS_ERR;
		}
	}
	if (expr->sinit_max_init_timeo->type != EXPR_ELLIPSIS) {
		u16 sinit_max_init_timeo;

		if (get_u16(expr->sinit_max_init_timeo, &sinit_max_init_timeo, error)) {
			return STATUS_ERR;
		}
		if (sctp_initmsg->sinit_max_init_timeo != sinit_max_init_timeo) {
			asprintf(error, "Bad getsockopt sctp_initmsg.sinit_max_init_timeo: expected: %hu actual: %hu",
				 sinit_max_init_timeo, sctp_initmsg->sinit_max_init_timeo);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_DELAYED_SACK
static int check_sctp_sack_info(struct sctp_sack_info_expr *expr,
				struct sctp_sack_info *sctp_sack_info,
				char **error)
{
	if (expr->sack_delay->type != EXPR_ELLIPSIS) {
		u32 sack_delay;

		if (get_u32(expr->sack_delay, &sack_delay, error)) {
			return STATUS_ERR;
		}
		if (sctp_sack_info->sack_delay != sack_delay) {
			asprintf(error, "Bad getsockopt sctp_sack_info.sack_delay: expected: %u actual: %u",
				 sack_delay, sctp_sack_info->sack_delay);
			return STATUS_ERR;
		}
	}
	if (expr->sack_freq->type != EXPR_ELLIPSIS) {
		u32 sack_freq;

		if (get_u32(expr->sack_freq, &sack_freq, error)) {
			return STATUS_ERR;
		}
		if (sctp_sack_info->sack_freq != sack_freq) {
			asprintf(error, "Bad getsockopt sctp_sack_info.sack_freq: expected: %u actual: %u",
				 sack_freq, sctp_sack_info->sack_freq);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#if defined(SCTP_GET_PEER_ADDR_INFO) || defined(SCTP_STATUS)
static int check_sctp_paddrinfo(struct sctp_paddrinfo_expr *expr,
				struct sctp_paddrinfo *sctp_paddrinfo,
				char **error)
{
	if (expr->spinfo_state->type != EXPR_ELLIPSIS) {
		s32 spinfo_state;

		if (get_s32(expr->spinfo_state, &spinfo_state, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrinfo->spinfo_state != spinfo_state) {
			asprintf(error, "Bad getsockopt sctp_paddrinfo.spinfo_state: expected: %u actual: %u",
				spinfo_state, sctp_paddrinfo->spinfo_state);
			return STATUS_ERR;
		}
	}
	if (expr->spinfo_cwnd->type != EXPR_ELLIPSIS) {
		u32 spinfo_cwnd;

		if (get_u32(expr->spinfo_cwnd, &spinfo_cwnd, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrinfo->spinfo_cwnd != spinfo_cwnd) {
			asprintf(error, "Bad getsockopt sctp_paddrinfo.spinfo_cwnd: expected: %u actual: %u",
				 spinfo_cwnd, sctp_paddrinfo->spinfo_cwnd);
			return STATUS_ERR;
		}
	}
	if (expr->spinfo_srtt->type != EXPR_ELLIPSIS) {
		u32 spinfo_srtt;

		if (get_u32(expr->spinfo_srtt, &spinfo_srtt, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrinfo->spinfo_srtt != spinfo_srtt) {
			asprintf(error, "Bad getsockopt sctp_paddrinfo.spinfo_srtt: expected: %u actual: %u",
				 spinfo_srtt, sctp_paddrinfo->spinfo_srtt);
			return STATUS_ERR;
		}
	}
	if (expr->spinfo_rto->type != EXPR_ELLIPSIS) {
		u32 spinfo_rto;

		if (get_u32(expr->spinfo_rto, &spinfo_rto, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrinfo->spinfo_rto != spinfo_rto) {
			asprintf(error, "Bad getsockopt sctp_paddrinfo.spinfo_rto: expected: %u actual: %u",
				 spinfo_rto, sctp_paddrinfo->spinfo_rto);
			return STATUS_ERR;
		}
	}
	if (expr->spinfo_mtu->type != EXPR_ELLIPSIS) {
		u32 spinfo_mtu;

		if (get_u32(expr->spinfo_mtu, &spinfo_mtu, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrinfo->spinfo_mtu != spinfo_mtu) {
			asprintf(error, "Bad getsockopt sctp_paddrinfo.spinfo_mtu: expected: %u actual: %u",
				 spinfo_mtu, sctp_paddrinfo->spinfo_mtu);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_STATUS
static int check_sctp_status(struct sctp_status_expr *expr,
			     struct sctp_status *sctp_status,
			     char **error)
{
	if (expr->sstat_state->type != EXPR_ELLIPSIS) {
		s32 sstat_state;

		if (get_s32(expr->sstat_state, &sstat_state, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_state != sstat_state) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_state: expected: %d actual: %d",
				 sstat_state, sctp_status->sstat_state);
			return STATUS_ERR;
		}
	}
	if (expr->sstat_rwnd->type != EXPR_ELLIPSIS) {
		u32 sstat_rwnd;

		if (get_u32(expr->sstat_rwnd, &sstat_rwnd, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_rwnd != sstat_rwnd) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_rwnd: expected: %u actual: %u",
				 sstat_rwnd, sctp_status->sstat_rwnd);
			return STATUS_ERR;
		}
	}
	if (expr->sstat_unackdata->type != EXPR_ELLIPSIS) {
		u16 sstat_unackdata;

		if (get_u16(expr->sstat_unackdata, &sstat_unackdata, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_unackdata != sstat_unackdata) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_unackdata: expected: %hu actual: %hu",
				 sstat_unackdata, sctp_status->sstat_unackdata);
			return STATUS_ERR;
		}
	}
	if (expr->sstat_penddata->type != EXPR_ELLIPSIS) {
		u16 sstat_penddata;

		if (get_u16(expr->sstat_penddata, &sstat_penddata, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_penddata != sstat_penddata) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_penddata: expected: %hu actual: %hu",
				 sstat_penddata, sctp_status->sstat_penddata);
			return STATUS_ERR;
		}
	}
	if (expr->sstat_instrms->type != EXPR_ELLIPSIS) {
		u16 sstat_instrms;

		if (get_u16(expr->sstat_instrms, &sstat_instrms, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_instrms != sstat_instrms) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_instrms: expected: %hu actual: %hu",
				 sstat_instrms, sctp_status->sstat_instrms);
			return STATUS_ERR;
		}
	}
	if (expr->sstat_outstrms->type != EXPR_ELLIPSIS) {
		u16 sstat_outstrms;

		if (get_u16(expr->sstat_outstrms, &sstat_outstrms, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_outstrms != sstat_outstrms) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_outstrms: expected: %hu actual: %hu",
				 sstat_outstrms, sctp_status->sstat_outstrms);
			return STATUS_ERR;
		}
	}
	if (expr->sstat_fragmentation_point->type != EXPR_ELLIPSIS) {
		u32 sstat_fragmentation_point;

		if (get_u32(expr->sstat_fragmentation_point, &sstat_fragmentation_point, error)) {
			return STATUS_ERR;
		}
		if (sctp_status->sstat_fragmentation_point != sstat_fragmentation_point) {
			asprintf(error, "Bad getsockopt sctp_status.sstat_fragmentation_point: expected: %u actual: %u",
				sstat_fragmentation_point, sctp_status->sstat_fragmentation_point);
			return STATUS_ERR;
		}
	}
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
	if (expr->spp_hbinterval->type != EXPR_ELLIPSIS) {
		u32 spp_hbinterval;

		if (get_u32(expr->spp_hbinterval, &spp_hbinterval, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrparams->spp_hbinterval != spp_hbinterval) {
			asprintf(error, "Bad getsockopt sctp_paddrparams.spp_hbinterval: expected: %u actual: %u",
				 spp_hbinterval, sctp_paddrparams->spp_hbinterval);
			return STATUS_ERR;
		}
	}
	if (expr->spp_pathmaxrxt->type != EXPR_ELLIPSIS) {
		u16 spp_pathmaxrxt;

		if (get_u16(expr->spp_pathmaxrxt, &spp_pathmaxrxt, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrparams->spp_pathmaxrxt != spp_pathmaxrxt) {
			asprintf(error, "Bad getsockopt sctp_paddrparams.spp_pathmaxrxt: expected: %hu actual: %hu",
				 spp_pathmaxrxt, sctp_paddrparams->spp_pathmaxrxt);
			return STATUS_ERR;
		}
	}
	if (expr->spp_pathmtu->type != EXPR_ELLIPSIS) {
		u32 spp_pathmtu;

		if (get_u32(expr->spp_pathmtu, &spp_pathmtu, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrparams->spp_pathmtu != spp_pathmtu) {
			asprintf(error, "Bad getsockopt sctp_paddrparams.spp_pathmtu: expected: %u actual: %u",
				 spp_pathmtu, sctp_paddrparams->spp_pathmtu);
			return STATUS_ERR;
		}
	}
	if (expr->spp_flags->type != EXPR_ELLIPSIS) {
		u32 spp_flags;

		if (get_u32(expr->spp_flags, &spp_flags, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrparams->spp_flags != spp_flags) {
			asprintf(error, "Bad getsockopt sctp_paddrparams.spp_flags: expected: 0x%08x actual: 0x%08x",
				 spp_flags, sctp_paddrparams->spp_flags);
			return STATUS_ERR;
		}
	}
	if (expr->spp_ipv6_flowlabel->type != EXPR_ELLIPSIS) {
#ifdef linux
		asprintf(error, "Bad getsockopt linux doesn't support sctp_paddrparams.spp_ipv6_flowlabel");
		return STATUS_ERR;
#else
		u32 spp_ipv6_flowlabel;

		if (get_u32(expr->spp_ipv6_flowlabel, &spp_ipv6_flowlabel, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrparams->spp_ipv6_flowlabel != spp_ipv6_flowlabel) {
			asprintf(error, "Bad getsockopt sctp_paddrparams.spp_ipv6_flowlabel: expected: %u actual: %u",
				 spp_ipv6_flowlabel, sctp_paddrparams->spp_ipv6_flowlabel);
			return STATUS_ERR;
		}
#endif
	}
	if (expr->spp_dscp->type != EXPR_ELLIPSIS) {
#ifdef linux
		asprintf(error, "Bad getsockopt linux doesn't support sctp_paddrparams.spp_dscp");
		return STATUS_ERR;
#else
		u8 spp_dscp;

		if (get_u8(expr->spp_dscp, &spp_dscp, error)) {
			return STATUS_ERR;
		}
		if (sctp_paddrparams->spp_dscp != spp_dscp) {
			asprintf(error, "Bad getsockopt sctp_paddrparams.spp_dscp: expected: %hhu actual: %hhu",
				 spp_dscp, sctp_paddrparams->spp_dscp);
			return STATUS_ERR;
		}
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
	if (expr->assoc_value->type != EXPR_ELLIPSIS) {
		u32 assoc_value;

		if (get_u32(expr->assoc_value, &assoc_value, error)) {
			return STATUS_ERR;
		}
		if (sctp_assoc_value->assoc_value != assoc_value) {
			asprintf(error, "Bad getsockopt sctp_assoc_value.assoc_value: expected: %u actual: %u",
				 assoc_value, sctp_assoc_value->assoc_value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_SS_VALUE
static int check_sctp_stream_value(struct sctp_stream_value_expr *expr,
				   struct sctp_stream_value *sctp_stream_value,
				   char **error)
{
	if (expr->stream_id->type != EXPR_ELLIPSIS) {
		u16 stream_id;

		if (get_u16(expr->stream_id, &stream_id, error)) {
			return STATUS_ERR;
		}
		if (sctp_stream_value->stream_id != stream_id) {
			asprintf(error, "Bad getsockopt sctp_stream_value.stream_id: expected: %u actual: %u",
				 stream_id, sctp_stream_value->stream_id);
			return STATUS_ERR;
		}
	}
	if (expr->stream_value->type != EXPR_ELLIPSIS) {
		u16 stream_value;

		if (get_u16(expr->stream_value, &stream_value, error)) {
			return STATUS_ERR;
		}
		if (sctp_stream_value->stream_value != stream_value) {
			asprintf(error, "Bad getsockopt sctp_stream_value.stream_value: expected: %u actual: %u",
				 stream_value, sctp_stream_value->stream_value);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_ASSOCINFO
static int check_sctp_assocparams(struct sctp_assocparams_expr *expr,
			     struct sctp_assocparams *sctp_assocparams,
			     char **error)
{
	if (expr->sasoc_asocmaxrxt->type != EXPR_ELLIPSIS) {
		u16 sasoc_asocmaxrxt;

		if (get_u16(expr->sasoc_asocmaxrxt, &sasoc_asocmaxrxt, error)) {
			return STATUS_ERR;
		}
		if (sctp_assocparams->sasoc_asocmaxrxt != sasoc_asocmaxrxt) {
			asprintf(error, "Bad getsockopt sctp_assocparams.sasoc_asocmaxrxt: expected: %hu actual: %hu",
				 sasoc_asocmaxrxt, sctp_assocparams->sasoc_asocmaxrxt);
			return STATUS_ERR;
		}
	}
	if (expr->sasoc_number_peer_destinations->type != EXPR_ELLIPSIS) {
		u16 sasoc_number_peer_destinations;

		if (get_u16(expr->sasoc_number_peer_destinations, &sasoc_number_peer_destinations, error)) {
			return STATUS_ERR;
		}
		if (sctp_assocparams->sasoc_number_peer_destinations != sasoc_number_peer_destinations) {
			asprintf(error, "Bad getsockopt sctp_assocparams.sasoc_number_peer_destinations: expected: %hu actual: %hu",
					 sasoc_number_peer_destinations, sctp_assocparams->sasoc_number_peer_destinations);
			return STATUS_ERR;
		}
	}
	if (expr->sasoc_peer_rwnd->type != EXPR_ELLIPSIS) {
		u32 sasoc_peer_rwnd;

		if (get_u32(expr->sasoc_peer_rwnd, &sasoc_peer_rwnd, error)) {
			return STATUS_ERR;
		}
		if (sctp_assocparams->sasoc_peer_rwnd != sasoc_peer_rwnd) {
			asprintf(error, "Bad getsockopt sctp_assocparams.sasoc_peer_rwnd: expected: %u actual: %u",
				 sasoc_peer_rwnd, sctp_assocparams->sasoc_peer_rwnd);
			return STATUS_ERR;
		}
	}
	if (expr->sasoc_local_rwnd->type != EXPR_ELLIPSIS) {
		u32 sasoc_local_rwnd;

		if (get_u32(expr->sasoc_local_rwnd, &sasoc_local_rwnd, error)) {
			return STATUS_ERR;
		}
		if (sctp_assocparams->sasoc_local_rwnd != sasoc_local_rwnd) {
			asprintf(error, "Bad getsockopt sctp_assocparams.sasoc_local_rwnd: expected: %u actual: %u",
				 sasoc_local_rwnd, sctp_assocparams->sasoc_local_rwnd);
			return STATUS_ERR;
		}
	}
	if (expr->sasoc_cookie_life->type != EXPR_ELLIPSIS) {
		u32 sasoc_cookie_life;

		if (get_u32(expr->sasoc_cookie_life, &sasoc_cookie_life, error)) {
			return STATUS_ERR;
		}
		if (sctp_assocparams->sasoc_cookie_life != sasoc_cookie_life) {
			asprintf(error, "Bad getsockopt sctp_assocparams.sasoc_cookie_life: expected: %u actual: %u",
				 sasoc_cookie_life, sctp_assocparams->sasoc_cookie_life);
			return STATUS_ERR;
		}
	}

	return STATUS_OK;
}
#endif

#ifdef SCTP_EVENT
static int check_sctp_event(struct sctp_event_expr *expr,
			    struct sctp_event *sctp_event,
			    char **error)
{
	if (expr->se_type->type != EXPR_ELLIPSIS) {
		u16 se_type;

		if (get_u16(expr->se_type, &se_type, error)) {
			return STATUS_ERR;
		}
		if (sctp_event->se_type != se_type) {
			asprintf(error, "Bad getsockopt sctp_event.se_type: expected: %hu actual: %hu",
				 se_type, sctp_event->se_type);
			return STATUS_ERR;
		}
	}
	if (expr->se_on->type != EXPR_ELLIPSIS) {
		u8 se_on;

		if (get_u8(expr->se_on, &se_on, error)) {
			return STATUS_ERR;
		}
		if (sctp_event->se_on != se_on) {
			asprintf(error, "Bad getsockopt sctp_event.se_on: expected: %hhu actual: %hhu",
				 se_on, sctp_event->se_on);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_DEFAULT_SNDINFO
static int check_sctp_sndinfo(struct sctp_sndinfo_expr *expr,
			      struct sctp_sndinfo *sctp_sndinfo,
			      char **error)
{
	if (expr->snd_sid->type != EXPR_ELLIPSIS) {
		u16 snd_sid;

		if (get_u16(expr->snd_sid, &snd_sid, error)) {
			return STATUS_ERR;
		}
		if (sctp_sndinfo->snd_sid != snd_sid) {
			asprintf(error, "Bad getsockopt sctp_sndinfo.snd_sid: expected: %hu actual: %hu",
				 snd_sid, sctp_sndinfo->snd_sid);
			return STATUS_ERR;
		}
	}
	if (expr->snd_flags->type != EXPR_ELLIPSIS) {
		u16 snd_flags;

		if (get_u16(expr->snd_flags, &snd_flags, error)) {
			return STATUS_ERR;
		}
		if (sctp_sndinfo->snd_flags != snd_flags) {
			asprintf(error, "Bad getsockopt sctp_sndinfo.snd_flags: expected: %hu actual: %hu",
				 snd_flags, sctp_sndinfo->snd_flags);
			return STATUS_ERR;
		}
	}
	if (expr->snd_ppid->type != EXPR_ELLIPSIS) {
		u32 snd_ppid;

		if (get_u32(expr->snd_ppid, &snd_ppid, error)) {
			return STATUS_ERR;
		}
		if (sctp_sndinfo->snd_ppid != snd_ppid) {
			asprintf(error, "Bad getsockopt sctp_sndinfo.snd_ppid: expected: %u actual: %u",
				 snd_ppid, sctp_sndinfo->snd_ppid);
			return STATUS_ERR;
		}
	}
	if (expr->snd_context->type != EXPR_ELLIPSIS) {
		u32 snd_context;

		if (get_u32(expr->snd_context, &snd_context, error)) {
			return STATUS_ERR;
		}
		if (sctp_sndinfo->snd_context != snd_context) {
			asprintf(error, "Bad getsockopt sctp_sndinfo.snd_context: expected: %u actual: %u",
				 snd_context, sctp_sndinfo->snd_context);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}
#endif

#ifdef SCTP_ADAPTATION_LAYER
static int check_sctp_setadaptation(struct sctp_setadaptation_expr *expr,
				    struct sctp_setadaptation *sctp_setadaptation,
				    char **error)
{
	if (expr->ssb_adaptation_ind->type != EXPR_ELLIPSIS) {
		u32 ssb_adaptation_ind;

		if (get_u32(expr->ssb_adaptation_ind, &ssb_adaptation_ind, error)) {
			return STATUS_ERR;
		}
		if (sctp_setadaptation->ssb_adaptation_ind != ssb_adaptation_ind) {
			asprintf(error, "Bad getsockopt sctp_setadaptation.ssb_adaptation_ind: expected: %u actual: %u",
				 ssb_adaptation_ind, sctp_setadaptation->ssb_adaptation_ind);
			return STATUS_ERR;
		}
	}
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
					&(live_paddrinfo->spinfo_address), live_fd, error)) {
			asprintf(error, "Bad getsockopt, bad get input for spinfo_address");
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
					live_fd, error)) {
			asprintf(error, "Bad getsockopt, bad get input for spp_address");
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
#ifdef SCTP_DEFAULT_SNDINFO
	case EXPR_SCTP_SNDINFO:
		live_optval = malloc(sizeof(struct sctp_sndinfo));
		live_optlen = sizeof(struct sctp_sndinfo);
		((struct sctp_sndinfo *)live_optval)->snd_assoc_id = 0;
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
		asprintf(error, "unsupported getsockopt value type: %s",
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
		asprintf(error, "Bad getsockopt optlen: expected: %d actual: %d",
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
			asprintf(error, "Bad getsockopt optval: expected: %d actual: %d",
				(int)script_optval, *(int*)live_optval);
			result = STATUS_ERR;
		}
		break;
	default:
		asprintf(error, "Cannot check getsockopt value type: %s",
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
		if (get_u16(val_expression->value.sctp_initmsg->sinit_num_ostreams,
			    &initmsg.sinit_num_ostreams, error)) {
		return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_initmsg->sinit_max_instreams,
			    &initmsg.sinit_max_instreams, error)) {
			return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_initmsg->sinit_max_attempts,
			    &initmsg.sinit_max_attempts, error)) {
			return STATUS_ERR;
		}
		if (get_u16(val_expression->value.sctp_initmsg->sinit_max_init_timeo,
			    &initmsg.sinit_max_init_timeo, error)) {
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
					&paddrinfo.spinfo_address, live_fd, error)) {
			asprintf(error, "Bad getsockopt, bad get input for spp_address");
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
#ifdef SCTP_DEFAULT_SNDINFO
	case EXPR_SCTP_SNDINFO:
		sndinfo.snd_assoc_id = 0;
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
				        &paddrparams.spp_address, live_fd, error)) {
			asprintf(error, "Bad setsockopt, bad input for spp_address for socketoption SCTP_PADDRPARAMS");
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
			asprintf(error, "Bad setsockopt, Linux doesn't support paddrparams.spp_ipv6_flowlabel");
			return STATUS_ERR;
		}
		if (get_u8(val_expression->value.sctp_paddrparams->spp_dscp,
		           &spp_dscp, error)) {
			return STATUS_ERR;
		} else if (spp_dscp != 0) {
			asprintf(error, "Bad setsockopt, Linux doesn't support paddrparams.spp_dscp");
			return STATUS_ERR;
		}
		paddrparams.spp_sackdelay = 0;
#endif
		optval = &paddrparams;
		break;
#endif
	default:
		asprintf(error, "unsupported setsockopt value type: %s",
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
