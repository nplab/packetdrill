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
 * A module to execute a system(3) shell command and check the result.
 */

#include "system.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "logging.h"

int checked_system(const char *command, char **error)
{
	int result = system(command);
	if (result == -1) {
		asprintf(error, "%s", strerror(errno));
	} else if (WIFSIGNALED(result) &&
	    (WTERMSIG(result) == SIGINT || WTERMSIG(result) == SIGQUIT)) {
		asprintf(error, "got signal %d (%s)",
			 WTERMSIG(result), strsignal(WTERMSIG(result)));
	} else if (WEXITSTATUS(result) != 0) {
		asprintf(error, "non-zero status %d", WEXITSTATUS(result));
	}
	return result;
}

int safe_system(const char *command, char **error)
{
	assert(*error == NULL);
	checked_system(command, error);
	if (*error != NULL)
		return STATUS_ERR;
	return STATUS_OK;
}

int verbose_system(const char *command)
{
	int result;
	char *error = NULL;

	DEBUGP("running: '%s'\n", command);
	result = checked_system(command, &error);
	if (result != 0) {
		DEBUGP("error: %s executing command '%s'\n", error, command);
	} else {
		DEBUGP("result: %d\n", result);
	}
	return result;
}
