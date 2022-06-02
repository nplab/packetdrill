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

static void checked_system(const char *command, char **error)
{
	int status;
    status = system(command);
	if (status == -1) {
		asprintf(error, "%s", strerror(errno));
	} else if (WIFSIGNALED(status) &&
			   (WTERMSIG(status) == SIGINT || WTERMSIG(status) == SIGQUIT)) {
		asprintf(error, "got signal %d (%s)",
				 WTERMSIG(status), strsignal(WTERMSIG(status)));
	} else if (WEXITSTATUS(status) != 0) {
		asprintf(error, "non-zero status %d", WEXITSTATUS(status));
	} else {
		*error = NULL;
	}
}

int safe_system(const char *command, char **error)
{
	checked_system(command, error);
	if (*error != NULL)
		return STATUS_ERR;
	return STATUS_OK;
}

int verbose_system(const char *command)
{
	char *error = NULL;

	DEBUGP("running: '%s'\n", command);
	checked_system(command, &error);
	if (*error != NULL) {
		DEBUGP("error: %s executing command '%s'\n", error, command);
		return STATUS_ERR;
	}
	return STATUS_OK;
}
