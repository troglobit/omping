/*
 * Copyright (c) 2010-2011, Red Hat, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND RED HAT, INC. DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RED HAT, INC. BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Author: Jan Friesse <jfriesse@redhat.com>
 */

#include <sys/types.h>

#include <signal.h>
#include <unistd.h>

#include "logging.h"
#include "clistate.h"

/*
 * Maximum number of exit request before hard kill action is taken
 */
#define MAX_EXIT_REQUESTS	2

/*
 * User requested exit of application (usually with SIGINT)
 */
static int exit_requested;

/*
 * User requested to display overall statistics (SIGINT/SIGUSR1)
 */
static int display_stats_requested;


/*
 * Cancel request for exit
 */
void
clistate_cancel_exit(void)
{

	exit_requested = 0;
}

/*
 * Cancel request for display statistics
 */
void
clistate_cancel_stats_display(void)
{

	display_stats_requested = 0;
}

/*
 * Return value > 0 if exit was requested.
 */
int
clistate_is_exit_requested(void)
{

	return (exit_requested);
}

/*
 * Return value > 0 if status display was requested.
 */
int
clistate_is_stats_display_requested(void)
{

	return (display_stats_requested);
}

/*
 * Request exit
 */
void
clistate_request_exit(void)
{

	exit_requested++;
	DEBUG2_PRINTF("Exit requested %d times", exit_requested);

	if (exit_requested > MAX_EXIT_REQUESTS) {
		signal(SIGINT, SIG_DFL);
		kill(getpid(), SIGINT);
	}
}

/*
 * Request display of statistics
 */
void
clistate_request_stats_display(void)
{

	display_stats_requested++;
}
