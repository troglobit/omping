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
#include <stdlib.h>

#include "clisig.h"
#include "clistate.h"

/*
 * Function prototypes
 */

static void	siginfo_handler(int sig);
static void	sigint_handler(int sig);

/*
 * Functions implementation
 */

/*
 * Register global signal handlers for application. sigaction is used to allow *BSD behavior, where
 * recvmsg, sendto, ... can return EINTR, what signal (Linux) doesn't do (functions are restarted
 * automatically)
 */
void
clisig_register_handlers(void)
{
	struct sigaction act;

	act.sa_handler = sigint_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	sigaction(SIGINT, &act, NULL);

	act.sa_handler = siginfo_handler;
#ifdef SIGINFO
	sigaction(SIGINFO, &act, NULL);
#endif
	sigaction(SIGUSR1, &act, NULL);
}

/*
 * Handler for SIGINFO signal
 */
static void
siginfo_handler(int sig)
{

	clistate_request_stats_display();
}

/*
 * Handler for SIGINT signal
 */
static void
sigint_handler(int sig)
{

	clistate_request_exit();
}
