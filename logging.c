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

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "addrfunc.h"
#include "logging.h"

static int logging_verbose;

int
logging_ai_to_str(const struct addrinfo *ai, char *dst, int max_l)
{
	if (ai->ai_family == PF_INET || ai->ai_family == PF_INET6) {
		return (logging_sa_to_str((struct sockaddr *)ai->ai_addr, dst, max_l));
	}

	return (0);
}

int
logging_get_verbose(void)
{

	return (logging_verbose);
}

int
logging_hexdump(const char *file_name, int line, int log_level, const char *prefix_str,
    const void *data, size_t data_len)
{
	size_t i;
	int res;
	uint8_t u8;

	res = 0;

	if (logging_get_verbose() >= log_level) {
		if (logging_get_verbose() >= LOGGING_LEVEL_DEBUG) {
			res += fprintf(stderr, "%s:%d ", file_name, line);
		}

		if (prefix_str != NULL) {
			res += fprintf(stderr, "%s", prefix_str);
		}

		for (i = 0; i < data_len; i++)	{
			u8 = ((const unsigned char *)data)[i];

			res += fprintf(stderr, "%02"PRIX8, u8);
		}
		res += fprintf(stderr, "\n");
	}

	return (res);
}

int
logging_printf(const char *file_name, int line, int log_level, const char *format, ...)
{
	va_list ap;
	int res;

	res = 0;

	if (logging_verbose >= log_level) {
		va_start(ap, format);
		if (logging_verbose >= LOGGING_LEVEL_DEBUG) {
			res += fprintf(stderr, "%s:%d ", file_name, line);
		}
		res += vfprintf(stderr, format, ap);
		res += fprintf(stderr, "\n");
		va_end(ap);
	}

	return (res);
}

int
logging_sa_to_str(const struct sockaddr *sa, char *dst, int max_l)
{
	int ipv;
	char buf[INET6_ADDRSTRLEN];

	if (af_sa_to_str(sa, buf) == NULL) {
		return (0);
	}

	switch (sa->sa_family) {
	case PF_INET:
		ipv = 4;
		break;
	case PF_INET6:
		ipv = 6;
		break;
	default:
		return (0);
	}

	return (snprintf(dst, max_l, "ipv%d, addr: %s", ipv, buf));
}

void
logging_set_verbose(int lv)
{

	logging_verbose = lv;
}
