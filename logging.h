/*
 * Copyright (c) 2010, Red Hat, Inc.
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

#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	LOGGING_LEVEL_QUIET	= 0,
	LOGGING_LEVEL_VERBOSE	= 1,
	LOGGING_LEVEL_DEBUG	= 2,
	LOGGING_LEVEL_DEBUG2	= 3,
};

#define	DEBUG_PRINTF(...) \
    logging_printf(__FILE__, __LINE__, LOGGING_LEVEL_DEBUG, __VA_ARGS__)

#define DEBUG2_HEXDUMP(prefix_str, data, data_len) \
    logging_hexdump(__FILE__, __LINE__, LOGGING_LEVEL_DEBUG2, prefix_str, data, data_len)

#define	DEBUG2_PRINTF(...) \
    logging_printf(__FILE__, __LINE__, LOGGING_LEVEL_DEBUG2, __VA_ARGS__)

#define	VERBOSE_PRINTF(...) \
    logging_printf(__FILE__, __LINE__, LOGGING_LEVEL_VERBOSE, __VA_ARGS__)

#define LOGGING_SA_TO_STR_LEN	(INET6_ADDRSTRLEN + 16)

extern int	logging_ai_to_str(const struct addrinfo *ai, char *dst, int max_l);
extern int	logging_get_verbose(void);

extern int	logging_hexdump(const char *file_name, int line, int log_level,
    const char *prefix_str, const void *data, size_t data_len);

extern int	logging_printf(const char *file_name, int line, int log_level,
    const char *format, ...) __attribute__((__format__(__printf__, 4, 5)));

extern int	logging_sa_to_str(const struct sockaddr *sa, char *dst, int max_l);
extern void	logging_set_verbose(int lv);

#ifdef __cplusplus
}
#endif

#endif /* _LOGGING_H_ */
