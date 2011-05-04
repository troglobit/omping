/*
 * Copyright (c) 2011, Red Hat, Inc.
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

#include <sys/time.h>

#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "gcra.h"
#include "util.h"

/*
 * item is gcra_item to be initialized. Interval is interval in ms in which packet
 * will arrive (max), and burst is number of packets which may arrive sooner.
 */
void
gcra_init(struct gcra_item *item, unsigned int interval, unsigned int burst)
{

	memset(item, 0, sizeof(*item));

	item->tau = burst * interval;
	item->interval = interval;
}

/*
 * item is gcra item and tv is time of packet arrival.
 * Returns 0 if packet is non conforming and should be discarded/put to queue, ..., and 1 if packet
 * is conforming.
 */
int
gcra_rl(struct gcra_item *item, struct timeval tv)
{
	uint64_t tv_u64;

	tv_u64 = util_tv_to_ms(tv);

	if (item->tat >= item->tau && tv_u64 < item->tat - item->tau) {
		return (0);
	} else {
		item->tat = ((tv_u64 > item->tat) ? tv_u64 : item->tat) + item->interval;

		return (1);
	}
}
