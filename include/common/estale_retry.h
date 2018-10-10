/*
 * Copyright 2014, 2016-2017 Cray Inc. All Rights Reserved.
 *
 * This file is part of Cray Data Virtualization Service (DVS).
 *
 * DVS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DVS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ESTALE_RETRY_H
#define ESTALE_RETRY_H

#define ESTALE_LOG(args...) DVS_LOG(args)

/*
 * Seconds between messages about ESTALE errors on the servers. We want some
 * information to be printed when there are ESTALE errors, but we want to
 * avoid flooding the console.
 */
#define ESTALE_MESSAGE_THROTTLE 300

/*
 * Ensure 3 minutes of retries.  For example, boot node failover scenarios
 * with NetRoot may result in ESTALE errors for roughly this amount of time.
 */
#define ESTALE_MAX_RETRY 36

#define ESTALE_TIMEOUT_SECS 300

enum {
	ESTALE_RETRY_FAIL,
	ESTALE_RETRY_PASS,
	ESTALE_FAILOVER_FAIL,
	ESTALE_FAILOVER_PASS,
	ESTALE_NUM_STATS
};

struct estale_stats {
	unsigned long	jiffies;
	atomic64_t	stats[ESTALE_NUM_STATS];
};

extern struct estale_stats global_estale_stats;

extern unsigned int estale_max_retry;
extern unsigned int estale_timeout_secs;

#endif /* ESTALE_RETRY_H */
