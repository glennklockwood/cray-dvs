/* Copyright 2018 Cray Inc. All Rights Reserved.
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

#ifndef __DVSSYS_TIMING_STAT_H__
#define __DVSSYS_TIMING_STAT_H__

#define DVS_TIMING_VERSION "1.0"

/*
 * DVS Timing Segment Stats Structure
 *
 * Stat parameters that are tracked for each type of DVS request and tracked
 * for each segment of the request (queue, file system, network, & overhead).
 *
 * max = maximum (longest) time observed since last reset
 * min = minimum (shortest) time observed since last reset
 * sum = running sum of all time measurements since last reset
 *
 * The sum parameter is tracked to allow for on-the-fly
 * calculations of mean at the time the stats are read by a user in the proc
 * stats file. By using this approach, we are able to establish a "running"
 * mean without needing to track and store each individual time separately.
 */
struct dvs_timing_segment {
	uint64_t max;
	uint64_t min;
	uint64_t sum;
};

/*
 * Elapsed Time Calcs:
 * - File System times are calculated in dvsofserver, before this function
 * - Queue time is measured from when the server receives the message/adds to
 * queue until the time the request is performed on the underlying files system.
 * That is, "fs_time_start" could just as easily be called queue_time_end.
 * - Server Overhead is found by deduction and not direct calculation by
 * subtracting the file system from the total server time. The overhead is the
 * time left unaccounted for after the queue and fs time segments have been
 * subtracted out.
 * - Network Time, like overhead, is found by subtracting the other measured
 * time segment from the overall total time (from server send message to server
 * receives message). Since times are measured on separate nodes (client &
 * server) each with their own clocks, the time spent on the network in each
 * individual direction (send and receive) cannot be found.
 */
struct dvs_timing_stats {
	spinlock_t sl;
	char *op_name;
	time_t last_reset;
	uint64_t count;

	struct dvs_timing_segment overhead;
	struct dvs_timing_segment network;
	struct dvs_timing_segment queue;
	struct dvs_timing_segment fs;
	struct dvs_timing_segment total;
};

/* Array that holds timing info for each defined request */
extern struct dvs_timing_stats dvs_client_timing_stats[];
extern struct dvs_timing_stats dvs_server_timing_stats[];

/* Called once on module startup */
void dvs_timing_init(void);
/* Called to reset timings stats back to pristine values */
void dvs_timing_reset(struct dvs_timing_stats *stats_array);

#endif /* __DVSSYS_TIMING_STAT_H__ */
