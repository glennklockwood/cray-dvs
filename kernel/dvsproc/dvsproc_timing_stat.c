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

#include "common/kernel/usiipc.h"
#include "dvs/kernel/usifile.h"
#include "common/dvsproc_timing_stat.h"

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

struct dvs_timing_stats dvs_client_timing_stats[RQ_DVS_END_V1];
EXPORT_SYMBOL(dvs_client_timing_stats);
struct dvs_timing_stats dvs_server_timing_stats[RQ_DVS_END_V1];
EXPORT_SYMBOL(dvs_server_timing_stats);

static void dvs_timing_stats_update(struct dvs_timing_stats *timing,
				    uint64_t count, uint64_t overhead,
				    uint64_t fs, uint64_t queue,
				    uint64_t network, uint64_t total)
{
	spin_lock(&timing->sl);

	timing->count += count;

	timing->overhead.sum += overhead;
	timing->fs.sum += fs;
	timing->queue.sum += queue;
	timing->network.sum += network;
	timing->total.sum += total;

	timing->overhead.max = max(overhead, timing->overhead.max);
	timing->fs.max = max(fs, timing->fs.max);
	timing->queue.max = max(queue, timing->queue.max);
	timing->network.max = max(network, timing->network.max);
	timing->total.max = max(total, timing->total.max);

	timing->overhead.min = min(overhead, timing->overhead.min);
	timing->fs.min = min(fs, timing->fs.min);
	timing->queue.min = min(queue, timing->queue.min);
	timing->network.min = min(network, timing->network.min);
	timing->total.min = min(total, timing->total.min);

	spin_unlock(&timing->sl);
}

/*
 * Update stats for several requests at once. This covers somewhat-asynchronous
 * operations to multiple simultaneous servers like open, close, read, and
 * write.
 */

void dvs_update_client_bulk_stats(struct per_node *pna, int n)
{
	int i, count = 0, request_type = -1;
	uint64_t overhead = 0;
	uint64_t fs = 0;
	uint64_t queue = 0;
	uint64_t network = 0;
	uint64_t total = 0;
	struct file_request *filerq;
	struct file_reply *filerp;
	struct dvs_timing_stats *op_stats;

	/*
	 * Aggregate all timing info to hold the op_stats lock for as little
	 * time as possible.
	 */
	for (i = 0; i < n; i++) {
		filerq = pna[i].request;
		filerp = pna[i].reply;

		if (filerq == NULL || filerp == NULL)
			continue;

		/* Get the request_type from a valid filerq */
		if (request_type == -1)
			request_type = filerq->request;

		/* Update network time only if both are valid */
		if (filerq->ipcmsg.network_time_us > 0 &&
		    filerp->ipcmsg.network_time_us > 0) {
			total += filerp->ipcmsg.network_time_us -
				 filerq->ipcmsg.network_time_us;
			network += filerp->ipcmsg.network_time_us -
				   filerq->ipcmsg.network_time_us -
				   filerp->ipcmsg.queue_time_us -
				   filerp->ipcmsg.process_time_us;
		}

		fs += filerp->fs_time_us;
		queue += filerp->ipcmsg.queue_time_us;
		overhead += filerp->ipcmsg.process_time_us - filerp->fs_time_us;
		count++;
	}

	if (count == 0)
		return;

	/* Update the actual info with the aggregated information */
	op_stats = &dvs_client_timing_stats[request_type];
	dvs_timing_stats_update(op_stats, count, overhead, fs, queue, network,
				total);
}
EXPORT_SYMBOL(dvs_update_client_bulk_stats);

/* Update timing info with results from a single request/reply message pair */
void dvs_update_client_stats(struct file_request *filerq,
			     struct file_reply *filerp)
{
	struct per_node pna;

	pna.request = filerq;
	pna.reply = filerp;

	dvs_update_client_bulk_stats(&pna, 1);
}
EXPORT_SYMBOL(dvs_update_client_stats);

void dvs_update_server_stats(int request, uint64_t process, uint64_t fs,
			     uint64_t queue)
{
	dvs_timing_stats_update(&dvs_server_timing_stats[request], 1,
				process - fs, fs, queue, 0, queue + process);
}
EXPORT_SYMBOL(dvs_update_server_stats);

/*
 * Initializes stats variables and sets correct initial values to use at the
 * start when count == 0 and/or after doing a reset
 */
static void init_timing_segment(struct dvs_timing_segment *seg)
{
	seg->max = 0;
	seg->min = 0xffffffffffffffff;
	seg->sum = 0;
}

/*
 * Resets the running timing stats that have been collected to defaults.
 */
void dvs_timing_reset(struct dvs_timing_stats *stats_array)
{
	int op;
	struct dvs_timing_stats *timing;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	time_t now = CURRENT_TIME.tv_sec;
#else
	time64_t now = ktime_get_real_seconds();
#endif

	for (op = 0; op < RQ_DVS_END_V1; op++) {
		timing = &stats_array[op];
		spin_lock(&timing->sl);
		timing->count = 0;
		timing->last_reset = now;
		init_timing_segment(&timing->queue);
		init_timing_segment(&timing->fs);
		init_timing_segment(&timing->overhead);
		init_timing_segment(&timing->network);
		init_timing_segment(&timing->total);
		spin_unlock(&timing->sl);
	}
}
EXPORT_SYMBOL(dvs_timing_reset);

/*
 * Initialize some things and then reset the timings
 */
void dvs_timing_init()
{
	int op;
	struct dvs_timing_stats *timing;

	for (op = 0; op < RQ_DVS_END_V1; op++) {
		timing = &dvs_client_timing_stats[op];
		spin_lock_init(&timing->sl);
		timing->op_name = file_request_to_string(op);
		/* Lop off the leading 'RQ_' */
		if (!strncmp(timing->op_name, "RQ_", 3))
			timing->op_name += 3;
	}
	dvs_timing_reset(dvs_client_timing_stats);

	for (op = 0; op < RQ_DVS_END_V1; op++) {
		timing = &dvs_server_timing_stats[op];
		spin_lock_init(&timing->sl);
		timing->op_name = file_request_to_string(op);
		/* Lop off the leading 'RQ_' */
		if (!strncmp(timing->op_name, "RQ_", 3))
			timing->op_name += 3;
	}
	dvs_timing_reset(dvs_server_timing_stats);
}
EXPORT_SYMBOL(dvs_timing_init);
