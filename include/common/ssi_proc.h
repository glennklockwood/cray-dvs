/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006, 2009, 2011, 2013-2018 Cray Inc. All Rights Reserved.
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

/*
 * If modifications to this file affect the libssi interface please
 * increment LIBSSI_VER in Makefile.in
 */

#ifndef __USIDVSSYS_H__
#define __USIDVSSYS_H__

#define DVS_PROCFS_DIR "fs/dvs"
#define DVS_PROCFS_NODEFILE "ssi-map"

#define DVS_SYSFS_DIR "dvs"
#define DVS_SYSFS_DEBUG "debug"
#define DVS_SYSFS_SYNC_PERIOD "sync_period_secs"
#define DVS_SYSFS_SYNC_TIMEOUT "sync_dirty_timeout_secs"
#define DVS_SYSFS_SYNC_THREADS "sync_num_threads"
#define DVS_SYSFS_ESTALE_MAX_RETRY "estale_max_retry"
#define DVS_SYSFS_ESTALE_TIMEOUT "estale_timeout_secs"
#define DVS_SYSFS_DROP_CACHES "drop_caches"
#define DVS_SYSFS_QUIESCE "quiesce"

#define DVS_DEBUGFS_DIR "dvs"
#define DVS_DEBUGFS_MOUNTS_DIR "mounts"
#define DVS_DEBUGFS_MAX_NODES "max-nodes"
#define DVS_DEBUGFS_STATS "stats"
#define DVS_DEBUGFS_MOUNT "mount"
#define DVS_DEBUGFS_OPENFILES "openfiles"
#define DVS_DEBUGFS_NODENAMES "nodenames"
#define DVS_DEBUGFS_LOG "log"
#define DVS_DEBUGFS_LOG_SIZE "log_size_kb"
#define DVS_DEBUGFS_RQ_LOG "request_log"
#define DVS_DEBUGFS_RQ_LOG_SIZE "request_log_size_kb"
#define DVS_DEBUGFS_RQ_LOG_TIME "request_log_time_min_secs"
#define DVS_DEBUGFS_FS_LOG "fs_log"
#define DVS_DEBUGFS_FS_LOG_SIZE "fs_log_size_kb"
#define DVS_DEBUGFS_FS_LOG_TIME "fs_log_time_min_secs"
#define DVS_DEBUGFS_SYNC_STATS "sync_stats"
#define DVS_DEBUGFS_ESTALE_STATS "estale_stats"
#define DVS_DEBUGFS_DROP_CACHES "drop_caches"
#define DVS_DEBUGFS_STATS_DIR "statistics"
#define DVS_DEBUGFS_CLIENT_TIMING "client_message_timings"
#define DVS_DEBUGFS_SERVER_TIMING "server_message_timings"

#define DVSIPC_SYSFS_DIR "dvsipc"
#define DVSIPC_SYSFS_CONFIG_TYPE "config-type"
#define DVSIPC_SYSFS_FAILOVER "failover"

#define DVSIPC_DEBUGFS_DIR "dvsipc"
#define DVSIPC_DEBUGFS_REQ "requests"
#define DVSIPC_DEBUGFS_LOG "log"
#define DVSIPC_DEBUGFS_LOG_SIZE "log_size_kb"

/* procfs open function data arg SLES12 workaround */
#include <linux/version.h>

#ifdef __KERNEL__
#include <linux/seq_file.h>
#include "dvs/usisuper.h"
#include "common/dvsproc_test.h"
#include "common/dvsproc_stat.h"
#include "common/dvsproc_timing_stat.h"
#include "common/dvsproc_node.h"
extern int dvsproc_add_mountpoint(struct incore_upfs_super_block *icsb);
extern int dvsproc_remove_mountpoint(struct incore_upfs_super_block *icsb);
extern void dvsproc_mount_options_print(struct seq_file *m,
					struct incore_upfs_super_block *icsb);

/*
 * Atomically set *ptarget to max of *ptarget or value.
 */
static inline void atomic64_max(atomic64_t *ptarget, size_t value)
{
	/*
	 * Clever coding. What we really want here is atomic64_ifgtset(), that
	 * is, atomically perform "if (value > *ptarget) *ptarget = value".
	 * There is no such atomic function. So what this does is to atomically
	 * read the old value, then non-atomically compare it to the desired new
	 * value, and if value <= old_val already (courtesy of, perhaps, some
	 * other CPU/thread), we're done. If value > old_val, we try to set it
	 * atomically, using atomic64_cmpxchg, which atomically performs "if
	 * (old_val == *ptarget) *ptarget = value": that is, if no one else has
	 * changed it between our last test and the atomic change attempt, we
	 * can change it. Then we test again.
	 *
	 * Why not just use a spinlock? Because this is, oddly, much faster. It
	 * apparently has something to do with the fact that the atomic64
	 * routines use a "raw" spinlock.
	 *
	 * There is a corner-case: if you create a test program where one CPU is
	 * trying to record a large maximum value (e.g. 2^64-1), and all the
	 * other CPUs are trying to record a linearly-expanding set of values,
	 * this loop could continuously fail the cmpxchg, and get stuck in this
	 * loop forever, waiting for the other CPUs to stop putting pressure on
	 * the value.
	 *
	 * That can't really happen in DVS. This is used to record either
	 * elapsed jiffies or byte counts. Those values have to come from
	 * somewhere, and that somewhere involves running oodles of code,
	 * getting network packets, etc. That is an eternity of time during
	 * which the large value CPU can record its high-water mark.
	 */
	size_t old_val;
	while ((old_val = atomic64_read(ptarget)) < value) {
		// ?jcn? rewrite to use return value from this function
		atomic64_cmpxchg(ptarget, old_val, value);
	}
}

/*
 * Atomically set *ptarget to min of *ptarget or value.
 */
static inline void atomic64_min(atomic64_t *ptarget, size_t value)
{
	/*
	 * Same as above, except records a minimum value.
	 *
	 * Note that this uses an unsigned trick: unsigned -1 is maxint for the
	 * type. Thus, if the current recorded value is zero, the comparison is
	 * with maxint.
	 *
	 * We prohibit setting the minimum value to zero, which would have the
	 * effect of resetting the minimum counter.
	 */
	size_t old_val;
	if (value) {
		while ((old_val = atomic64_read(ptarget)) - 1 >= value) {
			// ?jcn? rewrite to use return value from this function
			atomic64_cmpxchg(ptarget, old_val, value);
		}
	}
}

#endif

/*
 * Structure representing any quiesced directories
 * on a DVS server. When a user writes to
 * /proc/fs/dvs/quiesce one of these structures is created
 * and added to a list.
 */
struct quiesced_dir {
	char *dir;
	int dir_len;
	/* This struct is on the list of quiesced dirs */
	struct list_head quiesced_dirs_lh;
	/* List of quiesced remote refs that hang off of this struct */
	struct list_head quiesced_rr_list;
};

struct mount_hash_entry {
	struct list_head list;
	void *sb;
	uint64_t mount_path_hash;
};

#endif /* __USIDVSSYS_H__ */
