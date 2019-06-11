/*
 * Copyright 2009-2010, 2013, 2015-2016 Cray Inc. All Rights Reserved.
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

#ifndef __DVSSYS_STAT_H__
#define __DVSSYS_STAT_H__

#ifdef __KERNEL__
#include <linux/seq_file.h>
#include "dvs/usifile.h"
#include "dvs/vfsops.h"

/*
 * Magic number for identifying stats memory block.
 */
#define DVSSYS_STAT_MAGIC ((unsigned long)"DVSSTATS")

/*
 * Stats current version number.
 */
#define DVSSYS_STAT_VERSION 2

/*
 * Output format
 */
#define DVSSYS_STAT_FMT_LEGACY 0
#define DVSSYS_STAT_FMT_HELP 1
#define DVSSYS_STAT_FMT_FLAT 2
#define DVSSYS_STAT_FMT_JSON 3

#define DVSSYS_STAT_FFLG_VERBOSE (1 << 0)
#define DVSSYS_STAT_FFLG_PRETTY (1 << 1)
#define DVSSYS_STAT_FFLG_TEST (1 << 2)

/*
 * sequential list of statistic identifier for 'type' argument to
 * dvsdebug_stat_update().
 */
#define DVSSYS_STAT_REQ 1
#define DVSSYS_STAT_IO 2
#define DVSSYS_STAT_IPC_REQUEST 3
#define DVSSYS_STAT_IPC_REQUEST_ASYNC 4
#define DVSSYS_STAT_IPC_REPLY 5
#define DVSSYS_STAT_OPEN_FILES 6
#define DVSSYS_STAT_OPER 7
#define DVSSYS_STAT_OPER_TIME 8
#define DVSSYS_STAT_REQP 9
#define DVSSYS_STAT_REQP_TIME 10
#define DVSSYS_STAT_CLIENT_LEN 11
#define DVSSYS_STAT_CLIENT_OFF 12
#define DVSSYS_STAT_CREATE 13
#define DVSSYS_STAT_DELETE 14

/*
 * The 'tag' (3rd) argument to dvsdebug_stat_update(), for use with the
 * DVSSYS_STAT_CREATE and DVSSYS_STAT_DELETE stats.
 */
#define DVSSYS_STAT_TYPE_INODE 1
#define DVSSYS_STAT_TYPE_FILE 2
#define DVSSYS_STAT_TYPE_SYMLINK 3
#define DVSSYS_STAT_TYPE_DIRECTORY 4

/*
 * Specify bounds for 'tag' (3rd) argument to dvsdebug_stat_update().
 * This is specific to the statistic types above and may or may
 * not need to be defined depending on if this argument is used.
 *
 * Sizes of arrays for statistics on individual message/operation types
 *   REQ_COUNTERS  = DVS request message types
 *   REQP_COUNTERS = DVS request_message types
 *   OPER_COUNTERS = DVS file system operation types
 * For message/operation stats, type is passed as the 'tag' value
 * For other stats, 'tag' may have a different meaning (or none)
 */
#define DVSSYS_STAT_REQ_COUNTERS RQ_DVS_END_V1
#define DVSSYS_STAT_OPER_COUNTERS VFS_OP_END_V1
#define DVSSYS_STAT_REQP_COUNTERS RQ_DVS_END_V1

/*
 * Actual statistics counters
 * Used for both per-mount and aggregate statistics
 *   read_min, read_max    legacy read length water-marks
 *   write_min, write_max  legacy write length water-marks
 *   request[type][2]      legacy IPC requests/replies sent
 *   requestp[type][4]	   legacy IPC requests/replies received
 *   vfsop[type][4]        legacy FS operations
 *   ipc_request[2]	   legacy IPC requests
 *   ipc_request_async[2]  legacy IPC async requests
 *   ipc_reply[2]	   legacy IPC replies
 * 			   [0] = success count, [1] = failure count
 *      		   [2] = last duration, [3] = max duration
 *   open_files		   legacy number of files currently open
 *   inodes_created	   legacy total inodes created
 *   inodes_deleted	   legacy total inodes deleted
 *   user_read_stats[8]    user read statistics
 *   user_write_stats[8]   user write statistics
 *   page_read_stats[8]	   page read statistics
 *   page_write_stats[8]   page write statistics
 *      		   [0] = min, [1] = max,
 *      		   [2] = iops total, [3] = bytes total,
 *      		   [4] = iops rate total, [5] = bytes rate total
 *      		   [6] = jiffies at last sampling
 *      		   [7] = max offset
 *   files_created	   total files created
 *   files_deleted	   total files deleted
 *   links_created	   total symlinks created
 *   links_deleted	   total symlinks deleted
 *   dirs_created	   total directories created
 *   dirs_deleted	   total directories deleted
 */
struct dvsdebug_stat_counters {
	atomic64_t read_min, read_max;
	atomic64_t write_min, write_max;
	atomic64_t request[DVSSYS_STAT_REQ_COUNTERS][2];
	atomic64_t requestp[DVSSYS_STAT_REQ_COUNTERS][4];
	atomic64_t vfsops[VFS_OP_END_V1][4];
	atomic64_t ipc_request[2];
	atomic64_t ipc_request_async[2];
	atomic64_t ipc_reply[2];
	atomic64_t open_files;
	atomic64_t inodes_created;
	atomic64_t inodes_deleted;
	atomic64_t user_read_stats[8];
	atomic64_t user_write_stats[8];
	atomic64_t page_read_stats[8];
	atomic64_t page_write_stats[8];
	atomic64_t files_created;
	atomic64_t files_deleted;
	atomic64_t links_created;
	atomic64_t links_deleted;
	atomic64_t dirs_created;
	atomic64_t dirs_deleted;
};

/*
 * Statistics structure
 * mountpoint_id
 *   monotonic integer, -1 for aggregate stats
 *   will roll over after 2^32 mounts => not guaranteed unique
 *   used only for display purposes
 * version
 *   used on output to version it
 * control
 *   0 = statistics disabled, 1 = statistics enabled
 * format
 *   DVSSYS_STAT_FMT_* value for output format
 * fflags
 *   DVSSYS_STAT_FFLG_* flags
 *
 * stats_entry
 *   proc_create_data() return value, handle for Linux proc_*()
 *
 * counters
 *   statistics counters
 */
struct dvsdebug_stat {
	uint64_t magic; // do not move this field, EVER!
	uint64_t version; // do not move this field, EVER!
	unsigned int control;
	unsigned int format;
	unsigned int fflags;
	int mountpoint_id;
	struct dentry *mount_entry;
	struct dentry *mount_dir;
	struct dentry *stats_entry;
	struct dentry *openfile_entry;
	struct dentry *nodenames_entry;
	struct dentry *drop_caches_entry;
	struct dvsdebug_stat_counters counters;
};

extern void dvsdebug_stat_update(struct dvsdebug_stat *, unsigned int,
				 unsigned int, ssize_t);
extern void dvsdebug_stat_print(struct seq_file *, struct dvsdebug_stat *);
extern int dvsdebug_stat_set_control(struct dvsdebug_stat *, char *);
extern void dvsdebug_stat_init(struct dvsdebug_stat *, int);

extern struct dvsdebug_stat aggregate_stats;
#endif

#endif /* __DVSSYS_STAT_H__ */
