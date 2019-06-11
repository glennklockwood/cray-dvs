/*
 * Copyright 2013-2014, 2016-2017 Cray Inc. All Rights Reserved.
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

#ifndef SYNC_H
#define SYNC_H

#include "common/kernel/usiipc.h"
#include "dvs/kernel/usifile.h"

struct inode_hashlist {
	rwlock_t lock;
	struct list_head inode_list;
};

struct inode_ref {
	spinlock_t lock;
	struct list_head inode_list;
	struct list_head rr_list;
	struct inode_hashlist *hashentry;
	struct remote_ref *sync_rr;
	unsigned long ino;
	unsigned long last_write;
	unsigned long last_sync;
};

struct fsync_thread_info {
	struct semaphore sema;
	unsigned int num;
	volatile unsigned int run;
	struct task_struct *task;
};

struct ssi_server_info {
	struct list_head list;
	struct list_head rf_list;
	spinlock_t lock;
	long sync;
	atomic_t open_files;
	int node;
	int flags;
};

struct sync_proc_ops {
	unsigned int *(*sync_period_get)(void);
	unsigned int *(*sync_timeout_get)(void);
	unsigned int *(*sync_threads_get)(void);
	void (*sync_stats_print)(struct seq_file *m);
	int (*sync_stats_control)(unsigned int control);
	int (*sync_period_update)(unsigned int period);
	int (*sync_timeout_update)(unsigned int timeout);
	int (*sync_threads_update)(unsigned int threads);
};

extern atomic64_t closing_time;
extern atomic64_t closing_syncs;
extern unsigned int sync_period_secs;
extern int sync_proc_register(struct sync_proc_ops *ops);
extern int sync_proc_unregister(struct sync_proc_ops *ops);

int sync_init(void);
void sync_exit(void);
int sync_add_inode_ref(struct remote_ref *rr);
void sync_remove_inode_ref(struct remote_ref *rr);
void sync_server_data_written(struct remote_ref *rr);
void sync_client_sync_update(long delta, long start, struct remote_file *rf);
void sync_server_bulk_update(unsigned long *inodes, unsigned long *sync_times,
			     int size);
int fsync_inode_ref(struct inode_ref *ir, struct remote_ref *rr);
int sync_is_inode_dirty(struct remote_ref *rr);
extern void sync_server_enable_sync(void);
extern void sync_client_data_written(struct remote_file *rf);
extern int sync_client_add_server(int node, int flags,
				  struct incore_upfs_super_block *icsb);
extern int sync_client_check_dirty(int node, struct file *fp);

#ifdef SYNC_DEBUG
#define SYNC_LOG(args...) DVS_LOG(args)
#else
#define SYNC_LOG(args...)                                                      \
	do {                                                                   \
	} while (0)
#endif

#define SYNC_SERVER_NOSYNC 0x01
#define SYNC_SERVER_DOWN 0x02

#define SYNC_VERIFY_PATH "/"
#define ALL_SERVERS -1
#define SYNC_MAX_FSYNC_THREADS 32
#define SYNC_MAX_HASH_SIZE 4096

#define rf_inode(rf)                                                           \
	((rf && rf->finfo && rf->finfo->fp && file_inode(rf->finfo->fp)) ?     \
		 file_inode(rf->finfo->fp)->i_ino :                            \
		 -1)
#endif
