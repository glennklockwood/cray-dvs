/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2017 Cray Inc. All Rights Reserved.
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
 * Support for the /proc/sys/fs/dvs and /proc/fs/dvs namespace.
 * Manages the parsing of the /etc/dvs/node-map file.
 * Manages creation of global node_map structure.
 */

#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <asm/uaccess.h>

#include "common/ssi_proc.h"
#include "common/ssi_sysctl.h"
#include "common/kernel/usiipc.h"
#include "dvs/kernel/usifile.h"
#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"

LIST_HEAD(dvs_super_blocks);
EXPORT_SYMBOL(dvs_super_blocks);
struct semaphore dvs_super_blocks_sema;
EXPORT_SYMBOL(dvs_super_blocks_sema);

void (*dvs_close_quiesced_files_func)(struct quiesced_dir *) = NULL;
EXPORT_SYMBOL(dvs_close_quiesced_files_func);
void (*dvs_rr_ref_put_func)(struct remote_ref *) = NULL;
EXPORT_SYMBOL(dvs_rr_ref_put_func);

/* List of quiesced directories */
LIST_HEAD(quiesced_dirs);
EXPORT_SYMBOL(quiesced_dirs);
/* Semaphore protecting quiesce operations */
DECLARE_RWSEM(quiesce_barrier_rwsem);
EXPORT_SYMBOL(quiesce_barrier_rwsem);

atomic_t ssiproc_mounts = ATOMIC_INIT(-1);
int ssiproc_max_nodes = 0;
int usi_node_addr = 0;
unsigned long dvs_debug_mask = 0UL;
ssize_t max_transport_msg_size;
int max_transport_msg_pages;
int wb_threshold_pages;

/* ESTALE variables needed by /proc files */
unsigned int estale_max_retry = ESTALE_MAX_RETRY;
unsigned int estale_timeout_secs = ESTALE_TIMEOUT_SECS;
struct estale_stats global_estale_stats;

#ifdef CONFIG_CRAY_TRACE
int dvs_trace_idx = CRAYTRACE_BUF_UTRACE;
int dvs_trace_slots = 4096;
#endif

uint dvs_log_size_kb = DVS_LOG_SIZE_KB;
uint dvs_request_log_size_kb = DVS_RQ_LOG_SIZE_KB;
uint dvs_request_log_min_time_secs = DVS_RQ_LOG_MIN_TIME_SECS;
uint dvs_request_log_enabled = 1;
uint dvs_fs_log_size_kb = DVS_FS_LOG_SIZE_KB;
uint dvs_fs_log_min_time_secs = DVS_FS_LOG_MIN_TIME_SECS;
uint dvs_fs_log_enabled = 1;

module_param(dvs_log_size_kb, uint, 0444);
MODULE_PARM_DESC(dvs_log_size_kb, "size of the DVS log buffer in KB");
module_param(dvs_request_log_size_kb, uint, 0444);
MODULE_PARM_DESC(dvs_request_log_size_kb, "size of the DVS request log buffer in KB");
module_param(dvs_request_log_min_time_secs, uint, 0444);
MODULE_PARM_DESC(dvs_request_log_min_time_secs, "minimum amount of time in seconds required to log request info");
module_param(dvs_request_log_enabled, uint, 0444);
MODULE_PARM_DESC(dvs_request_log_enabled, "whether DVS request logging is enabled");
module_param(dvs_fs_log_size_kb, uint, 0444);
MODULE_PARM_DESC(dvs_fs_log_size_kb, "size of the DVS fs log buffer in KB");
module_param(dvs_fs_log_min_time_secs, uint, 0444);
MODULE_PARM_DESC(dvs_fs_log_min_time_secs, "minimum amount of time in seconds required to log fs info");
module_param(dvs_fs_log_enabled, uint, 0444);
MODULE_PARM_DESC(dvs_fs_log_enabled, "whether DVS fs logging is enabled");
module_param(ssiproc_max_nodes, int, 0644);
module_param(dvs_debug_mask, ulong, 0644);
#ifdef CONFIG_CRAY_TRACE
module_param(dvs_trace_slots, int, 0644);
#endif
module_param(estale_max_retry, uint, 0444);
module_param(estale_timeout_secs, uint, 0444);

#define SSIPROC_MAX_USER_INPUT 1024*1024

static struct proc_dir_entry	*ssiproc_dir; 
static struct proc_dir_entry	*ssiproc_mounts_dir; 
static struct sync_proc_ops	*sync_ops = NULL;

struct ssi_node_map *node_map;
struct rw_semaphore ssiproc_map_sem;

static void ssiproc_free_node_map(void);
static int ssiproc_ssimap_open(struct inode *, struct file *);
static ssize_t ssiproc_ssimap_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_ssimap_release(struct inode *, struct file *);

static int ssiproc_common_release(struct inode *, struct file *);
static int ssiproc_mn_open(struct inode *, struct file *);
static int ssiproc_log_open(struct inode *, struct file *);
static int ssiproc_log_size_open(struct inode *, struct file *);
static int ssiproc_rq_log_open(struct inode *, struct file *);
static int ssiproc_rq_log_size_open(struct inode *, struct file *);
static int ssiproc_rq_log_time_open(struct inode *, struct file *);
static int ssiproc_fs_log_open(struct inode *, struct file *);
static int ssiproc_fs_log_size_open(struct inode *, struct file *);
static int ssiproc_fs_log_time_open(struct inode *, struct file *);
static int ssiproc_debug_open(struct inode *, struct file *);
static ssize_t ssiproc_debug_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_stats_open(struct inode *, struct file *);
static ssize_t ssiproc_stats_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_rq_log_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_fs_log_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_log_size_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_rq_log_size_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_rq_log_time_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_fs_log_size_write(struct file *, const char *, size_t, loff_t *);
static ssize_t ssiproc_fs_log_time_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_mount_info_open(struct inode *, struct file *);
static int ssiproc_openfile_info_open(struct inode *, struct file *);
static int ssiproc_nodenames_open(struct inode *, struct file *);

static void * ssiproc_ssimap_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_ssimap_seq_next(struct seq_file *, void *, loff_t *);
static void ssiproc_ssimap_seq_stop(struct seq_file *, void *);
static int ssiproc_ssimap_seq_show(struct seq_file *, void *);

static void * ssiproc_log_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_log_size_seq_start(struct seq_file *, loff_t *);
static int ssiproc_log_seq_show(struct seq_file *, void *);
static int ssiproc_log_size_seq_show(struct seq_file *, void *);
static void * ssiproc_rq_log_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_rq_log_size_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_rq_log_time_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_fs_log_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_fs_log_size_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_fs_log_time_seq_start(struct seq_file *, loff_t *);
static int ssiproc_rq_log_seq_show(struct seq_file *, void *);
static int ssiproc_rq_log_size_seq_show(struct seq_file *, void *);
static int ssiproc_rq_log_time_seq_show(struct seq_file *, void *);
static int ssiproc_fs_log_seq_show(struct seq_file *, void *);
static int ssiproc_fs_log_size_seq_show(struct seq_file *, void *);
static int ssiproc_fs_log_time_seq_show(struct seq_file *, void *);
static void * ssiproc_common_seq_start(struct seq_file *, loff_t *);
static void * ssiproc_common_seq_next(struct seq_file *, void *, loff_t *);
static void ssiproc_common_seq_stop(struct seq_file *, void *);
static void * ssiproc_mn_seq_start(struct seq_file *, loff_t *);
static int ssiproc_mn_seq_show(struct seq_file *, void *);
static int ssiproc_debug_seq_show(struct seq_file *, void *);
static int ssiproc_stats_seq_show(struct seq_file *, void *);
static int ssiproc_mount_info_seq_show(struct seq_file *, void *);
static int ssiproc_openfile_info_seq_show(struct seq_file *, void *);
static int ssiproc_nodenames_seq_show(struct seq_file *, void *);
static void *ssiproc_quiesce_seq_start(struct seq_file *m, loff_t *pos);
static int ssiproc_quiesce_seq_show(struct seq_file *m, void *p);
static void *ssiproc_quiesce_seq_next(struct seq_file *m, void *p, loff_t *pos);
static void ssiproc_quiesce_seq_stop(struct seq_file *m, void *p);

static int ssiproc_sync_period_open(struct inode *, struct file *);
static ssize_t ssiproc_sync_period_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_sync_period_seq_show(struct seq_file *, void *);
static void * ssiproc_sync_period_seq_start(struct seq_file *, loff_t *);
static int ssiproc_sync_timeout_open(struct inode *, struct file *);
static ssize_t ssiproc_sync_timeout_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_sync_timeout_seq_show(struct seq_file *, void *);
static void * ssiproc_sync_timeout_seq_start(struct seq_file *, loff_t *);
static int ssiproc_sync_threads_open(struct inode *, struct file *);
static ssize_t ssiproc_sync_threads_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_sync_threads_seq_show(struct seq_file *, void *);
static void * ssiproc_sync_threads_seq_start(struct seq_file *, loff_t *);
static int ssiproc_sync_stats_open(struct inode *, struct file *);
static ssize_t ssiproc_sync_stats_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_sync_stats_seq_show(struct seq_file *, void *);
static void * ssiproc_sync_stats_seq_start(struct seq_file *, loff_t *);
static int ssiproc_estale_max_retry_open(struct inode *, struct file *);
static ssize_t ssiproc_estale_max_retry_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_estale_max_retry_seq_show(struct seq_file *, void *);
static void * ssiproc_estale_max_retry_seq_start(struct seq_file *, loff_t *);
static int ssiproc_estale_timeout_open(struct inode *, struct file *);
static ssize_t ssiproc_estale_timeout_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_estale_timeout_seq_show(struct seq_file *, void *);
static void * ssiproc_estale_timeout_seq_start(struct seq_file *, loff_t *);
static int ssiproc_estale_stats_open(struct inode *, struct file *);
static ssize_t ssiproc_estale_stats_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_estale_stats_seq_show(struct seq_file *, void *);
static void * ssiproc_estale_stats_seq_start(struct seq_file *, loff_t *);
static ssize_t ssiproc_drop_caches_read(struct file *fp, char *user_buffer, size_t count, loff_t *offset);
static ssize_t ssiproc_drop_caches_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_quiesce_open(struct inode *inode, struct file *file);

/*
 * seq_file ops vectors
 */
static struct seq_operations ssiproc_ssimap_ops = {
    	start:		ssiproc_ssimap_seq_start,
	next:		ssiproc_ssimap_seq_next,
	stop:		ssiproc_ssimap_seq_stop,
	show:		ssiproc_ssimap_seq_show,
};

static struct seq_operations ssiproc_maxnodes_ops = {
	start:		ssiproc_mn_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_mn_seq_show,
};

static struct seq_operations ssiproc_log_ops = {
	start:		ssiproc_log_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_log_seq_show,
};

static struct seq_operations ssiproc_log_size_ops = {
	start:		ssiproc_log_size_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_log_size_seq_show,
};

static struct seq_operations ssiproc_rq_log_ops = {
	start:		ssiproc_rq_log_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_rq_log_seq_show,
};

static struct seq_operations ssiproc_rq_log_size_ops = {
	start:		ssiproc_rq_log_size_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_rq_log_size_seq_show,
};

static struct seq_operations ssiproc_rq_log_time_ops = {
	start:		ssiproc_rq_log_time_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_rq_log_time_seq_show,
};

static struct seq_operations ssiproc_fs_log_ops = {
	start:		ssiproc_fs_log_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_fs_log_seq_show,
};

static struct seq_operations ssiproc_fs_log_size_ops = {
	start:		ssiproc_fs_log_size_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_fs_log_size_seq_show,
};

static struct seq_operations ssiproc_fs_log_time_ops = {
	start:		ssiproc_fs_log_time_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_fs_log_time_seq_show,
};

static struct seq_operations ssiproc_sync_period_ops = {
	start:		ssiproc_sync_period_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_sync_period_seq_show,
};

static struct seq_operations ssiproc_sync_timeout_ops = {
	start:		ssiproc_sync_timeout_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_sync_timeout_seq_show,
};

static struct seq_operations ssiproc_sync_threads_ops = {
	start:		ssiproc_sync_threads_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_sync_threads_seq_show,
};

static struct seq_operations ssiproc_sync_stats_ops = {
	start:		ssiproc_sync_stats_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_sync_stats_seq_show,
};

static struct seq_operations ssiproc_stats_ops = {
	start:		ssiproc_common_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_stats_seq_show,
};

static struct seq_operations ssiproc_mount_info_ops = {
	start:		ssiproc_common_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_mount_info_seq_show,
};

static struct seq_operations ssiproc_openfile_info_ops = {
	start:		ssiproc_common_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_openfile_info_seq_show,
};

static struct seq_operations ssiproc_nodenames_ops = {
	start:		ssiproc_common_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_nodenames_seq_show,
};

static struct seq_operations ssiproc_estale_max_retry_ops = {
	start:		ssiproc_estale_max_retry_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_estale_max_retry_seq_show,
};

static struct seq_operations ssiproc_estale_timeout_ops = {
	start:		ssiproc_estale_timeout_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_estale_timeout_seq_show,
};

static struct seq_operations ssiproc_quiesce_seq_ops = {
	start:		ssiproc_quiesce_seq_start,
	next:		ssiproc_quiesce_seq_next,
	stop:		ssiproc_quiesce_seq_stop,
	show:		ssiproc_quiesce_seq_show,
};

/*
 * Allocate and populate a quiesced directory
 */
struct quiesced_dir *create_qdir(char *dir) {
	int len;
	char *dir_copy = NULL;
	struct quiesced_dir *qdir = NULL;

	if (dir == NULL)
		return ERR_PTR(-EINVAL);

	len = strlen(dir);
	if ((dir_copy = kmalloc_ssi(len + 2, GFP_KERNEL)) == NULL)
		return ERR_PTR(-ENOMEM);
	if ((qdir = kmalloc_ssi(sizeof(struct quiesced_dir), GFP_KERNEL)) == NULL) {
		kfree_ssi(dir_copy);
		return ERR_PTR(-ENOMEM);
	}
	/* Make sure the directory ends in a / */
	strncpy(dir_copy, dir, len + 1);
	if (dir[len-1] != '/') {
		strcat(dir_copy, "/");
	}

	INIT_LIST_HEAD(&qdir->quiesced_dirs_lh);
	INIT_LIST_HEAD(&qdir->quiesced_rr_list);
	qdir->dir_len = len;
	qdir->dir = dir_copy;
	return qdir;
}

/*
 * Excise and deallocate and quiesced directory
 */
void destroy_qdir(struct quiesced_dir *qdir) {
	struct remote_ref *rr, *rr_tmp;

	if (dvs_rr_ref_put_func == NULL)
		printk(KERN_ERR "DVS: dvs_rr_ref_put_func is NULL!\n");

	/* rr_ref_put all remaining remote refs */
	list_for_each_entry_safe(rr, rr_tmp, &qdir->quiesced_rr_list, quiesced_lh) {
		list_del_init(&rr->quiesced_lh);
		KDEBUG_QSC(0, "Doing rr_ref_put for remote ref %p from client %s\n",
			rr, SSI_NODE_NAME(rr->node));
		if (dvs_rr_ref_put_func)
			dvs_rr_ref_put_func(rr);
	}
	kfree_ssi(qdir->dir);
	kfree_ssi(qdir);
}

int do_dir_quiesce(char *quiesce_dir) {
	struct quiesced_dir *qdir, *new_qdir;

	/* No one has linked this function! */
	if (dvs_close_quiesced_files_func == NULL) {
		printk(KERN_ERR "DVS: dvs_close_quiesced_files_func is NULL!");
		return -EINVAL;
	}

	new_qdir = create_qdir(quiesce_dir);
	if (IS_ERR(new_qdir))
		return PTR_ERR(new_qdir);

	down_read(&quiesce_barrier_rwsem);
	/* Check for duplicates */
	list_for_each_entry(qdir, &quiesced_dirs, quiesced_dirs_lh) {
		if (!strcmp(qdir->dir, new_qdir->dir)) {
			up_read(&quiesce_barrier_rwsem);
			kfree_ssi(new_qdir);
			printk("DVS: Could not quiesce %s: Directory is "
				"already quiesced\n", quiesce_dir);
			return 0;
		}
	}
	up_read(&quiesce_barrier_rwsem);

	printk("DVS: Quiescing directory %s. Waiting for outstanding requests "
		"to finish before continuing.\n", quiesce_dir);
	down_write(&quiesce_barrier_rwsem);
	printk("DVS: All outstanding requests finished. Continuing with quiesce.\n");

	/*
	 * Add struct to the list of quiesced dirs. This will stop
	 * incoming requests for the path from proceeding past
	 * do_usifile. dvs_close_all_quiesced_files will deal with
	 * any open files.
	 */
	list_add_tail(&new_qdir->quiesced_dirs_lh, &quiesced_dirs);
	/* Walk all open files and close any in the quiesced directory */
	dvs_close_quiesced_files_func(new_qdir);
	up_write(&quiesce_barrier_rwsem);
	return 0;
}

int do_dir_unquiesce(char *given_dir) {

	int len;
	char *quiesce_dir = given_dir;
	struct quiesced_dir *qdir, *qdir_tmp, *rdir = NULL;

	len = strlen(given_dir);

	/* Add a trailing slash if not given */
	if (given_dir[len-1] != '/') {
		if ((quiesce_dir = kmalloc_ssi(len + 2, GFP_KERNEL)) == NULL)
			return -ENOMEM;
		snprintf(quiesce_dir, len + 2, "%s/", given_dir);
	}

	/* Don't hold quiesce_barrier_rwsem write lock to just read the list */
	down_read(&quiesce_barrier_rwsem);
	list_for_each_entry_safe(qdir, qdir_tmp, &quiesced_dirs, quiesced_dirs_lh) {
		if (!strcmp(qdir->dir, quiesce_dir)) {
			rdir = qdir;
			break;
		}
	}
	up_read(&quiesce_barrier_rwsem);

	if (rdir == NULL)
		goto do_dir_unquiesce_out;

	/*
	 * If we're pretty sure that a matching quiesced directory exists, grab
	 * the big-hammer write lock and start unquiescing.
	 */
	rdir = NULL;
	down_write(&quiesce_barrier_rwsem);
	list_for_each_entry_safe(qdir, qdir_tmp, &quiesced_dirs, quiesced_dirs_lh) {
		if (!strcmp(qdir->dir, quiesce_dir)) {
			rdir = qdir;
			list_del(&qdir->quiesced_dirs_lh);
			break;
		}
	}

	/* If rdir is NULL someone else has unquiesced it out from under us */
	if (rdir == NULL) {
		up_write(&quiesce_barrier_rwsem);
		goto do_dir_unquiesce_out;
	}

	printk("DVS: Unquiescing directory %s\n", quiesce_dir);
	destroy_qdir(rdir);
	printk("DVS: Unquiesce of %s finished\n", quiesce_dir);
	up_write(&quiesce_barrier_rwsem);

do_dir_unquiesce_out:
	if (quiesce_dir != given_dir)
		kfree_ssi(quiesce_dir);
	return 0;
}

static int
ssiproc_quiesce_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &ssiproc_quiesce_seq_ops);
}

static void *
ssiproc_quiesce_seq_start(struct seq_file *m, loff_t *pos)
{
	down_read(&quiesce_barrier_rwsem);
	if (*pos > 0 || list_is_last(&quiesced_dirs, &quiesced_dirs)) {
		return NULL;
	}
        return list_first_entry(&quiesced_dirs, struct quiesced_dir, quiesced_dirs_lh);
}

static int
ssiproc_quiesce_seq_show(struct seq_file *m, void *p)
{
	struct quiesced_dir *qdir = p;
	seq_printf(m, "%s\n", qdir->dir);
        return 0;
}

#ifndef list_next_entry
/* list_next_entry not defined in SLES 11 */
#define list_next_entry(pos, member) \
        list_entry(pos->member.next, typeof(*pos), member)
#endif

static void *
ssiproc_quiesce_seq_next(struct seq_file *m, void *p, loff_t *pos) {
        struct quiesced_dir *qdir = p;
        if (list_is_last(&qdir->quiesced_dirs_lh, &quiesced_dirs)) {
                return NULL;
        }
        *pos += 1;
        return list_next_entry(qdir, quiesced_dirs_lh);
}

static void
ssiproc_quiesce_seq_stop(struct seq_file *m, void *p) {
	up_read(&quiesce_barrier_rwsem);
}

static ssize_t ssiproc_quiesce_write(struct file *fp, const char *buffer, size_t count, loff_t *off) {

	int ret = 0;
	char *input = NULL;
	char *dir;

	if ((input = kmalloc_ssi(count + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	if (copy_from_user(input, buffer, count)) {
		kfree_ssi(input);
		return -EFAULT;
	}

	input[count] = '\0';
	if (input[count-1] == '\n')
		input[count-1] = '\0';

	if ((dir = strchr(input, ' ')) == NULL) {
		printk("DVS: Quiesce command format '%s' not valid\n", input);
		kfree_ssi(input);
		return -EFAULT;
	}
	dir++;

	if (!strncasecmp("quiesce ", input, 8)) {
		ret = do_dir_quiesce(dir);
	} else if (!strncasecmp("unquiesce ", input, 10)) {
		ret = do_dir_unquiesce(dir);
	} else {
		printk("DVS: Quiesce command format '%s' not valid\n", input);
		ret = -EINVAL;
	}

	kfree_ssi(input);

	if (!ret)
		return count;
	return ret;
}

static struct file_operations ssiproc_quiesce_operations = {
        open:           ssiproc_quiesce_open,
        read:           seq_read,
        write:          ssiproc_quiesce_write,
        release:        ssiproc_common_release,
};

static ssize_t ssiproc_quiesce_write(struct file *, const char *, size_t , loff_t *);

static struct seq_operations ssiproc_estale_stats_ops = {
	start:		ssiproc_estale_stats_seq_start,
	next:		ssiproc_common_seq_next,
	stop:		ssiproc_common_seq_stop,
	show:		ssiproc_estale_stats_seq_show,
};

static struct file_operations ssiproc_ssimap_operations = {
    	open:		ssiproc_ssimap_open,
	read:		seq_read,
	write:		ssiproc_ssimap_write,
	llseek:		seq_lseek,
	release:	ssiproc_ssimap_release,
};

static struct file_operations ssiproc_maxnodes_operations= {
	open:		ssiproc_mn_open,
	read:		seq_read,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_debug_operations= {
	open:		ssiproc_debug_open,
	read:		seq_read,
	write:		ssiproc_debug_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_log_operations= {
	open:		ssiproc_log_open,
	read:		seq_read,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_log_size_operations= {
	open:		ssiproc_log_size_open,
	read:		seq_read,
	write:		ssiproc_log_size_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_rq_log_operations= {
	open:		ssiproc_rq_log_open,
	read:		seq_read,
	write:		ssiproc_rq_log_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_rq_log_size_operations= {
	open:		ssiproc_rq_log_size_open,
	read:		seq_read,
	write:		ssiproc_rq_log_size_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_rq_log_time_operations= {
	open:		ssiproc_rq_log_time_open,
	read:		seq_read,
	write:		ssiproc_rq_log_time_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_fs_log_operations= {
	open:		ssiproc_fs_log_open,
	read:		seq_read,
	write:		ssiproc_fs_log_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_fs_log_size_operations= {
	open:		ssiproc_fs_log_size_open,
	read:		seq_read,
	write:		ssiproc_fs_log_size_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_fs_log_time_operations= {
	open:		ssiproc_fs_log_time_open,
	read:		seq_read,
	write:		ssiproc_fs_log_time_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_sync_period_operations= {
	open:		ssiproc_sync_period_open,
	read:		seq_read,
	write:		ssiproc_sync_period_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_sync_timeout_operations= {
	open:		ssiproc_sync_timeout_open,
	read:		seq_read,
	write:		ssiproc_sync_timeout_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_sync_threads_operations= {
	open:		ssiproc_sync_threads_open,
	read:		seq_read,
	write:		ssiproc_sync_threads_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_sync_stats_operations= {
	open:		ssiproc_sync_stats_open,
	read:		seq_read,
	write:		ssiproc_sync_stats_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_stats_operations= {
	open:		ssiproc_stats_open,
	read:		seq_read,
	write:		ssiproc_stats_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_mount_info_operations= {
	open:		ssiproc_mount_info_open,
	read:		seq_read,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_openfile_info_operations= {
	open:		ssiproc_openfile_info_open,
	read:		seq_read,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_nodenames_operations= {
	open:		ssiproc_nodenames_open,
	read:		seq_read,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_estale_max_retry_operations= {
	open:		ssiproc_estale_max_retry_open,
	read:		seq_read,
	write:		ssiproc_estale_max_retry_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_estale_timeout_operations= {
	open:		ssiproc_estale_timeout_open,
	read:		seq_read,
	write:		ssiproc_estale_timeout_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_estale_stats_operations= {
	open:		ssiproc_estale_stats_open,
	read:		seq_read,
	write:		ssiproc_estale_stats_write,
	release:	ssiproc_common_release,
};

static struct file_operations ssiproc_drop_caches_operations = {
	read:		ssiproc_drop_caches_read,
	write:		ssiproc_drop_caches_write,
};

static struct ssiproc_info {
	int		flag;
	struct inode 	*ip;
	char		*buf;
} *winfop;

static int __init
ssiproc_init(void)
{
	struct proc_dir_entry	*ssiproc_ssimap = NULL;
	struct proc_dir_entry	*ssiproc_maxnodes = NULL;
	struct proc_dir_entry	*ssiproc_debug = NULL;
	struct proc_dir_entry	*ssiproc_stats = NULL;
	struct proc_dir_entry	*ssiproc_log = NULL;
	struct proc_dir_entry	*ssiproc_log_size = NULL;
	struct proc_dir_entry	*ssiproc_rq_log = NULL;
	struct proc_dir_entry	*ssiproc_rq_log_size = NULL;
	struct proc_dir_entry	*ssiproc_rq_log_time = NULL;
	struct proc_dir_entry	*ssiproc_fs_log = NULL;
	struct proc_dir_entry	*ssiproc_fs_log_size = NULL;
	struct proc_dir_entry	*ssiproc_fs_log_time = NULL;
	struct proc_dir_entry	*ssiproc_sync_period = NULL;
	struct proc_dir_entry	*ssiproc_sync_timeout = NULL;
	struct proc_dir_entry	*ssiproc_sync_threads = NULL;
	struct proc_dir_entry	*ssiproc_sync_stats = NULL;
	struct proc_dir_entry	*ssiproc_estale_max_retry = NULL;
	struct proc_dir_entry	*ssiproc_estale_timeout = NULL;
	struct proc_dir_entry	*ssiproc_estale_stats = NULL;
	struct proc_dir_entry	*ssiproc_drop_caches = NULL;
	struct proc_dir_entry	*ssiproc_quiesce = NULL;
    	int error;

	printk("DVS: Revision %s - Built: %s @ %s for lnet version %s\n",
		SVNREV, __DATE__, __TIME__, LNETVER);

	KDEBUG_INF(0, "DVS: %s: [%d]\n", __FUNCTION__, ssiproc_max_nodes);

	if (ssiproc_max_nodes == 0) {
		/* no point in doing anything if we don't have any nodes */
		error = -EINVAL;
		goto error;
	}

	/* set up the dvs log size file */
	if (dvs_log_init(LOG_DVS_LOG, dvs_log_size_kb, "DVS log") != 0) {
		printk(KERN_ERR "DVS: %s cannot init log\n", __FUNCTION__);
		error = -ENOMEM;
		goto error;
	}

	/* set up the rq log size file */
	if (dvs_log_init(LOG_RQ_LOG, dvs_request_log_size_kb, "DVS rq log")
			 != 0) {
		printk(KERN_ERR "DVS: %s cannot init log\n", __FUNCTION__);
		error = -ENOMEM;
		goto error;
	}

	/* set up the fs log size file */
	if (dvs_log_init(LOG_FS_LOG, dvs_fs_log_size_kb, "DVS fs log") != 0) {
		printk(KERN_ERR "DVS: %s cannot init log\n", __FUNCTION__);
		error = -ENOMEM;
		goto error;
	}

	init_rwsem(&ssiproc_map_sem);

    	/* create directory */
    	if ((ssiproc_dir = proc_mkdir(SSIPROC_DIR, NULL)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s\n", 
			__FUNCTION__, SSIPROC_DIR);
		error = -ENOMEM;
		goto error;
	}

    	/* create mounts directory */
    	if ((ssiproc_mounts_dir = proc_mkdir(SSIPROC_MOUNTS_DIR,
					     ssiproc_dir)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_MOUNTS_DIR);
		error = -ENOMEM;
		goto error;
	}

	/* Create ssi-map entry */
	if ((ssiproc_ssimap = proc_create(SSIPROC_NODEFILE, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_ssimap_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_NODEFILE);
		error = -ENOMEM;
		goto error;
	}

	/* Create max-nodes entry */
	if ((ssiproc_maxnodes = proc_create(SSIPROC_MAX_NODES, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_maxnodes_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_MAX_NODES);
		error = -ENOMEM;
		goto error;
	}

	/* Create debug entry */
	if ((ssiproc_debug = proc_create(SSIPROC_DEBUG, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_debug_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_DEBUG);
		error = -ENOMEM;
		goto error;
	}

	/* Create log entry */
	if ((ssiproc_log = proc_create(SSIPROC_LOG, 
					S_IFREG | S_IRUSR, ssiproc_dir,
					&ssiproc_log_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_LOG);
		error = -ENOMEM;
		goto error;
	}

	/* Create rq log entry */
	if ((ssiproc_rq_log = proc_create(SSIPROC_RQ_LOG,
					  S_IFREG | S_IRUSR, ssiproc_dir,
					  &ssiproc_rq_log_operations)) ==
					  NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_RQ_LOG);
		error = -ENOMEM;
		goto error;
	}

	/* Create fs log entry */
	if ((ssiproc_fs_log = proc_create(SSIPROC_FS_LOG,
					  S_IFREG | S_IRUSR, ssiproc_dir,
					  &ssiproc_fs_log_operations)) ==
					  NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_FS_LOG);
		error = -ENOMEM;
		goto error;
	}

	/* Create stats entry */
	dvsproc_stat_init(&aggregate_stats, -1);

	if ((ssiproc_stats = proc_create_data(SSIPROC_STATS, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_stats_operations, &aggregate_stats)) == NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_STATS);
		error = -ENOMEM;
		goto error;
	}

	aggregate_stats.stats_entry = ssiproc_stats;

	/* Create log_size_kb entry */
	if ((ssiproc_log_size = proc_create(SSIPROC_LOG_SIZE, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_log_size_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_LOG_SIZE);
		error = -ENOMEM;
		goto error;
	}

	/* Create rq_log_size_kb entry */
	if ((ssiproc_rq_log_size = proc_create(SSIPROC_RQ_LOG_SIZE,
					       S_IFREG | S_IRUGO | S_IWUSR,
					       ssiproc_dir,
					       &ssiproc_rq_log_size_operations))
					       == NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_RQ_LOG_SIZE);
		error = -ENOMEM;
		goto error;
	}

	/* Create rq_log_min_time_sec entry */
	if ((ssiproc_rq_log_time = proc_create(SSIPROC_RQ_LOG_TIME,
					       S_IFREG | S_IRUGO | S_IWUSR,
					       ssiproc_dir,
					       &ssiproc_rq_log_time_operations))
					       == NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_RQ_LOG_TIME);
		error = -ENOMEM;
		goto error;
	}

	/* Create fs_log_size_kb entry */
	if ((ssiproc_fs_log_size = proc_create(SSIPROC_FS_LOG_SIZE,
					       S_IFREG | S_IRUGO | S_IWUSR,
					       ssiproc_dir,
					       &ssiproc_fs_log_size_operations))
					       == NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_FS_LOG_SIZE);
		error = -ENOMEM;
		goto error;
	}

	/* Create fs_log_min_time_sec entry */
	if ((ssiproc_fs_log_time = proc_create(SSIPROC_FS_LOG_TIME,
					       S_IFREG | S_IRUGO | S_IWUSR,
					       ssiproc_dir,
					       &ssiproc_fs_log_time_operations))
					       == NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_FS_LOG_TIME);
		error = -ENOMEM;
		goto error;
	}

	ssi_sysctl_register();

	node_map = NULL;

	/* Create sync period entry */
	if ((ssiproc_sync_period = proc_create(SSIPROC_SYNC_PERIOD, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_sync_period_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_SYNC_PERIOD);
		error = -ENOMEM;
		goto error;
	}

	/* Create sync timeout entry */
	if ((ssiproc_sync_timeout = proc_create(SSIPROC_SYNC_TIMEOUT, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_sync_timeout_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_SYNC_TIMEOUT);
		error = -ENOMEM;
		goto error;
	}

	/* Create sync threads entry */
	if ((ssiproc_sync_threads = proc_create(SSIPROC_SYNC_THREADS, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_sync_threads_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_SYNC_THREADS);
		error = -ENOMEM;
		goto error;
	}

	/* Create sync stats entry */
	if ((ssiproc_sync_stats = proc_create(SSIPROC_SYNC_STATS, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_sync_stats_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_SYNC_STATS);
		error = -ENOMEM;
		goto error;
	}

	/* Create ESTALE max retry entry */
	if ((ssiproc_estale_max_retry = proc_create(SSIPROC_ESTALE_MAX_RETRY, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_estale_max_retry_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_ESTALE_MAX_RETRY);
		error = -ENOMEM;
		goto error;
	}

	/* Create ESTALE timeout entry */
	if ((ssiproc_estale_timeout = proc_create(SSIPROC_ESTALE_TIMEOUT, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					 &ssiproc_estale_timeout_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_ESTALE_TIMEOUT);
		error = -ENOMEM;
		goto error;
	}

	/* Create ESTALE stats entry */
	if ((ssiproc_estale_stats = proc_create(SSIPROC_ESTALE_STATS, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_estale_stats_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_ESTALE_STATS);
		error = -ENOMEM;
		goto error;
	}

	/* Create drop_caches stats entry */
	if ((ssiproc_drop_caches = proc_create(SSIPROC_DROP_CACHES, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_drop_caches_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_ESTALE_STATS);
		error = -ENOMEM;
		goto error;
	}

	/* Create quiesce entry */
	if ((ssiproc_quiesce = proc_create(SSIPROC_QUIESCE,
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_quiesce_operations)) == NULL) {
		printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
				__FUNCTION__, SSIPROC_DIR, SSIPROC_ESTALE_STATS);
		error = -ENOMEM;
		goto error;
	}

	/* Create test entry -- NOOP in production*/
	dvsproc_test_init(ssiproc_dir);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	ssiproc_ssimap->uid = 0;
	ssiproc_maxnodes->uid = 0;
	ssiproc_debug->uid = 0;
	ssiproc_log->uid = 0;
	ssiproc_rq_log->uid = 0;
	ssiproc_fs_log->uid = 0;
	ssiproc_stats->uid = 0;
	ssiproc_log_size->uid = 0;
	ssiproc_rq_log_size->uid = 0;
	ssiproc_fs_log_size->uid = 0;
	ssiproc_sync_period->uid = 0;
	ssiproc_sync_timeout->uid = 0;
	ssiproc_sync_threads->uid = 0;
	ssiproc_sync_stats->uid = 0;
	ssiproc_estale_max_retry->uid = 0;
	ssiproc_estale_timeout->uid = 0;
	ssiproc_estale_stats->uid = 0;
#else
	proc_set_user(ssiproc_ssimap, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_maxnodes, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_debug, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_log, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_rq_log, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_fs_log, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_stats, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_log_size, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_rq_log_size, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_fs_log_size, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_sync_period, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_sync_timeout, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_sync_threads, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_sync_stats, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_estale_max_retry, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_estale_timeout, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(ssiproc_estale_stats, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

#ifdef CONFIG_CRAY_TRACE
        craytrace_create_buf("DVS", dvs_trace_slots, &dvs_trace_idx);
#endif

	KDEBUG_INF(0, "DVS: dvsproc module loaded\n");
	return (0);
error:
	dvsproc_test_exit(ssiproc_dir);	/* NOOP in production */
	if (ssiproc_estale_timeout)
		remove_proc_entry(SSIPROC_ESTALE_TIMEOUT, ssiproc_dir);
	if (ssiproc_estale_max_retry)
		remove_proc_entry(SSIPROC_ESTALE_MAX_RETRY, ssiproc_dir);
	if (ssiproc_sync_stats)
		remove_proc_entry(SSIPROC_SYNC_STATS, ssiproc_dir);
	if (ssiproc_sync_threads)
		remove_proc_entry(SSIPROC_SYNC_THREADS, ssiproc_dir);
	if (ssiproc_sync_timeout)
		remove_proc_entry(SSIPROC_SYNC_TIMEOUT, ssiproc_dir);
	if (ssiproc_sync_period)
		remove_proc_entry(SSIPROC_SYNC_PERIOD, ssiproc_dir);
	if (ssiproc_fs_log_time)
		remove_proc_entry(SSIPROC_FS_LOG_TIME, ssiproc_dir);
	if (ssiproc_fs_log_size)
		remove_proc_entry(SSIPROC_FS_LOG_SIZE, ssiproc_dir);
	if (ssiproc_rq_log_time)
		remove_proc_entry(SSIPROC_RQ_LOG_TIME, ssiproc_dir);
	if (ssiproc_rq_log_size)
		remove_proc_entry(SSIPROC_RQ_LOG_SIZE, ssiproc_dir);
	if (ssiproc_log_size)
		remove_proc_entry(SSIPROC_LOG_SIZE, ssiproc_dir);
	if (ssiproc_stats)
		remove_proc_entry(SSIPROC_STATS, ssiproc_dir);
	if (ssiproc_fs_log)
		remove_proc_entry(SSIPROC_FS_LOG, ssiproc_dir);
	if (ssiproc_rq_log)
		remove_proc_entry(SSIPROC_RQ_LOG, ssiproc_dir);
	if (ssiproc_log)
		remove_proc_entry(SSIPROC_LOG, ssiproc_dir);
	if (ssiproc_debug)
		remove_proc_entry(SSIPROC_DEBUG, ssiproc_dir);
	if (ssiproc_maxnodes)
		remove_proc_entry(SSIPROC_MAX_NODES, ssiproc_dir);
	if (ssiproc_ssimap)
		remove_proc_entry(SSIPROC_NODEFILE, ssiproc_dir);
	if (ssiproc_drop_caches)
		remove_proc_entry(SSIPROC_DROP_CACHES, ssiproc_dir);
	if (ssiproc_quiesce)
		remove_proc_entry(SSIPROC_QUIESCE, ssiproc_dir);
	if (ssiproc_mounts_dir)
		remove_proc_entry(SSIPROC_MOUNTS_DIR, ssiproc_dir);
	if (ssiproc_dir)
		remove_proc_entry(SSIPROC_DIR, NULL);
	return (error);

} /* ssiproc_init */

static void __exit 
ssiproc_exit(void)
{
	KDEBUG_INF(0, "DVS: %s: \n", __FUNCTION__);

	dvsproc_test_exit(ssiproc_dir);	/* NOOP in production */
	ssiproc_lock_node_map(SSIPROC_LOCK_WRITE);
	remove_proc_entry(SSIPROC_ESTALE_STATS, ssiproc_dir);
	remove_proc_entry(SSIPROC_ESTALE_TIMEOUT, ssiproc_dir);
	remove_proc_entry(SSIPROC_ESTALE_MAX_RETRY, ssiproc_dir);
	remove_proc_entry(SSIPROC_SYNC_STATS, ssiproc_dir);
	remove_proc_entry(SSIPROC_SYNC_THREADS, ssiproc_dir);
	remove_proc_entry(SSIPROC_SYNC_TIMEOUT, ssiproc_dir);
	remove_proc_entry(SSIPROC_SYNC_PERIOD, ssiproc_dir);
	remove_proc_entry(SSIPROC_RQ_LOG, ssiproc_dir);
	remove_proc_entry(SSIPROC_RQ_LOG_SIZE, ssiproc_dir);
	remove_proc_entry(SSIPROC_RQ_LOG_TIME, ssiproc_dir);
	remove_proc_entry(SSIPROC_FS_LOG, ssiproc_dir);
	remove_proc_entry(SSIPROC_FS_LOG_SIZE, ssiproc_dir);
	remove_proc_entry(SSIPROC_FS_LOG_TIME, ssiproc_dir);
	remove_proc_entry(SSIPROC_LOG, ssiproc_dir);
	remove_proc_entry(SSIPROC_LOG_SIZE, ssiproc_dir);
	remove_proc_entry(SSIPROC_STATS, ssiproc_dir);
	remove_proc_entry(SSIPROC_DEBUG, ssiproc_dir);
	remove_proc_entry(SSIPROC_MAX_NODES, ssiproc_dir);
	remove_proc_entry(SSIPROC_DROP_CACHES, ssiproc_dir);
	remove_proc_entry(SSIPROC_QUIESCE, ssiproc_dir);
	remove_proc_entry(SSIPROC_NODEFILE, ssiproc_dir);
	remove_proc_entry(SSIPROC_MOUNTS_DIR, ssiproc_dir);
	remove_proc_entry(SSIPROC_DIR, NULL);

    	if (node_map) {
	    	ssiproc_free_node_map();
	}
	ssiproc_unlock_node_map(SSIPROC_LOCK_WRITE);

	ssi_sysctl_unregister();

#ifdef CONFIG_CRAY_TRACE
	if (dvs_trace_idx != CRAYTRACE_BUF_UTRACE) {
		craytrace_destroy_buf(dvs_trace_idx);
	}
#endif

	dvs_log_exit(LOG_DVS_LOG);
	KDEBUG_INF(0, "DVS: dvsproc module unloaded\n");

} /* ssiproc_exit */

static int
ssiproc_ssimap_open(struct inode *inode, struct file *file)
{
    	return seq_open(file, &ssiproc_ssimap_ops);
} /* ssiproc_ssimap_open */

static int
ssiproc_common_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static int
ssiproc_mn_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_maxnodes_ops);
}

static int
ssiproc_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, &ssiproc_debug_seq_show, NULL);
}

static int
ssiproc_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_log_ops);
}

static int
ssiproc_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_log_size_ops);
}

static int
ssiproc_rq_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_rq_log_ops);
}

static int
ssiproc_rq_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_rq_log_size_ops);
}

static int
ssiproc_rq_log_time_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_rq_log_time_ops);
}

static int
ssiproc_fs_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_fs_log_ops);
}

static int
ssiproc_fs_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_fs_log_size_ops);
}

static int
ssiproc_fs_log_time_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_fs_log_time_ops);
}

static int
ssiproc_sync_period_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_sync_period_ops);
}

static int
ssiproc_sync_timeout_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_sync_timeout_ops);
}

static int
ssiproc_sync_threads_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_sync_threads_ops);
}

static int
ssiproc_estale_max_retry_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_estale_max_retry_ops);
}

static int
ssiproc_estale_timeout_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_estale_timeout_ops);
}

static int
ssiproc_estale_stats_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_estale_stats_ops);
}

static int
ssiproc_sync_stats_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ssiproc_sync_stats_ops);
}

/*
 * Print a human-readable version of the a given debug value
 * Example: 0xf would yield OFC,OFS,PNC,PNS
 */
static void debug_to_string(unsigned long debug_val, char *buff) {

	int i, len;

	buff[0] = '\0';

	if (debug_val == 0) {
		strcat(buff, "NONE");
		return;
	}

	for (i = 0; i < DVS_DEBUG_MAX; i++) {
		if (debug_val & dvs_debug_names[i].flag) {
			strcat(buff, dvs_debug_names[i].name);
			strcat(buff, ",");
		}
	}

	/* Remove the trailing comma, if present */
	if ((len = strlen(buff)) > 0)
		buff[len - 1] = '\0';
}

int valid_number(char *str) {

	int i, len;

	if (str == NULL)
		return 0;

	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (str[i] == 'x' && i == 1)
			continue;
		if (str[i] >= '0' && str[i] <= '9')
			continue;
		if (str[i] >= 'a' && str[i] <= 'f')
			continue;
		if (str[i] >= 'A' && str[i] <= 'F')
			continue;
		return 0;
	}
	return 1;
}

static ssize_t
ssiproc_debug_write(struct file *file, const char *buffer,
			size_t count, loff_t *offp)
{
	char *ptr, *tok;
	char str[64];
	char debug_str[64];
	int i;
	char *name;
	unsigned long turn_off = 0, flag;

	if (count >= sizeof(str)) {
		return -EINVAL;
	}

	memset(str, 0, sizeof(str));

	if (copy_from_user(str, buffer, count)) {
		return -EFAULT;
	}

	ptr = str;
	while ((tok = strsep(&ptr, " \t\n"))) {

		if (tok == NULL || strlen(tok) == 0)
			continue;

		/* Carat means 'negate this option' */
		turn_off = 0;
		if (tok[0] == '^') {
			turn_off = 1;
			tok++;
		}

		/* Iterate through the debug names and look for a match */
		for (i = 0; i < DVS_DEBUG_MAX; i++) {
			name = dvs_debug_names[i].name;
			flag = dvs_debug_names[i].flag;
			if (!strcasecmp(name, tok)) {
				if (turn_off)
					dvs_debug_mask &= ~flag;
				else
					dvs_debug_mask |= flag;
				break;
			}
		}

		/* String wasn't found, assume it's an integer debug value */
		if (i == DVS_DEBUG_MAX) {
			if (valid_number(tok))
				dvs_debug_mask = simple_strtoul(tok, NULL, 0);
			else
				printk(KERN_ERR "DVS: String %s is not a valid "
						"debug string\n", tok);
		}
	}

	debug_to_string(dvs_debug_mask, debug_str);

	printk(KERN_INFO "DVS: %s: dvs_debug_mask is 0x%lx (%s)\n",
		__FUNCTION__, dvs_debug_mask, debug_str);
	return count;
}

static int
ssiproc_stats_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &ssiproc_stats_ops);
	if (rc) return rc;

       	seq = file->private_data;
	seq->private = PDE_DATA(inode); /* set in dvsproc_add_mountpoint() */
	return 0;
}

static ssize_t 
ssiproc_stats_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	struct seq_file *seq = file->private_data;
	struct dvsproc_stat *stats = seq->private;
	int rtn;
	char str[128];

	if (count >= sizeof(str)) {
		return -EINVAL;
	}

	memset(str, 0, sizeof(str));
	if (copy_from_user(str, buffer, count)) {
		return -EFAULT;
	}

	rtn = dvsproc_stat_set_control(stats, str);
	return (rtn < 0) ? rtn : count;
}

static int
ssiproc_mount_info_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &ssiproc_mount_info_ops);
	if (rc) return rc;

       	seq = file->private_data;
	seq->private = PDE_DATA(inode); /* set in dvsproc_add_mountpoint() */
	return 0;

}

static int
ssiproc_openfile_info_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &ssiproc_openfile_info_ops);
	if (rc) return rc;

	seq = file->private_data;
	seq->private = PDE_DATA(inode); /* set in dvsproc_add_mountpoint() */
	return 0;
}

static int
ssiproc_nodenames_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &ssiproc_nodenames_ops);
	if (rc) return rc;

	seq = file->private_data;
	seq->private = PDE_DATA(inode); /* set in dvsproc_add_mountpoint() */
	return 0;
}


static void *
ssiproc_common_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)m->private); /* set in ssiproc_XXX_open() */
}


static void *
ssiproc_ssimap_seq_start(struct seq_file *m, loff_t *pos)
{
    	struct ssi_node_map *tnp;
	loff_t n = *pos;

	KDEBUG_INF(0, "DVS: %s: pos[%lld] n[%lld]\n",
		   __FUNCTION__, *pos, n);

	ssiproc_lock_node_map(SSIPROC_LOCK_READ);

	/* sanity check the position (logical node number) the user asked for */
	if (n >= ssiproc_max_nodes)
	    	return (NULL);

	tnp = &node_map[n];

	return ((void *)tnp);

} /* ssiproc_ssimap_seq_start */


static void *
ssiproc_ssimap_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
    	loff_t n = ++*pos;
	struct ssi_node_map *tnp = (struct ssi_node_map *)p;

	if (n >= ssiproc_max_nodes)
	    	return (NULL);

	tnp = (void *)&node_map[n];

	return (tnp);

} /*ssiproc_ssimap_seq_next */



static void
ssiproc_ssimap_seq_stop(struct seq_file *m, void *p)
{
	ssiproc_unlock_node_map(SSIPROC_LOCK_READ);
} /* siiproc_ssimap_seq_stop */



/*
 * N.B. Assumes that the ssiproc_map_sem write lock is held
 */
static void
ssiproc_free_node_map(void)
{
    	int i;
	struct ssi_node_map *mp;

	if (node_map == NULL)
	    	return;

	for (i = 0; i < ssiproc_max_nodes; i++) {
	    	mp = &node_map[i];

		if (mp == NULL) {
		    	/*
			 * We don't allow a sparse list.  But it does
			 * not hurt to be paranoid here and make sure that
			 * we are not leaking memory.
			 */
		    	continue;
		}

		if (mp->name) 
		    	kfree(mp->name);

		if (mp->tok)
		    	kfree(mp->tok);
	}

	vfree(node_map);

} /* ssiproc_free_node_map */


static int 
ssiproc_ssimap_seq_show(struct seq_file *m, void *p)
{
	struct ssi_node_map *mp = (struct ssi_node_map *)p;
	int i = (int)(mp - node_map);

	if ((mp == NULL) || (i >= ssiproc_max_nodes))
	    	return (0);

	if (mp->name) {
		seq_printf(m, "%5d %10s ", i, mp->name);

		if (mp->tok)
			seq_printf(m, "%20s", mp->tok);

		seq_putc(m, '\n');
	}

	return (0);

} /* ssiproc_ssimap_seq_show */


static void *
ssiproc_mn_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&ssiproc_max_nodes);
}

static void *
ssiproc_common_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
	return(NULL);
}

static void
ssiproc_common_seq_stop(struct seq_file *m, void *p)
{
	return;
}

static int
ssiproc_mn_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", ssiproc_max_nodes);

	return 0;
}

static void *
ssiproc_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return dvs_log_handle(LOG_DVS_LOG);
}

static void *
ssiproc_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_log_size_kb);
}

static void *
ssiproc_rq_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (!dvs_request_log_enabled)
		return (NULL);

	return dvs_log_handle(LOG_RQ_LOG);
}

static void *
ssiproc_rq_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_request_log_size_kb);
}

static void *
ssiproc_rq_log_time_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_request_log_min_time_secs);
}

static void *
ssiproc_fs_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (!dvs_fs_log_enabled)
		return (NULL);

	return dvs_log_handle(LOG_FS_LOG);
}

static void *
ssiproc_fs_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_fs_log_size_kb);
}

static void *
ssiproc_fs_log_time_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_fs_log_min_time_secs);
}

static void *
ssiproc_sync_period_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (sync_ops && sync_ops->sync_period_get)
		return ((void *)sync_ops->sync_period_get());
	else
		return (NULL);
}

static void *
ssiproc_sync_timeout_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (sync_ops && sync_ops->sync_timeout_get)
		return ((void *)sync_ops->sync_timeout_get());
	else
		return (NULL);
}

static void *
ssiproc_sync_threads_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (sync_ops && sync_ops->sync_threads_get)
		return ((void *)sync_ops->sync_threads_get());
	else
		return (NULL);
}

static void *
ssiproc_estale_max_retry_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&estale_max_retry);
}

static void *
ssiproc_estale_timeout_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&estale_timeout_secs);
}

static void *
ssiproc_estale_stats_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&global_estale_stats);
}

static void *
ssiproc_sync_stats_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)sync_ops);
}

static int
ssiproc_debug_seq_show(struct seq_file *m, void *p)
{
	char debug_str[64];
	debug_to_string(dvs_debug_mask, debug_str);
	seq_printf(m, "0x%lx (%s)\n", dvs_debug_mask, debug_str);
	return 0;
}

static int
ssiproc_log_seq_show(struct seq_file *m, void *p)
{
	return(dvs_log_print(LOG_DVS_LOG, m));
}

static int
ssiproc_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_DVS_LOG));
	return 0;
}

static int
ssiproc_rq_log_seq_show(struct seq_file *m, void *p)
{
	return(dvs_log_print(LOG_RQ_LOG, m));
}

static int
ssiproc_rq_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_RQ_LOG));
	return 0;
}

static int
ssiproc_rq_log_time_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_request_log_min_time_secs);
	return 0;
}

static int
ssiproc_fs_log_seq_show(struct seq_file *m, void *p)
{
	return(dvs_log_print(LOG_FS_LOG, m));
}

static int
ssiproc_fs_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_FS_LOG));
	return 0;
}

static int
ssiproc_fs_log_time_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_fs_log_min_time_secs);
	return 0;
}

static int
ssiproc_sync_period_seq_show(struct seq_file *m, void *p)
{
	if (!sync_ops || !sync_ops->sync_period_get)
		return -EINVAL;
	
	seq_printf(m, "%u\n", *(sync_ops->sync_period_get()));
	return 0;
}

static int
ssiproc_sync_timeout_seq_show(struct seq_file *m, void *p)
{
	if (!sync_ops || !sync_ops->sync_timeout_get)
		return -EINVAL;
	
	seq_printf(m, "%u\n", *(sync_ops->sync_timeout_get()));
	return 0;
}

static int
ssiproc_sync_threads_seq_show(struct seq_file *m, void *p)
{
	if (!sync_ops || !sync_ops->sync_threads_get)
		return -EINVAL;
	
	seq_printf(m, "%u\n", *(sync_ops->sync_threads_get()));
	return 0;
}

static int
ssiproc_estale_max_retry_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%u\n", estale_max_retry);
	return 0;
}

static int
ssiproc_estale_timeout_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%u\n", estale_timeout_secs);
	return 0;
}

static int
ssiproc_estale_stats_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "Failed ESTALE retries: %ld\n",
	           atomic64_read(&global_estale_stats.stats[ESTALE_RETRY_FAIL]));
	seq_printf(m, "Failed ESTALE failovers: %ld\n",
	           atomic64_read(&global_estale_stats.stats[ESTALE_FAILOVER_FAIL]));
	seq_printf(m, "Successful ESTALE retries: %ld\n",
	           atomic64_read(&global_estale_stats.stats[ESTALE_RETRY_PASS]));
	seq_printf(m, "Successful ESTALE failovers: %ld\n",
	           atomic64_read(&global_estale_stats.stats[ESTALE_FAILOVER_PASS]));

	return 0;
}

static int
ssiproc_sync_stats_seq_show(struct seq_file *m, void *p)
{
	if (!sync_ops || !sync_ops->sync_stats_print)
		return -EINVAL;
	
	sync_ops->sync_stats_print(m);
	return 0;
}

static int
ssiproc_stats_seq_show(struct seq_file *m, void *p)
{
	dvsproc_stat_print(m, (struct dvsproc_stat *)p);
	return 0;
}

static int
ssiproc_mount_info_seq_show(struct seq_file *m, void *p)
{
	struct incore_upfs_super_block *icsb = (struct incore_upfs_super_block *)p;
	struct super_block *sb = icsb->superblock;
	int i;

	seq_printf(m, "local-mount %s\n", icsb->prefix);
	seq_printf(m, "remote-path %s\n", icsb->remoteprefix);
	seq_printf(m, "options (%s",
		   sb ? (sb->s_flags & MS_RDONLY ? "ro" : "rw") : "?");
	dvsproc_mount_options_print(m, icsb);
	seq_printf(m, ")\n");

	/* print non-boot option data */

	seq_printf(m, "active_nodes");
	for (i = 0; i < icsb->data_servers_len; i++) {
		if (icsb->data_servers[i].up)
			seq_printf(m, " %s", SSI_NODE_NAME(icsb->data_servers[i].node_map_index));
	}
	seq_printf(m, "\n");

	seq_printf(m, "inactive_nodes");
	for (i = 0; i < icsb->data_servers_len; i++) {
		if (!icsb->data_servers[i].up)
			seq_printf(m, " %s", SSI_NODE_NAME(icsb->data_servers[i].node_map_index));
	}
	seq_printf(m, "\n");

	if (icsb->loadbalance)
		seq_printf(m, "loadbalance_node %s\n", SSI_NODE_NAME(icsb->loadbalance_node));

	for (i = 0; i < icsb->data_servers_len; i++) {
		if (icsb->data_servers[i].magic != -1)
			break;
	}
	seq_printf(m, "remote-magic 0x%lx\n", icsb->data_servers[i].magic);

	return 0;
}

static int
ssiproc_openfile_info_seq_show(struct seq_file *m, void *p)
{
	struct incore_upfs_super_block *icsb = (struct incore_upfs_super_block *)p;

	seq_printf(m, "open files:  %d\n", atomic_read(&icsb->open_dvs_files));

	return 0;
}

static int
ssiproc_nodenames_seq_show(struct seq_file *m, void *p)
{
	struct incore_upfs_super_block *icsb = (struct incore_upfs_super_block *)p;
	int i;

	for (i = 0; i < icsb->data_servers_len; i++) {
		if (i > 0)
			seq_printf(m, ":");
		seq_printf(m, "%s", node_map[icsb->data_servers[i].node_map_index].name);
	}

	seq_printf(m, "\n");

	return 0;
}

static void
dvsproc_rq_log_set_control(unsigned int control)
{
	if (!control) {
		dvs_request_log_enabled = 0;
	} else if (control & ~DVSPROC_RQ_LOG_CONTROL_VALID_MASK) {
		printk(KERN_INFO "DVS: unknown request log control %u\n",
		       control);
	} else {
		/* process the selected control bits */

		if (control & DVSPROC_RQ_LOG_CONTROL_RESET)
			dvs_log_clear(LOG_RQ_LOG);

		if (control & DVSPROC_RQ_LOG_CONTROL_ENABLE)
			dvs_request_log_enabled = 1;
	}
}

static ssize_t
ssiproc_rq_log_write(struct file *file, const char *buffer, size_t count,
		     loff_t *offp)
{
	char str[16];
	unsigned int control;

	if (count >= sizeof(str))
		return -EINVAL;

	memset(str, 0, sizeof(str));
	if (copy_from_user(str, buffer, count))
		return -EFAULT;

	control = simple_strtoul(str, NULL, 0);
	dvsproc_rq_log_set_control(control);

	return count;
}

static void
dvsproc_fs_log_set_control(unsigned int control)
{
	if (!control) {
		dvs_fs_log_enabled = 0;
	} else if (control & ~DVSPROC_FS_LOG_CONTROL_VALID_MASK) {
		printk(KERN_INFO "DVS: unknown fs log control %u\n",
		       control);
	} else {
		/* process the selected control bits */

		if (control & DVSPROC_FS_LOG_CONTROL_RESET)
			dvs_log_clear(LOG_FS_LOG);

		if (control & DVSPROC_FS_LOG_CONTROL_ENABLE)
			dvs_fs_log_enabled = 1;
	}
}

static ssize_t
ssiproc_fs_log_write(struct file *file, const char *buffer, size_t count,
		     loff_t *offp)
{
	char str[16];
	unsigned int control;

	if (count >= sizeof(str))
		return -EINVAL;

	memset(str, 0, sizeof(str));
	if (copy_from_user(str, buffer, count))
		return -EFAULT;

	control = simple_strtoul(str, NULL, 0);
	dvsproc_fs_log_set_control(control);

	return count;
}

static ssize_t 
ssiproc_log_size_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	int ret, size;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &size) != 1)
		return -EINVAL;

	if ((ret = dvs_log_resize(LOG_DVS_LOG, size)) == 0)
		ret = count;

	return ret;
}

static ssize_t 
ssiproc_rq_log_size_write(struct file *file, const char *buffer,
			  size_t count, loff_t *offp)
{
	int ret, size;
	char sizestr[16];

	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &size) != 1)
		return -EINVAL;

	if ((ret = dvs_log_resize(LOG_RQ_LOG, size)) == 0) {
		ret = count;
		dvs_request_log_size_kb = size;
	}

	return ret;
}

static ssize_t 
ssiproc_fs_log_size_write(struct file *file, const char *buffer,
			  size_t count, loff_t *offp)
{
	int ret, size;
	char sizestr[16];

	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &size) != 1)
		return -EINVAL;

	if ((ret = dvs_log_resize(LOG_FS_LOG, size)) == 0) {
		ret = count;
		dvs_fs_log_size_kb = size;
	}

	return ret;
}

static ssize_t
ssiproc_rq_log_time_write(struct file *file, const char *buffer,
			  size_t count, loff_t *offp)
{
	int size;
	char sizestr[16];

	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &size) != 1)
		return -EINVAL;

	dvs_request_log_min_time_secs = size;

	return count;
}

static ssize_t
ssiproc_fs_log_time_write(struct file *file, const char *buffer,
			  size_t count, loff_t *offp)
{
	int size;
	char sizestr[16];

	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &size) != 1)
		return -EINVAL;

	dvs_fs_log_min_time_secs = size;

	return count;
}

static ssize_t
ssiproc_sync_period_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int period;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &period) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_period_update)
		sync_ops->sync_period_update(period);

	return count;
}

static ssize_t 
ssiproc_sync_timeout_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int timeout;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &timeout) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_timeout_update)
		sync_ops->sync_timeout_update(timeout);

	return count;
}

static ssize_t 
ssiproc_sync_threads_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int threads;
	char sizestr[16];
	int ret = 0;
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &threads) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_threads_update)
		ret = sync_ops->sync_threads_update(threads);

	if (ret)
		return ret;

	return count;
}

static ssize_t 
ssiproc_sync_stats_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int control;
	char sizestr[16];
	int ret = 0;
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &control) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_stats_control)
		ret = sync_ops->sync_stats_control(control);

	if (ret)
		return ret;

	return count;
}

static ssize_t 
ssiproc_estale_max_retry_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int max_retry;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &max_retry) != 1)
		return -EINVAL;

	estale_max_retry = max_retry;

	return count;
}

static ssize_t 
ssiproc_estale_timeout_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int timeout;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &timeout) != 1)
		return -EINVAL;

	estale_timeout_secs = timeout;

	return count;
}

static ssize_t 
ssiproc_estale_stats_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	unsigned int control;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &control) != 1)
		return -EINVAL;

	if (!control) {
		atomic64_set(&global_estale_stats.stats[ESTALE_RETRY_FAIL], 0);
		atomic64_set(&global_estale_stats.stats[ESTALE_RETRY_PASS], 0);
		atomic64_set(&global_estale_stats.stats[ESTALE_FAILOVER_FAIL], 0);
		atomic64_set(&global_estale_stats.stats[ESTALE_FAILOVER_PASS], 0);
	}

	return count;
}

/*
 * Set the attrcache_revalidation_time to the current time.
 * This forces revalidation of each inode in the mount point.
 */
static void
ssiproc_drop_mount_attr_cache(struct incore_upfs_super_block *icsb)
{
	spin_lock(&icsb->lock);
	icsb->attrcache_revalidate_time = jiffies;
	spin_unlock(&icsb->lock);
	DVS_LOG("DVS: Set attrcache_revalidate_time to %lu for %s\n",
		icsb->attrcache_revalidate_time, icsb->prefix);
	KDEBUG_PNC(0, "DVS: %s: Set attrcache_revalidate_time to %lu for %s\n",
		__FUNCTION__, icsb->attrcache_revalidate_time, icsb->prefix);
}

/*
 * Iterate through every mount point and set each for revalidation
 */
static void
ssiproc_drop_all_attr_cache(void)
{
	struct list_head *p;
	struct incore_upfs_super_block *icsb;
	down(&dvs_super_blocks_sema);
	list_for_each(p, &dvs_super_blocks) {
		icsb = list_entry(p, struct incore_upfs_super_block, list);
		ssiproc_drop_mount_attr_cache(icsb);
	}
	up(&dvs_super_blocks_sema);
}

static ssize_t
ssiproc_drop_caches_write(struct file *fp, const char *buffer, size_t count, loff_t *offset) {
	char sizestr[16];
	struct incore_upfs_super_block *icsb;
	if (count > 16)
		return -EFBIG;
	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;
	if (strncmp(sizestr, "1", 1)) {
		return count;
	}
	icsb = PDE_DATA(file_inode(fp));
	if (!icsb)
		ssiproc_drop_all_attr_cache();
	else
		ssiproc_drop_mount_attr_cache(icsb);
	return count;
}

static ssize_t
ssiproc_drop_caches_read(struct file *fp, char *user_buffer, size_t count, loff_t *offset)
{
	char buf[64];
	ssize_t bytes_written;
	struct incore_upfs_super_block *icsb;
	if (*offset > 0)
		return 0;
	/* Need 20 to express a 64 bit integer, plus newline */
	if (count < 22)
		return -EFBIG;
	icsb = PDE_DATA(file_inode(fp));
	if (!icsb)
		bytes_written = snprintf(buf, sizeof(buf), "0\n");
	else
		bytes_written = snprintf(buf, sizeof(buf), "%lu\n", icsb->attrcache_revalidate_time);
	if (copy_to_user(user_buffer, buf, bytes_written + 1))
		return -EFAULT;
	*offset += bytes_written;
	return bytes_written;
}

static ssize_t 
ssiproc_ssimap_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	int			ret = count;
	loff_t			pos = *offp;
	struct inode   	*inode = file_inode(file)->i_mapping->host;

	KDEBUG_INF(0, "DVS: %s: 0x%p 0x%p %ld %lld\n",
		   __FUNCTION__, file, inode, count, *offp);

	mutex_lock(&inode->i_mutex);

	if (!capable(CAP_SYS_ADMIN)) {
	    	ret = -EACCES;
		goto out;
	}

	if (winfop == NULL) {
		if (count > SSIPROC_MAX_USER_INPUT) {
			ret = -EFBIG;
			goto out;
		}
		winfop = (struct ssiproc_info *)vmalloc_ssi(SSIPROC_MAX_USER_INPUT);
		if (!winfop) {
			ret = -ENOMEM;
			goto out;
		}

		winfop->buf = (char *)(winfop + sizeof(struct ssiproc_info));
		winfop->flag = 1;
		winfop->ip = inode;
	}

	if (winfop->ip != inode) {
	    	ret = -EBUSY;
		goto out;
	}

	if (file->f_flags & O_APPEND) {
		pos = inode->i_size;
	}

	if ((pos + count) > SSIPROC_MAX_USER_INPUT) {
		ret = -EFBIG;
		vfree(winfop);
		goto out;
	}
	if (copy_from_user((winfop->buf + pos), buffer, count)) {
		ret = -EFAULT;
		vfree(winfop);
		goto out;
	}
	*offp = pos + count;
	if ((pos + count) > inode->i_size) {
		inode->i_size = pos + count;
	}
out:
	mutex_unlock(&inode->i_mutex);
	return (ret);

} /* ssiproc_ssimap_write */

static int
ssiproc_ssimap_release(struct inode *ip, struct file *fp)
{
	struct ssi_node_map	*tmap;
	int 			ret = 0;

	KDEBUG_INF(0, "DVS: %s: 0x%p 0x%p\n", __FUNCTION__, ip, fp);

	if ((winfop) && (winfop->buf) && (winfop->flag == 1) && 
	    (winfop->ip == ip)) {

		if (ip->i_size > SSIPROC_MAX_USER_INPUT) {
			ret = -EFBIG;
		} else if (node_map == NULL) {

			tmap = ssiproc_parse_mapfile(winfop->buf, ip->i_size, 
						&ret);
			if (tmap) {
				ssiproc_lock_node_map(SSIPROC_LOCK_WRITE);
				ssiproc_free_node_map();
				node_map = tmap;
				ssiproc_unlock_node_map(SSIPROC_LOCK_WRITE);
			} else {
				printk(KERN_ERR "DVS: %s: parse mapfile "
				       "failure\n", __FUNCTION__);
				ret = -EINVAL;
			}
		}
		/* If node_map != NULL, just ignore, return good status */
		vfree(winfop);
		winfop = NULL;
	}
	seq_release(ip, fp);
	return (ret);

} /* ssiproc_ssimap_release */


int
ssiproc_lock_node_map(int flag)
{
	if (flag & SSIPROC_LOCK_READ) {
		down_read(&ssiproc_map_sem);
	} else if (flag & SSIPROC_LOCK_WRITE) {
	    	down_write(&ssiproc_map_sem);
	} else {
	    	/* unknown lock request */
		return (1);
	}

	return (0);
} /* ssiproc_lock_node_map */

int
ssiproc_unlock_node_map(int flag)
{
    	if (flag & SSIPROC_LOCK_READ) {
	    	up_read(&ssiproc_map_sem);
	} else if (flag & SSIPROC_LOCK_WRITE) {
	    	up_write(&ssiproc_map_sem);
	} else {
	    	/* unknown lock request */
	    	return (1);
	}

	return (0);
} /* ssiproc_unlock_node_map */

/*
 * Creates a /proc/fs/dvs/mounts/X entry
 */
int
dvsproc_add_mountpoint(struct incore_upfs_super_block *icsb)
{
	char buf[20];
	int mount_num;
	struct dvsproc_stat *p;

	p = kmalloc_ssi(sizeof(struct dvsproc_stat), GFP_KERNEL);
	if (p) {
		mount_num = atomic_inc_return(&ssiproc_mounts);
	        dvsproc_stat_init(p, mount_num);

		snprintf(buf, sizeof(buf), "%d", mount_num);
    		p->mount_dir = proc_mkdir(buf, ssiproc_mounts_dir);
		if (p->mount_dir) {
			p->mount_entry = proc_create_data(SSIPROC_MOUNT,
						   S_IFREG | S_IRUGO | S_IWUSR,
						   p->mount_dir,
						   &ssiproc_mount_info_operations,
						   icsb);
			if (!p->mount_entry) {
				remove_proc_entry(buf, ssiproc_mounts_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->stats_entry = proc_create_data(SSIPROC_STATS,
						   S_IFREG | S_IRUGO | S_IWUSR, 
						   p->mount_dir,
						   &ssiproc_stats_operations,
						   p);
			if (!p->stats_entry) {
				remove_proc_entry(SSIPROC_MOUNT, p->mount_dir);
				remove_proc_entry(buf, ssiproc_mounts_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->openfile_entry = proc_create_data(SSIPROC_OPENFILES,
							S_IFREG | S_IRUGO | S_IWUSR,
							p->mount_dir,
							&ssiproc_openfile_info_operations,
							icsb);
			if (!p->openfile_entry) {
				remove_proc_entry(SSIPROC_STATS, p->mount_dir);
				remove_proc_entry(SSIPROC_MOUNT, p->mount_dir);
				remove_proc_entry(buf, ssiproc_mounts_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->nodenames_entry = proc_create_data(SSIPROC_NODENAMES,
							S_IFREG | S_IRUGO | S_IWUSR,
							p->mount_dir,
							&ssiproc_nodenames_operations,
							icsb);
			if (!p->nodenames_entry) {
				remove_proc_entry(SSIPROC_OPENFILES, p->mount_dir);
				remove_proc_entry(SSIPROC_STATS, p->mount_dir);
				remove_proc_entry(SSIPROC_MOUNT, p->mount_dir);
				remove_proc_entry(buf, ssiproc_mounts_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->drop_caches_entry = proc_create_data(SSIPROC_DROP_CACHES,
							S_IFREG | S_IRUGO | S_IWUSR,
							p->mount_dir,
							&ssiproc_drop_caches_operations,
							icsb);
			if (!p->drop_caches_entry) {
				remove_proc_entry(SSIPROC_NODENAMES, p->mount_dir);
				remove_proc_entry(SSIPROC_OPENFILES, p->mount_dir);
				remove_proc_entry(SSIPROC_STATS, p->mount_dir);
				remove_proc_entry(SSIPROC_MOUNT, p->mount_dir);
				remove_proc_entry(buf, ssiproc_mounts_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

		} else {
			kfree_ssi(p);
			goto add_mount_error;
		}
	} else {
add_mount_error:
	    	printk(KERN_ERR "DVS: %s: cannot init %s/%s/%s\n",
		       __FUNCTION__, SSIPROC_MOUNTS_DIR, "0", SSIPROC_STATS);
		return -ENOMEM;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	p->mount_entry->uid = 0;
	p->stats_entry->uid = 0;
	p->openfile_entry->uid = 0;
#else
	proc_set_user(p->mount_entry, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(p->stats_entry, KUIDT_INIT(0), KGIDT_INIT(0));
	proc_set_user(p->openfile_entry, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

	/* store per-mountpoint stats pointer in superblock */
	icsb->stats = p;

	return 0;
}

int
dvsproc_remove_mountpoint(struct incore_upfs_super_block *icsb)
{
	char buf[20];
	struct dvsproc_stat *p;

	p = icsb->stats;
	remove_proc_entry(SSIPROC_NODENAMES, p->mount_dir);
	remove_proc_entry(SSIPROC_OPENFILES, p->mount_dir);
	remove_proc_entry(SSIPROC_MOUNT, p->mount_dir);
	remove_proc_entry(SSIPROC_STATS, p->mount_dir);
	remove_proc_entry(SSIPROC_DROP_CACHES, p->mount_dir);
	snprintf(buf, 20, "%d", p->mountpoint_id);
	remove_proc_entry(buf, ssiproc_mounts_dir);
	kfree_ssi(p);

	return 0;
}

static int node_map_index_in_server(int index, struct dvs_server *servers, int len) {

	int i;
	for (i = 0; i < len; i++) {
		if (index == servers[i].node_map_index)
			return 1;
	}
	return 0;
}

/* Count unique servers between the data and metadata servers */
static int unique_servers(struct incore_upfs_super_block *icsb) {

	int i, n, node_map_index;

	n = icsb->data_servers_len;

	if (icsb->data_servers == icsb->meta_servers)
		return n;

	for (i = 0; i < icsb->meta_servers_len; i++) {
		node_map_index = icsb->meta_servers[i].node_map_index;
		if (!node_map_index_in_server(node_map_index,
						icsb->data_servers,
						icsb->data_servers_len)) {
			n++;
		}
	}

	return n;
}

void
dvsproc_mount_options_print(struct seq_file *m,
			    struct incore_upfs_super_block *icsb)
{
	int i;

	/*
	 * Compute number of node names that will fit, reserving half of the space
	 * for the two pathnames prepended in the /proc/self/mounts file.
	 * If we have more than this, we omit the "nodefile=" option,
	 * but the full list is still available in the nodenames /proc file.
	 */
	const int max_options_len = (4096-2)/2;/* Maximum length of generated options string.
	                                      Constraint comes from buffer size used by
	                                      glibc getmntent(), minu "\n" and zero byte.  */
	const int max_cname_len = 12;      /* Maximum length of cnames.  Allow space for
	                                      up to 99 rows x 99 columns of cabinets. */
	const int max_int_len = 10;		   /* Maximum length of a signed int in decimal format */
	const int other_opts_reserve =     /* Reserve space for the other options,
	                                      conservatively computed from the longest
	                                      variant of each. */
	          sizeof("options (rw")-1
	          +sizeof(",blksize=")+max_int_len-1
	          +sizeof(",nodename=")-1
	          +sizeof(",nodefile=/proc/fs/dvs/mounts//nodenames")+max_int_len-1
                  +sizeof(",statsfile=/proc/fs/dvs/mounts//stats")+max_int_len-1
	          +sizeof(",attrcache_timeout=")+sizeof(icsb->attrcache_timeout_str)
	          +sizeof(",noparallelwrite")-1
	          +sizeof(",nodwfs")-1
	          +sizeof(",nodwcfs")-1
	          +sizeof(",nomultifsync")-1
	          +sizeof(",nocache")-1
	          +sizeof(",nodatasync")-1
	          +sizeof(",noclosesync")-1
	          +sizeof(",noretry")-1
	          +sizeof(",nofailover")-1
	          +sizeof(",nouserenv")-1
	          +sizeof(",noclusterfs")-1
	          +sizeof(",nokillprocess")-1
	          +sizeof(",noatomic")-1
	          +sizeof(",nodeferopens")-1
	          +sizeof(",no_distribute_create_ops")-1
	          +sizeof(",no_ro_cache")-1
	          +sizeof(",cache_read_sz=")+max_int_len-1
	          +sizeof(",noloadbalance")-1
	          +sizeof(",maxnodes=")+max_int_len-1
	          +sizeof(",metastripewidth=")+max_int_len-1
	          +sizeof(",nnodes=")+max_int_len-1
	          +sizeof(",magic=0x")+16-1
	          +sizeof(",nohash_on_nid")-1
	          +sizeof(",hash=jenkins")-1;
	const int max_inline_nodes = (max_options_len - other_opts_reserve)/(max_cname_len + 1);

	seq_printf(m, ",blksize=%d", icsb->bsz);

	if (icsb->data_servers_len <= max_inline_nodes){
		seq_printf(m, ",nodename=");
		for (i = 0; i < icsb->data_servers_len; i++) {
			if (i > 0)
				seq_printf(m, ":");
			seq_printf(m, "%s", node_map[icsb->data_servers[i].node_map_index].name);
		}
	}
	if (icsb->meta_servers != icsb->data_servers) {
		seq_printf(m, ",mds=");
                for (i = 0; i < icsb->meta_servers_len; i++) {
                        if (i > 0)
                                seq_printf(m, ":");
                        seq_printf(m, "%s", node_map[icsb->meta_servers[i].node_map_index].name);
                }
	}
	seq_printf(m, ",nodefile=/proc/fs/dvs/mounts/%d/nodenames",
			icsb->stats->mountpoint_id);
	seq_printf(m, ",statsfile=/proc/fs/dvs/mounts/%d/stats",
			icsb->stats->mountpoint_id);
	seq_printf(m, ",attrcache_timeout=%s", icsb->attrcache_timeout_str);
	if (icsb->dwfs_flags & DWFS_BIT) {
		seq_printf(m, ",dwfs");
	} else {
		seq_printf(m, ",nodwfs");
	}
	if (icsb->dwfs_flags & DWCFS_BIT) {
		seq_printf(m, ",dwcfs");
	} else {
		seq_printf(m, ",nodwcfs");
	}
	if (icsb->parallel_write) {
		seq_printf(m, ",parallelwrite");
	} else {
		seq_printf(m, ",noparallelwrite");
	}
	if (icsb->multi_fsync) {
		seq_printf(m, ",multifsync");
	} else {
		seq_printf(m, ",nomultifsync");
	}
	if (icsb->cache) {
		seq_printf(m, ",cache");
	} else {
		seq_printf(m, ",nocache");
	}
	if (icsb->datasync) {
		seq_printf(m, ",datasync");
	} else {
		seq_printf(m, ",nodatasync");
	}
	if (icsb->closesync) {
		seq_printf(m, ",closesync");
	} else {
		seq_printf(m, ",noclosesync");
	}
	if (icsb->retry) {
		seq_printf(m, ",retry");
	} else {
		seq_printf(m, ",noretry");
	}
	if (icsb->failover) {
		seq_printf(m, ",failover");
	} else {
		seq_printf(m, ",nofailover");
	}
	if (icsb->userenv) {
		seq_printf(m, ",userenv");
	} else {
		seq_printf(m, ",nouserenv");
	}
	if (icsb->clusterfs) {
		seq_printf(m, ",clusterfs");
	} else {
		seq_printf(m, ",noclusterfs");
	}
	if (icsb->killprocess) {
		seq_printf(m, ",killprocess");
	} else {
		seq_printf(m, ",nokillprocess");
	}
	if (icsb->atomic) {
		seq_printf(m, ",atomic");
	} else {
		seq_printf(m, ",noatomic");
	}
	if (icsb->deferopens) {
		seq_printf(m, ",deferopens");
	} else {
		seq_printf(m, ",nodeferopens");
	}
	if (icsb->distribute_create_ops) {
		seq_printf(m, ",distribute_create_ops");
	} else {
		seq_printf(m, ",no_distribute_create_ops");
	}
	if (icsb->ro_cache) {
		seq_printf(m, ",ro_cache");
	} else {
		seq_printf(m, ",noro_cache");
	}
	if (icsb->cache_read_sz) {
		seq_printf(m, ",cache_read_sz=%d", icsb->cache_read_sz);
	}
	if (icsb->loadbalance) {
		seq_printf(m, ",loadbalance");
	} else {
		seq_printf(m, ",noloadbalance");
	}
	seq_printf(m, ",maxnodes=%d", icsb->data_stripe_width);
	if (icsb->meta_stripe_width) {
		seq_printf(m, ",metastripewidth=%d", icsb->meta_stripe_width);
	}
	seq_printf(m, ",nnodes=%d", unique_servers(icsb));
	if (icsb->expected_magic) {
		seq_printf(m, ",magic=0x%lx", icsb->expected_magic);
	} else {
		seq_printf(m, ",nomagic");
	}
	if (icsb->ino_ignore_prefix_depth) {
		seq_printf(m, ",ino_ignore_prefix_depth=%d", icsb->ino_ignore_prefix_depth);
	}
	if (icsb->data_hash.hash_on_nid && icsb->meta_hash.hash_on_nid) {
		seq_printf(m, ",hash_on_nid");
	} else if (icsb->data_hash.hash_on_nid) {
		seq_printf(m, ",data_hash_on_nid,nometa_hash_on_nid");
	} else if (icsb->meta_hash.hash_on_nid) {
		seq_printf(m, ",nodata_hash_on_nid,meta_hash_on_nid");
	} else {
		seq_printf(m, ",nohash_on_nid");
	}
	if (icsb->data_hash.algorithm == icsb->meta_hash.algorithm) {
		switch (icsb->data_hash.algorithm) {
			case HASH_JENKINS:
				seq_printf(m, ",hash=jenkins");
				break;
			case HASH_MODULO:
				seq_printf(m, ",hash=modulo");
				break;
			case HASH_DEFAULT:
			case HASH_FNV_1A:
				seq_printf(m, ",hash=fnv-1a");
				break;
		}
	}
	else {
		switch (icsb->data_hash.algorithm) {
			case HASH_JENKINS:
				seq_printf(m, ",data_hash=jenkins");
				break;
			case HASH_MODULO:
				seq_printf(m, ",data_hash=modulo");
				break;
			case HASH_DEFAULT:
			case HASH_FNV_1A:
				seq_printf(m, ",data_hash=fnv-1a");
				break;
		}
		switch (icsb->meta_hash.algorithm) {
			case HASH_JENKINS:
				seq_printf(m, ",meta_hash=jenkins");
				break;
			case HASH_MODULO:
				seq_printf(m, ",meta_hash=modulo");
				break;
			case HASH_DEFAULT:
			case HASH_FNV_1A:
				seq_printf(m, ",meta_hash=fnv-1a");
				break;
		}
	}
}

int sync_proc_register(struct sync_proc_ops *ops)
{
	if (!ops)
		return -1;

	sync_ops = ops;
	return 0;
}

int sync_proc_unregister(struct sync_proc_ops *ops)
{
	if (!ops || sync_ops != ops)
		return -1;

	sync_ops = NULL;
	return 0;
}

MODULE_LICENSE(DVS_LICENSE);
module_init(ssiproc_init);
module_exit(ssiproc_exit);

EXPORT_SYMBOL(global_estale_stats);
EXPORT_SYMBOL(estale_timeout_secs);
EXPORT_SYMBOL(estale_max_retry);
EXPORT_SYMBOL(dvs_debug_mask);
EXPORT_SYMBOL(max_transport_msg_size);
EXPORT_SYMBOL(max_transport_msg_pages);
EXPORT_SYMBOL(wb_threshold_pages);
EXPORT_SYMBOL(ssiproc_max_nodes);
EXPORT_SYMBOL(node_map);
EXPORT_SYMBOL(ssi_nodeid);
EXPORT_SYMBOL(ssiproc_parse_mapfile);
EXPORT_SYMBOL(ssiproc_get_my_nodeid);
EXPORT_SYMBOL(ssiproc_get_max_nodes);
EXPORT_SYMBOL(ssiproc_lock_node_map);
EXPORT_SYMBOL(ssiproc_unlock_node_map);
EXPORT_SYMBOL(usi_node_addr);
EXPORT_SYMBOL(dvsproc_add_mountpoint);
EXPORT_SYMBOL(dvsproc_remove_mountpoint);
EXPORT_SYMBOL(dvsproc_mount_options_print);
#ifdef CONFIG_CRAY_TRACE
EXPORT_SYMBOL(dvs_trace_idx);
EXPORT_SYMBOL(dvs_trace_slots);
#endif
EXPORT_SYMBOL(sync_proc_register);
EXPORT_SYMBOL(sync_proc_unregister);
EXPORT_SYMBOL(dvs_request_log_enabled);
EXPORT_SYMBOL(dvs_request_log_min_time_secs);
EXPORT_SYMBOL(dvs_fs_log_enabled);
EXPORT_SYMBOL(dvs_fs_log_min_time_secs);
