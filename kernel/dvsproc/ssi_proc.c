/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2018 Cray Inc. All Rights Reserved.
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
#include <linux/debugfs.h>

#include "common/ssi_proc.h"
#include "common/ssi_sysctl.h"
#include "common/kernel/usiipc.h"
#include "dvs/kernel/usifile.h"
#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"
#include "common/dvsproc_timing_stat.h"
#include "common/sys_setup.h"
#include "dvs/dvs_config.h"

#ifdef CONFIG_KATLAS
struct katlas_instance *dvs_alloc_instance;
#endif

static struct sync_proc_ops *sync_ops = NULL;

atomic_t dvs_debugfs_mounts = ATOMIC_INIT(-1);
LIST_HEAD(dvs_mount_hash_list);
EXPORT_SYMBOL(dvs_mount_hash_list);
DEFINE_RWLOCK(dvs_mount_hash_rwlock);
EXPORT_SYMBOL(dvs_mount_hash_rwlock);

int ssiproc_max_nodes = 0;
int usi_node_addr = 0;
ssize_t max_transport_msg_size;
int max_transport_msg_pages;
int wb_threshold_pages;

/* ESTALE variables needed by /proc files */
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
MODULE_PARM_DESC(dvs_request_log_size_kb,
		 "size of the DVS request log buffer in KB");
module_param(dvs_request_log_min_time_secs, uint, 0444);
MODULE_PARM_DESC(
	dvs_request_log_min_time_secs,
	"minimum amount of time in seconds required to log request info");
module_param(dvs_request_log_enabled, uint, 0444);
MODULE_PARM_DESC(dvs_request_log_enabled,
		 "whether DVS request logging is enabled");
module_param(dvs_fs_log_size_kb, uint, 0444);
MODULE_PARM_DESC(dvs_fs_log_size_kb, "size of the DVS fs log buffer in KB");
module_param(dvs_fs_log_min_time_secs, uint, 0444);
MODULE_PARM_DESC(dvs_fs_log_min_time_secs,
		 "minimum amount of time in seconds required to log fs info");
module_param(dvs_fs_log_enabled, uint, 0444);
MODULE_PARM_DESC(dvs_fs_log_enabled, "whether DVS fs logging is enabled");
module_param(ssiproc_max_nodes, int, 0644);
module_param(dvs_debug_mask, ulong, 0644);
#ifdef CONFIG_CRAY_TRACE
module_param(dvs_trace_slots, int, 0644);
#endif
module_param(estale_max_retry, uint, 0444);
module_param(estale_timeout_secs, uint, 0444);

#define DVSSYS_MAX_USER_INPUT 1024 * 1024

static struct proc_dir_entry *dvs_procfs_dir;
static struct dentry *dvs_debugfs_mounts_dir;
static struct dentry *dvs_debugfs_stats_dir;

static struct dentry *dentry_dvs_debug = NULL;

struct ssi_node_map *node_map;
struct rw_semaphore dvs_debugfs_map_sem;

static void dvs_procfs_free_node_map(void);
static int dvs_procfs_ssimap_open(struct inode *, struct file *);
static ssize_t dvs_procfs_ssimap_write(struct file *, const char *, size_t,
				       loff_t *);
static int dvs_procfs_ssimap_release(struct inode *, struct file *);

static int dvs_debugfs_common_release(struct inode *, struct file *);
static int dvs_debugfs_mn_open(struct inode *, struct file *);
static int dvs_debugfs_log_open(struct inode *, struct file *);
static int dvs_debugfs_log_size_open(struct inode *, struct file *);
static int dvs_debugfs_rq_log_open(struct inode *, struct file *);
static int dvs_debugfs_rq_log_size_open(struct inode *, struct file *);
static int dvs_debugfs_rq_log_time_open(struct inode *, struct file *);
static int dvs_debugfs_fs_log_open(struct inode *, struct file *);
static int dvs_debugfs_fs_log_size_open(struct inode *, struct file *);
static int dvs_debugfs_fs_log_time_open(struct inode *, struct file *);
static int dvs_debugfs_stats_open(struct inode *, struct file *);
static ssize_t dvs_debugfs_stats_write(struct file *, const char *, size_t,
				       loff_t *);
static ssize_t dvs_debugfs_rq_log_write(struct file *, const char *, size_t,
					loff_t *);
static ssize_t dvs_debugfs_fs_log_write(struct file *, const char *, size_t,
					loff_t *);
static ssize_t dvs_debugfs_log_size_write(struct file *, const char *, size_t,
					  loff_t *);
static ssize_t dvs_debugfs_rq_log_size_write(struct file *, const char *,
					     size_t, loff_t *);
static ssize_t dvs_debugfs_rq_log_time_write(struct file *, const char *,
					     size_t, loff_t *);
static ssize_t dvs_debugfs_fs_log_size_write(struct file *, const char *,
					     size_t, loff_t *);
static ssize_t dvs_debugfs_fs_log_time_write(struct file *, const char *,
					     size_t, loff_t *);
static int dvs_debugfs_mount_info_open(struct inode *, struct file *);
static int dvs_debugfs_openfile_info_open(struct inode *, struct file *);
static int dvs_debugfs_nodenames_open(struct inode *, struct file *);

static void *dvs_procfs_ssimap_seq_start(struct seq_file *, loff_t *);
static void *dvs_procfs_ssimap_seq_next(struct seq_file *, void *, loff_t *);
static void dvs_procfs_ssimap_seq_stop(struct seq_file *, void *);
static int dvs_procfs_ssimap_seq_show(struct seq_file *, void *);

static void *dvs_debugfs_log_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_log_size_seq_start(struct seq_file *, loff_t *);
static int dvs_debugfs_log_seq_show(struct seq_file *, void *);
static int dvs_debugfs_log_size_seq_show(struct seq_file *, void *);
static void *dvs_debugfs_rq_log_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_rq_log_size_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_rq_log_time_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_fs_log_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_fs_log_size_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_fs_log_time_seq_start(struct seq_file *, loff_t *);
static int dvs_debugfs_rq_log_seq_show(struct seq_file *, void *);
static int dvs_debugfs_rq_log_size_seq_show(struct seq_file *, void *);
static int dvs_debugfs_rq_log_time_seq_show(struct seq_file *, void *);
static int dvs_debugfs_fs_log_seq_show(struct seq_file *, void *);
static int dvs_debugfs_fs_log_size_seq_show(struct seq_file *, void *);
static int dvs_debugfs_fs_log_time_seq_show(struct seq_file *, void *);
static void *dvs_debugfs_common_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_common_seq_next(struct seq_file *, void *, loff_t *);
static void dvs_debugfs_common_seq_stop(struct seq_file *, void *);
static void *dvs_debugfs_mn_seq_start(struct seq_file *, loff_t *);
static int dvs_debugfs_mn_seq_show(struct seq_file *, void *);
static int dvs_debugfs_stats_seq_show(struct seq_file *, void *);
static int dvs_debugfs_mount_info_seq_show(struct seq_file *, void *);
static int dvs_debugfs_openfile_info_seq_show(struct seq_file *, void *);
static int dvs_debugfs_nodenames_seq_show(struct seq_file *, void *);

static int dvs_debugfs_sync_stats_open(struct inode *, struct file *);
static ssize_t dvs_debugfs_sync_stats_write(struct file *, const char *, size_t,
					    loff_t *);
static int dvs_debugfs_sync_stats_seq_show(struct seq_file *, void *);
static void *dvs_debugfs_sync_stats_seq_start(struct seq_file *, loff_t *);
static int dvs_debugfs_estale_stats_open(struct inode *, struct file *);
static ssize_t dvs_debugfs_estale_stats_write(struct file *, const char *,
					      size_t, loff_t *);
static int dvs_debugfs_estale_stats_seq_show(struct seq_file *, void *);
static void *dvs_debugfs_estale_stats_seq_start(struct seq_file *, loff_t *);
static ssize_t dvs_debugfs_drop_mount_caches_read(struct file *fp,
						  char *user_buffer,
						  size_t count, loff_t *offset);
static ssize_t dvs_debugfs_drop_mount_caches_write(struct file *, const char *,
						   size_t, loff_t *);

/* DVS Message Timing Stats */
static int dvs_debugfs_client_msg_timing_open(struct inode *, struct file *);
static int dvs_debugfs_server_msg_timing_open(struct inode *, struct file *);
static ssize_t dvs_debugfs_client_msg_timing_write(struct file *, const char *,
						   size_t, loff_t *);
static ssize_t dvs_debugfs_server_msg_timing_write(struct file *, const char *,
						   size_t, loff_t *);
static void *dvs_debugfs_msg_timing_seq_start(struct seq_file *, loff_t *);
static void *dvs_debugfs_msg_timing_seq_next(struct seq_file *, void *,
					     loff_t *);
static int dvs_debugfs_msg_timing_seq_show(struct seq_file *, void *);
static void dvs_debugfs_msg_timing_seq_stop(struct seq_file *, void *);

/*
 * seq_file ops vectors
 */

static struct seq_operations dvs_procfs_ssimap_ops = {
	start: dvs_procfs_ssimap_seq_start,
	next: dvs_procfs_ssimap_seq_next,
	stop: dvs_procfs_ssimap_seq_stop,
	show: dvs_procfs_ssimap_seq_show,
};

static struct seq_operations dvs_debugfs_maxnodes_ops = {
	start: dvs_debugfs_mn_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_mn_seq_show,
};

static struct seq_operations dvs_debugfs_log_ops = {
	start: dvs_debugfs_log_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_log_seq_show,
};

static struct seq_operations dvs_debugfs_log_size_ops = {
	start: dvs_debugfs_log_size_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_log_size_seq_show,
};

static struct seq_operations dvs_debugfs_rq_log_ops = {
	start: dvs_debugfs_rq_log_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_rq_log_seq_show,
};

static struct seq_operations dvs_debugfs_rq_log_size_ops = {
	start: dvs_debugfs_rq_log_size_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_rq_log_size_seq_show,
};

static struct seq_operations dvs_debugfs_rq_log_time_ops = {
	start: dvs_debugfs_rq_log_time_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_rq_log_time_seq_show,
};

static struct seq_operations dvs_debugfs_fs_log_ops = {
	start: dvs_debugfs_fs_log_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_fs_log_seq_show,
};

static struct seq_operations dvs_debugfs_fs_log_size_ops = {
	start: dvs_debugfs_fs_log_size_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_fs_log_size_seq_show,
};

static struct seq_operations dvs_debugfs_fs_log_time_ops = {
	start: dvs_debugfs_fs_log_time_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_fs_log_time_seq_show,
};

static struct seq_operations dvs_debugfs_sync_stats_ops = {
	start: dvs_debugfs_sync_stats_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_sync_stats_seq_show,
};

static struct seq_operations dvs_debugfs_stats_ops = {
	start: dvs_debugfs_common_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_stats_seq_show,
};

static struct seq_operations dvs_debugfs_mount_info_ops = {
	start: dvs_debugfs_common_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_mount_info_seq_show,
};

static struct seq_operations dvs_debugfs_openfile_info_ops = {
	start: dvs_debugfs_common_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_openfile_info_seq_show,
};

static struct seq_operations dvs_debugfs_nodenames_ops = {
	start: dvs_debugfs_common_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_nodenames_seq_show,
};

static struct seq_operations dvs_debugfs_msg_timing_seq_ops = {
	start: dvs_debugfs_msg_timing_seq_start,
	next: dvs_debugfs_msg_timing_seq_next,
	stop: dvs_debugfs_msg_timing_seq_stop,
	show: dvs_debugfs_msg_timing_seq_show,
};

static struct seq_operations dvs_debugfs_estale_stats_ops = {
	start: dvs_debugfs_estale_stats_seq_start,
	next: dvs_debugfs_common_seq_next,
	stop: dvs_debugfs_common_seq_stop,
	show: dvs_debugfs_estale_stats_seq_show,
};

static ssize_t dvs_debugfs_client_msg_timing_write(struct file *fp,
						   const char *buffer,
						   size_t count, loff_t *off)
{
	char str[4] = "";

	if (count >= sizeof(str))
		return -EINVAL;

	if (copy_from_user(str, buffer, count))
		return -EFAULT;

	if (strncmp(str, "0", 1))
		return -EINVAL;

	dvs_timing_reset(dvs_client_timing_stats);
	return count;
}

static ssize_t dvs_debugfs_server_msg_timing_write(struct file *fp,
						   const char *buffer,
						   size_t count, loff_t *off)
{
	char str[4] = "";

	if (count >= sizeof(str))
		return -EINVAL;

	if (copy_from_user(str, buffer, count))
		return -EFAULT;

	if (strncmp(str, "0", 1))
		return -EINVAL;

	dvs_timing_reset(dvs_server_timing_stats);
	return count;
}

static void *dvs_debugfs_msg_timing_seq_start(struct seq_file *m, loff_t *pos)
{
	struct tm ts;
	struct dvs_timing_stats *timing_stats = m->private;

	if (*pos >= RQ_DVS_END_V1)
		return NULL;

	/* If we're not at the start of the file, just return the info */
	if (*pos != 0)
		return &timing_stats[*pos];

	time_to_tm(timing_stats->last_reset, 0, &ts);
	seq_printf(m,
		   "# Version %s %s Timing Stats. "
		   "Stats last reset at %02d/%02d/%ld %02d:%02d:%02d. "
		   "All times in microseconds.\n",
		   DVS_TIMING_VERSION,
		   timing_stats == dvs_server_timing_stats ? "Server" :
							     "Client",
		   ts.tm_mon + 1, ts.tm_mday, 1900 + ts.tm_year, ts.tm_hour,
		   ts.tm_min, ts.tm_sec);

	if (timing_stats == dvs_server_timing_stats) {
		seq_printf(m, "# This file contains timings for messages"
			      " that this node has executed as a server.\n");
	} else {
		seq_printf(m, "# This file contains timings for messages"
			      " that this node has sent as a client.\n");
	}

	/* Column Names and Formatting */
	seq_printf(m, "# %-16s %-16s %16s %16s %16s %16s %16s %8s\n",
		   "Operation", "Measurement", "Number", "Sum_us", "Average_us",
		   "Max_us", "Min_us", "Approx_%");

	return &timing_stats[*pos];
}

static void *dvs_debugfs_msg_timing_seq_next(struct seq_file *m, void *p,
					     loff_t *pos)
{
	struct dvs_timing_stats *timing_stats = m->private;

	if (++*pos >= RQ_DVS_END_V1)
		return NULL;

	return &timing_stats[*pos];
}

/*
 * Calculate a percentage using two numbers without floating point math.
 */
static uint64_t percentage(uint64_t numerator, uint64_t denominator)
{
	uint64_t remainder;
	uint64_t round_up = 0;

	if (denominator == 0)
		return 0;

	/* Round up if the remainder is large enough */
	remainder = (100 * numerator) % denominator;
	if (remainder >= denominator / 2)
		round_up = 1;

	return (100 * numerator) / denominator + round_up;
}

/*
 * This function is shared between the client and server versions of message
 * timing. The relevant stats array is set in the open function.
 */
static int dvs_debugfs_msg_timing_seq_show(struct seq_file *m, void *p)
{
	struct dvs_timing_stats *timing = (struct dvs_timing_stats *)p;
	char *fmt = "%-18s %-16s %16lu %16lu %16lu %16lu %16lu %8lu\n";

	spin_lock(&timing->sl);
	if (timing->count == 0 || timing->total.sum == 0) {
		seq_printf(m, fmt, timing->op_name, "Server_Overhead", 0L, 0L,
			   0L, 0L, 0L, 0L);
		seq_printf(m, fmt, timing->op_name, "File_System", 0L, 0L, 0L,
			   0L, 0L, 0L);
		seq_printf(m, fmt, timing->op_name, "Queue", 0L, 0L, 0L, 0L, 0L,
			   0L);
		if (m->private != dvs_server_timing_stats) {
			seq_printf(m, fmt, timing->op_name, "Network", 0L, 0L,
				   0L, 0L, 0L, 0L);
		}
		seq_printf(m, fmt, timing->op_name, "Total", 0L, 0L, 0L, 0L, 0L,
			   0L);
	} else {
		seq_printf(m, fmt, timing->op_name, "Server_Overhead",
			   timing->count, timing->overhead.sum,
			   timing->overhead.sum / timing->count,
			   timing->overhead.max, timing->overhead.min,
			   percentage(timing->overhead.sum, timing->total.sum));
		seq_printf(m, fmt, timing->op_name, "File_System",
			   timing->count, timing->fs.sum,
			   timing->fs.sum / timing->count, timing->fs.max,
			   timing->fs.min,
			   percentage(timing->fs.sum, timing->total.sum));
		seq_printf(m, fmt, timing->op_name, "Queue", timing->count,
			   timing->queue.sum, timing->queue.sum / timing->count,
			   timing->queue.max, timing->queue.min,
			   percentage(timing->queue.sum, timing->total.sum));

		if (m->private != dvs_server_timing_stats) {
			seq_printf(m, fmt, timing->op_name, "Network",
				   timing->count, timing->network.sum,
				   timing->network.sum / timing->count,
				   timing->network.max, timing->network.min,
				   percentage(timing->network.sum,
					      timing->total.sum));
		}

		seq_printf(m, fmt, timing->op_name, "Total", timing->count,
			   timing->total.sum, timing->total.sum / timing->count,
			   timing->total.max, timing->total.min,
			   percentage(timing->total.sum, timing->total.sum));
	}
	spin_unlock(&timing->sl);

	return 0;
}

static void dvs_debugfs_msg_timing_seq_stop(struct seq_file *m, void *p)
{
	return;
}

static struct file_operations dvs_debugfs_client_timing_operations = {
	open: dvs_debugfs_client_msg_timing_open,
	read: seq_read,
	write: dvs_debugfs_client_msg_timing_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_server_timing_operations = {
	open: dvs_debugfs_server_msg_timing_open,
	read: seq_read,
	write: dvs_debugfs_server_msg_timing_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_procfs_ssimap_operations = {
	open: dvs_procfs_ssimap_open,
	read: seq_read,
	write: dvs_procfs_ssimap_write,
	llseek: seq_lseek,
	release: dvs_procfs_ssimap_release,
};

static struct file_operations dvs_debugfs_maxnodes_operations = {
	open: dvs_debugfs_mn_open,
	read: seq_read,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_log_operations = {
	open: dvs_debugfs_log_open,
	read: seq_read,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_log_size_operations = {
	open: dvs_debugfs_log_size_open,
	read: seq_read,
	write: dvs_debugfs_log_size_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_rq_log_operations = {
	open: dvs_debugfs_rq_log_open,
	read: seq_read,
	write: dvs_debugfs_rq_log_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_rq_log_size_operations = {
	open: dvs_debugfs_rq_log_size_open,
	read: seq_read,
	write: dvs_debugfs_rq_log_size_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_rq_log_time_operations = {
	open: dvs_debugfs_rq_log_time_open,
	read: seq_read,
	write: dvs_debugfs_rq_log_time_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_fs_log_operations = {
	open: dvs_debugfs_fs_log_open,
	read: seq_read,
	write: dvs_debugfs_fs_log_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_fs_log_size_operations = {
	open: dvs_debugfs_fs_log_size_open,
	read: seq_read,
	write: dvs_debugfs_fs_log_size_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_fs_log_time_operations = {
	open: dvs_debugfs_fs_log_time_open,
	read: seq_read,
	write: dvs_debugfs_fs_log_time_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_sync_stats_operations = {
	open: dvs_debugfs_sync_stats_open,
	read: seq_read,
	write: dvs_debugfs_sync_stats_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_stats_operations = {
	open: dvs_debugfs_stats_open,
	read: seq_read,
	write: dvs_debugfs_stats_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_mount_info_operations = {
	open: dvs_debugfs_mount_info_open,
	read: seq_read,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_openfile_info_operations = {
	open: dvs_debugfs_openfile_info_open,
	read: seq_read,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_nodenames_operations = {
	open: dvs_debugfs_nodenames_open,
	read: seq_read,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_estale_stats_operations = {
	open: dvs_debugfs_estale_stats_open,
	read: seq_read,
	write: dvs_debugfs_estale_stats_write,
	release: dvs_debugfs_common_release,
};

static struct file_operations dvs_debugfs_drop_mount_caches_operations = {
	read: dvs_debugfs_drop_mount_caches_read,
	write: dvs_debugfs_drop_mount_caches_write,
};

static struct dvs_debugfs_info {
	int flag;
	struct inode *ip;
	char *buf;
} * winfop;

static int dvs_debugfs_init(void)
{
	int error;

	static struct dentry *dentry_log = NULL;
	static struct dentry *dentry_log_size = NULL;
	static struct dentry *dentry_fs_log_enabled = NULL;
	static struct dentry *dentry_fs_log_size = NULL;
	static struct dentry *dentry_fs_log_time = NULL;
	static struct dentry *dentry_rq_log = NULL;
	static struct dentry *dentry_rq_log_size = NULL;
	static struct dentry *dentry_rq_log_time = NULL;
	static struct dentry *dentry_estale_stats = NULL;
	static struct dentry *dentry_client_msg_timing_stats = NULL;
	static struct dentry *dentry_server_msg_timing_stats = NULL;
	static struct dentry *dentry_max_nodes = NULL;
	static struct dentry *dentry_sync_stats = NULL;
	static struct dentry *dentry_stats = NULL;
	static struct dentry *dentry_ssimap = NULL;

	STARTUP_VERSIONED_MSG("DVS debugfs");

	KDEBUG_INF(0, "DVS: %s: [%d]\n", __FUNCTION__, ssiproc_max_nodes);

#ifdef CONFIG_KATLAS
	dvs_alloc_instance = katlas_instance_create(
		"dvs_global",
		KATLAS_POISON | KATLAS_VMALLOC_FALLBACK | KATLAS_GUARD_PANIC);
#endif

	/* Create /sys/kernel/debug/dvs */
	dentry_dvs_debug = debugfs_create_dir(DVS_DEBUGFS_DIR, NULL);
	if (!dentry_dvs_debug) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/kernel/debug/%s\n",
		       __func__, DVS_DEBUGFS_DIR);
		return -ENODEV;
	}

	/* create mounts directory */
	if ((dvs_debugfs_mounts_dir = debugfs_create_dir(
		     DVS_DEBUGFS_MOUNTS_DIR, dentry_dvs_debug)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_MOUNTS_DIR);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* create statistics directory */
	if ((dvs_debugfs_stats_dir = debugfs_create_dir(
		     DVS_DEBUGFS_STATS_DIR, dentry_dvs_debug)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_MOUNTS_DIR);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create log entry */
	if ((dentry_log = debugfs_create_file(
		     DVS_DEBUGFS_LOG, S_IFREG | S_IRUSR, dentry_dvs_debug, NULL,
		     &dvs_debugfs_log_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_LOG);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create log_size_kb entry */
	if ((dentry_log_size = debugfs_create_file(
		     DVS_DEBUGFS_LOG_SIZE, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &dvs_log_size_kb,
		     &dvs_debugfs_log_size_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_LOG_SIZE);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create fs_log entry */
	if ((dentry_fs_log_enabled = debugfs_create_file(
		     DVS_DEBUGFS_FS_LOG, S_IFREG | S_IRUSR, dentry_dvs_debug,
		     &dvs_fs_log_enabled, &dvs_debugfs_fs_log_operations)) ==
	    NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_FS_LOG);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create fs_log_size_kb entry */
	if ((dentry_fs_log_size = debugfs_create_file(
		     DVS_DEBUGFS_FS_LOG_SIZE, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &dvs_fs_log_size_kb,
		     &dvs_debugfs_fs_log_size_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_FS_LOG_SIZE);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create fs_log_min_time_secs entry */
	if ((dentry_fs_log_time = debugfs_create_file(
		     DVS_DEBUGFS_FS_LOG_TIME, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &dvs_fs_log_min_time_secs,
		     &dvs_debugfs_fs_log_time_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_FS_LOG_TIME);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create rq_log entry */
	if ((dentry_rq_log = debugfs_create_file(
		     DVS_DEBUGFS_RQ_LOG, S_IFREG | S_IRUSR, dentry_dvs_debug,
		     &dvs_request_log_enabled,
		     &dvs_debugfs_rq_log_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_RQ_LOG);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create rq_log_size_kb entry */
	if ((dentry_rq_log_size = debugfs_create_file(
		     DVS_DEBUGFS_RQ_LOG_SIZE, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &dvs_request_log_size_kb,
		     &dvs_debugfs_rq_log_size_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_RQ_LOG_SIZE);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create rq_log_min_time_sec entry */
	if ((dentry_rq_log_time = debugfs_create_file(
		     DVS_DEBUGFS_RQ_LOG_TIME, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &dvs_request_log_min_time_secs,
		     &dvs_debugfs_rq_log_time_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_RQ_LOG_TIME);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create ESTALE stats entry */
	if ((dentry_estale_stats = debugfs_create_file(
		     DVS_DEBUGFS_ESTALE_STATS, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &global_estale_stats,
		     &dvs_debugfs_estale_stats_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_ESTALE_STATS);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create dvs_timing_stats entries */
	if ((dentry_client_msg_timing_stats = debugfs_create_file(
		     DVS_DEBUGFS_CLIENT_TIMING, S_IFREG | S_IRUGO | S_IWUSR,
		     dvs_debugfs_stats_dir, NULL,
		     &dvs_debugfs_client_timing_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_CLIENT_TIMING);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create dvs_timing_stats entries */
	if ((dentry_server_msg_timing_stats = debugfs_create_file(
		     DVS_DEBUGFS_SERVER_TIMING, S_IFREG | S_IRUGO | S_IWUSR,
		     dvs_debugfs_stats_dir, NULL,
		     &dvs_debugfs_server_timing_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_SERVER_TIMING);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create max-nodes entry */
	if ((dentry_max_nodes = debugfs_create_file(
		     DVS_DEBUGFS_MAX_NODES, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &ssiproc_max_nodes,
		     &dvs_debugfs_maxnodes_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_MAX_NODES);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create sync stats entry */
	if ((dentry_sync_stats = debugfs_create_file(
		     DVS_DEBUGFS_SYNC_STATS, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, NULL,
		     &dvs_debugfs_sync_stats_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_SYNC_STATS);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	init_rwsem(&dvs_debugfs_map_sem);

	/* Create ssi-map entry */
	if ((dentry_ssimap = debugfs_create_file(
		     DVS_PROCFS_NODEFILE, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, NULL, &dvs_procfs_ssimap_operations)) ==
	    NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_PROCFS_NODEFILE);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	/* Create deprecated stats entry */
	dvsdebug_stat_init(&aggregate_stats, -1);

	if ((dentry_stats = debugfs_create_file(
		     DVS_DEBUGFS_STATS, S_IFREG | S_IRUGO | S_IWUSR,
		     dentry_dvs_debug, &aggregate_stats,
		     &dvs_debugfs_stats_operations)) == NULL) {
		printk(KERN_ERR
		       "DVS: %s: cannot init /sys/kernel/debug/%s/%s\n",
		       __func__, DVS_DEBUGFS_DIR, DVS_DEBUGFS_STATS);
		error = -ENOMEM;
		goto dvs_debugfs_init_error;
	}

	aggregate_stats.stats_entry = dentry_stats;

	return 0;

dvs_debugfs_init_error:
	debugfs_remove_recursive(dentry_dvs_debug);
	return error;
}

static int __init dvs_procfs_init(void)
{
	struct proc_dir_entry *dvs_procfs_ssimap = NULL;
	int error;

	STARTUP_VERSIONED_MSG("DVS");

	KDEBUG_INF(0, "DVS: %s: [%d]\n", __func__, ssiproc_max_nodes);

	if (ssiproc_max_nodes == 0) {
		printk(KERN_ERR "DVS: Error: ssiproc_max_nodes == 0\n");
		/* no point in doing anything if we don't have any nodes */
		error = -EINVAL;
		goto dvs_procfs_init_error;
	}

	/* Initialize the message timing bits */
	dvs_timing_init();

	/* Create directories for knobs and dirs, and initialize */
	error = dvs_debugfs_init();
	if (error)
		goto dvs_procfs_init_error;
	error = create_dvs_sysfs_dirs();
	if (error)
		goto dvs_procfs_init_error;

	/* set up the dvs log size file */
	if (dvs_log_init(LOG_DVS_LOG, dvs_log_size_kb, "DVS log") != 0) {
		printk(KERN_ERR "DVS: %s cannot init log\n", __func__);
		error = -ENOMEM;
		goto dvs_procfs_init_error;
	}

	/* set up the rq log size file */
	if (dvs_log_init(LOG_RQ_LOG, dvs_request_log_size_kb, "DVS rq log") !=
	    0) {
		printk(KERN_ERR "DVS: %s cannot init log\n", __func__);
		error = -ENOMEM;
		goto dvs_procfs_init_error;
	}

	/* set up the fs log size file */
	if (dvs_log_init(LOG_FS_LOG, dvs_fs_log_size_kb, "DVS fs log") != 0) {
		printk(KERN_ERR "DVS: %s cannot init log\n", __func__);
		error = -ENOMEM;
		goto dvs_procfs_init_error;
	}

	/* create directory */
	if ((dvs_procfs_dir = proc_mkdir(DVS_PROCFS_DIR, NULL)) == NULL) {
		printk(KERN_ERR "DVS: %s: cannot init /proc/%s\n", __func__,
		       DVS_PROCFS_DIR);
		error = -ENOMEM;
		goto dvs_procfs_init_error;
	}

	/* Create ssi-map entry */
	if ((dvs_procfs_ssimap = proc_create(
		     DVS_PROCFS_NODEFILE, S_IFREG | S_IRUGO | S_IWUSR,
		     dvs_procfs_dir, &dvs_procfs_ssimap_operations)) == NULL) {
		printk(KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n", __func__,
		       DVS_PROCFS_DIR, DVS_PROCFS_NODEFILE);
		error = -ENOMEM;
		goto dvs_procfs_init_error;
	}

	ssi_sysctl_register();

	node_map = NULL;

	/* Create test entry -- NOOP in production*/
	dvsproc_test_init(dvs_procfs_dir);

	proc_set_user(dvs_procfs_ssimap, KUIDT_INIT(0), KGIDT_INIT(0));

#ifdef CONFIG_CRAY_TRACE
	craytrace_create_buf("DVS", dvs_trace_slots, &dvs_trace_idx);
#endif

	KDEBUG_INF(0, "DVS: dvsproc module loaded\n");
	return 0;

dvs_procfs_init_error:
	remove_dvs_sysfs_dirs();
	if (dentry_dvs_debug)
		debugfs_remove_recursive(dentry_dvs_debug);
	dvsproc_test_exit(dvs_procfs_dir); /* NOOP in production */
	if (dvs_procfs_ssimap)
		remove_proc_entry(DVS_PROCFS_NODEFILE, dvs_procfs_dir);
	if (dvs_procfs_dir)
		remove_proc_entry(DVS_PROCFS_DIR, NULL);
#ifdef CONFIG_KATLAS
	katlas_instance_destroy(dvs_alloc_instance);
#endif
	return error;
} /* dvs_procfs_init */

static void __exit dvs_procfs_exit(void)
{
	KDEBUG_INF(0, "DVS: %s: \n", __func__);

	remove_dvs_sysfs_dirs();
	if (dentry_dvs_debug)
		debugfs_remove_recursive(dentry_dvs_debug);

	dvsproc_test_exit(dvs_procfs_dir); /* NOOP in production */
	dvs_procfs_lock_node_map(DVSSYS_LOCK_WRITE);
	remove_proc_entry(DVS_PROCFS_NODEFILE, dvs_procfs_dir);
	remove_proc_entry(DVS_PROCFS_DIR, NULL);

	if (node_map) {
		dvs_procfs_free_node_map();
	}
	dvs_procfs_unlock_node_map(DVSSYS_LOCK_WRITE);

	ssi_sysctl_unregister();

#ifdef CONFIG_CRAY_TRACE
	if (dvs_trace_idx != CRAYTRACE_BUF_UTRACE) {
		craytrace_destroy_buf(dvs_trace_idx);
	}
#endif

	dvs_log_exit(LOG_FS_LOG);
	dvs_log_exit(LOG_RQ_LOG);
	dvs_log_exit(LOG_DVS_LOG);

#ifdef CONFIG_KATLAS
	katlas_instance_destroy(dvs_alloc_instance);
#endif

	KDEBUG_INF(0, "DVS: dvsproc module unloaded\n");

} /* dvs_procfs_exit */

static int dvs_procfs_ssimap_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_procfs_ssimap_ops);
} /* dvs_procfs_ssimap_open */

static int dvs_debugfs_common_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static int dvs_debugfs_mn_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_maxnodes_ops);
}

static int dvs_debugfs_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_log_ops);
}

static int dvs_debugfs_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_log_size_ops);
}

static int dvs_debugfs_rq_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_rq_log_ops);
}

static int dvs_debugfs_rq_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_rq_log_size_ops);
}

static int dvs_debugfs_rq_log_time_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_rq_log_time_ops);
}

static int dvs_debugfs_fs_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_fs_log_ops);
}

static int dvs_debugfs_fs_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_fs_log_size_ops);
}

static int dvs_debugfs_fs_log_time_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_fs_log_time_ops);
}

static int dvs_debugfs_estale_stats_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_estale_stats_ops);
}

static int dvs_debugfs_sync_stats_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvs_debugfs_sync_stats_ops);
}

static int dvs_debugfs_client_msg_timing_open(struct inode *inode,
					      struct file *file)
{
	int ret;
	struct seq_file *seq;

	if ((ret = seq_open(file, &dvs_debugfs_msg_timing_seq_ops)))
		return ret;

	seq = file->private_data;
	if (seq == NULL) {
		printk(KERN_ERR "seq is NULL!\n");
		return -EINVAL;
	}
	seq->private = dvs_client_timing_stats;
	return 0;
}

static int dvs_debugfs_server_msg_timing_open(struct inode *inode,
					      struct file *file)
{
	int ret;
	struct seq_file *seq;

	if ((ret = seq_open(file, &dvs_debugfs_msg_timing_seq_ops)))
		return ret;

	seq = file->private_data;
	seq->private = dvs_server_timing_stats;
	return 0;
}

static int dvs_debugfs_stats_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &dvs_debugfs_stats_ops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private; /* set in dvsproc_add_mountpoint() */
	return 0;
}

static ssize_t dvs_debugfs_stats_write(struct file *file, const char *buffer,
				       size_t count, loff_t *offp)
{
	struct seq_file *seq = file->private_data;
	struct dvsdebug_stat *stats = seq->private;
	int rtn;
	char str[128];

	if (count >= sizeof(str)) {
		return -EINVAL;
	}

	memset(str, 0, sizeof(str));
	if (copy_from_user(str, buffer, count)) {
		return -EFAULT;
	}

	rtn = dvsdebug_stat_set_control(stats, str);
	return (rtn < 0) ? rtn : count;
}

static int dvs_debugfs_mount_info_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &dvs_debugfs_mount_info_ops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private; /* set in dvsproc_add_mountpoint() */
	return 0;
}

static int dvs_debugfs_openfile_info_open(struct inode *inode,
					  struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &dvs_debugfs_openfile_info_ops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private; /* set in dvsproc_add_mountpoint() */
	return 0;
}

static int dvs_debugfs_nodenames_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &dvs_debugfs_nodenames_ops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private; /* set in dvsproc_add_mountpoint() */
	return 0;
}

static void *dvs_debugfs_common_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)m->private); /* set in dvs_debugfs_XXX_open() */
}

static void *dvs_procfs_ssimap_seq_start(struct seq_file *m, loff_t *pos)
{
	struct ssi_node_map *tnp;
	loff_t n = *pos;

	KDEBUG_INF(0, "DVS: %s: pos[%lld] n[%lld]\n", __func__, *pos, n);

	dvs_procfs_lock_node_map(DVSSYS_LOCK_READ);

	/* sanity check the position (logical node number) the user asked for */
	if (n >= ssiproc_max_nodes)
		return (NULL);

	tnp = &node_map[n];

	return ((void *)tnp);

} /* dvs_procfs_ssimap_seq_start */

static void *dvs_procfs_ssimap_seq_next(struct seq_file *m, void *p,
					loff_t *pos)
{
	loff_t n = ++*pos;
	struct ssi_node_map *tnp = (struct ssi_node_map *)p;

	if (n >= ssiproc_max_nodes)
		return (NULL);

	tnp = (void *)&node_map[n];

	return (tnp);

} /*dvs_procfs_ssimap_seq_next */

static void dvs_procfs_ssimap_seq_stop(struct seq_file *m, void *p)
{
	dvs_procfs_unlock_node_map(DVSSYS_LOCK_READ);
} /* siiproc_ssimap_seq_stop */

/*
 * N.B. Assumes that the dvs_debugfs_map_sem write lock is held
 */
static void dvs_procfs_free_node_map(void)
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
			kfree_ssi(mp->name);

		if (mp->tok)
			kfree_ssi(mp->tok);
	}

	vfree_ssi(node_map);

} /* dvs_procfs_free_node_map */

static int dvs_procfs_ssimap_seq_show(struct seq_file *m, void *p)
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

} /* dvs_procfs_ssimap_seq_show */

static void *dvs_debugfs_mn_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&ssiproc_max_nodes);
}

static void *dvs_debugfs_common_seq_next(struct seq_file *m, void *p,
					 loff_t *pos)
{
	return (NULL);
}

static void dvs_debugfs_common_seq_stop(struct seq_file *m, void *p)
{
	return;
}

static int dvs_debugfs_mn_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", ssiproc_max_nodes);

	return 0;
}

static void *dvs_debugfs_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return dvs_log_handle(LOG_DVS_LOG);
}

static void *dvs_debugfs_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_log_size_kb);
}

static void *dvs_debugfs_rq_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (!dvs_request_log_enabled)
		return (NULL);

	return dvs_log_handle(LOG_RQ_LOG);
}

static void *dvs_debugfs_rq_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_request_log_size_kb);
}

static void *dvs_debugfs_rq_log_time_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_request_log_min_time_secs);
}

static void *dvs_debugfs_fs_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	if (!dvs_fs_log_enabled)
		return (NULL);

	return dvs_log_handle(LOG_FS_LOG);
}

static void *dvs_debugfs_fs_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_fs_log_size_kb);
}

static void *dvs_debugfs_fs_log_time_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&dvs_fs_log_min_time_secs);
}

static void *dvs_debugfs_estale_stats_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)&global_estale_stats);
}

static void *dvs_debugfs_sync_stats_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return ((void *)sync_ops);
}

static int dvs_debugfs_log_seq_show(struct seq_file *m, void *p)
{
	return (dvs_log_print(LOG_DVS_LOG, m));
}

static int dvs_debugfs_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_DVS_LOG));
	return 0;
}

static int dvs_debugfs_rq_log_seq_show(struct seq_file *m, void *p)
{
	return (dvs_log_print(LOG_RQ_LOG, m));
}

static int dvs_debugfs_rq_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_RQ_LOG));
	return 0;
}

static int dvs_debugfs_rq_log_time_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_request_log_min_time_secs);
	return 0;
}

static int dvs_debugfs_fs_log_seq_show(struct seq_file *m, void *p)
{
	return (dvs_log_print(LOG_FS_LOG, m));
}

static int dvs_debugfs_fs_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_FS_LOG));
	return 0;
}

static int dvs_debugfs_fs_log_time_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_fs_log_min_time_secs);
	return 0;
}

static int dvs_debugfs_estale_stats_seq_show(struct seq_file *m, void *p)
{
	seq_printf(
		m, "Failed ESTALE retries: %ld\n",
		atomic64_read(&global_estale_stats.stats[ESTALE_RETRY_FAIL]));
	seq_printf(m, "Failed ESTALE failovers: %ld\n",
		   atomic64_read(
			   &global_estale_stats.stats[ESTALE_FAILOVER_FAIL]));
	seq_printf(
		m, "Successful ESTALE retries: %ld\n",
		atomic64_read(&global_estale_stats.stats[ESTALE_RETRY_PASS]));
	seq_printf(m, "Successful ESTALE failovers: %ld\n",
		   atomic64_read(
			   &global_estale_stats.stats[ESTALE_FAILOVER_PASS]));

	return 0;
}

static int dvs_debugfs_sync_stats_seq_show(struct seq_file *m, void *p)
{
	if (!sync_ops || !sync_ops->sync_stats_print)
		return -EINVAL;

	sync_ops->sync_stats_print(m);
	return 0;
}

static int dvs_debugfs_stats_seq_show(struct seq_file *m, void *p)
{
	dvsdebug_stat_print(m, (struct dvsdebug_stat *)p);
	return 0;
}

static int dvs_debugfs_mount_info_seq_show(struct seq_file *m, void *p)
{
	struct incore_upfs_super_block *icsb =
		(struct incore_upfs_super_block *)p;
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
			seq_printf(
				m, " %s",
				SSI_NODE_NAME(
					icsb->data_servers[i].node_map_index));
	}
	seq_printf(m, "\n");

	seq_printf(m, "inactive_nodes");
	for (i = 0; i < icsb->data_servers_len; i++) {
		if (!icsb->data_servers[i].up)
			seq_printf(
				m, " %s",
				SSI_NODE_NAME(
					icsb->data_servers[i].node_map_index));
	}
	seq_printf(m, "\n");

	if (icsb->loadbalance)
		seq_printf(m, "loadbalance_node %s\n",
			   SSI_NODE_NAME(icsb->loadbalance_node));

	for (i = 0; i < icsb->data_servers_len; i++) {
		if (icsb->data_servers[i].magic != -1)
			break;
	}
	seq_printf(m, "remote-magic 0x%lx\n", icsb->data_servers[i].magic);

	return 0;
}

static int dvs_debugfs_openfile_info_seq_show(struct seq_file *m, void *p)
{
	struct incore_upfs_super_block *icsb =
		(struct incore_upfs_super_block *)p;

	seq_printf(m, "open files:  %d\n", atomic_read(&icsb->open_dvs_files));

	return 0;
}

static int dvs_debugfs_nodenames_seq_show(struct seq_file *m, void *p)
{
	struct incore_upfs_super_block *icsb =
		(struct incore_upfs_super_block *)p;
	int i;

	for (i = 0; i < icsb->data_servers_len; i++) {
		if (i > 0)
			seq_printf(m, ":");
		seq_printf(m, "%s",
			   node_map[icsb->data_servers[i].node_map_index].name);
	}

	seq_printf(m, "\n");

	return 0;
}

static void dvsproc_rq_log_set_control(unsigned int control)
{
	if (!control) {
		dvs_request_log_enabled = 0;
	} else if (control & ~DVS_DEBUGFS_RQ_LOG_CONTROL_VALID_MASK) {
		printk(KERN_INFO "DVS: unknown request log control %u\n",
		       control);
	} else {
		/* process the selected control bits */

		if (control & DVS_DEBUGFS_RQ_LOG_CONTROL_RESET)
			dvs_log_clear(LOG_RQ_LOG);

		if (control & DVS_DEBUGFS_RQ_LOG_CONTROL_ENABLE)
			dvs_request_log_enabled = 1;
	}
}

static ssize_t dvs_debugfs_rq_log_write(struct file *file, const char *buffer,
					size_t count, loff_t *offp)
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

static void dvsproc_fs_log_set_control(unsigned int control)
{
	if (!control) {
		dvs_fs_log_enabled = 0;
	} else if (control & ~DVS_DEBUGFS_FS_LOG_CONTROL_VALID_MASK) {
		printk(KERN_INFO "DVS: unknown fs log control %u\n", control);
	} else {
		/* process the selected control bits */

		if (control & DVS_DEBUGFS_FS_LOG_CONTROL_RESET)
			dvs_log_clear(LOG_FS_LOG);

		if (control & DVS_DEBUGFS_FS_LOG_CONTROL_ENABLE)
			dvs_fs_log_enabled = 1;
	}
}

static ssize_t dvs_debugfs_fs_log_write(struct file *file, const char *buffer,
					size_t count, loff_t *offp)
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

static ssize_t dvs_debugfs_log_size_write(struct file *file, const char *buffer,
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

static ssize_t dvs_debugfs_rq_log_size_write(struct file *file,
					     const char *buffer, size_t count,
					     loff_t *offp)
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

static ssize_t dvs_debugfs_fs_log_size_write(struct file *file,
					     const char *buffer, size_t count,
					     loff_t *offp)
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

static ssize_t dvs_debugfs_rq_log_time_write(struct file *file,
					     const char *buffer, size_t count,
					     loff_t *offp)
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

static ssize_t dvs_debugfs_fs_log_time_write(struct file *file,
					     const char *buffer, size_t count,
					     loff_t *offp)
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

static ssize_t dvs_debugfs_sync_stats_write(struct file *file,
					    const char *buffer, size_t count,
					    loff_t *offp)
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

static ssize_t dvs_debugfs_estale_stats_write(struct file *file,
					      const char *buffer, size_t count,
					      loff_t *offp)
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
		atomic64_set(&global_estale_stats.stats[ESTALE_FAILOVER_FAIL],
			     0);
		atomic64_set(&global_estale_stats.stats[ESTALE_FAILOVER_PASS],
			     0);
	}

	return count;
}

/*
 * Set the attrcache_revalidation_time to the current time.
 * This forces revalidation of each inode in the mount point.
 */
static void ssiproc_drop_mount_attr_cache(struct incore_upfs_super_block *icsb)
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
static void ssiproc_drop_all_attr_cache(void)
{
	struct list_head *p;
	struct incore_upfs_super_block *icsb;
	down(&dvs_super_blocks_sema);
	list_for_each (p, &dvs_super_blocks) {
		icsb = list_entry(p, struct incore_upfs_super_block, list);
		ssiproc_drop_mount_attr_cache(icsb);
	}
	up(&dvs_super_blocks_sema);
}

/*
 * Purge any cached values in the mount hash list
 */
static void drop_mount_path_hash_cache(void)
{
	struct mount_hash_entry *entry = NULL, *entry_tmp = NULL;

	write_lock(&dvs_mount_hash_rwlock);
	list_for_each_entry_safe (entry, entry_tmp, &dvs_mount_hash_list,
				  list) {
		list_del(&entry->list);
		kfree_ssi(entry);
	}
	write_unlock(&dvs_mount_hash_rwlock);
}

static ssize_t dvs_debugfs_drop_mount_caches_write(struct file *fp,
						   const char *buffer,
						   size_t count, loff_t *offset)
{
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
	if (!icsb) {
		ssiproc_drop_all_attr_cache();
		drop_mount_path_hash_cache();
	} else {
		ssiproc_drop_mount_attr_cache(icsb);
	}
	return count;
}

static ssize_t dvs_debugfs_drop_mount_caches_read(struct file *fp,
						  char *user_buffer,
						  size_t count, loff_t *offset)
{
	char buf[64];
	ssize_t bytes_written;
	struct incore_upfs_super_block *icsb;
	if (*offset > 0)
		return 0;
	/* Need 20 to express a 64 bit integer, plus newline */
	if (count < 22)
		return -EFBIG;
	icsb = file_inode(fp)->i_private;
	if (!icsb) {
		printk(KERN_ERR "DVS: %s: could not find inode\n", __func__);
		bytes_written = 0;
	} else
		bytes_written = snprintf(buf, sizeof(buf), "%lu\n",
					 icsb->attrcache_revalidate_time);
	if (copy_to_user(user_buffer, buf, bytes_written + 1))
		return -EFAULT;
	*offset += bytes_written;
	return bytes_written;
}

static ssize_t dvs_procfs_ssimap_write(struct file *file, const char *buffer,
				       size_t count, loff_t *offp)
{
	int ret = count;
	loff_t pos = *offp;
	struct inode *inode = file_inode(file)->i_mapping->host;

	KDEBUG_INF(0, "DVS: %s: 0x%p 0x%p %ld %lld\n", __func__, file, inode,
		   count, *offp);

	inode_lock(inode);

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EACCES;
		goto out;
	}

	if (winfop == NULL) {
		if (count > DVSSYS_MAX_USER_INPUT) {
			ret = -EFBIG;
			goto out;
		}
		winfop = (struct dvs_debugfs_info *)vmalloc_ssi(
			DVSSYS_MAX_USER_INPUT);
		if (!winfop) {
			ret = -ENOMEM;
			goto out;
		}

		winfop->buf =
			(char *)(winfop + sizeof(struct dvs_debugfs_info));
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

	if ((pos + count) > DVSSYS_MAX_USER_INPUT) {
		ret = -EFBIG;
		vfree_ssi(winfop);
		goto out;
	}
	if (copy_from_user((winfop->buf + pos), buffer, count)) {
		ret = -EFAULT;
		vfree_ssi(winfop);
		goto out;
	}
	*offp = pos + count;
	if ((pos + count) > inode->i_size) {
		inode->i_size = pos + count;
	}
out:
	inode_unlock(inode);
	return (ret);

} /* dvs_procfs_ssimap_write */

static int dvs_procfs_ssimap_release(struct inode *ip, struct file *fp)
{
	struct ssi_node_map *tmap;
	int ret = 0;

	KDEBUG_INF(0, "DVS: %s: 0x%p 0x%p\n", __func__, ip, fp);

	if ((winfop) && (winfop->buf) && (winfop->flag == 1) &&
	    (winfop->ip == ip)) {
		if (ip->i_size > DVSSYS_MAX_USER_INPUT) {
			ret = -EFBIG;
		} else if (node_map == NULL) {
			tmap = dvs_procfs_parse_mapfile(winfop->buf, ip->i_size,
							&ret);
			if (tmap) {
				dvs_procfs_lock_node_map(DVSSYS_LOCK_WRITE);
				dvs_procfs_free_node_map();
				node_map = tmap;
				dvs_procfs_unlock_node_map(DVSSYS_LOCK_WRITE);
			} else {
				printk(KERN_ERR "DVS: %s: parse mapfile "
						"failure\n",
				       __func__);
				ret = -EINVAL;
			}
		}
		/* If node_map != NULL, just ignore, return good status */
		vfree_ssi(winfop);
		winfop = NULL;
	}
	seq_release(ip, fp);
	return (ret);

} /* dvs_procfs_ssimap_release */

int dvs_procfs_lock_node_map(int flag)
{
	if (flag & DVSSYS_LOCK_READ) {
		down_read(&dvs_debugfs_map_sem);
	} else if (flag & DVSSYS_LOCK_WRITE) {
		down_write(&dvs_debugfs_map_sem);
	} else {
		/* unknown lock request */
		return (1);
	}

	return (0);
} /* dvs_procfs_lock_node_map */

int dvs_procfs_unlock_node_map(int flag)
{
	if (flag & DVSSYS_LOCK_READ) {
		up_read(&dvs_debugfs_map_sem);
	} else if (flag & DVSSYS_LOCK_WRITE) {
		up_write(&dvs_debugfs_map_sem);
	} else {
		/* unknown lock request */
		return (1);
	}

	return (0);
} /* dvs_procfs_unlock_node_map */

/*
 * Creates a /sys/kernel/debug/dvs/mounts/X entry
 */
int dvsproc_add_mountpoint(struct incore_upfs_super_block *icsb)
{
	char buf[20];
	int mount_num;
	struct dvsdebug_stat *p;

	p = kmalloc_ssi(sizeof(struct dvsdebug_stat), GFP_KERNEL);
	if (p) {
		mount_num = atomic_inc_return(&dvs_debugfs_mounts);
		dvsdebug_stat_init(p, mount_num);

		snprintf(buf, sizeof(buf), "%d", mount_num);
		p->mount_dir = debugfs_create_dir(buf, dvs_debugfs_mounts_dir);
		if (p->mount_dir) {
			p->mount_entry = debugfs_create_file(
				DVS_DEBUGFS_MOUNT, S_IFREG | S_IRUGO | S_IWUSR,
				p->mount_dir, icsb,
				&dvs_debugfs_mount_info_operations);
			if (!p->mount_entry) {
				debugfs_remove_recursive(p->mount_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->stats_entry = debugfs_create_file(
				DVS_DEBUGFS_STATS, S_IFREG | S_IRUGO | S_IWUSR,
				p->mount_dir, p, &dvs_debugfs_stats_operations);
			if (!p->stats_entry) {
				debugfs_remove_recursive(p->mount_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->openfile_entry = debugfs_create_file(
				DVS_DEBUGFS_OPENFILES,
				S_IFREG | S_IRUGO | S_IWUSR, p->mount_dir, icsb,
				&dvs_debugfs_openfile_info_operations);
			if (!p->openfile_entry) {
				debugfs_remove_recursive(p->mount_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->nodenames_entry = debugfs_create_file(
				DVS_DEBUGFS_NODENAMES,
				S_IFREG | S_IRUGO | S_IWUSR, p->mount_dir, icsb,
				&dvs_debugfs_nodenames_operations);
			if (!p->nodenames_entry) {
				debugfs_remove_recursive(p->mount_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

			p->drop_caches_entry = debugfs_create_file(
				DVS_DEBUGFS_DROP_CACHES,
				S_IFREG | S_IRUGO | S_IWUSR, p->mount_dir, icsb,
				&dvs_debugfs_drop_mount_caches_operations);
			if (!p->drop_caches_entry) {
				debugfs_remove_recursive(p->mount_dir);
				kfree_ssi(p);
				goto add_mount_error;
			}

		} else {
			kfree_ssi(p);
			goto add_mount_error;
		}
	} else {
add_mount_error:
		printk(KERN_ERR "DVS: %s: cannot init %s/%s/%s\n", __func__,
		       DVS_DEBUGFS_MOUNTS_DIR, "0", DVS_DEBUGFS_STATS);
		return -ENOMEM;
	}

	/* store per-mountpoint stats pointer in superblock */
	icsb->stats = p;

	return 0;
}

int dvsproc_remove_mountpoint(struct incore_upfs_super_block *icsb)
{
	struct dvsdebug_stat *p;

	p = icsb->stats;
	debugfs_remove_recursive(p->mount_dir);
	kfree_ssi(p);

	return 0;
}

static int node_map_index_in_server(int index, struct dvs_server *servers,
				    int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (index == servers[i].node_map_index)
			return 1;
	}
	return 0;
}

/* Count unique servers between the data and metadata servers */
static int unique_servers(struct incore_upfs_super_block *icsb)
{
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

void dvsproc_mount_options_print(struct seq_file *m,
				 struct incore_upfs_super_block *icsb)
{
	int i;

	/*
	 * Compute number of node names that will fit, reserving half of the
	 * space for the two pathnames prepended in the /proc/self/mounts file.
	 * If we have more than this, we omit the "nodefile=" option,
	 * but the full list is still available in the nodenames /proc file.
	 */
	const int max_options_len = (4096 - 2) / 2; /* Maximum length of
						   generated options string.
						   Constraint comes from buffer
						   size used by glibc
						   getmntent(), minu "\n" and
						   zero byte.  */
	const int max_cname_len = 12; /* Maximum length of cnames.  Allow space
					 for up to 99 rows x 99 columns of
					 cabinets. */
	const int max_int_len = 10; /* Maximum length of a signed int in decimal
				       format */
	const int other_opts_reserve = /* Reserve space for the other options,
					  conservatively computed from the
					  longest variant of each. */
		sizeof("options (rw") - 1 + sizeof(",blksize=") + max_int_len -
		1 + sizeof(",nodename=") - 1 +
		sizeof(",nodefile=/proc/fs/dvs/mounts//nodenames") +
		max_int_len - 1 +
		sizeof(",statsfile=/proc/fs/dvs/mounts//stats") + max_int_len -
		1 + sizeof(",attrcache_timeout=") +
		sizeof(icsb->attrcache_timeout_str) +
		sizeof(",noparallelwrite") - 1 + sizeof(",nodwfs") - 1 +
		sizeof(",nodwcfs") - 1 + sizeof(",nomultifsync") - 1 +
		sizeof(",nocache") - 1 + sizeof(",nodatasync") - 1 +
		sizeof(",noclosesync") - 1 + sizeof(",noretry") - 1 +
		sizeof(",nofailover") - 1 + sizeof(",nouserenv") - 1 +
		sizeof(",noclusterfs") - 1 + sizeof(",nokillprocess") - 1 +
		sizeof(",noatomic") - 1 + sizeof(",nodeferopens") - 1 +
		sizeof(",no_distribute_create_ops") - 1 +
		sizeof(",no_ro_cache") - 1 + sizeof(",cache_read_sz=") +
		max_int_len - 1 + sizeof(",noloadbalance") - 1 +
		sizeof(",maxnodes=") + max_int_len - 1 +
		sizeof(",metastripewidth=") + max_int_len - 1 +
		sizeof(",nnodes=") + max_int_len - 1 + sizeof(",magic=0x") +
		16 - 1 + sizeof(",nohash_on_nid") - 1 +
		sizeof(",hash=jenkins") - 1;
	const int max_inline_nodes =
		(max_options_len - other_opts_reserve) / (max_cname_len + 1);

	seq_printf(m, ",blksize=%d", icsb->bsz);
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
		seq_printf(m, ",no_ro_cache");
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
		seq_printf(m, ",ino_ignore_prefix_depth=%d",
			   icsb->ino_ignore_prefix_depth);
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
	} else {
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
	seq_printf(m, ",nodefile=/proc/fs/dvs/mounts/%d/nodenames",
		   icsb->stats->mountpoint_id);
	if (icsb->meta_servers != icsb->data_servers) {
		seq_printf(m, ",mds=");
		for (i = 0; i < icsb->meta_servers_len; i++) {
			if (i > 0)
				seq_printf(m, ":");
			seq_printf(
				m, "%s",
				node_map[icsb->meta_servers[i].node_map_index]
					.name);
		}
	}
	if (icsb->data_servers_len <= max_inline_nodes) {
		seq_printf(m, ",nodename=");
		for (i = 0; i < icsb->data_servers_len; i++) {
			if (i > 0)
				seq_printf(m, ":");
			seq_printf(
				m, "%s",
				node_map[icsb->data_servers[i].node_map_index]
					.name);
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

MODULE_LICENSE("GPL");
module_init(dvs_procfs_init);
module_exit(dvs_procfs_exit);

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
EXPORT_SYMBOL(dvs_procfs_parse_mapfile);
EXPORT_SYMBOL(dvs_procfs_get_my_nodeid);
EXPORT_SYMBOL(dvs_procfs_get_max_nodes);
EXPORT_SYMBOL(dvs_procfs_lock_node_map);
EXPORT_SYMBOL(dvs_procfs_unlock_node_map);
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
#ifdef CONFIG_KATLAS
EXPORT_SYMBOL(dvs_alloc_instance);
#endif
