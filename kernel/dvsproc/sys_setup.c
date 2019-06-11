/*
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
 * This file creates the directory /sys/fs/dvs.
 * This directory hosts the user-facing interfaces for DVS.
 */

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <asm/uaccess.h>

#include "common/ssi_proc.h"
#include "common/kernel/usiipc.h"
#include "common/ssi_sysctl.h"
#include "dvs/kernel/usifile.h"
#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"
#include "common/dvsproc_timing_stat.h"
#include "common/sys_setup.h"

void (*dvs_close_quiesced_files_func)(struct quiesced_dir *) = NULL;
EXPORT_SYMBOL(dvs_close_quiesced_files_func);

/* List of quiesced directories */
LIST_HEAD(quiesced_dirs);
EXPORT_SYMBOL(quiesced_dirs);
/* Semaphore protecting quiesce operations */
DECLARE_RWSEM(quiesce_barrier_rwsem);
EXPORT_SYMBOL(quiesce_barrier_rwsem);

static ssize_t quiesce_write(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buffer, size_t count);
static ssize_t quiesce_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf);

static void debug_to_string(unsigned long debug_val, char *buff);
static ssize_t debug_mask_write(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buffer,
				size_t count);
static ssize_t estale_max_retry_write(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buffer, size_t count);
static ssize_t estale_timeout_write(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buffer, size_t count);
static ssize_t sync_num_threads_write(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buffer, size_t count);
static ssize_t sync_timeout_write(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buffer, size_t count);
static ssize_t sync_period_write(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buffer, size_t count);
static ssize_t drop_caches_write(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buffer, size_t count);
static ssize_t debug_mask_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf);
static ssize_t estale_max_retry_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf);
static ssize_t estale_timeout_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf);
static ssize_t sync_num_threads_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf);
static ssize_t sync_timeout_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf);
static ssize_t sync_period_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf);
static ssize_t drop_caches_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf);
static struct kobj_attribute attr_debug;
static struct kobj_attribute attr_estale_max_retry;
static struct kobj_attribute attr_estale_timeout;
static struct kobj_attribute attr_sync_num_threads;
static struct kobj_attribute attr_sync_dirty_timeout_secs;
static struct kobj_attribute attr_sync_period_secs;
static struct kobj_attribute attr_quiesce;
static struct kobj_attribute attr_drop_caches;
static struct kobject *dvs_kobj;

/*
 * Allocate and populate a quiesced directory
 */
struct quiesced_dir *create_qdir(char *dir)
{
	int len;
	char *dir_copy = NULL;
	struct quiesced_dir *qdir = NULL;

	if (dir == NULL)
		return ERR_PTR(-EINVAL);

	len = strlen(dir);
	if ((dir_copy = kmalloc_ssi(len + 2, GFP_KERNEL)) == NULL)
		return ERR_PTR(-ENOMEM);
	if ((qdir = kmalloc_ssi(sizeof(struct quiesced_dir), GFP_KERNEL)) ==
	    NULL) {
		kfree_ssi(dir_copy);
		return ERR_PTR(-ENOMEM);
	}
	/* Make sure the directory ends in a / */
	strncpy(dir_copy, dir, len + 1);
	if (dir[len - 1] != '/') {
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
void destroy_qdir(struct quiesced_dir *qdir)
{
	struct remote_ref *rr, *rr_tmp;

	/*
	 * Each of these remote refs already has a refcount of zero from
	 * close_all_quiesced_files. No rr_ref_puts are required before
	 * freeing.
	 */
	list_for_each_entry_safe (rr, rr_tmp, &qdir->quiesced_rr_list, rr_lh) {
		list_del(&rr->rr_lh);
		KDEBUG_QSC(0, "Freeing remote ref %p from client %s\n", rr,
			   SSI_NODE_NAME(rr->node));
		kfree_ssi(rr);
	}
	kfree_ssi(qdir->dir);
	kfree_ssi(qdir);
}

int do_dir_quiesce(char *quiesce_dir)
{
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
	list_for_each_entry (qdir, &quiesced_dirs, quiesced_dirs_lh) {
		if (!strcmp(qdir->dir, new_qdir->dir)) {
			up_read(&quiesce_barrier_rwsem);
			kfree_ssi(new_qdir);
			printk("DVS: Could not quiesce %s: Directory is "
			       "already quiesced\n",
			       quiesce_dir);
			return 0;
		}
	}
	up_read(&quiesce_barrier_rwsem);

	printk("DVS: Quiescing directory %s. Waiting for outstanding requests "
	       "to finish before continuing.\n",
	       quiesce_dir);
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

int do_dir_unquiesce(char *given_dir)
{
	int len;
	char *quiesce_dir = given_dir;
	struct quiesced_dir *qdir, *qdir_tmp, *rdir = NULL;

	len = strlen(given_dir);

	/* Add a trailing slash if not given */
	if (given_dir[len - 1] != '/') {
		if ((quiesce_dir = kmalloc_ssi(len + 2, GFP_KERNEL)) == NULL)
			return -ENOMEM;
		snprintf(quiesce_dir, len + 2, "%s/", given_dir);
	}

	/* Don't hold quiesce_barrier_rwsem write lock to just read the list */
	down_read(&quiesce_barrier_rwsem);
	list_for_each_entry_safe (qdir, qdir_tmp, &quiesced_dirs,
				  quiesced_dirs_lh) {
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
	list_for_each_entry_safe (qdir, qdir_tmp, &quiesced_dirs,
				  quiesced_dirs_lh) {
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

static ssize_t quiesce_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	struct quiesced_dir *qdir;

	/* If list of quiesced dirs is too long, print remainder to kernel log
	 */
	int print_to_kernel_log = 0;

	buf[0] = '\0';

	list_for_each_entry (qdir, &quiesced_dirs, quiesced_dirs_lh) {
		if (!print_to_kernel_log) {
			if (qdir->dir_len + strlen(buf) + 6 > PAGE_SIZE) {
				printk(KERN_ERR
				       "DVS: %s: list of quiesced"
				       "directories is too long, printing remainder"
				       "to kernel log\n",
				       __FUNCTION__);
				print_to_kernel_log = 1;
				strcat(buf, "...\n");
			} else {
				strcat(buf, qdir->dir);
				strcat(buf, "\n");
			}
		}
		if (print_to_kernel_log) {
			printk(KERN_INFO "DVS: %s: quiesced directory: %s\n",
			       __FUNCTION__, qdir->dir);
		}
	}
	if (print_to_kernel_log)
		printk(KERN_INFO "DVS: %s: end of quiesced directory list",
		       __FUNCTION__);

	return strlen(buf);
}

#ifndef list_next_entry
/* list_next_entry not defined in SLES 11 */
#define list_next_entry(pos, member)                                           \
	list_entry(pos->member.next, typeof(*pos), member)
#endif

static ssize_t quiesce_write(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buffer, size_t count)
{
	int ret = 0;
	char *input = NULL;
	char *dir;

	if ((input = kmalloc_ssi(count + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	strncpy(input, buffer, count);

	input[count] = '\0';
	if (input[count - 1] == '\n')
		input[count - 1] = '\0';

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

LIST_HEAD(dvs_super_blocks);
EXPORT_SYMBOL(dvs_super_blocks);
struct semaphore dvs_super_blocks_sema;
EXPORT_SYMBOL(dvs_super_blocks_sema);

/*
 * Because these variables affect how DVS operates, their interfaces
 * are located in /sys/fs/dvs. By contrast, interfaces meant primarily
 * for debugging and logging purposes are located in /sys/kernel/debug/dvs.
 */
unsigned long dvs_debug_mask = 0UL;
unsigned int estale_max_retry = ESTALE_MAX_RETRY;
unsigned int estale_timeout_secs = ESTALE_TIMEOUT_SECS;

static struct sync_proc_ops *sync_ops = NULL;

/* Tests if a string represents a valid base 10 or base 16 number. */
int valid_number(char *str)
{
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

/**
 * Create a string listing which debugging options are applied.
 *
 * @param debug_val the integer debug mask
 * @param buff the character buffer to be written to
 */
static void debug_to_string(unsigned long debug_val, char *buff)
{
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

/*
 * Set the attrcache_revalidation_time to the current time.
 * This forces revalidation of each inode in the mount point.
 */
void dvs_drop_mount_attr_cache(struct incore_upfs_super_block *icsb)
{
	spin_lock(&icsb->lock);
	icsb->attrcache_revalidate_time = jiffies;
	spin_unlock(&icsb->lock);
	DVS_LOG("DVS: Set attrcache_revalidate_time to %lu for %s\n",
		icsb->attrcache_revalidate_time, icsb->prefix);
	KDEBUG_PNC(0, "DVS: %s: Set attrcache_revalidate_time to %lu for %s\n",
		   __func__, icsb->attrcache_revalidate_time, icsb->prefix);
}

static ssize_t debug_mask_write(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buffer,
				size_t count)
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
	strncpy(str, buffer, count);

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
				printk(KERN_ERR "DVS: %s: String %s is not a"
						"valid debug string\n",
				       __func__, tok);
		}
	}
	debug_to_string(dvs_debug_mask, debug_str);

	printk(KERN_INFO "DVS: %s: dvs_debug_mask is 0x%lx (%s)\n", __func__,
	       dvs_debug_mask, debug_str);

	return count;
}

static ssize_t estale_max_retry_write(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buffer, size_t count)
{
	unsigned int max_retry;
	char sizestr[16];

	if (count >= 16)
		return -EFBIG;

	memset(sizestr, 0, sizeof(sizestr));
	strncpy(sizestr, buffer, count);

	if (sscanf(sizestr, "%u", &max_retry) != 1)
		return -EINVAL;

	estale_max_retry = max_retry;

	return count;
}

static ssize_t estale_timeout_write(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buffer, size_t count)
{
	unsigned int timeout;
	char sizestr[16];

	if (count >= 16)
		return -EFBIG;

	memset(sizestr, 0, sizeof(sizestr));
	strncpy(sizestr, buffer, count);

	if (sscanf(sizestr, "%u", &timeout) != 1)
		return -EINVAL;

	estale_timeout_secs = timeout;

	return count;
}

static ssize_t sync_num_threads_write(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buffer, size_t count)
{
	unsigned int threads;
	char sizestr[16];
	int ret = 0;

	if (count >= 16)
		return -EFBIG;

	memset(sizestr, 0, sizeof(sizestr));
	strncpy(sizestr, buffer, count);

	if (sscanf(sizestr, "%u", &threads) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_threads_update)
		ret = sync_ops->sync_threads_update(threads);

	if (ret)
		return ret;

	return count;
}

static ssize_t sync_timeout_write(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buffer, size_t count)
{
	unsigned int timeout;
	char sizestr[16];

	if (count >= 16)
		return -EFBIG;

	memset(sizestr, 0, sizeof(sizestr));
	strncpy(sizestr, buffer, count);

	if (sscanf(sizestr, "%u", &timeout) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_timeout_update)
		sync_ops->sync_timeout_update(timeout);

	return count;
}

static ssize_t sync_period_write(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buffer, size_t count)
{
	unsigned int period;
	char sizestr[16];

	if (count >= 16)
		return -EFBIG;

	memset(sizestr, 0, sizeof(sizestr));
	strncpy(sizestr, buffer, count);

	if (sscanf(sizestr, "%u", &period) != 1)
		return -EINVAL;

	if (sync_ops && sync_ops->sync_period_update)
		sync_ops->sync_period_update(period);

	return count;
}

static ssize_t drop_caches_write(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buffer, size_t count)
{
	char sizestr[16];
	struct list_head *p;
	struct incore_upfs_super_block *icsb;

	if (count >= 16)
		return -EFBIG;

	memset(sizestr, 0, sizeof(sizestr));
	strncpy(sizestr, buffer, count);

	if (strncmp(sizestr, "1", 1)) {
		return count;
	}

	down(&dvs_super_blocks_sema);
	list_for_each (p, &dvs_super_blocks) {
		icsb = list_entry(p, struct incore_upfs_super_block, list);
		dvs_drop_mount_attr_cache(icsb);
	}
	up(&dvs_super_blocks_sema);

	return count;
}

static ssize_t debug_mask_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	char debug_str[64];
	debug_to_string(dvs_debug_mask, debug_str);
	return snprintf(buf, PAGE_SIZE, "0x%lx (%s)\n", dvs_debug_mask,
			debug_str);
}

static ssize_t estale_max_retry_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", estale_max_retry);
}

static ssize_t estale_timeout_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", estale_timeout_secs);
}

static ssize_t sync_num_threads_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	if (!sync_ops || !sync_ops->sync_threads_get)
		return -EINVAL;

	return snprintf(buf, PAGE_SIZE, "%u\n",
			*(sync_ops->sync_threads_get()));
}

static ssize_t sync_timeout_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	if (!sync_ops || !sync_ops->sync_timeout_get)
		return -EINVAL;

	return snprintf(buf, PAGE_SIZE, "%u\n",
			*(sync_ops->sync_timeout_get()));
}

static ssize_t sync_period_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	if (!sync_ops || !sync_ops->sync_period_get)
		return -EINVAL;

	return snprintf(buf, PAGE_SIZE, "%u\n", *(sync_ops->sync_period_get()));
}

static ssize_t drop_caches_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0\n");
}

static struct kobj_attribute attr_debug = {
	.attr = { .name = DVS_SYSFS_DEBUG,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = debug_mask_show,
	.store = debug_mask_write
};

static struct kobj_attribute attr_estale_max_retry = {
	.attr = { .name = DVS_SYSFS_ESTALE_MAX_RETRY,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = estale_max_retry_show,
	.store = estale_max_retry_write
};

static struct kobj_attribute attr_estale_timeout = {
	.attr = { .name = DVS_SYSFS_ESTALE_TIMEOUT,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = estale_timeout_show,
	.store = estale_timeout_write
};

static struct kobj_attribute attr_sync_num_threads = {
	.attr = { .name = DVS_SYSFS_SYNC_THREADS,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = sync_num_threads_show,
	.store = sync_num_threads_write
};

static struct kobj_attribute attr_sync_dirty_timeout_secs = {
	.attr = { .name = DVS_SYSFS_SYNC_TIMEOUT,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = sync_timeout_show,
	.store = sync_timeout_write
};

static struct kobj_attribute attr_sync_period_secs = {
	.attr = { .name = DVS_SYSFS_SYNC_PERIOD,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = sync_period_show,
	.store = sync_period_write
};

static struct kobj_attribute attr_quiesce = {
	.attr = { .name = DVS_SYSFS_QUIESCE,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = quiesce_show,
	.store = quiesce_write
};

static struct kobj_attribute attr_drop_caches = {
	.attr = { .name = DVS_SYSFS_DROP_CACHES,
		  .mode = S_IFREG | S_IRUGO | S_IWUSR },
	.show = drop_caches_show,
	.store = drop_caches_write
};

static struct kobject *dvs_kobj = NULL;

int create_dvs_sysfs_dirs(void)
{
	/* Create /sys/fs/dvs */
	dvs_kobj = kobject_create_and_add(DVS_SYSFS_DIR, fs_kobj);
	if (!dvs_kobj) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s\n", __func__,
		       DVS_SYSFS_DIR);
		return -ENODEV;
	}

	/* Add interfaces to /sys/fs/dvs */
	if (sysfs_create_file(dvs_kobj, &attr_debug.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_DEBUG);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_estale_max_retry.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_ESTALE_MAX_RETRY);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_estale_timeout.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_ESTALE_TIMEOUT);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_sync_num_threads.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_SYNC_THREADS);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_sync_dirty_timeout_secs.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_SYNC_TIMEOUT);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_sync_period_secs.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_SYNC_PERIOD);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_quiesce.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_QUIESCE);
		return -ENOMEM;
	}
	if (sysfs_create_file(dvs_kobj, &attr_drop_caches.attr)) {
		printk(KERN_ERR "DVS: %s: cannot init /sys/fs/%s/%s\n",
		       __func__, DVS_SYSFS_DIR, DVS_SYSFS_DROP_CACHES);
		return -ENOMEM;
	}

	return 0;
}

void remove_dvs_sysfs_dirs(void)
{
	if (dvs_kobj)
		kobject_put(dvs_kobj);
}
