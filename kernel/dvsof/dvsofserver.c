/*
 * Unpublished Work � 2003 Unlimited Scale, Inc.  All rights reserved.
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

#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/utime.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/dirent.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/kdev_t.h>
#include <linux/init_task.h>
#include <linux/rcupdate.h>
#include <linux/mman.h>
#include <linux/fadvise.h>
#include <linux/magic.h>
#include <linux/buffer_head.h>
#include <linux/delay.h>
#include <asm/ioctls.h>
#include <linux/kthread.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <fs/internal.h>
#endif

#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/kernel/hash_table.h"
#include "common/kernel/usiipc.h"
#include "common/kernel/ssi_util_init.h"
#include "dvs/usisuper.h"
#include "dvs/kernel/usifile.h"
#include "dvs/dvs_ioctl.h"
#include "common/kernel/usisyscall.h"
#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

int dvs_server_log_min = 5;

int dvsof_concurrent_reads = -1;
unsigned int dvsof_concurrent_reads_count = 0;
struct semaphore dvsof_concurrent_reads_sema;

int dvsof_concurrent_writes = -1;
unsigned int dvsof_concurrent_writes_count = 0;
struct semaphore dvsof_concurrent_writes_sema;

int dvsof_short_write_max_retry = 100;
int dvsof_short_write_timeout = 100;

extern struct rw_semaphore quiesce_barrier_rwsem;

/*
 * The linux kernel performs the following flags translation in do_filp_open
 * while processing the system call on the client. We need to revert these
 * before calling back into do_filp_open again on the server.
 *
 * Note that while the flag value (low two bits) for sys_open means:
 *      00 - read-only
 *      01 - write-only
 *      10 - read-write
 *      11 - special
 * it is changed into
 *      00 - no permissions needed
 *      01 - read-permission
 *      10 - write-permission
 *      11 - read-write
 * for the internal routines (ie open_namei()/follow_link() etc). 00 is
 * used by symlinks.
 */
static inline int
dvs_rollback_flags(int flags)
{
	int old_flags[4] = {3, 0, 1, 2};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	/* Starting in SLES12 we don't have to revert the flags */
	return flags;
#endif

	return ((flags & ~3) | old_flags[flags&0x3]);
}

static dvs_rq_func_t *dvs_rq_handlers[RQ_DVS_END_V1] =
{
	dvs_rq_lookup,
	dvs_rq_open,
	dvs_rq_close,
	dvs_rq_readdir,
	dvs_rq_create,
	dvs_rq_unlink,
	dvs_rq_ioctl,
	dvs_rq_flush,
	dvs_rq_fsync,
	dvs_rq_fasync,
	dvs_rq_lock,			/* 10 */
	dvs_rq_link,
	dvs_rq_symlink,
	dvs_rq_mkdir,
	dvs_rq_rmdir,
	dvs_rq_mknod,
	dvs_rq_rename,
	dvs_rq_readlink,
	dvs_rq_truncate,
	dvs_rq_setattr,
	dvs_rq_getattr,			/* 20 */
	dvs_rq_parallel_read,
	dvs_rq_parallel_write,
	dvs_rq_statfs,
	dvs_rq_readpage_async,		/* DEPRECATED 06/2014 */
	dvs_rq_readpage_data,		/* DEPRECATED 06/2014 */
	dvs_rq_geteoi,
	dvs_rq_setxattr,
	dvs_rq_getxattr,
	dvs_rq_listxattr,
	dvs_rq_removexattr,		/* 30 */
	dvs_rq_verifyfs,
	dvs_rq_ro_cache_disable,
	dvs_rq_permission,
	dvs_rq_sync_update,
	dvs_rq_readpages_rq,
	dvs_rq_readpages_rp,
	dvs_rq_writepages_rq,
	dvs_rq_writepages_rp
};

extern struct ssi_node_map *node_map;
extern int ssiproc_max_nodes;

/* Hash table for all inode operations. */
ht_t *inode_op_table = NULL;

/* ro_cache file state hash table */
ht_t *ro_cache_table = NULL;
extern struct semaphore ro_cache_sem;

extern struct semaphore iotsem;
extern struct semaphore *aretrysem;
extern struct list_head *alist;
extern int async_op_retry(void *);
extern int __async_op_retry(int, int, struct file_request *);

static char *get_last_path(char *);
static void remove_remote_ref (struct remote_ref *rr, unsigned long debug);

int send_multi_async_with_retry (char *myname, struct file_request *out_frq,
				 int out_frq_sz, struct file_request *in_frq,
				 int nord_start, int nnodes,
				 struct per_node **caller_pna)
{
	int nord = 0, retry_count = 0;
	struct file_request *frq = NULL;
	struct file_reply *frp = NULL;
	long error = 0, rval = 0;
	struct per_node *pna = NULL;
	int *in_node;

	pna = *caller_pna = (struct per_node *)kmalloc_ssi(
				sizeof(struct per_node) * nnodes, GFP_KERNEL);
	if (!pna) return -ENOMEM;
	in_node = filerq_get_node_base(in_frq, in_frq->node_offset);

	for (nord = nord_start; nord < nnodes; nord++) {
		frp = pna[nord].reply = (struct file_reply *)
					kmalloc_ssi(sizeof(struct file_reply),
							GFP_KERNEL);
		if (!frp) {
			error = -ENOMEM;
			break;
		}

		frq = pna[nord].request = (struct file_request *)
					kmalloc_ssi(out_frq_sz, GFP_KERNEL);
		if (!frq) {
			free_msg(pna[nord].reply);
			frp = pna[nord].reply = NULL;
			error = -ENOMEM;
			break;
		}
		memcpy(frq, out_frq, out_frq_sz);

		retry_count = 0;

send_multi_async_with_retry_1:

		RESET_FILERQ(frq);
		rval = send_ipc_request_async_stats(
			NULL, in_node[nord], RQ_FILE, frq, out_frq_sz, frp,
			sizeof(struct file_reply), NO_IDENTITY);
		if (rval < 0) {
			/*
			 * Retry for "node down" only.  Everything else
			 * causes the entire lookup operation to fail.
			 */
			if (rval != -EHOSTDOWN) {
				printk(KERN_ERR "DVS: "
					"send_multi_async_with_retry: %s: "
					"failed async open request to node %s "
					"(rval=%ld)\n", myname,
					SSI_NODE_NAME(in_node[nord]), rval);

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				error = rval;
				break;
			}
			if (!frq->retry) {
				KDEBUG_OFS(0, "DVS: send_multi_async_with_retry: %s: "
					"no retry\n", myname);

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				error = rval;
				break;
			}
			/*
			 * Delay before retry.
			 */
			if (retry_count == 0) {
				printk(KERN_ERR "DVS: "
					"send_multi_async_with_retry: %s: "
					"async IPC failed, node %d down, will "
					"attempt to retry\n", myname,
					in_node[nord]);
			}

			retry_count++;

			rval = common_retry(myname, retry_count);

			if (rval < 0) {
				KDEBUG_OFS(0, "DVS: send_multi_async_with_retry: %s: "
					"common_retry rval=%ld for node %d\n",
					myname, rval, in_node[nord]);

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				error = rval;
				break;
			}
			goto send_multi_async_with_retry_1;
		}
		if (retry_count) {
			printk(KERN_INFO "DVS: send_multi_async_with_retry: "
				"%s: retry %d OK, node %d\n", myname,
				retry_count, in_node[nord]);

		}
	}
	/*
	 * Wait for replies from the async IPC's.
	 */
	for (nord = nord_start; nord < nnodes; nord++) {
		if (!(frq = pna[nord].request) || !(frp = pna[nord].reply)) {
			continue;
		}
		rval = wait_for_async_request_stats(NULL, frq);

		if (rval < 0) {
			/* 
			 * Retry for "node down" only.  Everything else
			 * causes the entire open operation to fail.
			 */
			if (rval != -EHOSTDOWN) {
				printk(KERN_ERR "DVS: "
					"send_multi_async_with_retry: "
					"%s: failed wait for async open for "
					"node %s (rval=%ld)\n", myname,
					SSI_NODE_NAME(in_node[nord]), rval);

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				if (!error) /* Remember 1st error only*/
					error = rval;
				continue;
			}
			if (!frq->retry) {
				KDEBUG_OFS(0, "DVS: send_multi_async_with_retry: %s: "
					"no retry\n", myname);

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				if (!error) /* Remember 1st error only*/
					error = rval;
				continue;
			}
			/*
			 * The async request failed due to "node down".
			 * We now retry synchronously.
			 */
			printk(KERN_ERR "DVS: send_multi_async_with_retry: %s: "
				"wait for async IPC failed, node %d down, "
				"going into synchronous retry\n", myname,
				in_node[nord]);

			RESET_FILERQ(frq);
			if ((rval = send_ipc_with_retry(
				     NULL, myname, nord, in_node[nord], frq,
				     out_frq_sz, frp,
				     sizeof(struct file_reply))) < 0) {
				KDEBUG_OFS(0, "DVS: send_multi_async_with_retry: %s: "
					"send_ipc_with_retry rval=%ld for node "
					"%d (sync req)\n", myname,
					rval, in_node[nord]);

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;
                               
				if (!error) /* Remember only 1st error*/
					error = rval;
				continue;
			}
		}
	}
	return error;
}

/*
 * Used to cleanup partially complete namespace operations.
 */
static int ucleanup(int node, int *nlist, int op, char *path)
{
	struct file_request *filerq = NULL;
	struct file_reply *filerp;
	int rval = 0, rsz;
	unsigned long elapsed_jiffies;

	if (node < 0)
		return 0;

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}

	filerq->request = op;
	if (op == RQ_RMDIR) {
		strcpy(filerq->u.mkdirrq.pathname, path);
	} else {
		strcpy(filerq->u.unlinkrq.pathname, path);
	}
	capture_context(&filerq->context);

	for (; node>=0; node--) {
		if (nlist[node] == -1)
			continue;
		if (usi_node_addr == nlist[node]) {
			elapsed_jiffies = jiffies;
			if (op == RQ_UNLINK) {
				rval = p_sys_unlink(path);
				log_fs("unlink[ucleanup]", path,
				       jiffies - elapsed_jiffies, NULL);
			} else if (op == RQ_RMDIR) {
				rval = p_sys_rmdir(path);
				log_fs("rmdir[ucleanup]", path,
				       jiffies - elapsed_jiffies, NULL);
			}
	                if (rval < 0 && rval != -ENOENT) {
				KDEBUG_OFS(0, "DVS: ucleanup (IO): failure "
					   "to cleanup %s on local node %d "
					   "(rval=%d)\n",
					   path, nlist[node], rval);
			}
		} else {
			rval = send_ipc_request_stats(
				NULL, nlist[node], RQ_FILE, filerq, rsz, filerp,
				sizeof(struct file_reply), NO_IDENTITY);
			if (filerp->rval < 0 && filerp->rval != -ENOENT) {
				KDEBUG_OFS(0, "DVS: ucleanup (IO): failure "
					   "to cleanup %s on remote node %d "
					   "(filerp->rval=%ld)\n",
					   path, nlist[node], filerp->rval);
			}
			if (rval < 0) {
				KDEBUG_OFS(0, "DVS: ucleanup (IO): IPC "
					"failure to cleanup %s on remote "
					"node %d (rval=%d)\n",
					path, nlist[node], rval);
			}
		}
	}

done:
	free_msg(filerq);
	free_msg(filerp);

	return rval;
}

static void copy_inode_info(struct inode *ip, struct inode_attrs *attrs)
{
	attrs->i_mode = ip->i_mode;
	attrs->i_mtime = ip->i_mtime;
	attrs->i_atime = ip->i_atime;
	attrs->i_ctime = ip->i_ctime;
	attrs->i_uid = ip->i_uid;
	attrs->i_gid = ip->i_gid;
	attrs->i_nlink = ip->i_nlink;
	attrs->i_size = ip->i_size;
	attrs->i_rdev = ip->i_rdev;
	attrs->i_blocks = ip->i_blocks;
	attrs->i_version = ip->i_version;
	attrs->i_generation = ip->i_generation;
	attrs->i_sb = ip->i_sb;
	attrs->i_ino = ip->i_ino;
	attrs->i_flags = ip->i_flags;
}

/*
 * dvs_path_lookup - Gather nameidata for target file.
 *
 * Lustre only fills in part of the inode information during
 * a path_lookup. We need to call the getattr_it() function to
 * gather the remaining info (e.g., i_size).
 */
static int
dvs_path_lookup(const char *path, unsigned int flags, struct path *spath,
		const char *caller, struct file_request *filerq, unsigned long debug)
{
	int rval;
	unsigned long elapsed_jiffies;
	char op[64];

	elapsed_jiffies = jiffies;
	rval = kern_path(path, flags, spath);
	if (!strncmp(caller, "dvs_rq_lookup", 13))
		log_fs("lookup", path, jiffies - elapsed_jiffies, filerq);
	else {
		sprintf(op, "lookup[%s]", caller);
		log_fs(op, path, jiffies - elapsed_jiffies, filerq);
	}

	KDEBUG_OFS(debug, "DVS: %s: inode path %s rval %d\n",
				__FUNCTION__, path, rval);
	return rval;
}


/*
 * This routine rescans a parent directory to allow a negative dcache entry to be
 * revalidated when all other attempts fail.
 *
 * This should only be called when the caller can assure that the target file system
 * is NFS with multiple clients.
 *
 * We currently only call this for OPEN and GETATTR requests but this could be
 * extended for other operations that prove problematic with negative references.
 */
static int force_dcache_update(const char *path, struct path *spath,
			       struct file_request *filerq, unsigned long debug)
{
	int rval, close_rval;
	struct path parent;
	int ret;
	unsigned long elapsed_jiffies;

	if ((rval = dvs_path_lookup(path, LOOKUP_REVAL, spath, __func__,
				    filerq, debug))) {
		/*
		 * We must be dealing with a stale negative dentry as
		 * a result of NFS bug RH 228801.  Rescan the parent
		 * directory which is the only known cure for this until
		 * NFS is fixed.
		 */

		ret = dvs_path_lookup(path, LOOKUP_REVAL | LOOKUP_PARENT,
				      &parent, __func__, filerq, debug);
		if (!ret && parent.dentry) {
			struct file *opar;
			int opfd;
			int buf_size = PAGE_SIZE;
			char *dent_buf;

			KDEBUG_OFS(debug, "DVS: %s: failed REVAL, rescanning parent: %s %d\n",
				__FUNCTION__, path, rval);
			DVS_TRACE("forcedu", parent.dentry, 0);

			elapsed_jiffies = jiffies;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
			opar = dentry_open(parent.dentry, parent.mnt,
					O_DIRECTORY | O_RDONLY, current_cred());
#else
			opar = dentry_open(&parent, O_DIRECTORY | O_RDONLY, current_cred());
#endif
			log_fs("open[force_dcache_update]", path, jiffies - elapsed_jiffies,
			       filerq);
			if (IS_ERR(opar)) {
				KDEBUG_OFS(debug, "DVS: NFS unable to open parent %s\n",
					parent.dentry->d_name.name);
				/*
				 * dentry_open error may be a logical path_put in older kernels
				 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
				path_put(&parent);
#endif
				goto force_done;
			}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
			path_put(&parent);
#endif
			dent_buf = kmalloc_ssi(buf_size, GFP_KERNEL);
			if (!dent_buf) {
				rval = -ENOMEM;
				elapsed_jiffies = jiffies;
				filp_close(opar, NULL);
				log_fs("close[force_dcache_update]", path,
				       jiffies - elapsed_jiffies, filerq);
				goto force_done;
			}

			KDEBUG_OFS(debug, "DVS: rereading parent directory %s\n",
				parent.dentry->d_name.name);

			opfd = dvs_get_unused_fd(0);
			if (opfd < 0) {
				printk(KERN_ERR "DVS: force_dcache_lookup: cannot get unused fd\n");
				rval = opfd;
				kfree_ssi(dent_buf);
				elapsed_jiffies = jiffies;
				filp_close(opar, NULL);
				log_fs("close[force_dcache_update]", path,
				       jiffies - elapsed_jiffies, filerq);
				goto force_done;
			}
			fd_install(opfd, opar);

			do {
				elapsed_jiffies = jiffies;
				ret = p_sys_getdents64(opfd, (void*) dent_buf, buf_size);
				log_fs("getdents64[force_dcache_update]", path,
				       jiffies - elapsed_jiffies, filerq);
				if (ret > 0) {
					/*
					 * Check to see if the original inode was updated
					 * in this clump of entries.
					 */
					rval = dvs_path_lookup(path, 0, spath,
							       __func__, filerq,
							       debug);
				}
				/*
				 * Keep going as long as getdents read something and we
				 * didn't find it in the lookup.
				 */
			} while ((ret > 0) && rval);
			kfree_ssi(dent_buf);
			/* sys_close cleans up opfd from current->files */
			elapsed_jiffies = jiffies;
			if ((close_rval = p_sys_close(opfd))) {
				KDEBUG_FSE(debug, "close returned %d for file %s (fp: 0x%p)\n",
					close_rval, fpname(opar), opar);
			}
			log_fs("close[force_dcache_update]", path,
			       jiffies - elapsed_jiffies, filerq);
		}
	}

force_done:
	return rval;
}

/*
 * Set up and pass info from DVS to DWCFS.
 * It would be good to combine this and the DWFS info at some point.
 */
static long
dvs_dwcfs_init(struct file *filp, struct file_request *filerq)
{
	int error = -ENOTTY;
	struct dwcfs_fc_init fcd;

	/* not a dwcfs mount do nothing */
	if (!filerq->flags.is_dwcfs)
		return 0;

	if (!filp->f_op->unlocked_ioctl)
		goto out;

	fcd.request = filerq->request;
	fcd.flags = 0;
	if (filerq->request == RQ_CREATE)
		fcd.flags |= O_DWCFS_CREATE;

	if (filerq->flags.is_dwcfs_stripe)
		fcd.flags |= O_DWCFS_STRIPED;

	fcd.target_node = filerq->ipcmsg.target_node;
	fcd.dwcfs_mds   = filerq->dwcfs_mds;

	error = filp->f_op->unlocked_ioctl(filp, DWCFS_FC_INIT, (unsigned long)(&fcd));
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
out:
	return error;
}

static int get_inode_info(char *path, unsigned int flags,
			  struct inode_attrs *attrs,
			  struct file_request *filerq,
			  unsigned long debug)
{
	long rval;
	struct path spath;

	rval = dvs_path_lookup(path, flags, &spath, __func__, filerq, debug);
	if (rval) {
		printk(KERN_ERR "DVS: get_inode_info: path_lookup "
		       "failed: %ld\n", rval);
		rval = -USIERR_FILE_NOTFOUND;
	} else {
		if (spath.dentry) {
			KDEBUG_OFS(debug, "DVS: get_inode_info: found %s (%s) flags %d\n",
                               path, spath.dentry->d_name.name, flags);
			copy_inode_info(spath.dentry->d_inode, attrs);
		} else {
			printk(KERN_ERR "DVS: get_inode_info: "
			       "no dentry\n");
			rval = -USIERR_FILE_NOTFOUND;
		}
		path_put(&spath);
	}

	return(rval);
}


DEFINE_SPINLOCK(rr_sl);
LIST_HEAD(rr_list);

static inline void
dvs_init_files(struct files_struct *files)
{
	struct fdtable *fdt;
	int i;

	atomic_set(&files->count, 1);

	spin_lock_init(&files->file_lock);
	fdt = &files->fdtab;
	fdt->max_fds = NR_OPEN_DEFAULT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	fdt->close_on_exec = (fd_set *)&files->close_on_exec_init;
	fdt->open_fds = (fd_set *)&files->open_fds_init;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
	fdt->close_on_exec = files->close_on_exec_init;
	fdt->open_fds = files->open_fds_init;
#else
	files->resize_in_progress = false;
	init_waitqueue_head(&files->resize_wait);
	files->next_fd = 0;
	fdt->close_on_exec = files->close_on_exec_init;
	fdt->open_fds = files->open_fds_init;
	fdt->full_fds_bits = files->full_fds_bits_init;
#endif
#endif
	fdt->fd = &files->fd_array[0];
	for (i=0;i<NR_OPEN_DEFAULT;i++) {
		fdt->fd[i] = NULL;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	INIT_RCU_HEAD(&fdt->rcu);
#endif
	rcu_assign_pointer(files->fdt, fdt);
	return;
}

/*
 * Check if path is a child of dir,
 * using only string comparisons
 */
int dvs_is_subdir(char *dir, int dirlen, char *path) {
        if (dir == NULL || path == NULL)
                return 0;
        if (!strncmp(dir, path, dirlen))
                return 1;
        if (strlen(path) == dirlen - 1 && !strncmp(dir, path, dirlen-1))
                return 1;
        return 0;
}

/*
 * Given a path, iterate through the quiesced dirs
 * and return if the path is quiesced.
 */
int path_is_quiesced(char *opname, char *path1, char *path2) {

	struct quiesced_dir *qdir;
	extern struct list_head quiesced_dirs;

	list_for_each_entry(qdir, &quiesced_dirs, quiesced_dirs_lh) {
		if (dvs_is_subdir(qdir->dir, qdir->dir_len, path1) ||
				(dvs_is_subdir(qdir->dir, qdir->dir_len, path2))) {
			KDEBUG_QSC(0, "Op %s Request for %s%s%s is quiesced by %s\n",
					opname, path1, path2 ? ":" : "", path2 ? path2 : "",
					qdir->dir);
			return 1;
		}
	}
	return 0;
}
/*
 * Create a remote reference to a server-side file. These
 * references are maintained one per client file per node.
 * This remote reference contains a sublist with a per process
 * private file table which is used to provide a unique handle
 * for performing file locking operations.
 */
static struct remote_ref *add_remote_ref (struct file *fp, int node, int flags, int *quiesced)
{
	struct remote_ref *rr;

	rr = kmalloc_ssi(sizeof(struct remote_ref), GFP_KERNEL);
	if (rr == NULL)
		return NULL;

	rr->node = node;
	rr->fp = fp;
	rr->flags = flags;
	INIT_LIST_HEAD(&rr->quiesced_lh);
	INIT_LIST_HEAD(&rr->rr_lh);
	INIT_LIST_HEAD(&rr->posix_lock_lh);
	spin_lock_init(&rr->posix_lock_sl);
	rr->key = jiffies;
	rr->quiesced = 0;
	rr_ref_init(rr);

	dvsproc_stat_update(NULL, DVSPROC_STAT_OPEN_FILES, 0, 1);

	if (sync_add_inode_ref(rr) == -ENOMEM) {
		rr_ref_put(rr);
		return NULL;
	}

	spin_lock(&rr_sl);
	list_add(&rr->rr_lh, &rr_list);
	spin_unlock(&rr_sl);

	KDEBUG_OFS(0, "DVS: add_remote_ref: added 0x%p fp 0x%p node %d\n",
		   rr, rr->fp, rr->node);
	return rr;
}

/* 
 * Called to create process file table for a remote reference.
 * The dvs_posix_lock->files structure is used to provide unique identification
 * for file locking operations.  It is large however, so this routine
 * isn't called until a file locking operation is performed. 
 */
static struct dvs_posix_lock *
add_dvs_posix_lock (struct remote_ref *rr, int pid)
{
	struct dvs_posix_lock *dpl;

	dpl = kmalloc_ssi(sizeof(struct dvs_posix_lock), GFP_KERNEL);
	if (dpl == NULL)
		return NULL;

	dpl->pid = pid;
	dvs_init_files(&dpl->files);
	INIT_LIST_HEAD(&dpl->lh);

	spin_lock(&rr->posix_lock_sl);
	list_add(&dpl->lh, &rr->posix_lock_lh);
	spin_unlock(&rr->posix_lock_sl);
	KDEBUG_OFS(0, "DVS: add_dvs_posix_lock: rr 0x%p added pid %d\n", rr, pid);

	return dpl;
}


void free_remote_ref(struct kref *ref)
{
	struct remote_ref *rr;
	struct dvs_posix_lock *dpl, *dpl_tmp;
	struct files_struct *files;

	if (!ref)
		return;

	rr = container_of(ref, struct remote_ref, ref);

	spin_lock(&node_map[rr->node].rr_lock);
	rr->key = 0; /* zero so don't get false hits */
	spin_unlock(&node_map[rr->node].rr_lock);

	/* If quiesced, remove from the quiesced list */
	if (rr->quiesced) {
		list_del_init(&rr->quiesced_lh);
	}

	/* If our inode_ref still exists we need to remove it. This should
	 * return immediately unless the remote_ref was freed in
	 * file_node_down(). In that case we can't remove the inode_ref until
	 * now since do_usifile() may have a pointer to it. */
	if (!rr->quiesced)
		sync_remove_inode_ref(rr);

        /* If the remote_ref was freed from file_node_down() we still need to
         * remove the posix locks. If we did a normal close then there shouldn't
         * be any elements on the member_head list. */

restart:
	spin_lock(&rr->posix_lock_sl);
	list_for_each_entry_safe(dpl, dpl_tmp, &rr->posix_lock_lh, lh) {

		files = &dpl->files;
		/* wait for any non-DVS file_struct refs to be released - bug 808390 */
		if (atomic_read(&files->count) > 1) {
			spin_unlock(&rr->posix_lock_sl);
			cond_resched();
			goto restart;
		}

		locks_remove_posix(rr->fp, files);
		list_del(&dpl->lh);
		kfree(dpl);
	}
	spin_unlock(&rr->posix_lock_sl);

	if (!rr->quiesced)
		dvsproc_stat_update(NULL, DVSPROC_STAT_OPEN_FILES, 0, -1);

	kfree(rr);
}

/*
 * Remove remote references to a file.  There is a single remote_ref
 * structure for a single file. But multiple processes from a given
 * client can open the file, and each have an associated remote_ref_member
 * structure attached to the remote_ref.  None of the file's remote references
 * are removed until the file is about to be closed on the client node.
 */
static void remove_remote_ref (struct remote_ref *rr, unsigned long debug)
{
	struct dvs_posix_lock *dpl, *dpl_tmp;
	struct files_struct *files;

	if (!rr->quiesced)
		sync_remove_inode_ref(rr);

	/* free per-process structures attached to this remote_ref */
restart:
	spin_lock(&rr->posix_lock_sl);
	list_for_each_entry_safe(dpl, dpl_tmp, &rr->posix_lock_lh, lh) {
		/* wait for any non-DVS file_struct refs to be released - bug 808390 */
		files = &dpl->files;
		if (atomic_read(&files->count) > 1) {
			spin_unlock(&rr->posix_lock_sl);
			cond_resched();
			goto restart;
		}
		list_del(&dpl->lh);
		kfree(dpl);
	}
	spin_unlock(&rr->posix_lock_sl);

	KDEBUG_OFS(debug, "DVS: remove_remote_ref: removing 0x%p fp 0x%p node %d\n",
		   rr, rr->fp, rr->node);

	spin_lock(&node_map[rr->node].rr_lock);
	rr->key = 0; /* zero so don't get false hits */
	spin_unlock(&node_map[rr->node].rr_lock);

	/* calls free_remote_ref() */
	rr_ref_put(rr);
}

/* 
 * Returns remote_ref pointer if valid.  We don't assume client pointer is
 * valid by itself.  We also verify valid handle using a key match.
 */
static inline struct remote_ref *
get_valid_remote_ref(struct remote_handle *file_handle, int node, int *quiesced, unsigned long debug)
{
	struct remote_ref *rr;

	rr = (struct remote_ref *)(file_handle->remote_ref);

	/* Don't grab a lock if we don't have to */
	if (rr == NULL)
		return rr;

	spin_lock(&node_map[node].rr_lock);

	if (rr->key != file_handle->key) {
		spin_unlock(&node_map[node].rr_lock);
		return NULL;
	}

	if (rr->quiesced) {
		spin_unlock(&node_map[node].rr_lock);
		*quiesced = 1;
		KDEBUG_QSC(debug, "Remote Ref %p is quiesced\n", rr);
		return NULL;
	}

	rr_ref_get(rr);
	spin_unlock(&node_map[node].rr_lock);

	return rr;
}

static struct dvs_posix_lock *
find_remote_ref_lock(struct remote_ref *rr, pid_t pid)
{
	struct dvs_posix_lock *dpl;

	spin_lock(&rr->posix_lock_sl);
	list_for_each_entry(dpl, &rr->posix_lock_lh, lh) {
		if (dpl->pid == pid) {
			spin_unlock(&rr->posix_lock_sl);
			return dpl;
		}
	}
	spin_unlock(&rr->posix_lock_sl);

	return NULL;
}

static int remote_ref_has_locks(struct remote_ref *rr) {
	return !list_empty(&rr->posix_lock_lh);
}

/*
 * Find the files_struct for the specified client reference. This provides
 * a unique handle for performing file locking operations.  If allocate_files
 * is set, the caller needs a files struct returned (which requires the
 * allocation of a new remote_ref_member structure that contains it).
 * If lock is set, make note that a file locking operation was done to the
 * file (used if the client crashes before cleaning up locks).
 * Returns 0 on success, -errno otherwise.
 */
static int
dvs_switch_files(struct files_struct **hold_files, struct remote_ref *rr, int pid, int allocate_files, int lock, unsigned long debug)
{
	struct dvs_posix_lock *dpl;

	dpl = find_remote_ref_lock(rr, pid);
	if (dpl == NULL) {
		if (allocate_files) {
			dpl =  add_dvs_posix_lock(rr, pid);
			if (dpl)
				goto dpl_exists;

			KDEBUG_OFS(0, "%s: 0x%p:0x%x:%d not found\n",
			   		__FUNCTION__, rr, rr->node, pid);
			DVS_TRACEL("!dvssf", rr, rr->node, pid, 0, 0);
			return -ENOMEM;
		} else {
			/* no need to return error if allocate not required */
			task_lock(current);
			*hold_files = current->files;
			current->files = NULL;
			task_unlock(current);
			return 0;
		}
	}
dpl_exists:
	KDEBUG_OFS(0, "%s: 0x%p:0x%x:%d found 0x%p\n",
		__FUNCTION__, rr, rr->node, pid, &dpl->files);

	task_lock(current);
	*hold_files = current->files;
	current->files = &dpl->files;
	task_unlock(current);

	return 0;
}

/*
 * Safely undo the files_struct changes made to current by dvs_switch_files.
 */
static void dvs_restore_files(struct files_struct *hold_files)
{
	task_lock(current);
	current->files = hold_files;
	task_unlock(current);
}

static char *get_last_path(char *path)
{
	char *tmp = NULL;

	if (path == NULL) {
		return (NULL);
	}

	if ((tmp = strrchr(path, '/')) != NULL)
		return (tmp);
	else
		return (path);
}

/*
 * sync user data, so the write is resilient.
 */
static long uwrite_usersync(int fd, struct file *fp,
			    struct file_request *filerq)
{
	long rval;
	unsigned long elapsed_jiffies;

	elapsed_jiffies = jiffies;
	rval = p_sys_fsync(fd);
	log_fs("fsync[uwrite_usersync]", fpname(fp), jiffies - elapsed_jiffies,
	       filerq);
	if (rval < 0)
		KDEBUG_FSE(0, "uwrite fsync returned %ld\n", rval);

	return(rval);
}

/*
 * Return whether the path has any extended attributes associated with
 * it.  This is used to determine if any ACLs are present, in order to
 * determine if permission checks need to be sent to servers.  Not all
 * file systems reflect this accurately via a listxattr function, hence
 * the special casing and possible calls to getxattr.
 */
static int has_xattrs(struct inode *ip, char *path, struct file_request *filerq, unsigned long debug)
{
	int ret, ignore_listxattr = 0;
	char buf[16];
	unsigned long magic = ip->i_sb->s_magic;
	unsigned long elapsed_jiffies;

	/*
	 * Note that buf is 16 bytes in size to workaround a GPFS getxattr
	 * issue (see bug 783046), when really it only needs to be 1 byte in
	 * size for the follow code to work.  Do not reduce the size of buf!
	 */

	/*
	 * listxattr returns >0 on PanFS even if no ACLs are present, and
	 * 0 on GPFS regardless of whether ACLs are present or not. DWFS uses
	 * xattrs internally, so listxattr always returns >0. Go directly to
	 * getxattr calls for those file systems.
	 */
	if (magic == PAN_FS_CLIENT_MAGIC || magic == GPFS_MAGIC ||
	    magic == KDWFS_SUPER_MAGIC)
		ignore_listxattr = 1;

	if (!ignore_listxattr && ip->i_op->listxattr) {
		elapsed_jiffies = jiffies;
		ret = p_sys_listxattr(path, NULL, 0);
		log_fs("listxattr[has_xattrs]", path, jiffies - elapsed_jiffies,
		       filerq);
		if (ret > 0 || (ret < 0 && ret != -EOPNOTSUPP)) {
			KDEBUG_OFS(debug, "DVS: %s: listxattr returned %d, path %s\n",
				   __FUNCTION__, ret, path);
			return 1;
		}
	} else if (ip->i_op->getxattr) {
		/* check for access ACLs */
		elapsed_jiffies = jiffies;
		ret = p_sys_getxattr(path, "system.posix_acl_access", &buf,
				     sizeof(buf));
		log_fs("getxattr[has_xattrs]", path, jiffies - elapsed_jiffies,
		       filerq);
		if (ret > 0 || (ret < 0 && ret != -EOPNOTSUPP &&
				ret != -ENODATA)) {
			KDEBUG_OFS(debug, "DVS: %s: getxattr access returned %d, "
				   "path %s\n", __FUNCTION__, ret, path);
			return 1;
		}

		/* default ACLs only apply to directories */
		if (!S_ISDIR(ip->i_mode))
			return 0;

		/* check for default ACLs */
		elapsed_jiffies = jiffies;
		ret = p_sys_getxattr(path, "system.posix_acl_default", &buf,
				     sizeof(buf));
		log_fs("getxattr[has_xattrs]", path, jiffies - elapsed_jiffies,
		       filerq);
		if (ret > 0 || (ret < 0 && ret != -EOPNOTSUPP &&
				ret != -ENODATA)) {
			KDEBUG_OFS(debug, "DVS: %s: getxattr default returned %d, "
				   "path %s\n", __FUNCTION__, ret, path);
			return 1;
		}
	}

	return 0;
}

static int dvs_finish_open(struct file *fp, struct file_request *freq,
		       struct file_reply *frep, struct open_reply *openrp)
{
	struct remote_ref *rr;
	int flags = 0;
	int rval;
	int quiesced = 0;

	if (freq->request == RQ_OPEN && freq->u.openrq.use_openexec)
		flags |= DVS_RR_OPEN_EXEC;

	/* Find the names of the DWFS data stripes if this is a DWFS mount point
	 * and we're reading a regular file. */
	if (openrp->dwfs_info.path_len && S_ISREG(file_inode(fp)->i_mode)) {
		rval = get_dwfs_path(fp, &openrp->dwfs_info);
		if (rval < 0) {
			printk("DVS: dvs_finish_open could not get DWFS data "
			       "stripe path name\n");
			return rval;
		}

		rval = get_dwfs_bcstripe(fp, &openrp->dwfs_info);
		if (rval < 0) {
			printk("DVS: dvs_finish_open could not get DWFS "
			       "bcstripe path name\n");
			return rval;
		}
	}

	rr = add_remote_ref(fp, SOURCE_NODE(&freq->ipcmsg), flags, &quiesced);
	if (rr == NULL) {
		if (quiesced)
			return -EQUIESCE;
		return -ENOMEM;
	}

	openrp->rf.file_handle.remote_ref = rr;
	openrp->rf.file_handle.key = rr->key;
	openrp->rf.remote_node = usi_node_addr;
	openrp->rf.magic = file_inode(fp)->i_sb->s_magic;
	openrp->rf.flush_required = (fp->f_op && fp->f_op->flush);
	openrp->size = file_inode(fp)->i_size;
	copy_inode_info(file_inode(fp), &openrp->inode_copy);

	return 0;
}

/*
 * nfs filesystems may leave stale inode data visible on servers.  If
 * invalidate is set the client node has determined this may be possible
 * for the given path.  If so drop the dentry from the cache so a new
 * lookup will be done and current inode info gathered
 */
static void manage_name_cache(char *path, int invalidate,
			      struct file_request *filerq)
{
	struct path spath;

	if (invalidate) {
	        if (!dvs_path_lookup(path, 0, &spath, __func__, filerq, 0)) {
			/* Don't drop a dentry with something mounted on it */
			if (!have_submounts(spath.dentry))
				d_drop(spath.dentry);
			path_put(&spath);
		}
	}
}

/*
 * Helper function for do_usifile:  pull any path strings from the file request
 * and make manage_name_cache calls if applicable.
 */
static char *dvs_get_path(struct file_request *freq, char **path, char **oldpath)
{
	/* Not all callers zero out the path pointer */
	*path = NULL;

	switch (freq->request) {
	case RQ_LOOKUP:
		*path = freq->u.lookuprq.pathname;
		break;
	case RQ_READLINK:
		*path = freq->u.readlinkrq.pathname;
		break;
	case RQ_GETATTR:
		*path = freq->u.getattrrq.pathname;
		break;
	case RQ_SETATTR:
		*path = freq->u.setattrrq.pathname;
		break;
	case RQ_SETXATTR:
		*path = freq->u.setxattrrq.data;
		break;
	case RQ_GETXATTR:
		*path = freq->u.getxattrrq.data;
		break;
	case RQ_LISTXATTR:
		*path = freq->u.listxattrrq.data;
		break;
	case RQ_REMOVEXATTR:
		*path = freq->u.removexattrrq.data;
		break;
	case RQ_OPEN:
		*path = freq->u.openrq.pathname;
		break;
	case RQ_TRUNCATE:
		*path = freq->u.truncaterq.pathname;
		break;
	case RQ_CREATE:
		*path = freq->u.createrq.pathname;
		break;
	case RQ_UNLINK:
		*path = freq->u.unlinkrq.pathname;
		break;
	case RQ_LINK:
		*path = &freq->u.linkrq.pathname[freq->u.linkrq.orsz];
		if (oldpath)
			*oldpath = &freq->u.linkrq.pathname[0];
		break;
	case RQ_SYMLINK:
		*path = &freq->u.linkrq.pathname[0];
		break;
	case RQ_MKDIR:
		*path = freq->u.mkdirrq.pathname;
		break;
	case RQ_RMDIR:
		*path = freq->u.rmdirrq.pathname;
		break;
	case RQ_MKNOD:
		*path = freq->u.mknodrq.pathname;
		break;
	case RQ_RENAME:
		*path = &freq->u.linkrq.pathname[freq->u.linkrq.orsz];
		if (oldpath)
			*oldpath = &freq->u.linkrq.pathname[0];
		break;
	case RQ_STATFS:
		*path = freq->u.statfsrq.pathname;
		break;
	case RQ_PERMISSION:
		*path = freq->u.permissionrq.pathname;
		break;
	case RQ_VERIFYFS:
		*path = freq->u.verifyfsrq.pathname;
		break;
	default:
		break;
	}

	if (*path != NULL)
		manage_name_cache(*path, freq->flags.invalidate, freq);
	if (oldpath && *oldpath != NULL)
		manage_name_cache(*oldpath, freq->u.linkrq.invalidate_old, freq);
	return *path;
}

/*
 * ESTALE errors are special cased. In some situations we can recover from
 * ESTALE errors on GPFS or NFS by closing and re-opening the file. If we see
 * an ESTALE on the server, we check the following conditions:
 *    - The underlying filesystem is GPFS or NFS
 *    - The file isn't dirty
 *    - There aren't any locks on the file
 * If all of these are true, then we change the return value to ESTALE_DVS_RETRY
 * which tells the client to retry the operation. For inode operations, this
 * causes the client to resend the request after a timeout period. It will send
 * the request a maximum of estale_max_retry times (set through a module
 * parameter and /proc file) before giving up and returning ESTALE to the caller.
 * In the case of file operations, we will do a close and open of the file from
 * the client before retrying. If the open request generates an ESTALE we retry
 * the open request until it either succeeds or we reach the maximum retry count.
 */

static int
server_should_estale_retry(struct file_request *filerq, struct remote_ref *rr)
{
	if (!filerq)
		return 0;

	/* inode operations won't have a remote_ref, and since we won't be
	 * opening and closing the file we just need to make sure that the
	 * underlying filesystem is GPFS or NFS. */
	if (!rr) {
		if (filerq->flags.is_gpfs || filerq->flags.is_nfs)
			return 1;

		return 0;
	}

	if (rr->fp && rr->fp->f_path.dentry && rr->fp->f_path.dentry->d_sb) {
		if (file_inode(rr->fp)->i_sb->s_magic != GPFS_MAGIC &&
                    file_inode(rr->fp)->i_sb->s_magic != NFS_SUPER_MAGIC) {
			return 0;
		}
	} else {
		return 0;
	}

	/* We bail if the file is locked. We don't want to have to replace
	 * the lock after closing/opening the file. */
	if (remote_ref_has_locks(rr))
		return 0;

	/* Readonly files don't have an inode_ref, and they won't be dirty. */
	if (!(rr->fp->f_mode & FMODE_WRITE))
		return 1;

	/* Our file is writable, so we can only do the retry if it's not dirty */
	if (sync_is_inode_dirty(rr))
		return 0;

	return 1;
}

static void estale_print_messages(struct file_request *freq, int rval)
{
	int failed = 0;
	int retry = 0;

	if (freq->flags.estale_failover) {
		if (rval == -ESTALE_DVS_RETRY || rval == -ESTALE) {
			atomic64_inc(&global_estale_stats.stats[ESTALE_FAILOVER_FAIL]);
			failed = 1;
		} else {
			atomic64_inc(&global_estale_stats.stats[ESTALE_FAILOVER_PASS]);
		}
	} else if (freq->flags.estale_retry) {
		retry = 1;
		if (rval == -ESTALE_DVS_RETRY || rval == -ESTALE) {
			atomic64_inc(&global_estale_stats.stats[ESTALE_RETRY_FAIL]);
			failed = 1;
		} else {
			atomic64_inc(&global_estale_stats.stats[ESTALE_RETRY_PASS]);
		}
	} else {
		return;
	}

	if (jiffies > global_estale_stats.jiffies + ESTALE_MESSAGE_THROTTLE * HZ) {

		/* There is a race here where more than one messages can print since
		 * we're not locking around where we check and set the jiffies
		 * value. It's probably not worth closing up this hole. */
		global_estale_stats.jiffies = jiffies;
		printk("DVS: ESTALE: %s request from %s %s. Suppressing "
		       "ESTALE messages for %d seconds from this server."
		       " (Successful retries: %ld Failed retries: %ld "
		       "Successful failovers: %ld Failed failovers %ld)\n",
		       retry ? "Retry" : "Failover",
		       node_map[freq->ipcmsg.source_node].name,
		       failed ? "failed" : "succeeded", ESTALE_MESSAGE_THROTTLE,
		       atomic64_read(&global_estale_stats.stats[ESTALE_RETRY_PASS]),
		       atomic64_read(&global_estale_stats.stats[ESTALE_RETRY_FAIL]),
		       atomic64_read(&global_estale_stats.stats[ESTALE_FAILOVER_PASS]),
		       atomic64_read(&global_estale_stats.stats[ESTALE_FAILOVER_FAIL]));
	}
}

int noclusterfs_create(struct file_request *orig_filerq, char *path)
{
	struct file_request *filerq;
	struct file_reply *filerp;
	struct per_node *pna;
	long rval = 0;
	int request_size, nnodes, node, error;
	int *error_nlist, *freq_node;

	nnodes = orig_filerq->nnodes;
	pna = NULL;
	error = 0;

	/* Send off parallel requests */
	request_size = sizeof(struct file_request) + strlen(path) + 1;
	if ((filerq = kmalloc_ssi(request_size, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	freq_node = filerq_get_node_base(orig_filerq, orig_filerq->node_offset);

	filerq->request = RQ_CREATE;
	filerq->retry = orig_filerq->retry;
	filerq->rip = orig_filerq->rip;
	filerq->u.createrq.mode = orig_filerq->u.createrq.mode;
	filerq->u.createrq.flags = orig_filerq->u.createrq.flags;
	strcpy(filerq->u.createrq.pathname, path);
	memcpy(&filerq->context, &orig_filerq->context,
	       sizeof(struct usicontext));

	error = send_multi_async_with_retry("RQ_CREATE", filerq, request_size,
	                                    orig_filerq, 1, nnodes, &pna);
	if (!pna) {
		goto ncfs_create_done;
	}

	for (node = 1; node < nnodes; node++) {
		if (!(filerp = pna[node].reply)) {
			continue;
		}
		if (filerp->rval < 0) {
			if (orig_filerq->rip && filerp->rval == -EEXIST) {
				KDEBUG_OFS(0, "DVS: RQ_CREATE: clear EEXIST, "
				           "nord %d, path %s\n", node, path);
				continue;
			}
			KDEBUG_OFS(0, "DVS: RQ_CREATE: got error from node %d for "
			           "pathname %s: %ld\n", node, path,
			           filerp->rval);

			free_msg(pna[node].reply);
			pna[node].reply = NULL;
			free_msg(pna[node].request);
			pna[node].request = NULL;

			if (!error) /* Remember only 1st error*/
				error = filerp->rval;
			continue;
		}
	}
	if (error) {
		/*
		 * If there was any error, we must unlink on all nodes
		 * on which the create succeeded.
		 */
		error_nlist = kmalloc_ssi(sizeof(int) * nnodes, GFP_KERNEL);
		if (error_nlist) {
			for (node = 0; node < nnodes; node++) {
				error_nlist[node] = freq_node[node];
				if (!pna[node].request && node != 0) {
					/*
					 * Not created on these nodes.
					 */
					error_nlist[node] = -1;
				}
			}
			ucleanup(nnodes-1, error_nlist, RQ_UNLINK, path);
			kfree_ssi(error_nlist);
		}
	}

ncfs_create_done:
	if (pna) {
		for (node = 1; node < nnodes; node++) {
			free_msg(pna[node].reply);
			free_msg(pna[node].request);
		}
		kfree_ssi(pna);
	}
	free_msg(filerq);

	if (error)
		rval = error;

	return rval;
}

int noclusterfs_unlink(struct file_request *orig_filerq, char *path, int *enoent)
{
	struct file_request *filerq;
	struct file_reply *filerp;
	struct per_node *pna;
	long rval = 0;
	int request_size, node;
	int *freq_node;

	/* Send off parallel requests */
	request_size = sizeof(struct file_request) + strlen(path) + 1;
	if ((filerq = kmalloc_ssi(request_size, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	freq_node = filerq_get_node_base(orig_filerq, orig_filerq->node_offset);

	filerq->request = RQ_UNLINK;
	filerq->retry = orig_filerq->retry;
	filerq->rip = orig_filerq->rip;
	strcpy(filerq->u.unlinkrq.pathname, path);
	memcpy(&filerq->context, &orig_filerq->context,
	       sizeof(struct usicontext));

	rval = send_multi_async_with_retry("RQ_UNLINK", filerq, request_size,
	                             orig_filerq, 1, orig_filerq->nnodes, &pna);
	if (!pna) {
		goto ncfs_unlink_done;
	}

	for (node = orig_filerq->nnodes - 1; node >= 0; node--) {
		if (!(filerp = pna[node].reply)
		                    || freq_node[node] == usi_node_addr)
			continue;

		if ((filerp->rval != 0) && (filerp->rval != -ENOENT)) {
			KDEBUG_OFS(0, "DVS: RQ_UNLINK: got error from node %d: "
			           "%ld\n", node, rval);
			rval = filerp->rval;
			break;
		} else if (filerp->rval == -ENOENT) {
			(*enoent)++;
		}
	}

ncfs_unlink_done:
	if (pna) {
		for (node = 1; node < orig_filerq->nnodes; node++) {
			free_msg(pna[node].reply);
			free_msg(pna[node].request);
		}
		kfree_ssi(pna);
	}
	free_msg(filerq);

	return rval;
}

int noclusterfs_mkdir(struct file_request *orig_filerq, char *path, struct file_reply *filerp)
{
	struct file_request *filerq;
	long rval = 0;
	int request_size, node;
	int *freq_node;

	/* Send off parallel requests */
	request_size = sizeof(struct file_request) + strlen(path) + 1;
	if ((filerq = kmalloc_ssi(request_size, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	freq_node = filerq_get_node_base(orig_filerq, orig_filerq->node_offset);

	filerq->request = RQ_MKDIR;
	filerq->retry = orig_filerq->retry;
	filerq->rip = orig_filerq->rip;
	filerq->u.mkdirrq.mode = orig_filerq->u.mkdirrq.mode;
	strcpy(filerq->u.mkdirrq.pathname, path);
	memcpy(&filerq->context, &orig_filerq->context,
	       sizeof(struct usicontext));

	for (node = 1; node < orig_filerq->nnodes; node++) {
		rval = send_ipc_with_retry(NULL, "umkdir", node,
		                           freq_node[node], filerq,
		                           request_size, filerp,
		                           sizeof(struct file_reply));

		if (rval == -EQUIESCE)
			continue;

		if (rval < 0) {
			free_msg(filerq);
			ucleanup(node-1, freq_node, RQ_RMDIR, path);
			return rval;
		}
		if (filerp->rval < 0) {
			if (orig_filerq->rip && filerp->rval == -EEXIST) {
				KDEBUG_OFS(0, "DVS: RQ_MKDIR: clear EEXIST, nord "
				           "%d, path %s\n", node, path);
				filerp->rval = 0;
				continue;
			}
			KDEBUG_OFS(0, "DVS: RQ_MKDIR: got error from node %d: "
			           "%ld\n", node, filerp->rval);
			rval = filerp->rval;
			free_msg(filerq);
			ucleanup(node-1, freq_node, RQ_RMDIR, path);
			return rval;
		}
	}
	free_msg(filerq);

	if (rval == -EQUIESCE)
		rval = -EIO;
	return rval;
}

int noclusterfs_rmdir(struct file_request *orig_filerq, char *path, struct file_reply *filerp, int *enoent)
{
	struct file_request *filerq;
	long rval = 0;
	int request_size, node;
	int *freq_node;

	/* Send off parallel requests */
	request_size = sizeof(struct file_request) + strlen(path) + 1;
	if ((filerq = kmalloc_ssi(request_size, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	freq_node = filerq_get_node_base(orig_filerq, orig_filerq->node_offset);

	filerq->request = RQ_RMDIR;
	filerq->retry = orig_filerq->retry;
	filerq->rip = orig_filerq->rip;
	strcpy(filerq->u.unlinkrq.pathname, path);
	memcpy(&filerq->context, &orig_filerq->context,
	       sizeof(struct usicontext));

	for (node = 1; node < orig_filerq->nnodes; node++) {
		rval = send_ipc_with_retry(NULL, "urmdir", node,
		                           freq_node[node], filerq,
		                           request_size, filerp,
		                           sizeof(struct file_reply));
		if (rval < 0) {
			free_msg(filerq);
			return rval;
		}
		if ((filerp->rval != 0) && (filerp->rval != -ENOENT)) {
			KDEBUG_OFS(0, "DVS: RQ_RMDIR: got error from node %d: "
			           "%ld\n", node, filerp->rval);
			rval = filerp->rval;
			free_msg(filerq);
			return rval;
		} else if (filerp->rval == -ENOENT) {
			enoent++;
		}
	}
	free_msg(filerq);

	return rval;
}

int dvs_rq_lookup(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp;
	struct path spath;
	long rval = 0;
	char *path;
	int trips = 1;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: lookup: %s, %d\n", path, filerq->context.node);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	/* assume inode info invalid */
	filerp->u.lookuprp.inode_valid = 0;
	filerp->u.lookuprp.no_inode = 0;

lookup_path:
	rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug);
	/* 
	 * N.B  It is important to understand that we were called
	 * by a dir->i_op->lookup() call.  The fs specific lookup
	 * operation is expected to return one of a few things:
	 *
	 * 1) Success - a %NULL dentry pointer is returned.  The passed
	 *    in arg dentry pointer is filled in with the assiciated 
	 *    inode pointer set.  
	 *
	 * 2) SOFT Failure - a %NULL dentry pointer is returned.  
	 *    However the inode was not found in the passed in dir - so
	 *    no inode will be set in the passed in arg dentry pointer.
	 *
	 * 3) HARD Failure - An error (negative dentry ptr) is returned.
	 *    The error is things like -ENAMETOOLONG, or -EACCES.
	 *
	 * It is our job to translate the slightly twisted results of 
	 * a path_lookup() call into this expected return.  If you
	 * change the lookup flags passed to path_lookup the error
	 * handling code below will need to change.  There is only
	 * something like 16 different ways out of link_path_walk.
	 * What could possibly go wrong?
	 */

	if (rval == -ENOENT) {
		/* SOFT Failure case 2: don't want to do path_put */
		filerp->u.lookuprp.no_inode = 1;
		return 0;
	} else if (rval) {
		/* HARD Failure - case 3 */
		KDEBUG_FSE(debug, "lookup returned %ld for path %s\n",
		           rval, path);
		return rval;
	}

	/*
	 * Check that it's not an autofs placeholder directory (using a
	 * different inode number than the actual entity for this path)
	 * If so, open it so that it comes back online and re-look it up.
	 * Clients otherwise can get confused in parallel lookups and return
	 * ENOENT.
	 */
	if (!spath.dentry->d_inode->i_size &&
	             S_ISDIR(spath.dentry->d_inode->i_mode) &&
	             spath.dentry->d_sb->s_magic == AUTOFS_SUPER_MAGIC &&
	             trips--) {
		elapsed_jiffies = jiffies;
		fp = filp_open(path, O_DIRECTORY | O_RDONLY, 0);
		log_fs("open[dvs_rq_lookup]", path, jiffies - elapsed_jiffies, filerq);
		if (IS_ERR(fp)) {
			rval = PTR_ERR(fp);
			KDEBUG_FSE(debug, "filp_open returned %ld for "
			           "path %s, flags 0x%x\n", rval,
			           path, O_DIRECTORY | O_RDONLY);
			path_put(&spath);
			return rval;
		}
		elapsed_jiffies = jiffies;
		filp_close(fp, NULL);
		log_fs("close[dvs_rq_lookup]", path, jiffies - elapsed_jiffies, filerq);
		path_put(&spath);
		goto lookup_path;
	}

	/*
	 * Check for extended attributes and piggyback their existence
	 * on the lookup reply.  If no xattr data exists, we can
	 * perform permission checks on the client and avoid sending
	 * a RQ_PERMISSION request to the server.
	 */

	filerp->u.lookuprp.check_xattrs = has_xattrs(spath.dentry->d_inode,
	                                             path, filerq, debug);
	/* Send the underlying file system's magic value back on a lookup */
	filerp->u.lookuprp.underlying_magic = spath.dentry->d_inode->i_sb->s_magic;

	/* Success case 1 */
	/* copy inode, release dentry */
	copy_inode_info(spath.dentry->d_inode,
	                &filerp->u.lookuprp.inode_copy);
	KDEBUG_OFS(debug, "DVS: %s: RQ_LOOKUP: inode path %s has size %Ld\n",
	           __FUNCTION__, path, filerp->u.lookuprp.inode_copy.i_size);
	filerp->u.lookuprp.inode_valid = 1;
	filerp->u.lookuprp.node = usi_node_addr;
	path_put(&spath);

	return rval;
}


int dvs_rq_getattr(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp = NULL;
	struct path *path_ptr, spath;
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	fp = rr ? rr->fp : NULL;

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	/*
	 * If we are given a file pointer, use its struct path, otherwise
	 * get it through the string path
	 */
	if (fp) {
		KDEBUG_OFS(debug, "DVS: RQ_GETATTR fp: %p nnodes %d\n",
				fp, filerq->nnodes);
		path_ptr = &fp->f_path;
		path_get(path_ptr);
	} else {
		dvs_get_path(filerq, &path, NULL);
		KDEBUG_OFS(debug, "DVS: RQ_GETATTR: file %s nnodes %d\n",
			   path, filerq->nnodes);
		if ((rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug)) &&
				filerq->flags.is_nfs && filerq->flags.multiple_servers) {
			/*
			 * Must have had a successful lookup somewhere, let's
			 * try reevaluating/rescanning to update local dcache.
			 */
			rval = force_dcache_update(path, &spath, filerq, debug);
		}
		path_ptr = &spath;
	}

	if (rval)
		return rval; /* skip path_put */

	elapsed_jiffies = jiffies;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	rval = vfs_getattr(path_ptr->mnt, path_ptr->dentry,
	                   &filerp->u.getattrrp.kstatbuf);
#else
	rval = vfs_getattr(path_ptr, &filerp->u.getattrrp.kstatbuf);
#endif
	log_fs("getattr", path, jiffies - elapsed_jiffies, filerq);
	path_put(path_ptr);

	if (rval)
		KDEBUG_FSE(debug, "getattr returned %ld for path %s\n", rval, path);

	return rval;
}

int dvs_rq_setattr(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct path spath;
	struct file *fp;
	struct dentry *dep = NULL;
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: RQ_SETATTR: file %s nnodes %d\n",
	           path, filerq->nnodes);

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	/* Use a file pointer if we're given one */
	if (fp) {
		dep = fp->f_path.dentry;
	} else {
		/* Try to get the file path */
		if ((rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug)))
			return rval;
		dep = spath.dentry;
	}

	/*
	 * The ATTR_FILE flag should only be set if we have a valid file
	 * pointer. Since the iattr struct is filled in on the client
	 * side, there may be a valid file struct there but not one on
	 * the server side. If that's the case, just clear the flag.
	 * Specifically, this was a problem with mounting Lustre over
	 * DVS (bug 806435).
	 */
	if (!fp)
		filerq->u.setattrrq.attr.ia_valid &= ~ATTR_FILE;

	if (filerq->u.setattrrq.attr.ia_valid & ATTR_FILE)
		filerq->u.setattrrq.attr.ia_file = fp;

	mutex_lock(&dep->d_inode->i_mutex);

	/* update inode, release dentry */
	elapsed_jiffies = jiffies;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	rval = notify_change(dep, &filerq->u.setattrrq.attr);
#else
	rval = notify_change(dep, &filerq->u.setattrrq.attr, NULL);
#endif
	mutex_unlock(&dep->d_inode->i_mutex);
	log_fs("setattr", path, jiffies - elapsed_jiffies, filerq);

	if (!fp)
		path_put(&spath);

	if (rval < 0)
		KDEBUG_FSE(debug, "setattr returned %ld for path %s\n", rval, path);

	return rval;
}

int dvs_rq_getxattr(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	long rval = 0;
	char *path, *name, *value = NULL;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: RQ_GETXATTR: file %s nnodes %d\n",
	           path, filerq->nnodes);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) +
	                                        filerq->u.getxattrrq.valuelen,
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply) +
	                                     filerq->u.getxattrrq.valuelen;

	if (strlen(path)+1 != filerq->u.getxattrrq.pathlen) {
		printk(KERN_ERR "DVS: RQ_GETXATTR: bad path\n");
		return -EFAULT;
	}

	name = path + filerq->u.getxattrrq.pathlen;
	if (strlen(name)+1 != filerq->u.getxattrrq.namelen) {
		printk(KERN_ERR "DVS: RQ_GETXATTR: bad name\n");
		return -EFAULT;
	}

	if (filerq->u.getxattrrq.valuelen > 0)
		value = filerp->u.getxattrrp.data;

	elapsed_jiffies = jiffies;
	rval = p_sys_getxattr(path, name, value, filerq->u.getxattrrq.valuelen);
	log_fs("getxattr", path, jiffies - elapsed_jiffies, filerq);

	if (rval < 0 && rval != -EOPNOTSUPP && rval != -ENODATA)
		KDEBUG_FSE(debug, "getxattr returned %ld for path %s, name %s\n", rval,
		           path, name);

	return rval;
}

int dvs_rq_setxattr(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	long rval = 0;
	char *path, *name, *value;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: RQ_SETXATTR: file %s nnodes %d\n", path,
	           filerq->nnodes);

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	if (strlen(path)+1 != filerq->u.setxattrrq.pathlen ) {
		printk(KERN_ERR "DVS: RQ_SETXATTR: bad path\n");
		return  -EFAULT;
	}

	name = path + filerq->u.setxattrrq.pathlen;
	if ( strlen(name)+1 != filerq->u.setxattrrq.namelen ) {
		printk(KERN_ERR "DVS: RQ_SETXATTR: bad name\n");
		return -EFAULT;
	}

	value = name + filerq->u.setxattrrq.namelen;

	elapsed_jiffies = jiffies;
	rval = p_sys_setxattr(path, name, value,
		filerq->u.setxattrrq.valuelen, filerq->u.setxattrrq.flags);
	log_fs("setxattr", path, jiffies - elapsed_jiffies, filerq);

	if (rval < 0)
		KDEBUG_FSE(debug, "setxattr returned %ld for path %s, name %s\n", rval,
		           path, name);
	
	return rval;
}

int dvs_rq_listxattr(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	long rval = 0;
	char *path, *list = NULL;
	struct file_reply *filerp;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: RQ_LISTXATTR: file %s nnodes %d\n",
	           path, filerq->nnodes);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) +
	                                        filerq->u.listxattrrq.listlen,
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply) +
	                                     filerq->u.listxattrrq.listlen;

	if (strlen(path)+1 != filerq->u.listxattrrq.pathlen) {
		printk(KERN_ERR "DVS: RQ_LISTXATTR: bad path\n");
		return -EFAULT;
	}

	if (filerq->u.listxattrrq.listlen > 0)
		list = filerp->u.listxattrrp.data;

	elapsed_jiffies = jiffies;
	rval = p_sys_listxattr(path, list, filerq->u.listxattrrq.listlen);
	log_fs("listxattr", path, jiffies - elapsed_jiffies, filerq);

	if (rval < 0 && rval != -EOPNOTSUPP && rval != -ENODATA)
		KDEBUG_FSE(debug, "listxattr returned %ld for path %s\n", rval, path);

	return rval;
}

int dvs_rq_removexattr(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	long rval = 0;
	char *path, *name;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: RQ_LISTXATTR: file %s nnodes %d\n",
	           path, filerq->nnodes);

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	if (strlen(path)+1 != filerq->u.removexattrrq.pathlen) {
		printk(KERN_ERR "DVS: RQ_REMOVEXATTR: bad path\n");
		return -EFAULT;
	}

	name = path + filerq->u.removexattrrq.pathlen;
	if (strlen(name)+1 != filerq->u.removexattrrq.namelen) {
		printk(KERN_ERR "DVS: RQ_REMOVEXATTR: bad name\n");
		return -EFAULT;
	}

	elapsed_jiffies = jiffies;
	rval = p_sys_removexattr(path, name);
	log_fs("removexattr", path, jiffies - elapsed_jiffies, filerq);
	if (rval < 0)
		KDEBUG_FSE(debug, "removexattr returned %ld for path %s, name %s\n",
		           rval, path, name);

	return rval;
}

int dvs_rq_truncate(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	elapsed_jiffies = jiffies;
	rval = p_sys_truncate(path, filerq->u.truncaterq.len);
	log_fs("truncate", path, jiffies - elapsed_jiffies, filerq);

	if (rval < 0)
		KDEBUG_FSE(debug, "truncate returned %ld for path %s\n", rval, path);

	return rval;
}

int dvs_rq_readlink(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	long rval;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);
	KDEBUG_OFS(debug, "DVS: readlink: %s\n", get_last_path(path));

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) +
	                                        filerq->u.readlinkrq.bufsize,
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply) +
	                                     filerq->u.readlinkrq.bufsize;

	elapsed_jiffies = jiffies;
	rval = p_sys_readlink(path, filerp->u.readlinkrp.pathname,
	                      filerq->u.readlinkrq.bufsize);
	log_fs("readlink", path, jiffies - elapsed_jiffies, filerq);
	if (rval >= 0) {
		filerp->u.readlinkrp.pathname[rval] = 0;
		filerp->ipcmsg.reply_length = sizeof(struct file_reply) + rval;
	} else {
		KDEBUG_FSE(debug, "readlink returned %ld for path %s\n", rval, path);
	}

	return rval;
}

int dvs_rq_mkdir(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp, *ncfs_filerp = NULL;
	char *path, *sp = NULL;
	long rval = 0;
	int nnodes, bossnode = 0;
	int *freq_node;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	nnodes = filerq->nnodes;
	freq_node = filerq_get_node_base(filerq, filerq->node_offset);

	if ((filerq->nnodes > 1) && (usi_node_addr == freq_node[0])) {
		if ((ncfs_filerp = kmalloc_ssi(sizeof(struct file_reply),
		                                GFP_KERNEL)) == NULL)
			return -ENOMEM;
		INODE_SEMA_DOWN(path);
		sp = path;
		bossnode = 1;
	}

	elapsed_jiffies = jiffies;
	rval = p_sys_mkdir(path, filerq->u.mkdirrq.mode);
	log_fs("mkdir", path, jiffies - elapsed_jiffies, filerq);
	if (filerq->rip && rval == -EEXIST) {
		KDEBUG_OFS(debug, "DVS: RQ_MKDIR: clear EEXIST, "
		           "path %s\n", path);
		rval = 0;
	}
	if (rval >= 0) {
		get_inode_info(path, 0, &filerp->u.mkdirrp.inode_copy, filerq, debug);
	} else {
		KDEBUG_FSE(debug, "mkdir returned %ld for path %s, mode 0x%x\n", rval,
		           path, filerq->u.mkdirrq.mode);
	}

	/*
	 * If we're not the first node in the stripe, we're done.
	 * If this is a parallel FS, we're also done.
	 */
	if (bossnode) {
		rval = noclusterfs_mkdir(filerq, path, ncfs_filerp);
	}

	if (ncfs_filerp) {
		free_msg(ncfs_filerp);
	}

	if (sp)
		INODE_SEMA_UP(sp);

	return rval;
}

int dvs_rq_rmdir(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp, *ncfs_filerp = NULL;
	struct path spath;
	char *path, *sp = NULL;
	long rval = 0;
	int nnodes, enoent = 0;
	int *freq_node;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug);
	if (rval)
		return rval;

	nnodes = filerq->nnodes;
	freq_node = filerq_get_node_base(filerq, filerq->node_offset);

	if ((filerq->nnodes > 1) && (usi_node_addr == freq_node[0])) {
		if ((ncfs_filerp = kmalloc_ssi(sizeof(struct file_reply),
		                               GFP_KERNEL)) == NULL) {
			path_put(&spath);
			return -ENOMEM;
		}
		INODE_SEMA_DOWN(path);
		sp = path;
		if ((rval = noclusterfs_rmdir(filerq, path, ncfs_filerp,
		                              &enoent)) < 0) {
			free_msg(ncfs_filerp);
			if (sp)
				INODE_SEMA_UP(sp);

			path_put(&spath);
			return rval;
		}
	}

	elapsed_jiffies = jiffies;
	rval = p_sys_rmdir(path);
	log_fs("rmdir", path, jiffies - elapsed_jiffies, filerq);
	if (rval < 0) {
		KDEBUG_FSE(debug, "rmdir returned %ld for path %s\n", rval, path);
		if (rval == -ENOENT)
			enoent++;
	}
	if (nnodes > 1) {
		if (enoent == filerq->nnodes) {
			rval = -ENOENT;
		} else {
			rval = 0;
		}
	}

	if (ncfs_filerp) {
		free_msg(ncfs_filerp);
	}

	copy_inode_info(spath.dentry->d_inode,
	                &filerp->u.rmdirrp.inode_copy);

	if (sp)
		INODE_SEMA_UP(sp);

	path_put(&spath);

	return rval;
}


int dvs_rq_readdir(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp;
	long rval = 0;
	int fd;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) + 
	                                        filerq->u.readdirrq.count,
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: cannot get unused fd\n");
		return fd;
	}

	fp = rr ? rr->fp : NULL;

	/* push file handle into current */
	if (fp == NULL) {
		DVS_TRACE("fp==NULL", filerq->context.node, filerq->request);
		put_unused_fd(fd);
		return -EINVAL;
	}
	fd_install_get(fd, fp);

	if (filerq->u.readdirrq.offset != -1) {
		if (fp->f_op->llseek) {
			fp->f_op->llseek(fp, filerq->u.readdirrq.offset, 0);
		} else {
			default_llseek(fp, filerq->u.readdirrq.offset, 0);
		}
	}

	/* change address to be the ipc reply */
	elapsed_jiffies = jiffies;
	rval = p_sys_getdents64(fd,
	                      (struct linux_dirent64 *)filerp->u.readdirrp.data,
	                      filerq->u.readdirrq.count);
	log_fs("getdents64", fpname(fp), jiffies - elapsed_jiffies, filerq);
	if (rval >= 0) {
		/* must return current file position to client */
		filerp->u.readdirrp.f_pos = fp->f_pos;
		(*filerp_ptr)->ipcmsg.reply_length =
		                               sizeof(struct file_reply) + rval;
	} else {
		KDEBUG_FSE(debug, "readdir returned %ld for file %s (fp: 0x%p)\n", rval,
		           fpname(fp), fp); 
	}

	fd_uninstall(fd);
	put_unused_fd(fd);

	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_unlink(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct path spath;
	char *path, *sp = NULL;
	long rval = 0;
	int nnodes, enoent = 0;
	int *freq_node;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug);
	if (rval)
		return rval;

	nnodes = filerq->nnodes;
	freq_node = filerq_get_node_base(filerq, filerq->node_offset);

	/*
	 * nnodes will only be greater than 1 if 'noclusterfs' was
	 * specified.
	 */
	if ((nnodes > 1) && (usi_node_addr == freq_node[0])) {
		INODE_SEMA_DOWN(path);
		sp = path;
		if ((rval = noclusterfs_unlink(filerq, path, &enoent)) < 0) {
			if (sp)
				INODE_SEMA_UP(sp);

			path_put(&spath);
			return rval;
		}
	}

	elapsed_jiffies = jiffies;
	rval = p_sys_unlink(path);
	log_fs("unlink", path, jiffies - elapsed_jiffies, filerq);
	if (rval < 0) {
		KDEBUG_FSE(debug, "unlink returned %ld for path %s\n",
		           rval, path);
		if (rval == -ENOENT)
			enoent++;
	}
	if (filerq->nnodes > 1) {
		if (enoent == filerq->nnodes) {
			rval = -ENOENT;
		} else {
			rval = 0;
		}
	}

	copy_inode_info(spath.dentry->d_inode,
	                &filerp->u.unlinkrp.inode_copy);

	if (sp)
		INODE_SEMA_UP(sp);

	path_put(&spath);

	return rval;
}

int dvs_rq_create(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *filp, *active_fp = NULL;
	long rval = 0;
	int lflags, nnodes, bossnode = 0;
	int *freq_node;
	char *path, *sp = NULL;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	/* Revert client-side flag changes */
	lflags = dvs_rollback_flags(filerq->u.createrq.flags);

	KDEBUG_OFS(debug, "RQ_CREATE: %s flags 0x%x lflags 0x%x mode 0x%x node name %s\n",
	           path, filerq->u.createrq.flags,
	           lflags, filerq->u.createrq.mode,
	           SSI_NODE_NAME(filerq->context.node));

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) +
	                                        (2 * filerq->u.createrq.dwfs_path_len),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply) +
	                                  (2 * filerq->u.createrq.dwfs_path_len);

	nnodes = filerq->nnodes;
	freq_node = filerq_get_node_base(filerq, filerq->node_offset);

	/*
	 * nnodes will only be greater than 1 if 'noclusterfs' was
	 * specified.
	 */
	if ((nnodes > 1) && (usi_node_addr == freq_node[0])) {
		INODE_SEMA_DOWN(path);
		sp = path;
		bossnode = 1;
	}

	elapsed_jiffies = jiffies;
	filp = filp_open(path, lflags, filerq->u.createrq.mode);
	log_fs("create", path, jiffies - elapsed_jiffies, filerq);

	if (IS_ERR(filp)) {
		rval = PTR_ERR(filp);
		KDEBUG_FSE(debug, "create returned %ld for path %s, "
		           "mode 0x%x\n", rval,
		           path, filerq->u.createrq.mode);
		if (sp)
			INODE_SEMA_UP(sp);
		return rval;
	}

	copy_inode_info(file_inode(filp),
	                &filerp->u.createrp.inode_copy);
	/* Send the underlying magic number back to the client for the new inode */
	filerp->u.createrp.underlying_magic = file_inode(filp)->i_sb->s_magic;

	/*
	 * Complete an open request if we are piggybacking the open
	 * data with the create request.
	 */
	if (filerq->u.createrq.intent_open) {
		filerp->u.createrp.open_reply.dwfs_info.path_len = filerq->u.createrq.dwfs_path_len;
		rval = dvs_finish_open(filp, filerq, filerp,
		                   &filerp->u.createrp.open_reply);
		if (rval) {
			elapsed_jiffies = jiffies;
			filp_close(filp, NULL);
			log_fs("close[dvs_rq_create]", path,
			       jiffies - elapsed_jiffies, filerq);
		}
		goto create_done;
	}

	elapsed_jiffies = jiffies;
	filp_close(filp, NULL);
	log_fs("close[dvs_rq_create]", path, jiffies - elapsed_jiffies,
	       filerq);

	/* If 'noclusterfs' was not specified, we are done. */
	if (bossnode)
		rval = noclusterfs_create(filerq, path);

create_done:
	if (sp)
		INODE_SEMA_UP(sp);

	if (active_fp) {
		KDEBUG_OFS(debug, "DVS: %s OUT:  active_fp 0x%p, count %d\n",
		           file_request_to_string(filerq->request),
		           active_fp,
		           (int)atomic_long_read(&active_fp->f_count));
		fput(active_fp);
	}

	return rval;
}

int dvs_rq_open(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct path spath;
	struct file *fp = NULL;
	struct file *active_fp = NULL;
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) +
	                                        (2 * filerq->u.openrq.dwfs_path_len),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply) +
	                                  (2 * filerq->u.openrq.dwfs_path_len);

	fp = rr ? rr->fp : NULL;

	KDEBUG_OFS(debug, "RQ_OPEN: %s flags: 0x%x d_open %d %s\n",
			path, filerq->u.openrq.flags,
			filerq->u.openrq.d_open,
			SSI_NODE_NAME(filerq->context.node));

	/*
	 * In the open(O_CREAT) case, we will have already created the
	 * file through the initial ucreate()/RQ_CREATE path. Now
	 * we just need to get a handle to the create file.
	 */
	if ((filerq->u.openrq.flags & O_CREAT) && (filerq->u.openrq.d_open)) {
		if ((rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug)) &&
					    filerq->flags.is_nfs &&
					    filerq->flags.multiple_servers) {
			KDEBUG_OFS(debug, "DVS: %s: NFS dvs_path_lookup failed: %s %ld\n",
			           __FUNCTION__, path, rval);
			rval = force_dcache_update(path, &spath, filerq, debug);
		}

		if (rval)
			return rval;
		elapsed_jiffies = jiffies;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		fp = dentry_open(spath.dentry, spath.mnt,
		                 filerq->u.openrq.flags, current_cred());
#else
                fp = dentry_open(&spath,
                                 filerq->u.openrq.flags, current_cred());
		path_put(&spath);
#endif
		log_fs("open", path, jiffies - elapsed_jiffies, filerq);

		if (!IS_ERR(fp))
			goto open_succeeded;

		KDEBUG_FSE(debug, "dentry_open returned %ld for "
				"path %s, flags 0x%x\n", PTR_ERR(fp),
				path, filerq->u.openrq.flags);
	}

	/*
	 * This is plain jane open - not create. The file should exist
     * already, but we insert the client's mode to prevent a possible
     * race condition anyway. This race condition can occur if, after
     * an open-path create request returns, a different process deletes
     * the file on the server before the opening/creating process can 
     * open the newly made file it assumes still exists.
     * We may also get here if we fall back to filp_open on a failed
     * dentry_open.
	 */
	elapsed_jiffies = jiffies;
	if (filerq->u.openrq.use_openexec) {
		fp = open_exec(path);
	} else {
		fp = filp_open(path,
				filerq->u.openrq.flags | O_LARGEFILE,
				filerq->u.openrq.i_mode);
	}
	log_fs("open", path, jiffies - elapsed_jiffies, filerq);

	if (IS_ERR(fp)) {
		rval = PTR_ERR(fp);
		KDEBUG_FSE(debug, "filp_open returned %ld for path %s, flags "
				"0x%x\n", rval, path,
				filerq->u.openrq.flags | O_LARGEFILE);
		return rval;
	}

open_succeeded:
	/* do ro_cache hashtable entry checking/setting */
	if (filerq->u.openrq.ro_cache_check == RO_CACHE_READONLY) {
		if (usi_node_addr == filerq->u.openrq.ro_cache_node) {
			if ((rval = ro_cache_readonly(fp, path, &filerq->ipcmsg,
			                  filerq->u.openrq.ro_cache_cfp)) < 0) {
				printk(KERN_ERR "DVS: RQ_OPEN ro_cache_readonly"
				       " failure %ld: disabling caching\n",
				       rval);
				       filerp->u.openrp.ro_cache_check = 0;
			} else {
				filerp->u.openrp.ro_cache_check = rval;
			}
		}
	} else if (filerq->u.openrq.ro_cache_check == RO_CACHE_WRITABLE) {
		if (usi_node_addr == filerq->u.openrq.ro_cache_node) {
			if ((rval = ro_cache_write(fp, path, filerq)) < 0) {
				printk(KERN_ERR "DVS: RQ_OPEN ro_cache_write"
				       " failure %ld\n", rval);
				if (filerq->u.openrq.use_openexec)
					allow_write_access(fp);
				elapsed_jiffies = jiffies;
				filp_close(fp, NULL);
				log_fs("close[dvs_rq_open]", path,
				       jiffies - elapsed_jiffies, filerq);
				goto open_done;
			}
			filerp->u.openrp.ro_cache_check = rval;
		}
	}

	/* If this is a write only cached open add read perms to the file
	 * handle so cache pages being modified can first be read in if
	 * required. Actual user acces is controlled by client fp perms which
	 * won't change and real file system access was checked by the open
	 * on the backing file system above with the requested access flags. */
	if ((filerq->u.openrq.wb_cache) && (fp->f_mode & FMODE_WRITE) &&
	    !(fp->f_mode & FMODE_READ)) {
		fp->f_mode |= FMODE_PREAD | FMODE_READ;
	}

	KDEBUG_OFS(debug, "RQ_OPEN (%s) after filp_open OK fp 0x%p count %d\n",
	           path, fp, (int)atomic_long_read(&fp->f_count));

	/* for DWCFS to communicate the open flags via ioctl */
	if ((rval = dvs_dwcfs_init(fp, filerq)) < 0) {
		printk(KERN_ERR "%s dvs_dw_init failed %ld\n", __func__, rval);
		filp_close(fp, NULL);
		goto open_done;
	}

	filerp->u.openrp.dwfs_info.path_len = filerq->u.openrq.dwfs_path_len;
	rval = dvs_finish_open(fp, filerq, filerp, &filerp->u.openrp);
	if (rval) {
		if (filerq->u.openrq.use_openexec)
			allow_write_access(fp);
		elapsed_jiffies = jiffies;
		filp_close(fp, NULL);
		log_fs("close[dvs_rq_open]", path, jiffies - elapsed_jiffies,
		       filerq);
		goto open_done;
	}

	/*
	 * Disable readhead if file could stripe across servers.  This
	 * should affect page faults only, and not calls to readahead
	 * from DVS.
	 */
	if (filerq->u.openrq.max_nodes > 1)
		fp->f_ra.ra_pages = 0;

	rval = 0;

open_done:
	if (active_fp) {
		KDEBUG_OFS(debug, "DVS: %s OUT:  active_fp 0x%p, count %d\n",
		           file_request_to_string(filerq->request),
		           active_fp,
		           (int)atomic_long_read(&active_fp->f_count));
		fput(active_fp);
	}

	return rval;
}

/*
 * DEPRECATED 06/2014   Leave in for a while as live code which could
 * be enabled via a patch in the field in case things go horribly wrong
 * with the new ureadpages stuff.
 *
 * RQ_READPAGE_ASYNC is never directly responded to, so the
 * corresponding entry's RPC statistics in the stats file on the
 * server will always be 0.
 */
int dvs_rq_readpage_async(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_request *filerq2;
	struct file *fp;
	long rval = 0;
	int frep_size;

	fp = rr ? rr->fp : NULL;

	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) "
		       "for %s from %s\n", rr,
		       file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_rpa", rr, filerq->context.node, filerq->request,
		           0, 0);
		return -EINVAL;
	}

	get_file(fp);

	if (!(fp->f_op && (fp->f_op->read != NULL))) {
		printk(KERN_ERR "DVS: RQ_READPAGE_ASYNC: "
		       "no file read op!\n");
		rval = -USIERR_NOT_SUPPORTED;
		goto rpa_done;
	}

	/* allocate reply message */
	frep_size = sizeof(struct file_request) + filerq->u.readpagerq.count;
	filerq2 = kmalloc_ssi(frep_size, GFP_KERNEL);
	if (!filerq2) {
		rval = -ENOMEM;
		goto rpa_done;
	}

	rval = fp->f_op->read(fp, filerq2->u.readpagedata.data,
	                      filerq->u.readpagerq.count,
	                      &filerq->u.readpagerq.offset);
	if (rval < 0) {
		printk(KERN_ERR "DVS: RQ_READPAGE_ASYNC failed %ld\n", rval);
		KDEBUG_FSE(debug, "readpage returned %ld for file %s (fp: 0x%p)\n", rval,
		           fpname(fp), fp); 
	} else {
		/* increment DVS read byte counters */
		dvsproc_stat_update(NULL, DVSPROC_STAT_IO, filerq->request,
		                    rval);

		if (rval < filerq->u.readpagerq.count) {
			KDEBUG_OFS(debug, "DVS: RQ_READPAGE_ASYNC: short %ld %ld %Ld "
			           "%Ld %s\n", rval,
			           filerq->u.readpagerq.count,
			           filerq->u.readpagerq.offset,
			           file_inode(fp)->i_size,
			           fp->f_path.dentry->d_name.name);
		}
	}
	filerq2->request = RQ_READPAGE_DATA;
	filerq2->retry = filerq->retry;
	filerq2->rip = filerq->rip;
	filerq2->u.readpagedata.iop = filerq->u.readpagerq.iop;
	filerq2->u.readpagedata.iip = filerq->u.readpagerq.iip;
	filerq2->u.readpagedata.count = rval;
	filerq2->u.readpagedata.csize = filerq->u.readpagerq.csize;
	capture_context((&filerq2->context));

	rval = send_ipc_request_async_stats(NULL, SOURCE_NODE(&filerq->ipcmsg),
	                                    RQ_FILE, filerq2, frep_size, NULL,
	                                    0,
	                                    REMOTE_IDENTITY(&filerq->ipcmsg));

	if (rval && (rval != -EHOSTDOWN)) {
		printk(KERN_ERR "DVS: RQ_READPAGE_ASYNC failed to send data to "
		       "%s: %ld\n", SSI_NODE_NAME(SOURCE_NODE(&filerq->ipcmsg)),
		       rval);
	}

	/* free_msg/kfree_ssi() handles both kfree() and vfree() */
	free_msg(filerq2);

	/* WARNING:  errors not handled !! */
rpa_done:
	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

/*
 * DEPRECATED 06/2014   Leave in for a while as live code which could
 * be enabled via a patch in the field in case things go horribly wrong
 * with the new ureadpages stuff.
 *
 * EXECUTED ON CLIENTS (NOT SERVER)
 */
int dvs_rq_readpage_data(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct inode_info *iip;
	struct inode *ip = NULL;
	struct outstanding_io *iop, *iop2, **poio;
	struct outstanding_page *opp, *opp2;
	struct async_retry *p;
	struct list_head *lp, *tp;
	struct page *pagep;
	struct dvsproc_stat *stats;
	void *pgp;
	long rval = 0;
	char *rpd;
	int pi, clen, waste, found = 0;

	KDEBUG_OFS(debug, "DVS: RQ_READPAGE_DATA: 0x%p %ld\n",
	           filerq->u.readpagedata.iop,
	           (long)filerq->u.readpagedata.count);
	iop = filerq->u.readpagedata.iop;
	iip = filerq->u.readpagedata.iip;
	poio = &filerq->u.readpagedata.iip->oio;

	down(&aretrysem[SOURCE_NODE(&filerq->ipcmsg)]);
	list_for_each_safe(lp, tp, &alist[SOURCE_NODE(&filerq->ipcmsg)]) {
		p = list_entry(lp, struct async_retry, list);
		if (p->readpage.op == iop) {
			list_del(&p->list);
			DVS_TRACE("RQRPFREE", p->filerq, p);
			free_msg(p->filerq);
			kfree_ssi(p);
			found = 1;
			break;
		}
	}
	up(&aretrysem[SOURCE_NODE(&filerq->ipcmsg)]);

	/*
	 * If the outstanding IO request was not found in the async
	 * retry list, the initiator must have cancelled the request
	 * and done all necessary cleanup.
	 */
	if (!found) {
		return rval;
	}

	/* increment DVS read byte counter */
	if (iip->fp != NULL) {
		ip = file_inode(iip->fp);
		stats = INODE_ICSB(ip)->stats;
		if (filerq->u.readpagedata.count > 0) {
			dvsproc_stat_update(stats, DVSPROC_STAT_IO,
			                    filerq->request,
			                    filerq->u.readpagedata.count);
		}
	}

	waste = filerq->u.readpagedata.count;

	down(&iip->oio_sema);
	opp = iop->op;
	while (opp) {
		pagep = opp->pagep;
		pi = pagep->index - (iop->offset / PAGE_SIZE);
		clen = filerq->u.readpagedata.count - (pi * PAGE_SIZE);
		KDEBUG_OFS(debug, "DVS: RQ_READPAGE_DATA: found 0x%p %d %d\n", pagep,
		           pi, clen);
		pgp = kmap(pagep);
		rpd = filerq->u.readpagedata.data + (pi * PAGE_SIZE);
		if (clen < 0) {
			/* short read, happens if truncate or read past eof */
			/* Check for holes. */
			if (iop->offset < filerq->u.readpagedata.csize) {
				memset((char*)pgp, 0, PAGE_SIZE);
				SetPageUptodate(pagep);
			} else {
				KDEBUG_OFS(debug, "DVS: RQ_READPAGE_DATA: got error "
				           "from server %d %ld %Ld %d\n", pi,
				           filerq->u.readpagedata.count,
				           iop->offset, iop->length);
				SetPageError(pagep);
			}
		} else {
			if (clen < PAGE_SIZE) {
				KDEBUG_OFS(debug, "DVS: RQ_READPAGE_DATA: delivered "
				           "%d bytes (1)\n", clen);
				memcpy(pgp, rpd, clen);
				memset((char *)pgp + clen, 0, PAGE_SIZE - clen);
				SetPageUptodate(pagep);
			} else {
				KDEBUG_OFS(debug, "DVS: RQ_READPAGE_DATA delivered "
				           "%ld bytes (2)\n", rval);
				memcpy(pgp, rpd, PAGE_SIZE);
				SetPageUptodate(pagep);
			}
		}
		waste -= clen;

		kunmap(pagep);
		flush_dcache_page(pagep);
		unlock_page(pagep);
		opp2 = opp;
		opp = opp->next;
		kfree_ssi(opp2);
	}

	DVS_TRACEL("RPgdata", ip, waste, iop->offset, iop->length,
	           filerq->u.readpagedata.count);
	if (waste > 0)
		KDEBUG_OFS(debug, "DVS: RQ_READPAGE_DATA: wasted %d %Ld\n", waste,
		           iop->offset);

	/* unlink and free iop */
	if (iop == *poio) {
		*poio = iop->next;
	} else {
		iop2 = *poio;
		while (iop2) {
			if (iop == iop2->next) {
				iop2->next = iop->next;
				break;
			}
			iop2 = iop2->next;
		}
	}
	up(&iip->oio_sema);
	kfree_ssi(iop);

	return rval;
}

/* 
 * Accumulate IO transfer counts and offsets. Each full pages request is
 * farmed out as individual I/O requests spread over different CPUs, and as
 * each individual request completes, we use this code to update accumulators
 * in the original request.
 */
static inline void
_accumulate_totals(struct pages_request *pages_req, struct io_pages_reply *io_reply)
{
	/* 
	 * io_reply->xfer_count is the actual number of bytes exchanged with the
	 * backing store: the sum of iov read return values, or -1 if there was
	 * an error on any iov read. It will be <= requested length. If the file
	 * we are trying to cache hits EOF on read, we'll get a short total count.
	 * 
	 * The LNET transfer has been started, but it may be a while before it
	 * completes, and if there are errors, they will be caught in the
	 * process_iovs() code.
	 */
	if (io_reply->xfer_count < 0) {
		atomic64_inc(&pages_req->xfer_error);
	} else {
		atomic64_add(io_reply->xfer_count, &pages_req->xfer_count);
		atomic64_max(&pages_req->xfer_maxoff, pages_req->offset + io_reply->xfer_count);
	}
}

/*
 * Record totals in the statistics.
 */
static inline void
_record_totals(struct inode *ip, struct pages_request *pages_req, int op)
{
	/* Only log totals if there were no errors */
	if (! atomic64_read(&pages_req->xfer_error)) {
		struct dvsproc_stat *stats = INODE_ICSB(ip)->stats;
		dvsproc_stat_update(stats,
				    DVSPROC_STAT_CLIENT_LEN, op,
				    atomic64_read(&pages_req->xfer_count));
		dvsproc_stat_update(stats,
				    DVSPROC_STAT_CLIENT_OFF, op,
				    atomic64_read(&pages_req->xfer_maxoff));
	}
}

/* EXECUTED ON CLIENTS (NOT SERVER) */
int dvs_rq_readpages_rp(struct file_request *filerq, struct file_reply **filerp,
			struct remote_ref *rr, unsigned long debug)
{
	struct io_pages_reply		*io_reply;
	struct file_request		*orig_req;
	struct pages_request		*pages_req;
	struct inode_info		*iip;
	struct inode			*ip;
	struct io_parallel_request	*ipr;
	int				rval;

	io_reply = &filerq->u.iopagesrp;
	orig_req = io_reply->source_request;  /* may not be valid anymore */

	/*
	 * If the server returned ESTALE_DVS_RETRY, use __async_op_retry() to
	 * retry the request up to estale_max_retry times before failing the
	 * request.  Note that the call to unlink_filerq() doesn't actually
	 * unlink the request in this case.
	 */
	if (io_reply->xfer_count == -ESTALE_DVS_RETRY || io_reply->xfer_count == -EQUIESCE) {
		rval = unlink_filerq(orig_req, filerq->ipcmsg.source_seqno,
				     SOURCE_NODE(&filerq->ipcmsg),
				     UNLNK_ESTALE_Retry);
		/*
		 * If this special "UNLNK_ESTALE_Retry" call to unlink_filerq()
		 * returns zero, we call __async_op_retry() to retry the
		 * operation.  Otherwise, we continue on and handle the error
		 * using normal techniques.
		 */
		if (rval == 0) {
			__async_op_retry(SOURCE_NODE(&filerq->ipcmsg), 0,
					 orig_req);
			return 0;
		}
	}

	/*
	 * See if we can unlink the file request.  If we can, that meant
	 * that it was still valid, we now own it and we're OK to proceed.
	 * unlink_request() has a comment which describes this hierarchy
	 * in greater detail.
	 *
	 * If it's gone, so is the pages request and we've got nothing to do
	 * unless there were file system errors that we need to forward.
	 */
	if ((rval = unlink_filerq(orig_req, filerq->ipcmsg.source_seqno,
			SOURCE_NODE(&filerq->ipcmsg), UNLNK_Have_Reply)) > 0) {
		pages_req = orig_req->u.iopagesrq.rq;
	}
	else {
		/*
		 * Forward errors from the file system or an actual zero-length
		 * read (DVS IPC would have ignored it thus no message would
		 * have been sent) -- there has to be somebody waiting.
		 *
		 * If it's EAGAIN -- not sure what to make of that.  We
		 * obviously received a return message so not sure why the
		 * request would have been retried by failover.
		 */
		if (io_reply->xfer_count <= 0) {
			(void) process_iovs(NULL, NULL, io_reply,
			                    PRIOV_Error_Messenger);
		}

		return rval;
	}

	/* We're good - the request was still valid. */
        orig_req->ipcmsg.state = ST_SEND_COMPL;
	ip = pages_req->ip;
	iip = (struct inode_info *)ip->i_private;

	ipr = &orig_req->u.iopagesrq.ipr;

	KDEBUG_RPS(0, "DVS: %s: %s: received %ld of %ld for inode 0x%p "
	           "request 0x%p iovs %d\n", __FUNCTION__,
	           file_request_to_string(filerq->request),
	           io_reply->xfer_count, ipr->length,
	           ip, pages_req, ipr->count);

	/* Add reply lengths to the request page for statistics */
	_accumulate_totals(pages_req, io_reply);

	/*
	 * For each of the iovs that we received, find the matching pages
	 * and process each one.
	 */
	(void) process_iovs(pages_req, ipr, io_reply, PRIOV_Normal);

	/*
	 * OK, we got all of the iovs processed -- will never be more than 2
	 * (single server) unless the kernel 2MB limit is removed.
	 *
	 * Now, enter the cleanup phase.  We still have the extent mapped
	 * and now that we're done processing our pages, let's see if we're
	 * the last one still here.  If so, clean up the pages request and
	 * perhaps the pages descriptor.
	 *
	 * Recall that there can be multiple requests issued on the
	 * pages for different extents and multiple messages per request.
	 */
	if (!atomic_dec_return(&pages_req->msgs_outstanding)) {
		/* We're the last waiter - clean up */
		RELEASE_MSG_WAITERS(pages_req);
		/* Record totals for statistics */
		_record_totals(ip, pages_req, VFS_OP_READPAGES);
		(void) finalize_request(pages_req);
	}

	/*
	 * Async retry entries (ours is now gone), file requests and
	 * messages are 1-1 so we can free the original file request here.
	 */
	orig_req->u.iopagesrq.state = RPS_RPSRQ_FREE;
	free_msg(orig_req);  /* original file_request that is */

	return 0;
}

static ssize_t dvs_read(unsigned int fd, char *buf, size_t count, loff_t pos,
			int doing_readpages, struct file_request *filerq,
			struct file *fp)
{
	ssize_t rval, total;
	unsigned long elapsed_jiffies;
	mm_segment_t oldfs;

	total = 0;
	while (1) {
		if ((fp->f_flags & O_DIRECT) != 0) {
			oldfs = get_fs();
			set_fs(USER_DS);
		}

		elapsed_jiffies = jiffies;
		rval = p_sys_pread64(fd, buf, count, pos);

		if ((fp->f_flags & O_DIRECT) != 0) {
			set_fs(oldfs);
		}

		if (rval < 0) {
			log_fs(doing_readpages ? "readpages" : "read",
			       fpname(fp), jiffies - elapsed_jiffies, filerq);
			return rval;
		}
		log_fs(doing_readpages ? "readpages" : "read", fpname(fp),
		       jiffies - elapsed_jiffies, filerq);
		buf += rval;
		count -= rval;
		pos += rval;
		total += rval;
		if (count == 0 || rval == 0)
			break;
	}

	return total;
}

int dvs_read_common(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, int doing_readpages, unsigned long debug)
{
	struct file_request *priv_freq;
	struct file_reply *filerp;
	struct io_pages_reply *io_reply;
	struct io_parallel_request *ipr;
	struct file *fp;
	struct page **pglist;
	struct rma_state rma_state;
	void *mmva, *ava;
	char *datap;
	long rval = 0;
	int frep_size, fd, i, j, ret, total_xfer = 0;

	datap = NULL;
	filerp = NULL;
	ava = NULL;

	fp = rr ? rr->fp : NULL;

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: cannot get unused fd\n");
		return fd;
	}

	if (doing_readpages) {
		/*
		 * RQ_READPAGES_RQ is never directly responded to, so the
		 * corresponding entry's RPC statistics in the stats file on the
		 * server will always be 0.
		 *
		 * Do some set-up and then fall through to pretend that we're
		 * a RQ_PARALLEL_READ.
		 */
		ipr = &filerq->u.iopagesrq.ipr;

		/*
		 * Allocate space for the return file request plus a size_t
		 * for the actual amount read for each iov.  This pretty much is
		 * just going to be a file_request size + 16 at the moment.
		 */
		frep_size = sizeof(struct file_request) + (ipr->count *
		                                           sizeof(size_t));
		if ((priv_freq = kmalloc_ssi(frep_size, GFP_KERNEL)) == NULL) {
			put_unused_fd(fd);
			return -ENOMEM;
		}

		priv_freq->request = RQ_READPAGES_RP;
		priv_freq->retry = filerq->retry;
		priv_freq->rip = filerq->rip;
		priv_freq->ipcmsg.source_seqno = filerq->ipcmsg.seqno;
		io_reply = &priv_freq->u.iopagesrp;
		io_reply->source_request =
		                       filerq->u.iopagesrq.source_request;
		capture_context(&priv_freq->context);

		KDEBUG_RPS(debug, "DVS: %s: %s: server received request for 0x%p from %s"
		           " len %ld iov_count %d\n", __FUNCTION__,
		           file_request_to_string(filerq->request),
		           filerq->u.iopagesrq.rq,
		           SSI_NODE_NAME(filerq->context.node),
		           ipr->length, ipr->count);
	} else {
		frep_size = 0;
		ipr = &filerq->u.ioprq;
		io_reply = NULL;
		priv_freq = NULL;
	}

	/* push file handle into current */
	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) "
		       "for %s from %s\n", rr,
		       file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_pr", rr, filerq->context.node, filerq->request, 0, 0);
		rval = -EINVAL;

		put_unused_fd(fd);
		return rval;
	}

	fd_install_get(fd, fp);

	/*
	 * Calculate the total length of the IOVs for this node.
	 * Note that for READPAGES_RQ pr->length is the amount for
	 * this node but for PARALLEL_READ, pr->length is the sum of
	 * all the stripes (or the size presented to uread2())
	 */
	total_xfer = 0;
	for (i = 0; i < ipr->count; i++) {
		total_xfer += ipr->iov[i].count;
	}

	if (dvsof_concurrent_reads_count) {
		if (down_interruptible(&dvsof_concurrent_reads_sema))
			DVS_LOG("%s: down_interruptible() call on "
			        "dvsof_concurrent_reads_sema interrupted\n",
			        __func__);
	}

	if (ipr->rma_handle == NULL) {
		/*
		 * Allocate reply message with space for data, we
		 * should only be here if the payload is small, the
		 * larger ones would have an rma_handle.
		 */
		*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply) +
		                                   total_xfer, GFP_KERNEL);
		if (!filerp) {
			rval = -ENOMEM;
			goto readp_done;
		}

		datap = filerp->u.readrp.data;
	} else if (!doing_readpages) {
		*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
		                                   GFP_KERNEL);
		if (!filerp) {
			rval = -ENOMEM;
			goto readp_done;
		}

		(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);
	}

	total_xfer = 0;
	for (i = 0; i < ipr->count; i++) {
		if (ipr->rma_handle) {
			KDEBUG_OFS(debug, "%s: remote copy invoked (0x%p:0x%x:0x%lx)\n",
			           "READ", ipr->base, ipr->count, ipr->length);
			setup_rma(&rma_state, filerq->context.node,
			          ipr->rma_handle, ipr->base, 1);

			/*
			 * Allocate buffer to hold data read.
			 */
			rma_state.bsz = ipr->iov[i].count;

			if ((fp->f_flags & O_DIRECT) == 0) {
				datap = rma_state.buffer =
				         dvs_alloc_buf(rma_state.bsz);
			} else {
				mmva = NULL;
				ava = rma_state.buffer = dvs_direct_buf_alloc(
				                                rma_state.bsz,
				                                &pglist, &mmva);
				datap = mmva;
			}
			if (!datap) {
				printk(KERN_ERR "DVS: %s: %s: cannot allocate "
				       "memory for parallel read buffer\n",
				       __FUNCTION__,
				       file_request_to_string(filerq->request));
				rval = -ENOMEM;
				goto readp_done;
			}
		}

		KDEBUG_OFS(debug, "%s: read 0x%lx, off:0x%Lx\n", __FUNCTION__,
		           ipr->iov[i].count, ipr->iov[i].offset);

		rval = dvs_read(fd, datap, ipr->iov[i].count,
		                ipr->iov[i].offset, doing_readpages, filerq,
				fp);

		if (ipr->rma_handle) {
			if (rval >= 0) {
				rma_state.valid_size = rval;
			} else {
				rma_state.valid_size = 0;
			}
			rma_state.buffer_remote_start = ipr->iov[i].address;
			if ((ret = end_rma(&rma_state,
				ipr->rma_handle)) < 0) {
				rval = ret;
			}

			if ((fp->f_flags & O_DIRECT) == 0) {
				if (rma_state.buffer)
					dvs_free_buf(rma_state.buffer);
			} else {
				dvs_direct_buf_free(rma_state.bsz, pglist,
				                    mmva, ava);
			}
		}

		if (rval < 0) {
			KDEBUG_FSE(debug, "read returned %ld for file %s (fp: 0x%p)\n",
			           rval, fpname(fp), fp); 
			if (!doing_readpages) {
				total_xfer = rval;
			} else {
				if ((rval == -ESTALE) &&
				    server_should_estale_retry(filerq, rr)) {
					rval = -ESTALE_DVS_RETRY;
				}
				total_xfer = rval;
				/* transfer error to all remaining IOVs */
				for (j = i; j < ipr->count; j++) {
					io_reply->rvals[j] = rval;
				}
			}
			break;
		} else {
			total_xfer += rval;
			if (ipr->rma_handle == NULL)
				datap += rval;
			if (doing_readpages) {
				io_reply->rvals[i] = rval;
				if (rval != 0)
					io_reply->rmas_completed++;
			}
		}
	}

	/* increment DVS read byte counters */
	if (total_xfer > 0)
		dvsproc_stat_update(NULL, DVSPROC_STAT_IO,
		                    filerq->request, total_xfer);

	rval = total_xfer;
	if (ipr->rma_handle == NULL)
		filerp->ipcmsg.reply_length = sizeof(struct file_reply) +
		                    total_xfer;

	if (doing_readpages) {
		io_reply->xfer_count = total_xfer;
		i = send_ipc_request_async_stats(NULL,
		                                 SOURCE_NODE(&filerq->ipcmsg),
		                                 RQ_FILE, priv_freq, frep_size,
		                                 NULL, 0,
		                                 REMOTE_IDENTITY(&filerq->ipcmsg));
		if (i && (i != -EHOSTDOWN)) {
			printk(KERN_ERR "DVS: %s: RQ_READPAGE_RP failed to send"
			       " data to %s: %d\n", __FUNCTION__,
			       SSI_NODE_NAME(SOURCE_NODE(&filerq->ipcmsg)), i);
		}
		free_msg(priv_freq);
	} else {
		/* return current attributes */
		copy_inode_info(file_inode(fp),
		                &filerp->u.readrp.inode_copy);
	}

readp_done:
	if (dvsof_concurrent_reads_count)
		up(&dvsof_concurrent_reads_sema);

	if (fp) {
		fd_uninstall(fd);

		KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
		           file_request_to_string(filerq->request),
		           fp, (int)atomic_long_read(&fp->f_count));
		fput(fp);
	}

	put_unused_fd(fd);
	return rval;
}

int dvs_rq_readpages_rq(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	return dvs_read_common(filerq, filerp_ptr, rr, 1, debug);
}

int dvs_rq_parallel_read(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	return dvs_read_common(filerq, filerp_ptr, rr, 0, debug);
}

/* EXECUTED ON CLIENTS (NOT SERVER) */
int dvs_rq_writepages_rp(struct file_request *filerq, struct file_reply **filerp, struct remote_ref *rr, unsigned long debug)
{
	struct io_pages_reply *io_reply;
	struct file_request *orig_req;
	struct pages_request *pages_req;
	struct inode_info *iip;
	struct inode *ip;
	struct io_parallel_request *ipr;
	int rval;

	KDEBUG_OFC(0, "DVS: %s: called. rq 0x%p rr 0x%p\n", __FUNCTION__, filerq, rr);
	DVS_TRACE("rq_wp_rp", filerq, rr);

	io_reply = &filerq->u.iopagesrp;
	orig_req = io_reply->source_request; /* may no longer be valid */

	/*
	 * If the server returned ESTALE_DVS_RETRY, use __async_op_retry() to
	 * retry the request up to estale_max_retry times before failing the
	 * request.  Note that the call to unlink_filerq() doesn't actually
	 * unlink the request in this case.
	 */
	if (io_reply->xfer_count == -ESTALE_DVS_RETRY || io_reply->xfer_count == -EQUIESCE) {
		rval = unlink_filerq(orig_req, filerq->ipcmsg.source_seqno,
				     SOURCE_NODE(&filerq->ipcmsg),
				     UNLNK_ESTALE_Retry);
		/*
		 * If this special "UNLNK_ESTALE_Retry" call to unlink_filerq()
		 * returns zero, we call __async_op_retry() to retry the
		 * operation.  Otherwise, we continue on and handle the error
		 * using normal techniques.
		 */
		if (rval == 0) {
			__async_op_retry(SOURCE_NODE(&filerq->ipcmsg), 0,
					 orig_req);
			return 0;
		}
	}

	rval = unlink_filerq(orig_req, filerq->ipcmsg.source_seqno,
				SOURCE_NODE(&filerq->ipcmsg), UNLNK_Have_Reply);
	if (rval > 0) {
		pages_req = orig_req->u.iopagesrq.rq;
	} else {
		/*
		 * Forward errors from the file system or an actual zero-length
		 * read (DVS IPC would have ignored it thus no message would
		 * have been sent) -- there has to be somebody waiting.
		 *
		 * If it's EAGAIN -- not sure what to make of that.  We
		 * obviously received a return message so not sure why the
		 * request would have been retried by failover.
		 */
		if (io_reply->xfer_count <= 0) {
			(void) process_iovs(NULL, NULL, io_reply,
					PRIOV_Error_Messenger);
		}

		return rval;
	}

	/* We're good - the request was still valid. */
	orig_req->ipcmsg.state = ST_SEND_COMPL;
	ip = pages_req->ip;
	iip = (struct inode_info *)ip->i_private;

	ipr = &orig_req->u.iopagesrq.ipr;

	KDEBUG_RPS(debug, "DVS: %s: %s: received %ld of %ld for inode 0x%p "
			"request 0x%p iovs %d\n", __FUNCTION__,
			file_request_to_string(filerq->request),
			io_reply->xfer_count, ipr->length,
			ip, pages_req, ipr->count);
	DVS_TRACEL("wbrp_val", filerq, ip, pages_req, io_reply->xfer_count,
			ipr->count);

	/* Add reply lengths to the request page for statistics */
	_accumulate_totals(pages_req, io_reply);

	/*
	 * For each of the iovs that we received, find the matching pages
	 * and process each one.
	 */
	(void) process_iovs(pages_req, ipr, io_reply, PRIOV_Normal);

	/*
	 * OK, we got all of the iovs processed.
	 *
	 * Now, enter the cleanup phase.  We still have the extent mapped
	 * and now that we're done processing our pages, let's see if we're
	 * the last one still here.  If so, wake the original writepages thread
	 * that made this request so it can do cleanup.
	 *
	 * Recall that there can be multiple requests issued on the
	 * pages for different extents and multiple messages per request.
	 */
	if (!atomic_dec_return(&pages_req->msgs_outstanding)) {
		/* Record totals for statistics */
		_record_totals(ip, pages_req, VFS_OP_WRITEPAGES);

		DVS_TRACE("wbrpwake", pages_req, ip);
		RELEASE_MSG_WAITERS(pages_req);

		up(&pages_req->writepages_sema);
	}

	/*
	 * Async retry entries (ours is now gone), file requests and
	 * messages are 1-1 so we can free the original file request here.
	 */
	orig_req->u.iopagesrq.state = RPS_RPSRQ_FREE;
	free_msg(orig_req);  /* original file_request that is */

	return 0;
}

static ssize_t dvs_write(unsigned int fd, char *buf, size_t count, loff_t pos,
			 int doing_writepages, struct file_request *filerq,
			 struct file *fp)
{
	ssize_t rval, total;
	int i;
	unsigned long elapsed_jiffies;
	mm_segment_t oldfs;

	total = 0;
	i = 0;
	do {
		if ((fp->f_flags & O_DIRECT) != 0) {
			oldfs = get_fs();
			set_fs(USER_DS);
		}

		elapsed_jiffies = jiffies;
		rval = p_sys_pwrite64(fd, buf, count, pos);

		if ((fp->f_flags & O_DIRECT) != 0) {
			set_fs(oldfs);
		}

		if (rval < 0) {
			log_fs(doing_writepages ? "writepages" : "write",
			       fpname(fp), jiffies - elapsed_jiffies, filerq);
			return rval;
		}
		log_fs(doing_writepages ? "writepages" : "write", fpname(fp),
		       jiffies - elapsed_jiffies, filerq);
		buf += rval;
		count -= rval;
		pos += rval;
		total += rval;
		if (count == 0)
			return total;

		DVS_LOG("Short write at offset %Lu count %lu retry %d\n",
		        pos, count, i);
		if (dvsof_short_write_timeout > 0)
			msleep(dvsof_short_write_timeout);
		i++;
	} while (dvsof_short_write_max_retry == -1 ||
	         i < dvsof_short_write_max_retry);

	printk("DVS: %s: Returning error after failed short write retry\n",
	       __func__);

	return -ENOSPC;
}

int dvs_write_common(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, int doing_writepages, unsigned long debug)
{
	struct file_request *priv_freq;
	struct file_reply *filerp = NULL;
	struct io_pages_reply *io_reply;
	struct io_parallel_request *ipr;
	struct file *fp;
	struct rma_state rma_state;
	struct page **pglist;
	void *mmva, *ava = NULL;
	char *datap = NULL;
	long rval = 0;
	int frep_size, fd, i, j, ret, total_xfer = 0;

	fp = rr ? rr->fp : NULL;

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: cannot get unused fd\n");
		return fd;
	}

	/* Do some setup and fall through for normal parallel write handling */
	if (doing_writepages) {
		ipr = &filerq->u.iopagesrq.ipr;

		frep_size = sizeof(struct file_request) +
				(ipr->count * sizeof(size_t));
		priv_freq = kmalloc_ssi(frep_size, GFP_KERNEL);
		if (!priv_freq) {
			put_unused_fd(fd);
			return -ENOMEM;
		}

		priv_freq->request = RQ_WRITEPAGES_RP;
		priv_freq->retry = filerq->retry;
		priv_freq->rip = filerq->rip;
		priv_freq->ipcmsg.source_seqno = filerq->ipcmsg.seqno;

		io_reply = &priv_freq->u.iopagesrp;
		io_reply->source_request = filerq->u.iopagesrq.source_request;
		capture_context(&priv_freq->context);

		KDEBUG_RPS(debug, "DVS: %s: %s: server received request for 0x%p from %s"
				" len %ld off 0x%p iov_count %d\n", __FUNCTION__,
				file_request_to_string(filerq->request),
				filerq->u.iopagesrq.rq,
				SSI_NODE_NAME(filerq->context.node),
				ipr->length, ipr->base, ipr->count);
	} else {
		ipr = &filerq->u.ioprq;

		frep_size = 0;
		io_reply = NULL;
		priv_freq = NULL;

		if (ipr->rma_handle == NULL)
			datap = (char *)(ipr->iov + ipr->count);

		*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
				GFP_KERNEL);
		if (!filerp_ptr) {
			put_unused_fd(fd);
			return -ENOMEM;
		}

		(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);
	}

	/* push file handle into current */
	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) "
		       "for %s from %s\n", rr,
		       file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_pw", rr, filerq->context.node, filerq->request,
		           0, 0);
		put_unused_fd(fd);

		// need to cleanup filerp or priv_freq !!??

		return -EINVAL;
	}

	fd_install_get(fd, fp);

	if (dvsof_concurrent_writes_count) {
		if (down_interruptible(&dvsof_concurrent_writes_sema))
			DVS_LOG("%s: down_interruptible() call on "
			        "dvsof_concurrent_writes_sema interrupted\n",
			        __func__);
	}

	DVS_TRACE("RQPWS", ipr->count, 0);
	for (i=0; i < ipr->count; i++) {
		if (ipr->rma_handle) {
			KDEBUG_IPC(0, "%s: remote copy invoked (0x%x)\n",
			           "WRITE", ipr->count);
			setup_rma(&rma_state, filerq->context.node,
			          ipr->rma_handle, ipr->base, 0);

			/*
			 * Allocate buffer to hold all the
			 * data for the write
			 */
			rma_state.bsz = ipr->iov[i].count;

			if ((fp->f_flags & O_DIRECT) == 0) {
				datap = rma_state.buffer =
				                dvs_alloc_buf(rma_state.bsz);
			} else {
				mmva = NULL;
				ava = rma_state.buffer = dvs_direct_buf_alloc(
				                                  rma_state.bsz,
				                                  &pglist,
				                                  &mmva);
				datap = mmva;
			}

			rma_state.flush = 1;

			if (!datap) {
				printk(KERN_ERR "DVS: RQ_PARALLEL_WRITE: cannot"
				       " allocate memory for parallel write "
				       "buffer\n");
				rval = -ENOMEM;
				goto writep_done;
			}

			/* buffer the data to write from 
			 * the client node. */
			rval = ipc_rma_get(filerq->context.node,
					rma_state.buffer, ipr->iov[i].address,
					ipr->iov[i].count, &rma_state);
			if (rval != ipr->iov[i].count)
				goto writep_failed;

			/* track completed rmas for client error handling */
			if (doing_writepages)
				io_reply->rmas_completed++;
		}

		KDEBUG_RPS(debug, "DVS: %s: doing write: i %d count %lu offset %lld\n",
				__FUNCTION__, i, ipr->iov[i].count,
				ipr->iov[i].offset);

		rval = dvs_write(fd, datap, ipr->iov[i].count,
				ipr->iov[i].offset, doing_writepages, filerq,
				fp);

writep_failed:
		if (ipr->rma_handle) {
			if ((ret = end_rma(&rma_state, ipr->rma_handle)) < 0) {
				rval = ret;
			}

			if ((fp->f_flags & O_DIRECT) == 0) {
				if (rma_state.buffer)
					dvs_free_buf(rma_state.buffer);
			} else {
				dvs_direct_buf_free(rma_state.bsz, pglist, mmva,
						ava);
			}
		}

		if (rval < 0) {
			KDEBUG_FSE(debug, "write returned %ld for file "
			           "%s (fp: 0x%p)\n", rval,
			           fpname(fp), fp); 
			if (!doing_writepages) {
				total_xfer = rval;
			} else {
				if ((rval == -ESTALE) &&
				    server_should_estale_retry(filerq, rr)) {
					rval = -ESTALE_DVS_RETRY;
				}
				total_xfer = rval;
				/* error all remaining IOVs */
				for (j = i; j < ipr->count; j++) {
					io_reply->rvals[j] = rval;
				}
			}
			break;
		} else {
			sync_server_data_written(rr);
			total_xfer += rval;

			if (ipr->rma_handle == NULL)
				datap += rval;

			if (doing_writepages) {
				io_reply->rvals[i] = rval;
			}
		}

	}

	if (rval >= 0 && ipr->datasync) {
		ret = uwrite_usersync(fd, fp, filerq);
		if (ret < 0) {
			rval = ret;
			total_xfer = rval;
		}
	}

	/* increment DVS write byte counters */
	if (total_xfer > 0)
		dvsproc_stat_update(NULL, DVSPROC_STAT_IO, filerq->request,
		                    total_xfer);

	rval = total_xfer;

	if (doing_writepages) {
		io_reply->xfer_count = total_xfer;

		i = send_ipc_request_async_stats(NULL,
				SOURCE_NODE(&filerq->ipcmsg), RQ_FILE,
				priv_freq, frep_size, NULL, 0,
				REMOTE_IDENTITY(&filerq->ipcmsg));
		if (i && (i != -EHOSTDOWN)) {
			printk(KERN_ERR "DVS: %s: RQ_WRITEPAGES_RP failed to "
				"send reply to %s: %d\n", __FUNCTION__,
				SSI_NODE_NAME(SOURCE_NODE(&filerq->ipcmsg)), i);
		}

		free_msg(priv_freq);
	} else {
		/* return current attributes */
		copy_inode_info(file_inode(fp),
				&filerp->u.writerp.inode_copy);
	}

writep_done:
	if (dvsof_concurrent_writes_count)
		up(&dvsof_concurrent_writes_sema);

	fd_uninstall(fd);
	put_unused_fd(fd);

	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_writepages_rq(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	return dvs_write_common(filerq, filerp_ptr, rr, 1, debug);
}

int dvs_rq_parallel_write(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	return dvs_write_common(filerq, filerp_ptr, rr, 0, debug);
}

int dvs_rq_fsync(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file *fp;
	long rval = 0;
	int fd;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	/* push file handle into current */
	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) "
		       "for %s from %s\n", rr,
		       file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_fs", rr, filerq->context.node, filerq->request,
		           0, 0);
		return -EINVAL;
	}

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: cannot get unused fd\n");
		return fd;
	}

	fd_install_get(fd, fp);

	elapsed_jiffies = jiffies;
	if (filerq->u.fsyncrq.kind) {
		rval = p_sys_fdatasync(fd);
		log_fs("fdatasync", fpname(fp), jiffies - elapsed_jiffies,
		       filerq);
	} else {
		rval = p_sys_fsync(fd);
		log_fs("fsync", fpname(fp), jiffies - elapsed_jiffies,
		       filerq);
	}

	if (rval < 0) {
		KDEBUG_FSE(debug, "%s returned %ld for file "
		           "%s (fp: 0x%p)\n", filerq->u.fsyncrq.kind ?
		           "fdatasync" : "fsync", rval, fpname(fp), fp);
	}

	fd_uninstall(fd);
	put_unused_fd(fd);

	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_flush(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct files_struct *hold_files;
	struct file *fp;
	long rval = 0;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) "
		       "for %s from %s\n", rr,
		       file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_flsh", rr, filerq->context.node,
		           filerq->request, 0, 0);
		return -EINVAL;
	}

	/*
	 * Set our files pointer, if possible.  This might not be
	 * necessary, since all Posix lock operations are taken care
	 * of by RQ_LOCK, but for now we'll do it out of paranoia.
	 */
	(void) dvs_switch_files(&hold_files, rr, filerq->context.tgid, 0, 0, debug);

	/*
	 * This is a client close, but not the last close.
	 * Take a file reference just so we can call filp_close.
	 */
	get_file(fp);
	elapsed_jiffies = jiffies;
	rval = filp_close(fp, current->files);
	/*
	 * Log this as "flush" rather than "close" to match up with the
	 * RQ_FLUSH request logged by the clients.
	 */
	log_fs("flush", fpname(fp), jiffies - elapsed_jiffies, filerq);
	if (rval < 0) {
		KDEBUG_FSE(debug, "flush returned %ld for file %s (fp: 0x%p)\n", rval,
		           fpname(fp), fp); 
	}

	dvs_restore_files(hold_files);

	return rval;
}

int dvs_rq_fasync(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file *fp;
	long rval = 0;
	int fd;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                               GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	/* push file handle into current */
	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) "
		       "for %s from %s\n", rr,
		       file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_fas", rr, filerq->context.node, filerq->request,
		           0, 0);
		return -EINVAL;
	}

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: cannot get unused fd\n");
		return fd;
	}

	fd_install_get(fd, fp);

	if (fp->f_op && fp->f_op->fasync) {
		elapsed_jiffies = jiffies;
		rval = fp->f_op->fasync(fd, fp, filerq->u.fasyncrq.arg);
		log_fs("fasync", fpname(fp), jiffies - elapsed_jiffies, filerq);
		if (rval < 0) {
			KDEBUG_FSE(debug, "fasync returned %ld for file %s (fp: 0x%p)\n",
			           rval, fpname(fp), fp);
		}
	}

	fd_uninstall(fd);
	put_unused_fd(fd);

	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_link(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	long rval = 0;
	char *path, *oldpath;
	int flags;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, &oldpath);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	elapsed_jiffies = jiffies;
	rval = p_sys_link(oldpath, path);
	log_fs("link", path, jiffies - elapsed_jiffies, filerq);
	if (rval >= 0) {
		/* 
		 * Workaround for Bz755542 - link, unlink, link returns
		 * stale inode attributes.  Revalidate cache on lookup
		 * for NFS file systems; also revalidate if fs type is
		 * not set - just to be safe.
		 */
		flags = 0;
		if (filerq->u.linkrq.magic == NFS_SUPER_MAGIC ||
			filerq->u.linkrq.magic == 0) {
			flags = LOOKUP_REVAL;
		}
		get_inode_info(path, flags, &filerp->u.linkrp.inode_copy, filerq, debug);

		KDEBUG_OFS(debug, "DVS: RQ_LINK: path %s, reply i_ino %lu, i_nlink "
		           "%u, i_ctime %lu/%lu\n", path,
		           filerp->u.linkrp.inode_copy.i_ino,
		           (unsigned int) filerp->u.linkrp.inode_copy.i_nlink,
		           filerp->u.linkrp.inode_copy.i_ctime.tv_sec,
		           filerp->u.linkrp.inode_copy.i_ctime.tv_nsec);
	} else {
		KDEBUG_FSE(debug, "link returned %ld for path %s\n", rval, path);
	}

	return rval;
}

int dvs_rq_symlink(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	elapsed_jiffies = jiffies;
	rval = p_sys_symlink(path,
	                     &filerq->u.linkrq.pathname[filerq->u.linkrq.orsz]);
	log_fs("symlink", path, jiffies - elapsed_jiffies, filerq);
	if (rval >= 0) {
		get_inode_info(&filerq->u.linkrq.pathname[filerq->u.linkrq.orsz],
		               0, &filerp->u.linkrp.inode_copy, filerq, debug);
	} else {
		KDEBUG_FSE(debug, "symlink returned %ld for path %s\n", rval,
		           &filerq->u.linkrq.pathname[filerq->u.linkrq.orsz]);
	}

	return rval;
}

int dvs_rq_mknod(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	elapsed_jiffies = jiffies;
	rval = p_sys_mknod(path, filerq->u.mknodrq.mode,
	                   new_encode_dev((dev_t)filerq->u.mknodrq.dev));
	log_fs("mknod", path, jiffies - elapsed_jiffies, filerq);
	if (rval >= 0) {
		get_inode_info(path, 0, &filerp->u.mknodrp.inode_copy, filerq, debug);
	} else {
		KDEBUG_FSE(debug, "mknod returned %ld for path %s, mode "
		           "0x%x\n", rval, path, filerq->u.mknodrq.mode);
	}

	return rval;
}

int dvs_rq_rename(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct path spath;
	long rval = 0;
	char *path, *oldpath;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, &oldpath);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	elapsed_jiffies = jiffies;
	rval = p_sys_rename(oldpath, path);
	log_fs("rename", path, jiffies - elapsed_jiffies, filerq);
	if (filerq->rip && rval == -ENOENT) {
		KDEBUG_OFS(debug, "DVS: RQ_RENAME: clear ENOENT, path %s\n",
		           filerq->u.linkrq.pathname);
		rval = 0;
	}
	if (rval >= 0) {
		get_inode_info(path, 0, &filerp->u.linkrp.inode_copy, filerq, debug);

		if (!dvs_path_lookup(oldpath, 0, &spath, __func__, filerq, debug)) {
			d_drop(spath.dentry);
			path_put(&spath);
		}
	} else {
		KDEBUG_FSE(debug, "rename returned %ld for path %s\n", rval, path);
	}

	return rval;
}

static int dvs_do_ioctl(unsigned int fd, struct file *fp,
			struct file_request *filerq, unsigned int type,
			int by_ref, unsigned long val, void *ref, int size)
{
	void *vmem;
	int rval;
	unsigned long elapsed_jiffies;

	if (by_ref) {
		/* vmalloc()/vmalloc_ssi() guarantees guard pages surrounding
		 * the allocation, preventing buffer overflow exploits.
		 * Note that if a buffer overflow is attempted, a kernel
		 * OOPS will result. */
		vmem = vmalloc_ssi(size);
		if (!vmem)
			return -ENOMEM;
		memcpy(vmem, ref, size);
		elapsed_jiffies = jiffies;
		rval = p_sys_ioctl(fd, type, (unsigned long)vmem);
		log_fs("ioctl", fpname(fp), jiffies - elapsed_jiffies, filerq);
		memcpy(ref, vmem, size);
		vfree_ssi(vmem);
		return rval;
	} else {
		/* Careful, this could easily be a security vulnerability.
		 * If the ioctl _type_ actually takes a pointer instead
		 * of a value, we have a user-controlled pointer that the
		 * kernel will use for read/write. We have no good way
		 * to validate what ioctls actually take arguments by-value.
		 * This is the best I can figure out.
		 * Fortunately, the vast majority of ioctls are by reference...*/
		switch (type) {
		case BLKRRPART:
		case BLKFLSBUF:
		case BLKRASET:
		case FIFREEZE:
		case FITHAW:
		case FIOCLEX:
		case FIONCLEX:
			elapsed_jiffies = jiffies;
			rval = p_sys_ioctl(fd, type, val);
			log_fs("ioctl", fpname(fp), jiffies - elapsed_jiffies,
			       filerq);
			/*There is no copy back possible for a by-value arg */
			break;
		default:
			KDEBUG_OFS(0, "DVS: Unknown by-value ioctl %d\n", type);
			rval = -ENOTTY;
		}

		return rval;
	}
}

int dvs_rq_ioctl(struct file_request *filerq, struct file_reply **filerp_ptr,
		 struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp;
	struct dvs_ioctl_tunnel *itun;
	char *path;
	long rval = 0;
	int fd;

	dvs_get_path(filerq, &path, NULL);

	if (filerq->u.ioctlrq.arg_rw) {
		if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply) +
					       filerq->u.ioctlrq.arg_size,
					       GFP_KERNEL)) == NULL) {
			return -ENOMEM;
		}
		(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply)
		    + filerq->u.ioctlrq.arg_size;

	} else {
		if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
					       GFP_KERNEL)) == NULL) {
			return -ENOMEM;
		}
		(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);
	}

	filerp = *filerp_ptr;

	fp = rr ? rr->fp : NULL;

	/* push file handle into current */
	if (fp == NULL) {
		DVS_TRACE("fp==NULL", filerq->context.node, filerq->request);
		return -EINVAL;
	}

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: cannot get unused fd\n");
		return fd;
	}

	fd_install_get(fd, fp);

	switch (filerq->u.ioctlrq.cmd) {
	case DVS_TUNNEL_IOCTL:
	case DVS_BCAST_IOCTL:
		itun = (struct dvs_ioctl_tunnel *)filerq->u.ioctlrq.data;
		rval = dvs_do_ioctl(fd, fp, filerq, itun->ioctl_cmd,
				    itun->arg_by_ref, *(itun->arg), itun->arg,
				    itun->arg_size);
		break;
	default:
		rval = dvs_do_ioctl(fd, fp, filerq, filerq->u.ioctlrq.cmd,
				    filerq->u.ioctlrq.arg_is_ref,
				    filerq->u.ioctlrq.arg,
				    filerq->u.ioctlrq.data,
				    filerq->u.ioctlrq.arg_size);
	}

	if (rval < 0) {
		KDEBUG_FSE(debug, "ioctl(%d) returned %ld for file %s (fp: 0x%p)\n",
			   filerq->u.ioctlrq.cmd, rval, fpname(fp), fp);
	}

	if (filerq->u.ioctlrq.arg_rw) {
		memcpy(filerp->u.ioctlrp.data, (void *)filerq->u.ioctlrq.data,
		       filerq->u.ioctlrq.arg_size);
	}

	fd_uninstall(fd);
	put_unused_fd(fd);

	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
		   file_request_to_string(filerq->request),
		   fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_geteoi(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp;
	struct kstat stat;
	long rval = 0;
	unsigned long elapsed_jiffies;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	char *path = NULL;
	char *path_buffer = NULL;
	int path_size = 512;
	int path_err = 0;
#endif

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	if (fp == NULL) {
		DVS_TRACE("fp==NULL", filerq->context.node, filerq->request);
		return -EINVAL;
	}
	get_file(fp);

	rval = 0;
	if (fp->f_path.dentry && fp->f_path.dentry->d_op &&
	                    fp->f_path.dentry->d_op->d_revalidate) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		struct nameidata nd;
		elapsed_jiffies = jiffies;
		rval = vfs_path_lookup(fp->f_path.dentry->d_parent, fp->f_path.mnt,
		                       fp->f_path.dentry->d_name.name, 0, &nd);
		log_fs("lookup[dvs_rq_geteoi]", fpname(fp),
		       jiffies - elapsed_jiffies, filerq);
		if (rval) {
			path_buffer = vmalloc_ssi(path_size);
			if (path_buffer) {
				path = d_path(&fp->f_path, path_buffer,	path_size);
				if (IS_ERR(path)) {
					path_err = * ((int *) path);
					snprintf(path_buffer, path_size, "d_path "
						"returned error %d", path_err);
					path = path_buffer;
				}
			}
			printk(KERN_ERR "DVS: geteoi cannot revalidate: "
				"no nameidata for %s %ld\n", path, rval);
			if (path_buffer) {
				vfree_ssi(path_buffer);
			}
			goto geteoi_done;
		}

		elapsed_jiffies = jiffies;
		rval = fp->f_path.dentry->d_op->d_revalidate(fp->f_path.dentry, &nd);
		log_fs("revalidate[dvs_rq_geteoi]", fpname(fp),
		       jiffies - elapsed_jiffies, filerq);
		path_put(&nd.path);
#else
		/* no nameidata from vfs_path_lookup in SLES12. Safe to pass NULL again? */
		elapsed_jiffies = jiffies;
		rval = fp->f_path.dentry->d_op->d_revalidate(fp->f_path.dentry, 0);
		log_fs("revalidate[dvs_rq_geteoi]", fpname(fp),
		       jiffies - elapsed_jiffies, filerq);
#endif
		if (rval < 0) {
			KDEBUG_FSE(debug, "geteoi revalidate returned %ld for file %s "
			           "(fp: 0x%p)\n", rval, fpname(fp), fp); 
			printk(KERN_ERR "DVS: RQ_GETEOI: lseek failed %ld\n",
			       rval);
			goto geteoi_done;
		}
	} else {
		KDEBUG_OFS(debug, "DVS: RQ_GETEOI: skipped calling d_revalidate\n");
	}

	if (fp->f_path.dentry && file_inode(fp)) {
		if (file_inode(fp)->i_op &&
		                  file_inode(fp)->i_op->getattr) {
			elapsed_jiffies = jiffies;
			rval = file_inode(fp)->i_op->getattr(fp->f_path.mnt,
			                                            fp->f_path.dentry,
			                                            &stat);
			/*
			 * Log this as "geteoi" rather than "getattr" to match
			 * up with the RQ_GETEOI request logged by the clients.
			 */
			log_fs("geteoi", fpname(fp), jiffies - elapsed_jiffies,
			       filerq);
			if (rval < 0) {
				KDEBUG_FSE(debug, "geteoi getattr returned %ld for "
				           "file %s (fp: 0x%p)\n", rval,
				           fpname(fp), fp); 
			} else {
				filerp->u.lseekrp.offset = stat.size;
			}
		} else {
			filerp->u.lseekrp.offset = file_inode(fp)->i_size;
			rval = 0;
		}
		KDEBUG_OFS(debug, "DVS: RQ_GETEOI: returning offset %lld\n",
		           filerp->u.lseekrp.offset);
	} else {
		printk(KERN_ERR "DVS: RQ_GETEOI: lseek failed: no inode\n");
		rval = -USIERR_FILE_NOTFOUND;
	}
geteoi_done:
	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_lock(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp;
	struct pid *hold_task_tgid;
	struct files_struct *hold_files;
	long rval = 0;
	int fd;
	pid_t hold_tgid;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	hold_tgid = current->tgid;
	hold_task_tgid = NULL;
	hold_files = NULL;

	KDEBUG_OFS(debug, "%s: RQ_LOCK: 0x%p:%d:%d:%s\n", __FUNCTION__, fp,
	           filerq->u.lockrq.cmd, 0,
	           SSI_NODE_NAME(filerq->context.node));

	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) for %s from %s\n",
		       rr, file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_lck", rr, filerq->context.node, filerq->request,
		           0, 0);
		return -EINVAL;
	}

	/* update f_pos in case l_whence == SEEK_CUR */
	fp->f_pos = filerq->u.lockrq.f_pos;

	/* push file handle into current */
	if ((filerq->u.lockrq.cmd == F_GETLK || filerq->u.lockrq.cmd == F_SETLK
	                                || filerq->u.lockrq.cmd == F_SETLKW) ) {
		if ((rval = dvs_switch_files(&hold_files, rr,
		               filerq->context.tgid, 1,
		               (filerq->u.lockrq.lock.l_type == F_RDLCK
		                || filerq->u.lockrq.lock.l_type == F_WRLCK),
				debug))) {
			printk(KERN_ERR "DVS: RQ_LOCK: dvs_switch_files "
			       "failed: %ld, fp 0x%p\n", rval, fp);
			return rval;
		}

		fd = dvs_get_unused_fd(0);
		if (fd < 0) {
			KDEBUG_OFS(debug, "DVS: RQ_LOCK: can't get fd\n");
			printk(KERN_ERR "DVS: RQ_LOCK: can't get fd\n");
			dvs_restore_files(hold_files);
			return -EBADF;
		}
		fd_install_get(fd, fp);
		current->tgid = filerq->context.tgid;
		KDEBUG_OFS(debug, "DVS: RQ_LOCK: files:0x%p tgid:0x%x\n", current->files,
		           current->tgid);

		/*
		 * Temporarily NULL the current process' group_leader
		 * pid pointer to ensure the kernel does not use
		 * fl_nspid to assign a different fl_pid to the
		 * file_lock.
		 */
		if (!filerq->flags.is_nfs && thread_group_leader(current) && task_tgid(current)) {
			hold_task_tgid = task_tgid(current);
			current->group_leader->pids[PIDTYPE_PID].pid = NULL;
		}

		/*
		 * F_SETLKW can wait for an indeterminate amount of
		 * time - inform the DVS IPC layer.
		 */
		if (filerq->u.lockrq.cmd == F_SETLKW)
			ipc_block_thread();
	} else {
		fd = dvs_get_unused_fd(0);
		if (fd < 0) {
			printk(KERN_ERR "DVS: cannot get unused fd\n");
			return fd;
		}

		/* cmd == F_CANCELLK? */
		fd_install_get(fd, fp);
	}

	elapsed_jiffies = jiffies;
	rval = p_sys_fcntl(fd, filerq->u.lockrq.cmd,
	                   (unsigned long)&filerq->u.lockrq.lock);
	log_fs("fcntl", fpname(fp), jiffies - elapsed_jiffies, filerq);

	if (rval < 0) {
		KDEBUG_FSE(debug, "fcntl(%d) returned %ld for file %s (fp: 0x%p)\n",
		           filerq->u.lockrq.cmd, rval, fpname(fp), fp); 
		DVS_TRACEL("!RQ_LOCK", current->pid, fp, (uint64_t)rval, 0, 0);
	}

	/* tell the DVS IPC layer the thread is no longer blocking */
	if (filerq->u.lockrq.cmd == F_SETLKW)
		ipc_release_thread();

	filerp->u.lockrp.rlock = filerq->u.lockrq.lock;

	if (hold_task_tgid) {
		current->group_leader->pids[PIDTYPE_PID].pid = hold_task_tgid;
	}

	fd_uninstall(fd);
	put_unused_fd(fd);
	if (hold_files != NULL) {
		dvs_restore_files(hold_files);
		current->tgid = hold_tgid;
	}

	KDEBUG_OFS(debug, "DVS: %s OUT:  fp 0x%p, count %d\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count));
	fput(fp);

	return rval;
}

int dvs_rq_close(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file *fp;
	struct files_struct *hold_files;
	long rval = 0;
	int fd;
	unsigned long start_jiffies;
	struct dvs_posix_lock *dpl;
	struct dentry *dep;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	fp = rr ? rr->fp : NULL;

	if (fp == NULL) {
		printk(KERN_ERR "DVS: handle not found (0x%p) for %s from %s\n",
		       rr, file_request_to_string(filerq->request),
		       SSI_NODE_NAME(filerq->context.node));
		DVS_TRACEL("!rq_close", rr, filerq->context.node, filerq->request, 0, 0);
		return -EINVAL;
	}

	/* do ro_cache cleanup */
	if (filerq->u.closerq.ro_cache_check == RO_CACHE_READONLY) {
		if (usi_node_addr == filerq->u.closerq.ro_cache_node) {
			if ((rval = ro_cache_remove_fp(fp,
			           SOURCE_NODE(&filerq->ipcmsg),
			           filerq->u.closerq.ro_cache_client_fp)) < 0) {
				printk(KERN_ERR "DVS: RQ_CLOSE: ro_cache_remove_fp"
				       " failure %ld\n", rval);
			}
		}
	} else if (filerq->u.closerq.ro_cache_check == RO_CACHE_WRITABLE) {
		if (usi_node_addr == filerq->u.closerq.ro_cache_node) {
			if ((rval = ro_cache_downwrite(fp)) < 0) {
				printk(KERN_ERR "DVS: RQ_CLOSE: ro_cache_downwrite"
				       " failure %ld fp 0x%p\n", rval, fp);
			}
		}
	}

	/*
	 * To avoid racing with file_node_down() and calling
	 * rr_ref_put() twice, we remove the remote_ref from the list
	 * of remote_refs. file_node_down() corrupts the rr->key value
	 * on remote_refs it's going to free, so we check it against the
	 * remote_file key again here. If they differ, then
	 * file_node_down() is taking care of the close/free, so we can
	 * leave.
	 */
	spin_lock(&rr_sl);
	spin_lock(&node_map[filerq->ipcmsg.source_node].rr_lock);
	if (rr->key != ((struct remote_handle *)&filerq->file_handle)->key) {
		spin_unlock(&node_map[filerq->ipcmsg.source_node].rr_lock);
		spin_unlock(&rr_sl);
		return rval;
	}
	list_del(&rr->rr_lh);
	spin_unlock(&node_map[filerq->ipcmsg.source_node].rr_lock);
	spin_unlock(&rr_sl);

	/*
	 * Push the files struct into current if available, else create
	 * it. Note the process closing the file from the client node
	 * might not be the same one that did the RQ_OPEN.
	 */
	if ((rval = dvs_switch_files(&hold_files, rr,
	                             filerq->context.tgid, 1, 0, debug))) {
		printk(KERN_ERR "DVS: RQ_CLOSE: dvs_switch_files "
		       "failed: %ld, fp 0x%p\n", rval, fp);
		remove_remote_ref(rr, debug);
		return rval;
	}

	KDEBUG_OFS(debug, "RQ_CLOSE (0x%p, %d)\n", fp,
	           (int)atomic_long_read(&fp->f_count));

	/* push file handle into current */
	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		printk(KERN_ERR "DVS: RQ_CLOSE: cannot "
		       "get unused fd %d\n", fd);
		rval = fd;
		dvs_restore_files(hold_files);

		remove_remote_ref(rr, debug);
		return rval;
	}
	fd_install_get(fd, fp);

	if (!filerq->u.closerq.sync && rr && rr->inode_ref && 
	                            rr->inode_ref->last_sync <=
	                            rr->inode_ref->last_write) {
		SYNC_LOG("Sync: inode %lu: sync on close\n",
		         rr->inode_ref->ino);
		start_jiffies = jiffies;
		if (!fsync_inode_ref(rr->inode_ref, rr)) {
			atomic64_add(jiffies - start_jiffies, &closing_time);
			atomic64_inc(&closing_syncs);
		}
	}

	if (filerq->u.closerq.sync) {
		/*
		 * Sync the data to backing store to ensure a DVS
		 * server crash after a successful close() can't
		 * result in data loss.
		 */
		elapsed_jiffies = jiffies;
		rval = p_sys_fsync(fd);
		log_fs("fsync", fpname(fp), jiffies - elapsed_jiffies, filerq);
		if (rval < 0) {
			KDEBUG_FSE(debug, "close fsync returned %ld "
			           "for file %s (fp: 0x%p)\n", rval,
			           fpname(fp), fp); 
			if ((rval != -EINVAL) && (rval != -EINTR)) {
				printk(KERN_ERR "DVS: RQ_CLOSE: fsync failed: "
				       "%ld\n", rval);
			}
		}
	}

	/* Remove any POSIX locks still active on the file. */
	spin_lock(&rr->posix_lock_sl);
	list_for_each_entry(dpl, &rr->posix_lock_lh, lh) {
		locks_remove_posix(rr->fp, &dpl->files);
		DVS_TRACEL("closepl", rr, rr->fp, dpl, &dpl->files, current);
	}
	spin_unlock(&rr->posix_lock_sl);

	/* remove our inode_ref before closing the file */
	sync_remove_inode_ref(rr);

	/* If the original open was an open_exec() we need to undo the
	 * deny_write_access() call it made. */
	if (rr->flags & DVS_RR_OPEN_EXEC)
		allow_write_access(fp);

	/* sys_close cleans up fd from current->files */
	elapsed_jiffies = jiffies;
	rval = p_sys_close(fd);
	log_fs("close", fpname(fp), jiffies - elapsed_jiffies, filerq);
	if (rval < 0) {
		KDEBUG_FSE(debug, "close returned %ld for file "
		           "%s (fp: 0x%p)\n", rval,
		           fpname(fp), fp); 
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
/* SLES11 */
#define dvs_d_count(d) (d->d_lockref.count)
#else
/* SLES12 || Centos 7.1 */
#define dvs_d_count(d) d_count(d)
#endif
	dep = fp->f_path.dentry;
	KDEBUG_OFS(debug, "DVS: %s OUT0: fp 0x%p f_count %d dentry 0x%p d_flags 0x%x d_count %u\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count),
		   dep,
		   dep->d_flags,
		   dvs_d_count(dep) );

	dvs_restore_files(hold_files);

	/* fd already cleaned up by close */
	remove_remote_ref(rr, debug);

	KDEBUG_OFS(debug, "DVS: %s OUT1: fp 0x%p f_count %d dentry 0x%p d_count %u\n",
	           file_request_to_string(filerq->request),
	           fp, (int)atomic_long_read(&fp->f_count),
		   dep,
		   dvs_d_count(dep) );

	fput(fp);

	/*
	 * See https://github.com/torvalds/linux/commit/4a9d4b024a3102fc083c925c242d98ac27b1c5f6 
	 * fput() for kernel threads is deferred to a work queue so that
	 * it can be called from interrupt context. This has the side effect
	 * of making fput async for kernel threads. It is important for
	 * dvs to maintain proper close semantics so make sure all delayed
	 * fput's are completed before returning from dvs_rq_close
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	flush_delayed_fput();
#endif

	return rval;
}

int dvs_rq_statfs(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	long rval = 0;
	char *path;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	elapsed_jiffies = jiffies;
	rval = p_sys_statfs(path, &filerp->u.statfsrp.sbuf);
	log_fs("statfs", path, jiffies - elapsed_jiffies, filerq);
	if (rval < 0) {
		KDEBUG_FSE(debug, "statfs returned %ld for path %s\n", rval, path);
	}

	return rval;
}

/* EXECUTED ON CLIENTS (NOT SERVER) */
int dvs_rq_ro_cache_disable(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	long rval = 0;
	struct file *cfp;
	struct dvsproc_stat *stats;
	
	if ((*filerp_ptr = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	cfp = filerq->u.rocachedisablerq.fp;
	if (cfp)
		stats = FILE_ICSB(cfp)->stats;

	if (cfp && (cfp->f_op == &upfsfops)) {
		if (cfp->private_data == NULL) {
			printk(KERN_ERR "DVS: RQ_RO_CACHE_DISABLE: fp "
			       " 0x%p private_data NULL!\n", cfp);
			return -EINVAL;
		}
		down(&FILE_PRIVATE(cfp)->rocache_sema);
		FILE_PRIVATE(cfp)->cache = 0;
		truncate_inode_pages(&(file_inode(cfp))->i_data, 0);
		up(&FILE_PRIVATE(cfp)->rocache_sema);
		rval = 0;
	} else {
		printk(KERN_ERR "DVS: RQ_RO_CACHE_DISABLE: file 0x%p for cache"
		       " clear does not exist\n", cfp);
		rval = -EINVAL;
	}
	
	return rval;
}

int dvs_rq_permission(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct file *fp;
	struct path spath;
	struct inode *ip;
	long rval = 0;
	char *path;
	int trips = 1;
	unsigned long elapsed_jiffies;

	dvs_get_path(filerq, &path, NULL);

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

lookup_path:
	rval = dvs_path_lookup(path, 0, &spath, __func__, filerq, debug);
	if (rval)
		return rval;

	/*
	 * Check that it's not an autofs placeholder directory (using a
	 * different inode number than the actual entity for this path)
	 * If so, open it so that it comes back online and re-look it up.
	 * Clients otherwise can get confused in parallel lookups and return
	 * ENOENT.
	 */
	if (!spath.dentry->d_inode->i_size &&
	             S_ISDIR(spath.dentry->d_inode->i_mode) &&
	             spath.dentry->d_sb->s_magic == AUTOFS_SUPER_MAGIC &&
	             trips--) {
		elapsed_jiffies = jiffies;
		fp = filp_open(path, O_DIRECTORY | O_RDONLY, 0);
		log_fs("open[dvs_rq_permission]", path, jiffies - elapsed_jiffies, filerq);
		if (IS_ERR(fp)) {
			rval = PTR_ERR(fp);
			KDEBUG_FSE(debug, "filp_open returned %ld for "
			           "path %s, flags 0x%x\n", rval,
			           path, O_DIRECTORY | O_RDONLY);
			path_put(&spath);
			return rval;
		}
		elapsed_jiffies = jiffies;
		filp_close(fp, NULL);
		log_fs("close[dvs_rq_permission]", path, jiffies - elapsed_jiffies, filerq);
		path_put(&spath);
		goto lookup_path;
	}
	ip = spath.dentry->d_inode;

	/* If this isn't a true clusterfs, don't verify the inode number.
	   This is usually used only in tmpfs testing */
	if (!filerq->flags.ignore_ino_check && ip->i_ino != filerq->u.permissionrq.ino) {
		printk("DVS: RQ_PERMISSION: %ld != %ld\n",
		       spath.dentry->d_inode->i_ino,
		       filerq->u.permissionrq.ino);
		path_put(&spath);
		return -EBADF;
	}

	elapsed_jiffies = jiffies;
	rval = inode_permission(ip, filerq->u.permissionrq.mask);
	log_fs("permission", path, jiffies - elapsed_jiffies, filerq);
	KDEBUG_OFS(debug, "DVS: %s: RQ_PERMISSION: inode_permission returned "
	           "%ld, path %s\n", __FUNCTION__, rval, path);

	copy_inode_info(ip, &filerp->u.permissionrp.inode_copy);

	path_put(&spath);

	return rval;
}


int dvs_rq_sync_update(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;

	if ((*filerp_ptr = filerp = vmalloc_ssi(sizeof(struct file_reply) +
	                                   (filerq->u.syncupdaterq.size *
	                                    sizeof(unsigned long)))) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply) +
	                                     (filerq->u.syncupdaterq.size *
	                                      sizeof(unsigned long));

	sync_server_bulk_update(filerq->u.syncupdaterq.inodes,
	                        filerp->u.syncupdaterp.sync_times,
	                        filerq->u.syncupdaterq.size);
	SYNC_LOG("Sync: Finished bulk update request from %s\n",
	         node_map[filerq->ipcmsg.source_node].name);

	return 0;
}

int dvs_rq_verifyfs(struct file_request *filerq, struct file_reply **filerp_ptr, struct remote_ref *rr, unsigned long debug)
{
	struct file_reply *filerp;
	struct path spath;
	char *mp = filerq->u.verifyfsrq.pathname;
	long rval = 0;
	unsigned long elapsed_jiffies;

	if ((*filerp_ptr = filerp = kmalloc_ssi(sizeof(struct file_reply),
	                                        GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	(*filerp_ptr)->ipcmsg.reply_length = sizeof(struct file_reply);

	KDEBUG_PNS(debug, "DVS: RQ_VERIFYFS: mountpoint %s\n", mp);

	/*
	 * Given the request from mount on the client, just verify
	 * that the path to the directory exists on the server.
	 */
	elapsed_jiffies = jiffies;
	rval = kern_path(mp, LOOKUP_FOLLOW, &spath);
	if (!rval) {
		struct kstat kstatbuf;

		/*
		 * Ask the filesystem to get the mode bits, user and group info for
		 * the root_inode of the mounted directory.  This may be different
		 * than the informaion we'd find in the inode we get back from
		 * kern_path().
		 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		rval = vfs_getattr(spath.mnt, spath.dentry,
	                   &kstatbuf);
#else
		rval = vfs_getattr(&spath,
	                   &kstatbuf);
#endif
		log_fs("verifyfs", mp, jiffies - elapsed_jiffies, filerq);
		if (!S_ISDIR(spath.dentry->d_inode->i_mode)) {
			rval = -ENOTDIR;
		} else {
			/*
			 * Copy mode bits, user and group into the d_inode.
			 */
			spath.dentry->d_inode->i_mode = kstatbuf.mode;
			spath.dentry->d_inode->i_uid = kstatbuf.uid;
			spath.dentry->d_inode->i_gid = kstatbuf.gid;

			copy_inode_info(spath.dentry->d_inode,
			                &filerp->u.verifyfsrp.inode_copy);

			filerp->u.verifyfsrp.magic = spath.dentry->d_sb->s_magic;

			/* Check that HZ is equal on both the client and server.
			 * If it's not, we have to disable periodic sync for
			 * this server. */
			if (filerq->u.verifyfsrq.hz != HZ)
				filerp->u.verifyfsrp.sync = SYNC_SERVER_NOSYNC;
		}
		path_put(&spath);
	} else {
		log_fs("verifyfs", mp, jiffies - elapsed_jiffies, filerq);
	}

	KDEBUG_PNS(debug, "DVS: RQ_VERIFYFS: rval %ld\n", rval);

	return rval;
}

static struct dvsproc_stat *dvs_request_stats_type(struct file_request *filerq)
{
	switch(filerq->request) {
		case RQ_READPAGE_DATA: {			/* DEPRECATED 06/2014 */
			struct inode_info *iip;
			iip = filerq->u.readpagedata.iip;
			if (iip->fp != NULL)
				return FILE_ICSB(iip->fp)->stats;
			break;
		}
		case RQ_RO_CACHE_DISABLE: {
			struct file *cfp;
			cfp = filerq->u.rocachedisablerq.fp;
			if (cfp != NULL)
				return FILE_ICSB(cfp)->stats;
			break;
		}
		default:
			return NULL;
	}
	return NULL;
}

int quiesce_remote_ref(char *dir, int dirlen, struct remote_ref *rr) {
	/* This large path_buff is ok because it's called from a userspace
	 * process, as part of writing to the quiesce proc file */
        char path_buff[UPFS_MAXNAME + 16];
        char *path;

	if (dir == NULL) {
		printk(KERN_ERR "DVS: quiesce_remote_file called with NULL dir\n");
		return 0;
	}

	/* Find out the file's current path */
	path = d_path(&rr->fp->f_path, path_buff, sizeof(path_buff));
	if (IS_ERR(path)) {
		printk("DVS: quiesce_remote_ref %p had d_path error %lu\n",
			rr->fp, PTR_ERR(path));
		return 0;
	}

	/* We found a candidate. */
	if (dvs_is_subdir(dir, dirlen, path)) {
		rr->quiesced = 1;
		return 1;
	}
	return 0;
}

void dvs_rr_ref_put(struct remote_ref *rr) {
        rr_ref_put(rr);
}
EXPORT_SYMBOL(dvs_rr_ref_put);

/*
 * This function iterates through the open remote references.
 * If an rr is for a file in a quiesced file system, all locks
 * are removed and that file is closed. The remote reference is
 * preserved in the quiesce_dir list. This function must be called
 * with a write lock on quiesce_barrier_rwsem held.
 */
void close_all_quiesced_files(struct quiesced_dir *qdir) {

        struct remote_ref *rr, *rr_tmp;
	struct dvs_posix_lock *dpl, *dpl_tmp;
	struct files_struct *files;
	unsigned long elapsed_jiffies;
	char pb[32] = "";
	char *path = pb;
	char *dir = qdir->dir;
        int dirlen = qdir->dir_len;
	int closed_files = 0;
	struct list_head *qdir_rr_list = &qdir->quiesced_rr_list;

        /* Iterate over every single open file. Remove any in dir and save them */
	spin_lock(&rr_sl);
	list_for_each_entry_safe(rr, rr_tmp, &rr_list, rr_lh) {
		if (quiesce_remote_ref(dir, dirlen, rr)) {
			rr_ref_get(rr);
			if (dvs_debug_mask & DVS_DEBUG_QUIESCE)
				path = dvs_dentry_path(rr->fp->f_path.dentry,
							pb, sizeof(pb));
			KDEBUG_QSC(0, "%s rr %p being quiesced\n", path, rr);
			list_del_init(&rr->rr_lh);
			list_add_tail(&rr->quiesced_lh, qdir_rr_list);
                }
        }
	spin_unlock(&rr_sl);

        /* Iterate through the list of files to close, and close them */
	list_for_each_entry(rr, qdir_rr_list, quiesced_lh) {

                if (atomic_long_read(&rr->fp->f_count) <= 0) {
                        printk(KERN_ERR "DVS: close_all_quiesced_files: count "
					"error for 0x%p\n", rr->fp);
                }

		if (dvs_debug_mask & DVS_DEBUG_QUIESCE)
			path = dvs_dentry_path(rr->fp->f_path.dentry, pb, sizeof(pb));

		sync_remove_inode_ref(rr);

                /* We can't do any of the teardown process until we're sure
                 * that no one is holding a remote_ref or inode_ref pointer.
                 * The actual work is done in free_remote_ref(). */

		/* TODO: Move the remote ref stuff to its own function */
restart:
		spin_lock(&rr->posix_lock_sl);
		list_for_each_entry_safe(dpl, dpl_tmp, &rr->posix_lock_lh, lh) {
			KDEBUG_QSC(0, "%s Removing remote ref member\n", path);

			files = &dpl->files;
			/* wait for any non-DVS file_struct refs to be released - bug 808390 */
			if (atomic_read(&files->count) > 1) {
				spin_unlock(&rr->posix_lock_sl);
				cond_resched();
				goto restart;
			}

			/* Remove any POSIX locks left on the file */
			locks_remove_posix(rr->fp, files);
			list_del(&dpl->lh);
			kfree(dpl);
		}
		spin_unlock(&rr->posix_lock_sl);

		KDEBUG_QSC(0, "Closing file %s %p\n", path, rr->fp);
		elapsed_jiffies = jiffies;
		/*
		 * Close the quiesced file. If we don't flush every fput
		 * they'll all get performed after we leave kernel space.
		 */
                filp_close(rr->fp, NULL);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		flush_delayed_fput();
#endif
		log_fs("close[close_all_quiesced_files]", fpname(rr->fp),
		       jiffies - elapsed_jiffies, NULL);

		/* Update the number of open files */
		dvsproc_stat_update(NULL, DVSPROC_STAT_OPEN_FILES, 0, -1);
		closed_files++;
        }

	printk(KERN_ERR "DVS: Quiesce finished for %s after closing %d files\n",
		qdir->dir, closed_files);
}
EXPORT_SYMBOL(close_all_quiesced_files);

/*
 * If the request is for a quiesced directory,
 * return 1. Else return 0.
 */
int request_is_quiesced(struct file_request *filerq) {

	char *path1 = NULL;
	char *path2 = NULL;
	char *opname = file_request_to_string(filerq->request);

	/* path2 is for links and renames, where 2 paths are in play */
	dvs_get_path(filerq, &path1, &path2);
	if (path1 == NULL)
		return 0;

	return path_is_quiesced(opname, path1, path2);
}

static int do_usifile(struct file_request *filerq)
{
	struct file_reply *filerp = NULL;
	struct remote_ref *rr = NULL;
	struct usicontext *save_ctx;
	struct dvsproc_stat *stats = NULL;
	unsigned long debug = filerq->ipcmsg.debug;
	mm_segment_t oldfs;
	long rval;
	int rr_quiesced = 0;

	rval = -ENXIO;

	if (!filerq || filerq->request >= RQ_DVS_END_V1) {
		printk(KERN_ERR "DVS: do_usifile: illegal request %d\n",
				filerq->request);
		return -EINVAL;
	}

	down_read(&quiesce_barrier_rwsem);

	/*
	 * If rr is NULL, cases that need these will test for this condition
	 * and return error. If rr is NULL, cases that need a remote ref will
	 * test for this condition and return error.
	 */
	rr = get_valid_remote_ref(&filerq->file_handle,
			filerq->ipcmsg.source_node, &rr_quiesced, debug);

	/* Check if this request is for a quiesced directory */
	if (rr_quiesced || (rr == NULL && request_is_quiesced(filerq))) {
		up_read(&quiesce_barrier_rwsem);
		return -EQUIESCE;
	}

	if ((save_ctx = kmalloc_ssi(sizeof(struct usicontext),
					GFP_KERNEL)) == NULL) {
		printk("DVS: do_usifile: failed to allocate usicontext: "
				"req=%d, client=%s\n", filerq->request,
				SSI_NODE_NAME(filerq->context.node));
		if (rr)
			rr_ref_put(rr);
		up_read(&quiesce_barrier_rwsem);
		return -ENOMEM;
	}

	/*
	 * The following is necessary to allow kernel addresses to be passed
	 * to the syscall layer.  This needs to happen when an ipc thread gets
	 * initialized.
	 */
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/*
	 * Replace the current context with the passed context
	 */
	if (push_context(save_ctx, &filerq->context) < 0) {
		printk("DVS: do_usifile: failed to push context: "
				"req=%d, client=%s\n", filerq->request,
				SSI_NODE_NAME(filerq->context.node));
		set_fs(oldfs);
		kfree_ssi(save_ctx);
		if (rr)
			rr_ref_put(rr);
		up_read(&quiesce_barrier_rwsem);
		return -ENOMEM; /* push context only fails with ENOMEM */
	}

	KDEBUG_OFS(debug, "DVS: dvsofserver: do_usifile: request %d (%s)\n",
			filerq->request, file_request_to_string(filerq->request));

	/* Call the server functions that will actually handle the request. */
	rval = (*dvs_rq_handlers[filerq->request])(filerq, &filerp, rr, debug);

	if (rval < 0)
		KDEBUG_OFS(debug, "DVS: do_usifile %s OUT:  rval = %ld\n",
				file_request_to_string(filerq->request), rval);

	DVS_TRACE("doFR", (u64)filerq->request, (u64)rval);

	/* Translate internal to external error if necessary */
	if (rval == -ERESTARTSYS) {
		rval = -EAGAIN;
	}

	pop_context((save_ctx));
	set_fs(oldfs);

	/* send reply and free working storage */
	if (filerp) {
		if (rval == -ESTALE && server_should_estale_retry(filerq, rr))
			rval = -ESTALE_DVS_RETRY;

		filerp->rval = rval;

		/* return the last sync time to the client */
		filerp->ipcmsg.jiffies_val = LONG_MIN;
		if (rr && rr->inode_ref && rr->inode_ref->last_sync)
			filerp->ipcmsg.jiffies_val = jiffies -
				rr->inode_ref->last_sync;

		KDEBUG_OFS(debug, "DVS: dvsofserver: do_usifile: request (%s) "
				"send reply rval %ld\n",
				file_request_to_string(filerq->request), rval);

		stats = dvs_request_stats_type(filerq);

		send_ipc_reply_stats(stats, filerq, filerp,
				filerp->ipcmsg.reply_length, REPLY_NOCOPY);
	}

	if (rr)
		rr_ref_put(rr);

	kfree_ssi(save_ctx);

	estale_print_messages(filerq, rval);

	KDEBUG_OFS(debug, "DVS: dvsofserver: do_usifile: request %d (%s) done\n",
			filerq->request, file_request_to_string(filerq->request));

	up_read(&quiesce_barrier_rwsem);

	return 0;
}

int do_usifile_stats(struct file_request *freq)
{
	int ret;
	unsigned long elapsed_jiffies = jiffies;

	ret = do_usifile(freq);

	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(NULL, DVSPROC_STAT_REQP, freq->request, ret);
	dvsproc_stat_update(NULL, DVSPROC_STAT_REQP_TIME, freq->request,
			elapsed_jiffies);

	return ret;
}

/*
 * Search a server list for a dead node and set it down
 */
static int set_servers_down(int node, struct dvs_server *servers, int len) {

	int i, found = 0;

	for (i = 0; i < len; i++) {
		if (!servers[i].up || servers[i].node_map_index != node)
			continue;
		servers[i].up = 0;
		servers[i].magic = -1;
		found++;
	}
	return found;
}

static int file_uses_node(int node, struct file *fp) {

	int i;
	int len = FILE_PRIVATE(fp)->rf_len;
	struct remote_file *rf = FILE_PRIVATE(fp)->rf;

	for (i = 0; i < len; i++) {
		if (rf[i].remote_node == node) {
			return 1;
		}
	}

	return 0;
}

/*
 * We don't clear the identity for 'excluding_node' as we don't want RQ_CLOSE to
 * be sent to the server that we know is down.
 */
static void reset_file_remote_identities(int excluding_node, struct file *fp) {

	int i;
	int len = FILE_PRIVATE(fp)->rf_len;
	struct remote_file *rf = FILE_PRIVATE(fp)->rf;

	for (i = 0; i < len; i++) {
		if (rf[i].remote_node != excluding_node) {
			rf[i].identity = BOGUS_IDENTITY;
		}
	}
}

/*
 * React to a server (or the current node) failing or unloading DVS.
 * Don't break out of loops when a match of the node is found, since nodes
 * may be listed multiple times per mount.
 */
void file_node_down(int node)
{
	struct remote_ref *rr, *rr_tmp;
	int cnt = 0, super_blocks_affected = 0, found;
	struct list_head rr_to_be_freed;
	struct task_struct *task = NULL;
	struct file *hold_fp = NULL;
	struct open_file_info *finfo = NULL;
	struct incore_upfs_super_block *icsb = NULL;
	unsigned long elapsed_jiffies;

	DVS_TRACE("FND", node, 0);
	KDEBUG_OFS(0, "DVS: file_node_down: node %s\n",
			node >= 0 ? SSI_NODE_NAME(node) : "ALL");

	INIT_LIST_HEAD(&rr_to_be_freed);

	down_read(&quiesce_barrier_rwsem);

	/* We received a false node_down event */
	if (node == usi_node_addr) {
		KDEBUG_OFS(0, "DVS: %s: local node down \n", __FUNCTION__);
		(void) check_processes(node, NULL, NULL);
		up_read(&quiesce_barrier_rwsem);
		return;
		/* client is reacting to a server going down */
	} else if (node != -1) {

		/*
		 * See if any processes need to be killed to prevent silent
		 * data corruption.
		 */
		(void) check_processes(node, NULL, NULL);

		/*
		 * Adjust node state information for each super block if
		 * failover is enabled.
		 */
		down(&dvs_super_blocks_sema);
		list_for_each_entry(icsb, &dvs_super_blocks, list) {

			found = 0;

			if (!icsb->loadbalance && !icsb->failover)
				continue;

			down_write(&failover_sema);

			found += set_servers_down(node, icsb->data_servers,
						icsb->data_servers_len);

			found += set_servers_down(node, icsb->meta_servers,
						icsb->meta_servers_len);

			if (!found) {
				up_write(&failover_sema);
				continue;
			}

			super_blocks_affected++;

			/* loadbalance case */
			if (icsb->loadbalance && found) {
				int new_index;

				if ((icsb->loadbalance - found) == 0)
					icsb->loadbalance = 1;
				else
					icsb->loadbalance -= found;
				new_index = usi_node_addr % icsb->loadbalance;
				icsb->loadbalance_node = loadbalance_index(icsb, new_index);
				KDEBUG_INF(0, "DVS: %s: loadbalance failover "
						"from %s to %s\n", __FUNCTION__,
						SSI_NODE_NAME(node),
						SSI_NODE_NAME(icsb->loadbalance_node));
				DVS_TRACEL("dvsFO->", node,
						icsb->loadbalance_node,
						__builtin_return_address(0),
						__builtin_return_address(1), 0);
				up_write(&failover_sema);
				continue;
			}

			/* non-loadbalance case */
			spin_lock(&icsb->lock);
			list_for_each_entry(finfo, &icsb->open_files, list) {
				/*
				 * Trash the file identity for any file that
				 * was using the dead node.  This causes the
				 * next I/O attempt to that file to fail
				 * at which point a new node will be picked
				 * based on the server node state(s) at that
				 * time.  If the file is in stripe parallel
				 * mode, clear all server identities (except
				 * for 'node') to ensure even striping across
				 * servers, etc.
				 */
				if (file_uses_node(node, finfo->fp)) {
					reset_file_remote_identities(node, finfo->fp);
				}

			}
			spin_unlock(&icsb->lock);
			up_write(&failover_sema);
		}
		up(&dvs_super_blocks_sema);

		if (!task) {
			/*
			 * Adjust any asynchronous requests which may be
			 * targeting the down server.  Do it in a separate
			 * thread so the main thread can continue to call
			 * krca_heartbeat() in a timely manner, etc.
			 */
			task = kthread_run(async_op_retry, (void *)(long)node,
					"%s", "DVS-retry");
			if (IS_ERR(task)) {
				printk(KERN_INFO "DVS: %s: error %ld create "
						"DVS-retry thread\n",
						__FUNCTION__, PTR_ERR(task));
			}
		}
	}

	if (super_blocks_affected) {
		printk(KERN_INFO "DVS: %s: removing %s from list of available "
				"servers for %d mount points\n", __FUNCTION__,
				SSI_NODE_NAME(node), super_blocks_affected);
	}

	/*
	 * If this is a server reacting to a client going down or the
	 * server shutting down DVS itself, clean up any remote references
	 * and open files created on behalf of the client (or clients).
	 */

	spin_lock(&rr_sl);
	list_for_each_entry_safe(rr, rr_tmp, &rr_list, rr_lh) {
		if ((node == -1) || (rr->node == node)) {

			spin_lock(&node_map[rr->node].rr_lock);
			/* corrupt key value so do_usifile doesn't use this
			 * remote_ref */
			rr->key = 0;
			spin_unlock(&node_map[rr->node].rr_lock);

			list_del_init(&rr->rr_lh);
			list_add(&rr->rr_lh, &rr_to_be_freed);
		}
	}
	spin_unlock(&rr_sl);

	list_for_each_entry_safe(rr, rr_tmp, &rr_to_be_freed, rr_lh) {
		cnt++;
		KDEBUG_OFS(0, "DVS: file_node_down: (2) %s %s\n",
				node >= 0 ? SSI_NODE_NAME(node) : "ALL",
				rr->fp->f_path.dentry->d_name.name);
		DVS_TRACEL("FND", node, rr->fp,
				atomic_long_read(&rr->fp->f_count), 0, 0);
		if (atomic_long_read(&rr->fp->f_count) <= 0) {
			printk(KERN_ERR "DVS: file_node_down: count error "
					"node=%s, fp=0x%p\n", SSI_NODE_NAME(node), rr->fp);
		}

		/* We can't do any of the teardown process until we're sure
		 * that no one is holding a remote_ref or inode_ref pointer. 
		 * The actual work is done in free_remote_ref(). */
		hold_fp = rr->fp;
		list_del(&rr->rr_lh);
		rr_ref_put(rr);
		/* free_remote_ref has cleaned up the posix locks, but
		   we have to do the final close on the file */
		elapsed_jiffies = jiffies;
		filp_close(hold_fp, NULL);
		log_fs("close[file_node_down]", fpname(rr->fp),
		       jiffies - elapsed_jiffies, NULL);
	}

	if (cnt) {
		KDEBUG_OFS(0, "DVS: file_node_down: Cleaned up %d file "
				"references from down node %s\n", cnt,
				node >= 0 ? SSI_NODE_NAME(node) : "ALL");
	}

	up_read(&quiesce_barrier_rwsem);
}

/*
 * Adds new ro_cache_fp entry to list of file instances currently being cached
 * for inode
 */
struct ro_cache_fp *ro_cache_listadd_fp(struct file *fp,
		struct ro_cache_ihash *ihash, int cnode,
		time_t cidentity)
{
	struct ro_cache_fp *cfp;

	cfp = kmalloc_ssi(sizeof(struct ro_cache_fp), GFP_KERNEL);
	if (cfp == NULL)
		return NULL;

	cfp->cnode = cnode;
	cfp->cidentity = cidentity;
	cfp->fp = fp;

	down(&ihash->fp_sem);
	cfp->next = ihash->fp_head;
	if (ihash->fp_head)
		ihash->fp_head->prev = cfp;
	ihash->fp_head = cfp;
	ihash->fp_count++;
	up(&ihash->fp_sem);

	KDEBUG_OFS(0, "DVS: ro_cache_listadd_fp: added 0x%p fp 0x%p node %s ino %lu\n",
			cfp, fp, SSI_NODE_NAME(cnode), ihash->i_ino);

	return cfp;
}

static struct ro_cache_ihash *ihash_init(unsigned long ino)
{
	struct ro_cache_ihash *ihash = NULL;

	ihash = kmalloc_ssi(sizeof(struct ro_cache_ihash), GFP_KERNEL);
	if (ihash == NULL)
		return NULL;

	ihash->i_ino = ino;
	ihash->writecount = 0;
	ihash->fp_count = 0;
	ihash->fp_head = NULL;
	sema_init(&ihash->fp_sem, 1);

	return ihash;
}

/*
 * Checks hashtable for existing inode entry and creates new entry if one does
 * not exist.  If file can safely be cached, adds fp to list of cached files
 * returns 1 if caching is safe
 * returns 0 if caching not safe
 */
int ro_cache_readonly(struct file *fp, char *path, struct usiipc *ipcmsg,
		struct file *client_fp)
{
	struct ro_cache_ihash *ihash = NULL;
	struct ro_cache_fp *cfp = NULL;
	unsigned long ino = file_inode(fp)->i_ino;
	int rval = 1;

	down(&ro_cache_sem);
	ihash = ht_find_data(ro_cache_table, ino);
	if (ihash != NULL) {
		if (!ihash->writecount) {
			cfp = ro_cache_listadd_fp(client_fp, ihash,
					SOURCE_NODE(ipcmsg),
					REMOTE_IDENTITY(ipcmsg));
			if (cfp == NULL)
				rval = -ENOMEM;
		} else
			rval = 0;

		up(&ro_cache_sem);
		return rval;
	}

	/* if not found create an inode entry and add fp - caching is safe  */
	ihash = ihash_init(ino);
	if (!ihash) {
		printk(KERN_CRIT "DVS: ro_cache_find_entry: failed to init "
				"ihash entry for %lu\n", ino);
		goto error;
	}

	if (!ht_insert_data(ro_cache_table, ino, path, ihash)) {
		kfree(ihash);
		printk(KERN_CRIT "DVS: ro_cache_find_entry: Failed to insert "
				"ro_cache inode hashtable entry for %lu\n", ino);
		goto error;
	}

	cfp = ro_cache_listadd_fp(client_fp, ihash, SOURCE_NODE(ipcmsg),
			REMOTE_IDENTITY(ipcmsg));
	if (cfp == NULL) {
		ht_delete_data(ro_cache_table, ino);
		kfree(ihash);
		printk(KERN_CRIT "DVS:ro_cache_find_entry: Failed to insert "
				"fp to inode hash list for %lu\n", ino);
		goto error;
	}

	/* success */
	up(&ro_cache_sem);
	return rval;

error:
	up(&ro_cache_sem);
	return -ENOMEM;
}

/*
 * walk the list of client fps for the given inode and send disable requests to
 * all clients on the list.  If the client is down, remove cfp from list as the
 * file will be gone.
 */
int ro_cache_listwalk(struct ro_cache_ihash *ihash, struct file_request *o_req)
{
	struct ro_cache_fp *cfp, *next_cfp, *prev_cfp;
	int rval, fp_count, iter, max_count, error = 0;
	int req_size = sizeof(struct file_request);
	int rep_size = sizeof(struct file_reply);
	struct per_node *pna = NULL;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;

	down(&ihash->fp_sem);

	if (ihash->fp_count) {
		fp_count = max_count = ihash->fp_count > 128 ? 128 : ihash->fp_count;

		pna = (struct per_node *)kmalloc_ssi(sizeof(struct per_node) *
				max_count, GFP_KERNEL);
		if (!pna) {
			up(&ihash->fp_sem);
			return -ENOMEM;
		}

		for (iter = 0; iter < max_count; iter++) {
			filerq = pna[iter].request =
				kmalloc_ssi(req_size, GFP_KERNEL);
			filerp = pna[iter].reply =
				kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
			if (!filerq || !filerp) {
				error = -ENOMEM;
				goto done;
			}
		}
	} else {
		if (ihash->fp_head)
			printk(KERN_ERR "DVS: ro_cache_listwalk: fp_count 0 but"
					" fp_head non-null!\n");
		up(&ihash->fp_sem);
		return 0;
	}

send_requests:

	cfp = ihash->fp_head;

	for (iter = 0; iter < fp_count; iter++) {
		filerq = pna[iter].request;
		filerp = pna[iter].reply;

		filerq->request = RQ_RO_CACHE_DISABLE;
		filerq->retry = o_req->retry;
		filerq->rip = o_req->rip;
		capture_context((&filerq->context));

		filerq->u.rocachedisablerq.fp = cfp->fp;

		rval = send_ipc_request_async_stats(NULL, cfp->cnode, RQ_FILE,
				filerq, req_size, filerp,
				rep_size, cfp->cidentity);

		/* If send fails entire operation fails as a client could be left
		 * in cache mode, unless failure was EHOSTDOWN then client files
		 * will no longer be open due to down node
		 */
		if (rval < 0) {
			if (rval == -EHOSTDOWN) {
				cfp = cfp->next;
				continue;
			} else {
				printk(KERN_ERR "DVS: ro_cache_listwalk: failed send"
						" RQ_RO_CACHE_DISABLE to node %s: 0x%p: %d\n",
						SSI_NODE_NAME(cfp->cnode), cfp->fp, rval);
				error = rval;
				goto done;
			}
		}

		pna[iter].sent = 1;
		cfp = cfp->next;
	}

	/* wait for replies */
	cfp = ihash->fp_head;

	for (iter = 0; iter < fp_count; iter++) {
		filerq = pna[iter].request;
		filerp = pna[iter].reply;

		if (pna[iter].sent) {
			rval = wait_for_async_request_stats(NULL, filerq);
			pna[iter].sent = 0;
			if (rval < 0) {
				/* response failure */
				if (rval != -EHOSTDOWN) {
					printk(KERN_ERR "DVS: ro_cache_listwalk: "
							"wait for ipc failed %d\n", rval);
					error = rval;
					goto done;
				}
			} else if (filerp->rval < 0) {
				/* failure on server */
				printk(KERN_ERR "DVS: ro_cache_listwalk: error "
						"on server for RQ_RO_CACHE_DISABLE %ld\n",
						filerp->rval);
				error = filerp->rval;
				goto done;
			}
		}

		prev_cfp = cfp->prev;
		next_cfp = cfp->next;
		if (prev_cfp)
			prev_cfp->next = next_cfp;
		else
			ihash->fp_head = next_cfp;
		if (next_cfp)
			next_cfp->prev = prev_cfp;

		kfree(cfp);
		cfp = next_cfp;
		ihash->fp_count--;

		memset(filerq, 0, req_size);
		memset(filerp, 0, rep_size);
	}

	if (ihash->fp_count) {
		fp_count = ihash->fp_count > 128 ? 128 : ihash->fp_count;
		goto send_requests;
	}

done:
	for (iter = 0; iter < max_count; iter++) {
		if (pna[iter].sent)
			wait_for_async_request_stats(NULL, pna[iter].request);
		if (pna[iter].request)
			free_msg(pna[iter].request);
		if (pna[iter].reply)
			free_msg(pna[iter].reply);
	}
	kfree(pna);
	up(&ihash->fp_sem);

	if (error)
		return error;
	return 0;
}

/*
 *  Check hashtable on writable file open.  If inode entry exists check for open
 *  file instances and disable cache modes.  Else create inode entry and increment
 *  writecount. Returns 0 on success.
 */
int ro_cache_write(struct file *fp, char *path, struct file_request *freq)
{
	struct ro_cache_ihash *ihash = NULL;
	unsigned long ino = file_inode(fp)->i_ino;
	int rval;

	down(&ro_cache_sem);
	ihash = ht_find_data(ro_cache_table, ino);
	if (ihash == NULL) {
		ihash = ihash_init(ino);
		if (!ihash) {
			up(&ro_cache_sem);
			printk(KERN_CRIT "DVS: ro_cache_write: Failed to init "
					"ihash for ino %lu\n", ino);
			return -ENOMEM;
		}

		ihash->writecount++;
		if (!ht_insert_data(ro_cache_table, ino, path, ihash)) {
			kfree(ihash);
			up(&ro_cache_sem);
			printk(KERN_CRIT "DVS: ro_cache_write:  Failed to insert "
					"ro_cache inode hashtable entry for %lu\n", ino);
			return -ENOMEM;
		}

		/* success */
		up(&ro_cache_sem);
		return 0;
	}

	/* if ihash found, inc the writecount. If file was not yet in write-mode
	 * invalidate cache for any fps on list of cached files */
	ihash->writecount++;

	if (ihash->writecount == 1) {
		rval = ro_cache_listwalk(ihash, freq);
		if (rval) {
			ihash->writecount--;
			up(&ro_cache_sem);
			return rval;
		}
	}

	up(&ro_cache_sem);
	return 0;
}

/*
 *  Walk the list of fps for the given file and remove it from the list of
 *  cache mode files as it is being closed
 */
int ro_cache_remove_fp(struct file *fp, int cnode, struct file *client_fp)
{
	struct ro_cache_ihash *ihash = NULL;
	struct ro_cache_fp *cfp, *next, *prev;
	unsigned long ino = file_inode(fp)->i_ino;

	down(&ro_cache_sem);
	ihash = ht_find_data(ro_cache_table, ino);
	if (ihash == NULL) {
		KDEBUG_OFS(0, "DVS: ro_cache_remove_fp: no inode hash entry for "
				"0x%p node %s\n", fp, SSI_NODE_NAME(cnode));
		up(&ro_cache_sem);
		return 0;
	}

	down(&ihash->fp_sem);
	cfp = ihash->fp_head;
	while (cfp) {
		if ((cfp->fp == client_fp) && (cfp->cnode == cnode)) {
			next = cfp->next;
			prev = cfp->prev;
			if (prev)
				prev->next = next;
			else
				ihash->fp_head = next;
			if (next)
				next->prev = prev;

			ihash->fp_count--;
			up(&ihash->fp_sem);

			if ((ihash->writecount == 0) && (ihash->fp_head == NULL)) {
				if (ihash->fp_count != 0)
					printk(KERN_ERR "DVS: ro_cache_remove_fp:"
							" removing inode w/ fpcount!\n");
				ht_delete_data(ro_cache_table, ino);
				kfree(ihash);
			}

			up(&ro_cache_sem);

			KDEBUG_OFS(0, "DVS: ro_cache_remove_fp: "
					"removing 0x%p node %s\n", fp, SSI_NODE_NAME(cnode));
			kfree(cfp);

			return 0;
		}
		cfp = cfp->next;
	}
	KDEBUG_OFS(0, "DVS: ro_cache_remove_fp: cfp not found 0x%p node %s\n",
			fp, SSI_NODE_NAME(cnode));
	up(&ihash->fp_sem);
	up(&ro_cache_sem);

	return 0;
}

/*
 *  Decrement the write count for the given file as it was a writable file
 *  that is being closed
 */
int ro_cache_downwrite(struct file *fp)
{
	struct ro_cache_ihash *ihash = NULL;
	unsigned long ino = file_inode(fp)->i_ino;

	down(&ro_cache_sem);
	ihash = ht_find_data(ro_cache_table, ino);
	if (ihash == NULL) {
		KDEBUG_OFS(0, "DVS: ro_cache_downwrite: no inode hash entry for"
				" file being released 0x%p ino %lu\n", fp, ino);
		up(&ro_cache_sem);
		return 0;
	}

	ihash->writecount--;
	if ((ihash->writecount == 0) && (ihash->fp_head == NULL)) {
		ht_delete_data(ro_cache_table, ino);
		kfree(ihash);
	}

	up(&ro_cache_sem);
	KDEBUG_OFS(0, "DVS: ro_cache_downwrite: released writefile 0x%p ino %lu\n",
			fp, ino);

	return 0;
}

unsigned long dvs_hash_ino(unsigned long ino) {
	return hash_fnv_1a(ino);
}
EXPORT_SYMBOL(dvs_hash_ino);


MODULE_PARM_DESC(dvsof_short_write_max_retry, "number of retries to make for short writes");
module_param(dvsof_short_write_max_retry, int , 0444);
MODULE_PARM_DESC(dvsof_short_write_timeout, "msec to wait between short write retries");
module_param(dvsof_short_write_timeout, int , 0444);
MODULE_PARM_DESC(dvsof_concurrent_reads, "number of threads allowed in read path");
module_param(dvsof_concurrent_reads, int , 0444);
MODULE_PARM_DESC(dvsof_concurrent_writes, "number of threads allowed in write path");
module_param(dvsof_concurrent_writes, int , 0444);
