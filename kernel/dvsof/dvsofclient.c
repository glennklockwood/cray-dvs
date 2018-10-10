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

#include <linux/module.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <asm/bitops.h>
#include <linux/dirent.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/uio.h>
#include <linux/swap.h>
#include <linux/aio.h>
#include <linux/magic.h>
#include <linux/rwsem.h>
#ifdef RHEL_RELEASE_CODE /* bug 823318 */
  #include <linux/swap.h>
#endif
#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"
#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/kernel/usiipc.h"
#include "common/kernel/dvsfs.h"
#include "dvs/usisuper.h"
#include "dvs/kernel/usifile.h"
#include "dvs/kernel/usifileproto.h"
#include "dvs/dvs_ioctl.h"

struct semaphore iotsem;

/* ro_cache hash semaphore */
struct semaphore ro_cache_sem;

DECLARE_RWSEM(failover_sema);

/* forward declarations */
static int urelease_common (struct inode *ip, struct file *fp, int retry);
static int uopen (struct inode *ip, struct file *fp);
static void remove_oio(struct async_retry *p);
static int deferred_uopen (struct inode *ip, struct file *fp, int nord);
int cleanup_reqs(struct inode *ip, cleanup_mode_t mode);
static int ureadpages(struct file *fp, struct address_space *mapping,
                      struct list_head *page_list, unsigned num_pages,
                      int doing_readpage);
static int process_extent(struct file *fp, pages_request_t *rq);

static struct vm_operations_struct vmops = {
	fault:		filemap_fault,
};

/* async retry list */
struct list_head *alist;
struct semaphore *aretrysem;

/* statistics are approximate - not exact */
long inodes_read = 0;
long current_inodes = 0;
long max_inodes = 0;
long mmap_pages_read = 0;
long revalidates_done = 0;
long revalidates_skipped = 0;

#define MAGIC 0x3e3f

/*
 * Table of environment variables that we may process during an open() on
 * a DVS file.
 */
typedef struct {
	int             opt_which;
	char *          opt_name;
	int             opt_len;
} opt_entry;

#define DVS_DATASYNC_TYPE    0
#define DVS_CACHE_TYPE       1
#define DVS_BLOCKSIZE_TYPE   2
#define DVS_MAXNODES_TYPE    3
#define DVS_CLOSESYNC_TYPE   4
#define DVS_METATEST_TYPE    5
#define DVS_KILLPROCESS_TYPE 6
#define DVS_ATOMIC_TYPE      7
#define DVS_DEFEROPENS_TYPE  8
#define DVS_CACHE_RD_SZ_TYPE 9

static opt_entry optionlist[] = {
	{DVS_DATASYNC_TYPE,    DVS_DATASYNC,      0},
	{DVS_CACHE_TYPE,       DVS_CACHE,         0},
	{DVS_BLOCKSIZE_TYPE,   DVS_BLOCKSIZE,     0},
	{DVS_MAXNODES_TYPE,    DVS_MAXNODES,      0},
	{DVS_CLOSESYNC_TYPE,   DVS_CLOSESYNC,     0},
	{DVS_METATEST_TYPE,    DVS_METATEST,      0},
	{DVS_KILLPROCESS_TYPE, DVS_KILLPROCESS,   0},
	{DVS_ATOMIC_TYPE,      DVS_ATOMIC,        0},
	{DVS_DEFEROPENS_TYPE,  DVS_DEFEROPENS,    0},
	{DVS_CACHE_RD_SZ_TYPE, DVS_CACHE_READ_SZ, 0},
};
static int numoptions = sizeof(optionlist) / sizeof(opt_entry);

/*
 * Fill in the per-nord path name for the DWFS data files in the remote file
 * structs. stripe_end is the path to all of the data stripes except the BC
 * stripe. bcstripe_path holds the path to the BC stripe. Both stripe_path and
 * bcstripe_path are relative to the DWFS mount point and don't include the
 * index number on the end of the filename.
 */
int create_dwfs_data_paths(struct file *fp, struct dwfs_open_info *dwfs_info)
{
	int bcstripe_index;
	char *stripe_path, *bcstripe_path;
	ssize_t size, bcstripe_size;
	struct inode *inode;
	char *data_path, *path, buf[1];
	int i, start_nord;

	bcstripe_index = dwfs_info->bcstripe;
	stripe_path = dwfs_info->path;
	bcstripe_path = dwfs_info->path + dwfs_info->path_len;

	inode = file_inode(fp);

	/* Figure out the size of the path by using snprintf() with a one byte
	 * buffer. snprintf() won't overflow the buffer, so we're safe. */
	size = snprintf(buf, 1, "/%s/%s%d",
		                FILE_ICSB(fp)->remoteprefix,
				stripe_path,
		                INODE_ICSB(inode)->data_servers_len - 1);

	bcstripe_size = snprintf(buf, 1, "/%s/%s%d",
	                         FILE_ICSB(fp)->remoteprefix,
	                         bcstripe_path,
	                         bcstripe_index);

	/* Add room for the NULL byte */
	size += 1;
	bcstripe_size += 1;

	if (bcstripe_size > size)
		size = bcstripe_size;

	if ((data_path = kmalloc_ssi(size * FILE_PRIVATE(fp)->data_rf_len,
	                             GFP_KERNEL)) == NULL)
		return -ENOMEM;

	start_nord = inode_sso(inode);

	for (i = 0; i < FILE_PRIVATE(fp)->data_rf_len; i++) {
		if ((start_nord + i) % INODE_ICSB(inode)->data_servers_len == bcstripe_index)
			path = bcstripe_path;
		else
			path = stripe_path;

		KDEBUG_OFC(0, "file %p nord %d data_rf_len %d stripe path: %s\n",
				fp, i, FILE_PRIVATE(fp)->data_rf_len, path);

		if (size < snprintf(data_path + (size * i), size,
		                    "/%s/%s%d", FILE_ICSB(fp)->remoteprefix, path,
		                    (start_nord + i) % INODE_ICSB(inode)->data_servers_len)) {
			kfree_ssi(data_path);
			printk(KERN_ERR "DVS: %s Setting dwfs_data_path to NULL\n", __func__);
			DATA_RF(fp, 0)->dwfs_data_path = NULL;

			printk("DVS: Error: DWFS data path for remote_prefix "
			       "%s, stripe_path %s, and nord %d exceeds buffer "
			       "length of %lu\n", FILE_ICSB(fp)->remoteprefix,
			       stripe_path,
			       (start_nord + i) % INODE_ICSB(inode)->data_servers_len, size);
			return -ENAMETOOLONG;
		}

		if (DATA_RF(fp, i)->dwfs_data_path != NULL) {
			printk("DVS: Error: DWFS data path already initialized "
					"to %s for file %s\n",
					DATA_RF(fp, i)->dwfs_data_path, fpname(fp));
			kfree_ssi(data_path);
			return -EINVAL;
		}

		KDEBUG_OFC(0, "Setting file %p dwfs_data_path to %s\n", fp, path);
		DATA_RF(fp, i)->dwfs_data_path = data_path + (size * i);
	}

	return 0;
}

/*
 * If we know that this file is quiesced, mark it as such and do any
 * cleanup that needs to happen.
 */
void mark_remote_file_quiesced(struct file *fp, struct remote_file *rf) {

	struct ssi_server_info *server_info = NULL;
	int rf_offset = (rf - FILE_PRIVATE(fp)->rf)/sizeof(struct remote_file);
	char pb[32] = "";
	char *path = pb;

	if (rf->quiesced)
		return;

	server_info = node_map[rf->remote_node].server_info;

	if (dvs_debug_mask & DVS_DEBUG_QUIESCE)
		path = dvs_dentry_path(fp->f_path.dentry, pb, sizeof(pb));

	KDEBUG_QSC(0, "Quiescing remote file %s:%d FILE_NNODES %d\n", path,
			rf_offset, FILE_PRIVATE(fp)->data_rf_len);

	/* NULL out any stale remote handle info */
	rf->quiesced = 1;
	rf->file_handle.remote_ref = NULL;
	rf->file_handle.key = -1;

	if (server_info == NULL) {
		return;
	}

	/* Remove the remote file from the sync list */
	spin_lock(&server_info->lock);
	if (!list_empty(&rf->list)) {
		list_del_init(&rf->list);
		/* A negative open_files count is leaving a trap for sync_thread */
		BUG_ON(atomic_dec_return(&server_info->open_files) < 0);
	}
	else {
		printk(KERN_ERR "DVS: Attempting to re-quiesce file %p offset "
			"%d\n",	fp, rf_offset);
	}
	spin_unlock(&server_info->lock);
}


/*
 * Common retry code
 */

/*
 * file_ops_retry manages the retry of the reopen of a file,
 * in order to get ready for retry of a file-related operation.
 * It will keep trying indefinitely, every RETRYSLEEP seconds.
 * Return:
 * - This function will return immediately with EHOSTDOWN if
 *   retry was not enabled when this filesystem was mounted.
 * - It will also return immediately with EHOSTDOWN if check_processes()
 *   determines that a server failure could result in data corruption
 *   should a retry be allowed.
 * - A zero return indicates the open succeeded; okay to retry op.
 * - An error is returned if the open fails for any other reason
 *   than EHOSTDOWN, or if the delay sleep is interrupted.
 */
int file_ops_retry(struct file *fp, char *opname, int orig_rval)
{
	int rval, oval, retry = 0, i;
	struct inode *ip = file_inode(fp);
	char *path=NULL, *bufp=NULL;
	wait_queue_head_t wqh;
	int retryalready=0;
	DEFINE_WAIT(wait);
	int sleep_before_reopen = 1;
	char pb[32] = "";
	char *path_ptr = NULL;

	if (orig_rval == -EQUIESCE) {
		/* Check that there is still at least one unquiesced remote file
		      otherwise we have to close and reopen the file */
		for (i = 0; i < FILE_PRIVATE(fp)->data_rf_len; i++) {
			if (!DATA_RF(fp, i)->quiesced) {
				/* We always retry with quiesce */
				return 0;
			}
		}
		/* No need to sleep during quiesce situations */
		sleep_before_reopen = 0;
		if ((dvs_debug_mask & DVS_DEBUG_QUIESCE) && path_ptr == NULL)
			path_ptr = dvs_dentry_path(fp->f_path.dentry, pb, sizeof(pb));
		KDEBUG_QSC(0, "Op %s file %p No unquiesced remote files FILE_NNODES"
				" %d\n", opname, fp, FILE_PRIVATE(fp)->data_rf_len);
	}

	/*
	 * We will attempt a close and open of the file for ESTALE_DVS_RETRY,
	 * and if that fails with an ESTALE_DVS_RETRY we will loop in
	 * inode_ops_retry until we succeed or we reach the maximum number of
	 * retries. If estale_max_retry is zero, we bail out here and return
	 * ESTALE to the caller.
	 */
	
	if (orig_rval == -ESTALE_DVS_RETRY) {
		orig_rval = -ESTALE;
		if (!estale_max_retry)
			return -ESTALE;
	}


	if (orig_rval == -EHOSTDOWN) {
		if (!INODE_ICSB(ip)->retry) {
			KDEBUG_OFC(0, "DVS: file_ops_retry: %s: no retry\n", opname);
			return -EHOSTDOWN;
		}

		if ((rval = check_processes(0, fp, NULL)))
			return rval;
	}

	down(&FILE_PRIVATE(fp)->rip_sema);
	if (!FILE_PRIVATE(fp)->rip) {
		FILE_PRIVATE(fp)->rip = 1;
	} else {
		retryalready = FILE_PRIVATE(fp)->rip;
	}
	up(&FILE_PRIVATE(fp)->rip_sema);
	while (1) {
		if (!retry) {
			bufp = (char *)__get_free_page(GFP_KERNEL);
			if (bufp) {
				if (fp->f_path.dentry == NULL || 
					IS_ERR(path = get_path(fp->f_path.dentry,
						fp->f_path.mnt, bufp, ip))) {
					path = NULL;
				}
			}
		}
		retry++;

		if (sleep_before_reopen) {
			DVS_TRACE("rtdelay", fp, retry);
			KDEBUG_OFC(0, "DVS: file_ops_retry: %s: begin delay (%d seconds) "
					"before retry %d, ip=0x%p, fp=0x%p, path=%s\n", opname,
					RETRYSLEEP, retry, ip, fp, path ? path : "N/A");
			init_waitqueue_head(&wqh);
			prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
			if (schedule_timeout(RETRYSLEEP*HZ)) {
				DVS_TRACE("rtintr", fp, retry);
				KDEBUG_OFC(0, "DVS: file_ops_retry: %s: retry delay "
						"interrupted, bailing out, ip=0x%p, fp=0x%p, "
						"path=%s\n", opname, ip, fp,
						path ? path : "N/A");
				rval = orig_rval;
				if (!retryalready) {
					down(&FILE_PRIVATE(fp)->rip_sema);
					FILE_PRIVATE(fp)->rip = 0;
					up(&FILE_PRIVATE(fp)->rip_sema);
				}
				finish_wait(&wqh, &wait);
				break;
			}
			finish_wait(&wqh, &wait);
		}

		if (retryalready) {
			down(&FILE_PRIVATE(fp)->rip_sema);
			retryalready = FILE_PRIVATE(fp)->rip;
			up(&FILE_PRIVATE(fp)->rip_sema);
			if (retryalready) {
				DVS_TRACE("rta", fp, 0);
				continue;
			} else {
				rval = 0;
				break;
			}
		}

		DVS_TRACE("rtbegin", fp, retry);
		KDEBUG_OFC(0, "DVS: file_ops_retry: %s: begin retry %d, ip=0x%p, "
			   "fp=0x%p path=%s\n", opname, retry, ip, fp,
			   path ? path : "N/A");

		/* Quiesced files have already been closed */
		if (fp->private_data != NULL && orig_rval != -EQUIESCE) {
			rval = urelease_common(ip, fp, 1);
			/* urelease_common shouldn't return -ESTALE_DVS_RETRY */
			if (rval == -EHOSTDOWN)
				break;
		}

		if (orig_rval == -EQUIESCE) {
			KDEBUG_QSC(0, "Op %s Attempting to reopen file %s due to "
				"quiesce\n", opname, path_ptr);
		}

		if ((oval = uopen(ip, fp)) < 0) {
			/* retry re-open for "node down" only. uopen can't return
			 * -ESTALE_DVS_RETRY. */
			if (orig_rval == -EQUIESCE) {
				KDEBUG_QSC(0, "Op %s Reopen of %s due to "
					"quiesce returned %d\n", opname,
					path_ptr, oval);
			}


			if (oval != (ssize_t)-EHOSTDOWN) {
				printk(KERN_INFO "DVS: file_ops_retry: %s: "
					"retry re-open failed (%d), bailing "
					"out, ip=0x%p, fp=0x%p, path=%s\n", opname,
					oval, ip, fp, path ? path : "N/A");
				rval = oval;
                                if (!retryalready) {
                                        down(&FILE_PRIVATE(fp)->rip_sema);
                                        FILE_PRIVATE(fp)->rip = 0;
                                        up(&FILE_PRIVATE(fp)->rip_sema);
                                }
				break;
			}
			KDEBUG_OFC(0, "DVS: file_ops_retry: %s: retry "
				"re-open failed, will try again, ip=0x%p, "
				"fp=0x%p\n", opname, ip, fp);
			continue;
		}
		down(&FILE_PRIVATE(fp)->rip_sema);
		FILE_PRIVATE(fp)->rip = 0;
		up(&FILE_PRIVATE(fp)->rip_sema);

		DVS_TRACE("rtopen", fp, retry);
		KDEBUG_OFC(0, "DVS: file_ops_retry: %s: retry %d re-open "
			"OK, ip=0x%p, fp=0x%p, path=%s\n", opname, retry, ip, fp,
			path ? path : "N/A");

		rval = 0;
		break;
	}

	free_page((unsigned long)bufp);
	return( rval );
}

/*
 * file_node_estale marks a node as ESTALE in the estale nodes array in the
 * open_file_info struct. This is a per file view of which servers are returning
 * ESTALE, so different files on the same client may not share the same list of
 * which servers are returning ESTALE. When a file is opened for the first time,
 * we assume all servers are functioning properly. As ESTALES are returned from
 * the servers, we remove them from the list of usable servers for this file.
 * Once they have been removed, there is no way to fail back to using those
 * servers without closing and reopening the file.
 */
int file_node_estale(struct inode *ip, struct file* fp, int node)
{
	int super_nord;
	struct incore_upfs_super_block *icsb;
	struct open_file_info *finfo;
	char *buf;

	if (!fp || !(finfo = fp->private_data))
		return -ESTALE;

	icsb = ip->i_sb->s_fs_info;

	/* Find the nord offset into the icsb data_servers for the node that is
	 * ESTALE. */
	if ((super_nord = super_node_to_nord(icsb, node)) < 0)
		return -ESTALE;

	/* Allocate the estale_nodes array if it doesn't already exist */
	spin_lock(&finfo->estale_lock);
	if (!finfo->estale_nodes) {
		spin_unlock(&finfo->estale_lock);

		if ((buf = kmalloc_ssi(sizeof(char) * MAX_PFS_NODES, GFP_KERNEL)) == NULL)
			return -ESTALE;

		spin_lock(&finfo->estale_lock);
		if (!finfo->estale_nodes) {
			finfo->estale_num_nodes = 0;
			finfo->estale_max_nodes = icsb->data_servers_len;
			finfo->estale_nodes = buf;
		} else {
			kfree_ssi(buf);
		}
	}

	/* If we ran out of nodes, return ESTALE back up to the caller.
	 * Leave one server functional in case the caller tries another
	 * operation. */
	if (finfo->estale_num_nodes >= finfo->estale_max_nodes - 1) {
		spin_unlock(&finfo->estale_lock);

		ESTALE_LOG("ESTALE: fp 0x%p (file: %s) - Exhausted all servers. Returning "
		           "ESTALE\n", fp, fpname(fp));

		return -ESTALE;
	}

	if (!finfo->estale_nodes[super_nord]) {
		finfo->estale_nodes[super_nord] = 1;
		finfo->estale_num_nodes++;
	}

	spin_unlock(&finfo->estale_lock);

	ESTALE_LOG("ESTALE: fp 0x%p (file: %s) - Setting server %s to ESTALE\n",
	           fp, fpname(fp), SSI_NODE_NAME(node));

	return 0;
}

/*
 * send_ipc_file_retry is a wrapper for send_ipc_request.
 * It manages retry of a file-related IPC request.
 *   myname - function name for error messages
 *   fp - file pointer
 *   nord - node ordinal
 *   filerq, rqsz - request buffer and size
 *   freply, rpsz - reply buffer and size
 *   node - message destination, returned to caller
 * Return value <0 if error, >=0 if OK.
 *
 * Set freply = NULL, rpsz = 0 for async send.
 */
int send_ipc_file_retry (char *myname,
			struct file *fp,
			struct remote_file *rf_array,
			int rf_len,
			int nord,
			struct file_request *filerq,
			int rqsz,
			struct file_reply *freply,
			int rpsz,
			int *node)
{
	int rval = 0, last_rval = 0, rval2 = 0, retry = 0, nodetotry, estale_retry = 0;
	int rf_offset, node_offset = 0;
	int emit_retry_warning = 1;
	int orig_rf_offset;
	int servers_len = 0;
	time_t identity;
	struct inode *ip = file_inode(fp);
	struct incore_upfs_super_block *icsb = FILE_ICSB(fp);

	/* Figure out the correct server list to use */
	if (rf_array[nord].rf_type & RF_TYPE_DATA)
		servers_len = icsb->data_servers_len;
	else
		servers_len = icsb->meta_servers_len;

	KDEBUG_OFC(0, "DVS-send_ipc_file_retry called fp %p rf_array %p rf_len %d\n",
				fp, rf_array, rf_len);

	/* rf_offset is the offset into the remote_file array in the
	 * open_file_info struct. This is used by the dwfs option to access the
	 * MDS remote_file which is the last member of the remote_file array. */
	rf_offset = nord;
	orig_rf_offset = rf_offset;

	filerq->nnodes = 1;
	while (1) {
		last_rval = rval;
		capture_context((&filerq->context));
		if (filerq->flags.root_ctx)
			set_root_context(&filerq->context);

		/*
		 * If the server is quiesced, iterate through the rest of them.
		 * If all servers are quiesced, print an error and bail out.
		 */
		if (rval == -EQUIESCE && filerq->request == RQ_OPEN) {
			emit_retry_warning = 0;
			KDEBUG_QSC(0, "Op %s Node %s path %s was quiesced for node_offset %d, "
				"servers_len %d\n", myname, SSI_NODE_NAME(nodetotry),
				filerq->u.openrq.pathname, node_offset, servers_len);
			node_offset = (node_offset + 1) % servers_len;
			if (node_offset == 0) {
				printk(KERN_ERR "DVS: send_ipc_file_retry: "
						"Could not find unquiesced server for"
						" %s", myname);
				return -EIO;
			}
		}
		else if (rval == -EQUIESCE) {
			emit_retry_warning = 0;
			KDEBUG_QSC(0, "Op %s Node %s file %p was quiesced for rf_offset %d, "
				"data_servers_len %d\n", myname, SSI_NODE_NAME(nodetotry),
				fp, rf_offset, INODE_ICSB(ip)->data_servers_len);
			rf_offset = (rf_offset + 1) % rf_len;
			if (rf_offset == orig_rf_offset) {
				KDEBUG_QSC(0, KERN_ERR "DVS: send_ipc_file_retry "
						"could not find unquiesced remote"
						" file for %s. Calling file_ops_retry\n", myname);
				/* file_ops_retry reopens file if all quiesced */
				rval2 = file_ops_retry(fp, myname, rval);
				/* Reopen may have failed...bail if so */
				if (rval2) {
					KDEBUG_QSC(0, "Op %s file %p file_ops_retry "
						"returned %d. Bailing out\n",
						myname, fp, rval2);
					return rval2;
				}
			}
		}

		/* This file is quiesced, go to the next one */
		if (filerq->request != RQ_OPEN && rf_array[rf_offset].quiesced) {
			KDEBUG_QSC(0, "Op %s file %p rf_offset %d quiesced! "
					"FILE_NNODES: %d\n", myname, fp,
					rf_offset, rf_len);
			rval = -EQUIESCE;
			continue;
		}

		filerq->client_fp = fp;
		if (filerq->request != RQ_OPEN) {
			if (!rf_array[rf_offset].valid) {
				printk(KERN_ERR "DVS: send_ipc_file_retry: "
						"invalid handle for nord %d \n",
						rf_offset);
				return(-EINVAL);
			}
			filerq->rip = retry;
			nodetotry = rf_array[rf_offset].remote_node;
		} else {
			/* uopen has not set up node yet yet */
			if (rf_array[rf_offset].rf_type & RF_TYPE_META)
				nodetotry = inode_meta_server(ip, rf_offset);
			else
				nodetotry = inode_data_server(ip, rf_offset);
		}
		/*
		* Stuff the handle (possibly revised in retry
		* scenarios by the call to file_ops_retry() below)
		* into the request.
		*/
		filerq->file_handle = rf_array[rf_offset].file_handle;
		*node = nodetotry;

		KDEBUG_OFC(0, "DVS: set filerq dwcfs mds node %d FILE_NODE %d\n",
				filerq->dwcfs_mds, nodetotry);

		identity = filerq->request == RQ_OPEN ? NO_IDENTITY : rf_array[rf_offset].identity;
		RESET_FILERQ(filerq);
		if (freply == NULL) {
			rval = send_ipc_request_async_stats(INODE_ICSB(ip)->stats,
							nodetotry,
							RQ_FILE,
							filerq,
							rqsz,
							NULL,
							0,
							identity);
		} else {
			rval = send_ipc_request_stats(INODE_ICSB(ip)->stats,
							nodetotry,
							RQ_FILE,
							filerq,
							rqsz,
							freply,
							rpsz,
							identity);
		}

		if (rval >= 0) {
			if (last_rval == -EQUIESCE) {
				KDEBUG_QSC(0, "Op %s request succeeded for node %s, %s %d\n",
					myname, SSI_NODE_NAME(nodetotry),
					filerq->request == RQ_OPEN ? "node_offset" : "rf_offset",
					filerq->request == RQ_OPEN ? node_offset : rf_offset);
			}
			break;
		}

		if (rval != -EHOSTDOWN && rval != -ESTALE_DVS_RETRY && rval != -EQUIESCE) {
			printk(KERN_ERR "DVS: send_ipc_file_retry: %s: ipc "
			       "failed, node %s: %d\n", myname,
			       SSI_NODE_NAME(nodetotry), rval);
			return(rval);
		}

		/*
		 * If we got an EQUIESCE for the current fp and rf_offset,
		 * we need to invalidate that remote_file.
		 */
		if (rval == -EQUIESCE && filerq->request != RQ_OPEN)
			mark_remote_file_quiesced(fp, &rf_array[rf_offset]);

		retry++;

		if (filerq->request == RQ_OPEN) {
			if (rval == -ESTALE_DVS_RETRY) {
				if (!estale_max_retry)
					return -ESTALE;

				filerq->flags.estale_retry = 1;
				estale_retry++;

				/* we retry estale_max_retry times on the
				 * original server. If that doesn't work we only
				 * try the other servers once. */
				if (estale_retry >= estale_max_retry) {
					if ((rval = file_node_estale(ip, fp, nodetotry)) < 0)
						return rval;

					/* Inform the server that this request
					 * is a retry failover request for an
					 * ESTALE error. This is used for
					 * logging on the server side. */
					filerq->flags.estale_failover = 1;

					/* Don't bother calling inode_ops_retry()
					 * since we don't need a delay. We know
					 * we're switching to a different server
					 * since this one is ESTALE. */
					continue;
				}

				ESTALE_LOG("ESTALE: fp 0x%p (file: %s) - Retrying "
				           "operation on original server %s\n",
				           fp, fpname(fp),
				           SSI_NODE_NAME(nodetotry));
			}

			if ((rval2 = inode_ops_retry(ip, fp->f_path.dentry, myname,
								retry, rval, nodetotry)) < 0) {
				return(rval2);
			}
		} else {
			if ((rval2 = file_ops_retry(fp, myname, rval)) < 0) {
				return(rval2);
			}
		}
	}
	if (retry && emit_retry_warning) {
		printk(KERN_INFO "DVS: send_ipc_file_retry: %s: retry %d OK, "
			"node %s\n", myname, retry, SSI_NODE_NAME(nodetotry));
	}
	if (estale_retry && filerq->flags.estale_failover) {
		ESTALE_LOG("ESTALE: fp 0x%p (file: %s) - Failover to server %s "
		           "succeeded\n", fp, fpname(fp),
		           SSI_NODE_NAME(nodetotry));
	}
	if (freply)
		sync_client_sync_update(freply->ipcmsg.jiffies_val,
		                        filerq->ipcmsg.jiffies_val,
		                        DATA_RF(fp, rf_offset));
	return(rval);
}

EXPORT_SYMBOL(send_ipc_file_retry);

/*
 * send_multi_async_ipc_file_retry is a wrapper for send_ipc_request_async.
 * It manages retry of a file-related async IPC request.
 *   myname - function name for error messages
 *   fp - file pointer
 *   rf_array, rf_len - remote file array and length of array
 *   filerq, filerq_sz - request buffer and size
 *   filerp_sz - reply buffer size
 *   caller_pna - per_node junk (requests and replies)
 *   node_used - destination, returned to caller
 * Return value <0 if error, >=0 if OK.
 *
 * caller required to free all pna memory!!!!
 */
int send_multi_async_ipc_file_retry (char *myname,
				struct file *fp,
				struct remote_file *rf_array,
				int rf_len,
				struct file_request *filerq,
				int filerq_sz,
				int filerp_sz,
				struct per_node **caller_pna,
				int *node_used)
{
	int rval = 0, error = 0, retry_count = 0;
	int nord = 0, node = 0;
	struct remote_file *rf = NULL;
	struct inode *ip = file_inode(fp);
	struct per_node *pna = NULL;
	struct file_request *frq = NULL;
	struct file_reply *frp = NULL;
	time_t identity;

	KDEBUG_OFC(0, "DVS: send_multi_async_ipc_file_retry: %s:\tfp=0x%p "
			"filerq=0x%p filerq_sz=%d, rf_len=%d\n",
			myname, fp, filerq, filerq_sz, rf_len);

	/* Make sure requester doesn't detach from request */
	filerq->ipcmsg.free_required = 0;
	filerq->nnodes = rf_len;
	filerq->client_fp = fp;
	pna = *caller_pna = (struct per_node *)kmalloc_ssi(
			sizeof(struct per_node) * rf_len, GFP_KERNEL);
	if (!pna)
		return -ENOMEM;

	capture_context((&filerq->context));

	for (nord = 0; nord < rf_len; nord++) {

		rf = &rf_array[nord];

		/* If not data or meta, what are we dealing with here? */
		if (rf->rf_type == 0) {
			printk(KERN_ERR "DVS: Op %s fp %p rf[%d]->rf_type is 0!\n", myname, fp, nord);
		}

		frp = pna[nord].reply = (struct file_reply *)kmalloc_ssi(
				filerp_sz, GFP_KERNEL);
		if (!frp) {
			error = -ENOMEM;
			break;
		}

		frq = pna[nord].request = (struct file_request *)kmalloc_ssi(
				filerq_sz, GFP_KERNEL);
		if (!frq) {
			free_msg(pna[nord].reply);
			frp = pna[nord].reply = NULL;
			error = -ENOMEM;
			break;
		}
		memcpy(frq, filerq, filerq_sz);

		if (frq->request == RQ_IOCTL) {
			if (frq->u.ioctlrq.cmd == DVS_AUGMENTED_BCAST_IOCTL) {
				struct dvs_augmented_ioctl_tunnel *dbi =
					(struct dvs_augmented_ioctl_tunnel *)&frq->u.ioctlrq.data;
				dbi->stripe_index = nord;
			}
		}

		retry_count = 0;
send_multi_async_ipc_file_retry:

		if (frq->request == RQ_OPEN) {
			if (rf->rf_type & RF_TYPE_META)
				node = inode_meta_server(ip, nord);
			else if (rf->rf_type & RF_TYPE_DATA)
				node = inode_data_server(ip, nord);
			pna[nord].node = node;
		} else {
			pna[nord].node = node = rf->remote_node;

			/*
			 * Stuff the handle (possibly revised in retry
			 * scenarios by the call to file_ops_retry() below)
			 * into the request.
			 */
			if (!rf->valid || rf->quiesced) {
				if (rf->quiesced) {
					KDEBUG_QSC(0, "Op %s File %p nord %d FILE_NNODES %d "
							"quiesced nord %d of %d\n", myname, fp, nord,
							FILE_PRIVATE(fp)->data_rf_len, nord, rf_len);
				}
				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;
				frq->file_handle.remote_ref = NULL;
				frq->file_handle.key = 0;
				continue;
			}

			frq->file_handle = rf->file_handle;

			frq->rip = retry_count;
		}

		/* In ro_cache mode notify the server if it is nord 0, that
		 * is where the cache hashtable data is stored for any
		 * particular file
		 */
		if ((frq->request == RQ_OPEN) && (frq->u.openrq.ro_cache_check)) {
			if (nord == 0)
				frq->u.openrq.ro_cache_node = node;
			else
				frq->u.openrq.ro_cache_node = -1;
		} else if ((frq->request == RQ_CLOSE) &&
				(frq->u.closerq.ro_cache_check)) {
			if (nord == 0)
				frq->u.closerq.ro_cache_node = node;
			else
				frq->u.closerq.ro_cache_node = -1;
		}

		/*
		 * If this is an initial open request (not a retry), save the
		 * node in node_orig.  node_orig is used by the failover code
		 * to re-route I/O back to the original nodes as servers come
		 * back online.
		 */
		if ((filerq->request == RQ_OPEN) && (FILE_PRIVATE(fp)->rip != 2))
			rf->remote_node_orig = node;

		/*
		 * If this is an open, or a close with a forced bogus identity,
		 * ensure it gets delivered to the server.  Bogus identities
		 * are set by the failback code to force clients to re-route
		 * I/O back to the original server nodes.  We want close
		 * requests to be allowed to the current servers however for
		 * cleanup purposes, hence this exception.
		 */
		if ((frq->request == RQ_OPEN) || ((frq->request == RQ_CLOSE) &&
					(rf->identity == BOGUS_IDENTITY))) {
			identity = NO_IDENTITY;
		} else {
			identity = rf->identity;
		}

		RESET_FILERQ(frq);
		rval = send_ipc_request_async_stats(
				INODE_ICSB(ip)->stats, node, RQ_FILE, frq, filerq_sz, frp,
				filerp_sz, identity);
		if (rval < 0) {
			/*
			 * Retry for "node down" only.  Everything else causes
			 * the entire open operation to fail.  No retries for
			 * RQ_CLOSE either (node down implies file closed).
			 */
			if ((rval != -EHOSTDOWN && rval != -EQUIESCE)
					|| (frq->request == RQ_CLOSE)){
				int req = frq->request;

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				if ((req == RQ_CLOSE) && (rval == -EHOSTDOWN || rval == -EQUIESCE))
					continue;

				if (node == rf->remote_node) {
					printk(KERN_ERR "DVS: "
							"send_multi_async_ipc_file_retry: "
							"%s: failed async request to node "
							"%s (rval=%d) %s\n", myname,
							SSI_NODE_NAME(node), rval,
							(rval == -EHOSTDOWN) ?
							"node is down" : "");
				}
				error = rval;
				break;
			}
			/*
			 * Delay before retry.
			 */
			retry_count++;

			if (filerq->request == RQ_OPEN) {
				rval = inode_ops_retry(ip, fp->f_path.dentry, myname,
						retry_count, rval, node);
			} else {
				rval = file_ops_retry(fp, myname, rval);
			}
			if (rval < 0) {
				KDEBUG_OFC(0, "DVS: send_multi_async_ipc_file_retry: "
						"%s: file_ops_retry rval=%d for node "
						"%s\n", myname, rval,
						SSI_NODE_NAME(node));

				free_msg(pna[nord].reply);
				pna[nord].reply = NULL;
				free_msg(pna[nord].request);
				pna[nord].request = NULL;

				error = rval;
				break;
			}
			goto send_multi_async_ipc_file_retry;
		}
		if (retry_count) {
			printk(KERN_INFO "DVS: send_multi_async_ipc_file_retry:"
					" %s: retry %d OK, node %s\n", myname,
					retry_count, SSI_NODE_NAME(node));
		}
	}

	/*
	 * Wait for replies from the async IPC's.
	 */
	for (nord = 0; nord < rf_len; nord++) {
		if (!(frq = pna[nord].request) || !(frp = pna[nord].reply)) {
			continue;
		}
		DVS_TRACEL("smaifrW", nord, pna[nord].request,
				pna[nord].reply, 0, 0);

		rval = wait_for_async_request_stats(INODE_ICSB(ip)->stats, frq);

		if (rval < 0) {
			node = pna[nord].node;

			/*
			 * Retry for "node down", ESTALE and EQUIESCE retry only.
			 * Everything else causes the entire operation to fail. 
			 * No retries for RQ_CLOSE either (node down implies
			 * file closed).
			 */
			if ((rval != -EHOSTDOWN && rval != -ESTALE_DVS_RETRY && rval != -EQUIESCE)
					|| (frq->request == RQ_CLOSE)) {
				if ((frq->request == RQ_CLOSE) &&
						(rval == -EHOSTDOWN || rval == -EQUIESCE)) {
					continue;
				}
				printk(KERN_ERR "DVS: "
						"send_multi_async_ipc_file_retry: %s: "
						"failed wait for async IPC to node %s "
						"(rval=%d) %s\n", myname, 
						SSI_NODE_NAME(node), rval,
						(rval == -EHOSTDOWN) ? "node is down" :
						"");
				if (!error) /* Remember 1st error. */
					error = rval;
				continue;
			}
			/*
			 * The async request failed due to "node down".
			 * We now retry synchronously if retry is enabled.
			 * We always retry for EQUIESCE.
			 */
			if (!INODE_ICSB(ip)->retry && rval != -EQUIESCE) {
				KDEBUG_OFC(0, "DVS: send_multi_async_ipc_file_retry: "
						"%s: no retry\n", myname);
				if (!error) /* Remember only the first error. */
					error = -EHOSTDOWN;
				continue;
			}
			KDEBUG_OFC(0, "DVS: send_multi_async_ipc_file_retry:"
					" %s: node %s down, going into synchronous "
					"retry\n", myname, SSI_NODE_NAME(node));
			/*
			 * Hopefully not setting frq->rip is ok here...
			 * If we did, send_ipc_file_retry would reset it
			 * right away anyways...
			 */
			if (rval == -EQUIESCE && frq->request != RQ_OPEN) {
				KDEBUG_QSC(0, "Op %s File %p nord %d returned "
					"EQUIESCE. Calling send_ipc_file_retry\n",
					myname, fp, nord);
				mark_remote_file_quiesced(fp, &rf_array[nord]);
			}
			if ((rval = send_ipc_file_retry(myname,
							fp,
							rf_array,
							rf_len,
							nord,
							frq,
							filerq_sz,
							frp,
							filerp_sz,
							&node) < 0)) {

				KDEBUG_OFC(0, "DVS: send_multi_async_ipc_file_retry: "
						"%s: send_ipc_file_retry rval=%d "
						"for node %s (sync req)\n",
						myname, rval, SSI_NODE_NAME(node));
				if (!error) /* Remember only 1st error*/
					error = rval;
			}
		} else {
			sync_client_sync_update(frp->ipcmsg.jiffies_val,
					frq->ipcmsg.jiffies_val,
					DATA_RF(fp, nord));
		}
	}

	/* only meaningful for single node scenarios */
	*node_used = node;

	return(error);
}

static inline int
async_op_valid(struct async_retry *p, int node)
{
	struct list_head *lp, *tp;
	struct async_retry *cp;

	list_for_each_safe(lp, tp, &alist[node]) {
		cp = list_entry(lp, struct async_retry, list);
		if (cp == p) {
			DVS_TRACE("aov", p, node);
			return 1;
		}
	}
	DVS_TRACE("!aov", p, node);
	return 0;
}

/*
 * The filerq argument is only used when called by dvs_rq_readpages_rp(), as
 * in that case we want to retry a specific request only due to an ESTALE rval.
 */
void __async_op_retry(int node, int shutdown, struct file_request *filerq)
{
   int rval;
   struct async_retry *p;
   struct list_head *lp, *tp;
   int handle_estale = (filerq != NULL);
   unsigned long elapsed_jiffies;

   DVS_TRACEL("aorIN", node, shutdown, current, filerq, 0);

   if (handle_estale)
      rval = -ESTALE_DVS_RETRY;
   else
      rval = -EHOSTDOWN;

   /*
    * Mark the candidates first under lock and we'll come back one by one
    * in the loop below to deal with them.   We mark them to hold them since
    * the below loop drops/reacquires the lock a bunch of times.
    */
   down(&aretrysem[node]);
   list_for_each_safe(lp, tp, &alist[node]) {
      p = list_entry(lp, struct async_retry, list);

      if (handle_estale) {
         if (p->filerq == filerq) {
            /*
             * We know if we're in this routine for the first time or the
             * previous attempts didn't work, so regardless of this one's
             * state, we're going to retry it.
             */
            p->ar_status = AR_Will_Retry;
            break;
         }
      }
      else {
         if (p->ar_status == AR_Default) {
            p->ar_status = AR_Will_Retry;
         }
      }
   }
   up(&aretrysem[node]);

restartlist:
   down(&aretrysem[node]);

   list_for_each_safe(lp, tp, &alist[node]) {
      int	rval = 1;

      p = list_entry(lp, struct async_retry, list);
      if (handle_estale && (p->filerq != filerq)) {
         continue;
      }
      if (!shutdown && (!handle_estale && p->ar_status != AR_Will_Retry)) {
         continue;  /* if we didn't mark it -- it's new -- ignore */
      }

      if (shutdown || !p->filerq->retry || !p->fp) {
         struct inode	*ip;
         struct inode	*grabbed;

         ip = (p->fp) ? file_inode(p->fp) : p->filerq->u.iopagesrq.rq->ip;

         /*
          * We'll remove all the requests for this inode and come
          * around for the next.
          */
         grabbed = igrab(ip);
         up(&aretrysem[node]);

         while (rval) {
            rval = cleanup_reqs(ip, CLUP_Forced);

            if (rval) {
               cond_resched();  /* buy some time */
            }
         }

         if (grabbed) {
            iput(ip);
         }
         if (handle_estale) {
            goto done;
         } else {
            goto restartlist;
         }
      }
      else {
         if (node == p->ar_node) {
            int	new_node;

            /*
             * That's our node and it's down apparently.  Let's retry to
             * another server.
             */
            if ((!identity_valid(p->ar_node, DATA_RF(p->fp, p->ar_nord)->identity) &&
			(p->ar_status < AR_Retried)) || handle_estale) {
               KDEBUG_OFC(0, "DVS: %s: retrying ar 0x%p fp 0x%p node %d estale %d\n",
				__FUNCTION__, p, p->fp, node, handle_estale);
               p->ar_status = AR_Retried;  /* hold it */
               up(&aretrysem[node]);

               rval = file_ops_retry(p->fp, "async_op_retry", rval);

               /*
                * request is still ours since it was in retried state
                */

               if ((rval < 0) && (rval != -EHOSTDOWN)) {
                  goto restartlist;  /* try again? */
               }
               else {
                  if (!DATA_RF(p->fp, p->ar_nord)->valid ||
                        DATA_RF(p->fp, p->ar_nord)->quiesced) {
                     KDEBUG_OFC(0, "%s: nord %d invalid handle - deferring open\n",
					__FUNCTION__, p->ar_nord);
                     rval = deferred_uopen(file_inode(p->fp), p->fp, p->ar_nord);
                  }
               }

               p->filerq->file_handle = DATA_RF(p->fp, p->ar_nord)->file_handle;

               KDEBUG_OFC(0, "DVS: %s: About to send %s RETRY to node %s\n",
				__FUNCTION__, "async_op_retry",
				SSI_NODE_NAME(DATA_RF(p->fp, p->ar_nord)->remote_node));
               new_node = DATA_RF(p->fp, p->ar_nord)->remote_node;
               DVS_TRACEL("aorRsend", p, p->fp, p->filerq, p->ar_node, new_node);

               RESET_FILERQ(p->filerq);
	       elapsed_jiffies = jiffies;
               rval = send_ipc_request_async_stats(
				FILE_ICSB(p->fp)->stats,
				new_node, RQ_FILE, p->filerq,
				p->rqsz, NULL, 0,
				DATA_RF(p->fp, p->ar_nord)->identity);

               if ((rval < 0) && (rval != -EHOSTDOWN)) {
                  printk(KERN_ERR "DVS: %s: error %d during send_async\n",
				__FUNCTION__, rval);
                  p->filerq->retry = 0;
               }
	       /*
	        * The timing logged for this request is a bit misleading as it
		* does not cover the response.
		*/
	       log_request(p->filerq->request, NULL, file_inode(p->fp), p->fp,
			   1, new_node, jiffies - elapsed_jiffies);

               /* exit if we are handling an ESTALE and the send was successful */
               if (handle_estale && rval >= 0) {
                  /*
                   * ar_status may need to be an atomic due to this next check but
                   * this should be OK since above, if the message is already returned
                   * and another thread is in this routine, they'll press ahead once
                   * they've found their message regardless of its status.  We know
                   * they'd set it to AR_Will_Retry while marking candidates but we
                   * could change that back to AR_Default below but they'll already
                   * be on their way to sending again.
                   */
                  if (p->ar_status == AR_Retried) {
                     p->ar_status = AR_Default;
                  }
                  goto done;
               }
               else {
                  p->ar_status = AR_Default;  /* is still claimed via AR_Retried */
                  goto restartlist;
               }
            }
         }
      }
   }
   up(&aretrysem[node]);

done:
   DVS_TRACEL("aorOUT", node, shutdown, current, 0, 0);
}

int async_op_retry(void *data)
{
	int i, node = (int)(long)data;

	if (node != -1) {
		__async_op_retry(node, 0, NULL);
	} else {
		for (i=0; i<ssiproc_max_nodes; i++) {
			__async_op_retry(i, 1, NULL);
		}
	}

	return 0;
}

/* DEPRECATED 06/2014 */
static void remove_oio(struct async_retry *p)
{
	struct outstanding_io *iop, *iop2, **poio;
	struct outstanding_page *opp, *opp2;
	struct page *pagep;
	struct inode_info *iip;
	struct readpage_retry *rr = &p->readpage;

	DVS_TRACE("rmoio", p, p->ar_node);

	iop = rr->op;
	iip = rr->iip;

	down(&iip->oio_sema);
	poio = &iip->oio;
	opp = rr->op->op;
	while (opp) {
		pagep = opp->pagep;
		SetPageError(pagep);
		unlock_page(pagep);
		opp2 = opp;
		opp = opp->next;
		kfree(opp2);
	}

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
	kfree(rr->op);
	list_del(&p->list);
	free_msg(p->filerq);
	kfree(p);
}

/*
 * file_operations
 */

static loff_t ulseek (struct file *fp, loff_t off, int op)
{
	long rval;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode_info *iip = NULL;
	loff_t offset = 0;
	unsigned long elapsed_jiffies;
	int node;

	KDEBUG_OFC(0, "DVS: ulseek: called 0x%p %lld %d\n", fp, off, op);

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: ulseek: called with NULL private_data\n");
		rval = -USIERR_INTERNAL;
		goto ulseek_done;
	}

	iip = (struct inode_info *) file_inode(fp)->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ulseek: no inode info\n");
		return -USIERR_INTERNAL;
	}

	if (FILE_PRIVATE(fp)->nokill_error) {
		rval = -EHOSTDOWN;
		goto ulseek_done;
	}

	/* Only local position is supported */
	if (!META_RF(fp, 0)->use_local_position) {
		printk(KERN_ERR "DVS: ulseek: called and not local position\n");
		rval = -USIERR_INTERNAL;
		goto ulseek_done;
	}

	/* Avoid sending message if possible. Client side caching always needs
	 * to use the local value. */
	if (op != SEEK_END || FILE_PRIVATE(fp)->cache) {
		down_write(&iip->write_sem);
		offset = default_llseek(fp, off, op);
		up_write(&iip->write_sem);
		return offset;
	}

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto ulseek_done;
	}
	filerq->request = RQ_GETEOI;
	filerq->retry = FILE_ICSB(fp)->retry;
	filerq->u.lseekrq.offset = off;
	filerq->u.lseekrq.op = op;

	elapsed_jiffies = jiffies;
	rval = send_ipc_file_retry("ulseek",
					fp,
					FILE_PRIVATE(fp)->meta_rf,
					FILE_PRIVATE(fp)->meta_rf_len,
					0,
					filerq,
					sizeof(struct file_request),
					filerp,
					sizeof(struct file_reply),
					&node);
	if (rval >= 0) {
		log_request(filerq->request, NULL, file_inode(fp), fp,
			    1, node, jiffies - elapsed_jiffies);
	}
	if (rval < 0 || filerp->rval < 0) {
		KDEBUG_OFC(0, "DVS: ulseek: got error from server %ld/%ld\n",
			rval, filerp->rval);
		if (rval == 0)
			rval = filerp->rval;
		goto ulseek_done;
	}

	KDEBUG_OFC(0, "DVS: ulseek: setting pos to %Ld\n",
	           filerp->u.lseekrp.offset + off);

	down_write(&iip->write_sem);
	offset = default_llseek(fp, filerp->u.lseekrp.offset + off, SEEK_SET);
	up_write(&iip->write_sem);

	free_msg(filerq);
	free_msg(filerp);

	return offset;

ulseek_done:
	free_msg(filerq);
	free_msg(filerp);
	return rval;
}

/* block io info - index by block */
struct io_vector {
	int 	nord;
	char	*address;
	size_t	count;
	loff_t	offset;
};

static int build_iovec(struct io_vector *iov, int nblks, int nord, struct usi_iovec *target)
{
	int i, j = 0;

	for (i=0; i < nblks; i++) {
		if (iov[i].nord != nord)
			continue;
		target[j].address = iov[i].address;
		target[j].count = iov[i].count;
		target[j].offset = iov[i].offset;
		KDEBUG_OFC(0, "DVS: build_iovec: nord: %d addr: 0x%p count: %ld "
			"offset: %Ld\n", iov[i].nord, iov[i].address,
			iov[i].count, iov[i].offset);
		j++;
	}

	return(j);
}

static int find_max_length(struct file *fp, size_t size)
{
	int nnodes, n, mmsz;
	long blksize;
	size_t bps, pps, len;

	/* round up and down */
	size += PAGE_SIZE * 2;

	if (FILE_PRIVATE(fp)->data_rf_len > 0)
		nnodes = FILE_PRIVATE(fp)->data_rf_len;
	else
		nnodes = FILE_PRIVATE(fp)->meta_rf_len;

	blksize = FILE_PRIVATE(fp)->blocksize;

	bps = blksize * nnodes;
	pps = bps / PAGE_SIZE;

	n = sizeof(struct usi_iovec) + (pps * sizeof(u64));
	len = 0;
	/*
	 * Maximum transport layer message size
	 */
	mmsz = MAX_MSG_SIZE - sizeof(struct file_request);

	/* Adjust for transport message buffer overflow */
	if (n > mmsz) {
		n = mmsz;
		bps = PAGE_SIZE * 
			((mmsz - sizeof(struct usi_iovec)) / sizeof(u64));
	}

	while (size) {
		mmsz -= n;
		if (mmsz < 0)
			break;
		if (size < bps) {
			len += size;
			size = 0;
		} else {
			len += bps;
			size -= bps;
		}
	}

	KDEBUG_OFC(0, "DVS: find_max_length: %ld\n", len);
	BUG_ON(len == 0);
	return(len);
}

static int get_nord_for_offset (struct file *fp, loff_t off, long blksize)
{
	int nord;

	/*
	 * Use data servers if available, otherwise use metadata servers.
	 * A data server may not be available if, for instance, a readdir
	 * is done on a metadata server.
	 */
	if (FILE_PRIVATE(fp)->data_rf_len > 0)
		nord = off / blksize % FILE_PRIVATE(fp)->data_rf_len;
	else
		nord = off / blksize % FILE_PRIVATE(fp)->meta_rf_len;

	KDEBUG_OFC(0, "DVS: get_nord_for_offset: fp 0x%p of %ld bs %ld nd %d\n", fp,
		   (long)off, blksize, nord);

	return nord;
}

static size_t get_length_for_offset (struct file *fp, size_t size, loff_t off,
				     long blksize)
{
	size_t len;

	len = blksize - (off % blksize);
	if (len > size || FILE_PRIVATE(fp)->atomic)
		len = size;

	return(len);
}

#ifdef WHITEBOX
static void wait_read_rdma_done(void *req, int status, void *addr,
				size_t length)
{
        struct semaphore *rdsema = (struct semaphore *)req;
	up(rdsema);
}
#endif

static ssize_t uread2 (struct file *fp, struct inode *ip, char *buf,
			size_t size, loff_t *offp)
{
	int rval, rsz;
	struct file_request *filerq=NULL;
	struct file_reply *filerp=NULL;
	struct per_node *pna = NULL;
	struct io_vector *iov = NULL;
	int nnodes, blksize, nblks, cv = 0, nord, error, pc;
	loff_t pos;
	size_t length, xfer;
	void *rma_handle = NULL;
	char *obuf = buf;
	loff_t piggyback = 0;
	unsigned long elapsed_jiffies;
#ifdef WHITEBOX
	struct semaphore rdsema;
#endif

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: uread2: called with NULL private_data\n");
		return(-USIERR_INTERNAL);
	}
	KDEBUG_OFC(0, "DVS: uread2: called 0x%p %ld\n", fp, size);
	if (!access_ok(VERIFY_WRITE, buf, size))
		return(-EFAULT);

	if (FILE_PRIVATE(fp)->data_rf_len > 0)
		nnodes = FILE_PRIVATE(fp)->data_rf_len;
	else
		nnodes = FILE_PRIVATE(fp)->meta_rf_len;

	blksize = FILE_PRIVATE(fp)->blocksize;
	pos = *offp;
	nblks = ((size + blksize -1) / blksize) + 2;
	KDEBUG_OFC(0, "DVS: uread2: size %ld nnodes %d, pos %ld, nblks %d, "
		"blksize %d\n", (long)size, nnodes, (long)pos, nblks, blksize);
	pna = (struct per_node *)kmalloc_ssi(sizeof(struct per_node) * nnodes, GFP_KERNEL);
	iov = (struct io_vector *)kmalloc_ssi(sizeof(struct io_vector) * nblks, GFP_KERNEL);
	if (!pna || !iov) {
		rval = -ENOMEM;
		goto out;
	}
	length = size;

	while (length) {
		nord = get_nord_for_offset(fp, pos, blksize);

		if (!DATA_RF(fp, nord)->valid || DATA_RF(fp, nord)->quiesced) {
			rval = deferred_uopen(ip, fp, nord);
			if (rval < 0)
				goto done;
		}
		xfer = get_length_for_offset(fp, length, pos, blksize);

		pna[nord].count++;
		pna[nord].length += xfer;
		if (pna[nord].length > piggyback)
			piggyback = pna[nord].length;

		iov[cv].offset = pos;
		iov[cv].nord = nord;
		iov[cv].address = obuf;
		iov[cv].count = xfer;

		obuf += xfer;
		pos += xfer;
		length -= xfer;
		cv++;
	}

	if (piggyback > MAX_FILE_BUFFER) {
		printk(KERN_ERR "DVS: uread2: max file buffer exceeded\n");
		rval = -EINVAL;
		goto done;
	} else if ((piggyback > MAX_FILE_PAYLOAD) || (fp->f_flags & O_DIRECT)) {
		rma_handle = map_ipc_memory(buf, size, READ);
		if (IS_ERR(rma_handle)) {
			rval = PTR_ERR(rma_handle);
			rma_handle = NULL;
			goto done;
		}
		if (rma_handle == NULL)  {
			KDEBUG_OFC(0, "DVS: uread2: map_ipc_memory failed\n");
			rval = -EFAULT;
			goto done;
		}
		pc = count_ipc_memory(rma_handle);
		piggyback = 0;
#ifdef WHITEBOX
		sema_init(&rdsema, 0);
		register_ipc_read_complete(rma_handle, wait_read_rdma_done, &rdsema);
#endif
	} else {
		rma_handle = NULL;
		pc = 0;
	}

	/*
	 * build messages and send asynchronously
	 */
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].count == 0)
			continue;
                KDEBUG_OFC(0, "DVS: %s: nord %d count %d\n", __FUNCTION__, nord, pna[nord].count);
		rsz = sizeof(struct file_request) +
		      (sizeof(struct usi_iovec) * pna[nord].count);
		if (rma_handle)
			rsz += (pc * sizeof(u64));
		filerq = pna[nord].request = kmalloc_ssi(rsz, GFP_KERNEL);
		filerp = pna[nord].reply = kmalloc_ssi(sizeof(struct file_reply) + piggyback, GFP_KERNEL);
		if (!filerq || !filerp) {
			rval = -ENOMEM;
			goto done;
		}
		filerq->request = RQ_PARALLEL_READ;
		filerq->retry = INODE_ICSB(ip)->retry;
		filerq->file_handle = DATA_RF(fp,nord)->file_handle;
		filerq->client_fp = fp;
		filerq->u.ioprq.rma_handle = rma_handle;
		filerq->u.ioprq.base = buf;
		filerq->u.ioprq.length = size;
		if (rma_handle)
			build_rma_list(rma_handle, (u64 *)(&filerq->u.ioprq.iov + pna[nord].count));
		capture_context((&filerq->context));
		filerq->u.ioprq.count = build_iovec(iov, cv, nord, filerq->u.ioprq.iov);

		DVS_TRACEL("urd2", nord, inode_sso(file_inode(fp)),
				DATA_RF(fp, nord)->remote_node,
				FILE_ICSB(fp)->data_servers_len, 0);
		KDEBUG_OFC(0, "DVS: %s: %d:%d:%d:%d\n",
			   __FUNCTION__, nord, inode_sso(file_inode(fp)),
			   DATA_RF(fp, nord)->remote_node,
			   FILE_ICSB(fp)->data_servers_len);
		elapsed_jiffies = jiffies;
		rval = send_ipc_request_async_stats(
			INODE_ICSB(ip)->stats, DATA_RF(fp,nord)->remote_node,
			RQ_FILE, filerq, rsz, filerp,
			sizeof(struct file_reply) + piggyback, DATA_RF(fp, nord)->identity);
		if (rval >= 0)
			log_request(filerq->request, NULL, ip, fp, 1,
				    DATA_RF(fp,nord)->remote_node,
				    jiffies - elapsed_jiffies);
		if (rval < 0) {
			if (rval != -EHOSTDOWN) {
				printk(KERN_ERR "DVS: uread2: ipc call failed "
				       "%d\n", rval);
			}
			goto done;
		}
		pna[nord].sent = 1;
	}

	/*
	 * wait for messages
	 */
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].count == 0)
			continue;
		filerq = pna[nord].request;
		KDEBUG_OFC(0, "DVS: uread2: waiting for reply from node %s\n",
			SSI_NODE_NAME(DATA_RF(fp,nord)->remote_node));
		rval = wait_for_async_request_stats(INODE_ICSB(ip)->stats, filerq);
		KDEBUG_OFC(0, "DVS: uread2: got reply from node %s\n",
			SSI_NODE_NAME(DATA_RF(fp,nord)->remote_node));
		pna[nord].sent = 0;
		if (rval < 0) {
			if ((rval != -EINTR) && (rval != -ENOSPC) &&
			    (rval != -EHOSTDOWN) && (rval != -ESTALE_DVS_RETRY) &&
			    (rval != -EQUIESCE)) {
				printk(KERN_ERR "DVS: uread2: wait ipc call "
					"failed %d\n", rval);
			}
			if (rval == -EQUIESCE)
				mark_remote_file_quiesced(fp, DATA_RF(fp, nord));
			goto done;
		}
		sync_client_sync_update(pna[nord].reply->ipcmsg.jiffies_val,
		                        filerq->ipcmsg.jiffies_val,
		                        DATA_RF(fp, nord));
	}

	error = 0;
	xfer = 0;
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].count == 0)
			continue;
		filerp = pna[nord].reply;
		if (filerp->rval < 0) {
			KDEBUG_OFC(0, "DVS: uread2: got error from server %ld\n",
				 filerp->rval);
			/* report first error */
			error = filerp->rval;
			break;
		} else if (piggyback) {
			char *dp = filerp->u.readrp.data;
			int i, len, tlen;

			KDEBUG_OFC(0, "DVS: uread2: piggyback total %ld\n",
				filerp->rval);
			xfer += filerp->rval;
			tlen = filerp->rval;

			for (i=0; i<pna[nord].count; i++) {
				len = pna[nord].request->u.ioprq.iov[i].count;
				if (len > tlen)
					len = tlen;
				KDEBUG_OFC(0, "DVS: uread2: read piggyback: 0x%p %d\n",
					pna[nord].request->u.ioprq.iov[i].
								address, len);

				if (len) {
					if (copy_to_user(pna[nord].request->u.ioprq.iov[i].address,
						dp, len)) {
							error = -EFAULT;
							break;
					}
					dp += len;
					tlen -= len;
				}

				if (tlen == 0) {
					/*
					 * The read may have been short because of a hole,
					 * and so needs to be padded
					 */
					if (len < pna[nord].request->u.ioprq.iov[i].count) {
						int  pad = pna[nord].request->u.ioprq.iov[i].count - len;
						char *mp = pna[nord].request->u.ioprq.iov[i].address + len;
						loff_t gpos = compute_file_size (ip,
							nnodes,
							FILE_PRIVATE(fp)->blocksize,
							pna[nord].request->u.ioprq.iov[i].offset + len + 1,
							nord);

						if (ip->i_size < gpos)
							continue;

						if ((ip->i_size - gpos) < pad)
							pad = ip->i_size - gpos;

						KDEBUG_OFC(0, "DVS: uread2: zero fill "
							"%d %d %d %Ld %Ld 0x%p\n",
							nord, pad, len,
							ip->i_size, gpos, mp);
						if (clear_user(mp, pad)) {
							error = -EFAULT;
							break;
						}
						xfer += pad;
					}
				}
			}
		} else {
			int i, len, tlen;

			xfer += filerp->rval;
			tlen = filerp->rval;

			for (i=0; i<pna[nord].count; i++) {
				len = pna[nord].request->u.ioprq.iov[i].count;
				if (len > tlen)
					len = tlen;

				tlen -= len;
#ifdef WHITEBOX
				if (len > 0) {
					down(&rdsema);
				}
#endif

				if (tlen == 0) {
					/*
					 * The read may have been short because of a hole,
					 * and so needs to be padded
					 */
					if (len < pna[nord].request->u.ioprq.iov[i].count) {
						int  pad = pna[nord].request->u.ioprq.iov[i].count - len;
						char *mp = pna[nord].request->u.ioprq.iov[i].address + len;
						loff_t gpos = compute_file_size (ip,
							nnodes,
							FILE_PRIVATE(fp)->blocksize,
							pna[nord].request->u.ioprq.iov[i].offset + len + 1,
							nord);

						if (ip->i_size < gpos)
							continue;

						if ((ip->i_size - gpos) < pad)
							pad = ip->i_size - gpos;

						KDEBUG_OFC(0, "DVS: uread2: zero fill "
							"%d %d 0x%p\n", nord,
							pad, mp);
						if (clear_user(mp, pad)) {
							error = -EFAULT;
							break;
						}
						xfer += pad;
					}
				}
			}
			KDEBUG_OFC(0, "DVS: uread2: delivered %ld bytes\n",
				filerp->rval);
		}
		if ( nord == 0 ) {
			/* don't update_inode(), just take a few interesting things... */
			ip->i_mtime = filerp->u.readrp.inode_copy.i_mtime;
			ip->i_atime = filerp->u.readrp.inode_copy.i_atime;
			ip->i_ctime = filerp->u.readrp.inode_copy.i_ctime;
		}

	}

	if (error) {
		KDEBUG_OFC(0, "DVS: uread2: returning error: %d\n", error);
		rval = error;
	} else {
		KDEBUG_OFC(0, "DVS: uread2: returning total of %ld\n", (long)xfer);
		*offp += xfer;
		rval = xfer;

		/* increment DVS read byte counters */
		dvsproc_stat_update(INODE_ICSB(ip)->stats, DVSPROC_STAT_IO,
				    RQ_PARALLEL_READ, xfer);
	}

done:
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].request) {
			if (pna[nord].sent)
				wait_for_async_request_stats(INODE_ICSB(ip)->stats,
							     pna[nord].request);
			free_msg(pna[nord].request);
		}
		if (pna[nord].reply)
			free_msg(pna[nord].reply);
	}
	unmap_ipc_memory(buf, rma_handle);
out:
	kfree(pna);
	kfree(iov);
	return((ssize_t)rval);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
static ssize_t uread(struct kiocb *iocb, const struct iovec *iov,
		     unsigned long nr_segs, loff_t pos)
#else
static ssize_t uread(struct kiocb *iocb, struct iov_iter *to)
#endif
{
	/* Ignore the value of pos, use *offp below */
	int i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
	size_t size, count = 0;
#else
	size_t size;
	unsigned long nr_segs = to->nr_segs;
	loff_t pos = iocb->ki_pos;
	const struct bio_vec *bvec = to->bvec;
	const struct iovec *iov = to->iov;
	char *page_buf;
#endif
	struct file *fp = iocb->ki_filp;
	char *buf;
	loff_t *offp = &iocb->ki_pos;		/* pos == *offp */
	ssize_t mxlen, rval = 0, tval = 0;
	size_t init_size;
	struct inode *ip = file_inode(fp);
	__kernel_size_t vec_len = 0;


	if (FILE_PRIVATE(fp)->nokill_error)
		return -EHOSTDOWN;

	if (FILE_PRIVATE(fp)->cache_read_sz && (nr_segs == 1)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
		vec_len = iov[0].iov_len;
#else
		if (to->type == ITER_BVEC) {
			vec_len = bvec[0].bv_len;
		} else {
			vec_len = iov[0].iov_len;
		}
#endif
		KDEBUG_OFC(0, "DVS: uread: ro_cache nr_segs 1 vec_len %ld\n", vec_len);
	}

	/*
	 * Only regular files not flagged with O_DIRECT can be read from
	 * the page cache when caching is enabled, all other reads are pushed
	 * to the server. If CACHE_READ_SZ is enabled do not allow page cache
	 * reads for segments larger than size specified as readpages can be
	 * inefficient in that case.
	 */
	if (S_ISREG(ip->i_mode) && FILE_PRIVATE(fp)->cache &&
	    !(fp->f_flags & O_DIRECT) &&
	     (!FILE_PRIVATE(fp)->cache_read_sz || (vec_len < FILE_PRIVATE(fp)->cache_read_sz))) {
		/*
		 * Don't allow pages to be created for a cached-read which are
		 * beyond the end of the file.  readpage(s) will error them
		 * out otherwise and EIO can be seen.
		 */
		if (*offp >= ip->i_size) {
			return 0;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
		KDEBUG_OFC(0, "DVS: uread: generic_file_aio_read for 0x%p\n", fp);
		tval = generic_file_aio_read(iocb, iov, nr_segs, pos);
		KDEBUG_OFC(0, "DVS: uread: generic_file_aio_read returns %ld\n", tval);
#else
		KDEBUG_OFC(0, "DVS: uread: generic_file_read_iter for 0x%p\n", fp);
		tval = generic_file_read_iter(iocb, to);
		KDEBUG_OFC(0, "DVS: uread: generic_file_read_iter returns %ld\n", tval);
#endif
		goto done;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
	rval = generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);

	if (rval)
		return rval;
#endif

	for (i = 0; i < nr_segs; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
		buf = (char *)iov[i].iov_base;
		size = iov[i].iov_len;
#else
		if (to->type == ITER_BVEC) {
			page_buf = (char *)kmap_atomic(bvec[i].bv_page);
			buf = page_buf + bvec[i].bv_offset;
			size = bvec[i].bv_len;
		} else {
			buf = (char *)iov[i].iov_base;
			size = iov[i].iov_len;
		}

#endif
		init_size = size;

ureadretry:
		mxlen = find_max_length(fp, size);
		if (size < mxlen)
			mxlen = size;

		while (size) {
			if (size < mxlen)
				mxlen = size;
			KDEBUG_OFC(0, "DVS: uread: 0x%p %ld %ld %Ld \n", buf, mxlen,
				   size, *offp);
			rval = uread2(fp, ip, buf, mxlen, offp);
			if (rval < (ssize_t)0) {
				/* retry for "node down" and ESTALE retry and EQUIESCE only */
				if (rval != (ssize_t)-EHOSTDOWN &&
					rval != (ssize_t)-ESTALE_DVS_RETRY &&
					rval != (ssize_t)-EQUIESCE) {
					tval = rval;
					break;
				}
				rval = file_ops_retry(fp, "uread", rval);
				if (rval < (ssize_t)0) {
					tval = rval;
					break;
				}
				size = init_size;
				goto ureadretry;
			}
			tval += rval;
			size -= rval;
			buf  += rval;
			if (rval < mxlen)
				break;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,9)
		if (to->type == ITER_BVEC) {
			kunmap_atomic(page_buf);
		}
#endif

		if (rval < (ssize_t)0) {
			if (!tval)
				tval = rval;
			break;
		}
	}

done:
	if (tval > 0) {
		/* 
		 * Accumulate user read statistics. These are placed here,
		 * because we want to see all of the user reads accounted for.
		 * Any driver read() or aio_read() call will end up here, and
		 * tval will be the total number of bytes actually read. We add
		 * this to the original offset position 'pos' to get the maximum
		 * offset.
		 */
		dvsproc_stat_update(INODE_ICSB(ip)->stats,
				    DVSPROC_STAT_CLIENT_LEN,
				    VFS_OP_AIO_READ, tval);
		dvsproc_stat_update(INODE_ICSB(ip)->stats,
				    DVSPROC_STAT_CLIENT_OFF,
				    VFS_OP_AIO_READ, pos+tval);
	}
	return(tval);
}

static ssize_t uwrite2 (struct file *fp, struct inode *ip, const char *buf, size_t size, loff_t *offp)
{
	int rval = 0, rsz;
	struct file_request *filerq=NULL;
	struct file_reply *filerp=NULL;
	struct per_node *pna = NULL;
	struct io_vector *iov = NULL;
	struct inode_info *iip;
	int nnodes, blksize, nblks, cv = 0, nord, error, pc;
	loff_t pos;
	size_t length, xfer;
	void *rma_handle = NULL;
	char *obuf = (char *)buf;
	loff_t piggyback = 0;
	unsigned long limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
	unsigned long elapsed_jiffies;

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: %s: no inode info\n", __func__);
		return (ssize_t)-USIERR_INTERNAL;
	}

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: uwrite2: called with NULL "
			"private_data\n");
		return(-USIERR_INTERNAL);
	}
	KDEBUG_OFC(0, "DVS: uwrite2: called 0x%p %ld\n", fp, size);
	if (!access_ok(VERIFY_READ, buf, size))
		return(-EFAULT);

	if (FILE_PRIVATE(fp)->data_rf_len > 0)
		nnodes = FILE_PRIVATE(fp)->data_rf_len;
	else
		nnodes = FILE_PRIVATE(fp)->meta_rf_len;

	blksize = FILE_PRIVATE(fp)->blocksize;
	pos = *offp;
	KDEBUG_OFC(0, "DVS: uwrite2: nnodes %d, blksize %d, pos %ld\n",
		nnodes, blksize, (long)pos);
	nblks = ((size + blksize -1) / blksize) + 2;
	KDEBUG_OFC(0, "DVS: uwrite2: nblks %d\n", nblks);
	pna = (struct per_node *)kmalloc_ssi(sizeof(struct per_node) * nnodes, GFP_KERNEL);
	iov = (struct io_vector *)kmalloc_ssi(sizeof(struct io_vector) * nblks, GFP_KERNEL);
	if (!pna || !iov) {
		rval = -ENOMEM;
		goto out;
	}

	length = size;
	if (!S_ISBLK(ip->i_mode) && limit != RLIM_INFINITY) {
		if (pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			rval = -EFBIG;
			goto out;
		}
		if (length > limit - (u32)pos)
			length = limit - (u32)pos;
	}

	while (length) {
		nord = get_nord_for_offset(fp, pos, blksize);

		if (!DATA_RF(fp, nord)->valid || DATA_RF(fp, nord)->quiesced) {
			rval = deferred_uopen(ip, fp, nord);
			if (rval < 0)
				goto done;
		}
		xfer = get_length_for_offset(fp, length, pos, blksize);

		pna[nord].count++;
		pna[nord].length += xfer;
		if (pna[nord].length > piggyback)
			piggyback = pna[nord].length;

		iov[cv].offset = pos;
		iov[cv].nord = nord;
		iov[cv].address = obuf;
		iov[cv].count = xfer;

		obuf += xfer;
		pos += xfer;
		length -= xfer;
		cv++;
	}

	KDEBUG_OFC(0, "DVS: %s: pna[0].count %d\n", __FUNCTION__, pna[0].count);

	if (INODE_ICSB(ip)->parallel_write) {
		iip->inode_lock_holder = 0;
		mutex_unlock(&ip->i_mutex);
	}

	if (piggyback > MAX_FILE_BUFFER) {
		printk(KERN_ERR "DVS: uwrite2: max file buffer exceeded\n");
		rval = -EINVAL;
		goto done;
	} else if ((piggyback > MAX_FILE_PAYLOAD) || (fp->f_flags & O_DIRECT)) {
		rma_handle = map_ipc_memory((char *)buf, size, WRITE);
		if (IS_ERR(rma_handle)) {
			rval = PTR_ERR(rma_handle);
			rma_handle = NULL;
			goto done;
		}
		if (rma_handle == NULL)  {
			KDEBUG_OFC(0, "DVS: uwrite2: map_ipc_memory failed\n");
			rval = -EFAULT;
			goto done;
		}
		pc = count_ipc_memory(rma_handle);
		piggyback = 0;
	} else {
		rma_handle = NULL;
		pc = 0;
	}

	KDEBUG_OFC(0, "DVS: %s: nnodes %d pna[0].count %d\n", __FUNCTION__, nnodes, pna[0].count);

	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].count == 0)
			continue;

                KDEBUG_OFC(0, "DVS: %s: nord %d count %d\n", __FUNCTION__, nord, pna[nord].count);

		rsz = sizeof(struct file_request) +
		      (sizeof(struct usi_iovec) * pna[nord].count);
		if (rma_handle) {
			KDEBUG_OFC(0, "DVS: %s: rsz %d count %d pc %d\n",
				__FUNCTION__, rsz, pna[nord].count, pc);
	       		rsz += (pc * sizeof(u64));
		} else {
			KDEBUG_OFC(0, "DVS: %s: rsz %d count %d piggyback %Ld\n",
				__FUNCTION__, rsz, pna[nord].count, piggyback);
	       		rsz += piggyback;
		}

		if (rsz > 128 * 1024) {
			// Kmem allocation limit - just return an error
			KDEBUG_OFC(0, "DVS: %s: attempt to allocate %d bytes from kmem - returning ENXIO\n", __FUNCTION__, rsz);
			rval = -ENXIO;
			goto done;
		}

		filerq = pna[nord].request = kmalloc_ssi(rsz, GFP_KERNEL);
		filerp = pna[nord].reply = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
		if (!filerq || !filerp) {
			rval = -ENOMEM;
			goto done;
		}
		filerq->request = RQ_PARALLEL_WRITE;
		filerq->retry = INODE_ICSB(ip)->retry;
		filerq->file_handle = DATA_RF(fp,nord)->file_handle;
		filerq->u.ioprq.rma_handle = rma_handle;
		filerq->u.ioprq.base = (void *)buf;
		filerq->u.ioprq.length = size;
		filerq->u.ioprq.datasync = FILE_PRIVATE(fp)->datasync;
		filerq->u.ioprq.count = build_iovec(iov, cv, nord, filerq->u.ioprq.iov);
		filerq->client_fp = fp;
		if (rma_handle) {
			build_rma_list(rma_handle, (u64 *)(&filerq->u.ioprq.iov + pna[nord].count));
		} else {
			char *dp = (char *)(&filerq->u.ioprq.iov + pna[nord].count);
			int i, len;

			for (i=0; i<pna[nord].count; i++) {
				len = pna[nord].request->u.ioprq.iov[i].count;
				KDEBUG_OFC(0, "DVS: uwrite2: write piggyback: 0x%p %d\n",
					pna[nord].request->u.ioprq.iov[i].address, len);
				if (copy_from_user(dp, pna[nord].request->u.ioprq.iov[i].address,
					len)) {
						rval = -EFAULT;
						goto done;
				}
				dp += len;
			}
		}

		capture_context((&filerq->context));
		DVS_TRACEL("uwr2",  nord, inode_sso(file_inode(fp)),
				DATA_RF(fp, nord)->remote_node,
				FILE_ICSB(fp)->data_servers_len, 0);
		KDEBUG_OFC(0, "DVS: %s: %d:%d:%d:%d\n",
			   __FUNCTION__, nord, inode_sso(file_inode(fp)),
			   DATA_RF(fp, nord)->remote_node,
			   FILE_ICSB(fp)->data_servers_len);
		elapsed_jiffies = jiffies;
		rval = send_ipc_request_async_stats(
			INODE_ICSB(ip)->stats, DATA_RF(fp, nord)->remote_node,
			RQ_FILE, filerq, rsz, filerp, sizeof(struct file_reply),
			DATA_RF(fp,nord)->identity);
		if (rval >= 0)
			log_request(filerq->request, NULL, ip, fp, 1,
				    DATA_RF(fp, nord)->remote_node,
				    jiffies - elapsed_jiffies);
		if (rval < 0) {
			if (rval != -EHOSTDOWN) {
				printk(KERN_ERR "DVS: uwrite2: ipc call failed"
				       " %d\n", rval);
			}
			goto done;
		}
		pna[nord].sent = 1;
	}

	/*
	 * wait for messages
	 */
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].count == 0)
			continue;
		filerq = pna[nord].request;
		KDEBUG_OFC(0, "DVS: uwrite2: waiting for reply from node %s\n",
			SSI_NODE_NAME(DATA_RF(fp,nord)->remote_node));
		rval = wait_for_async_request_stats(INODE_ICSB(ip)->stats, filerq);
		KDEBUG_OFC(0, "DVS: uwrite2: got reply from node %s\n",
			SSI_NODE_NAME(DATA_RF(fp,nord)->remote_node));
		pna[nord].sent = 0;
		if (rval < 0) {
			if ((rval != -EINTR) && (rval != -ENOSPC) &&
			    (rval != -EHOSTDOWN) && (rval != -ESTALE_DVS_RETRY) &&
			    (rval != -EQUIESCE)) {
				printk(KERN_ERR "DVS: uwrite2: wait ipc call "
					"failed %d\n", rval);
			}

			if (rval == -EQUIESCE) {
				mark_remote_file_quiesced(fp, DATA_RF(fp, nord));
			}

			goto done;
		}
	}

	error = 0;
	xfer = 0;
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].count == 0)
			continue;
		filerp = pna[nord].reply;
		if (filerp->rval < 0) {
			KDEBUG_OFC(0, "DVS: uwrite2: got error from server %ld\n",
				filerp->rval);
			/* report first error */
			if (error == 0)
				error = filerp->rval;
		} else {
			KDEBUG_OFC(0, "DVS: uwrite2: delivered %ld bytes\n",
				filerp->rval);
			sync_client_data_written(DATA_RF(fp, nord));
			xfer += filerp->rval;

			if ( nord == 0 ) {
				if (iip->inode_lock_holder != current->pid) {
					mutex_lock(&ip->i_mutex);
					iip->inode_lock_holder = current->pid;
				}

				/* don't update_inode(), just take a few interesting things... */
				dvs_update_timespec(&ip->i_mtime,
				                    &filerp->u.writerp.inode_copy.i_mtime);
				dvs_update_timespec(&ip->i_atime,
				                    &filerp->u.writerp.inode_copy.i_atime);
				dvs_update_timespec(&ip->i_ctime,
				                    &filerp->u.writerp.inode_copy.i_ctime);
			}
		}
	}

	if (error) {
		if (error != -ENOSPC && error != -EDQUOT) {
			KDEBUG_OFC(0, "DVS: uwrite2: returning error: %d\n", error);
		}
		rval = error;
	} else {
		KDEBUG_OFC(0, "DVS: uwrite2: returning total of %ld\n", (long)xfer);
		*offp += xfer;
		rval = xfer;

		/* increment DVS write byte counters */
		dvsproc_stat_update(INODE_ICSB(ip)->stats, DVSPROC_STAT_IO,
				    RQ_PARALLEL_WRITE, xfer);
	}

done:
	for (nord = 0; nord < nnodes; nord++) {
		if (pna[nord].request) {
			if (pna[nord].sent &&
			    (wait_for_async_request_stats(INODE_ICSB(ip)->stats,
							  pna[nord].request)
			     == 0))
				if (pna[nord].reply && pna[nord].reply->rval >= 0)
					sync_client_data_written(DATA_RF(fp, nord));
			free_msg(pna[nord].request);
		}
		if (pna[nord].reply)
			free_msg(pna[nord].reply);
	}
	unmap_ipc_memory((char *)buf, rma_handle);

	if (iip->inode_lock_holder != current->pid) {
		mutex_lock(&ip->i_mutex);
		iip->inode_lock_holder = current->pid;
	}

out:
	kfree(pna);
	kfree(iov);
	return((ssize_t)rval);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
static ssize_t uwrite(struct kiocb *iocb, const struct iovec *iov,
		      unsigned long nr_segs, loff_t pos)
#else
static ssize_t uwrite(struct kiocb *iocb, struct iov_iter *from)
#endif
{
	/* Ignore the value of pos, use *offp below */
	int i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
	size_t size, count = 0;
#else
	size_t size;
	unsigned long nr_segs = from->nr_segs;
	loff_t pos = iocb->ki_pos;
	const struct bio_vec *bvec = from->bvec;
	const struct iovec *iov = from->iov;
	char *page_buf;
#endif
	struct file *fp = iocb->ki_filp;
	loff_t *offp = &iocb->ki_pos;		/* pos == *offp */
	char *buf;
	ssize_t mxlen, rval = 0, tval = 0;
	loff_t off, off2;
	struct inode *ip = file_inode(fp);
	struct inode_info *iip;

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: uwrite: no inode info\n");
		return((ssize_t)-USIERR_INTERNAL);
	}
	
	if (FILE_PRIVATE(fp)->nokill_error)
		return((ssize_t)-EHOSTDOWN);

	/*
	 * Regular files not flagged O_DIRECT can write to the page cache.
	 * All other writes are pushed to the server.
	 */
	if (S_ISREG(ip->i_mode) && FILE_PRIVATE(fp)->cache &&
	    !(fp->f_flags & O_DIRECT)) {
		down(&FILE_PRIVATE(fp)->write_sema);
		FILE_PRIVATE(fp)->write = 1;
		up(&FILE_PRIVATE(fp)->write_sema);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
		KDEBUG_OFC(0, "DVS: %s: generic_file_aio_write for 0x%p\n",
			__FUNCTION__, fp);
		rval = generic_file_aio_write(iocb, iov, nr_segs, pos);
		KDEBUG_OFC(0, "DVS: uread: generic_file_aio_write returns %ld\n", rval);
#else
		KDEBUG_OFC(0, "DVS: %s: generic_file_write_iter for 0x%p\n",
			__FUNCTION__, fp);
		rval = generic_file_write_iter(iocb, from);
		KDEBUG_OFC(0, "DVS: uread: generic_file_write_iter returns %ld\n", rval);
#endif

		down(&FILE_PRIVATE(fp)->write_sema);
		FILE_PRIVATE(fp)->write = 0;
		up(&FILE_PRIVATE(fp)->write_sema);

		return rval;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
	rval = generic_segment_checks(iov, &nr_segs, &count, VERIFY_READ);
	if (rval) {
		return rval;
	}
#else
	rval = generic_write_checks(iocb, from);
	if (rval <= 0) {
		return rval;
	}
#endif

	down(&FILE_PRIVATE(fp)->write_sema);
	FILE_PRIVATE(fp)->write = 1;
	up(&FILE_PRIVATE(fp)->write_sema);
	/* Serialize access to the mutex to avoid inherent mutex unfairness */
	down_write(&iip->write_sem); 
	mutex_lock(&ip->i_mutex);
	up_write(&iip->write_sem); 

	iip->inode_lock_holder = current->pid;

	/* The backend file system will have final say on position for files
	   opened with O_APPEND. We make a best guess in case of a striped file */
	if (fp->f_flags & O_APPEND) {
		off = ip->i_size;
	} else {
		off = *offp;
	}

	for (i = 0; i < nr_segs; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
		buf = (char *)iov[i].iov_base;
		size = iov[i].iov_len;
#else
		if ( from->type == ITER_BVEC) {
			page_buf = (char *)kmap_atomic(bvec[i].bv_page);
			buf = page_buf + bvec[i].bv_offset;
			size = bvec[i].bv_len;
		} else {
			buf = (char *)iov[i].iov_base;
			size = iov[i].iov_len;
		}
#endif

uwriteretry:
		mxlen = find_max_length(fp, size);
		if (size < mxlen)
			mxlen = size;

		while (size) {
			if (size < mxlen)
				mxlen = size;
			off2 = off;

			/* push to the server */
			KDEBUG_OFC(0, "DVS: uwrite: 0x%p %ld %ld %ld %ld %Ld %Ld\n",
				   buf, mxlen, size, rval, tval, off,
				   fp->f_pos);
			rval = uwrite2(fp, ip, buf, mxlen, &off);
			if (rval < (ssize_t)0) {
				/* retry for "node down" only */
				if (rval != (ssize_t)-EHOSTDOWN &&
					rval != (ssize_t)-ESTALE_DVS_RETRY &&
					rval != (ssize_t)-EQUIESCE)
					break;
				if ((rval = file_ops_retry(fp, "uwrite", rval)) < 0) {
					break;
				}
				off = off2;	/* fix up offset for retry */
				goto uwriteretry;
			}

			KDEBUG_OFC(0, "DVS: uwrite: done: %ld %ld %lld %lld\n",
				   (long)rval, (long)rval, off, off2 );

			tval += rval;
			size -= rval;
			buf  += rval;
			if (rval < mxlen)
				break;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,9)
		if ( from->type == ITER_BVEC) {
			kunmap_atomic(page_buf);
		}
#endif
		if (off > ip->i_size) {
			ip->i_size = off;
			ip->i_blocks = compute_file_blocks(ip);
		}
		if (rval < (ssize_t)0) {
			if (!tval)
				tval = rval;
			break;
		}
		*offp = off;
	}

	iip->inode_lock_holder = 0;
	down(&FILE_PRIVATE(fp)->write_sema);
	FILE_PRIVATE(fp)->write = 0;
	up(&FILE_PRIVATE(fp)->write_sema);
	mutex_unlock(&ip->i_mutex);

	if (tval > 0) {
		/* 
		 * Accumulate user write statistics. These are placed here,
		 * because we want to see all of the user writes accounted for.
		 * Any driver write() or aio_write() call will end up here, and
		 * tval will be the total number of bytes actually written. We
		 * add this to the original offset position 'pos' to get the
		 * maximum offset.
		 */
		dvsproc_stat_update(INODE_ICSB(ip)->stats,
				    DVSPROC_STAT_CLIENT_LEN,
				    VFS_OP_AIO_WRITE, tval);
		dvsproc_stat_update(INODE_ICSB(ip)->stats,
				    DVSPROC_STAT_CLIENT_OFF,
				    VFS_OP_AIO_WRITE, pos+tval);
	}
	return(tval);
}

/*
 * WARNING:
 * This structure is asumed to match ALL of the callback structures defined
 * in readdir.c.  Only the count value is actually used.
 */
struct getdents_callback {
	void * current_dir;
	void * previous;
	int count;
	int error;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
static int ureaddir (struct file *fp, void *dirent, filldir_t filldir)
#else
static int ureaddir (struct file *fp, struct dir_context *ctx)
#endif
{
	int rval, node;
	struct file_request *filerq=NULL;
	struct file_reply *filerp=NULL;
	unsigned long elapsed_jiffies;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	struct getdents_callback *info = dirent;
#endif

	int max = MAX_FILE_PAYLOAD + sizeof(struct file_reply);
	struct inode *ip = file_inode(fp);
	struct inode_info *iip;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	KDEBUG_OFC(0, "DVS: ureaddir: called %d\n", info->count);
#else
	KDEBUG_OFC(0, "DVS: ureaddir: called %ld\n", (long int) ctx->pos);
#endif

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: ureaddir: called with NULL "
			"private_data\n");
		return -USIERR_INTERNAL;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ureaddir: no inode info\n");
		return -USIERR_INTERNAL;
	}

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	if (!filerq) {
		return -ENOMEM;
	}

	iip->inode_lock_holder = current->pid;
	filerq->request = RQ_READDIR;
	filerq->retry = INODE_ICSB(ip)->retry;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	if (info->count > max)
		filerq->u.readdirrq.count = max;
	else
		filerq->u.readdirrq.count = info->count;
#else
	filerq->u.readdirrq.count = max;
#endif

	if (META_RF(fp, 0)->use_local_position) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
		filerq->u.readdirrq.offset = fp->f_pos;
#else
		filerq->u.readdirrq.offset = ctx->pos;
#endif
	} else {
		filerq->u.readdirrq.offset = -1;
	}
	filerp = kmalloc_ssi(sizeof(struct file_reply) +
			     filerq->u.readdirrq.count, GFP_KERNEL);
	if (!filerp) {
		rval = -ENOMEM;
		goto done;
	}
	elapsed_jiffies = jiffies;
	rval = send_ipc_file_retry("ureaddir",
					fp,
					FILE_PRIVATE(fp)->meta_rf,
					FILE_PRIVATE(fp)->meta_rf_len,
					0,
					filerq,
					sizeof(struct file_request),
					filerp,
					sizeof(struct file_reply)+filerq->u.readdirrq.count,
					&node);
	if (rval >= 0)
		log_request(filerq->request, NULL, ip, fp, 1, node,
			    jiffies - elapsed_jiffies);

	if (rval < 0) {
		;
	} else if (filerp->rval < 0) {
		KDEBUG_OFC(0, "DVS: ureaddir: got error from server %ld\n",
			filerp->rval);
		rval = filerp->rval;
	} else {
		int namlen;
		char *cp = (char *)filerp->u.readdirrp.data;
		struct linux_dirent64 *de;
		int nbytes = filerp->rval;
		loff_t offset = 0;

		while (nbytes > 0) {
			de = (struct linux_dirent64 *)cp;
			namlen = strlen(de->d_name);

			/*
			 * Prevent the special DVS files
			 * (superblock, backup superblock) from showing up.
			 */
			if (!SUPERBLOCK_NAME(de->d_name)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
				if (filldir(dirent, de->d_name, namlen, offset,
						de->d_ino, DT_UNKNOWN))
					break;
#else
				if (!dir_emit(ctx, de->d_name, namlen,
						de->d_ino, DT_UNKNOWN))
					break;
#endif
			}

			offset = de->d_off;
			cp += de->d_reclen;
			nbytes -= de->d_reclen;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
			ctx->pos = offset;
#endif
		}
		KDEBUG_OFC(0, "DVS: ureaddir: delivered %ld bytes pos %ld\n",
			(filerp->rval - nbytes),
			(long)filerp->u.readdirrp.f_pos);
		filerp->rval = 0;
		rval = filerp->rval;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
		fp->f_pos = filerp->u.readdirrp.f_pos;
#endif
	}

done:
	iip->inode_lock_holder = 0;
	free_msg(filerq);
	free_msg(filerp);
	return(rval);
}

static long do_remote_ioctl(struct file *fp,
			    struct ioctl_desc *id, void *arg_val)
{
	int rval = 0, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	int freq_sz, frep_sz;
	struct inode *ip = file_inode(fp);
	unsigned long elapsed_jiffies;

	freq_sz = sizeof(struct file_request) +
	    (id->arg_is_ref ? id->arg_size : 0);
	filerq = (struct file_request *)kmalloc_ssi(freq_sz, GFP_KERNEL);
	if (!filerq) {
		rval = -ENOMEM;
		goto out;
	}

	frep_sz = sizeof(struct file_reply) + (id->arg_rw ? id->arg_size : 0);
	filerp = (struct file_reply *)kmalloc_ssi(frep_sz, GFP_KERNEL);
	if (!filerp) {
		rval = -ENOMEM;
		goto out;
	}

	filerq->request = RQ_IOCTL;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->u.ioctlrq.cmd = id->cmd;
	filerq->u.ioctlrq.arg_size = id->arg_size;
	filerq->u.ioctlrq.arg_is_ref = id->arg_is_ref;
	filerq->u.ioctlrq.arg_rw = id->arg_rw;
	if (id->arg_is_ref) {
		memcpy(filerq->u.ioctlrq.data, arg_val, id->arg_size);
	} else {
		filerq->u.ioctlrq.arg = (unsigned long)arg_val;
	}
	capture_context((&filerq->context));

	if (id->cmd == DVS_BCAST_IOCTL || id->cmd == DVS_AUGMENTED_BCAST_IOCTL) {
		/* Broadcast ioctl to all servers */
		struct per_node *pna = NULL;
		struct file_reply *frp = NULL;
		int nnodes, nord;

		nnodes = FILE_PRIVATE(fp)->meta_rf_len;

		/* Do opens on all nodes, so that we
		 * have all possible file handles */
		for (nord = 0; nord < nnodes; nord++) {
			if (!META_RF(fp, nord)->valid) {
				rval = deferred_uopen(ip, fp, nord);
				if (rval < 0)
					goto out;
			}
		}

		elapsed_jiffies = jiffies;

		/* Send ioctl to all servers */
		if ((rval =
		     send_multi_async_ipc_file_retry("uioctl",
							fp,
							FILE_PRIVATE(fp)->meta_rf,
							FILE_PRIVATE(fp)->meta_rf_len,
							filerq,
							freq_sz,
							frep_sz,
							&pna,
							&node)) < 0) {
			goto bcast_done;
		}
		log_request(filerq->request, NULL, ip, fp, nnodes, node,
			    jiffies - elapsed_jiffies);

		/* Check responses */
		for (nord = 0; nord < nnodes; nord++) {
			if (!(frp = pna[nord].reply))
				continue;
			rval = frp->rval;
			if (rval < 0) {
				KDEBUG_OFC(0, "DVS: do_remote_ioctl: got error from "
						"server %d\n", rval);
				if (id->arg_rw) {
					/* Write back the results. */
					memcpy(arg_val, frp->u.ioctlrp.data,
					       id->arg_size);
				}
				goto bcast_done;
			}
		}

		/* Write back the results.  */
		if (rval >= 0 && id->arg_rw) {
			rval = pna[0].reply->rval;
			memcpy(arg_val, pna[0].reply->u.ioctlrp.data,
			       id->arg_size);
		}

bcast_done:
		/* cleanup */
		if (pna) {
			for (nord = 0; nord < nnodes; nord++) {
				free_msg(pna[nord].reply);
				free_msg(pna[nord].request);
			}
			kfree_ssi(pna);
		}
	} else {
		elapsed_jiffies = jiffies;
		rval = send_ipc_file_retry("uioctl",
						fp,
						FILE_PRIVATE(fp)->meta_rf,
						FILE_PRIVATE(fp)->meta_rf_len,
						0,
						filerq,
						freq_sz,
						filerp,
						frep_sz,
						&node);
		if (rval < 0)
			goto out;
		log_request(filerq->request, NULL, ip, fp, 1, node,
			    jiffies - elapsed_jiffies);

		/* Write back the results.  */
		if (id->arg_rw) {
			memcpy(arg_val, filerp->u.ioctlrp.data, id->arg_size);
		}

		if (filerp->rval < 0) {
			KDEBUG_OFC(0, "DVS: do_remote_ioctl: got error %ld from "
					"server\n", filerp->rval);
		}
		rval = filerp->rval;
	}

out:
	free_msg(filerq);
	free_msg(filerp);
	return rval;
}

static long uioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	int rval = 0, ival;
	struct ioctl_desc id;
	struct ioctl_desc *idp = NULL;
	struct dvs_ioctl_tunnel *itun = NULL;
	struct dvs_augmented_ioctl_tunnel *atun = NULL;
	struct inode *ip = file_inode(fp);
	short val;

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: uioctl: called with NULL private_data\n");
		return -USIERR_INTERNAL;
	}

	if (FILE_PRIVATE(fp)->nokill_error)
		return -EHOSTDOWN;

	idp = get_ioctl_desc(cmd);
	if (!idp) {
		KDEBUG_OFC(0, "DVS: uioctl: called with unknown cmd 0x%x\n", cmd);
		return -ENOSYS;
	}
	memcpy(&id, idp, sizeof(struct ioctl_desc));

	if (id.arg_size > MAX_FILE_PAYLOAD) {
		printk(KERN_ERR "DVS: uioctl: arg too large, "
		       "cmd 0x%x size %d\n", cmd, id.arg_size);
		return -USIERR_INTERNAL;
	}
	KDEBUG_OFC(0, "DVS: uioctl: called for cmd = 0x%x\n", cmd);

	/*
	 * Handle DVS ioctls
	 */
	switch (cmd) {
	case DVS_GET_REMOTE_FS_MAGIC:
		return put_user(INODE_PRIVATE(ip)->underlying_magic, (unsigned long __user *)arg);
		break;
	case DVS_GET_FILE_BLK_SIZE:
		return put_user(FILE_PRIVATE(fp)->blocksize, (int __user *)arg);
		break;
	case DVS_SET_FILE_BLK_SIZE:
		if ((rval = get_user(ival, (int __user *)arg)) < 0)
			return rval;
		if (ival > 0) {
			FILE_PRIVATE(fp)->blocksize = ival;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_FILE_STRIPE_WIDTH:
		return put_user(FILE_PRIVATE(fp)->data_rf_len, (int __user *)arg);
		break;
	case DVS_SET_FILE_STRIPE_WIDTH:
		if ((rval = get_user(ival, (int __user *)arg)) < 0)
			return rval;
		if (!INODE_ICSB(ip)->loadbalance) {
			if (ival > 0) {
				if (ival > INODE_ICSB(ip)->data_servers_len)
					FILE_PRIVATE(fp)->data_rf_len = INODE_ICSB(ip)->data_servers_len;
				else
					FILE_PRIVATE(fp)->data_rf_len = ival;
				return 0;
			}
		}
		return -EINVAL;
		break;
	case DVS_GET_FILE_DATASYNC:
		return put_user(FILE_PRIVATE(fp)->datasync, (short __user *)arg);
		break;
	case DVS_SET_FILE_DATASYNC:
		if ((rval = get_user(val, (short __user *)arg)) < 0)
			return rval;
		if ((val == 0) || (val == 1)) {
			FILE_PRIVATE(fp)->datasync = val;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_FILE_CACHE:
		return put_user(FILE_PRIVATE(fp)->cache, (short __user *)arg);
		break;
	case DVS_SET_FILE_CACHE:
		if ((rval = get_user(val, (short __user *)arg)) < 0)
			return rval;
		if (val == 0) {
			if (!FILE_PRIVATE(fp)->cache)
				return 0;

			DVS_LOG("Turning off caching for file %s\n", fpname(fp));
			FILE_PRIVATE(fp)->cache = 0;

			if ((SUPER_SFLAGS(ip) & MS_RDONLY) || (!S_ISREG(ip->i_mode)))
				return 0;

			INODE_DEC_CWC_FILES(ip);
			if (INODE_CWC_FILES(ip)) {
				DVS_LOGP("Warning: Caching disabled for writable "
				         "file %s while data may still be "
				         "cached\n", fpname(fp));
			}

			/* Flush all the pages since this file isn't using
			 * caching anymore */
			if ((rval = filemap_write_and_wait(ip->i_mapping)) < 0) {
				DVS_LOGP("Warning: Could not flush pages for "
				         "file %s. Error %d\n", fpname(fp),
				         rval);
			}

			return 0;
		} else if (val == 1) {
			if (FILE_PRIVATE(fp)->cache)
				return 0;

			INODE_INC_CWC_FILES(ip);
			FILE_PRIVATE(fp)->cache = 1;
			DVS_LOG("Turning on caching for file %s\n", fpname(fp));

			return 0;
		} else {
			return -EINVAL;
		}
		break;
	case DVS_GET_FILE_CLOSESYNC:
		return put_user(FILE_PRIVATE(fp)->closesync, (short __user *)arg);
		break;
	case DVS_SET_FILE_CLOSESYNC:
		if ((rval = get_user(val, (short __user *)arg)) < 0)
			return rval;
		if ((val == 0) || (val == 1)) {
			FILE_PRIVATE(fp)->closesync = val;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_FILE_KILLPROCESS:
		return put_user(FILE_PRIVATE(fp)->killprocess, (short __user *)arg);
		break;
	case DVS_SET_FILE_KILLPROCESS:
		if ((rval = get_user(val, (short __user *)arg)) < 0)
			return rval;
		if ((val == 0) || (val == 1)) {
			FILE_PRIVATE(fp)->killprocess = val;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_FILE_ATOMIC:
		return put_user(FILE_PRIVATE(fp)->atomic, (short __user *)arg);
		break;
	case DVS_SET_FILE_ATOMIC:
		if ((rval = get_user(val, (short __user *)arg)) < 0)
			return rval;
		if ((val == 0) || (val == 1)) {
			FILE_PRIVATE(fp)->atomic = val;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_FILE_DEFEROPENS:
		return put_user(FILE_PRIVATE(fp)->deferopens, (short __user *)arg);
		break;
	case DVS_SET_FILE_DEFEROPENS:
		if ((rval = get_user(val, (short __user *)arg)) < 0)
			return rval;
		if ((val == 0) || (val == 1)) {
			FILE_PRIVATE(fp)->deferopens = val;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_FILE_CACHE_READ_SZ:
		return put_user(FILE_PRIVATE(fp)->cache_read_sz,
				(unsigned int __user *)arg);
		break;
	case DVS_SET_FILE_CACHE_READ_SZ:
		if ((rval = get_user(ival, (int __user *)arg)) < 0)
			return rval;
		if (ival > 0 && (SUPER_SFLAGS(ip) & MS_RDONLY)) {
			FILE_PRIVATE(fp)->cache_read_sz = ival;
			return 0;
		} else
			return -EINVAL;
		break;
	case DVS_GET_NNODES:
		/* Note necessarily correct when using separate metadata servers */
		return put_user(INODE_ICSB(ip)->data_servers_len, (int __user *)arg);
		break;
	case DVS_TUNNEL_IOCTL:
	case DVS_BCAST_IOCTL:
		itun = kmalloc_ssi(sizeof(struct dvs_ioctl_tunnel), GFP_KERNEL);
		if (!itun) {
			rval = -ENOMEM;
			goto out;
		}
		if (copy_from_user(itun, (void __user *)arg,
					   sizeof(struct dvs_ioctl_tunnel))) {
			rval = -EFAULT;
			goto out;
		}
		if (itun->arg_size < 0
		    || (itun->arg_size == 0 && itun->arg_by_ref)) {
			rval = -EINVAL;
			goto out;
		}

		if (itun->arg_size > 0) {
			if (sizeof(struct dvs_ioctl_tunnel) +
			    itun->arg_size > MAX_FILE_PAYLOAD) {
				printk(KERN_ERR "DVS: uioctl: arg too large, "
				       "cmd 0x%x size %d\n", cmd,
				       itun->arg_size);
				rval = -USIERR_INTERNAL;
				goto out;
			}
			itun = krealloc(itun, sizeof(struct dvs_ioctl_tunnel) +
					itun->arg_size, GFP_KERNEL);
			if (!itun) {
				rval = -ENOMEM;
				goto out;
			}
			if ((rval =
			     copy_from_user(itun->arg,
					    (void __user *)((char *)arg) +
					    sizeof(struct dvs_ioctl_tunnel),
					    itun->arg_size))) {
				rval = -EFAULT;
				goto out;
			}
		}

		id.arg_size = sizeof(struct dvs_ioctl_tunnel) + itun->arg_size;

		rval = do_remote_ioctl(fp, &id, (void *)itun);
		if (rval == 0) {
			if (copy_to_user((void __user *)arg, itun, id.arg_size)) {
				rval = -EFAULT;
				goto out;
			}
		}
		break;
	case DVS_AUGMENTED_TUNNEL_IOCTL:
	case DVS_AUGMENTED_BCAST_IOCTL:
		atun =
		    kmalloc_ssi(sizeof(struct dvs_augmented_ioctl_tunnel),
			    GFP_KERNEL);
		if (!atun) {
			rval = -ENOMEM;
			goto out;
		}
		if ((rval = copy_from_user(atun, (void __user *)arg,
					   sizeof(struct
						  dvs_augmented_ioctl_tunnel)))) {
			rval = -EFAULT;
			goto out;
		}
		if (atun->arg_size < 0
		    || (atun->arg_size == 0 && atun->arg_by_ref)) {
			rval = -EINVAL;
			goto out;
		}

		if (atun->arg_size > 0) {
			if (sizeof(struct dvs_augmented_ioctl_tunnel) +
			    atun->arg_size > MAX_FILE_PAYLOAD) {
				printk(KERN_ERR "DVS: uioctl: arg too large, "
				       "cmd 0x%x size %d\n", cmd,
				       atun->arg_size);
				rval = -USIERR_INTERNAL;
				goto out;
			}
			atun =
			    krealloc(atun,
				     sizeof(struct dvs_augmented_ioctl_tunnel) +
				     atun->arg_size, GFP_KERNEL);
			if (!atun) {
				rval = -ENOMEM;
				goto out;
			}
			if ((rval =
			     copy_from_user(atun->arg,
					    (void __user *)((char *)arg) +
					    sizeof(struct
						   dvs_augmented_ioctl_tunnel),
					    atun->arg_size))) {
				rval = -EFAULT;
				goto out;
			}
		}

		id.arg_size =
		    sizeof(struct dvs_augmented_ioctl_tunnel) + atun->arg_size;
		atun->stripe_size = FILE_PRIVATE(fp)->blocksize;
		atun->stripe_width = FILE_PRIVATE(fp)->data_rf_len;
		atun->stripe_index = 0;
		rval = do_remote_ioctl(fp, &id, (void *)atun);
		if (rval == 0) {
			if (copy_to_user((void __user *)arg, atun, id.arg_size)) {
				rval = -EFAULT;
				goto out;
			}
		}
		break;
	default:
		rval = -EINVAL;
		goto out;
	}

out:
	kfree_ssi(itun);
	kfree_ssi(atun);
	return (rval);
}

static int ummap (struct file *fp, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(fp);
	struct inode_info *iip;

	if (FILE_PRIVATE(fp)->nokill_error)
		return -EHOSTDOWN;

	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE)) {
		KDEBUG_OFC(0, "DVS: ummap: does not support shared writeable "
			"mmap\n");
		return -ENOSYS;
	}
	if (!inode->i_sb || !S_ISREG(inode->i_mode)) {
		KDEBUG_OFC(0, "DVS: ummap: not regular file\n");
		return -EACCES;
	}

	vma->vm_ops = &vmops;
	iip = (struct inode_info *)inode->i_private;
	KDEBUG_OFC(0, "DVS: ummap: called fp[0x%p] ip[0x%p] inode_info[0x%p]\n", fp, inode,
		iip);
	return 0;
}

/*
 * Set defaults in fp->private_data and handle overrides to
 * mount-time DVS parameters via user environment.
 * Fields considered are: datasync, no_caching, blksize, nnodes,
 * closesync, killprocess, deferopens, cache_read_sz
 */
static void parse_user_environment(char *path,
				struct incore_upfs_super_block *icsb,
				struct open_file_info *ofi)
{
	int i;
	unsigned long rval, env_len;
	char *env, *penv;

	/* Reset values to defaults */
	ofi->datasync =		icsb->datasync;
	ofi->closesync =	icsb->closesync;
	ofi->cache =		icsb->cache;
	ofi->blocksize =	icsb->bsz;
	ofi->data_rf_len =	icsb->data_stripe_width;
	ofi->meta_rf_len =	icsb->meta_stripe_width;
	ofi->killprocess =	icsb->killprocess;
	ofi->atomic =		icsb->atomic;
	ofi->deferopens =	icsb->deferopens;
	ofi->ro_cache =		icsb->ro_cache;
	ofi->cache_read_sz =	icsb->cache_read_sz;

	/* enable FILE_CACHE for RO_CACHE so it can be disabled via CACHE env var */
	if (ofi->ro_cache) {
		ofi->cache = 1;
	}

	if (!icsb->userenv) {
		return;
	}

	/*
	 * Examine the process environment to check for DVS
	 * environment variables which can override mount-time settings.
	 *
	 * The variables we look for on all open calls are:
	 *
	 *	DVS_DATASYNC=on/off     [overrides -o datasync (default off)]
	 *	DVS_CLOSESYNC=on/off    [overrides -o closesync (default off)]
	 *	DVS_CACHE=on/off        [overrides -o cache (default off)]
	 *	DVS_BLOCKSIZE=n (bytes) [overrides -o blksize (default 524288)]
	 *	DVS_MAXNODES=n          [overrides -o maxnodes (default #nodes)]
	 *	DVS_METATEST=on/off     [noclusterfs metadata testing only]
	 *	DVS_KILLPROCESS=on/off	[overrides -o killprocess (default on)]
	 *	DVS_ATOMIC=on/off       [overrides -o atomic (default off)]
	 *	DVS_DEFEROPENS=on/off   [overrides -o deferopens (default on)]
	 *
	 * The environment variables are contiguous and nul-separated
	 * in user memory, so we just allocate some space and copy them in.
	 */

	/*
	 * No need to lock current->mm here as it can't change beneath us,
	 * and env_end/env_start are fixed values.  If DVS is GPL'd in
	 * the future however, we should use get_task_mm/mmput here.
	 */
	if (!current->mm)
		return;

	env_len = current->mm->env_end - current->mm->env_start;
	if (env_len == 0)
		return;

	env = (char *)kmalloc_ssi(env_len, GFP_KERNEL);
	KDEBUG_OFC(0, "DVS: %s: allocated 0x%lx bytes for env at 0x%p\n",
		__FUNCTION__, env_len, env);
	if (env)
		rval = copy_from_user(env, (void *)current->mm->env_start,
				      env_len);
	else
		rval = -ENOMEM;
	if (rval != 0) {
		printk(KERN_ERR "DVS: %s: copy_from_user failed to copy %lu "
		       "bytes of user environment\n", __FUNCTION__, rval);
		if (env)
			kfree_ssi(env);
		return;
	}
	/* Add a nul byte at the end in case it's missing */
	*(env + env_len - 1) = '\0';
	penv = env;
	i = 0;
	while ((i < env_len) && (*penv != '\0')) {
		int opt;
		int len;

		for (opt = 0; opt < numoptions; opt++) {
			unsigned long optlen = optionlist[opt].opt_len;
			char *sval;
			int val;

			if ((i + optlen) >= env_len) {
				continue;
			}

			if (strncmp(penv, optionlist[opt].opt_name,
								optlen) != 0) {
				continue;
			}

			sval = penv + optlen;
			val = 0;

			KDEBUG_OFC(0, "DVS: %s: pid %d (%s): found "
				"env_var %s: value %s\n",
				__FUNCTION__, current->pid,
				current->comm,
				optionlist[opt].opt_name, sval);

			switch (optionlist[opt].opt_which) {
			case DVS_DATASYNC_TYPE:
				if (strcmp(sval, "on") == 0)
					ofi->datasync = 1;
				else if (strcmp(sval, "off") == 0)
					ofi->datasync = 0;
				KDEBUG_OFC(0, "DVS: %s: setting datasync to %d "
					   "for file %s\n", __FUNCTION__,
					   ofi->datasync, path);
				break;
			case DVS_CACHE_TYPE:
				if (strcmp(sval, "on") == 0) {
					ofi->cache = 1;
					DVS_LOG("Turning on caching for file "
					        "%s\n", path);
				} else if (strcmp(sval, "off") == 0) {
					ofi->cache = 0;
					DVS_LOG("Turning off caching for file "
					        "%s\n", path);
				}
				KDEBUG_OFC(0, "DVS: %s: setting cache to %d for "
					   "file %s\n", __FUNCTION__,
					   ofi->cache, path);
				break;
			case DVS_BLOCKSIZE_TYPE:
				val = simple_strtol(sval, NULL, 0);
				if (val > 0) {
					KDEBUG_OFC(0, "DVS: %s: setting blocksize "
						"to %d for file %s\n",
						__FUNCTION__, val, path);
					ofi->blocksize = val;
				}
				break;
			case DVS_MAXNODES_TYPE:
				if (!icsb->loadbalance) {
					val = simple_strtol(sval, NULL, 0);
					if (val > 0) {
						if (val > icsb->data_servers_len)
							val = icsb->data_servers_len;
						KDEBUG_OFC(0, "DVS: %s: setting "
							"nnodes to %d for file"
							" %s\n", __FUNCTION__,
							val, path);
						ofi->data_rf_len = val;
					}
				}
				break;
			case DVS_CLOSESYNC_TYPE:
				if (strcmp(sval, "on") == 0)
					ofi->closesync = 1;
				else if (strcmp(sval, "off") == 0)
					ofi->closesync = 0;
				KDEBUG_OFC(0, "DVS: %s: setting sync on close to "
					   "%d for file %s\n", __FUNCTION__,
					   ofi->closesync, path);
				break;
			case DVS_KILLPROCESS_TYPE:
				if (strcmp(sval, "on") == 0)
					ofi->killprocess = 1;
				else if (strcmp(sval, "off") == 0)
					ofi->killprocess = 0;
				KDEBUG_OFC(0, "DVS: %s: setting killprocess "
					   "to %d for file %s\n", __FUNCTION__,
					   ofi->killprocess, path);
				break;
			case DVS_ATOMIC_TYPE:
				if (strcmp(sval, "on") == 0)
					ofi->atomic = 1;
				else if (strcmp(sval, "off") == 0)
					ofi->atomic = 0;
				KDEBUG_OFC(0, "DVS: %s: setting atomic stripe "
                                           "parallel to %d for file %s\n", 
                                           __FUNCTION__, ofi->atomic, path);
				break;
			case DVS_DEFEROPENS_TYPE:
				if (strcmp(sval, "on") == 0)
					ofi->deferopens = 1;
				else if (strcmp(sval, "off") == 0)
					ofi->deferopens = 0;
				KDEBUG_OFC(0, "DVS: %s: setting defer opens to "
					"%d for file %s\n", __FUNCTION__,
					ofi->deferopens, path);
				break;
			case DVS_CACHE_RD_SZ_TYPE:
				val = simple_strtol(sval, NULL, 0);
				if (val > 0 && (icsb->superblock->s_flags & MS_RDONLY)) {
					KDEBUG_OFC(0, "DVS: %s: setting cache_read_sz"
						" to %d for file %s\n",
						__FUNCTION__, val, path);
					ofi->cache_read_sz = val;
				}
				break;
			}
		}
		len = strlen(penv) + 1;
		penv += len;
		i += len;
	}

	kfree_ssi(env);

	KDEBUG_OFC(0, "DVS: %s: pid %d (%s): path %s: datasync %d closesync %d "
		   "cache %d blocksize %d nnodes %d killprocess %d "
		   "deferopens %d cache_read_sz %d\n",
		   __FUNCTION__, current->pid, current->comm, path,
		   ofi->datasync, ofi->closesync, ofi->cache,
		   ofi->blocksize, ofi->data_rf_len, ofi->killprocess,
		   ofi->deferopens, ofi->cache_read_sz);
}

static void remote_file_init (struct remote_file *rf,
			      struct remote_file *source,
			      struct file_reply *frp,
			      struct open_file_info *finfo)
{
	struct incore_upfs_super_block *icsb = FILE_ICSB(finfo->fp);

	rf->file_handle = source->file_handle;
	rf->use_local_position = 1;
	rf->flush_required = source->flush_required;
	rf->magic = source->magic;
	rf->last_write = 0;
	rf->last_sync = 0;
	rf->finfo = finfo;
	if (frp) {
		rf->identity = REMOTE_IDENTITY(&frp->ipcmsg);
		rf->remote_node = SOURCE_NODE(&frp->ipcmsg);
	} else {
		rf->identity = source->identity;
		rf->remote_node = source->remote_node;
	}

	if (node_map[rf->remote_node].server_info && !(icsb->flags & MS_RDONLY)) {
		atomic_inc(&node_map[rf->remote_node].server_info->open_files);
		spin_lock(&node_map[rf->remote_node].server_info->lock);
		list_add_tail(&rf->list,
		              &node_map[rf->remote_node].server_info->rf_list);
		spin_unlock(&node_map[rf->remote_node].server_info->lock);
	} else {
		INIT_LIST_HEAD(&rf->list);
	}

	rf->quiesced = 0;
	rf->valid = 1;
}

/*
 * Create an open_file_info struct for this newly opened file.
 * Passing non-negative arguments for data_stripe_width or meta_stripe_width
 * will override the default stripe widths.
 */
static struct open_file_info *alloc_init_file_private(char *path,
					struct file *fp,
					struct incore_upfs_super_block *icsb,
					int data_stripe_width,
					int meta_stripe_width) {

	int i, rf_len;
	struct open_file_info def_ofi, *ofi = NULL;

	memset(&def_ofi, 0, sizeof(struct open_file_info));
	/*
	 * Set file values to defaults, and if the user is overriding any
	 * settings, detect those now. Pass in a dummy ofi to get values
	 * before allocating the private data.
	 */
	parse_user_environment(path, icsb, &def_ofi);

	/* Override defaults with given values */
	if (data_stripe_width >= 0)
		def_ofi.data_rf_len = data_stripe_width;
	if (meta_stripe_width >= 0)
		def_ofi.meta_rf_len = meta_stripe_width;

	rf_len = def_ofi.data_rf_len + def_ofi.meta_rf_len;
	if ((ofi = kmalloc_ssi(sizeof(struct open_file_info) +
					sizeof(struct remote_file) * rf_len,
					GFP_KERNEL)) == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	*ofi = def_ofi;
	ofi->rf_len = rf_len;
	/*
	 * Initialize and establish the type of remote file,
	 * either data or metadata
	 */
	for (i = 0; i < ofi->rf_len; i++) {
		ofi->rf[i].dwfs_data_path = NULL;
		mutex_init(&ofi->rf[i].mutex);
		if (ofi->meta_rf_len == 0)
			ofi->rf[i].rf_type = RF_TYPE_DATA;
		else if (i < ofi->data_rf_len)
			ofi->rf[i].rf_type = RF_TYPE_DATA;
		else
			ofi->rf[i].rf_type = RF_TYPE_META;
	}

	/* If there are no dedicated metadata servers, we use data servers */
	ofi->data_rf = ofi->rf;
	if (ofi->meta_rf_len > 0) {
		ofi->meta_rf = ofi->rf + ofi->data_rf_len;
	} else {
		ofi->meta_rf = ofi->rf;
		ofi->meta_rf_len = ofi->data_rf_len;
	}

	/* initialize the rest of the open_file_info */
	INIT_LIST_HEAD(&ofi->list);
	ofi->fp = fp;
	ofi->open_flags = fp->f_flags;
	spin_lock_init(&ofi->estale_lock);
	sema_init(&ofi->rip_sema, 1);
	sema_init(&ofi->write_sema, 1);
	sema_init(&ofi->rocache_sema, 1);
	return ofi;
}

static int uopen (struct inode *ip, struct file *fp)
{
	struct inode_info *iip;
	struct incore_upfs_super_block *icsb = INODE_ICSB(ip);
	int rval = 0, rsz = 0, node = 0, acquired_mutex = 0;
	int delete_dentry = 0, send_request = 1, rpsz = 0, inval, node_used;
	struct file_request *filerq = NULL;
	struct file_reply *frp = NULL;
	char *bufp = NULL, *path = NULL;
	struct per_node *pna = NULL;
	struct remote_file *rf_array;
	struct remote_file *rf;
	struct open_reply *openrp = NULL;
	unsigned long elapsed_jiffies;
	int offset;
	int rf_len = 0;
	int data_stripe_width = -1, meta_stripe_width = -1;
	uint64_t path_trunc[4];
	int private_data_allocated = (fp->private_data != NULL);

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: uopen: called with NULL inode info\n");
		return -USIERR_INTERNAL;
	}

	if ((fp->private_data != NULL) && !FILE_PRIVATE(fp)->rip) {
		printk(KERN_ERR "DVS: uopen: called with private_data 0x%p\n",
				fp->private_data);
		return -USIERR_INTERNAL;
	}

	/*
	 * Set up the file_request structure.
	 */
	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		return -ENOMEM;
	}

	if (fp->f_path.dentry == NULL) {
		path = ERR_PTR(-ENOENT);
	} else {
		path = get_path(fp->f_path.dentry, fp->f_path.mnt, bufp, ip);
	}

	if (IS_ERR(path)) {
		free_page((unsigned long)bufp);
		return PTR_ERR(path);
	}

	KDEBUG_OFC(0, "DVS: uopen: called ip 0x%p path %s flags 0x%x\n", ip, path,
			fp->f_flags);

#ifdef CONFIG_ARM64
	/* Def of O_DIRECTORY on ARM is different than x86 */
	KDEBUG_OFC(0, "DVS: uopen: Stripping O_DIRECTORY from directory open"
				" ip 0x%p path %s flags 0x%x\n", ip, path,
				fp->f_flags);
	fp->f_flags &= ~O_DIRECT;
	fp->f_flags &= ~O_DIRECTORY;
	KDEBUG_OFC(0, "DVS: uopen: called ip 0x%p path %s flags 0x%x\n", ip, path,
		   fp->f_flags);
#endif
	/*
	 * If iip->openrp exists, we don't have to send an open request to the
	 * server as the create request did the open for us.  This shortcut
	 * only applies to the first process to open the file after the create.
	 */
	if (iip->openrp) {
		spin_lock(&iip->lock);
		if (iip->openrp) {
			send_request = 0;
			openrp = iip->openrp;
			iip->openrp = NULL;
		}
		spin_unlock(&iip->lock);
	}

	if (send_request) {
		rsz = sizeof(struct file_request) + strlen(path) + 1;
		filerq = kmalloc_ssi(rsz, GFP_KERNEL);
		if (!filerq) {
			free_page((unsigned long)bufp);
			return -ENOMEM;
		}
		filerq->request = RQ_OPEN;
		filerq->retry = INODE_ICSB(ip)->retry;
                filerq->flags.multiple_servers = (INODE_ICSB(ip)->data_servers_len > 1 ||
						INODE_ICSB(ip)->meta_servers_len > 1);
		filerq->u.openrq.flags = fp->f_flags;
                filerq->u.openrq.use_openexec = current->in_execve;
		strcpy(filerq->u.openrq.pathname, path);
		set_is_flags(filerq, ip);
		filerq->u.openrq.i_mode = ip->i_mode;

		/*
		 * write-append file position handled on client for dwfs and
		 * write-caching
		 */
		if ((FILE_DWFS(fp)) ||
		    (INODE_ICSB(ip)->cache && !(SUPER_SFLAGS(ip) & MS_RDONLY))) {
			filerq->u.openrq.flags &= ~O_APPEND;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		/*
		 * Unconditionally remove the O_EXCL here. Any O_CREAT|O_EXCL
		 * races will have been resolved in ucreate.
		 */
		filerq->u.openrq.flags &= ~O_EXCL;
#endif

		if (FILE_DWCFS(fp)) {
			/* truncate is handled by VFS, doesn't need to be
			 * forwarded, O_EXCL done by create */
			filerq->u.openrq.flags &= ~(O_TRUNC|O_EXCL);
			filerq->flags.is_dwcfs_stripe =
				(INODE_ICSB(ip)->data_stripe_width > 1 && !INODE_ICSB(ip)->loadbalance);
		}
	}

	/*
	 * fp->private_data points to an open_file_info struct that is created
	 * here at open() time.
	 */
	if (!private_data_allocated) {

		/* Non-regular files are opened on a metadata server only */
		if (!S_ISREG(file_inode(fp)->i_mode)) {
			data_stripe_width = 0;
			meta_stripe_width = 1;
		}

		if (IS_ERR(fp->private_data = alloc_init_file_private(path,
							fp,
							icsb,
							data_stripe_width,
							meta_stripe_width))) {
			rval = PTR_ERR(fp->private_data);
			goto uopen_done;
		}

		atomic_inc(&icsb->open_dvs_files);
		dvsproc_stat_update(INODE_ICSB(ip)->stats, DVSPROC_STAT_OPEN_FILES, 0, 1);
		/*
		 * If this is an O_CREAT open and this pid completed a create
		 * request this file instance can do dentry_open on the server
		 */
		if (iip->o_creat_pid == current->pid) {
			FILE_PRIVATE(fp)->d_open = 1;
			iip->o_creat_pid = -1;
		}

		DVS_TRACEL("opensso", ip->i_ino, icsb->data_servers_len,
                           FILE_PRIVATE(fp)->data_rf_len, inode_sso(ip), ip);
		/*
 		 * Load up the last 32 chars of the path name into the
		 * args field of a normal trace entry.  Also include the inode
		 * pointer so they can be matched up in the trace output.
		 */
		memset(path_trunc, 0, sizeof(path_trunc));
		offset = strlen(path) - sizeof(path_trunc);
		if (offset < 0)
			offset = 0;
		strncpy((char *) path_trunc, path + offset, sizeof(path_trunc));
		DVS_TRACEL("open_nam", ip, path_trunc[0], path_trunc[1],
					path_trunc[2], path_trunc[3]);
	} else {
		KDEBUG_QSC(0, "Opening file %p path %s, possibly because of "
				"quiescing\n", fp, path);
		/*
		 * uopen loop in progress.  An open_file_info struct
		 * already exists.
		 */
		KDEBUG_OFC(0, "DVS: uopen: uopen loop in progress\n");
		down(&FILE_PRIVATE(fp)->rip_sema);
		FILE_PRIVATE(fp)->rip = 2;
		up(&FILE_PRIVATE(fp)->rip_sema);

		/*
		 * If O_CREAT was specified on the initial open of the file,
		 * use it again for the re-open to ensure the DVS server does
		 * a dentry open instead of a full open.
		 */
		if (FILE_PRIVATE(fp)->open_flags & O_CREAT) {
			KDEBUG_QSC(0, "uopen file %p path %s tagged with O_CREAT\n",
				fp, path);
			filerq->u.openrq.flags |= O_CREAT;
		}
	}

	/*
	 * If the open information was piggybacked with the create request,
	 * we set up the remote file information and are done.
	 */
	if (!send_request) {
		rf = &FILE_PRIVATE(fp)->meta_rf[0];

		remote_file_init(rf, &openrp->rf, NULL,
		                 (struct open_file_info *)fp->private_data);

		if (FILE_DWFS(fp)) {
			KDEBUG_OFC(0, "Calling create_dwfs_data_paths file %p "
					"data_rf %p data_rf_len %d "
					"meta_rf %p meta_rf_len %d\n", fp,
					FILE_PRIVATE(fp)->data_rf, FILE_PRIVATE(fp)->data_rf_len,
					FILE_PRIVATE(fp)->meta_rf, FILE_PRIVATE(fp)->meta_rf_len);
			if ((rval = create_dwfs_data_paths(fp,
			                                   &openrp->dwfs_info)) < 0) {
				printk(KERN_ERR "Could not initialize DWFS "
				       "data paths for file %s\n", fpname(fp));

				goto uopen_error;
			}
		}
		kfree(openrp);
		KDEBUG_OFC(0, "DVS: %s: using piggybacked open data for %s\n",
			   __FUNCTION__, path);
		free_page((unsigned long)bufp);
		if (!private_data_allocated) {
			spin_lock(&icsb->lock);
			list_add(&FILE_PRIVATE(fp)->list, &icsb->open_files);
			spin_unlock(&icsb->lock);
		}
		return 0;
	}

	/* Regular open on all remote files */
	rf_len = FILE_PRIVATE(fp)->rf_len;
	rf_array = FILE_PRIVATE(fp)->rf;

	/* Alter the rf_array/rf_len settings for deferopens */
	if (FILE_PRIVATE(fp)->deferopens) {
		/* Files get opened on the metadata servers first */
		rf_array = FILE_PRIVATE(fp)->meta_rf;
		rf_len = 1;

		/* Complex side effects:
		 * - extends reply structure to hold TWO paths
		 * - triggers uopen() kdwfs ioctls() on server
		 */
		if (FILE_DWFS(fp))
			filerq->u.openrq.dwfs_path_len = DWFS_PATH_LEN;
	}

	/* number of nodes that file could stripe to */
	filerq->u.openrq.max_nodes = FILE_PRIVATE(fp)->data_rf_len;

	/*
	 * Notify the server if it can safely use dentry_open. Applies to
	 * retries and deferred opens for this file instance as well
	 */
	if (FILE_PRIVATE(fp)->d_open)
		filerq->u.openrq.d_open = 1;

	/* If ro_cache mode enabled, check open flags and notify first server
	 * in stripe list to either check if caching is safe or notify clients
	 * file is being opened in write mode.  If file_cache is not set user
	 * disabled caching via env var so no need to do hashtable checking.
	 */
	if (FILE_PRIVATE(fp)->ro_cache && S_ISREG(file_inode(fp)->i_mode)) {
		if (FILE_RO_OPENFLAGS(fp) && FILE_PRIVATE(fp)->cache) {
			filerq->u.openrq.ro_cache_check = RO_CACHE_READONLY;
			filerq->u.openrq.ro_cache_cfp = fp;
		} else if (FILE_RW_OPENFLAGS(fp) || FILE_WO_OPENFLAGS(fp)) {
			filerq->u.openrq.ro_cache_check = RO_CACHE_WRITABLE;
		}
	}

	/* Lock inode if no write in progress. */
	down(&FILE_PRIVATE(fp)->write_sema);
	if (!FILE_PRIVATE(fp)->write) {
		up(&FILE_PRIVATE(fp)->write_sema);
		if (!IGNORE_INODE_SEMAPHORE(iip)) {
			mutex_lock(&ip->i_mutex);
			acquired_mutex = 1;
			iip->inode_lock_holder = current->pid;
		}
	} else
		up(&FILE_PRIVATE(fp)->write_sema);

	if (!FILE_PRIVATE(fp)->cache && INODE_CWC_FILES(ip) && S_ISREG(ip->i_mode) &&
	    !(SUPER_SFLAGS(ip) & MS_RDONLY)) {
		printk(KERN_ERR "DVS: %s: Inode is currently open "
		       "with write cache option enabled. There are potential "
		       "coherency issues if caching isn't enabled. File: %s "
		       "inode: %p\n", __func__, fpname(fp), ip);
	}

	/* Do special case handling for client write caching */
	if (FILE_PRIVATE(fp)->cache && !((SUPER_SFLAGS(ip) & MS_RDONLY)) &&
	    (S_ISREG(ip->i_mode))) {

		/* If there are open file instances of this inode flush out
		 * dirty cache pages before sending the open request so the
		 * server has the latest attrs from this node and the local
		 * state can be correctly synced with the server.  Except in
		 * retry, the initial open would have done the sync for correct
		 * coherency and we may be retrying for a writeback that is
		 * already holding page locks. */
		if (INODE_CWC_FILES(ip) && !FILE_PRIVATE(fp)->rip) {
			rval = filemap_write_and_wait(ip->i_mapping);
			if (rval < 0) {
				printk(KERN_ERR "DVS: %s: Failed writeback for "
					"inode %p %lu rval %d\n", __FUNCTION__,
					ip, ip->i_ino, rval);
				goto uopen_error;
			}
		}

		/* notify the server this is a write cached file open */
		filerq->u.openrq.wb_cache = 1;
	}

	rpsz = sizeof(struct file_reply) + (2 * filerq->u.openrq.dwfs_path_len);
	elapsed_jiffies = jiffies;
	if ((rval = send_multi_async_ipc_file_retry("uopen",
							fp,
							rf_array,
							rf_len,
							filerq,
							rsz,
							rpsz,
							&pna,
							&node_used)) < 0) {
		printk(KERN_ERR "DVS: send_multi_async_ipc_file_retry failed with %d\n", rval);
		goto uopen_error;
	}
	log_request(filerq->request, path, ip, NULL, rf_len, node_used,
		    jiffies - elapsed_jiffies);

	atomic64_add(rf_len, &iip->num_requests_open);

	KDEBUG_OFC(0, "About to fill in remote_file structs: fp %p rf %p "
			"rf_len %d data_rf %p data_rf_len %d meta_rf %p "
			"meta_rf_len %d\n",
			fp, FILE_PRIVATE(fp)->rf, FILE_PRIVATE(fp)->rf_len,
			FILE_PRIVATE(fp)->data_rf, FILE_PRIVATE(fp)->data_rf_len,
			FILE_PRIVATE(fp)->meta_rf, FILE_PRIVATE(fp)->meta_rf_len);

	/*
	 * Fill in open_file_info.remote_file[] structs.
	 */
	for (node = 0; node < rf_len; node++) {
		rf = &rf_array[node];

		frp = pna[node].reply;
		if (!frp)
			continue;
		if (frp->rval < 0) {
			KDEBUG_OFC(0, "DVS: uopen: got error from server %ld\n",
					frp->rval);
			rval = frp->rval;
			goto uopen_error;
		}

		remote_file_init(rf, &frp->u.openrp.rf, frp,
		                 (struct open_file_info *)fp->private_data);
		frp->rval = 0;

		if (FILE_DWFS(fp)) {
			if ((rval = create_dwfs_data_paths(fp,
			                        &frp->u.openrp.dwfs_info)) < 0) {
				printk(KERN_ERR "Could not initialize DWFS "
				       "data paths for file %s\n", fpname(fp));
				goto uopen_error;
			}
		}

		if ((rf->magic == NFS_SUPER_MAGIC) && rf_len > 1) {
			printk(KERN_ERR "DVS: %s: striping data across "
			       "multiple DVS servers is not supported "
			       "for NFS file systems (mount %s)\n",
			       __FUNCTION__, icsb->prefix);
			rval = -EACCES;
			goto uopen_error;
		}

		/* ro_cache response check */
		if ((FILE_PRIVATE(fp)->ro_cache) && (node == 0)) {
			down(&FILE_PRIVATE(fp)->rocache_sema);
			/* if file cache is already disabled another
			 * open raced us here or user disabled it,
			 * leave caching off.
			 */
			if (FILE_PRIVATE(fp)->cache)
				FILE_PRIVATE(fp)->cache = frp->u.openrp.ro_cache_check;
			up(&FILE_PRIVATE(fp)->rocache_sema);
		}

		KDEBUG_OFC(0, "DVS: uopen: got file handle 0x%p for "
			"local file 0x%p size %Ld nord %d\n",
			rf->file_handle.remote_ref,
			fp, frp->u.openrp.size,
		        node);
	}

	KDEBUG_OFC(0, "DVS: uopen: file blocksize for fp 0x%p set to %d for inode "
		   "0x%p\n", fp, FILE_PRIVATE(fp)->blocksize, ip);

	/* reset the reply to nord 0 to pick up proper attrs from lustre */
	frp = pna[0].reply;

	/*
	 * If the inode changed on the server, delete the dentry to force the
	 * kernel to do a lookup and fetch the inode info from the server.
	 * This updates the DVS attribute and data caching to provide
	 * close-to-open consistency.  The s_root check is included because the
	 * local mount point inode is always 1 and thus the i_ino check could
	 * always fail and cause an infinite loop. Skip this when 'noclusterfs'
	 * is specified as we don't expect inode numbers to match (etc.) across
	 * multiple file systems. Also skip when we're in tmpfs or autofs: see
	 * upermission and Bug 842634 for details.
	 */
	if (((ip->i_mode & S_IFMT) != (frp->u.openrp.inode_copy.i_mode & S_IFMT) ||
		ip->i_ino != frp->u.openrp.inode_copy.i_ino) &&
		!ignore_ino_mismatch(fp->f_path.dentry, ip)) {
		KDEBUG_OFC(0, "DVS: %s: deleting dentry 0x%p for inode 0x%p "
				"(%ld %ld %d %d), path %s\n", __FUNCTION__,
			fp->f_path.dentry, ip, ip->i_ino, frp->u.openrp.inode_copy.i_ino,
			ip->i_mode, frp->u.openrp.inode_copy.i_mode, path);
		delete_dentry = 1;
		goto uopen_error;
	}

	KDEBUG_OFC(0, "DVS: %s: updating inode 0x%p (%ld), path %s new size %lld\n",
			__FUNCTION__, ip, ip->i_ino, path,
			frp->u.openrp.inode_copy.i_size);

	/*
	 * Force a cache invalidate even if the remote mtime matches for 
	 * write-caching.  This user may have been the last writer but that
	 * doesn't mean all its data is current.  Also track opened write cache
	 * files for coherency management.
	 */
	if (!FILE_PRIVATE(fp)->rip && FILE_PRIVATE(fp)->cache && !(SUPER_SFLAGS(ip) & MS_RDONLY)) {
		inval = 1;
		INODE_INC_CWC_FILES(ip);
	} else {
		inval = 0;
	}

	update_inode(&frp->u.openrp.inode_copy, ip, fp->f_path.dentry, fp, inval);

	if (acquired_mutex) {
		iip->inode_lock_holder = 0;
		mutex_unlock(&ip->i_mutex);
	}

	rval = 0;

uopen_done:
	if (!private_data_allocated) {
		if (fp->private_data) {
			spin_lock(&icsb->lock);
			list_add(&FILE_PRIVATE(fp)->list, &icsb->open_files);
			spin_unlock(&icsb->lock);
		}
	}

	if (openrp)
		kfree(openrp);
	if (pna) {
		for (node = 0; node < rf_len; node++) {
			free_msg(pna[node].reply);
			free_msg(pna[node].request);
		}
		kfree(pna);
	}
	free_msg(filerq);
	free_page((unsigned long)bufp);
	return(rval);

uopen_error:
	/*
	 * Error in the middle of open - close any opened so far.
	 */
	if (acquired_mutex) {
		iip->inode_lock_holder = 0;
		mutex_unlock(&ip->i_mutex);
	}

	KDEBUG_OFC(0, "DVS: uopen: an error occurred (%d)\n", rval);

	if (urelease_common(ip, fp, 0)) {
		printk(KERN_ERR "DVS: uopen: urelease failure after uopen "
			"failure");
	}

	/* delete the dentry and return -ERESTARTSYS */
	if (delete_dentry) {
		struct dentry *dentry = fp->f_path.dentry;

		d_drop(dentry);
		set_tsk_thread_flag(current, TIF_SIGPENDING);
		rval = -ERESTARTSYS;
	}

	goto uopen_done;
}


/*
 * Open a file on single data server, on demand.
 * Deferred opens are not used on metadata files, those are
 * opened at first file open.
 */
static int deferred_uopen (struct inode *ip, struct file *fp, int nord)
{
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	int rval, rsz, node;
	struct inode_info *iip;
	struct remote_file *rf;
	unsigned long elapsed_jiffies;

	char *bufp = NULL, *path = NULL;

	iip = (struct inode_info *)ip->i_private;

	mutex_lock(&DATA_RF(fp, nord)->mutex);
	if (DATA_RF(fp, nord)->valid &&
		!DATA_RF(fp, nord)->quiesced) {
		/* race */
		rval = 0;
		goto deferred_uopen_done;
	}

	/*
	 * Set up the file_request structure
	 */
	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto deferred_uopen_done;
	}

	if (fp->f_path.dentry == NULL) {
		rval = -ENOENT;
		goto deferred_uopen_done;
	} else if (FILE_DWFS(fp)) {
		path = DATA_RF(fp, nord)->dwfs_data_path;
	} else {
		path = get_path(fp->f_path.dentry, fp->f_path.mnt, bufp, ip);
	}

	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		goto deferred_uopen_done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	if (!filerq) {
		rval = -ENOMEM;
		goto deferred_uopen_done;
	}
	filerq->request = RQ_OPEN;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->u.openrq.flags = fp->f_flags;
	set_is_flags(filerq, ip);

	if (FILE_DWCFS(fp)) {
		/* truncate is handled by VFS, doesn't need to be
		 * forwarded, O_EXCL done by create */
		filerq->u.openrq.flags &= ~(O_TRUNC|O_EXCL);
	}
	filerq->flags.is_dwcfs_stripe =
		(FILE_DWCFS(fp) && INODE_ICSB(ip)->data_stripe_width > 1 && !INODE_ICSB(ip)->loadbalance);

	strcpy(filerq->u.openrq.pathname, path);

	/* Create and open the DWFS data stripe files as root. The stripe files
	 * have 0 permissions to prevent users from opening the data stripe
	 * files directly, so we have to be root to do the open. */
	if (FILE_DWFS(fp))
		filerq->flags.root_ctx = 1;

        /*
         * Adjust some flags. If O_CREAT was specified on the initial open
	 * of the file, use it again for the deferred open. Also use O_CREAT
	 * if we're doing a deferred open of a DWFS data stripe. For the
	 * non-DWFS case, if a create was completed for this open file allow
	 * the server to do a dentry_open instead of a full open.  O_APPEND
	 * is unneccessary because write-append file position is handled on the
	 * client for dwfs and write-caching. We can't do a dentry_open for the
	 * DWFS case since we may have to create the data stripe.
         */
	if (FILE_PRIVATE(fp)->open_flags & O_CREAT || FILE_DWFS(fp)) {
		filerq->u.openrq.flags |= O_CREAT;
	}
	if (FILE_PRIVATE(fp)->d_open && !FILE_DWFS(fp)) {
		filerq->u.openrq.d_open = 1;
	}
	if ((FILE_DWFS(fp)) ||
	    (INODE_ICSB(ip)->cache && !(SUPER_SFLAGS(ip) & MS_RDONLY))) {
		filerq->u.openrq.flags &= ~O_APPEND;
	}
	if (FILE_DWFS(fp)) {
		filerq->u.openrq.flags &= ~O_ACCMODE;
		filerq->u.openrq.flags |= O_RDWR;
	}

	KDEBUG_OFC(0, "DVS: deferred_uopen: called ip 0x%p path %s flags 0x%x "
		   "freqflags 0x%x\n", ip, path, fp->f_flags,
		   filerq->u.openrq.flags);

	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerp) {
		rval = -ENOMEM;
		goto deferred_uopen_done;
	}

	elapsed_jiffies = jiffies;
	rval = send_ipc_file_retry("deferred_uopen",
					fp,
					FILE_PRIVATE(fp)->data_rf,
					FILE_PRIVATE(fp)->data_rf_len,
					nord,
					filerq,
					rsz,
					filerp,
					sizeof(struct file_reply),
					&node);
	if (rval < 0) {
		goto deferred_uopen_done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);

	if (filerp->rval < 0) {
		KDEBUG_OFC(0, "DVS: deferred_uopen: got error from server %ld\n",
				filerp->rval);
		rval = filerp->rval;
		goto deferred_uopen_done;
	} else {
		rval = 0;
	}

	rf = DATA_RF(fp, nord);

	remote_file_init(rf, &filerp->u.openrp.rf, filerp,
	                 (struct open_file_info *)fp->private_data);

	KDEBUG_OFC(0, "DVS: deferred_uopen: got file handle 0x%p for local file 0x%p "
		" nord %d path %s\n", rf->file_handle.remote_ref, fp, nord,
			filerq->u.openrq.pathname);

	/*
	 * Check the inode number to ensure the file on this open is still
	 * the same as the one originally opened. Skip this when 'noclusterfs'
	 * is specified as we don't expect inode numbers to match across
	 * multiple file systems. For DWFS, the deferred opens are done on the
	 * data stripe inodes. We don't expect these to match the MDS inode.
	 */
	if (FILE_DWFS(fp) || FILE_DWCFS(fp)) {
		KDEBUG_OFC(0, "DVS: deferred_uopen: deferred open for DWFS data "
		           "stripe file. MDS ino %lu, stripe ino %lu\n",
		           ip->i_ino, filerp->u.openrp.inode_copy.i_ino);
	} else if (INODE_ICSB(ip)->clusterfs &&
	           (filerp->u.openrp.inode_copy.i_ino != ip->i_ino)) {
		rval = -ENOENT;
		printk(KERN_INFO "DVS: %s: open() returned %d for %s (pid "
		       "%d), file %s removed before deferred open executed\n",
		       __FUNCTION__, rval, current->comm, current->pid, path);
	}

deferred_uopen_done:
	mutex_unlock(&DATA_RF(fp, nord)->mutex);

	KDEBUG_OFC(0, "DVS: deferred_uopen: %d\n", rval);

	if (bufp)
		free_page((unsigned long)bufp);
	if (filerq)
		free_msg(filerq);
	if (filerp)
		free_msg(filerp);
	return(rval);
}


static int uflush (struct file *fp, fl_owner_t id)
{
	int rval = 0, nord = 0, nnodes = 0, node;
	struct file_request *filerq = NULL;
	struct file_reply *frp = NULL;
	struct per_node *pna = NULL;
	unsigned long elapsed_jiffies;

	KDEBUG_OFC(0, "DVS: uflush: called\n");

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: uflush: called with NULL private_data\n");
		return -USIERR_INTERNAL;
	}

	if (FILE_PRIVATE(fp)->nokill_error)
		return -EHOSTDOWN;

	if (!META_RF(fp, 0)->flush_required) {
		return 0;
	}

	/*
	 * flush request not required for readonly file opens, we know that
	 * no info will have changed
	 */
	if (FILE_RO_OPENFLAGS(fp)) {
		return 0;
	}

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	if (!filerq) {
		return -ENOMEM;
	}
	filerq->request = RQ_FLUSH;
	filerq->retry = FILE_ICSB(fp)->retry;

	nnodes = FILE_PRIVATE(fp)->data_rf_len;

	elapsed_jiffies = jiffies;
	if ((rval = send_multi_async_ipc_file_retry("uflush",
						fp,
						FILE_PRIVATE(fp)->data_rf,
						FILE_PRIVATE(fp)->data_rf_len,
						filerq,
						sizeof(struct file_request),
						sizeof(struct file_reply),
						&pna,
						&node)) < 0) {
		goto uflush_done;
	}
	log_request(filerq->request, NULL, file_inode(fp), fp, nnodes,
		    node, jiffies - elapsed_jiffies);

	for (nord = 0; nord < nnodes; nord++) {
		if (!(frp = pna[nord].reply))
			continue;
		rval = frp->rval;
		if (rval < 0) {
			KDEBUG_OFC(0, "DVS: uflush: got error from server %d\n",
				rval);
			goto uflush_done;
		}
	}

uflush_done:
	if (pna) {
		for (nord = 0; nord < nnodes; nord++) {
			free_msg(pna[nord].reply);
			free_msg(pna[nord].request);
		}
		kfree(pna);
	}
	free_msg(filerq);
	return(rval);
}

static int urelease_common (struct inode *ip, struct file *fp, int retry)
{
	int nord = 0, nnodes = 0, rval = 0, ct = 0, node;
	struct file_request *filerq = NULL;
	struct file_reply *frp = NULL;
	struct inode_info *iip;
	struct per_node *pna = NULL;
	struct incore_upfs_super_block *icsb = ip->i_sb->s_fs_info;
	struct dentry *dent;
	struct ssi_server_info *server_info = NULL;
	struct remote_file *rf = NULL;
	unsigned long elapsed_jiffies;
	int acquired_mutex = 0;

	KDEBUG_OFC(0, "DVS: urelease: entered for fp 0x%p\n", fp);
	DVS_TRACEL("urelcomm", ip, fp, retry, NULL, NULL);

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: urelease: no inode info\n");
		return -USIERR_INTERNAL;
	}

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: urelease: called with NULL "
			"private_data\n");
		return -USIERR_INTERNAL;
	}

	/*
	 * Return EHOSTDOWN if this is a DVS-invoked release due to
	 * file_ops_retry.  Otherwise, let it finish normally as it is
	 * the last close of a file from userspace and we need to clean
	 * up the DVS-allocated resources on the server(s) and client.
	 */
	if (FILE_PRIVATE(fp)->nokill_error && FILE_PRIVATE(fp)->rip)
		return -EHOSTDOWN;

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	if (!filerq) {
		return -ENOMEM;
	}

	/* Sync any cached write data to the server on close */
	if (!retry && FILE_PRIVATE(fp)->cache && !((SUPER_SFLAGS(ip) & MS_RDONLY))) {
		KDEBUG_OFC(0, "DVS: %s: writing back pages for inode 0x%p\n",
				__FUNCTION__, ip);
		rval = filemap_write_and_wait(ip->i_mapping);
		if (rval < 0)
			printk(KERN_ERR "DVS: %s: Failed to do writeback for "
				"inode %p %lu rval %d\n", __FUNCTION__, ip,
				ip->i_ino, rval);
		else
			KDEBUG_OFC(0, "DVS: %s: completed filemap_write_and_wait\n",
					__FUNCTION__);

		/* We could fail the close here to notify user of the sync
		 * failure but we may not want to strand open files if the wb
		 * server can't be reached. */
	}

retry_requests:
	/*
	 * Either readpage or readpages will be active at any given time so
	 * there's no potential for them to run together.
	 * Wait for outstanding page reads from either path at the moment.
	 */
	down(&FILE_PRIVATE(fp)->write_sema);
	if (!FILE_PRIVATE(fp)->write) {
		up(&FILE_PRIVATE(fp)->write_sema);
		if (!IGNORE_INODE_SEMAPHORE(iip)) {
			mutex_lock(&ip->i_mutex);
			acquired_mutex = 1;
			iip->inode_lock_holder = current->pid;
		}
	} else {
		up(&FILE_PRIVATE(fp)->write_sema);
	}

	/*
	 * If we're in retry mode (due to failover), we don't want to destroy
	 * anything - rather just close the file and move on with re-issuing
	 * the requests to a different server.
	 *
	 * Otherwise, we want to try and get as close as we can to free'ing
	 * the requests (which are really associated with the inode) when the
	 * inode is going idle.  Free them too early and there is the potential
	 * that somebody opened the file (library) and did a pages
	 * request only to see that their range was already requested.
	 * They could now be waiting on those pages (maybe even after closing
	 * the file?) and if we tear down the requests on the inode too early,
	 * we'd be invalidating the page they're waiting on.
	 *
	 * From earlier (inconclusive) testing, it appears that perhaps pages
	 * set with an error may be re-faulted back in if we'd marked them in
	 * error but it's best to play it safe and try and tear down any
	 * ones that are still waiting when the inode goes south.
	 *
	 * We do know for sure that this file instance (struct file) is going
	 * away so we need to scan the outstanding requests and locate any
	 * requests we issued with this file instance and reset the file
	 * pointers (client_fp in file_request and fp in the async_retry)
	 * structures.  We'll set them to another open file instance if we can
         * and let this file close or if we're the last one, NULL out our file
         * pointer and indicate that the file request shouldn't be retried if
	 * failover occurs.
	 */
	dent = fp->f_path.dentry;

	while (!retry && !list_empty(&iip->requests)) {
		int	dcount;
		int	rval;

		spin_lock(&dent->d_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#ifdef RHEL_RELEASE_CODE /* bug 823318 */
		dcount = atomic_read(&dent->d_count);
#else
		dcount = dent->d_count;
#endif
#else
		dcount = dent->d_lockref.count;
#endif
		spin_unlock(&dent->d_lock);

		/*
		 * Use the dcount as a heuristic to try and do the right thing.
		 * The worst that can happen is we tear down a pending request
		 * since it looked like the inode was going to be released only
		 * to have a new reference slip in.  If we cancelled the request
		 * and somebody was now waiting on the page, we'll error it as
		 * part of the cancel and unlock it and it should be re-faulted
		 * in after that waiter starts using the error'ed page.
		 */
		if (dcount == 1) {
			rval = cleanup_reqs(ip, CLUP_Forced);
		}
		else {
			rval = detach_file_from_reqs(fp);
		}
		if (rval == -EAGAIN) {
			if (acquired_mutex == 1) {
				acquired_mutex = 0;
				iip->inode_lock_holder = 0;
				mutex_unlock(&ip->i_mutex);
			}
			cond_resched();  /* burns up some time */
			goto retry_requests;
		}
                if ((dcount != 1/*detach*/) && rval) {
                   /*
                    * We detached this file from the pending requests so let
                    * this close happen.  We know the detach is only successful
                    * when the server is no longer using our file pointer for
                    * any outstanding operations.
                    */
                   break;
                }
	}

	/* used by the old ureadpage path */
	while ((retry == 0) && iip->oio) {
		if (acquired_mutex == 1) {
			acquired_mutex = 0;
			iip->inode_lock_holder = 0;
			mutex_unlock(&ip->i_mutex);
		}
		if (ct == 0) {
			KDEBUG_OFC(0, "DVS: urelease: waiting for page cache request\n");
			ct++;
		}
		cond_resched();
		if (!IGNORE_INODE_SEMAPHORE(iip)) {
			mutex_lock(&ip->i_mutex);
			acquired_mutex = 1;
			iip->inode_lock_holder = current->pid;
		}
	}

	/* Dec the count of open files for cache coherency controls */
	if (!retry && FILE_PRIVATE(fp)->cache && !((SUPER_SFLAGS(ip) & MS_RDONLY))) {
		INODE_DEC_CWC_FILES(ip);
	}

	if (acquired_mutex == 1) {
		acquired_mutex = 0;
		iip->inode_lock_holder = 0;
		mutex_unlock(&ip->i_mutex);
	}

	filerq->request = RQ_CLOSE;
	filerq->u.closerq.sync = FILE_PRIVATE(fp)->closesync && !FILE_PRIVATE(fp)->datasync;
	filerq->retry = INODE_ICSB(ip)->retry;
	nnodes = FILE_PRIVATE(fp)->rf_len;

	/* In RO_CACHE mode notify server to remove a cached file from the open
	 * list or for a writable file decrement the writecount
	 */
	if (FILE_PRIVATE(fp)->ro_cache) {
		if ((FILE_PRIVATE(fp)->open_flags & O_ACCMODE) == O_RDONLY) {
			filerq->u.closerq.ro_cache_check = RO_CACHE_READONLY;
			filerq->u.closerq.ro_cache_client_fp = fp;
		} else if (((FILE_PRIVATE(fp)->open_flags & O_ACCMODE) == O_RDWR) ||
		    ((FILE_PRIVATE(fp)->open_flags & O_ACCMODE) == O_WRONLY)) {
			filerq->u.closerq.ro_cache_check = RO_CACHE_WRITABLE;
		}
	}

	elapsed_jiffies = jiffies;
	if ((rval = send_multi_async_ipc_file_retry("urelease",
						fp,
						FILE_PRIVATE(fp)->rf,
						FILE_PRIVATE(fp)->rf_len,
						filerq,
						sizeof(struct file_request),
						sizeof(struct file_reply),
						&pna,
						&node)) < 0) {
		goto urelease_nearly_done;
	}
	log_request(filerq->request, NULL, ip, fp, nnodes, node,
		    jiffies - elapsed_jiffies);

	for (nord = 0; nord < nnodes; nord++) {
		if (!(frp = pna[nord].reply))
			continue;
		rval = frp->rval;
		if (rval < 0) {
			KDEBUG_OFC(0, "DVS: urelease: got error %ld from nord %d\n",
				frp->rval, nord);
			break;
		}
	}

urelease_nearly_done:

	for (nord = 0; nord < nnodes; nord++) {
		rf = &FILE_PRIVATE(fp)->rf[nord];

		/* Quiesced files are already closed */
		if (rf->quiesced)
			continue;

		if (node_map[rf->remote_node].server_info &&
		                 rf->finfo ==
		                 ((struct open_file_info *)fp->private_data) &&
		                 !list_empty(&DATA_RF(fp, nord)->list) &&
		                 rf->valid) {
			server_info = node_map[rf->remote_node].server_info;
			spin_lock(&server_info->lock);
			list_del_init(&rf->list);
			spin_unlock(&server_info->lock);
			if (unlikely(atomic_dec_return(&server_info->open_files) < 0))
				BUG();
		}
	}
	if (!FILE_PRIVATE(fp)->rip) {
		spin_lock(&icsb->lock);
		list_del(&FILE_PRIVATE(fp)->list);
		spin_unlock(&icsb->lock);
		atomic_dec(&icsb->open_dvs_files);
		dvsproc_stat_update(INODE_ICSB(ip)->stats, DVSPROC_STAT_OPEN_FILES,
				    0, -1);
		kfree_ssi(DATA_RF(fp, 0)->dwfs_data_path);
		kfree_ssi(FILE_PRIVATE(fp)->estale_nodes);
		kfree_ssi(fp->private_data);
		fp->private_data = NULL;
	} else {
		for (nord = 0; nord < nnodes; nord++) {
			FILE_RF(fp,nord)->file_handle.remote_ref = NULL;
			FILE_RF(fp,nord)->file_handle.key = 0;
			FILE_RF(fp,nord)->identity = 0;
			FILE_RF(fp,nord)->valid = 0;
		}
	}

	if (pna) {
		for (nord = 0; nord < nnodes; nord++) {
			free_msg(pna[nord].reply);
			free_msg(pna[nord].request);
		}
		kfree(pna);
	}
	free_msg(filerq);

	KDEBUG_OFC(0, "DVS: %s:  Completing. rval %d\n",
			__FUNCTION__, rval);

	return(rval);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static int ufsync (struct file *fp, struct dentry *de, int datasync)
#else
static int ufsync (struct file *fp, loff_t off1, loff_t off2, int datasync)
#endif
{
	int rval, nord, nnodes, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode_info *iip;
	struct per_node *pna = NULL;
	unsigned long elapsed_jiffies;

	KDEBUG_OFC(0, "DVS: ufsync: called\n");

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: ufsync: called with NULL private_data\n");
		return -USIERR_INTERNAL;
	}

	if (FILE_PRIVATE(fp)->nokill_error)
		return -EHOSTDOWN;

	iip = (struct inode_info *)file_inode(fp)->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ufsync: no inode info\n");
		return -USIERR_INTERNAL;
	}

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	if (filerq == NULL)
		return -ENOMEM;

	filerq->request = RQ_FSYNC;
	filerq->retry = FILE_ICSB(fp)->retry;
	filerq->u.fsyncrq.kind = datasync;

	if (FILE_ICSB(fp)->multi_fsync) {
		elapsed_jiffies = jiffies;
		nnodes = FILE_PRIVATE(fp)->data_rf_len;
		if ((rval = send_multi_async_ipc_file_retry("ufsync",
							fp,
							FILE_PRIVATE(fp)->data_rf,
							FILE_PRIVATE(fp)->data_rf_len,
							filerq,
							sizeof(struct file_request),
							sizeof(struct file_reply),
							&pna,
							&node)) >= 0) {
			log_request(filerq->request, NULL, file_inode(fp), fp,
				    nnodes, node, jiffies - elapsed_jiffies);
			for (nord = 0; nord < nnodes; nord++) {
				if (!(filerp = pna[nord].reply))
					continue;
				rval = filerp->rval;
				if (rval < 0) {
					KDEBUG_OFC(0, "DVS: %s: got error from server %d\n",
					           __func__, rval);
					break;
				}
			}
		}

		if (pna != NULL) {
			for (nord = 0; nord < nnodes; nord++) {
				free_msg(pna[nord].reply);
				free_msg(pna[nord].request);
			}
			kfree_ssi(pna);
		}
	} else {
		/* Only send the fsync to a single server */
		filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
		if (filerp == NULL) {
			free_msg(filerq);
			return -ENOMEM;
		}

		elapsed_jiffies = jiffies;
		rval = send_ipc_file_retry("ufsync",
						fp,
						FILE_PRIVATE(fp)->meta_rf,
						FILE_PRIVATE(fp)->meta_rf_len,
						0,
						filerq,
						sizeof(struct file_request),
						filerp,
						sizeof(struct file_reply),
						&node);
		if (rval >= 0) {
			log_request(filerq->request, NULL, file_inode(fp), fp,
				    1, node, jiffies - elapsed_jiffies);
		}
		if (rval < 0 || filerp->rval < 0) {
			KDEBUG_OFC(0, "DVS: %s: got error from server %d/%ld\n",
				   __func__, rval, filerp->rval);
		}
		free_msg(filerp);
	}

	free_msg(filerq);

	return(rval);
}

static int ufasync (int arg1, struct file *fp, int arg3)
{
	int rval, node;
	struct file_request *filerq=NULL;
	struct file_reply *filerp=NULL;
	unsigned long elapsed_jiffies;

	KDEBUG_OFC(0, "DVS: ufasync: called\n");

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: ufasync: called with NULL "
			"private_data\n");
		return -USIERR_INTERNAL;
	}

	if (FILE_PRIVATE(fp)->nokill_error)
		return -EHOSTDOWN;

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		return -ENOMEM;
	}
	filerq->request = RQ_FASYNC;
	filerq->retry = FILE_ICSB(fp)->retry;
	filerq->u.fasyncrq.arg = arg3;

	elapsed_jiffies = jiffies;
	rval = send_ipc_file_retry("ufasync",
					fp,
					FILE_PRIVATE(fp)->meta_rf,
					FILE_PRIVATE(fp)->meta_rf_len,
					0,
					filerq,
					sizeof(struct file_request),
					filerp,
					sizeof(struct file_reply),
					&node);
	if (rval >= 0)
		log_request(filerq->request, NULL, file_inode(fp), fp, 1,
			    node, jiffies - elapsed_jiffies);
	if (rval < 0 || filerp->rval < 0) {
		KDEBUG_OFC(0, "DVS: ufasync: got error from server %d/%ld\n",
			   rval, filerp->rval);
	}

	free_msg(filerq);
	free_msg(filerp);
	return(rval);
}

#define DVS_MAX_LOCK_RETRIES 10

/*
 * posix_lock_file_wait() with a retry loop around it should the kernel
 * return -ERESTARTSYS.  If we hit DVS_MAX_LOCK_RETRIES (unlikely), bail
 * out to avoid a potential infinite loop.
 */
static inline int posix_lock_file_wait_retry(struct file *fp,
					     struct file_lock *fl)
{
	int rval = 0, retry = 0;

	do {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
		rval = posix_lock_file_wait(fp, fl);
#else
		rval = locks_lock_file_wait(fp, fl);
#endif
	} while ((rval == -ERESTARTSYS) && (retry++ < DVS_MAX_LOCK_RETRIES));


	if (rval)
		DVS_TRACEL("lockf", fp, fl, rval, retry, 0);

	return rval;
}

static int ulock (struct file *fp, int cmd, struct file_lock *fl)
{
	int rval, retry=0, node;
	struct file_request *filerq=NULL;
	struct file_reply *filerp=NULL;
	struct flock lk;
	struct inode *ip = file_inode(fp);
	unsigned long elapsed_jiffies;

	/*
	* pfs discretionary file locking is implemented by forwarding all lock
	* request to nord 0 for the parallel file.  While not all of the file
	* data exists on nord 0, all of the locking info can.
	*/
	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: ulock: called with NULL private_data\n");
		return -USIERR_INTERNAL;
	}
	KDEBUG_OFC(0, "DVS: ulock: called\n");

	if (FILE_PRIVATE(fp)->nokill_error) {
		return -EHOSTDOWN;
	}
	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		/* Do client unlock even if we can't do server unlock. */
		if (fl->fl_type == F_UNLCK) {
			(void) posix_lock_file_wait_retry(fp, fl);
		}
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_LOCK;
	filerq->retry = INODE_ICSB(ip)->retry;

	/*
	* convert from file_lock to flock
	* whence can be 0 as start is absolute
	*/
	lk.l_type = fl->fl_type;
	lk.l_whence = 0;
	lk.l_start = fl->fl_start;
	if (fl->fl_end == OFFSET_MAX) {
		lk.l_len = 0;
	}
	else {
		lk.l_len = fl->fl_end - fl->fl_start + 1;
	}
	lk.l_pid = current->tgid;
	filerq->u.lockrq.lock = lk;
	filerq->u.lockrq.cmd = cmd;

	/*
	* Acquire local lock before sending request to server.  We don't want
	* to get a lock on the server and then fail to get it on the client due
	* to races.
	*/
	if ((cmd != F_GETLK) && (lk.l_type != F_UNLCK)) {
		rval = posix_lock_file_wait_retry(fp, fl);
		if (rval != 0) {
			KDEBUG_OFC(0, "DVS: ulock: client posix_lock_file_wait"
			"(0x%p, 0x%p) returned %d\n", fp, fl, rval);
			goto done;
		}
	}

	/*
	* Since ulseek() doesn't send all lseek operations to the server
	* node, we add f_pos to the lock request to ensure locks with
	* a l_whence of SEEK_CUR work correctly.
	*/
	filerq->u.lockrq.f_pos = fp->f_pos;

	set_is_flags(filerq, ip);

	do {
		elapsed_jiffies = jiffies;
		rval = send_ipc_file_retry("ulock",
						fp,
						FILE_PRIVATE(fp)->meta_rf,
						FILE_PRIVATE(fp)->meta_rf_len,
						0,
						filerq,
						sizeof(struct file_request),
						filerp,
						sizeof(struct file_reply),
						&node);
		if (rval >= 0) {
			log_request(filerq->request, NULL, ip, fp, 1, node,
				    jiffies - elapsed_jiffies);
		}
		if (rval < 0) {
			/*
			* Do client unlock even if server unlock failed.
			* Drop the local lock if the server request failed
			*/
			if ((cmd != F_GETLK) && (fl->fl_type != F_UNLCK)) {
				fl->fl_type = F_UNLCK;
			}
			if (fl->fl_type == F_UNLCK) {
				(void) posix_lock_file_wait_retry(fp, fl);
			}
		} else if (filerp->rval < 0) {
			KDEBUG_OFC(0, "DVS: ulock: got error from server %ld\n",
				filerp->rval);
			rval = filerp->rval;
			/*
			* Do client unlock even if server unlock failed, 
			* unless the server returned ERESTARTSYS - then
			* return ERESTARTSYS an let the kernel call ulock()
			* to try everything again.
			*/
			if (fl->fl_type == F_UNLCK) {
				if (rval != -ERESTARTSYS) {
					(void) posix_lock_file_wait_retry(fp, fl);
				}
			}
				/*
				* Drop the local lock before returning error 
				* if it could not be acquired on the server
				*/
			else {
				if (cmd != F_GETLK) {
					fl->fl_type = F_UNLCK;
					(void) posix_lock_file_wait_retry(fp, fl);
				}
			}
		} else {
			if (cmd == F_GETLK) {
				fl->fl_type = filerp->u.lockrp.rlock.l_type;
				fl->fl_pid = filerp->u.lockrp.rlock.l_pid;
				if (fl->fl_type != F_UNLCK) {
					fl->fl_start = 
						filerp->u.lockrp.rlock.l_start;
					if (filerp->u.lockrp.rlock.l_len == 0) {
						fl->fl_end = OFFSET_MAX;
					}
					else {
						fl->fl_end = 
						filerp->u.lockrp.rlock.l_start +
						filerp->u.lockrp.rlock.l_len - 1;
					}
 				}
		} else {
			/*
			* The lock is created/removed on the client node as
			* well as on the the server node because the kernel
			* does not call the vfs layer to remove posix locks
			* at file close unless f_path.dentry->d_inode->i_flock is
			* set.  We have to use real locks instead of just
			* plugging in a temporary non-NULL value into i_flock
			* because multiple files can be referencing the same
			* inode, and there's no good way to make that safe.
			* F_[RD|WR]LCK are handled above.  Do client unlock
			* if everything else was successful.
			*/
			if (fl->fl_type == F_UNLCK) {
				rval = posix_lock_file_wait_retry(fp, fl);
				if (rval != 0 && 
					!fatal_signal_pending(current) &&
					!(current->flags & PF_EXITING)) {
					printk(KERN_ERR "DVS: ulock: "
					"posix_lock_file_wait(0x%p, 0x%p) returned "
					"%d\n", fp, fl, rval);
				}
			}
		}
		rval = filerp->rval;
		}
		cond_resched(); /* kill some time */
		retry++;
	} while (((rval == -ERESTARTSYS) || (rval == -EAGAIN)) && 
		(retry < DVS_MAX_LOCK_RETRIES));

done:
	free_msg(filerq);
	free_msg(filerp);
	return(rval);
}

/* BSD-style file locking is not supported at this time. */
static int uflock (struct file *fp, int cmd, struct file_lock *fl)
{
	return(-ENOTSUPP);
}

#ifdef UNUSED
/* NOTE: readv/writev NOT CURRENTLY USED */
static ssize_t ureadv (struct file *fp, const struct iovec *iovp, unsigned long count, loff_t *off)
{
	return((ssize_t)-ENOTSUPP);
}

/* NOTE: readv/writev NOT CURRENTLY USED */
static ssize_t uwritev (struct file *fp, const struct iovec *iovp, unsigned long count, loff_t *off)
{
	return((ssize_t)-ENOTSUPP);
}
#endif

/*
 * ========================================================
 */

static pages_request_t *init_pages_request(int num_freqs)
{
	pages_request_t *pagesrq;
	int size;

	size = sizeof(pages_request_t) + (num_freqs * sizeof(freq_instance_t));

	pagesrq = kmalloc_ssi(size, GFP_KERNEL);
	if (!pagesrq)
		return NULL;

	pagesrq->num_freqs = num_freqs;
	INIT_LIST_HEAD(&pagesrq->rq_list);

	atomic64_set(&pagesrq->xfer_count, 0);
	atomic64_set(&pagesrq->xfer_maxoff, 0);
	atomic64_set(&pagesrq->xfer_error, 0);

	atomic_set(&pagesrq->msgs_outstanding, 0);  /* process_extent() sets */
	atomic_set(&pagesrq->rq_msg_waiters, 0);
	sema_init(&pagesrq->rq_msg_sema, 0);
	sema_init(&pagesrq->writepages_sema, 0);

	atomic_set(&pagesrq->rq_read_waiters, 0);
	sema_init(&pagesrq->rq_read_sema, 0);

	return pagesrq;
}

static int uwritepage(struct page *pagep, struct writeback_control *wbc)
{
	pages_request_t *rq;
	pages_desc_t *pagesd;
	loff_t size;
	struct inode *inode = pagep->mapping->host;
	struct inode_info *iip = (struct inode_info *)inode->i_private;
	int len, rval = 0;

	KDEBUG_OFC(0, "DVS: %s: called: page: 0x%p index %lu\n", __FUNCTION__, pagep,
			pagep->index);

	/* if last file page isn't full only write out the valid data */
	size = i_size_read(inode);
	if (pagep->index == (size >> PAGE_CACHE_SHIFT))
		len = size & ~PAGE_CACHE_MASK;
	else
		len = PAGE_CACHE_SIZE;

	pagesd = kmalloc_ssi(sizeof(pages_desc_t), GFP_KERNEL); //GFP_NOFS??
	if (!pagesd) {
		rval = -ENOMEM;
		goto done;
	}

	atomic_set(&pagesd->ref_count, 1); 
	atomic_set(&pagesd->state, RPS_PGSD_INUSE);

	pagesd->pages = kmalloc_ssi(sizeof(struct page *), GFP_KERNEL);
	if (!pagesd->pages) {
		rval = -ENOMEM;
		goto done;
	}

	pagesd->pages[0] = pagep;

	/* Create a page_req to pass to proc_extent. Use 2 freqs just in case
	 * page happens to split a block somehow. */
	rq = init_pages_request(2);
	if (!rq) {
		rval = -ENOMEM;
		goto done;
	}

	rq->ip = inode;
	rq->fp = iip->wb_fp; /* get inode stashed by write_begin */
	rq->wbc = wbc;

	rq->offset = pagep->index * PAGE_SIZE;
	rq->length = len;

	rq->pagesd = pagesd;

	rq->ext_indx = 0;
	rq->ext_count = 1;

	atomic_inc(&pagesd->ref_count); /* ref for the request */
	atomic_set(&rq->state, RPS_RQ_ACTIVE);

	rq->rq_flags |= PIO_RQ_FLAGS_WRITEPAGE;

	/* local page ref cleaned up by process_iovs */
	page_cache_get(pagep);

	/* mark the page as under writeback IO before sending the request */
	set_page_writeback(pagep);

	down_write(&iip->requests_sem);

	list_add_tail(&rq->rq_list, &iip->requests); /* failover list */

	rval = process_extent(rq->fp, rq);
	if (rval < 0) {
		KDEBUG_OFC(0, "DVS: %s: process_extent failure %d\n", __FUNCTION__,
				rval);
		up_write(&iip->requests_sem);

		/* process_extent will do all page cleanup on error */
		goto done;
	}

	up_write(&iip->requests_sem);

	/*
	 * Server requests sent successfully.  Wait for all server replies to
	 * return before completing so that writepages_rp can do wbc accounting
	 */
	down(&rq->writepages_sema);

	/* all msgs returned - mark page_req expired */
	(void) finalize_request(rq);

done:
	if (pagesd && !atomic_dec_return(&pagesd->ref_count)) {
		if (pagesd->pages) {
			kfree_ssi(pagesd->pages);
		}

		atomic_set(&pagesd->state, RPS_PGSD_FREE);
		kfree_ssi(pagesd);
	}

	KDEBUG_OFC(0, "DVS: %s: uwritepage exiting: %d\n", __FUNCTION__, rval);

	return rval;
}

static int do_write_extent(extent_t *ep, struct inode *ip, pages_desc_t *pagesd,
		struct writeback_control *wbc)
{
	pages_request_t *pagesrq;
	loff_t index;
	loff_t size;
	size_t len;
	int i, freq_count, rval = 0;
	struct file *fp;
	size_t blksz;

	struct inode_info *iip = (struct inode_info *)ip->i_private;
	fp = iip->wb_fp;
	if (!fp)
		BUG();

	if (FILE_DWFS(fp))
		blksz = FILE_PRIVATE(fp)->blocksize;
	else
		blksz = max_transport_msg_size;

	/*
	 * Calculate number of blocks to know how many freqs must be tracked.
	 * This is the number of 'msgs' sent by process_extent. The extra 1 is
	 * to account for an unaligned request splitting two blocks.
	 */
	freq_count = (((ep->count * PAGE_SIZE) + blksz - 1) / blksz) + 1;
	if (freq_count > FILE_PRIVATE(fp)->data_rf_len)
		freq_count = FILE_PRIVATE(fp)->data_rf_len;

	pagesrq = init_pages_request(freq_count);
	if (!pagesrq) {
		rval = -ENOMEM;
		goto error;
	}

	index = pagesd->pages[ep->indx]->index; /* index of extents 1st page */

	/* check if final page in extent is incomplete page */
	size = i_size_read(ip);
	if ((index + ep->count - 1) == (size >> PAGE_CACHE_SHIFT))
		len = size & ~PAGE_CACHE_MASK;
	else
		len = PAGE_CACHE_SIZE;

	/* calculate total length:  initial full pages + final page */
	len += (ep->count - 1) * PAGE_CACHE_SIZE;

	KDEBUG_OFC(0, "DVS: %s: ep indx %d ep count %d pagesrq 0x%p index %lld len"
		" %lu pagesd 0x%p ep 0x%p ip 0x%p size %lld wbc 0x%p\n",
		__FUNCTION__, ep->indx, ep->count, pagesrq, index, len, pagesd,
		ep, ip, size, wbc);

	DVS_TRACEL("dowrext", ep, ip, wbc, pagesrq, pagesd);
	DVS_TRACEL("dowrext+", ep->indx, ep->count, index, len, size);

	/* a zero length file with dirty pages indicates an incoherency between
	 * file size and dirty page handling.  Error out. */
	if (len == 0) {
		printk(KERN_ERR "DVS: %s: zero length write_extent request. "
			"inode %p wbc %p index %Ld count %d\n", __FUNCTION__,
			ip, wbc, index,	ep->count);
		rval = -EFAULT;

		/* pagesrq not made active yet.  Free it now. */
		kfree_ssi(pagesrq);

		goto error;
	}

	pagesrq->ip = ip;
	pagesrq->fp = iip->wb_fp; /* stashed by write_begin */
	pagesrq->wbc = wbc;

	pagesrq->offset = index * PAGE_CACHE_SIZE; /* real offset into file */
	pagesrq->length = len;
	pagesrq->pagesd = pagesd;
	pagesrq->ext_indx = ep->indx;
	pagesrq->ext_count = ep->count;

	atomic_inc(&pagesd->ref_count);  /* page requests reference */
	atomic_set(&pagesrq->state, RPS_RQ_ACTIVE);

	pagesrq->rq_flags |= PIO_RQ_FLAGS_WRITEPAGE;

	/* lock requests list, add to failover list, and send */
	down_write(&iip->requests_sem);

	list_add_tail(&pagesrq->rq_list, &iip->requests);

	rval = process_extent(pagesrq->fp, pagesrq);
	if (rval < 0) {
		KDEBUG_OFC(0, "DVS: %s: process_extent failure %d\n", __FUNCTION__,
				rval);
		/* process_extent will clean up the pages, just return */
		pagesrq = NULL;
	}

	ep->pagesrq = pagesrq;

	up_write(&iip->requests_sem);

	return rval;

error:
	/* cleanup all the pages in the extent that failed to send */ 
	for (i = 0; i < ep->count; i++) {
		if (rval == -EAGAIN)
			redirty_page_for_writepage(wbc,
					pagesd->pages[ep->indx + i]);
		else
			SetPageError(pagesd->pages[ep->indx + i]);

		end_page_writeback(pagesd->pages[ep->indx + i]);
		unlock_page(pagesd->pages[ep->indx + i]);

		page_cache_release(pagesd->pages[ep->indx + i]);
	}

	ep->count = 0;
	ep->pagesrq = NULL;

	if (rval == -EAGAIN)
		rval = 0;
	else
		mapping_set_error(pagesd->pages[ep->indx]->mapping, rval);

	return rval;
}

/*
 * Write caching page writeback function.  Writes back pages using large RMA
 * transfers of contiguous page ranges.  Individual page handling logic based
 * on Linux Kernel generic write_pages function write_cache_pages.
 */  
static int
uwritepages(struct address_space *mapping, struct writeback_control *wbc)
{
	int rval = 0;
	int done = 0;
	unsigned nr_pages;
	unsigned long npages;
	pgoff_t uninitialized_var(wb_index);
	pgoff_t index;
	pgoff_t end;
	pgoff_t done_index;
	pgoff_t prev_index = -1;
	int new_extent;
	int cycled;
	int range_whole = 0;
	int tag;

	pages_desc_t *pagesd = NULL;
	struct inode *ip = mapping->host;

	extent_t *extents = NULL;
	extent_t *ep = NULL;
	int extent_count = 1;
	int extents_alloc = DEFAULT_EXTENTS;

	KDEBUG_OFC(0, "DVS: %s: called. map 0x%p nr_to_write %ld start %lld end %lld"
			" tagged %u rc %u mode %d map nrpages %lu wbc 0x%p\n",
			__FUNCTION__, mapping, wbc->nr_to_write, wbc->range_start,
			wbc->range_end, wbc->tagged_writepages, wbc->range_cyclic,
			wbc->sync_mode, mapping->nrpages, wbc);

	DVS_TRACEL("uwpages", mapping, wbc, wbc->range_start, wbc->range_end,
			wbc->sync_mode);

	if (wbc->range_cyclic) {
		wb_index = mapping->writeback_index; /* prev offset */
		index = wb_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
		npages = mapping->nrpages;
	} else {
		index = wbc->range_start >> PAGE_CACHE_SHIFT;
		end = wbc->range_end >> PAGE_CACHE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		cycled = 1; /* ignore range_cyclic tests */

		if (range_whole)
			npages = mapping->nrpages;
		else
			npages = (end - index) + 1; /* inclusive */
	}

	/* Prevent allocation of an unnecessarily large number of pages */
	if (npages > wb_threshold_pages)
		npages = wb_threshold_pages; /* 8Mb worth of pages to match the wb size */

	pagesd = kmalloc_ssi(sizeof(pages_desc_t), GFP_KERNEL);
	if (!pagesd) {
		rval = -ENOMEM;
		goto done;
	}

	atomic_set(&pagesd->ref_count, 1);
	atomic_set(&pagesd->state, RPS_PGSD_INUSE);

	pagesd->pages = kmalloc_ssi(npages * sizeof(struct page *), GFP_KERNEL);
	if (!pagesd->pages) {
		rval = -ENOMEM;
		goto done;
	}

	extents = kmalloc_ssi(sizeof(extent_t) * DEFAULT_EXTENTS, GFP_KERNEL);
	if (!extents) {
		rval = -ENOMEM;
		goto done;
	}

	/* init an empty extent */
	ep = &extents[0];
	ep->count = 0;
	new_extent = 1;

	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;

retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, index, end);

	done_index = index;

	while (!done && (index <= end)) {
		int i;

		KDEBUG_RPS(0, "DVS: %s: map 0x%p wbc 0x%p ext 0x%p ep 0x%p index %lu <= "
			"end %lu done %lu\n", __FUNCTION__, mapping, wbc,
			extents, ep, index, end, done_index);

		nr_pages = find_get_pages_tag(mapping, &index, tag,
				npages, pagesd->pages);
		if (nr_pages == 0)
			break;

		KDEBUG_RPS(0, "DVS: %s: map 0x%p wbc 0x%p ext 0x%p ep 0x%p index %lu "
			"end %lu nr_pages %u\n", __FUNCTION__, mapping, wbc,
			extents, ep, index, end, nr_pages);

		/*
		 * process each dirty or tagged page and create extents of
		 * contiguous page ranges
		 */
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pagesd->pages[i];

			/* don't let the list run beyond the page array size */
			BUG_ON(i >= npages);

			if (page->index > end) {
				/*
				 * can't be range_cyclic (1st pass) because
				 * end == -1 in that case.
				 */
				page_cache_release(page);

				done = 1;
				break;
			}

			done_index = page->index;

			lock_page(page);

			/* page truncated or invalidated.  skip it */
			if (unlikely(page->mapping != mapping)) {
continue_unlock:
				unlock_page(page);
				page_cache_release(page);
				continue;
			}

			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (PageWriteback(page)) {
				if (wbc->sync_mode != WB_SYNC_NONE)
					wait_on_page_writeback(page);
				else
					goto continue_unlock;
			}

			BUG_ON(PageWriteback(page));

			/* clear_page_dirty_for_io leaves a page marked clean
			 * but tagged dirty in the radix tree.  This must be
			 * cleaned up by running set/end_page_writeback or
			 * redirty_page_for_writepage beyond this point. */
			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			/*
			 * We have a locked dirty page now.  Add to extent
			 * and mark it under writeback
			 */
			set_page_writeback(page);

			if((!new_extent) && (prev_index != (page->index - 1))) {

				/* check if extents are exhausted.
				 * extent_count points to the next one */
				if (extent_count == extents_alloc) {
					extent_t *new_extents;

					extents_alloc += DEFAULT_EXTENTS;
					new_extents = krealloc(extents,
						sizeof(extent_t) * extents_alloc,
						GFP_KERNEL);
					if (!new_extents) {
						printk(KERN_ERR "DVS: %s: extent"
							" krealloc failed. ip 0x%p"
							" wbc 0x%p map 0x%p page"
							" 0x%p\n", __FUNCTION__,
							ip, wbc, mapping, page);

						extents_alloc -= DEFAULT_EXTENTS;
						rval = -ENOMEM;

						SetPageError(page);
						mapping_set_error(page->mapping,
								rval);
						end_page_writeback(page);
						unlock_page(page);
						page_cache_release(page);

						done = 1;
						break;
					}

					extents = new_extents;
					ep = &extents[extent_count - 1];
				}

				/* Current page is not contiguous, we have a
				 * completed extent.  Send it to server */
				rval = do_write_extent(ep, ip, pagesd, wbc);
				if (rval < 0) {
					/* Write failed. Handle outstanding 
					 * reqs and quit */
					printk(KERN_ERR "DVS: %s: extent write "
						"failed. rval %d ip 0x%p ep 0x%p "
						"wbc 0x%p map 0x%p page 0x%p\n",
						__FUNCTION__, rval, ip, ep, wbc,
						mapping, page);

					SetPageError(page);
					mapping_set_error(page->mapping, rval);
					end_page_writeback(page);
					unlock_page(page);
					page_cache_release(page);

					done_index = page->index + 1;

					done = 1;
					break;
				}

				/* move to next extent */
				ep = &extents[extent_count++];
				ep->count = 0;
				new_extent = 1;
			}

			if (new_extent) {
				ep->indx = i; /* page array offset */
				new_extent = 0;
			}

			ep->count++;
			prev_index = page->index;
		} /* nr_pages loop */

		/* send last extent now that all pages processed if it exists */
		if (ep->count != 0) {
			rval = do_write_extent(ep, ip, pagesd, wbc);
			if (rval < 0) {
				printk(KERN_ERR "DVS: %s: last extent write "
					"failed. rval %d ip 0x%p ep 0x%p wbc 0x%p "
					"map 0x%p i %d\n", __FUNCTION__, rval,
					ip, ep, wbc, mapping, i);
				done = 1;
			}
		}

		/* drop page refs on any find_get_pages_tag pages not used */
		for (i = i + 1; i < nr_pages; i++) {
			page_cache_release(pagesd->pages[i]);
		}

		/* server requests sent successfully.  Wait for all server
		 * replies for all sent extents to return before completing
		 * so that writepages_rp can do wbc accounting */
		for (i = 0; i < extent_count; i++) {
			pages_request_t *prq = extents[i].pagesrq;
			ep = &extents[i];
			if ((prq) && (ep->count)) {
				DVS_TRACEL("uwpwait", prq, ip, wbc, 0, 0); 
				down(&prq->writepages_sema);

				/* all msgs returned - mark page_req expired */
				(void) finalize_request(prq);

				/* reset completed extent */
				ep->count = 0;
			}
		}

		/* reset extent array to be reused in case of more work */
		extent_count = 1;
		ep = &extents[0];
		new_extent = 1;

		/* all requests have returned. wbc has been updated by 
		 * dvs_rq_writepages_rp/process_iovs with server info */
		if ((wbc->nr_to_write <= 0) &&
				(wbc->sync_mode == WB_SYNC_NONE)) {
			done = 1;
			break;
		}

		cond_resched();
	} /*  index loop */
			
	if (!cycled && !done) {
		/* range_cyclic:  hit last page.  wrap back to file start */
		cycled = 1;
		index = 0;
		end = wb_index - 1;
		goto retry;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

done:

	if (extents) {
		kfree_ssi(extents);
	}

	if (pagesd && !atomic_dec_return(&pagesd->ref_count)) {
		if (pagesd->pages) {
			kfree_ssi(pagesd->pages);
		}
		atomic_set(&pagesd->state, RPS_PGSD_FREE);
		kfree_ssi(pagesd);
	}

	return rval;
}

/*
 * DEPRECATED 06/2014   Leave in for a while as live code which could
 * be enabled via a patch in the field in case things go horribly wrong
 * with the new ureadpages stuff.
 *
 * 05/2015 this I/O path is now incompatible with ureadpages and its new
 * failover strategy and will be removed shortly.
 */
static int __attribute__ ((unused))
ureadpage_old(struct file *fp, struct page *pagep)
{
	int rval=0, nord, rlen, node, node_used;
	loff_t offset, blk_offset;
	struct file_request *filerq = NULL;
	struct inode_info *iip;
	struct inode *ip;
	struct outstanding_io *found, *iop = NULL;
	struct outstanding_page *opp;
	struct async_retry *p, *aretry = NULL;
	struct list_head *lp, *tp;

	ip = file_inode(fp);
	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ureadpage: has no inode info\n");
		SetPageError(pagep);
		unlock_page(pagep);
		return(-USIERR_INTERNAL);
	}

	if (fp->private_data == NULL) {
		printk(KERN_ERR "DVS: ureadpage: called with NULL "
			"private_data\n");
		SetPageError(pagep);
		unlock_page(pagep);
		return(-USIERR_INTERNAL);
	}

	if (FILE_PRIVATE(fp)->nokill_error) {
		SetPageError(pagep);
		unlock_page(pagep);
		return(-EHOSTDOWN);
	}

	iip->fp = fp;	/* used in RQ_READPAGE_DATA */
	rlen = FILE_PRIVATE(fp)->blocksize;

	/* compute the file offset for this page */
	offset = (loff_t)pagep->index << PAGE_CACHE_SHIFT;
	blk_offset = (offset / rlen) * rlen;

	KDEBUG_RPS(0, "DVS: %s: cpu %d file 0x%p offset %Ld inode size %Ld\n",
		__FUNCTION__, raw_smp_processor_id(), fp, offset,
		file_inode(fp)->i_size);

	nord = get_nord_for_offset(fp, blk_offset, rlen);

	if (!DATA_RF(fp, nord)->valid) {
		rval = deferred_uopen(ip, fp, nord);
		if (rval < 0) {
			SetPageError(pagep);
			unlock_page(pagep);
			return(rval);
		}
	}

/* could be a mount option */
/* MUST NOT EXCEED MAX MESSAGE SIZE (regardless of stripe size) */
#define PREFETCH ((MAX_MSG_SIZE-sizeof(struct file_request)) & PAGE_MASK)

	/* read max of (stripe size, PREFETCH) */
	/* MUST NOT EXCEED MAX MESSAGE SIZE (regardless of stripe size) */
        if (rlen > PREFETCH)
                rlen = PREFETCH;

	opp = kmalloc_ssi(sizeof(*opp), GFP_KERNEL);
	if (!opp) {
		SetPageError(pagep);
		unlock_page(pagep);
		return -ENOMEM;
	}
	opp->pagep = pagep;
	opp->next = NULL;
        DVS_TRACEL("RPgReqst", ip, offset, PAGE_SIZE, opp, 1);

	down(&iip->oio_sema);
	/* check for the page in the outstanding io list */
	iop = iip->oio;
	found = NULL;
	while (iop) {
		if ((offset >= iop->offset) && (offset < (iop->offset + iop->length))) {
			found = iop;
			break;
		}
		iop = iop->next;
	}
	if (found) {
		/* add page to list waiting for the i/o */
		KDEBUG_RPS(0, "DVS: %s found oio: 0x%p %Ld %d\n",
			__FUNCTION__, found, offset, rlen);
		opp->next = found->op;
		found->op = opp;
		up(&iip->oio_sema);
		return(0);
	} else {
		iop = kmalloc_ssi(sizeof(*iop), GFP_KERNEL);
		if (!iop) {
			up(&iip->oio_sema);
			rval = -ENOMEM;
			goto error;
		}
		found = iop;
		KDEBUG_RPS(0, "DVS: %s create oio: 0x%p %Ld %d\n",
			__FUNCTION__, iop, offset,
			rlen);
		iop->offset = offset;
		iop->length = rlen;
		iop->op = opp;
		iop->next = iip->oio;
		iip->oio = iop;
	}
	up(&iip->oio_sema);

	filerq = kmalloc_ssi(sizeof(struct file_request), GFP_KERNEL);
	if (!filerq) {
		rval = -ENOMEM;
		goto error;
	}
	filerq->request = RQ_READPAGE_ASYNC;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->client_fp = fp;
	filerq->u.readpagerq.offset = offset;
	filerq->u.readpagerq.count = rlen;
	filerq->u.readpagerq.iop = found;
	filerq->u.readpagerq.iip = iip;
	filerq->u.readpagerq.csize = ip->i_size;
	filerq->file_handle = DATA_RF(fp,nord)->file_handle;
	capture_context((&filerq->context));

	/* Add to async retry list */
	aretry = kmalloc_ssi(sizeof(struct async_retry), GFP_KERNEL);
	if (!aretry) {
		rval = -ENOMEM;
		goto error;
	}
	aretry->fp = fp;
	INIT_LIST_HEAD(&aretry->list);
	aretry->ar_status = AR_Default;
	aretry->ar_nord = nord;
	aretry->ar_node = node = DATA_RF(fp, nord)->remote_node;
	aretry->filerq = filerq;
	aretry->rqsz = sizeof(struct file_request);
	aretry->readpage.iip = iip;
	aretry->readpage.op = found;
	aretry->readpage.page = pagep;

	down(&aretrysem[node]);
	list_add_tail(&aretry->list, &alist[node]);
	up(&aretrysem[node]);

	rval = send_ipc_request_async_stats(
		INODE_ICSB(ip)->stats, node, RQ_FILE, filerq,
		sizeof(struct file_request), NULL, 0, DATA_RF(fp, nord)->identity);
        if (rval == -EHOSTDOWN) {
		down(&aretrysem[node]);
		list_for_each_safe(lp, tp, &alist[node]) {
			p = list_entry(lp, struct async_retry, list);
			if (p == aretry) {
				/*
				 * If async_retry is not AR_Default it is already
				 * being handled by async_op_retry
				 */
				if (p->ar_status != AR_Default)
					break;

				p->ar_status = AR_Retried;
				up(&aretrysem[node]);
				rval = send_ipc_file_retry("ureadpage",
							fp,
							FILE_PRIVATE(fp)->data_rf,
							FILE_PRIVATE(fp)->data_rf_len,
							nord,
							filerq,
							sizeof(struct file_request),
							NULL,
							0,
							&node_used);

				down(&aretrysem[node]);
				if (rval < 0) {
					list_del(&p->list);
					free_msg(p->filerq);
					kfree(p);
					filerq = NULL;
					aretry = NULL;
					break;
				}

				/*
				 * If FILE_NODE() has changed, send_ipc_file_retry/
				 * file_ops_retry has resent this request to a new
				 * server. Adjust which alist is used for replies.
				 * Note that if a reply arrives before the lists
				 * are corrected below the reply could be missed,
				 * stranding the aretry - BUG 810526.
				 */
				if (aretry->ar_node != DATA_RF(fp, nord)->remote_node) {
					list_del(&aretry->list);
					up(&aretrysem[node]);
					down(&aretrysem[DATA_RF(fp, nord)->remote_node]);
					aretry->ar_node = node =
						DATA_RF(fp, nord)->remote_node;
					list_add_tail(&aretry->list,
						&alist[aretry->ar_node]);
				}

				p->ar_status = AR_Default;
				break;
			}
		}
		up(&aretrysem[node]);
	}

	if ((rval < 0) && (rval != -EHOSTDOWN)) {
		goto error;
	}

	mmap_pages_read++;

	/* Do not free filerq, will be free'd in RQ_READPAGE_DATA */

	return(rval);

error:
	if (aretry) {
		/*
		 * The request could have been reaped due to timeout.
		 * We need to make sure that it is still valid before
		 * freeing it.
		 */
		down(&aretrysem[node]);
		list_for_each_safe(lp, tp, &alist[node]) {
			p = list_entry(lp, struct async_retry, list);
			if (p == aretry) {
				remove_oio(p);
				break;
			}
		}
		up(&aretrysem[node]);
		return(rval);
	}

	SetPageError(pagep);
	unlock_page(pagep);
	kfree(opp);

	if (iop) {
		down(&iip->oio_sema);
		iip->oio = iip->oio->next;
		up(&iip->oio_sema);
		kfree(iop);
	}

	if (filerq) {
		free_msg(filerq);
	}

	return(rval);
};


/*
 * ureadpages() was likely called earlier on a range that included this page
 * but for various reasons, we probably marked it in error since it wasn't
 * needed and the calling process was exiting.
 *
 * We're now being called since the kernel needs it and with a
 * PageError, this routine is favored.
 *
 * We'll do the basic set up and call ureadpages()  We know that the page
 * is already in the cache and locked in this case with the previous error
 * (if there was one) cleared.
 */
static int ureadpage(struct file *fp, struct page *pagep)
{
   int	rval;

   DVS_TRACE("RPSpage", fp, pagep->index);
   KDEBUG_RPS(0, "DVS: %s: cpu %d readpage for fp 0x%p (ip 0x%p) index %ld\n",
		__FUNCTION__, raw_smp_processor_id(), fp,
		file_inode(fp), pagep->index);

   rval = ureadpages(fp, (struct address_space*) NULL,
			(struct list_head*) pagep, 1 /* page count */,
			DO_RPG /* doing_readpage */);
   return(rval);
};


/*
 * An upper-DVS layer handler which is invoked when the read actually
 * has been completed by the transport.
 * This is different than the message sent by the server which would indicate
 * overall completion of all writes(or reads from this end)
 */
static void dvs_read_complete(void *req, int status, void *addr, size_t length)
{
	pages_request_t	*rq = (pages_request_t *) req;
	int reads_remaining = atomic_dec_return(&rq->reads_outstanding);

	KDEBUG_RPS(0, "DVS: %s: cpu %d rq 0x%p stat %d addr 0x%p len %ld remain %d\n",
				__FUNCTION__, raw_smp_processor_id(), rq,
				status, addr, length, reads_remaining);

	if (unlikely(reads_remaining < 0)) {
		/*
		 * It appears that in error cases LNet can re-run transactions
		 * more than once -- note that and exit.
		 */
		printk(KERN_ERR "DVS: dvs_read_complete ignoring read "
			"counter underflow to %d\n", reads_remaining);
		atomic_inc(&rq->reads_outstanding);
		return;
	}

	if (status) {
		atomic_set(&rq->state, RPS_RQ_INVALID);
		DVS_TRACEL("RPSrdCE!", req, status, addr, length,
			reads_remaining);
	}
	else {
		DVS_TRACEL("RPSrdCok", req, status, addr, length,
			reads_remaining);
	}

	if (!reads_remaining) {
		RELEASE_READ_WAITERS(rq);

		if (status) {
			/*
			 * There was an error on the read (write actually)
			 * Since there are places that wait on the safer
			 * rq_msg_waiters (detach_file_from_req() today)
			 * and it appears that the response message may not be
			 * received in these error cases, wake anybody waiting
			 * for messages.
			 */
			RELEASE_MSG_WAITERS(rq);
		}
	}
}


static void error_page_range(struct page **page, int count, int release, int wb)
{
   int		i;

   for (i = 0; i < count; i++) {
      struct page	*tp = page[i];

      SetPageError(tp);
      if (wb) {
         end_page_writeback(tp);
      }
      unlock_page(tp);
      if (release) {
         page_cache_release(tp);
      }
   }
}


void iov_to_rq_pages(struct usi_iovec *iov, pages_request_t *rq,
				int *start_page, int *end_page)
{
   *start_page = ((iov->offset - rq->offset) / PAGE_SIZE) + rq->ext_indx;

   if (iov->count < PAGE_SIZE)
      *end_page = *start_page;
   else {
      *end_page = *start_page + (iov->count / PAGE_SIZE) - 1;

      if (iov->count % PAGE_SIZE)
         *end_page = *end_page + 1;
   }
}


/*
 * A callback routine that may be registered with the IPC layer that does
 * all the necessary processing to adjust a file request if it's being re-sent
 * or sent to an unexpected server.
 *
 * This may entail moving it to the correct asynchronous list, adjusting the
 * counters in the request/etc.
 *
 * If this request is registered and the lower layer notes that something is
 * abnormal about the send, this routine is invoked.
 */
static void adjust_filerq(struct usiipc *msg, int to_node)
{
   struct file_request	*freq = (struct file_request *) msg;
   pages_request_t	*rq;
   struct async_retry	*aretry = NULL;
   int			i;
   int			actual_msgs, actual_reads, msgs, reads;
   int			orig_node = freq->ipcmsg.target_node;
   int			switch_chains = orig_node != to_node;

   /*
    * Since we're going to likely mess with the request, lock the (old) aretry
    * chain to claim ownership temporarily.
    */
   down(&aretrysem[orig_node]);

   if ((unlikely(freq->request != RQ_READPAGES_RQ) &&
         (freq->request != RQ_WRITEPAGES_RQ))) {
      BUG();
   }

   if (switch_chains) {
      freq->ipcmsg.target_node = to_node;
   }
   rq = freq->u.iopagesrq.rq;

   /*
    * Walk all the file requests for this pages_request and find ours.
    * Along the way, count up the messages that should be outstanding and
    * the number of reads so we can adjust the counters to account for our
    * file request being sent to a new server.  Note this isn't a perfect
    * system since reads could happen in the middle of us counting but if
    * we can see the freq, there's a good chance it hasn't been issued yet
    * since a fair amount of time has passed due to failover.
    */
   actual_msgs = actual_reads = 0;
   for (i = 0; i < rq->msg_count; i++) {
      freq_instance_t	*fip;

      if ((fip = &rq->freqs[i])->freq) {
         if (fip->freq == freq) {
            if (unlikely(fip->to_node != orig_node)) BUG();
            fip->to_node = to_node;
            aretry = fip->aretry;
         }
         actual_msgs++;
         actual_reads += fip->read_count;
      }
   }

   KDEBUG_RPS(0, "DVS: %s: adjust freq 0x%p from node %d to %d reads %d msgs %d\n",
		__FUNCTION__, freq, orig_node, to_node, actual_reads,
		actual_msgs);
   DVS_TRACEL("RPSadjst", freq, orig_node, to_node, 0, 0);

   /*
    * Adjust the fields in the pages_request that were related to this
    * file_request like reads, msgs/etc.
    */
   if ((msgs = atomic_read(&rq->msgs_outstanding)) != actual_msgs) {
      KDEBUG_RPS(0, "DVS: %s: cpu %d adjust msgs out from %d to %d\n",
		__FUNCTION__, raw_smp_processor_id(), msgs, actual_msgs);
      atomic_set(&rq->msgs_outstanding, actual_msgs);
   }
   if ((reads = atomic_read(&rq->reads_outstanding)) != actual_reads) {
      KDEBUG_RPS(0, "DVS: %s: cpu %d adjust reads out from %d to %d\n",
		__FUNCTION__, raw_smp_processor_id(), reads, actual_reads);
      atomic_set(&rq->reads_outstanding, actual_reads);
   }
   DVS_TRACEL("RPSadjMR", rq, msgs, actual_msgs, reads, actual_reads);

   atomic_set(&rq->state, RPS_RQ_ACTIVE);  /* in case it was invalid */

   if (switch_chains) {
      if (unlikely(!aretry || !async_op_valid(aretry, orig_node) ||
	   (aretry->ar_status != AR_Retried))) {
         BUG();
      }

      list_del(&aretry->list);
   }

   up(&aretrysem[orig_node]);  /* was locked unconditionally */

   if (switch_chains) {
      aretry->ar_node = to_node;
      down(&aretrysem[to_node]);
      list_add_tail(&aretry->list, &alist[to_node]);
      up(&aretrysem[to_node]);
   }
}


/*
 * A blend of uread2/uwrite2 and ureadpage_old designed specifically to
 * asynchronously send parallel page IO requests which will be written directly
 * to or read directly from mapped page cache pages for either page read or 
 * write requests.
 */
static int process_extent(struct file *fp, pages_request_t *rq)
{
   void			*rma_handle = NULL;
   int			rval = 0;
   size_t		rps_blksize;
   int			num_blks;
   loff_t		xfer_off = rq->offset;
   size_t		xfer_len = rq->length;
   char			*xfer_addr;
   int			num_xfers;
   int			nord_indx = 0;
   int			nnodes = FILE_PRIVATE(fp)->data_rf_len;
   int			nodes_used = 0, iovs_used = 0;
   int			msgs_successfully_sent = 0;
   int			*node_info_map = NULL;
   rps_per_node_t	*node_info = NULL, *this_node;
   rps_usi_iovec_t	*iovs = NULL, *this_iov;
   struct async_retry	*aretry = NULL;
   struct file_request	*filerq = NULL;
   int			i, j;
   unsigned long	elapsed_jiffies;
   #define INVALID	-1

			/* required to be ordered as time progresses */
   enum			{ re_unset, re_mapped,
				re_send_loop } re_state = re_unset;

   /*
    * Use the blocksize listed on the mount line for the DWFS case since that's
    * the only place the data lives. Also, since we're using
    * get_length_for_offset() to calculate the transfer lengths, we need to
    * calculate num_blks based on where our offset is in the first block. For
    * example, a 16k read with an 8k block size could consist of either two 8k
    * reads or one 4k read, one 8k read, and one 4k read depending on what the
    * offset is.
    */
   if (FILE_DWFS(fp)) {
      rps_blksize = FILE_PRIVATE(fp)->blocksize;
      num_blks = ((rq->length + (rq->offset % rps_blksize))
			+ rps_blksize - 1) / rps_blksize;
   } else {
      rps_blksize = max_transport_msg_size;
      num_blks = (rq->length + rps_blksize - 1) / rps_blksize;
   }

   /*
    * OK, we've now got the number of blocks and their size.  We know that the
    * entire I/O will fit inside the blocks but may be a subset.  The blocks
    * will be distributed to one or more servers based on the distribution
    * algorithm (DWFS or normal page-cache behavior)
    *
    * We need to know the exact number of network transfers however and
    * must account for the block size being larger than the maximum
    * network transfer size.
    *
    * Larger blocksizes will simply be multiple IOVs (transfers) to span the
    * block.  If the block size is larger than the maximum transfer size,
    * there may be extra transfers in the block not required for the I/O.
    * We'll calculate the number of transfers needed here.
    */

   if (rps_blksize > max_transport_msg_size) {
      int xfers_blk = (rps_blksize + max_transport_msg_size - 1)
			/ max_transport_msg_size;
      size_t last_blk_res;
      size_t offset_in_blk = rq->offset % rps_blksize;

      /*
       * Figure out how many transfers are in the first block.
       */
      num_xfers = (((offset_in_blk + rq->length > rps_blksize)
                    ? rps_blksize - offset_in_blk
                    : rq->length)
                  + max_transport_msg_size - 1)
                  / max_transport_msg_size;

      /*
       * Now figure out how many are in the very last block.
       */
      num_xfers += (num_blks > 1)
                     ? ((((last_blk_res =
				((rq->offset + rq->length) % rps_blksize))
                           ? last_blk_res
                           : rps_blksize)
                       + max_transport_msg_size - 1)
                       / max_transport_msg_size)
                     : 0;

      /*
       * Now for every block in the middle.  These are easy since we know
       * they're all full blocks.
       */
      num_xfers += (num_blks > 2)
                     ? (num_blks - 2) * xfers_blk
                     : 0;
   }
   else {
      num_xfers = num_blks;
   }

   /*
    * Remember that we're a writer for the requests on this inode.
    */
   KDEBUG_RPS(0, "DVS: %s: cpu %d reading %d blks (%d xfers) for inode 0x%p "
		"offset %Ld length %ld(pages %d)\n",
		__FUNCTION__, raw_smp_processor_id(), num_blks, num_xfers,
		rq->ip, xfer_off, xfer_len, rq->ext_count);

   DVS_TRACEL("proc_ext", num_blks, num_xfers, rq->ip, xfer_len, rq->ext_count);

   node_info_map = kmalloc_ssi(sizeof(int) * nnodes, GFP_KERNEL);
   node_info = kmalloc_ssi(sizeof(rps_per_node_t) * nnodes, GFP_KERNEL);
   iovs = kmalloc_ssi(sizeof(rps_usi_iovec_t) * num_xfers, GFP_KERNEL);

   if (!node_info_map || !node_info || !iovs) {
      rval = -ENOMEM;
      goto error;
   }
   for (i = 0; i < nnodes; i++) {
      node_info_map[i] = INVALID;
   }

   /* Map it to get the ball rolling. */
   rq->vmap_addr = xfer_addr = vmap(&rq->pagesd->pages[rq->ext_indx],
				rq->ext_count, VM_MAP, PAGE_KERNEL_EXEC);
   if (!rq->vmap_addr) {
      printk(KERN_ERR "DVS: %s: failed to vmap kernel pages\n", __func__);
      rval = -ENOMEM;
      goto error;
   }

   KDEBUG_RPS(0, "DVS: %s: cpu %d mapped request 0x%p to 0x%p now reading\n",
		__FUNCTION__, raw_smp_processor_id(), rq, rq->vmap_addr);

   rma_handle = map_ipc_kernel_memory(rq->vmap_addr, rq->length, DVS_NEED_HANDLER);
   if (IS_ERR_OR_NULL(rma_handle))  {
      printk(KERN_ERR "DVS: %s: map_ipc_kernel_memory failed\n", __func__);
      rval = -EFAULT;
      rma_handle = NULL;
      goto error;
   }
   rq->rma_handle = rma_handle;  /* keep it here too for cleanup */

   if (unlikely(count_ipc_memory(rma_handle))) {
      BUG();  /* old page pointers scheme not used by LNet, consider removing */
   }

   /*
    * Register that we want to be notified when each read completes.
    */
   register_ipc_read_complete(rma_handle, dvs_read_complete, rq);

   re_state++;  /* mapping/registration complete */

   while (xfer_len) {
      int	this_xfer;
      int	this_xfer_remaining;
      int	nord;

      /* For DWFS, we need to make sure that we only read within our stripe. */
      if (FILE_DWFS(fp)) {
         this_xfer = get_length_for_offset(fp, xfer_len, xfer_off, rps_blksize);
      } else {
         this_xfer = (xfer_len >= rps_blksize) ? rps_blksize : xfer_len;
      }

      nord = get_nord_for_offset(fp, xfer_off, rps_blksize);

      if (!DATA_RF(fp, nord)->valid) {
         rval = deferred_uopen(rq->ip, fp, nord);
         if (rval < 0) {
            goto error;
         }
      }

      this_xfer_remaining = this_xfer;

      while (this_xfer_remaining) {
         this_xfer = (this_xfer_remaining > max_transport_msg_size)
			? max_transport_msg_size
			: this_xfer_remaining;

         /*
          * Get the compressed index of this nord so we don't always have to
          * examine each one.  That way we can roll through these in one pass.
          */
         if (node_info_map[nord] == INVALID) {
            nord_indx = node_info_map[nord] = nodes_used++;
            node_info[nord_indx].nord = nord;
         }
         else {
            nord_indx = node_info_map[nord];
         }
         this_node = &node_info[nord_indx];

         this_iov = &iovs[iovs_used];
         this_iov->iov_next = INVALID;

         if (this_node->iov_count++ == 0) {
            this_node->iov_list = iovs_used;
            this_node->iov_last = iovs_used;
         }
         else {
            iovs[this_node->iov_last].iov_next = iovs_used;
            this_node->iov_last = iovs_used;
         }
         iovs_used++;

         this_iov->usi_iov.address = xfer_addr;
         this_iov->usi_iov.count = this_xfer;
         this_iov->usi_iov.offset = xfer_off;

         this_node->xfer_total += this_xfer;

         xfer_addr += this_xfer;
         xfer_off += this_xfer;
         xfer_len -= this_xfer;

         this_xfer_remaining -= this_xfer;
      }
   }  /* create iov/per node information */

   if (unlikely(iovs_used != num_xfers)) {
      printk(KERN_EMERG "DVS: IOV mismatch! allocated %d used %d blksize %ld"
		" offset %Ld length %ld DW %d servers %d\n",
		num_xfers, iovs_used, rps_blksize, rq->offset, rq->length,
		FILE_DWFS(fp), nnodes);
      BUG();
   }

   re_state++;  /* starting to send messages */

   /*
    * The number of reads is 1-1 with the number of IOVs.  These may originate
    * from the same server or from multiple servers.  Initialize this to the
    * maximum value and it will be adjusted if there were errors.
    */
   atomic_set(&rq->reads_outstanding, iovs_used);

   /*
    * Set msgs_outstanding to its maximum value here to keep it around until
    * we're done sending all the messages (can't increment it upward from
    * zero since a message could come back and free it while we were trying
    * to send the next one)  We'll come back and decrement it if there are
    * errors and messages weren't able to be sent.
    *
    * Note that at the moment, we prevent multiple messages from being used
    * if the target file system is NFS.  We should revisit that if the file
    * system is read-only.
    */
   atomic_set(&rq->msgs_outstanding, nodes_used);
   msgs_successfully_sent = 0;

   for (nord_indx = 0; nord_indx < nodes_used; nord_indx++) {
      rps_per_node_t			*ni = &node_info[nord_indx];
      struct io_parallel_request	*ipr;
      freq_instance_t			*inst;
      int				request_size;
      int				to_node;
      dvs_tx_desc_t			tx_cookie;

      filerq = NULL;
      aretry = NULL;
      request_size = sizeof(struct file_request) +
			(sizeof(struct usi_iovec) * ni->iov_count);
      filerq = kmalloc_ssi(request_size, GFP_KERNEL);
      if (!filerq) {
         rval = -ENOMEM;
         goto error;
      }

      /* setup a request for writepage(s) or readpages request */
      if (rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE) {
         filerq->request = RQ_WRITEPAGES_RQ;
      } else {
         filerq->request = RQ_READPAGES_RQ;
      }

      filerq->u.iopagesrq.rq = rq;  /* the original extent request */

      filerq->u.iopagesrq.source_request = filerq;
      filerq->u.iopagesrq.state = RPS_RPSRQ_INUSE;

      /*
       * The number of messages sent for this pages_request.
       * Will be the same or less than the number of reads.  For example:
       *
       * a) 4MB going to 1 server with a 1MB read size would be:
       *      msgs_outstanding = 1
       *      reads_outstanding = 4
       *      4 IOVs in 1 message
       *
       * b) 4MB going to 2 servers with a 2MB read size would be:
       *      msgs_outstanding = 2
       *      reads_outstanding = 2
       *      2 messages with 1 IOV each
       */

      filerq->retry = INODE_ICSB(rq->ip)->retry;
      filerq->file_handle = DATA_RF(fp, ni->nord)->file_handle;
      filerq->client_fp = fp;
      tx_cookie = register_ipc_request(FREQ_IPC(filerq));

      ipr = &filerq->u.iopagesrq.ipr;
      ipr->rma_handle = rma_handle; /* server needs to know if RMA vs. piggyb */

      /*
       * The I/O on the server is driven off the IOVs, the base and length here
       * are just an overview of the whole I/O and are technically not correct
       * when there are multiple servers.
       */
      ipr->base = rq->vmap_addr;
      ipr->length = ni->xfer_total;

      ipr->datasync = 0;

      to_node = DATA_RF(fp, ni->nord)->remote_node;

      /*
       * Transfer the IOVs to the message payload.  When the message(s) come
       * back, each request (file_request) will traverse the IOVs to map
       * it(them) back to the pages they're supposed to clean up and release.
       *
       * While we do have more convenient mechanisms on the client which
       * directly identify the pages in the request, it's just easier to parse
       * the IOVs since the request may have come back short so we need to
       * base our actions on the server response.
       */
      j = ni->iov_list;
      for (i = 0; i < ni->iov_count; i++) {
              ipr->iov[i] = iovs[j].usi_iov;
              j = iovs[j].iov_next;
              KDEBUG_RPS(0, "DVS: %s: cpu %d inode 0x%p filerq 0x%p nord %d "
			      "iov[%d] addr 0x%p off %Ld cnt %ld\n",
			      __FUNCTION__, raw_smp_processor_id(), rq->ip,
			      filerq, ni->nord, i, ipr->iov[i].address,
			      ipr->iov[i].offset, ipr->iov[i].count);
      }
      ipr->count = ni->iov_count;

      KDEBUG_RPS(0, "DVS: %s: cpu %d sending node %d %d IOVs for inode 0x%p "
                  "filerq 0x%p request 0x%p\n",
                     __FUNCTION__, raw_smp_processor_id(), ni->nord,
                     ni->iov_count, rq->ip, filerq, rq);

      DVS_TRACEL("procext+", ni->nord, ni->iov_count, rq->ip, filerq, rq);

      capture_context((&filerq->context));

      aretry = kmalloc_ssi(sizeof(struct async_retry), GFP_KERNEL);
      if (!aretry) {
         rval = -ENOMEM;
         goto error;
      }
      INIT_LIST_HEAD(&aretry->list);
      aretry->fp = fp;
      aretry->ar_nord = ni->nord;
      aretry->ar_node = to_node;
      aretry->filerq = filerq;
      aretry->tx_cookie = tx_cookie;
      aretry->rqsz = request_size;
      aretry->ar_status = AR_Default;
      KDEBUG_RPS(0, "DVS: %s: cpu %d aretry 0x%p for inode 0x%p filerq 0x%p\n",
			__FUNCTION__, raw_smp_processor_id(), aretry,
			rq->ip, filerq);

      down(&aretrysem[to_node]);
      list_add_tail(&aretry->list, &alist[to_node]);
      up(&aretrysem[to_node]);

       /* Check the dynamic number of freqs created by init_pages_request */
      if (++rq->msg_count > rq->num_freqs) {
         printk(KERN_ERR "DVS: %s: Overflowing pages_request num_freqs.\n",
                __FUNCTION__);
         rval = -ENOBUFS;
         goto error;
      }

      /*
       * Add this file request to the pages_request_t so we can locate all
       * the file requests if we need to cancel the transaction.  Also keep
       * track of the number of reads in the file request instance in case
       * we need to adjust the counters/etc for failover or errors.
       */
      inst = &rq->freqs[rq->msg_count - 1];
      inst->freq = filerq;
      inst->read_count = ni->iov_count;
      inst->cookie = tx_cookie;
      inst->to_node = to_node;
      inst->aretry = aretry;

      /*
       * Tell the IPC layer to let us know if something went wrong with the
       * send to_node like retry, failover, etc.
       */
      NOTIFY_OF_ABNORMAL_SEND(filerq, to_node);

      elapsed_jiffies = jiffies;
      rval = send_ipc_request_async_stats(INODE_ICSB(rq->ip)->stats,
			to_node, RQ_FILE, filerq, request_size,
			NULL, 0, DATA_RF(fp, ni->nord)->identity);
      if (rval < 0) {
         KDEBUG_RPS(0, "DVS: %s: cpu %d xmit error inode 0x%p filerq 0x%p nord %d "
				"iov %d\n",
			__FUNCTION__, raw_smp_processor_id(), rq->ip, filerq,
			ni->nord, i);

         if (rval == -EHOSTDOWN) {
            struct list_head	*lp, *tp;
            struct async_retry	*thisa;
            int			node;

            down(&aretrysem[to_node]);
            list_for_each_safe(lp, tp, &alist[to_node]) {
               thisa = list_entry(lp, struct async_retry, list);
               if (thisa == aretry) {
                  /*
                   * If async_retry is not in the default state, it's
                   * already being handled by async_op_retry.
                   */
                  if (thisa->ar_status != AR_Default) {
                     break;
                  }

                  thisa->ar_status = AR_Retried;
                  up(&aretrysem[to_node]);
		  elapsed_jiffies = jiffies;
                  rval = send_ipc_file_retry("read_extent",
						fp,
						FILE_PRIVATE(fp)->data_rf,
						FILE_PRIVATE(fp)->data_rf_len,
						ni->nord,
						filerq,
						sizeof(struct file_request),
						NULL,
						0,
						&node);
                  if (rval < 0) {
                     /* If send file retry couldn't do it we're done! */
                     goto error;
                  }
		  log_request(filerq->request, NULL, rq->ip, fp, 1, node,
			      jiffies - elapsed_jiffies);

                  thisa->ar_status = AR_Default;
                  down(&aretrysem[to_node]);
                  break;
               }
            }
            up(&aretrysem[to_node]);
         }
         else {
            inst->freq = NULL;
            goto error;
         }
      }
      log_request(filerq->request, NULL, rq->ip, fp, 1, to_node,
		  jiffies - elapsed_jiffies);
      msgs_successfully_sent++;
   }  /* send each message */

   /*
    * Not safe to look at rq anymore if all messages happened to return.
    */

done:
   /*
    * These are the things that are free'd regardless of whether or not there
    * were any errors.
    */
   if (node_info_map) {
      kfree(node_info_map);
   }
   if (node_info) {
      kfree(node_info);
   }
   if (iovs) {
      kfree(iovs);
   }

   return rval;

error:
   /*
    * Something obviously went wrong either initially or down the road after
    * perhaps 1 or more messages had been sent.
    *
    * Things that may be in play that we need to handle are:
    *   - any memory we allocated for node_info/etc
    *   - did we map things that need to be unmapped if not used?
    *   - the pages themselves need to be errored, did we actually send any
    *     messages?  If so we'd need to get into the IOVs to see what's left.
    *   - async retry and the file_request can be deleted since if we hit an
    *     error it was on the last (which could have been first) message.
    *   - pages_request can be deleted if nothing was sent.
    *   - pages descriptor is handled above us so nothing to do there.
    */

   if (re_state >= re_send_loop) {
      /*
       * Start with the async retry and file request since we don't need them
       * going forward.
       */
      if (aretry) {
	 down(&aretrysem[aretry->ar_node]);
         list_del(&aretry->list);
	 up(&aretrysem[aretry->ar_node]);
         kfree(aretry);
         aretry = NULL;
      }
      if (filerq) {
         free_msg(filerq);
         filerq = NULL;
      }
   }

   /*
    * Now figure out what's going on with the pages themselves.
    *
    * Since readpage is special and placed in the cache by the kernel,
    * we'll only focus on the pages ureadpages placed in the cache.
    * Figure out which ones were not used and therefore need to be
    * errored, unlocked and released.
    */
   if (!rq->rq_flags & RPS_RQ_FLAGS_READPAGE) {
      if (re_state < re_send_loop) {
         /*
          * Never made it to the send loop, error the whole page range since
          * it wasn't ever touched.
          */
         atomic_set(&rq->reads_outstanding, 0);
         error_page_range(&rq->pagesd->pages[rq->ext_indx], rq->ext_count, 1,
               rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE);
      }
      else {
         /*
          * Handle erroring the pages here since we understand what's been sent
          * out and what didn't make it.  Work directly off the built up IOVs
          * to error and unlock anything that hadn't been processed.
          */
         for (; nord_indx < nodes_used; nord_indx++) {
            int			k, iov, reads;
            int			start_page, end_page;
            rps_per_node_t	*ni = &node_info[nord_indx];

            iov = ni->iov_list;
            for (k = 0; k < ni->iov_count; k++) {
               reads = atomic_dec_return(&rq->reads_outstanding);
               if (unlikely(reads < 0)) BUG();

               iov_to_rq_pages(&iovs[iov].usi_iov, rq, &start_page, &end_page);

               error_page_range(&rq->pagesd->pages[start_page],
				(end_page - start_page) + 1, 1/* release */,
				rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE);
               iov = iovs[iov].iov_next;
            }
         }

         /*
          * Wake anybody who returned while we were erroring the pages.
          */
         RELEASE_READ_WAITERS(rq);
      }
   }

   /*
    * It gets a little messy here in trying to figure out what to do with
    * the rest of the stuff.  Easiest to divide it into "did we send anything"
    * vs. not.
    */
   if (re_state >= re_send_loop && msgs_successfully_sent) {
      /*
       * Adjust the msgs_outstanding by the number that didn't make it but
       * leave one at this point to hold the request since the ones that did
       * make it would be looking to clean up when they returned.
       */
      if ((i = (nodes_used - msgs_successfully_sent - 1))) {
         atomic_sub(i, &rq->msgs_outstanding);
      }

      if (atomic_dec_return(&rq->msgs_outstanding)) {
         /*
          * One or more messages were sent successfully but at least one
          * didn't make it and the intended recipient wasn't marked as down.
          * We already errored the pages for the message(s) that didn't make it.
          * Mark the request as invalid which will cause any outstanding file
          * requests to be errored when they arrive -- just to be safe.
          * Any messages that successfully arrived of course will have
          * valid pages which we can't really change at this point.
          *
          * And yes, we're going to gamble that from the time it took us to
          * decrement the msgs_outstanding to the time we set the state below
          * that the request didn't disappear..
          */
         atomic_set(&rq->state, RPS_RQ_INVALID);

         /* Wait for outstanding messages so we can clean up and error out
          * rather than forcing uwritepages to handle cleanup */
         if (rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE) {
            down(&rq->writepages_sema);

            (void) finalize_request(rq);
         }
      }
      else {
         /*
          * Whatever we sent is now back so let's just treat this like a
          * normal request that will disappear when the list is cleaned up.
          */
         (void) finalize_request(rq);
      }
   }
   else {
      /*
       * Failed early enough that nothing was done.  Clean up the request
       * since we own it.
       */
      if (re_state >= re_mapped) {
         if (rq->vmap_addr) {
            vunmap(rq->vmap_addr);
         }
         if (rma_handle) {
            unmap_ipc_kernel_memory(rma_handle);
         }
      }

      atomic_dec(&rq->pagesd->ref_count);  /* we don't exist anymore */
      list_del(&rq->rq_list);
      kfree(rq);
      rq = NULL;
   }

   goto done;
}


/*
 * Check if an outstanding file request is still valid (meaning it wasn't
 * cancelled by somebody while it was pending)  If it's valid, remove the
 * async retry entry and mark the pages request as expiring.
 *
 * The readpages hierarchy goes like this:
 *
 * The async. retry list is the primary entity used to determine who "owns"
 * the request -- if you find your file_request in that list, you're in control.
 * Along with the async. retry list is the pages request list which hangs off
 * the private inode information.  If you own the async. entry, you also own
 * the pages_request_t for that request.
 *
 * There are 4 different ways that DVS interacts with these two entities:
 *
 *   1- returning file_requests (RQ_READPAGES_RP) that are sent from the
 *      DVS server and are received on the client in do_usifile.
 *      These are the most important since they represent the normal case and
 *      we want these to be as fast as possible.  If they're able to be unlinked
 *      from the async. chain, the pages request is located and processed.
 *      If their request is gone, somebody already cleaned up which involves
 *      disabling the RMA landing pad and unmapping the page cache address
 *      range.  We do this without being a reader (since that would block the
 *      writers trying to issue new requests) for the request chain since
 *      the atomic state in each request will prevent our request from being
 *      deleted from the chain until its state is marked by us as expired.
 *      There's no need to traverse the chain (which would require us to be a
 *      reader) since the async. entry has a pointer to each pages request.
 *
 *      When we're done processing these, we atomically mark them as expired
 *      and these will be deleted by anybody who encounters them as a writer.
 *
 *      Note that do_usifile may run as an error forwarder in the case where
 *      it wasn't able to unlink the file request and there were errors on
 *      the read.  It does this to resolve what would otherwise be a deadlock
 *      on waiters of read completions.
 *
 *   2- Incoming requests being added to the request chain by writers.
 *      We want writers to continue to be writers until they've exhausted all
 *      their extents.  They shouldn't be blocked or affected in any way as
 *      long as somebody like 3- or 4- isn't running.
 *
 *   3- urelease_common() cleanup or anybody who would want to cancel this
 *      file_request.  These would be walking the pages request chain for
 *      the inode under the write lock which would prevent any new incoming
 *      requests.
 *
 *      Each pages request needs to be validated to make sure that somebody
 *      else isn't working with it (ie, a returning 1- request at the same time
 *      we decide we want to cancel it)  To validate each request, we take its
 *      array of async. requests (remember there can be multiple msgs to
 *      different servers for each pages_request_t) and attempt to unlink them.
 *      If we can unlink N and the pages_request outstanding_msgs count is
 *      also N, we're free to remove the pages_request.  If we can't get N,
 *      somebody is processing the remainder so we'll let them finish while
 *      holding the write lock the entire time and then clean up.
 *
 *      If we remove the pages request, we need to clean up afterwards which
 *      is slightly tricky since the transport has been given the landing pad
 *      address which is the page cache pages vmapp'ed.  We'll unmap it which
 *      would prevent future writes to that area if the data hasn't yet already
 *      arrived but this raises the possibility that the kernel could panic
 *      on an invalid address.  We'll obviously also walk each page, mark it
 *      in error and unlock it.  We may need further work here to sequester
 *      the mapped area and return it back after either time or confirmation
 *      that the write occurred.
 *
 *   4- node down code.   The node down code would be looking specifically at
 *      the async. entries that were issued for the downed node with the goal
 *      to re-issue them to a different server.  Would be holding the sema.
 *      for the async. list so there shouldn't be any interaction.  If somebody
 *      were to try and cancel a request that happened to now be to a downed
 *      node, whoever wins the async. lock wins though the failover code will
 *      win (others backoff) if an async entry has been retried.
 */
int unlink_filerq(struct file_request *freq, dvs_tx_desc_t tx_cookie,
			int to_node, unlink_mode_t unlnk_mode)
{
   struct async_retry		*aentry, *afound = NULL;
   struct io_pages_request	*rp_req;
   pages_request_t		*rptr;
   freq_instance_t		*fip;
   int				rq_state = -1;
   int				i, found;
   int				rval = 0;

   if (!freq) {
      goto done;
   }

   /*
    * We can't look at the file request pointer yet until we determine if
    * it's still valid (meaning that it's still pending)  We do this by
    * searching the async. retry list and if it's found we're good.  If not,
    * somebody cancelled the request and cleaned up -- including free'ing freq.
    */
   down(&aretrysem[to_node]);
   list_for_each_entry(aentry, &alist[to_node], list) {
      if ((aentry->filerq == freq) && (aentry->tx_cookie == tx_cookie)) {
         if (unlikely(freq->ipcmsg.seqno != tx_cookie)) BUG();

         /*
	  * UNLNK_ESTALE_Retry is special - it finds the async_retry struct
	  * and sees if we should retry the request, and reflects that in the
	  * return value.
	  */
         if (unlnk_mode == UNLNK_ESTALE_Retry) {
            if (++freq->u.iopagesrq.estale_retries <= estale_max_retry) {
               freq->flags.estale_retry = 1;
               up(&aretrysem[to_node]);
               return 0;
            }
            up(&aretrysem[to_node]);
            return 1;
         }

         /*
          * This is our reply so obviously the retry was successful.
          * No need to defer to this one now.
          */
         if (aentry->ar_status == AR_Retried &&
		unlnk_mode == UNLNK_Have_Reply) {
            aentry->ar_status = AR_Default;
         }

         switch (aentry->ar_status) {
            case AR_Default:
            case AR_Will_Retry:
            case AR_Cancel_Retry:
               afound = aentry;
               list_del(&afound->list);  /* it's ours! */
               rval++;
               break;

            case AR_Retried:
               /*
                * We're not going to mess with the running failover code.
                * Let's give them some time and try again.
                */
               up(&aretrysem[to_node]);
               rval = -EAGAIN;
               goto done;
         }

         /*
          * Mark this as expiring so that new requests coming in won't use it.
          * This could be because we've already processed part of the request
          * and it somehow got faulted out and the new request coming in would
          * need to actually be a new request.
          */
         rp_req = &freq->u.iopagesrq;
         rptr = rp_req->rq;
         rq_state = atomic_cmpxchg(&rptr->state, RPS_RQ_ACTIVE, RPS_RQ_EXPIRING);
         break;
      }
   }
   up(&aretrysem[to_node]);

   if (!afound) {
      goto done;
   }

   kfree_ssi(afound);

   KDEBUG_RPS(0, "DVS: %s: unlinked freq 0x%p aretry 0x%p node %d rq 0x%p\n",
		__FUNCTION__, freq, afound, to_node, rptr);

   /* Sanity check everything for a while as non-DEBUG code. */
   if (unlikely(((freq->request != RQ_READPAGES_RQ) &&
		(freq->request != RQ_WRITEPAGES_RQ)) ||
		rp_req->state != RPS_RPSRQ_INUSE || rq_state == RPS_RQ_FREE ||
		rq_state == RPS_RQ_EXPIRED ||
		atomic_read(&rptr->pagesd->state) == RPS_PGSD_FREE)) {
      BUG();
   }

   found = 0;
   for (i = 0; i < rptr->msg_count; i++) {
      if ((found = ((fip = &rptr->freqs[i])->freq == freq))) {
         if (unlikely(fip->aretry != afound)) BUG();
         fip->freq = NULL;  /* better to kill these off here */
         fip->aretry = NULL;
         break;
      }
   }

   if (unlikely(!found)) {
      BUG();
   }

done:
   DVS_TRACEL("RPSUnlnk", freq, rptr, rval, rq_state, unlnk_mode);

   return rval;
}

/*
 * Walk an IOV list and do the normal page processing of zeroing/etc or if
 * we're in an error mode, mark each page in error.
 */
int process_iovs(pages_request_t *rq, struct io_parallel_request *ipr,
		struct io_pages_reply *rp, processiovs_mode_t mode)
{
   int		i, j, iov_start_page, iov_end_page, reads;
   loff_t	diff;
   long		this_rval;
   struct page	*page;
   char		*datap;
   struct writeback_control *wbc;
   int		rval = 0;
   struct inode_info *iip;

   KDEBUG_OFC(0, "DVS: %s: entering process_iovs. rq 0x%p ipr 0x%p rp 0x%p mode %d\n",
		__FUNCTION__, rq, ipr, rp, mode);

   if (mode != PRIOV_Cleanup) {

      if (mode == PRIOV_Error_Messenger) {
         int				rq_state;
         struct io_pages_request	*io_req;

         /*
          * Do a quick sanity check on the error messenger to make sure
          * everything is still valid.  We know that since there were errors,
          * the transaction couldn't have completed in a normal fashion and
          * this means everything should still be valid but we'll verify.
          */
         io_req = &rp->source_request->u.iopagesrq;

         ipr = &io_req->ipr;
         rq = io_req->rq;
         DVS_TRACE("prIOV_em", rq->ip, rq);

         rq_state = atomic_read(&rq->state);

         if (unlikely((io_req->state != RPS_RPSRQ_INUSE) ||
		(rq_state == RPS_RQ_FREE) || (rq_state == RPS_RQ_EXPIRED))) {
            BUG();
         }
      }

      /*
       * Account for the RMAs that didn't happen due to either file system
       * errors or an actual return value of 0 bytes which DVS IPC on the
       * server would ignore and not do the LNetPut().
       *
       * Once we're through with these adjustments, check that we didn't
       * just finish off all the reads as a result and if that's the case,
       * wake any waiters.
       *
       * Note that writes perform RMAs prior to the file system call so an
       * RMA could have taken place even if the write system call failed.
       */
      if ((i = ipr->count - rp->rmas_completed)) {
            if (!atomic_sub_return(i, &rq->reads_outstanding)) {
                  RELEASE_READ_WAITERS(rq);
            }
      }

      if (mode == PRIOV_Error_Messenger) {
         RELEASE_READ_WAITERS(rq);
         RELEASE_MSG_WAITERS(rq);

         return rval;
      }
   }

   if ((reads = atomic_read(&rq->reads_outstanding))) {
      /*
       * The message is back or cancelled but the reads are apparently lagging.
       * Wait for them to complete since we'll be potentially zeroing/etc.
       * Note that the read callback does pass up the offset and the length
       * of each read as it completes but we don't know the overall
       * return status to know if the original read request was short so
       * best at this point just to wait for everything to finish before
       * mucking with anything.
       *
       * Signal that we're waiting.
       */
      if (unlikely(reads < 0)) BUG();

      WAIT_FOR_READS(rq);
   }

   rval = ipr->count < 1;  /* better than nothing.. */

   wbc = rq->wbc;
   iip = (struct inode_info *)rq->ip->i_private;
   if (unlikely((rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE) && (!wbc || !iip)))
      BUG();

   /*
    * Check to see if LNet possibly had errors on the write.  The callback
    * would have marked the request invalid if so.
    */
   if (atomic_read(&rq->state) == RPS_RQ_INVALID) {
      mode = PRIOV_Cleanup;
   }

   for (i = 0; i < ipr->count; i++) {
      this_rval = (mode == PRIOV_Cleanup) ? -EINVAL : rp->rvals[i];

      /*
       * The index into the extents array of the starting page of
       * this iov.
       */
      iov_to_rq_pages(&ipr->iov[i], rq, &iov_start_page, &iov_end_page);

      KDEBUG_RPS(0, "DVS: %s: got rval %ld for request 0x%p iov %d iov_off %Ld "
			"iov_count %ld(pages %ld) flags %d wbc 0x%p\n",
			__FUNCTION__, this_rval, rq, i,
			ipr->iov[i].offset, ipr->iov[i].count,
			ipr->iov[i].count / PAGE_SIZE, rq->rq_flags, wbc);
      DVS_TRACEL("RPSprIOV", rq->ip, i,
			ipr->iov[i].offset, ipr->iov[i].count, this_rval);
      DVS_TRACEL("prociov", rq, rq->ip, iov_start_page, iov_end_page, wbc);

      KDEBUG_OFC(0, "DVS: %s: before page loop: sp %d ep %d\n", __FUNCTION__,
            iov_start_page, iov_end_page);

      for (j = iov_start_page; j <= iov_end_page; j++) {
         page = rq->pagesd->pages[j];

         if (rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE) {

            KDEBUG_RPS(0, "DVS: %s: wb reply. rq 0x%p j %d rval %ld ct %lu pg 0x%p "
                  "wbc 0x%p\n", __FUNCTION__, rq, j, this_rval, ipr->iov[i].count,
                  page, wbc);

            /* failed to write complete iov, error the range */
            if (this_rval != ipr->iov[i].count) {
               this_rval = -EIO;
            }

            if (this_rval < 0) {
		KDEBUG_OFC(0, "DVS: %s: error %ld\n", __FUNCTION__, this_rval);

               if (!rval) {
                  rval = this_rval;
               }

               if (this_rval == -EAGAIN) {
                  redirty_page_for_writepage(wbc, page);
                  rval = 0;
               } else {
                  SetPageError(page);
                  mapping_set_error(page->mapping, this_rval);
               }
            } else {
               /* success */
               wbc->nr_to_write--;
               atomic_dec(&iip->dirty_pgs);
            }

            /* clear writeback flag and unlock page now that IO has completed */
            end_page_writeback(page);
            unlock_page(page);
            page_cache_release(page);

         } else { /* readpage(s) */

            KDEBUG_OFC(0, "DVS: %s: rp reply. rq 0x%p j %d rval %ld ct %lu pg 0x%p\n",
                  __FUNCTION__, rq, j, this_rval, ipr->iov[i].count, page);

            if (this_rval < 0) {
               if (!rval) {
                  rval = this_rval;  /* use first error as the return value */
               }
               /*
                * File system error for this iov, mark all its pages as
                * invalid.  Remember that an iov may be a portion of an
                * extent.
                */
               KDEBUG_RPS(0, "DVS: %s: fs error %ld for inode 0x%p request 0x%p\n",
                     __FUNCTION__, this_rval, rq->ip, rq);
               SetPageError(page);
            }
            else {
               loff_t	page_offset = page->index * PAGE_SIZE;
               loff_t	io_last = ipr->iov[i].offset + this_rval;
               loff_t	page_last = page_offset + PAGE_SIZE;

               if (io_last < page_last) {
                  /*
                   * I/O fell short for the extent.  Check that
                   * this page is still part of the file first.
                   */
                  if (page_offset >= rq->ip->i_size) {
                     KDEBUG_RPS(0, "DVS: %s: trunc'ed inode 0x%p on request 0x%p "
                              "io_last %Ld page_last %Ld isize %Ld\n flag %d\n",
                              __FUNCTION__, rq->ip, rq, io_last, page_last,
                              rq->ip->i_size, rq->rq_flags);

                     /* pre-reading a page for cache write, zero it */
                     if (rq->rq_flags & PIO_RQ_FLAGS_PREREAD) {
                        datap = rq->vmap_addr + ((j - rq->ext_indx) * PAGE_SIZE);
                        memset(datap, 0, PAGE_SIZE);

                     /* non pre-read case, error the page.  it won't be used */
                     } else {
                        error_page_range(&page, 1,
                              !(rq->rq_flags & RPS_RQ_FLAGS_READPAGE), 0);
                        continue;  /* skip the common page processing */
                     }
                  } else {
                     /*
                      * set a pointer into the actual page since it looks like
                      * we've got to clear part or all of the page.
                      */
                     datap = rq->vmap_addr + ((j - rq->ext_indx) * PAGE_SIZE);
                     diff = page_last - io_last;

                     if (diff < PAGE_SIZE) {
                        memset(datap + (PAGE_SIZE - diff), 0, diff);
                     }
                     else {
                        memset(datap, 0, PAGE_SIZE);
                     }
                     KDEBUG_RPS(0, "DVS: %s: short read inode 0x%p on request 0x%p "
                           "io_last %Ld page_last %Ld diff %Ld\n",
                           __FUNCTION__, rq->ip, rq, io_last, page_last, diff);
                  }
               }
               SetPageUptodate(page);
               flush_dcache_page(page);
            }
            unlock_page(page);
            if (!rq->rq_flags & RPS_RQ_FLAGS_READPAGE) {
               page_cache_release(page);
            }
         } /* readpages/readpage */
      }  /* each page */
   }  /* each IOV */

   KDEBUG_RPS(0, "DVS: %s: Exiting. rq 0x%p\n", __FUNCTION__, rq);

   return rval;
}


/*
 * A common routine to clean up all the stuff associated with a ureadpages()
 * request except for the actual request itself which may or may not be removed
 * by the caller (depending on who that is)
 */
int finalize_request(pages_request_t *rq)
{
   int	rval = 0;
   int	state = atomic_read(&rq->state);

   if (unlikely(atomic_read(&rq->msgs_outstanding) ||
	atomic_read(&rq->reads_outstanding) || (state == RPS_RQ_EXPIRED) ||
	(state == RPS_RQ_ACTIVE) || (state == RPS_RQ_FREE))) {
      BUG();
   }

   unmap_ipc_kernel_memory(rq->rma_handle);
   vunmap(rq->vmap_addr);

   KDEBUG_RPS(0, "DVS: %s: unmap 0x%p inode 0x%p request 0x%p\n",
		__FUNCTION__, rq->vmap_addr, rq->ip, rq);
   DVS_TRACEL("RPSFinlR", rq->ip, rq, rq->vmap_addr, rq->msg_count, 0);

   /*
    * Clean up the pages stuff if we're the last users.
    */
   if (!atomic_dec_return(&rq->pagesd->ref_count)) {
      KDEBUG_RPS(0, "DVS: %s: free pages 0x%p pagesd 0x%p inode 0x%p\n",
		__FUNCTION__, rq->pagesd->pages, rq->pagesd, rq->ip);
      atomic_set(&rq->pagesd->state, RPS_PGSD_FREE);
      kfree_ssi(rq->pagesd->pages);
      kfree_ssi(rq->pagesd);
   }
   state = atomic_cmpxchg(&rq->state, RPS_RQ_EXPIRING, RPS_RQ_EXPIRED);

   /*
    * The state of the pages_request at this point is either
    * expired or invalid.  If it's invalid, we processed part of it normally
    * and others were errored.  We're done with it now so mark it normal
    * so that it'll get cleaned up.
    */
   if (state == RPS_RQ_INVALID) {
      atomic_set(&rq->state, RPS_RQ_EXPIRED);
      DVS_TRACE("RPSFinlI", rq->ip, rq);
   }

   return rval;
}


/*
 * When a file instance is closed, we need to make sure that any I/O
 * requests made on behalf of the inode by this file no longer reference this
 * file instance.  Walk the list of requests and find another file instance
 * and change any references to this instance to some other.
 *
 * This should be safe since normally all the opens would be of the same type
 * (read-only).  If we can't find another file instance, NULL out the
 * pointers so that any failover processing would know to delete any requests.
 *
 * Returns:
 *   0: failure -- somehow unable to detach fp from outstanding requests
 *   >0: success, file was detached -- may not have been on a request at all
 *   EAGAIN: request was recently re-issued due to failover, try again
 */
int detach_file_from_reqs(struct file *fp)
{
   int			rval = 1;
   struct inode		*ip = file_inode(fp);
   struct inode_info	*iip = (struct inode_info *) ip->i_private;
   pages_request_t	*rq;
   struct file		*another_fp = NULL;
   enum			{ initial, required, rescanning } rescan = initial;

   /*
    * There could be other paths opening the file that are holding the
    * requests semaphore (and wanting the inode mutex which we hold) so we'll
    * back off (as a closer) if there's an active writer to prevent deadlock.
    */
   if (!down_read_trylock(&iip->requests_sem)) {
      return -EAGAIN;
   }

rescan:
   list_for_each_entry(rq, &iip->requests, rq_list) {
      int			i;
      freq_instance_t		*fip;
      struct async_retry	*aentry, *afound;

      switch (atomic_read(&rq->state)) {
         case RPS_RQ_FREE:
            BUG();

         case RPS_RQ_ACTIVE:
         case RPS_RQ_EXPIRING:
         case RPS_RQ_INVALID:
            if (rq->fp == fp) {
               if (another_fp || (rescan == rescanning)) {
                  for (i = 0; i < rq->msg_count; i++) {
                     int	current_node;

                     fip = &rq->freqs[i];

                     /*
                      * Grab a local copy since failover might be running and
                      * changing fip->to_node while we're checking.
                      */
                     current_node = fip->to_node;
                     afound = NULL;

                     down(&aretrysem[current_node]);
                     list_for_each_entry(aentry, &alist[current_node], list) {
                        if ((aentry->filerq == fip->freq) &&
				(aentry->tx_cookie == fip->cookie)) {
                           afound = aentry;
                           break;
                        }
                     }

                     if (afound) {
                        if (unlikely(afound != fip->aretry)) BUG();
                        if (afound->ar_status == AR_Retried) {
                           /*
                            * So we have to be a little more careful here
                            * since we're racing with the async retry stuff
                            * and they (perhaps just) issued the request
                            * with our file pointer so we can't exactly allow
                            * it to be free'd unfortunately.
                            *
                            * We'll signal above that this guy needs to be
                            * held off for a while.
                            */
                           up(&aretrysem[current_node]);
                           rval = -EAGAIN;
                           goto done;
                        }
                        KDEBUG_RPS(0, "DVS: %s: did inode 0x%p file 0x%p new 0x%p\n",
					__FUNCTION__, ip, fp, another_fp);
                        DVS_TRACEL("RPSDtchd", ip, fp, another_fp, afound,
					afound->filerq);
                        afound->filerq->client_fp = another_fp;
                        afound->fp = another_fp;

                        if (!another_fp) {
                           /*
                            * We're clearing our file pointer and there's not
                            * another to replace it with so it can't really
                            * be retried.
                            */
                           afound->ar_status = AR_Cancel_Retry;
                        }
                     }
                     else {
                        rval = 0;  /* trumps anything else that was found */
                     }
                     up(&aretrysem[current_node]);
                  }
                  rq->fp = another_fp;

                  /*
                   * Since an I/O request using this file pointer was issued,
                   * we should wait for the server to finish up rather than
                   * moving on at this point with the close.
                   *
                   * The server is using the remote ref file handle and if we
                   * continue on, our close that's about to happen could occur
                   * in the middle of the server's read operation so rather
                   * than trying to protect the server from failures by a bad
                   * file handle or etc, just wait for the message to come
                   * back on this end before closing this file instance.
                   *
                   * We could technically wait on either reads_outstanding or
                   * msgs_outstanding but msgs is a little safer for the
                   * server since we know that the server would be completely
                   * done with our file handle at that point.
                   */
                  if (atomic_read(&rq->msgs_outstanding)) {
                     WAIT_FOR_MSGS(rq);
                  }
               }
               else {
                  /*
                   * Come back to this one in hopes that we found another
                   * file instance further down the list that we can patch
                   * in here.
                   */
                  rescan = required;
                  continue;
               }
            }
            else {
               another_fp = rq->fp;
            }
            break;

         case RPS_RQ_EXPIRED:
            break;
      }
   }

   if (rescan == required) {
      rescan = rescanning;
      goto rescan;
   }

done:
   up_read(&iip->requests_sem);

   if (rval != -EAGAIN) {
      KDEBUG_RPS(0, "DVS: %s: inode 0x%p file 0x%p\n", __FUNCTION__, ip, fp);
      DVS_TRACEL("RPSDtach", ip, fp, rval, another_fp, rq);
   }

   return rval;
}


/*
 * Walk the outstanding requests for an inode and perform actions as
 * specified by the cleanup mode.
 *
 * 1) CLUP_Force - Force the removal of any pending request
 * 2) CLUP_Passive - Cleanup as much as possible without doing any damage
 *
 * Returns:
 *   0: success, we were able to clean up all the requests on this inode
 *   >0: we weren't able to clean up them all, likely because one of the
 *       messages was being processed.
 *   EAGAIN: retry again with a fresh start.  This differs from being
 *           unsuccessful in that locks should be dropped/etc.  Likely due to
 *           failover concurrently running so this breaks any ties.
 */
int cleanup_reqs(struct inode *ip, cleanup_mode_t mode)
{
   int			rval = 0;
   struct inode_info	*iip = (struct inode_info *) ip->i_private;
   struct list_head	*lp, *tp;
   pages_request_t	*rq;
   int			retry = 0;

   KDEBUG_RPS(0, "DVS: %s: inode 0x%p mode %d\n", __FUNCTION__, ip, mode);
   DVS_TRACE("cleanrqs", ip, mode);

   down_write(&iip->requests_sem);

again:
   list_for_each_safe(lp, tp, &iip->requests) {
      freq_instance_t		*fip;
      struct file_request	*freq;
      int			state;
      int			ret;
      int			i;

      rq = list_entry(lp, pages_request_t, rq_list);

      switch ((state = atomic_read(&rq->state))) {
         int	refs_on_unlink;

         case RPS_RQ_FREE:
            BUG();

         case RPS_RQ_ACTIVE:
         case RPS_RQ_EXPIRING:
         case RPS_RQ_INVALID:
            if (mode == CLUP_Passive && rval != -EAGAIN) {
               /*
                * Return a count (will look like an error which it is) of
                * the ones that cannot be removed.
                */
               rval++;
               break;
            }

            /*
             * In all of these cases, we need to make sure that there aren't
             * messages arriving as we're trying to tear these down.
             */
            refs_on_unlink = -1;
            for (i = 0; i < rq->msg_count; i++) {
               fip = &rq->freqs[i];
               freq = fip->freq;  /* capture this before it can go away */
               if ((ret = unlink_filerq(freq, fip->cookie,
					fip->to_node, UNLNK_Cleanup)) > 0) {
                  if (unlikely(freq->u.iopagesrq.rq != rq)) BUG();

                  refs_on_unlink = atomic_dec_return(&rq->msgs_outstanding);

                  (void) process_iovs(rq, &freq->u.iopagesrq.ipr, NULL,
					PRIOV_Cleanup);
                  free_msg(freq);
               }
               else {
                  /*
                   * We couldn't unlink it for one of several reasons.
                   *
                   *  - A message just came back and is being processed.
                   *    That's only a problem if the request at this point still
                   *    is marked as active.  If it's not, we'll return that
                   *    we weren't successful and the upper layers will try
                   *    again.
                   *
                   *  - EAGAIN was returned so let's back off and retry since
                   *    failover is likely running and it's best to let it run
                   *    vs. trying to cancel the request out from underneath it.
                   */
                  if (ret == -EAGAIN) {
                     rval = ret;
                  }
                  else {
                     if (atomic_read(&rq->state) == RPS_RQ_ACTIVE) BUG();
                     DVS_TRACE("RPSClupU", ip, ret);
                     rval = 1;  /* being processed it appears */

                     /*
                      * If an outstanding write request made it to this point
                      * the writepages waiter must have been killed so clean up
                      * needs to be done.  If we couldn't unlink above but there
                      * are no more outstanding msgs then the last msg reply
                      * came back during the close and we can clean up now.
                      * Unless it is for a kthread, their teardown might lag
                      * behind the file close. Give them a chance to finish.
                      */
                     if ((rq->rq_flags & PIO_RQ_FLAGS_WRITEPAGE) && (!freq) &&
                         (!(ret = atomic_read(&rq->msgs_outstanding))) &&
                         (!(rq->wbc->for_kupdate || rq->wbc->for_background))) {
                        refs_on_unlink = 0;
                        rval = 0;
                     }
                  }
               }
            }
            if (!refs_on_unlink) {
               /*
                * We were able to unlink them all!  We know that the
                * transport has completed the transaction or process_iovs()
                * wouldn't have returned.
                */
               KDEBUG_RPS(0, "DVS: %s: cpu %d canceled rq 0x%p\n",
			__FUNCTION__, raw_smp_processor_id(), rq);
               DVS_TRACEL("cr_finrq", rq, ip, mode, 0, 0);

               /* Our last unlinked msg was the last (or only) */
               (void) finalize_request(rq);
               RELEASE_MSG_WAITERS(rq);
               list_del(&rq->rq_list);
               kfree_ssi(rq);
            }
            else {
               /*
                * We couldn't unlink anything so somebody's closing this out.
                * We'll check the requests again and this should have gone to
                * expired by that time.  If after a few times it's still not
                * expired, bail out and return the error upward.
                */
              retry++;
            }
            break;

         case RPS_RQ_EXPIRED:
            list_del(&rq->rq_list);
            kfree_ssi(rq);
            break;
      }
   }

   if (rval && retry <= 4) {  /* nothing special about the 4 */
      rval = 0;
      goto again;
   }

   up_write(&iip->requests_sem);

   DVS_TRACEL("RPSClupE", ip, mode, retry, rval, 0);

   return rval;
}
EXPORT_SYMBOL(cleanup_reqs);


static int ureadpages(struct file *fp, struct address_space *mapping,
                      struct list_head *page_list, unsigned num_pages,
                      int doing_readpage)
{
   struct page		*this_page, *single_page = NULL;
   int			rval = 0;  /* will always be the last error */
   int			pending_rval;
   int			page_count = 0;
   pages_desc_t		*pagesd;
   int			i;
   loff_t		indx_bias = -1, prev_bias = -1;
   loff_t		indx = -1, prev_indx = -1;
   int			decreasing_order = 1, start, stop;
   struct inode		*ip = file_inode(fp);
   struct inode_info	*iip = (struct inode_info *)ip->i_private;

   extent_t	*extents = NULL;
   int		extents_alloc = DEFAULT_EXTENTS;
   extent_t	*ep = NULL;

   int		extent_count = 1;  /* there will always be 1 for sure */

		/* required to be ordered as time progresses */
   enum		{ rp_unset, rp_in_cache,
			rp_extent_read } rp_state = rp_unset;

   int		contig_pages = 0;
   enum		{ sema_unset, reader, writer } sema_state = sema_unset;

   KDEBUG_OFC(0, "DVS: %s called. fp 0x%p map 0x%p num %u readpage %d\n", __FUNCTION__,
         fp, mapping, num_pages, doing_readpage);   

   /*
    * Start with some early initialization for the single-page case.
    * We need certain things set up in case there are early errors.
    * We'll initialize the remainder once things are allocated.
    */
   if (doing_readpage) {
      page_count = contig_pages = num_pages;
      single_page = (struct page*) page_list;
   }

   /*
    * If this is a page pre-read for a cached write and we know the file is
    * empty or the page is beyond the end of the file, no need to send a request
    * to the server to find out the page doesn't exist.  Just zero the page and
    * set it up for uwrite_begin.
    */
   if (doing_readpage == DO_PRERD) {
      loff_t page_offset = single_page->index * PAGE_SIZE;
      if (page_offset >= ip->i_size) {
         KDEBUG_RPS(0, "DVS: %s: write to empty or write extend. page 0x%p, indx %lu"
               " off %Ld i_size %Ld\n", __FUNCTION__, single_page,
               single_page->index, page_offset, ip->i_size);
         zero_user(single_page, 0, PAGE_CACHE_SIZE);
         SetPageUptodate(single_page);
         flush_dcache_page(single_page);
         unlock_page(single_page);

         return 0;
      }
   }

   /* 
    * Note that this routine will be called from every processor on a node
    * likely all with the same page list but that's not guaranteed.  All ranks
    * will compute the extents but only 1 will win for each extent.  A rank that
    * wins one may not necessarily win others.
    */

   pagesd = kmalloc_ssi(sizeof(pages_desc_t), GFP_KERNEL);
   if (!pagesd) {
      rval = -ENOMEM;
      goto done;
   }

   /* 
    * Add a reference to ourselves to keep pagesd around while we're still
    * processing extents.  There can be multiple requests for each collection
    * of pages so this needs to hang around until responses for all outstanding
    * requests are received.
    */
   atomic_set(&pagesd->ref_count, 1);
   atomic_set(&pagesd->state, RPS_PGSD_INUSE);

   /* 
    * Pages -- supplied by Linux -- already exist on a list, we want them in a
    * sorted array so we can determine where the extents boundaries are.
    */

   pagesd->pages = kmalloc_ssi(num_pages * sizeof(struct page *), GFP_KERNEL);
   if (!pagesd->pages) {
      rval = -ENOMEM;
      goto done;
   }

   extents = kmalloc_ssi(sizeof(extent_t) * DEFAULT_EXTENTS, GFP_KERNEL);
   if (!extents) {
      rval = -ENOMEM;
      goto done;
   }

   if (doing_readpage) {
      /*
       * We're emulating readpage() so the arguments/conditions are quite
       * different than how we'd be called from readpages() but we'll set
       * everything up so that we can just jump on the readpages train as if
       * it were already rolling with 1 extent.
       */

      ep = &extents[0];
      indx = indx_bias = 0;
      pagesd->pages[indx] = single_page;

      goto extents_are_known;
   }


   /************************************************************************
    *
    * Walk the supplied list of pages and sort them into contiguous ranges
    * of pages termed extents.
    *
    ************************************************************************/
   list_for_each_entry(this_page, page_list, lru) {
      indx = this_page->index;
      if (!page_count++) {
         /* First page -- assume decreasing, contiguous */
         indx_bias = prev_bias = (indx - num_pages) + 1;
         ep = &extents[0];
         ep->indx = 0;  /* in case increasing */
      }
      else {
         if (indx > prev_indx) {  /* oops, increasing order */
            decreasing_order = 0;
            if (page_count == 2) {
               indx_bias = prev_indx;
               pagesd->pages[0] = pagesd->pages[num_pages - 1];
            }
            indx_bias += ((indx - prev_indx) - 1);
         }
         else {  /* decreasing offset */
            indx_bias -= ((prev_indx - indx) - 1);
         }
      }

      if (indx_bias != prev_bias) {
         /*
          * extent_count always points to the next available one.
          */
         if (extent_count == extents_alloc) {
            extent_t	*new_extents;

            extents_alloc += DEFAULT_EXTENTS;
            new_extents = krealloc(extents, sizeof(extent_t) * extents_alloc,
				GFP_KERNEL);
            if (!new_extents) {
               extents_alloc -= DEFAULT_EXTENTS;
               rval = -ENOMEM;
               goto done;
            }
            extents = new_extents;
            ep = &extents[extent_count - 1];
         }

         if (decreasing_order) {
            ep->indx = prev_indx - prev_bias;
         }
         ep->count = contig_pages;
         ep = &extents[extent_count++];
         ep->indx = indx - indx_bias;
         contig_pages = 0;
      }

      contig_pages++;
      pagesd->pages[indx - indx_bias] = this_page;
      prev_indx = indx;
      prev_bias = indx_bias;
   } /* foreach page in  pagelist */

extents_are_known:

   if (page_count != num_pages) {
      printk(KERN_ERR "DVS: %s: page count mismatch %d %d\n",
		__FUNCTION__, page_count, num_pages);
   }

   /*
    * OK, we know the exact number of extents needed at this point but we don't
    * yet understand how many might require being split into 3 extents ala
    * case 4: below.  In that example, an extent that we've calculated here
    * would find an existing request (in-flight) that is in the middle of our
    * extent here, requiring that we split this extent into a new extent covering
    * the beginning portion, a middle portion which matches the in-flight request
    * and an extent for the tail portion.  In this case, each extent here
    * worst-case would require 2 so let's just allocate that many here where
    * it's easy to do.
    */
   if (extent_count * 2 > extents_alloc) {
      extent_t	*new_extents;
      int	current_extents = extents_alloc;

      extents_alloc = extent_count * 2;
      new_extents = krealloc(extents, sizeof(extent_t) * extents_alloc,
				GFP_KERNEL);
      if (!new_extents) {
         extents_alloc = current_extents;
         rval = -ENOMEM;
         goto done;
      }
      extents = new_extents;
      ep = &extents[extent_count - 1];
   }

   if (decreasing_order) {
      ep->indx = indx - indx_bias;
   }
   ep->count = contig_pages;


   /************************************************************************
    *
    * OK, they're now set up in order in an array ready for vmap()
    * Walk the extent list and do asynchronous reads for each extent.
    *
    ************************************************************************/
   if (decreasing_order) {
      start = extent_count;
      stop = 0;
   }
   else {
      start = -1;
      stop = extent_count - 1;
   }

   DVS_TRACEL("RPStart", ip, page_count, extent_count, decreasing_order,
		doing_readpage);
   KDEBUG_RPS(0, "DVS: %s: cpu %d requested %d pages in %d extents for inode 0x%p (%s)\n",
		__FUNCTION__, raw_smp_processor_id(), page_count, extent_count,
		ip, fpname(fp));

   /* 
    * Go through each extent under the read_lock and see if we've got a match to
    * an existing request.  Probability says that there is.  If we've got an
    * extent that's only partially covered by a request, split it and add it to
    * our extents assuming that somebody has already done the same and we
    * haven't got that far yet.
    * 
    * Once we've found something that's not covered, become a writer and recheck
    * that we're still in the lead for that extent and continue to hold the
    * write lock until we find something that's covered by an existing request.
    */
   down_read(&iip->requests_sem);
   sema_state = reader;

   do {  /* for each extent */
      loff_t		base_indx;
      loff_t		offset;
      size_t		count;
      struct list_head	*lp, *tp;

next_extent:
      if (stop == start) {
         break;
      }
      if (decreasing_order) {
         start--;
      }
      else {
         start++;
      }
      ep = &extents[start];
      base_indx = pagesd->pages[ep->indx]->index;
      offset = base_indx * PAGE_SIZE;
      count = ep->count * PAGE_SIZE;
      rp_state = rp_unset;
      KDEBUG_RPS(0, "DVS: %s: cpu %d extent %d(of %d) for inode 0x%p "
					"off %Ld(page %Ld) len %ld(%d)\n",
		__FUNCTION__, raw_smp_processor_id(), start, extent_count, ip,
		offset, base_indx, count, ep->count);
      DVS_TRACEL("RPSprExt", ip, offset, count, start, extent_count);

find_check:
      list_for_each_safe(lp, tp, &iip->requests) {  /* we delete expired ones */
         size_t			diff;
         pages_request_t	*lrq;

         lrq = list_entry(lp, pages_request_t, rq_list);
         /*
          * Skip/clean up expired requests so that the proxy threads don't
          * have to slow things down by grabbing the write lock.
          */
         switch (atomic_read(&lrq->state)) {
            case RPS_RQ_EXPIRED:
               if (sema_state == writer) {
                  list_del(&lrq->rq_list);
                  kfree_ssi(lrq);
               }
            case RPS_RQ_EXPIRING:
            case RPS_RQ_INVALID:  /* handle it at the close of the file */
               continue;

            case RPS_RQ_FREE:
               BUG();

            case RPS_RQ_ACTIVE:
               /* good! */
               break;
         }

         /*
          * First off, let's see if they touch in some fashion.  If so, we
          * would hope that this extent is completely contained in an
          * outstanding request but it's possible we may have to split an
          * extent into covered vs. not covered piece.  There should be at most
          * two not-covered portions.
          */
         if ((count + lrq->length) >
             (diff = ((lrq->offset + lrq->length) - offset)) && (diff > 0)) {
            /*
             * They touch! -- four possibilities:
             *   1) This extent starts prior to the request but overlaps, so we
             *      need to create a new extent for the initial portion.
             *   2) This extent is completely contained by the request.  This
             *      is easy because we're done with this one then.
             *   3) This extent overlaps on the end of the request and is
             *      not covered for a portion beyond, so we need to create a
             *      new extent for the tail portion.
             *   4) This extent completely spans the request so we need to
             *      create two extents, one for the initial portion and one
             *      for the tail.
             *
             * We'll start with the most common first.  If there's nothing to
             * do we'll move to the next extent but otherwise need to reduce
             * this extent by the amount that touches and keep searching.
             */
            int	original_extent = start;

            /*
             * If this extent touches one that we created something went
             * wrong in either extent creation or extent processing.
             */
            BUG_ON(pagesd == lrq->pagesd);

            if (offset >= lrq->offset) {
               if ((offset + count) <= (lrq->offset + lrq->length)) {
                  /* case 2 -- easy! */
                  if (doing_readpage) {
                     /*
                      * Something's wrong.  We were supplied a locked page that
                      * the kernel added to the cache for us and yet there's
                      * an outstanding request for that same page which would
                      * also have been in the cache at that point.
                      */
                     BUG();
                  }

                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 2 extent %d for inode 0x%p "
			"off %Ld len %ld request 0x%p Roff %Ld Rlen %ld\n",
			__FUNCTION__, raw_smp_processor_id(), original_extent,
			ip, offset, count, lrq, lrq->offset, lrq->length);
                  DVS_TRACEL("RPSc2", ip, original_extent, lrq, 0, 0);

                  if (sema_state == writer) {
		     /*
		      * OK, we're obviously not the lead dog in this race, drop
		      * back to a reader to continue (retreat with tail between
		      * legs?)
		      */
                     up_write(&iip->requests_sem);
                     DVS_TRACE("RPSrC2W-", ip, lrq);

                     down_read(&iip->requests_sem);
                     sema_state = reader;

                     KDEBUG_RPS(0, "DVS: %s: cpu %d backing off as writer on 0x%p\n",
			__FUNCTION__, raw_smp_processor_id(), lrq);
                  }

                  goto next_extent; /* nothing to do with this extent, it's covered */
               }
               else {
                  /* case 3 -- not covered off the back - shorten the front */
                  diff /= PAGE_SIZE;  /* diff still has what we want */
                  ep->indx += diff;
                  ep->count -= diff;
                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 3 extent %d for inode 0x%p off"
				"%Ld len %ld request 0x%p Roff %Ld Rlen %ld\n",
			__FUNCTION__, raw_smp_processor_id(), original_extent,
			ip, offset, count, lrq, lrq->offset, lrq->length);
                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 3 extent %d inode 0x%p "
						"shorten front by diff %zu\n",
			__FUNCTION__, raw_smp_processor_id(),
			original_extent, ip, diff);
                  DVS_TRACEL("RPSc3", ip, original_extent, ep->indx, diff, lrq);
               }
            }
            else {
               int	request_pages = lrq->length / PAGE_SIZE;

               diff = ((offset + count) - lrq->offset) / PAGE_SIZE;
               ep->count -= diff;  /* shorten the end in either case */

               if (diff > request_pages) {
                  extent_t	*new_ep;

                  /*
                   * case 4:
                   * Both ends are not covered - yuk.  OK, shorten this extent
                   * by the full range of the request and add a new extent for
                   * the remainder off the end.
                   *
                   * The new extent will be out of offset order but that's OK.
                   */

                   if (extent_count == extents_alloc) {
                      BUG();  /* remove at some point now allocating 2x above */
                   }

                  if (decreasing_order) {
                     /*
                      * Let's increment extent_count to be technically correct
                      * but we're going to have to (re)use the one right behind
                      * us which may or may not overwrite it.
                      */

                     extent_count++;
                     new_ep = &extents[++start];
                  }
                  else {
                     /*
                      * Just tack it on to the end of the extents even though
                      * it's offset is lower than the latter ones.
                      */
                     new_ep = &extents[extent_count++];
                  }
                  new_ep->indx = ep->indx + ep->count + request_pages;
                  new_ep->count = diff - request_pages;
                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 4 extent %d for inode 0x%p "
			"off %Ld len %ld request 0x%p Roff %Ld Rlen %ld\n",
			__FUNCTION__, raw_smp_processor_id(), original_extent,
			ip, offset, count, lrq, lrq->offset, lrq->length);
                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 4 extent %d inode 0x%p "
			"remove middle by request %d and diff %zu\n",
			__FUNCTION__, raw_smp_processor_id(), original_extent,
			ip, request_pages, diff);
                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 4 extent %d inode 0x%p "
			"add new extent %d of indx %d count %d\n",
			__FUNCTION__, raw_smp_processor_id(),
			original_extent, ip,
			(decreasing_order) ? original_extent : extent_count - 1,
			ep->indx, ep->count);
                  DVS_TRACEL("RPSc4", ip, original_extent, ep->indx, diff, lrq);
               }
               else {
                  /* case 1 -- we've already shortened the end of the extent */

                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 1 extent %d for inode 0x%p "
			"off %Ld len %ld request 0x%p Roff %Ld Rlen %ld\n",
			__FUNCTION__, raw_smp_processor_id(), original_extent,
			ip, offset, count, lrq, lrq->offset, lrq->length);
                  KDEBUG_RPS(0, "DVS: %s: cpu %d case 1 extent %d inode 0x%p "
			"shorten back by diff %zu\n",
			__FUNCTION__, raw_smp_processor_id(),
			original_extent, ip, diff);
                  DVS_TRACEL("RPSc1", ip, original_extent, ep->indx, diff, lrq);
               }
            }

            /*
             * OK, we just modified the extent we started with, let's just start
             * the whole thing over since we could now have been covered by one
             * that we passed up earlier.  Reset the extent pointer so we see
             * this one again on the next iteration.
             */
            if (decreasing_order) {
               start++;
            }
            else {
               start--;
            }
            KDEBUG_RPS(0, "DVS: %s: cpu %d case 1,3,4 extent %d for inode 0x%p "
			"request 0x%p restart start to %d\n",
			__FUNCTION__, raw_smp_processor_id(), original_extent,
			ip, lrq, start);
            goto next_extent;  /* process this modified one again */
         }  /* the two requests touch */
      }  /* foreach request list */


      /* 
       * If we made it to this point, we didn't find an outstanding request
       * that matched our range.
       */
      if (sema_state == writer) {
         pages_request_t	*rq;
         int			*page_status;
         int			error_count;

         page_status = kmalloc_ssi(sizeof(int) * ep->count, GFP_KERNEL);
         if (!page_status) {
            rval = -ENOMEM;
            goto done;
         }

         /*
          * OK, it's the real deal - we won -- maybe!  Check to make sure we
          * can add it to the page cache first.  If that's the case, we get
          * to keep the write lock since it appears that we're in the lead!
          */
         error_count = pending_rval = 0;
         for (i = 0; i < ep->count; i++) {
            struct page	*tp = pagesd->pages[ep->indx + i];
            int		ret;

            ret = (doing_readpage) ? 0 : add_to_page_cache(tp, mapping,
							tp->index, GFP_KERNEL);
            if (ret) {
               error_count++;
               page_status[i] = ret;  /* need to know which ones we added */
               pending_rval = ret;
            }
            else {
               if (!doing_readpage) {
                  list_del(&tp->lru);  /* page_list threads through lru */
                  lru_cache_add_file(tp);
               }
            }
         }

         if (error_count) {
            /*
             * OK, we're obviously quite late to the party since it's
             * already been added to the cache.  Back out as a writer.
             * The request likely came and went from the list already.
             */
            if (error_count != ep->count) {
               /*
                * Some apparently made it.  Walk the list and find the ones
                * that we successfully added to the page cache and mark them
                * in error.  They'll come back in through ureadpage() if needed.
                */
               for (i = 0; i < ep->count; i++) {
                  if (!page_status[i]) {
                     struct page	*tp = pagesd->pages[ep->indx + i];

                     error_page_range(&tp, 1, !doing_readpage, 0);

                     DVS_TRACE("RPSrPCaE", ip, tp->index);
                     KDEBUG_RPS(0, "DVS: %s: cpu %d page %ld added to existing "
				"range for %s\n", __FUNCTION__,
				raw_smp_processor_id(), tp->index, fpname(fp));
                  }
               }
               rval = pending_rval;
            }
            up_write(&iip->requests_sem);
            DVS_TRACE("RPSrLtW-", ip, start);

            down_read(&iip->requests_sem);
            sema_state = reader;
            KDEBUG_RPS(0, "DVS: %s: cpu %d backing writer off on extent %d for "
					"inode 0x%p off %Ld(page %Ld) len %ld\n",
		__FUNCTION__, raw_smp_processor_id(),
		start, ip, offset, base_indx, count);
            kfree_ssi(page_status);
            goto next_extent;
         }

         rp_state++;  /* in cache */

         kfree_ssi(page_status);

         /*
          * Continue using the default number of freqs for readpage requests.
          * May need to be revisited if readpages kernel interface or blocksize
          * handling changes.
          */
         rq = init_pages_request(DEFAULT_FREQ_INSTANCES);
         if (!rq) {
            rval = -ENOMEM;
            goto done;
         }

         /* freqs, rma_handle, vmap_addr filled in by process_extent() */
         rq->ip = ip;
         rq->fp = fp;  /* fast way to know which file initiated this request */
         rq->offset = offset;
         rq->length = count;

         rq->pagesd = pagesd;

         rq->ext_indx = ep->indx;
         rq->ext_count = ep->count;

         atomic_inc(&pagesd->ref_count);  /* this pages request uses pagesd */
         atomic_set(&rq->state, RPS_RQ_ACTIVE);

         rq->rq_flags |= (doing_readpage) ? RPS_RQ_FLAGS_READPAGE : 0;

         /* notify process_iovs this is a pre-read for a page cache write */
         if (doing_readpage == DO_PRERD) {
            rq->rq_flags |= PIO_RQ_FLAGS_PREREAD;
         }

         list_add_tail(&rq->rq_list, &iip->requests);

         KDEBUG_RPS(0, "DVS: %s: cpu %d won extent %d for inode 0x%p"
					"off %Ld(page %Ld) len %ld\n",
		__FUNCTION__, raw_smp_processor_id(), start, ip,
		offset, base_indx, count);
         KDEBUG_RPS(0, "DVS: %s: cpu %d extent %d for inode 0x%p added request 0x%p"
				" pagesd 0x%p ep_indx %d ep_count %d\n",
		__FUNCTION__, raw_smp_processor_id(), start, ip, rq, pagesd,
		ep->indx, ep->count);
         DVS_TRACEL("RPSWRq", ip, offset, count, rq, extent_count);

         rp_state++;  /* starting extent read */
         if ((rval = process_extent(fp, rq)) < 0) {
            /*
             * If this had an error it would have cleaned up as much as
             * possible.  For now, let's bail out and fail the whole call as
             * opposed to thinking that perhaps the next extent (if there is
             * one) might work OK.  The likelyhood is it won't.
             */
            goto done;
         }
      }
      else {
         /*
          * If there was a reliable way to check the pages to see if they're
          * already in the cache before we become a writer that'd be better.
          * We could be way late and the request has been processed, deleted
          * with the pages already being in the cache.
          */
         if (sema_state != reader) BUG();
         up_read(&iip->requests_sem);

         down_write(&iip->requests_sem);
         sema_state = writer;

         DVS_TRACEL("RPSrpsW+", ip, current->pid, start, 0, 0);
         KDEBUG_RPS(0, "DVS: %s: cpu %d now writer for extent %d inode 0x%p"
					"off %Ld(page %Ld) len %ld\n",
		__FUNCTION__, raw_smp_processor_id(), start, ip,
		offset, base_indx, count);
         goto find_check;
      }
   } while (start != stop);  /* process each extent */

done:
   /*
    * Check to see whether we need to clean up page-related stuff.
    */
   if (rval) {
      if (doing_readpage) {
         /*
          * The supplied page is always placed in the page cache by the kernel
          * and released after we're done.  Things may not have been allocated
          * properly so use the initial variables to process the page here.
          */
         SetPageError(single_page);
         unlock_page(single_page);
      }
      else {
         if (rp_state == rp_in_cache) {
            /*
             * It's in the cache but we didn't make it to the read_extent()
             * call.  That means we need to error every extent page.
             * read_extent() would have otherwise taken care of erroring the
             * pages related to the actual error.
             */
            loff_t start_index = pagesd->pages[ep->indx]->index;

            DVS_TRACEL("RPSrPCdE", ip, start_index, ep->count, rval, 0);
            KDEBUG_RPS(0, "DVS: %s: cpu %d erroring pages %Ld-%Ld of %s on exit\n",
			__FUNCTION__, raw_smp_processor_id(),
			start_index, start_index + ep->count - 1, fpname(fp));

            error_page_range(&pagesd->pages[ep->indx], ep->count, 1, 0);
         }
      }
   }

   if (sema_state == writer) {
      up_write(&iip->requests_sem);
      DVS_TRACE("RPSExiW-", ip, current->pid);
      KDEBUG_RPS(0, "DVS: %s: cpu %d ip 0x%p unlocking as writer done\n",
			__FUNCTION__, raw_smp_processor_id(), ip);
   }
   else if (sema_state == reader) {
      up_read(&iip->requests_sem);
   }

   /*
    * OK, now see what we need to free.  The pages_request (if allocated)
    * we don't need to worry about.  read_extent either left it intact on
    * the requests chain (being valid or invalid) or possibly got rid of it.
    */
   if (extents) {
      kfree_ssi(extents);  /* easy -- only used locally */
   }

   /*
    * A little more tricky since we could have issued messages/etc.
    */
   if (pagesd && !atomic_dec_return(&pagesd->ref_count)) {
      /*
       * We either didn't use pagesd or we did and the messages all came back
       * and were processed before we could leave this routine.
       */
      if (pagesd->pages) {
         kfree_ssi(pagesd->pages);
      }
      atomic_set(&pagesd->state, RPS_PGSD_FREE);
      kfree_ssi(pagesd);
   }

   KDEBUG_RPS(0, "DVS: %s: cpu %d exiting OK on inode 0x%p with %d\n",
		__FUNCTION__, raw_smp_processor_id(), ip, rval);

   return rval;
}


#ifdef NOT_USED
static int usync_page(struct page *pagep)
{
	printk(KERN_ERR "DVS: usync_page: called!!!\n");
	return(-USIERR_NOT_SUPPORTED);
}
#endif

static int uwrite_begin(struct file *file, struct address_space *mapping, 
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	struct page *page;
	pgoff_t index;
	struct inode *inode = mapping->host;
	struct inode_info *iip = (struct inode_info *)inode->i_private;
	int rval = 0;

	index = pos >> PAGE_CACHE_SHIFT;

	KDEBUG_OFC(0, "DVS: %s: fp 0x%p map 0x%p pos %lld len %u index %lu flags %u\n",
			__FUNCTION__, file, mapping, pos, len, index, flags);

retry:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	iip->wb_fp = file;

	if (PageUptodate(page))
		goto out;

	if (len == PAGE_CACHE_SIZE)
		goto out;

	/* read in backing page as single page readpage first */
	rval = ureadpages(file, NULL, (struct list_head *)page, 1, DO_PRERD);
	if (rval < 0) {
		page_cache_release(page);
		return rval;
	}

	/* ureadpages will unlock page on completion. Wait for read to complete
	 * and make sure page is valid. */
	lock_page(page);
	if (!PageUptodate(page)) {
		unlock_page(page);
		page_cache_release(page);
		return -EIO;
	}

	/* page was moved to new mapping while unlocked - retry it */
	if (page->mapping != mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}

out:
	*pagep = page;
	return rval;
}

/*
 * Helper function to trigger page writeback for a given number of dirty
 * pages. Writeback will attempt to writeback at least that number of pages.
 * Similar to the (unexported) kernel function filemap_fdatawrite but allows for
 * a faster WB_SYNC_NONE writeback.
 */
static int dvs_fdatawrite_nr_nowait(struct address_space *mapping, int count)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
		.nr_to_write = count,
	};

	KDEBUG_OFC(0, "DVS: %s: count %d map 0x%p\n",
			__FUNCTION__, count, mapping);

	wbc.range_start = 0;
	wbc.range_end = LLONG_MAX; /* tells writeback to check entire file */

	if (mapping->a_ops->writepages)
		ret = mapping->a_ops->writepages(mapping, &wbc);
	else
		BUG(); /* writepages should always be set in DVS */

	return ret;
}

static int uwrite_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *pagep, void *fsdata)
{
	struct inode *inode = pagep->mapping->host;
	struct inode_info *iip = (struct inode_info *)inode->i_private;
	loff_t end = pos + copied;
	int ret, count_dirty = 0;

	KDEBUG_OFC(0, "DVS: %s: %Ld %u %u 0x%lx %Ld\n", __FUNCTION__, pos, copied,
		len, (long)pagep->flags, inode->i_size);

	/* full page wasn't written as told to write_begin. need to read in
	 * remaining page data to get the page uptodate */
	if (unlikely((len == PAGE_CACHE_SIZE) && (copied != PAGE_CACHE_SIZE))) {
		//error out for now
		SetPageError(pagep);
		unlock_page(pagep);
		page_cache_release(pagep);

		return -EIO;
	}

	if (!PageUptodate(pagep))
		SetPageUptodate(pagep);

	if (end > inode->i_size) {
		// do we need inode_add_bytes here?
		i_size_write(inode, end);
		inode->i_blocks = compute_file_blocks(inode);
	}

	/* 
	 * When write cache is enabled, the Linux kernel does not use the
	 * normal uwrite or uaio_write entry-points, but instead uses the
	 * uwrite_begin/uwrite_end entry-points. uwrite_begin is used to
	 * set up the cache page for writing (including pre-fill), and
	 * uwrite_end is used in place of uwrite/uaio_write. So this is
	 * where we accumulate the user write statistics, under the
	 * VFS_OP_AIO_WRITE tag.
	 */
	dvsproc_stat_update(INODE_ICSB(inode)->stats,
			    DVSPROC_STAT_CLIENT_LEN,
			    VFS_OP_AIO_WRITE, len);
	dvsproc_stat_update(INODE_ICSB(inode)->stats,
			    DVSPROC_STAT_CLIENT_OFF,
			    VFS_OP_AIO_WRITE, pos+len);

	/* add to dirty count if page was not previously dirty */
	if (!PageDirty(pagep))
		count_dirty = atomic_inc_return(&iip->dirty_pgs);

	set_page_dirty(pagep);
	unlock_page(pagep);
	page_cache_release(pagep);

	/* If the inode has hit its dirty page threshold trigger a writeback */
	if (count_dirty >= wb_threshold_pages) {
		ret = dvs_fdatawrite_nr_nowait(mapping, count_dirty);
		if (ret < 0)
			printk(KERN_ERR "DVS: %s: datawrite failure %d\n",
					__FUNCTION__, ret);
	}

	return copied;
}

/*
 * DVS must have a valid direct_IO function defined in its
 * address_space_operations for direct I/O to work.  Direct I/O is
 * handled by the default DVS read/write functions however as they
 * can avoid the client node page cache as expected.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
static ssize_t udirect_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			  loff_t offset, unsigned long nr_segs)
{
	ssize_t ret;

	if (rw == WRITE) {
		ret = uwrite(iocb, iov, nr_segs, offset);
		KDEBUG_OFC(0, "DVS: udirect_IO: uwrite returns %ld\n", ret);
	} else {
		ret = uread(iocb, iov, nr_segs, offset);
		KDEBUG_OFC(0, "DVS: udirect_IO: uread returns %ld\n", ret);
	}

	return ret;
}
#else
static ssize_t udirect_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;

	if (iov_iter_rw(iter) == WRITE) {
		ret = uwrite(iocb, iter);
		KDEBUG_OFC(0, "DVS: udirect_IO: uwrite returns %ld\n", ret);
	} else {
		ret = uread(iocb, iter);
		KDEBUG_OFC(0, "DVS: udirect_IO: uread returns %ld\n", ret);
	}

	return ret;
}
#endif
/*
 * File operation stat wrappers
 */

static loff_t
ulseek_stats(struct file *fp, loff_t off, int op)
{
	loff_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ulseek(fp, off, op);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_LLSEEK, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_LLSEEK,
			    elapsed_jiffies);
    
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
static ssize_t
do_sync_read_stats(struct file *fp, char __user *buf, size_t len, loff_t *ppos)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = do_sync_read(fp, buf, len, ppos);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_READ, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_READ,
			    elapsed_jiffies);
    
	return ret;
}

static ssize_t
uread_stats(struct kiocb *iocb, const struct iovec *iov, unsigned long nr_segs,
	    loff_t pos)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(iocb->ki_filp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uread(iocb, iov, nr_segs, pos);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	KDEBUG_OFC(0, "DVS: uread_stats: uread returns %ld\n", ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_AIO_READ, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_AIO_READ,
			    elapsed_jiffies);

	return ret;
}

static ssize_t
do_sync_write_stats(struct file *fp, const char __user *buf, size_t len,
		    loff_t *ppos)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = do_sync_write(fp, buf, len, ppos);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_WRITE, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_WRITE,
			    elapsed_jiffies);
    
	return ret;
}

static ssize_t
uwrite_stats(struct kiocb *iocb, const struct iovec *iov,
	     unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(iocb->ki_filp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uwrite(iocb, iov, nr_segs, pos);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_AIO_WRITE, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_AIO_WRITE,
			    elapsed_jiffies);

	return ret;
}
#else
static ssize_t uread_iter_stats(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(iocb->ki_filp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uread(iocb, to);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	KDEBUG_OFC(0, "DVS: uread_iter_stats: uread returns %ld\n", ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_AIO_READ, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_AIO_READ,
			    elapsed_jiffies);

	return ret;
}

static ssize_t uwrite_iter_stats(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(iocb->ki_filp)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = uwrite(iocb, from);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	KDEBUG_OFC(0, "DVS: uwrite_iter_stats: uwrite returns %ld\n", ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_AIO_WRITE, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_AIO_WRITE,
			    elapsed_jiffies);

	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
static int
ureaddir_stats(struct file *fp, void *dirent, filldir_t filldir)
#else
static int
ureaddir_stats(struct file *fp, struct dir_context *ctx)
#endif
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	ret = ureaddir(fp, dirent, filldir);
#else
	ret = ureaddir(fp, ctx);
#endif

	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_READDIR, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_READDIR,
			    elapsed_jiffies);
    
	return ret;
}

static long
uioctl_stats(struct file *fp, unsigned int cmd, unsigned long arg)
{
	long ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uioctl(fp, cmd, arg);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_UNLOCKED_IOCTL,
			    ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME,
			    VFS_OP_UNLOCKED_IOCTL, elapsed_jiffies);
    
	return ret;
}

static int
ummap_stats(struct file *fp, struct vm_area_struct *vma)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ummap(fp, vma);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_MMAP, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_MMAP,
			    elapsed_jiffies);
    
	return ret;
}

static int
uopen_stats(struct inode *ip, struct file *fp)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uopen(ip, fp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_OPEN, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_OPEN,
			    elapsed_jiffies);
    
	return ret;
}

static int
uflush_stats(struct file *fp, fl_owner_t id)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uflush(fp, id);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_FLUSH, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_FLUSH,
			    elapsed_jiffies);
    
	return ret;
}

static int
urelease_stats(struct inode *ip, struct file *fp)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = urelease_common(ip, fp, 0);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_RELEASE, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_RELEASE,
			    elapsed_jiffies);
    
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static int
ufsync_stats(struct file *fp, struct dentry *de, int datasync)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ufsync(fp, de, datasync);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_FSYNC, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_FSYNC,
			    elapsed_jiffies);
    
	return ret;
}
#else
static int
ufsync_stats(struct file *fp, loff_t off1, loff_t off2, int datasync)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ufsync(fp, off1, off2, datasync);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_FSYNC, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_FSYNC,
			    elapsed_jiffies);
    
	return ret;
}
#endif

static int
ufasync_stats(int arg1, struct file *fp, int arg3)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ufasync(arg1, fp, arg3);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_FASYNC, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_FASYNC,
			    elapsed_jiffies);
    
	return ret;
}

static int
ulock_stats(struct file *fp, int cmd, struct file_lock *fl)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ulock(fp, cmd, fl);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_LOCK, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_LOCK,
			    elapsed_jiffies);
    
	return ret;
}

static int
uflock_stats(struct file *fp, int cmd, struct file_lock *fl)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uflock(fp, cmd, fl);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_FLOCK, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_FLOCK,
			    elapsed_jiffies);
    
	return ret;
}

static int
uwritepage_stats(struct page *pagep, struct writeback_control *wbc)
{
	int ret;
	struct dvsproc_stat *stats = NULL;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uwritepage(pagep, wbc);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_WRITEPAGE, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_WRITEPAGE,
			    elapsed_jiffies);
    
	return ret;
}

static int
uwritepages_stats(struct address_space *mapping, struct writeback_control *wbc)
{
	int ret;
	struct dvsproc_stat *stats = NULL;
	unsigned long elapsed_jiffies = jiffies;

	ret = uwritepages(mapping, wbc);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_WRITEPAGES, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_WRITEPAGES,
			elapsed_jiffies);

	return ret;
}

static int
ureadpage_stats(struct file *fp, struct page *pagep)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ureadpage(fp, pagep);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_READPAGE, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_READPAGE,
			    elapsed_jiffies);
    
	return ret;
}

static int
ureadpages_stats(struct file *fp, struct address_space *mapping,
		 struct list_head *page_list, unsigned num_pages)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = ureadpages(fp, mapping, page_list, num_pages, DO_RPGS);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_READPAGES, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_READPAGES,
			    elapsed_jiffies);
    
	return ret;
}

static int
uwrite_begin_stats(struct file *fp, struct address_space *mapping, loff_t pos,
		   unsigned len, unsigned flags, struct page **pagep,
		   void **fsdata)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uwrite_begin(fp, mapping, pos, len, flags, pagep, fsdata);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_WRITE_BEGIN, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_WRITE_BEGIN,
			    elapsed_jiffies);
    
	return ret;
}

static int
uwrite_end_stats(struct file *fp, struct address_space *mapping, loff_t pos,
		 unsigned len, unsigned copied, struct page *pagep,
		 void *fsdata)
{
	int ret;
	struct dvsproc_stat *stats = FILE_ICSB(fp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = uwrite_end(fp, mapping, pos, len, copied, pagep, fsdata);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_WRITE_END, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_WRITE_END,
			    elapsed_jiffies);
    
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
static ssize_t
udirect_IO_stats(int rw, struct kiocb *iocb, const struct iovec *iov,
		 loff_t offset, unsigned long nr_segs)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(iocb->ki_filp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = udirect_IO(rw, iocb, iov, offset, nr_segs);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_DIRECT_IO, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_DIRECT_IO,
			    elapsed_jiffies);
    
	return ret;
}
#else
static ssize_t
udirect_IO_stats(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;
	struct dvsproc_stat *stats = FILE_ICSB(iocb->ki_filp)->stats;
	unsigned long elapsed_jiffies = jiffies;
	
	ret = udirect_IO(iocb, iter);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER, VFS_OP_DIRECT_IO, ret);
	dvsproc_stat_update(stats, DVSPROC_STAT_OPER_TIME, VFS_OP_DIRECT_IO,
			    elapsed_jiffies);
    
	return ret;
}
#endif

/* 
 * Useful to know the flow. read() -> aio_read(), write() -> aio_write().
 *
 * .read
 *   do_sync_read_stats +DVSPROC_STAT_OPER,VFS_OP_READ
 *     do_sync_read
 *       filp->f_op->aio_read == .aio_read
 *         do_sync_read_stats +DVSPROC_STAT_OPER,VFS_OP_AIO_READ
 *           uread +DVSPROC_STAT_CLIENT_LEN,VFS_OP_AIO_READ
 *                 +DVSPROC_STAT_CLIENT_OFF,VFS_OP_AIO_READ
 *             if cached: generic_file_aio_read (linux)
 *               .readpages, satisfies read from cache
 *             if !cached: uread2
 *               send RQ_PARALLEL_READ
 *               
 * .write
 *   do_sync_write_stats +DVSPROC_STAT_OPER,VFS_OP_WRITE
 *     do_sync_write
 *       filp->f_op->aio_write == .aio_write
 *         uwrite_stats +DVSPROC_STAT_OPER,VFS_OP_AIO_WRITE
 *           uwrite +DVSPROC_STAT_CLIENT_LEN,VFS_OP_AIO_WRITE
 *                  +DVSPROC_STAT_CLIENT_OFF,VFS_OP_AIO_WRITE
 *             uwrite2
 *               send RQ_PARALLEL_WRITE
 *               
 */
struct file_operations upfsfops = {
	llseek:		ulseek_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,9)
	read:		do_sync_read_stats,
	write:		do_sync_write_stats,
	aio_read:	uread_stats,
	aio_write:	uwrite_stats,
#else
	read_iter:	uread_iter_stats,
	write_iter:	uwrite_iter_stats,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	readdir:	ureaddir_stats,
#else
	iterate:	ureaddir_stats,
#endif
	unlocked_ioctl:	uioctl_stats,
	mmap:		ummap_stats,
	open:		uopen_stats,
	flush:		uflush_stats,
	release:	urelease_stats,
	fsync:		ufsync_stats,
	fasync:		ufasync_stats,
	lock:		ulock_stats,
	/*readv:	ureadv,*/
	/*writev:	uwritev,*/
	/*sendpage:	usendpage,*/
	flock:		uflock_stats,
};
EXPORT_SYMBOL(upfsfops);

struct address_space_operations upfsaops = {
	writepage:		uwritepage_stats,
	writepages:		uwritepages_stats,
	readpage:		ureadpage_stats,
	readpages:		ureadpages_stats,
	/*sync_page:		usync_page,*/
	write_begin:		uwrite_begin_stats,
	write_end:		uwrite_end_stats,
	direct_IO:		udirect_IO_stats,
};

/* Function prototype for pseudo-linker function with dvsproc */
void close_all_quiesced_files(struct quiesced_dir *qdir);
void dvs_rr_ref_put(struct remote_ref *rr);

static int __init
init_dvs(void)
{
	int i;
	int rval;

	extern void (*dvs_close_quiesced_files_func)(struct quiesced_dir *qdir);
	extern void (*dvs_rr_ref_put_func)(struct remote_ref *rr);

	if ((rval = dvsutil_init()))
		return rval;

	if (dvsof_concurrent_writes != -1) {
		if (dvsof_concurrent_writes < 0) {
			printk(KERN_ERR "DVS: %s: Error: Invalid value %d for "
			       "dvsof_concurrent_writes\n", __func__,
			       dvsof_concurrent_writes);
			return -EINVAL;
		}

		/* Limit number of concurrent writers in
		 * dvs_rq_parallel_write() */
		if (dvsof_concurrent_writes == 0)
			dvsof_concurrent_writes_count = num_online_cpus();
		else
			dvsof_concurrent_writes_count = dvsof_concurrent_writes;

		sema_init(&dvsof_concurrent_writes_sema,
		          dvsof_concurrent_writes_count);
	}

	if (dvsof_concurrent_reads != -1) {
		if (dvsof_concurrent_reads < 0) {
			printk(KERN_ERR "DVS: %s: Error: Invalid value %d for "
			       "dvsof_concurrent_reads\n", __func__,
			       dvsof_concurrent_reads);
			return -EINVAL;
		}

		/* Limit number of concurrent readers in
		 * dvs_rq_parallel_read() */
		if (dvsof_concurrent_reads == 0)
			dvsof_concurrent_reads_count = num_online_cpus();
		else
			dvsof_concurrent_reads_count = dvsof_concurrent_reads;

		sema_init(&dvsof_concurrent_reads_sema,
		          dvsof_concurrent_reads_count);
	}

	sema_init(&dvs_super_blocks_sema, 1);
	sema_init(&iotsem, 1);
	sema_init(&ro_cache_sem, 1);

	initialize_syscall_linkage();

	ssiutil_register_handlers(handler_receive, DVSIPC_INSTANCE_DVS,
	                          do_usifile_stats);
	ssiutil_register_handlers(handler_node_up, DVSIPC_INSTANCE_DVS,
	                          file_node_up);
	ssiutil_register_handlers(handler_node_down, DVSIPC_INSTANCE_DVS,
	                          file_node_down);

	inode_op_table = ht_init(INODE_OP_SIZE);
	if (inode_op_table == NULL) {
		printk(KERN_ERR "DVS: ht_init failed\n");
		goto init_failed;
	}

	if (sync_init()) {
		printk(KERN_ERR "DVS: sync_init failed\n");
		goto sync_fail;
	}

	/* ro_cache hashtable setup */
	ro_cache_table = ht_init(INODE_OP_SIZE);
	if (ro_cache_table == NULL) {
		printk(KERN_ERR "DVS: ht_init failed\n");
		goto htable_fail_1;
	}

	if (dvspn_init()) {
		printk(KERN_ERR "DVS: dvspn_init failed\n");
		goto htable_fail_2;
	}

	for (i = 0; i < numoptions; i++) {
		optionlist[i].opt_len = strlen(optionlist[i].opt_name);
		KDEBUG_OFC(0, "DVS: %s: option %d len %d name %s\n", __FUNCTION__,
			   i, optionlist[i].opt_len, optionlist[i].opt_name);
	}

	/*
	 * dvs.ko can only depend on functions in dvs_proc.ko or depmod gets
	 * ornery. But dvs_proc.ko absolutely requires access to the
	 * close_all_quiesced_files function for the quiesce feature.
	 * We can remedy this by combining dvs_proc.ko and dvs.ko
	 * into one module at some point in the future
	 */
	dvs_close_quiesced_files_func = close_all_quiesced_files;
	dvs_rr_ref_put_func = dvs_rr_ref_put;

	KDEBUG_INF(0, "DVS: dvsof module loaded\n");
	return 0;

htable_fail_2:
	ht_delete(ro_cache_table, 1);
htable_fail_1:
	ht_delete(inode_op_table, 1);
sync_fail:
	sync_exit();
init_failed:
	dvspn_exit();

	printk(KERN_ERR "DVS: dvsof module initialization failed\n");
	return 1;
}

static void __exit
exit_dvs(void)
{
	ssiutil_unregister_handlers(handler_receive, DVSIPC_INSTANCE_DVS,
	                            do_usifile_stats);
	ssiutil_unregister_handlers(handler_node_up, DVSIPC_INSTANCE_DVS,
	                            file_node_up);
	ssiutil_unregister_handlers(handler_node_down, DVSIPC_INSTANCE_DVS,
	                            file_node_down);

	/* Make sure IPC is disabled */
	ipc_term();

	/* clean up UPFS server state */
	file_node_down(-1);

	/* Cleanup the hash tables */
	ht_delete(inode_op_table, 1);
	ht_delete(ro_cache_table, 1);

	sync_exit();
	dvspn_exit();

	dvsutil_exit();	

	KDEBUG_INF(0, "DVS: dvsof module unloaded\n");
}

module_init(init_dvs);
module_exit(exit_dvs);
MODULE_LICENSE(DVS_LICENSE);
