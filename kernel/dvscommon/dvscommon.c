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

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <asm/bitops.h>
#include <linux/dirent.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/dcache.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
/* task_lock()/unlock() APIs moved from <linux/sched.h> */
#include <linux/sched/task.h>
/* new API for handling inode->i_version */
#include <linux/iversion.h>
#endif
#include <linux/mount.h>
#include <linux/uidgid.h>
#ifdef CONFIG_CRAY_ABORT_INFO
#include <linux/job_acct.h>
#endif /* CONFIG_CRAY_ABORT_INFO */
#include <uapi/linux/magic.h>
/* required for internal struct mount definition used in find_vfsmount */
#include <fs/mount.h>

#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"
#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/kernel/hash_table.h"
#include "common/kernel/fnv_hash.h"
#include "common/kernel/usiipc.h"
#include "common/kernel/dvsfs.h"
#include "dvs/kernel/usifile.h"
#include "dvs/kernel/usifileproto.h"
#include "dvs/usisuper.h"

#ifdef CONFIG_CRAY_COMPUTE
static DEFINE_SPINLOCK(job_kill_lock);
#endif

static struct vfsmount *find_vfsmount(struct dentry *dep);

/*
 * In case the DVS filesystem has been mounted on the client node
 * with a local mountpoint different than that used on the server nodes,
 * replace the local mountpoint in the pathname being sent to the server
 * with the remote mountpoint.
 *
 * The algorithm is as follows:
 *
 *    - Find the final part of the pathname after the local mountpoint prefix
 *    - Move that final part of the pathname to the start of the buffer plus
 *      the length of the remote mountpoint prefix (to allow space for it)
 *    - Copy in the new mountpoint prefix at the start of the buffer
 *    - Return the start of the buffer as the new pathname pointer
 *
 * 'bufp' points to the start of the page-size memory buffer
 * 'path' points to the start of the pathname in the buffer
 *        (usually near the end of the buffer)
 * 'localprefix' the pathname prefix of the local mountpoint
 * 'ip'   is the inode for the file whose pathname is being generated
 */

char *replacepath(char *bufp, char *path, char *localprefix, struct inode *ip)
{
	char *remoteprefix;
	int localprefixlen;
	int remoteprefixlen;
	int stringremlen;

	if (!bufp || !path || !ip) {
		return path;
	}

	remoteprefix = INODE_ICSB(ip)->remoteprefix;
	localprefixlen = strlen(localprefix);
	remoteprefixlen = strlen(remoteprefix);

	/* Local and remote mountpoints are the same - no replacement */
	if (strcmp(localprefix, remoteprefix) == 0) {
		return path;
	}

	/* Path does not start with local mountpoint - no replacement */
	if (strncmp(path, localprefix, localprefixlen) != 0) {
		return path;
	}

	/*
	 * Do not remove local prefix when it is the root directory.
	 * Need the "/" to separate the remote_prefix from the
	 * pathname. Occurs when chroot'd to dvs fs.
	 */
	if (strcmp(localprefix, "/") == 0) {
		localprefixlen--;
	}

	stringremlen = strlen(path) - localprefixlen;
	if ((remoteprefixlen + stringremlen) >= PAGE_SIZE) {
		printk(KERN_ERR "DVS: %s: unable to replace prefix %s "
				"with %s on path %s: string too long\n",
		       __FUNCTION__, localprefix, remoteprefix, path);
		return path;
	}
	KDEBUG_PNC(0, "DVS: %s: local path %s localprefix %s\n", __FUNCTION__,
		   path, localprefix);
	if (localprefixlen != remoteprefixlen) {
		memmove(bufp + remoteprefixlen, path + localprefixlen,
			stringremlen);
		path = bufp;
	}
	memcpy(path, remoteprefix, remoteprefixlen);
	*(path + stringremlen + remoteprefixlen) = 0;
	KDEBUG_PNC(0, "DVS: %s: remote path %s remoteprefix %s\n", __FUNCTION__,
		   path, remoteprefix);

	return path;
}

/*
 * update local inode values to match the remote inode
 */
void update_inode(struct inode_attrs *remoteip, struct inode *newip,
		  struct dentry *dep, struct file *fp, int invalidate)
{
	struct inode_info *iip = (struct inode_info *)newip->i_private;

	KDEBUG_OFC(0, "DVS: %s: updating inode 0x%p ino %ld\n", __FUNCTION__,
		   newip, newip->i_ino);

	/* Don't overwrite the existing inode attrs if this is a write cached
	 * file and there are other open file handles.  The exception is opens
	 * doing an invalidate, the open call will have triggered a writeback
	 * to sync the server and client to maintain close-to-open coherency */
	if ((!invalidate) && (INODE_CWC_FILES(newip))) {
		return;
	}

	if ((invalidate) ||
	    ((!fp || FILE_PRIVATE(fp)->cache) &&
	     !timespec_equal(&newip->i_mtime, &remoteip->i_mtime))) {
		/* remote mtime has changed, invalidate any cached pages */
		invalidate_mapping_pages(&newip->i_data, 0, ~0UL);
		KDEBUG_OFC(0,
			   "DVS: %s: invalidate cached pages for inode 0x%p\n",
			   __FUNCTION__, newip);
	}
	newip->i_mtime = remoteip->i_mtime;
	newip->i_atime = remoteip->i_atime;
	newip->i_ctime = remoteip->i_ctime;
	newip->i_uid = remoteip->i_uid;
	newip->i_gid = remoteip->i_gid;
	newip->i_mode = remoteip->i_mode;
	newip->i_rdev = remoteip->i_rdev;
	set_nlink(newip, remoteip->i_nlink);
	newip->i_size = remoteip->i_size;
	newip->i_blocks = remoteip->i_blocks;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	newip->i_version = remoteip->i_version;
#else
	inode_set_iversion(newip, remoteip->i_version);
#endif
	newip->i_generation = remoteip->i_generation;
	newip->i_flags = remoteip->i_flags;

	iip->cache_time = jiffies;
	iip->mount_path_hash = remoteip->mount_path_hash;

	if (dep)
		dep->d_time = jiffies;
}

int dvs_attrcache_time_valid(unsigned long timestamp, struct super_block *sb)
{
	if (SUPER_ICSB(sb)->attrcache_timeout == 0)
		return 0;

	/* 0 could indicate a real jiffies value, but we assume it's
	 * uninitialized. */
	if (timestamp == 0)
		return 0;

	/* Don't consider the cache valid if we've dropped our caches after
	 * the timestamp. */
	if (time_after(SUPER_ICSB(sb)->attrcache_revalidate_time, timestamp))
		return 0;

	/* Check if the cache falls in the timeout window. */
	if (time_after(jiffies, timestamp + SUPER_ICSB(sb)->attrcache_timeout))
		return 0;

	return 1;
}

void utruncate(struct inode *ip)
{
	int rval, rsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode_info *iip;
	char *bufp = NULL, *path;
	struct dentry *dep;
	unsigned long elapsed_jiffies;

	KDEBUG_OFC(0, "DVS: utruncate: called: ip %ld\n", ip->i_ino);

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: utruncate: parent has no inode info\n");
		goto done;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp)
		goto done;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	dep = container_of(ip->i_dentry.first, struct dentry, d_alias);
#else
	dep = container_of(ip->i_dentry.first, struct dentry, d_u.d_alias);
#endif

	if (SUPERBLOCK_NAME(dep->d_name.name))
		goto done;

	path = get_path(dep, NULL, bufp, ip);
	if (IS_ERR(path))
		goto done;

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		goto done;
	}
	filerq->request = RQ_TRUNCATE;
	filerq->retry = INODE_ICSB(ip)->retry;
	strcpy(&filerq->u.truncaterq.pathname[0], path);
	filerq->u.truncaterq.len = ip->i_size;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("utruncate", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_OFC(0, "DVS: utruncate: got error from server %ld\n",
			   filerp->rval);
	}
done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return;
}

/*
 * urevalidate() returns 1 if the dentry is OK, and 0 otherwise to
 * make the kernel invalidate the dentry rather than return failure.
 */
int urevalidate(struct dentry *dentry, unsigned int flags)
{
	struct inode *ip = dentry->d_inode;
	struct inode_info *iip;
	int rval, rsz, valid_dentry = 0, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path;
	unsigned long elapsed_jiffies;

	if (flags & LOOKUP_RCU) {
		return -ECHILD;
	}

	/* Check if we can use the cached value */
	if (dvs_attrcache_time_valid(dentry->d_time, dentry->d_sb))
		return 1;

	if (!ip || !ip->i_private) {
		/* consider a NULL inode stale */
		KDEBUG_OFC(0, "DVS: %s: no inode info %s\n", __FUNCTION__,
			   dentry->d_name.name);
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	/*
	 * Send lookup to server to get inode data
	 */
	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		KDEBUG_OFC(0, "DVS: %s: __get_free_page() failure\n",
			   __FUNCTION__);
		goto done;
	}
	path = get_path(dentry, NULL, bufp, ip);
	if (IS_ERR(path)) {
		KDEBUG_OFC(0, "DVS: %s: get_path() returned %ld\n",
			   __FUNCTION__, PTR_ERR(path));
		goto done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		KDEBUG_OFC(0, "DVS: %s: kmalloc failure\n", __FUNCTION__);
		goto done;
	}
	filerq->request = RQ_LOOKUP;
	filerq->retry = INODE_ICSB(ip)->retry;
	strcpy(filerq->u.lookuprq.pathname, path);
	capture_context((&filerq->context));

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("urevalidate", ip, dentry, filerq, rsz,
				    filerp, sizeof(struct file_reply), &node);
	if (rval < 0) {
		KDEBUG_OFC(0, "DVS: %s: send_ipc_inode_retry() returned %d\n",
			   __FUNCTION__, rval);
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: %s: %s got error from server %ld ip 0x%p dep "
			   "0x%p path %s\n",
			   __FUNCTION__, path, filerp->rval, ip, dentry,
			   filerq->u.lookuprq.pathname);
		goto done;
	}
	if (!filerp->u.lookuprp.inode_valid) {
		KDEBUG_OFC(0,
			   "DVS: %s: %s called ino: %ld ip: 0x%p path: %s, "
			   "found invalid inode\n",
			   __FUNCTION__, path, ip->i_ino, ip,
			   filerq->u.lookuprq.pathname);
		goto done;
	}

	if (INODE_ICSB(ip)->clusterfs &&
	    (((ip->i_mode & S_IFMT) !=
	      (filerp->u.lookuprp.inode_copy.i_mode & S_IFMT)) ||
	     (ip->i_ino != filerp->u.lookuprp.inode_copy.i_ino))) {
		/* force a new lookup if type or inode number doesn't match */
		KDEBUG_OFC(0, "DVS: %s: %s inode changed: %i/%i, %lu/%lu\n",
			   __FUNCTION__, path, ip->i_mode,
			   filerp->u.lookuprp.inode_copy.i_mode, ip->i_ino,
			   filerp->u.lookuprp.inode_copy.i_ino);
	} else {
		/* update attributes */
		iip->check_xattrs = filerp->u.lookuprp.check_xattrs;
		update_inode(&filerp->u.lookuprp.inode_copy, ip, dentry, NULL,
			     0);
		KDEBUG_OFC(0,
			   "DVS: %s: %s called ino: %ld ip: 0x%p dep: 0x%p "
			   "mode: 0x%x bsz: %d path: %s xattrs: %d\n",
			   __FUNCTION__, path, ip->i_ino, ip, dentry,
			   ip->i_mode, INODE_ICSB(ip)->bsz,
			   filerq->u.lookuprq.pathname, iip->check_xattrs);
		valid_dentry = 1;
	}

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);

	if (!valid_dentry) {
		/*
		 * If the inode has changed but something is mounted here,
		 * we can't throw away the dentry as we'd lose whatever is
		 * mounted as well.  Instead, leave things as they are.
		 * Should an access occur after the mount(s) are removed,
		 * another revalidate will occur and we will then toss the
		 * dentry and update the inode.
		 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
		if (have_submounts(dentry))
			valid_dentry = 1;
		else
			d_drop(dentry);
#else
		struct path mnt_path;

		mnt_path.mnt = find_vfsmount(dentry);
		mnt_path.dentry = dentry;

		if (mnt_path.mnt && path_has_submounts(&mnt_path))
			valid_dentry = 1;
		else
			d_drop(dentry);

		if (mnt_path.mnt) {
			mntput(mnt_path.mnt);
		}
#endif
	}

	return valid_dentry;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)

static inline void
from_dvs_kstat(struct kstat *kstat, struct dvs_kstat *dvs_kstat)
{
	if (unlikely(sizeof(struct kstat) != sizeof(struct dvs_kstat))) {
		DVS_BUG();
	}

	memcpy(kstat, dvs_kstat, sizeof(struct kstat));
}

#else

static inline void
from_dvs_kstat(struct kstat *kstat, struct dvs_kstat *dvs_kstat)
{
	kstat->ino = dvs_kstat->ino;
	kstat->dev = dvs_kstat->dev;
	kstat->mode = dvs_kstat->mode;
	kstat->nlink = dvs_kstat->nlink;
	kstat->uid = dvs_kstat->uid;
	kstat->gid = dvs_kstat->gid;
	kstat->rdev = dvs_kstat->rdev;
	kstat->size = dvs_kstat->size;
	kstat->atime = dvs_kstat->atime;
	kstat->mtime = dvs_kstat->mtime;
	kstat->ctime = dvs_kstat->ctime;
	kstat->blksize = dvs_kstat->blksize;
	kstat->blocks = dvs_kstat->blocks;
}

#endif

int ugetattr(struct vfsmount *mnt, struct dentry *dep, struct kstat *kstatp)
{
	struct inode *ip = dep->d_inode;
	struct inode_info *iip;
	int rval, rsz, node;
	struct file *fp = NULL;
	struct open_file_info *ofi;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct incore_upfs_super_block *icsb = NULL;
	char *bufp = NULL, *path;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		rval = -EACCES;
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ugetattr: parent has no inode info\n");
		rval = -USIERR_INTERNAL;
		goto done;
	}

	/* If this inode is unlinked find a file pointer to use */
	if (ip->i_nlink == 0) {
		KDEBUG_PNC(0, "ugetattr: given inode %lu is unlinked\n",
			   ip->i_ino);
		icsb = (struct incore_upfs_super_block *)ip->i_sb->s_fs_info;
		spin_lock(&icsb->lock);
		list_for_each_entry (ofi, &icsb->open_files, list) {
			if (file_inode(ofi->fp) == ip &&
			    get_file_rcu(ofi->fp)) {
				fp = ofi->fp;
				break;
			}
		}
		spin_unlock(&icsb->lock);
	}

	/*
	 * Lustre or datawarp cache does not update i_size on lookup
	 * so let the getattr proceed for those file system if the i_size
	 * is 0
	 */
#ifdef WITH_DATAWARP
	if (((iip->underlying_magic == LL_SUPER_MAGIC) ||
	     (iip->underlying_magic == KDWCFS_SUPER_MAGIC)) &&
	    (ip->i_size == 0)) {
#else
	if ((iip->underlying_magic == LL_SUPER_MAGIC) && (ip->i_size == 0)) {
#endif
		KDEBUG_OFC(0, "Lustre or DWCFS: assuming invalid dentry 0x%p\n",
			   dep);
	} else {
		/*
		 * If the mountpoint is read only and the dentry's d_time is
		 * within the attribute cache timeout dont send the request to
		 * the server, just use the current inode attributes
		 */
		if ((mnt->mnt_sb->s_flags & MS_RDONLY) &&
		    dvs_attrcache_time_valid(iip->cache_time, dep->d_sb)) {
			generic_fillattr(ip, kstatp);
			rval = 0;
			goto done;
		}
	}

	/*
	 * If this is a write cached file and there is currently an open file
	 * handle then the client has the most current attributes, return the
	 * local attributes to the caller.
	 */
	if (INODE_CWC_FILES(ip)) {
		generic_fillattr(ip, kstatp);
		rval = 0;
		goto done;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}
	path = get_path(dep, NULL, bufp, ip);
	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		goto done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_GETATTR;
	filerq->retry = INODE_ICSB(ip)->retry;
	strcpy(filerq->u.getattrrq.pathname, path);

	elapsed_jiffies = jiffies;
	if (fp) {
		rval = send_ipc_file_retry("ugetattr-unlinked", fp,
					   FILE_PRIVATE(fp)->meta_rf,
					   FILE_PRIVATE(fp)->meta_rf_len, 0,
					   filerq, rsz, filerp,
					   sizeof(struct file_reply), &node);
	} else {
		rval = send_ipc_inode_retry("ugetattr", ip, dep, filerq, rsz,
					    filerp, sizeof(struct file_reply),
					    &node);
	}
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, path, ip, fp, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: ugetattr: got error from server %d ip 0x%p "
			   "dep 0x%p path %s\n",
			   rval, ip, dep, filerq->u.getattrrq.pathname);
		goto done;
	}

	/*
	 * Inode info could be updated here, but there isn't enough info
	 * in the kstat struct to do it.  update this when bug 767874 is
	 * fixed to make all necessary data available.
	 */

	from_dvs_kstat(kstatp, &filerp->u.getattrrp.kstatbuf);

	/*
	 * The dev element of the kstat buffer is gotten from the remote call to
	 * the vfs_getattr() call.  But that information isn't relevant here
	 * because it's giving the index of the remote device.  We need to
	 * replace it with the index for the local device which is in the super
	 * block hanging off the inode.
	 */
	kstatp->dev = ip->i_sb->s_dev;

	KDEBUG_OFC(0,
		   "DVS: ugetattr: called ino: %ld ip: 0x%p dep: 0x%p path: %s "
		   "size: %Ld\n",
		   ip->i_ino, ip, dep, filerq->u.getattrrq.pathname,
		   ip->i_size);
done:
	if (fp)
		fput(fp);
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

int usetattr(struct dentry *dep, struct iattr *iattrp)
{
	struct inode *ip = dep->d_inode;
	struct inode_info *iip;
	struct file *fp = NULL;
	int rval = 0, rsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		rval = -EACCES;
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: usetattr: parent has no inode info\n");
		rval = -USIERR_INTERNAL;
		goto done;
	}

	/*
	 * update server
	 */
	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}

	/*
	 * If this setattr is from an ftruncate, use the file pointer
	 * in the iattrp struct to get the remote file information
	 */
	if (iattrp->ia_valid & ATTR_FILE) {
		fp = iattrp->ia_file;
		path = "";
	} else {
		path = get_path(dep, NULL, bufp, ip);
		if (IS_ERR(path)) {
			rval = PTR_ERR(path);
			goto done;
		}
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_SETATTR;
	filerq->retry = INODE_ICSB(ip)->retry;
	strcpy(filerq->u.setattrrq.pathname, path);

	/*
	 * The kernel doesn't allow mode changes when dealing with
	 * ATTR_KILL_S*ID.
	 */
	if (iattrp->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		iattrp->ia_valid &= ~ATTR_MODE;
	filerq->u.setattrrq.attr = *iattrp;

	elapsed_jiffies = jiffies;
	if (fp) { /* This is an ftruncate */
		rval = send_ipc_file_retry("usetattr-ftruncate", fp,
					   FILE_PRIVATE(fp)->meta_rf,
					   FILE_PRIVATE(fp)->meta_rf_len, 0,
					   filerq, rsz, filerp,
					   sizeof(struct file_reply), &node);
	} else {
		rval = send_ipc_inode_retry("usetattr", ip, dep, filerq, rsz,
					    filerp, sizeof(struct file_reply),
					    &node);
	}
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: usetattr: got error from server %d ip 0x%p "
			   "dep 0x%p path %s\n",
			   rval, ip, dep, filerq->u.setattrrq.pathname);
		goto done;
	}

	/* update local inode attributes */
	setattr_copy(ip, iattrp);
	if (iattrp->ia_valid & ATTR_SIZE) {
		if (iattrp->ia_size != i_size_read(ip)) {
			truncate_setsize(ip, iattrp->ia_size);
		}
	}

	KDEBUG_OFC(0,
		   "DVS: usetattr: called ino: %ld ip: 0x%p dep: 0x%p path: %s "
		   "size: %Ld\n",
		   ip->i_ino, ip, dep, filerq->u.setattrrq.pathname,
		   ip->i_size);
done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

int usetxattr(struct dentry *dentry, const char *name, const void *value,
	      size_t size, int flags, const char *prefix, size_t prefix_len)
{
	struct inode *ip = dentry->d_inode;
	struct inode_info *iip;
	int rval, rsz, psz, n, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path, *cp;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dentry->d_name.name)) {
		rval = -EACCES;
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: usetxattr: parent has no inode info\n");
		rval = -USIERR_INTERNAL;
		goto done;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}
	path = get_path(dentry, NULL, bufp, ip);
	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		printk(KERN_ERR "DVS: usetxattr: patherr %d\n", rval);
		goto done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1 + prefix_len +
	      strlen(name) + 1 + size;
	psz = sizeof(struct file_reply);
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(psz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_SETXATTR;
	filerq->retry = INODE_ICSB(ip)->retry;

	cp = filerq->u.setxattrrq.data;
	n = strlen(path) + 1;
	memcpy(cp, path, n);
	filerq->u.setxattrrq.pathlen = n;
	cp += n;

	if (prefix_len > 0) {
		memcpy(cp, prefix, prefix_len);
		cp += prefix_len;
	}

	n = strlen(name) + 1;
	memcpy(cp, name, n);
	filerq->u.setxattrrq.namelen = prefix_len + n;
	cp += n;

	memcpy(cp, value, size);
	filerq->u.setxattrrq.valuelen = size;

	filerq->u.setxattrrq.flags = flags;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("usetxattr", ip, dentry, filerq, rsz,
				    filerp, psz, &node);

	if (rval < 0) {
		KDEBUG_OFC(
			0,
			"DVS: usetxattr: send error %d, ip 0x%p dentry 0x%p\n",
			rval, ip, dentry);
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (filerp->rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: usetxattr: got error from server %d ip 0x%p "
			   "dentry 0x%p\n",
			   rval, ip, dentry);
		goto done;
	}

	if (value)
		iip->check_xattrs = 1;

	KDEBUG_OFC(0, "DVS: usetxattr: returned %d\n", rval);
done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

ssize_t ugetxattr(struct dentry *dentry, const char *name, void *value,
		  size_t size, const char *prefix, size_t prefix_len)
{
	struct inode *ip = dentry->d_inode;
	struct inode_info *iip;
	int rval, rsz, psz, n, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path, *cp;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dentry->d_name.name)) {
		rval = -EACCES;
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ugetxattr: parent has no inode info\n");
		rval = -USIERR_INTERNAL;
		goto done;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}
	path = get_path(dentry, NULL, bufp, ip);
	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		goto done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1 + prefix_len +
	      strlen(name) + 1 + size;
	psz = sizeof(struct file_reply) + size;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(psz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_GETXATTR;
	filerq->retry = INODE_ICSB(ip)->retry;

	cp = filerq->u.getxattrrq.data;
	n = strlen(path) + 1;
	memcpy(cp, path, n);
	filerq->u.getxattrrq.pathlen = n;
	cp += n;

	if (prefix_len > 0) {
		memcpy(cp, prefix, prefix_len);
		cp += prefix_len;
	}

	n = strlen(name) + 1;
	memcpy(cp, name, n);
	filerq->u.getxattrrq.namelen = prefix_len + n;

	filerq->u.getxattrrq.valuelen = size;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("ugetxattr", ip, dentry, filerq, rsz,
				    filerp, psz, &node);

	if (rval < 0) {
		KDEBUG_OFC(
			0,
			"DVS: ugetxattr: send error %d, ip 0x%p dentry 0x%p\n",
			rval, ip, dentry);
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: ugetxattr: got error from server %d ip 0x%p "
			   "dentry 0x%p\n",
			   rval, ip, dentry);
		goto done;
	}

	KDEBUG_OFC(0, "DVS: ugetxattr: returned %d size %ld\n", rval, size);

	if (size == 0)
		goto done;
	if (rval > size) {
		rval = -ERANGE;
		goto done;
	}
	memcpy(value, filerp->u.getxattrrp.data, rval);

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

ssize_t ulistxattr(struct dentry *dentry, char *list, size_t size)
{
	struct inode *ip = dentry->d_inode;
	struct inode_info *iip;
	int rval, rsz, psz, n, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path, *cp;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dentry->d_name.name)) {
		rval = -EACCES;
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: ulistxattr: parent has no inode info\n");
		rval = -USIERR_INTERNAL;
		goto done;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}
	path = get_path(dentry, NULL, bufp, ip);
	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		goto done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1 + size;
	psz = sizeof(struct file_reply) + size;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(psz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_LISTXATTR;
	filerq->retry = INODE_ICSB(ip)->retry;

	cp = filerq->u.listxattrrq.data;
	n = strlen(path) + 1;
	memcpy(cp, path, n);
	filerq->u.listxattrrq.pathlen = n;
	cp += n;

	filerq->u.listxattrrq.listlen = size;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("ulistxattr", ip, dentry, filerq, rsz,
				    filerp, psz, &node);

	if (rval < 0) {
		KDEBUG_OFC(
			0,
			"DVS: ulistxattr: send error %d, ip 0x%p dentry 0x%p\n",
			rval, ip, dentry);
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: ulistxattr: got error from server %d ip 0x%p "
			   "dentry 0x%p\n",
			   rval, ip, dentry);
		goto done;
	}

	KDEBUG_OFC(0, "DVS: ulistxattr: returned %d size %ld\n", rval, size);

	if (size == 0)
		goto done;
	if (rval > size) {
		rval = -ERANGE;
		goto done;
	}
	memcpy(list, filerp->u.listxattrrp.data, rval);

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

int uremovexattr(struct dentry *dentry, const char *name)
{
	struct inode *ip = dentry->d_inode;
	struct inode_info *iip;
	int rval, rsz, psz, n, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path, *cp;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dentry->d_name.name)) {
		rval = -EACCES;
		goto done;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: uremovexattr: parent has no inode "
				"info\n");
		rval = -USIERR_INTERNAL;
		goto done;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}
	path = get_path(dentry, NULL, bufp, ip);
	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		printk(KERN_ERR "DVS: uremovexattr: patherr %d\n", rval);
		goto done;
	}

	rsz = sizeof(struct file_request) + strlen(path) + 1 + strlen(name) + 1;
	psz = sizeof(struct file_reply);
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(psz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_REMOVEXATTR;
	filerq->retry = INODE_ICSB(ip)->retry;

	cp = filerq->u.removexattrrq.data;
	n = strlen(path) + 1;
	memcpy(cp, path, n);
	filerq->u.removexattrrq.pathlen = n;
	cp += n;

	n = strlen(name) + 1;
	memcpy(cp, name, n);
	filerq->u.removexattrrq.namelen = n;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("uremovexattr", ip, dentry, filerq, rsz,
				    filerp, psz, &node);

	if (rval < 0) {
		KDEBUG_OFC(0,
			   "DVS: uremovexattr: send error %d, ip 0x%p dentry "
			   "0x%p\n",
			   rval, ip, dentry);
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_OFC(
			0,
			"DVS: uremovexattr: got error %d from server ip 0x%p "
			"dentry 0x%p\n",
			rval, ip, dentry);
		goto done;
	}

	KDEBUG_OFC(0, "DVS: uremovexattr: returned %d\n", rval);
done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

/*
 * Common retry code
 */

/*
 * common_retry simply manages the delay before the next
 * retry of an inode-related operation (no reopen needed).
 * A zero return indicates that it's okay to retry op.
 * An error is returned if the delay sleep is interrupted.
 * Note that this function should not be called if retry
 * was not enabled when this filesystem was mounted -- see
 * the retry flag in the file_request structure.
 */
long common_retry(char *opname, int retno)
{
	long rval;
	wait_queue_head_t wqh;
	DEFINE_WAIT(wait);

	printk(KERN_ERR "DVS: common_retry: %s: begin delay (%d seconds) "
			"before retry %d\n",
	       opname, RETRYSLEEP, retno);

	init_waitqueue_head(&wqh);
	prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
	if (schedule_timeout(RETRYSLEEP * HZ)) {
		printk(KERN_ERR "DVS: common_retry: %s: retry delay "
				"interrupted, bailing out\n",
		       opname);
		rval = -EHOSTDOWN;
	} else {
		printk(KERN_ERR "DVS: common_retry: %s: begin retry %d\n",
		       opname, retno);
		rval = 0;
	}
	finish_wait(&wqh, &wait);

	return (rval);
}

/*
 * send_ipc_with_retry is a wrapper for send_ipc_request.
 * It manages retry of an inode-related IPC request.
 */
int send_ipc_with_retry(struct dvsdebug_stat *stats, char *myname, int nord,
			int node, struct file_request *filerq, int rsz,
			struct file_reply *freply, int rpsz)
{
	int retcount = 0;
	long rval;

	while (1) {
		RESET_FILERQ(filerq);
		filerq->rip = retcount;
		rval = send_ipc_request_stats(stats, node, RQ_FILE, filerq, rsz,
					      freply, rpsz, NO_IDENTITY);
		if (rval >= 0) {
			break;
		}
		if (!filerq->retry) {
			KDEBUG_OFC(0,
				   "DVS: send_ipc_with_retry: %s: no retry\n",
				   myname);
			break;
		}
		printk(KERN_ERR "DVS: send_ipc_with_retry: %s: ipc failed for "
				"nord %d: %ld\n",
		       myname, nord, rval);
		if (rval != -EHOSTDOWN && rval != -EQUIESCE) {
			goto done;
		}
		retcount++;
		if ((rval = common_retry(myname, retcount)) < 0) {
			goto done;
		}
	}
	if (retcount) {
		printk(KERN_INFO "DVS: send_ipc_with_retry: %s: retry %d OK, "
				 "nord %d\n",
		       myname, retcount, nord);
	}
done:
	if (rval == -EQUIESCE)
		rval = -EIO;

	return (rval);
}

loff_t compute_file_size(struct inode *ip, int nnodes, int blksize,
			 loff_t fsize, int node)
{
	loff_t psize, fszmo;
	int bsz;

	if (SUPER_DWCFS(ip))
		return fsize;

	if (fsize == 0) {
		return (0);
	}

	fszmo = fsize - 1;
	bsz = blksize;

	if (bsz == 0)
		return (0);

	if (ip != NULL) {
		nnodes = 1;
		node = 0;
	}

	if ((ip == NULL) || (S_ISREG(ip->i_mode))) {
		KDEBUG_OFC(0,
			   "DVS: compute_file_size: ip 0x%p fsize %Ld bsz %d "
			   "nnodes %d node %d fszmo %Ld\n",
			   ip, fsize, bsz, nnodes, node, fszmo);
		psize = ((fszmo / bsz) * nnodes * bsz) + (node * bsz) +
			((fszmo % bsz) + 1);
		KDEBUG_OFC(0, "DVS: compute_file_size: psize %Ld\n", psize);
		return (psize);
	} else {
		return (fsize);
	}
}

unsigned long compute_file_blocks(struct inode *ip)
{
	unsigned long pblocks;

	pblocks = (ip->i_size + 511) >> 9;

	KDEBUG_OFC(0,
		   "DVS: compute_file_blocks: Found %ld blocks for "
		   "inode %ld\n",
		   pblocks, ip->i_ino);
	return pblocks;
}

struct semaphore *ihash_find_entry(ht_t *inode_op_table, char *path)
{
	struct semaphore *sema = NULL;
	int hash = fnv_32_str(path, FNV1_32_INIT) % INODE_OP_SIZE;

	sema = ht_find_data(inode_op_table, hash);
	if (sema != NULL) {
		return sema;
	}

	sema = kmalloc_ssi(sizeof(struct semaphore), GFP_KERNEL);
	if (!sema)
		return NULL;
	sema_init(sema, 1);

	if (!ht_insert_data(inode_op_table, hash, path, sema)) {
		kfree_ssi(sema);
		printk(KERN_CRIT "DVS: ihash_find_entry: Failed to insert "
				 "semaphore for %d into hash table",
		       hash);
		return NULL;
	}

	return sema;
}

/*
 * Return our previously-recorded value for this filesystem's root vfsmount.
 */
static struct vfsmount *find_vfsmount(struct dentry *dep)
{
	struct incore_upfs_super_block *icsb;
	struct vfsmount *vmnt;

	icsb = (struct incore_upfs_super_block *)dep->d_sb->s_fs_info;
	vmnt = icsb->root_vfsmount;

	if (vmnt == NULL) {
		dvs_set_root_vfsmount(dep->d_inode);
		vmnt = icsb->root_vfsmount;
	}

	if (vmnt) {
		mntget(vmnt);
	}

	return vmnt;
}

char *get_path(struct dentry *dep, struct vfsmount *mnt, char *bufp,
	       struct inode *ip)
{
	char *path;
	char *tmp_path;
	int len;
	char *bp;
	char *rootpath;
	struct vfsmount *mnt2 = NULL;
	struct path p;

        if (!current->fs) {
                /* Current->fs can be NULL during process exit. So
                   don't call into d_path(), which expects it to be
                   non-NULL. */
                return (ERR_PTR(-ESRMNT));
        }

	p.mnt = mnt;
	p.dentry = dep;

	if (strlen(dep->d_name.name) != dep->d_name.len) {
		printk(KERN_ERR "DVS: get_path name problem '%s' %d\n",
		       dep->d_name.name, dep->d_name.len);
        }

	if (mnt && (mnt == (mnt2 = find_vfsmount(dep)))) {
		path = d_path(&p, bufp, PAGE_SIZE);
	} else {
		if (mnt2 == NULL) {
			mnt2 = find_vfsmount(dep);
		}
		mnt = mnt2;

		if (!mnt) {
			/* NULL vfsmount is valid during unmount of a bind
			   mount, so don't print an error message. */
			return (ERR_PTR(-ESRMNT));
		}
		p.mnt = mnt;
		path = d_path(&p, bufp, PAGE_SIZE);
	}
	mntput(mnt);

	if (IS_ERR(path)) {
		KDEBUG_OFC(0, "%s:%d err %ld\n", __FUNCTION__, __LINE__,
			   PTR_ERR(path));
		return (path);
	}

	/* remove the " (deleted)" string d_path can add */
	if (!IS_ROOT(dep) && d_unhashed(dep)) {
		len = strlen(path) - 10;
		if (len > 0) {
			tmp_path = path + len;
			if (strncmp(tmp_path, " (deleted)", 10) == 0)
				*tmp_path = '\0';
		}
	}

	/*
	 * Translate the local mountpoint prefix so that the proper remote
	 * path is used.
	 */
	bp = (char *)__get_free_page(GFP_KERNEL);

	if (bp == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	p.mnt = mnt;
	p.dentry = mnt->mnt_root;
	rootpath = d_path(&p, bp, PAGE_SIZE);

	path = replacepath(bufp, path, rootpath, ip);
	free_page((unsigned long)bp);

	return (path);
}

/*
 * inode_ops_retry simply manages the delay before the next
 * retry of an inode-related operation (no reopen needed).
 * Return:
 * - This function will return immediately with EHOSTDOWN if
 *   retry was not enabled when this filesystem was mounted.
 * - It will also return immediately with EHOSTDOWN if check_processes()
 *   determines that a server failure could result in data corruption
 *   should a retry be allowed.
 * - A zero return indicates that it's okay to retry op.
 * - An error is returned if the delay sleep is interrupted.
 * - As a fix for Bug 843755, if the MDS is targeted and gets EHOSTDOWN,
 *   this function will return immediately, rather than retrying.
 *
 * TODO: Would be nice if these retry ops also printed the destination node!!!
 */
int inode_ops_retry(struct inode *ip, struct dentry *dep, char *opname,
		    int retry, int orig_rval, int node)
{
	int rval;
	char *path = NULL, *bufp = NULL;
	wait_queue_head_t wqh;
	DEFINE_WAIT(wait);

	/* Always retry if a server is quiesced */
	if (orig_rval == -EQUIESCE) {
		return 0;
	}

	if (orig_rval == -ESTALE_DVS_RETRY) {
		if (!estale_max_retry)
			return -ESTALE;
		orig_rval = -ESTALE;
	}

	if (orig_rval == -EHOSTDOWN) {
		if (!INODE_ICSB(ip)->retry) {
			KDEBUG_INF(0, "DVS: inode_ops_retry: %s: no retry\n",
				   opname);
			return -EHOSTDOWN;
		}

		if ((rval = check_processes(0, NULL, ip)))
			return rval;

		/* Datawarp cannot afford to lose any servers */
		if (SUPER_DWFS(ip)) {
			KDEBUG_INF(
				0,
				"DVS: inode_ops_retry: %s: no retry for DW\n",
				opname);
			return -EHOSTDOWN;
		}
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (bufp && dep) {
		path = get_path(dep, NULL, bufp, ip);
		if (IS_ERR(path)) {
			path = NULL;
		}
	}
	KDEBUG_INF(0,
		   "DVS: inode_ops_retry: %s: begin delay (%d seconds) "
		   "before retry %d, ip=0x%p, path=%s\n",
		   opname, RETRYSLEEP, retry, ip, path ? path : "N/A");

	init_waitqueue_head(&wqh);

	prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
	if (schedule_timeout(RETRYSLEEP * HZ)) {
		KDEBUG_INF(0,
			   "DVS: inode_ops_retry: %s: retry delay "
			   "interrupted, bailing out, ip=0x%p, path=%s\n",
			   opname, ip, path ? path : "N/A");
		rval = orig_rval;
	} else {
		KDEBUG_INF(0,
			   "DVS: inode_ops_retry: %s: begin retry %d, "
			   "ip=0x%p, path=%s\n",
			   opname, retry, ip, path ? path : "N/A");
		rval = 0;
	}
	finish_wait(&wqh, &wait);

	free_page((unsigned long)bufp);
	return (rval);
}

/*
 * Given a node integer (index into the ssi_map) return the index of that node
 * into the super block's list of nodes
 */
int super_node_to_nord(struct incore_upfs_super_block *icsb, int node)
{
	int i;

	for (i = 0; i < icsb->data_servers_len; i++) {
		if (icsb->data_servers[i].node_map_index == node)
			return i;
	}

	return -1;
}

static void release_estale_list(struct inode *ip)
{
	struct inode_info *iip = INODE_PRIVATE(ip);

	write_lock(&iip->estale_lock);

	/* check that no one freed estale_nodes while we were
	 * waiting for the write lock */
	if (!iip->estale_nodes) {
		write_unlock(&iip->estale_lock);
		return;
	}

	kfree_ssi(iip->estale_nodes);
	iip->estale_nodes = NULL;
	write_unlock(&iip->estale_lock);

	ESTALE_LOG("ESTALE: ip 0x%p - Timeout reached. Resetting"
		   " ESTALE node list\n",
		   ip);
}

/*
 * Given an array indicating if nodes are up or down, return
 * the nth up node in that list, starting from the beginning
 * again if necessary.
 */
struct dvs_server *get_nth_up_server(struct dvs_server *servers, int len, int n)
{
	int valid_nodes, i;

	if (len == 0)
		printk(KERN_ERR "DVS: get_nth_up_node_index len is zero!\n");

retry:
	valid_nodes = 0;
	i = 0;
	do {
		if (servers[i].up) {
			if (valid_nodes++ == n) {
				return &servers[i];
			}
		}
	} while (++i < len);

	/* if no nodes are up return the first node in the list, then
	 * the caller has a node to send retries to if the option is set */
	if (!valid_nodes) {
		printk(KERN_ERR "DVS: No valid nodes!\n");
		return &servers[0];
	}

	n %= valid_nodes;
	goto retry;
}

/*
 * Given some inode, server, and hashing information, generate the target
 * server for an operation on an inode.
 */
struct dvs_server *inode_server(struct inode *ip, int offset,
				struct dvs_server *servers, int servers_len,
				struct hash_info *hash)
{
	int i, index, nord, new_offset;
	struct dvs_server *server = NULL;
	struct inode_info *iip = INODE_PRIVATE(ip);

	index = (dvs_hash(hash, ip->i_ino) + offset) % servers_len;

	if (SUPER_DWFS(ip))
		return &servers[index];

	read_lock(&iip->estale_lock);
	if (iip->estale_nodes) {
		/*
		 * If the nodes were marked ESTALE long enough ago we can
		 * clear estale_nodes and check if any nodes are working
		 * again.
		 */
		if (iip->estale_jiffies + estale_timeout_secs * HZ < jiffies) {
			read_unlock(&iip->estale_lock);
			release_estale_list(ip);
			return get_nth_up_server(servers, servers_len, index);
		}
		/*
		 * Check our desired server against the estale list
		 */
		for (i = 0; i < servers_len; i++) {
			new_offset = (index + i) % servers_len;
			server = get_nth_up_server(servers, servers_len,
						   new_offset);
			nord = server - servers;
			if (!iip->estale_nodes[nord]) {
				read_unlock(&iip->estale_lock);
				return server;
			}
		}
	}
	read_unlock(&iip->estale_lock);

	return get_nth_up_server(servers, servers_len, index);
}

/*
 * Given an inode, find the target server for a data operation.
 * Used exclusively by open for opening files on data servers
 */
int inode_data_server(struct inode *ip, int offset)
{
	struct dvs_server *server = NULL;
	struct incore_upfs_super_block *icsb = INODE_ICSB(ip);

	if (icsb->loadbalance)
		return icsb->loadbalance_node;

	server = inode_server(ip, offset, icsb->data_servers,
			      icsb->data_servers_len, &icsb->data_hash);
	return server->node_map_index;
}

/*
 * Given an inode, find the target server for a metadata operation.
 */
int inode_meta_server(struct inode *ip, int offset)
{
	struct dvs_server *server = NULL;
	struct incore_upfs_super_block *icsb = INODE_ICSB(ip);

	if (icsb->loadbalance)
		return icsb->loadbalance_node;

	server = inode_server(ip, offset, icsb->meta_servers,
			      icsb->meta_servers_len, &icsb->meta_hash);
	return server->node_map_index;
}

/*
 * inode_node_estale marks a server as ESTALE for a particular inode. There is
 * no global view of which servers are ESTALE, so this information is kept
 * track of in an array attached to the inode_info struct. The next time we
 * try to select a server for an inode op request, we'll check the ESTALE array
 * and avoid any servers marked ESTALE.
 */
int inode_node_estale(struct inode *ip, int node)
{
	struct inode_info *iip;
	struct incore_upfs_super_block *icsb;
	int super_nord;
	char *buf;

	if (!ip)
		return -ESTALE;

	iip = ip->i_private;
	icsb = ip->i_sb->s_fs_info;

	/* find the offset into the estale_nodes array */
	if ((super_nord = super_node_to_nord(icsb, node)) < 0)
		return -ESTALE;

	/* Allocate estale_nodes if it doesn't exist */
	write_lock(&iip->estale_lock);
	if (!iip->estale_nodes) {
		write_unlock(&iip->estale_lock);

		if ((buf = kmalloc_ssi(MAX_PFS_NODES * sizeof(char),
				       GFP_KERNEL)) == NULL)
			return -ESTALE;

		write_lock(&iip->estale_lock);
		if (!iip->estale_nodes) {
			iip->estale_num_nodes = 0;
			iip->estale_max_nodes = icsb->data_servers_len;
			iip->estale_nodes = buf;
		} else {
			kfree_ssi(buf);
		}
	}

	/* We want to leave at least one node up so new operations
	 * can have a legitimate shot at having their request succeed */
	if (iip->estale_num_nodes >= iip->estale_max_nodes - 1) {
		write_unlock(&iip->estale_lock);

		ESTALE_LOG("ESTALE: ip 0x%p - Exhausted all servers. Returning "
			   "ESTALE\n",
			   ip);

		return -ESTALE;
	}

	/* Note the time that the most recent ESTALE occurred. We'll erase
	 * the ESTALE data for this inode after a set amount of time after
	 * the last ESTALE. */
	iip->estale_jiffies = jiffies;

	if (!iip->estale_nodes[super_nord]) {
		iip->estale_nodes[super_nord] = 1;
		iip->estale_num_nodes++;
	}

	write_unlock(&iip->estale_lock);

	ESTALE_LOG("ESTALE: ip 0x%p - Setting server %s to ESTALE\n", ip,
		   SSI_NODE_NAME(node));

	return 0;
}

void set_is_flags(struct file_request *filerq, struct inode *ip)
{
	filerq->flags.is_gpfs =
		(INODE_PRIVATE(ip)->underlying_magic == GPFS_MAGIC);
	filerq->flags.is_nfs =
		(INODE_PRIVATE(ip)->underlying_magic == NFS_SUPER_MAGIC);
#ifdef WITH_DATAWARP
	filerq->flags.is_dwfs =
		(INODE_PRIVATE(ip)->underlying_magic == KDWFS_SUPER_MAGIC);
	filerq->flags.is_dwcfs =
		(INODE_PRIVATE(ip)->underlying_magic == KDWCFS_SUPER_MAGIC);
#endif

	/* Only used by DataWarp cache but no harm in setting it */
	filerq->dwcfs_mds = dwcfs_mds(ip);
}

static inline int req_is_create_type(int request)
{
	switch (request) {
	case RQ_CREATE:
	case RQ_LOOKUP:
	case RQ_LINK:
	case RQ_SYMLINK:
	case RQ_MKDIR:
	case RQ_MKNOD:
		return 1;
	}
	return 0;
}

/*
 * send_ipc_inode_retry is a wrapper for send_ipc_request.
 * It manages retry of an inode-related IPC request.
 *   myname - function name for error messages
 *   ip, dep - inode and dentry pointers
 *   filerq, rqsz - request buffer and size
 *   filerp, rpsz - reply buffer and size
 *   node_used - destination, returned to caller
 * Return value <0 if error, >=0 if OK.
 */
int send_ipc_inode_retry(char *myname, struct inode *ip, struct dentry *dep,
			 struct file_request *filerq, int rqsz,
			 struct file_reply *freply, int rpsz, int *node_used)
{
	int rval = 0, rval2 = 0, last_rval, retry = 0, nodetotry = -1;
	int emit_retry_warning = 1, estale_retry = 0;
	struct inode *d_inode = dep->d_inode;
	int node_offset = 0;
	char pb[64] = "";

	/* if the dentry contains an inode use it to determine the server hash
	 * as this is guaranteed to be the target inode and will send inode ops
	 * to the same server as file ops to prevent seeing stale inode data
	 */
	if (d_inode)
		ip = d_inode;

	set_is_flags(filerq, ip);
	filerq->flags.multiple_servers = (INODE_ICSB(ip)->meta_servers_len > 1);

	while (1) {
		last_rval = rval;
		capture_context((&filerq->context));
		filerq->rip = retry;

		/*
		 * if mode enabled, use a non-zero hash value to
		 * distribute create like operations that hash against
		 * a parent directory across all servers
		 */
		if (INODE_ICSB(ip)->distribute_create_ops && node_offset == 0 &&
		    req_is_create_type(filerq->request)) {
			node_offset = current->pid + usi_node_addr;
		}

		/* Try a different server if the last one was quiesced */
		if (rval == -EQUIESCE) {
			KDEBUG_QSC(
				0,
				"DVS: Op %s node %s path %s was quiesced for node_offset %d, "
				"SUPER_NNODES %d\n",
				myname, SSI_NODE_NAME(nodetotry),
				dvs_dentry_path(dep, pb, sizeof(pb)),
				node_offset, INODE_ICSB(ip)->meta_servers_len);

			node_offset++;
			emit_retry_warning = 0;

			/*
			 * We've gone through all node possibilities
			 * and they're all quiesced. Something has gone
			 * wrong with how we're choosing nodes.
			 */
			if (node_offset == INODE_ICSB(ip)->meta_servers_len) {
				printk(KERN_ERR
				       "DVS: Cannot find unquiesced server for "
				       "%s\n",
				       myname);
				return -EIO;
			}
		}

		nodetotry = inode_meta_server(ip, node_offset);

		KDEBUG_OFC(0,
			   "send_ipc_inode_retry:  nodetotry %s, request %s\n",
			   SSI_NODE_NAME(nodetotry),
			   file_request_to_string(filerq->request));

		/* In cases where multiple DVS servers are being used to serve
		 * nfs file systems it's possible to cause nfs ESTALE errors.
		 * If the target dentry doesn't contain an inode (d_inode) to
		 * use to determine the server hash or the op is otherwise being
		 * sent to a different server invalidate the inode on the server
		 * to prevent seeing stale inode data. This is not necessary
		 * on read-only mount points, where invalidates would generate
		 * extra operations on the underlying file system for no
		 * benefit.
		 */
		filerq->flags.invalidate = 0;

		if ((INODE_PRIVATE(ip)->underlying_magic == NFS_SUPER_MAGIC) &&
		    (INODE_ICSB(ip)->meta_servers_len > 1) &&
		    !(SUPER_SFLAGS(ip) & MS_RDONLY)) {
			if ((!d_inode) ||
			    (inode_meta_server(d_inode, 0) != nodetotry)) {
				filerq->flags.invalidate = 1;
			}
			KDEBUG_OFC(
				0,
				"DVS: send_ipc_inode_retry: %s: multiple nfs "
				"servers.  ip invalidate: %d, nodetotry: %d "
				"d_ip LNODE: %d\n",
				myname, filerq->flags.invalidate, nodetotry,
				(d_inode != NULL) ?
					inode_meta_server(d_inode, 0) :
					-1);

			if ((filerq->request == RQ_LINK) ||
			    (filerq->request == RQ_RENAME)) {
				if ((filerq->u.linkrq.invalidate_old >= 0) &&
				    (filerq->u.linkrq.invalidate_old !=
				     nodetotry)) {
					filerq->u.linkrq.invalidate_old = 1;
				} else {
					filerq->u.linkrq.invalidate_old = 0;
				}
			}
		}

		RESET_FILERQ(filerq);
		rval = send_ipc_request_stats(INODE_ICSB(ip)->stats, nodetotry,
					      RQ_FILE, filerq, rqsz, freply,
					      rpsz, NO_IDENTITY);
		if (rval >= 0) {
			if (last_rval == -EQUIESCE) {
				KDEBUG_QSC(
					0,
					"DVS: Op %s node %s returned success node_offset %d",
					myname, SSI_NODE_NAME(nodetotry),
					node_offset);
			}
			break;
		}

		KDEBUG_INF(0,
			   "DVS: send_ipc_inode_retry: %s: ipc failed, node "
			   "%s: %d\n",
			   myname, SSI_NODE_NAME(nodetotry), rval);
		if (rval != -EHOSTDOWN && rval != -ESTALE_DVS_RETRY &&
		    rval != -EQUIESCE) {
			goto done;
		}
		retry++;

		if (rval == -ESTALE_DVS_RETRY) {
			if (!estale_max_retry) {
				rval = -ESTALE;
				goto done;
			}

			filerq->flags.estale_retry = 1;
			estale_retry++;

			if (estale_retry >= estale_max_retry) {
				if ((rval = inode_node_estale(
					     ip, filerq->ipcmsg.target_node)) <
				    0)
					goto done;

				/* Inform the server that this request
				 * is a retry failover request for an
				 * ESTALE error. This is used for
				 * logging on the server side. */
				filerq->flags.estale_failover = 1;

				/* Don't bother calling inode_ops_retry()
				 * since we don't need a delay. We know
				 * we're switching to a different server
				 * since this one is ESTALE. The exception
				 * is if the timeout is zero. In this case
				 * we don't keep any history, so we'll
				 * only retry the default server. */
				if (estale_timeout_secs)
					continue;
			}

			ESTALE_LOG("ESTALE: ip 0x%p - Retrying operation on "
				   "original server %s\n",
				   ip, SSI_NODE_NAME(nodetotry));
		}

		rval2 = inode_ops_retry(ip, dep, myname, retry, rval,
					nodetotry);
		if (rval2 < 0) {
			rval = rval2;
			goto done;
		}
	}
	if (retry && emit_retry_warning) {
		KDEBUG_INF(0,
			   "DVS: send_ipc_inode_retry: %s: retry %d OK, "
			   "node %s\n",
			   myname, retry, SSI_NODE_NAME(nodetotry));
	}
	if (estale_retry && filerq->flags.estale_failover) {
		ESTALE_LOG(
			"ESTALE: ip 0x%p - Failover to server %s succeeded\n",
			ip, SSI_NODE_NAME(nodetotry));
	}
done:
	/* Make sure this error is palatable to the kernel,
	   in case we get here */
	if (rval == -EQUIESCE)
		rval = -EIO;
	*node_used = nodetotry;
	return (rval);
}

/*
 * Check the state of all processes to ensure loss of communication with
 * a DVS server can not result in silent data corruption.  A DVS server
 * considers a write to the underlying file system successful as long
 * as the RQ_PARALLEL_WRITE operation called write() and was able to send
 * a reply back to the client.  If the mount point was not configured with
 * the 'datasync' option however, the data might not have gotten to disk
 * before the server went down.  Thus the DVS client must find any processes
 * susceptible to data corruption because of this and kill them or return
 * EHOSTDOWN (depending on who the caller is).
 *
 * A special case of this function is invoked when a false node_down event is
 * detected on the local node. In this case, we cleanup any existing dvs
 * references on the local node by forcibly killing any active dvs users.
 */
int check_processes(int node, struct file *fp, struct inode *ip)
{
	int i, j, ret = 0, num_killed = 0, allocated_array = 0, file_found = 0;
	struct task_struct *g, *p;
	struct fdtable *fdt;
	struct files_struct *files;
	struct task_struct **tasks_killed = NULL;
	struct list_head *head;
	int force = (node == usi_node_addr);
#ifdef CONFIG_CRAY_ABORT_INFO
	char *job_abort_message;
#endif
	extern rwlock_t *dvs_tasklist_lock;

	/*
	 * If we received a false node_down event, get rid of active dvs
	 * references.
	 */
	if (force) {
		goto killprocs;
	}

	/*
	 * If fp or ip are non-NULL, we only have to check the current
	 * process as it directly encountered a failure while trying to
	 * perform a file or inode operation to a server that went down.
	 * Other processes will be checked as they are forced to attempt
	 * a retry, or when a RCA event calls check_processes().
	 */

	if (fp) {
		if (FILE_PRIVATE(fp)->nokill_error ||
		    (!FILE_PRIVATE(fp)->datasync &&
		     sync_client_check_dirty(ALL_SERVERS, fp))) {
			KDEBUG_INF(0,
				   "DVS: check_processes: returning "
				   "-EHOSTDOWN (fp=0x%p, pid=%d)\n",
				   fp, current->pid);
			return -EHOSTDOWN;
		} else {
			return 0;
		}
	}

	if (ip) {
		files = current->files;
		if (!files)
			return 0;

		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		for (i = 0; i < fdt->max_fds; i++) {
			fp = fcheck_files(files, i);
			if (fp && file_inode(fp) && (file_inode(fp) == ip) &&
			    (fp->f_op == &upfsfops) && (fp->private_data) &&
			    !FILE_PRIVATE(fp)->datasync &&
			    sync_client_check_dirty(ALL_SERVERS, fp)) {
				KDEBUG_INF(0,
					   "DVS: check_processes: returning "
					   "-EHOSTDOWN (fp=0x%p, pid=%d)\n",
					   fp, current->pid);
				ret = -EHOSTDOWN;
				break;
			}
		}
		spin_unlock(&files->file_lock);

		return ret;
	}

	/*
	 * If there are no open files on superblocks that contain the node
	 * of interest, we can just return as there will be no client
	 * processes to kill.
	 */
	down(&dvs_super_blocks_sema);
	list_for_each (head, &dvs_super_blocks) {
		struct incore_upfs_super_block *s =
			list_entry(head, struct incore_upfs_super_block, list);

		for (i = 0; i < s->data_servers_len; i++) {
			if ((s->data_servers[i].node_map_index == node) &&
			    (atomic_read(&s->open_dvs_files) > 0)) {
				file_found = 1;
				break;
			}
		}
	}
	up(&dvs_super_blocks_sema);

	if (!file_found)
		return 0;

	/*
	 * If fp and ip are NULL, check_processes() was called because a RCA
	 * event was received because a specific node went down.  We have to
	 * check all processes on the client to make sure they don't have files
	 * that may now be corrupted.  We have to check all files: even if all
	 * DVS superblocks were mounted with the datasync option set, a user
	 * could have overriden that setting via an environment variable.
	 */
killprocs:
	read_lock(dvs_tasklist_lock);
again:
	do_each_thread(g, p)
	{
		task_lock(p);
		files = p->files;
		if (!files) {
			task_unlock(p);
			continue;
		}

		/*
		 * We can't increment files->count and call task_unlock()
		 * here since that would require a corresponding call to
		 * put_files_struct() which could then block while we are
		 * holding a spinlock.  Instead we hold the task lock while
		 * we examine all of the process' files.
		 */

		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		for (i = 0; i < fdt->max_fds; i++) {
			fp = fcheck_files(files, i);
			if (!fp || (fp->f_op != &upfsfops) ||
			    (fp->private_data == NULL) ||
			    (!force && (FILE_PRIVATE(fp)->datasync ||
					!sync_client_check_dirty(node, fp)))) {
				continue;
			}

			for (j = 0; j < FILE_PRIVATE(fp)->data_rf_len; j++) {
				if (force ||
				    (DATA_RF(fp, j)->remote_node == node)) {
					if (!(force ||
					      FILE_PRIVATE(fp)->killprocess)) {
						FILE_PRIVATE(fp)->nokill_error =
							1;
						goto done;
					} else if (allocated_array) {
						tasks_killed[num_killed++] = p;
						goto done;
					}
					force_sig(SIGKILL, p);
					get_task_struct(p);
					num_killed++;
					goto done;
				}
			}
		}
	done:
		spin_unlock(&files->file_lock);
		task_unlock(p);
	}
	while_each_thread(g, p);

	if (num_killed && !allocated_array) {
		tasks_killed = kmalloc_ssi(
			sizeof(struct task_struct *) * num_killed, GFP_ATOMIC);
		DVS_BUG_ON(tasks_killed == NULL);
		allocated_array = 1;
		num_killed = 0;
		goto again;
	}

	read_unlock(dvs_tasklist_lock);

	/*
	 * Now that we've dropped all spinlocks, we can safely call
	 * job_set_abort_info() if necessary for all tasks identified above.
	 */
	for (i = 0; i < num_killed; i++) {
#ifdef CONFIG_CRAY_COMPUTE
		static u64 dvs_last_apid_killed = 0;
#endif

		p = tasks_killed[i];
#if defined(CONFIG_CRAY_COMPUTE) && !defined(RHEL_RELEASE_CODE) /* bug 823318  \
								 */
		spin_lock(&job_kill_lock);
		if (p->csa_apid != dvs_last_apid_killed) {
			dvs_last_apid_killed = p->csa_apid;
			spin_unlock(&job_kill_lock);
			DVS_LOGP(
				"DVS: check_processes: killing pid %d (%s) with "
				"APID %llu due to node %s failure\n",
				p->pid, p->comm, p->csa_apid,
				SSI_NODE_NAME(node));
		} else {
			spin_unlock(&job_kill_lock);
			DVS_LOG("DVS: check_processes: killing pid %d (%s) with "
				"APID %llu due to node %s failure\n",
				p->pid, p->comm, p->csa_apid,
				SSI_NODE_NAME(node));
		}
#else
		DVS_LOGP("DVS: check_processes: killing pid %d (%s) due "
			 "to node %s failure\n",
			 p->pid, p->comm, SSI_NODE_NAME(node));
#endif
#if defined(CONFIG_CRAY_ABORT_INFO) && !defined(RHEL_RELEASE_CODE) /* bug      \
								      823318   \
								    */
		if ((job_abort_message = kmalloc_ssi(128, GFP_ATOMIC)) ==
		    NULL) {
			(void)job_set_abort_info(
				p->pid, "DVS server failure "
					"detected: killing process to avoid "
					"potential data loss");
		} else {
			job_abort_message[0] = '\0';
			snprintf(job_abort_message, 128,
				 "DVS server failure "
				 "detected: killing process with APID %llu to "
				 "avoid potential data loss",
				 p->csa_apid);
			(void)job_set_abort_info(p->pid, job_abort_message);
			kfree_ssi(job_abort_message);
		}
#endif
		put_task_struct(p);
	}

	if (allocated_array)
		kfree_ssi(tasks_killed);

	return 0;
}

static atomic64_t dvs_request_log_count = ATOMIC64_INIT(0);

/*
 * Log information about client-generated DVS requests in real time.
 * The fp parameter is only used when path is not known.
 *
 * WARNING: external scripts may be relying on the entries of this file - do
 * not remove entries without investigating this first!
 */
void log_request(int request, char *path, struct inode *ip, struct file *fp,
		 u64 count, int node, unsigned long elapsed_jiffies)
{
	char *type = "[unknown]", *node_name = "[multiple]";
	char *bufp = NULL, *new_path = NULL;
	unsigned long time = jiffies_to_msecs(elapsed_jiffies);
	u64 total;

	if (!dvs_request_log_enabled ||
	    ((time / 1000) < dvs_request_log_min_time_secs)) {
		return;
	}

	/* if path is not provided, determine it from the info available */
	if (!path) {
		if (fp && fp->f_path.dentry && fp->f_path.mnt) {
			bufp = (char *)__get_free_page(GFP_KERNEL);
			if (bufp) {
				new_path = get_path(fp->f_path.dentry,
						    fp->f_path.mnt, bufp, ip);
			}
		} else if (ip) {
			bufp = (char *)__get_free_page(GFP_KERNEL);
			if (bufp) {
				struct dentry *dep = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
				dep = container_of(ip->i_dentry.first,
						   struct dentry, d_alias);
#else
				dep = container_of(ip->i_dentry.first,
						   struct dentry, d_u.d_alias);
#endif
				new_path = get_path(dep, NULL, bufp, ip);
			}
		}
		if (!new_path || IS_ERR(new_path))
			new_path = "[unknown]";
	} else {
		new_path = path;
	}

	if (ip) {
		if (S_ISREG(ip->i_mode))
			type = "file";
		else if (S_ISDIR(ip->i_mode))
			type = "dir";
		else if (S_ISLNK(ip->i_mode))
			type = "link";
		else if (S_ISCHR(ip->i_mode))
			type = "chr";
		else if (S_ISBLK(ip->i_mode))
			type = "blk";
		else if (S_ISFIFO(ip->i_mode))
			type = "fifo";
		else if (S_ISSOCK(ip->i_mode))
			type = "sock";
	}

	if (count == 1)
		node_name = SSI_NODE_NAME(node);

	RQ_LOG("path=%s type=%s req=%s count=%lld node=%s time=%ld.%03ld\n",
	       new_path, type, file_request_to_string(request), count,
	       node_name, time / 1000, time % 1000);

	/*
	 * Give some visibility to slow requests in the console log, but
	 * redact the path to be on the safe side.
	 */
	if (dvs_request_log_min_time_secs) {
		total = atomic64_inc_return(&dvs_request_log_count);
		if ((total == 1) || (total == 50) || (total == 500)) {
			printk("DVS: type=%s req=%s count=%lld node=%s "
			       "time=%ld.%03ld [#%llu]\n",
			       type, file_request_to_string(request), count,
			       node_name, time / 1000, time % 1000, total);
		}
	}

	free_page((unsigned long)bufp);
}

static atomic64_t dvs_fs_log_count = ATOMIC64_INIT(0);

/*
 * Log information about server-generated file system requests in real time.
 *
 * WARNING: external scripts may be relying on the entries of this file - do
 * not remove entries without investigating this first!
 */
uint64_t log_fs(char *op, const char *path, uint64_t start_time_us,
		struct file_request *filerq)
{
	char *new_path = "[unknown]";
	char *source_node = "[unknown]";
	uint64_t total_reqs;
	uint64_t elapsed_time_us;

	elapsed_time_us = dvs_time_get_us() - start_time_us;

	if (!dvs_fs_log_enabled ||
	    elapsed_time_us / USEC_PER_SEC < dvs_fs_log_min_time_secs)
		return elapsed_time_us;

	if (filerq)
		source_node = SSI_NODE_NAME(filerq->ipcmsg.source_node);

	if (path)
		new_path = (char *)path;
	/*
	 * Time measurements are taken with microsecond resolution, but
	 * currently get reported in fs_log using only milliseconds resolution.
	 * The us to ms conversion takes place below and can be adjusted or
	 * removed if seeking greater precision.
	 */
	FS_LOG("op=%s uid=%d apid=%llu node=%s time=%lld.%03lld path=%s\n", op,
	       current_uid(), DVS_LOG_APID, source_node,
	       (long long)(elapsed_time_us / USEC_PER_SEC),
	       (long long)(elapsed_time_us % MSEC_PER_SEC), new_path);

	/*
	 * Give some visibility to slow requests in the console log, but
	 * redact the path and uid to be on the safe side.
	 */
	if (dvs_fs_log_min_time_secs) {
		total_reqs = atomic64_inc_return(&dvs_fs_log_count);
		if (total_reqs == 1 || total_reqs == 50 || total_reqs == 500) {
			printk("DVS: op=%s apid=%llu node=%s time=%lld.%06lld\n",
			       op, DVS_LOG_APID, source_node,
			       (long long)(elapsed_time_us / USEC_PER_SEC),
			       (long long)(elapsed_time_us % USEC_PER_SEC));
		}
	}
	return elapsed_time_us;
}
