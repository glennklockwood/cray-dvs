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

#ifndef KERNEL_USIFILE_H
#define KERNEL_USIFILE_H

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file usifile.h"
#endif /* __KERNEL__ */

#include <linux/statfs.h>
#include <linux/namei.h>
#include <linux/fdtable.h>

#include "common/usierrno.h"
#include "common/resource.h"
#include "common/kernel/hash_table.h"
#include "common/kernel/usiipc.h"
#include "common/kernel/usicontext.h"
#include "common/kernel/ioctl_desc.h"
#include "dvs/usifile.h"
#include "dvs/usisuper.h"

/* Defines for the various hashing algorithms */
#define HASH_DEFAULT			0
#define HASH_FNV_1A			1
#define HASH_JENKINS			2
#define HASH_MODULO			3

#define DEFAULT_CACHE			0
#define DEFAULT_DWFS_FLAGS		0
#define DEFAULT_PARALLEL_WRITE		0
#define DEFAULT_MULTIFSYNC		0
#define DEFAULT_DATASYNC		0
#define DEFAULT_CLOSESYNC		0
#define DEFAULT_RETRY			1
#define DEFAULT_FAILOVER		1
#define DEFAULT_USERENV 		1
#define DEFAULT_CLUSTERED		1
#define DEFAULT_KILLPROCESS		1
#define DEFAULT_ATOMIC          	0
#define DEFAULT_DEFEROPENS		0
#define DEFAULT_MAGIC			0
#define DEFAULT_DISTRIBUTE_CREATE_OPS	0
#define DEFAULT_RO_CACHE		0
#define DEFAULT_CACHE_READ_SZ		0

#define RETRYSLEEP			5    /* seconds between retries */

#define DVS_NEED_HANDLER		3

/* Datawarp Cache specific section */
#define O_DWCFS_CREATE		(1 << 30)
#define O_DWCFS_STRIPED		(1 << 31)

/*
 * This structure will probably change to include more info over time.
 * Eventually we want to be able to support per file striping so the stripe
 * width and stripe depth will probably be added.
 * For the moment the mds_node is passed to DWCFS and will be used as
 * a verification with the way kdwcfs picks the MDS.
 * Soon it will get changed to the authoritative value for MDS
 */

/* Do not change without also changing the definitions in kdwcfs */
#define DWCFS_IOCTL_IDENT ((unsigned int)0xDF)
#define DWCFS_FC_INIT _IOW(DWCFS_IOCTL_IDENT, 11, struct dwcfs_fc_init)
struct dwcfs_fc_init {
	u32 flags;	 /* Separate from normal open flags */
	int target_node; /* Used to sanity check the message destination */
	int start_node;	 /* Possibly removed these in the future */
	int dwcfs_mds;	 /* DVS will pick the MDS node for dwcfs */
	/* Stash the operation so we can set the right flags in the ioctl */
	int request;
};

/* End DWCFS */

#define DWFS_BIT		(1 << 0)
#define DWCFS_BIT		(1 << 1)

/*
 * User environment variables handled on an open() request on a DVS file.
 */
#define DVS_DATASYNC    	"DVS_DATASYNC="
#define DVS_CACHE       	"DVS_CACHE="
#define DVS_BLOCKSIZE   	"DVS_BLOCKSIZE="
#define DVS_MAXNODES    	"DVS_MAXNODES="
#define DVS_CLOSESYNC   	"DVS_CLOSESYNC="
#define DVS_METATEST    	"DVS_METATEST="
#define DVS_KILLPROCESS 	"DVS_KILLPROCESS="
#define DVS_ATOMIC      	"DVS_ATOMIC="
#define DVS_DEFEROPENS	 	"DVS_DEFEROPENS="
#define DVS_CACHE_READ_SZ	"DVS_CACHE_READ_SZ="

#define MAX_FILE_PAYLOAD (MAX_MSG_SIZE-4096)
#define MAX_FILE_BUFFER  (1UL << 34)   /* 16 GB */
#define MAX_BUFFER_RETRIES	(1024)

/* Size of inode operation hash table */
#define INODE_OP_SIZE 4093

#define PAN_FS_CLIENT_MAGIC	0xAAD7AAEA
#define GPFS_MAGIC		0x47504653
#define LL_SUPER_MAGIC		0x0BD00BD0
#define KDWCFS_SUPER_MAGIC	0xBBFBBF20UL
#define KDWFS_SUPER_MAGIC	0xBBFBBF10UL

#define DWFS_PATH_LEN 256

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
static inline struct inode *file_inode(struct file *f)
{
        return f->f_dentry->d_inode;
}
#endif

/* Get dvs-private super block info given various fs objects */
#define INODE_ICSB(i) ((struct incore_upfs_super_block *) (i->i_sb->s_fs_info))
#define FILE_ICSB(f)  (INODE_ICSB(file_inode(f)))
#define SUPER_ICSB(s) ((struct incore_upfs_super_block *) s->s_fs_info)

/* Get inode and file private data */
#define INODE_PRIVATE(i) ((struct inode_info *) i->i_private)
#define FILE_PRIVATE(f) ((struct open_file_info *)f->private_data)

/* Access specific remote file in a file's private data */
#define DATA_RF(f, n) ((struct remote_file *) &FILE_PRIVATE(f)->data_rf[n])
#define META_RF(f, n) ((struct remote_file *) &FILE_PRIVATE(f)->meta_rf[n])
/* This is to access just the generic remote file structure in the list */
#define FILE_RF(f, n) ((struct remote_file *) &FILE_PRIVATE(f)->rf[n])

/* Macros for detecting datawarp file systems */
#define FILE_DWFS(f)		(FILE_ICSB(f)->dwfs_flags & DWFS_BIT)
#define FILE_DWCFS(f)		(FILE_ICSB(f)->dwfs_flags & DWCFS_BIT)
#define SUPER_DWFS(i)		(INODE_ICSB(i)->dwfs_flags & DWFS_BIT)
#define SUPER_DWCFS(i)		(INODE_ICSB(i)->dwfs_flags & DWCFS_BIT)

/* Various other macros of convenience */
#define FILE_RO_OPENFLAGS(f)	((FILE_PRIVATE(f)->open_flags & O_ACCMODE) == O_RDONLY)
#define FILE_RW_OPENFLAGS(f)	((FILE_PRIVATE(f)->open_flags & O_ACCMODE) == O_RDWR)
#define FILE_WO_OPENFLAGS(f)	((FILE_PRIVATE(f)->open_flags & O_ACCMODE) == O_WRONLY)

#define INODE_CWC_FILES(i)	(atomic64_read(&INODE_PRIVATE(i)->i_cwc_files))
#define INODE_INC_CWC_FILES(i)	(atomic64_inc(&INODE_PRIVATE(i)->i_cwc_files))
#define INODE_DEC_CWC_FILES(i)	(atomic64_dec(&INODE_PRIVATE(i)->i_cwc_files))
#define SUPER_SFLAGS(i)		(((struct super_block *)i->i_sb)->s_flags)

#define SUPERBLOCK_NAME(name) (strncmp(name, UPFS_SUPER_PREFIX,                \
	strlen(UPFS_SUPER_PREFIX)) == 0)

#define fpname(fp) 						\
	((fp && fp->f_path.dentry && fp->f_path.dentry->d_name.name)	\
	? (const char *) fp->f_path.dentry->d_name.name		\
	: "[unknown]")

static inline int loadbalance_index(struct incore_upfs_super_block *, int);
int super_node_to_nord(struct incore_upfs_super_block *icsb, int node);
static inline int inode_sso(struct inode *ip);

static inline int
loadbalance_index(struct incore_upfs_super_block *icsb, int node)
{
	int i = 0, valid_nodes = 0, list_len = icsb->data_servers_len;

	do {
		if (icsb->data_servers[i].up) {
			if (valid_nodes++ == node) {
				return icsb->data_servers[i].node_map_index;
			}
		}
	} while (++i < list_len);

	/* else return the first node. this should never occur because the
	 * loadbalance code shouldn't run when there isn't 1 node up, but
	 * return this just in case and to quiet a compiler warning */
	return icsb->data_servers[0].node_map_index;
}

/*
 * Hashing from Bob Jenkins (http://burtleburtle.net/bob/hash/integer.html.
 */
static inline unsigned long
hash_jenkins(unsigned long val)
{
        val = (val + 0x7ed55d16) + (val << 12);
        val = (val ^ 0xc761c23c) ^ (val >> 19);
        val = (val + 0x165667b1) + (val << 5);
        val = (val + 0xd3a2646c) ^ (val << 9);
        val = (val + 0xfd7046c5) + (val << 3);
        val = (val ^ 0xb55a4f09) ^ (val >> 16);
        return val;
}

/*
 * FNV-1a hashing
 */
#define FNV1_PRIME_32 0x01000193
static inline unsigned long
hash_fnv_1a(unsigned long val) {

	int i;
	unsigned long hash = 0x811c9dc5;
	unsigned char *data = (char *) &val;

	for (i = 0; i < sizeof(unsigned long); i++) {
		hash ^= data[i];
		hash *= FNV1_PRIME_32;
	}
	return hash;
}


static inline unsigned long
dvs_hash(struct hash_info *hash, unsigned long val)
{
	if (hash->hash_on_nid)
		val = (unsigned long) usi_node_addr;

	switch (hash->algorithm) {
		case HASH_MODULO:
			return val;
		case HASH_JENKINS:
			return hash_jenkins(val);
		case HASH_FNV_1A:
		case HASH_DEFAULT:
		default:
			return hash_fnv_1a(val);
	}
}

/*
 * inode_sso - calculate the starting stripe offset for the supplied inode.
 */
static inline int
inode_sso(struct inode *ip)
{
	struct incore_upfs_super_block *icsb = INODE_ICSB(ip);

	if (icsb->loadbalance)
		return 0;
	return dvs_hash(&icsb->data_hash, ip->i_ino) % icsb->data_servers_len;
}

static inline int
dwcfs_mds(struct inode *ip)
{
	return INODE_ICSB(ip)->meta_servers[0].node_map_index;
}

struct dvs_posix_lock {
	struct list_head lh;
	struct files_struct files;
	int pid;
};

/* Flags for remote refs */
#define DVS_RR_OPEN_EXEC	0x01

struct remote_ref {
	/* Entry for the big remote ref list */
	struct list_head rr_lh;
	struct list_head inode_list;
	struct list_head quiesced_lh;
	struct inode_ref *inode_ref;
	struct kref ref;
	int node;
	unsigned long key;
	struct file *fp;
	int flags;
	/* This flag indicates that the file has been closed due to quiesce.
	   Keep the rr around to provide the correct error */
	int quiesced;
	/* These are useful for keeping track of locks on the file */
	spinlock_t posix_lock_sl;
	struct list_head posix_lock_lh;
};

void free_remote_ref(struct kref *ref);

#define rr_ref_init(rr) kref_init(&rr->ref)
#define rr_ref_get(rr) kref_get(&rr->ref)
#define rr_ref_put(rr) kref_put(&rr->ref, free_remote_ref)

struct extent;
struct page_desc;
struct pages_request;

struct	remote_handle {
	void		*remote_ref;
	unsigned long 	key;
};

#define SIZEOF_DEBUG_MUTEX 160

/*
 * Remote files can play the role of data remote file or metadata remote file.
 * We use the rf_type bitmask to tell them apart. If a mount point does not
 * have separate metadata servers, remote files for that mount point will play
 * both roles.
 */
#define RF_TYPE_DATA	(1 << 0)
#define RF_TYPE_META	(1 << 1)

struct	remote_file {
	struct list_head list;
	struct open_file_info *finfo;
	union {
		struct mutex mutex;
		char non_debug_pad[SIZEOF_DEBUG_MUTEX];
	};
	char	*dwfs_data_path;
	int	valid;
	int	quiesced;
	int	remote_node;
	int	remote_node_orig;
	struct remote_handle file_handle;
	int	use_local_position;
	int	flush_required;
	int	rf_type;
	time_t	identity;
	unsigned long magic;
	long last_write;
	long last_sync;
};

/* Prototype required for usetattr when doing ftruncate */
int send_ipc_file_retry (char *myname,
			struct file *fp,
			struct remote_file *rf,
			int rf_len,
			int nord,
			struct file_request *filerq,
			int rqsz,
			struct file_reply *freply,
			int rpsz,
			int *node);

struct outstanding_page {
	struct page *pagep;
	struct outstanding_page *next;
};

struct outstanding_io {
	loff_t	offset;
	int	length;
	struct outstanding_page *op;
	struct outstanding_io *next;
};

typedef struct extent {
	int	indx; /* offset into pagesrq pagesd array, not page index */
	int	count;
	struct 	pages_request *pagesrq; /* request for this extent */
} extent_t;

#define RPS_PGSD_FREE		0x021234
#define RPS_PGSD_INUSE		0x025678

typedef struct pages_desc {
	struct page		**pages;
	atomic_t		ref_count;  /* multiple requests per pages */
	atomic_t		state;
} pages_desc_t;

#define DEFAULT_FREQ_INSTANCES	4

#define DEFAULT_EXTENTS      64

typedef struct freq_instance {
	struct file_request	*freq;
	int			read_count;
	struct async_retry	*aretry;
	dvs_tx_desc_t		cookie;
	int			to_node;
} freq_instance_t;

typedef enum {
	PRIOV_Normal,
	PRIOV_Cleanup,
	PRIOV_Error_Messenger
} processiovs_mode_t;

typedef enum {
	CLUP_Forced,
	CLUP_Passive
} cleanup_mode_t;

typedef enum {
	UNLNK_Cleanup,
	UNLNK_Have_Reply,
	UNLNK_ESTALE_Retry
} unlink_mode_t;

#define RPS_RQ_FREE	0x1001
#define RPS_RQ_ACTIVE	0x1002
#define RPS_RQ_EXPIRING	0x1003
#define RPS_RQ_EXPIRED	0x1004
#define RPS_RQ_INVALID	0x1005  /* was cancelled or an error occurred */

#define RPS_RQ_FLAGS_READPAGE	0x01
#define PIO_RQ_FLAGS_WRITEPAGE	0x02
#define PIO_RQ_FLAGS_PREREAD	0x04

#define DO_RPGS  0x00 /* doing readpages request */
#define DO_RPG   0x01 /* doing readpage request */
#define DO_PRERD 0x02 /* doing cached write page pre-read */

/*
 * xfer_count and xfer_error are accumulators that collect the total page
 * transfer bytes (or errors) as the different nodes complete transfers.
 * When all is done, if there are any errors, the total is discarded.
 * Otherwise it is logged in the statistics.
 */
typedef struct pages_request {
	struct list_head	rq_list;
	atomic_t		state;
	loff_t			offset;
	size_t			length;
	atomic64_t		xfer_count;	   /* accumulator for transfer count */
	atomic64_t		xfer_maxoff;	   /* accumulator for max offset */
	atomic64_t		xfer_error;	   /* error counter */
	pages_desc_t		*pagesd;
	int			ext_indx;
	int			ext_count;
	struct inode		*ip;
	struct file		*fp;		   /* requesting file (may be gone) */
	struct writeback_control *wbc;
	void			*vmap_addr;
	void			*rma_handle;

	short			rq_flags;

	int			msg_count;	   /* total of freqs issued */
	atomic_t		msgs_outstanding;  /* for this request */
	atomic_t		rq_msg_waiters;
	struct semaphore	rq_msg_sema;	   /* used for waiting */
	struct semaphore	writepages_sema;   /* wake waiting writepages */

	atomic_t		reads_outstanding; /* actual transfers */
	atomic_t		rq_read_waiters;
	struct semaphore	rq_read_sema;	   /* used for waiting */

	int			num_freqs;
	freq_instance_t		freqs[0];
} pages_request_t;

typedef enum {
	AR_Default,
	AR_Will_Retry,
	AR_Retried,
        AR_Cancel_Retry,  /* Keep this after the ones that affirm retry */
} async_retry_t;

struct async_retry {
	struct list_head	list;
	dvs_tx_desc_t		tx_cookie;
	int			ar_nord;  /* DVS server index */
	int			ar_node;  /* actual NID */
	struct file_request	*filerq;
	struct file		*fp;
	int			rqsz;
	int			ar_status;

	/*
	 * DEPRECATED 06/2014
	 * Isolate the readpage stuff here so when it goes away this can
	 * as well.
	 */
	struct readpage_retry {
		struct inode_info	*iip;
		struct outstanding_io	*op;
		struct page		*page;
	} readpage;
};

#define IGNORE_INODE_SEMAPHORE(iip) (iip->inode_lock_holder == current->pid)

#define NOTIFY_OF_ABNORMAL_SEND(filerq, start_node) { \
	(filerq)->ipcmsg.notify_of_abnormal_send = 1; \
	(filerq)->ipcmsg.abnormal_handler = adjust_filerq; \
	(filerq)->ipcmsg.target_node = (start_node); \
}

#define WAIT_FOR_READS(rq) { \
	atomic_inc(&((rq)->rq_read_waiters)); \
	if (atomic_read(&((rq)->reads_outstanding))) { \
		down(&((rq)->rq_read_sema)); \
	} \
}

#define RELEASE_READ_WAITERS(rq) { \
	while (atomic_read(&((rq)->rq_read_waiters))) { \
		up(&((rq)->rq_read_sema)); \
		atomic_dec(&((rq)->rq_read_waiters)); \
	} \
}

#define WAIT_FOR_MSGS(rq) { \
	atomic_inc(&((rq)->rq_msg_waiters)); \
	if (atomic_read(&((rq)->msgs_outstanding))) { \
		down(&((rq)->rq_msg_sema)); \
	} \
}

#define RELEASE_MSG_WAITERS(rq) { \
	while (atomic_read(&((rq)->rq_msg_waiters))) { \
		up(&((rq)->rq_msg_sema)); \
		atomic_dec(&((rq)->rq_msg_waiters)); \
	} \
}

struct inode_info {
	/* struct file is only used by imported files in place of path */
	struct file		*fp;

	/* readpage support */
	struct semaphore	oio_sema;
	struct outstanding_io	*oio;

	/* readpages support */
	struct list_head	requests;
	struct rw_semaphore	requests_sem;

	/* writepages support */
	struct file		*wb_fp;
	atomic_t		dirty_pgs;
	atomic64_t		i_cwc_files;

	/* deadlock avoidance */
	pid_t			inode_lock_holder; /* uopen and urelease only */

	spinlock_t		lock;
	struct open_reply	*openrp; /* if open is piggybacked w/ create */
	short			check_xattrs;

	/* readlink caching */
	char			*link_cache;
	spinlock_t		link_lock;

	/* safe O_CREAT handling */
	pid_t			o_creat_pid;

	/* Underlying file system info */
	unsigned long		underlying_magic;

	unsigned long		cache_time;
	/* write semaphore for multiple writers */
	struct rw_semaphore	write_sem;

	rwlock_t		estale_lock;
	char			*estale_nodes;
	int			estale_num_nodes;
	int			estale_max_nodes;
	unsigned long		estale_jiffies;

	atomic64_t		num_requests_open;
	unsigned long		ii_create_jiffies;
};

/*
 * open_file_info - Every open file is allocated one of these in uopen.
 */
struct open_file_info {
	int			blocksize;

	/* retry in progress: 1 retry in progress, 2 uopen loop in progress*/
	int			rip;

	unsigned int		open_flags;
	short			d_open;

	short			datasync;
	short			closesync;
	short			cache;
	short			killprocess;
	short			nokill_error;
	short			atomic;
	short			deferopens;
	short			ro_cache;
	unsigned int		cache_read_sz;

	/* write in progress if nonzero */
	short			write;

	struct semaphore	rip_sema;
	struct semaphore	write_sema;
	struct semaphore	rocache_sema;

	struct file		*fp;
	struct list_head	list;

	/* estale node tracking */
	spinlock_t		estale_lock;
	char			*estale_nodes;
	int			estale_num_nodes;
	int			estale_max_nodes;

	/*
	 * The remote files are allocated as a single array of size
	 * (data_rf_len + meta_rf_len), with the data remote files first.
	 * The data_rf and meta_rf pointers are set to point to the proper
	 * elements in the array.
	 */
	/* Remote files open on this file's behalf on data servers */
	int			data_rf_len;
	struct remote_file	*data_rf;
	/* Remote files open on this file's behalf on metadata servers */
	int			meta_rf_len;
	struct remote_file	*meta_rf;
	/* Array of data and metadata remote files */
	int			rf_len;
	struct remote_file	rf[0];
};

#define filerq_get_node_base(_f, _node)		\
	(_f->nnodes ? ((int *)((char *)(_f) + (_node))) : NULL)

struct dwfs_open_info {
	unsigned int	path_len;
	unsigned int	bcstripe;
	char		path[1];
};

struct verifyfs_request {
	unsigned int hz;
	int flags;
	char pathname[1];
};

struct verifyfs_reply {
	unsigned long	magic;
	unsigned long	sync;
	struct		inode_attrs inode_copy;
};

struct lookup_request {
	char	pathname[1];
};

struct lookup_reply {
	short		inode_valid;
	short		no_inode;
	short		check_xattrs;
	int		node;
	struct		inode_attrs inode_copy;
	unsigned long	underlying_magic;
};

struct open_request {
	int		flags;
	int		max_nodes;
	unsigned int	dwfs_path_len;
	int		ro_cache_node;
	short		ro_cache_check;
	short		use_openexec;
	umode_t		i_mode;
	struct file	*ro_cache_cfp;
	short		d_open;
	short		wb_cache;
	char		pathname[1];
};

struct open_reply {
	struct	remote_file rf;
	loff_t	size;
	short	ro_cache_check;
	struct	inode_attrs inode_copy;
	struct dwfs_open_info dwfs_info;
};

struct create_request {
	int	mode;
	int	flags;
	short	intent_open;
	unsigned int dwfs_path_len;
	char	pathname[1];
};

struct create_reply {
	struct	inode_attrs inode_copy;
	struct	open_reply  open_reply;	/* if open is piggybacked w/ create */
	unsigned long       underlying_magic;
	struct dwfs_open_info dwfs_info;
};

struct usi_iovec {
	void	*address;
	size_t	count;
	loff_t	offset;
};

struct read_request {
	void	*address;
	size_t	count;
	loff_t	offset;
	void	*rma_handle;
	char	data[1];
};

struct read_reply {
	struct	inode_attrs inode_copy;
	char	data[1];
};

struct io_parallel_request {
	void	*rma_handle;
	void	*base;
	size_t	length;
	int	count;
	int	datasync; /* only used for write reqs */
	struct usi_iovec iov[1];
};

struct write_request {
	void	*address;
	size_t	count;
	loff_t	offset;
	void	*rma_handle;
	int	datasync;
	char	data[1];
};

struct write_reply {
	struct	inode_attrs inode_copy;
};

struct close_request {
	short	sync;
	short	ro_cache_check;
	int	ro_cache_node;
	struct	file *ro_cache_client_fp;
};

struct readdir_request {
	unsigned int count;
	loff_t	offset;
};

struct readdir_reply {
	loff_t	f_pos;
	char	data[1];
};

struct ioctl_request {
	unsigned int cmd;
	unsigned long arg;
	int	arg_size;
	char	arg_is_ref:1;
	char	arg_rw:1;
	char	data[1];
};

struct ioctl_reply {
	char data[1];
};

struct unlink_request {
	char	pathname[1];
};

struct unlink_reply {
	struct inode_attrs inode_copy;
};

struct lseek_request {
	loff_t	offset;
	unsigned int	op;
};

struct lseek_reply {
	loff_t	offset;
};

struct fsync_request {
	int	kind;
};

struct fasync_request {
	int	arg;
};

struct link_request {
	int	      invalidate_old;  /* negative if not a valid server nid */
        unsigned long magic;
	int	      orsz;
	int	      nrsz;
	char	      pathname[1];
};

struct link_reply {
	struct	inode_attrs inode_copy;
};

struct mkdir_request {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	int	mode;
#else
	umode_t	mode;
#endif
	char	pathname[1];
};

struct mkdir_reply {
	struct	inode_attrs inode_copy;
};

struct rmdir_request {
	char	pathname[1];
};

struct rmdir_reply {
	struct inode_attrs inode_copy;
};

struct mknod_request {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	int	mode;
#else
	umode_t	mode;
#endif
	int	dev;
	char	pathname[1];
};

struct mknod_reply {
	struct	inode_attrs inode_copy;
};

struct readlink_request {
	int	bufsize;
	char	pathname[1];
};

struct readlink_reply {
	char	pathname[1];
};

struct truncate_request {
	loff_t	len;
	char	pathname[1];
};

struct readpage_request {		/* DEPRECATED 06/2014 */
	void    *iop;
	struct inode_info *iip;
	size_t	count;
	size_t	csize;
	loff_t	offset;
};

struct readpage_data {			/* DEPRECATED 06/2014 */
	void    *iop;
	struct inode_info *iip;
	size_t	csize;
	size_t	count;
	char	data[1];
};

#define RPS_RPSRQ_FREE	0x031234
#define RPS_RPSRQ_INUSE	0x034567

struct io_pages_request {
	int				state;
	int				estale_retries;
	pages_request_t			*rq; /* original extent request */
	struct file_request		*source_request;
	struct io_parallel_request	ipr; /* needs to be last for the iovs */
};

struct io_pages_reply {
	struct file_request		*source_request;
	int				rmas_completed;
	long				xfer_count;
	long				rvals[1];  /* read return for each */
};

struct lock_request {
	int	cmd;
	int no_owner;
	struct flock lock;
	loff_t f_pos;
};

struct lock_reply {
	struct flock rlock;
};

struct getattr_request {
	char pathname[1];
};

struct getattr_reply {
	struct kstat kstatbuf;
};

struct setattr_request {
	struct iattr	attr;
	size_t	size_offset;
	char	pathname[1];
};

struct setxattr_request {
	int pathlen;
	int namelen;
	int valuelen;
	int flags;
	char data[1];
};

struct getxattr_request {
	int pathlen;
	int namelen;
	int valuelen;
	char data[1];
};

struct getxattr_reply {
	char data[1];
};

struct listxattr_request {
	int pathlen;
	int listlen;
	char data[1];
};

struct listxattr_reply {
	char data[1];
};

struct removexattr_request {
	int pathlen;
	int namelen;
	char data[1];
};

struct statfs_request {
	char pathname[1];
};

struct statfs_reply {
	struct statfs sbuf;
};

struct rocache_disable_request {
	struct file *fp;
};

struct permission_request {
	int		mask;
	unsigned long	ino;
	char		pathname[1];
};

struct permission_reply {
	struct		inode_attrs inode_copy;
};

struct sync_update_request {
	int size;
	unsigned long inodes[1];
};

struct sync_update_reply {
	unsigned long sync_times[1];
};

#define FREQ_IPC(request) (&(((struct file_request *)request)->ipcmsg))
#define RESET_FILERQ(freq) (((struct file_request *)(freq))->ipcmsg.state \
				= ST_INITIAL)

struct file_request {
	struct 	usiipc ipcmsg;
	struct	usicontext context;
	int	request;
	int	retry;	/* retry enabled for mounted filesystem */
	int	rip;	/* retry in progress for this request */
	struct	remote_handle file_handle;
	size_t	node_offset;
	int	nnodes;  /* nnodes (clusterfs aware) or maxnodes, based on operation */
	int	dwcfs_mds;
	struct file *client_fp;
	struct	{
		unsigned	invalidate :1;
		unsigned	multiple_servers :1;  /* nnodes only - no clusterfs */
		unsigned	is_nfs :1;
		unsigned	is_gpfs :1;
		unsigned	is_dwfs:1;
		unsigned	is_dwcfs:1;
		unsigned	is_dwcfs_stripe:1;
		unsigned	estale_retry :1;
		unsigned	estale_failover :1;
		unsigned	root_ctx :1; /* execute the request on the server as root */
		unsigned	ignore_ino_check :1; /* Don't bother checking inode number in rq_permission */
	} flags;
	union	{
		struct verifyfs_request		verifyfsrq;
		struct lookup_request 		lookuprq;
		struct open_request		openrq;
		struct read_request		readrq;
		struct write_request		writerq;
		struct close_request		closerq;
		struct readdir_request		readdirrq;
		struct create_request		createrq;
		struct unlink_request		unlinkrq;
		struct lseek_request		lseekrq;
		struct ioctl_request		ioctlrq;
		struct fsync_request		fsyncrq;
		struct fasync_request		fasyncrq;
		struct link_request		linkrq;
		struct mkdir_request		mkdirrq;
		struct rmdir_request		rmdirrq;
		struct mknod_request		mknodrq;
		struct readlink_request		readlinkrq;
		struct truncate_request		truncaterq;
		struct readpage_request		readpagerq;	/* DEPRECATED 06/2014 */
		struct readpage_data		readpagedata;	/* DEPRECATED 06/2014 */
		struct io_pages_request		iopagesrq;
		struct io_pages_reply		iopagesrp;
		struct lock_request		lockrq;
		struct getattr_request  	getattrrq;
		struct setattr_request		setattrrq;
		struct io_parallel_request 	ioprq;
		struct statfs_request		statfsrq;
		struct setxattr_request		setxattrrq;
		struct getxattr_request		getxattrrq;
		struct listxattr_request	listxattrrq;
		struct removexattr_request	removexattrrq;
		struct rocache_disable_request	rocachedisablerq;
		struct permission_request	permissionrq;
		struct sync_update_request	syncupdaterq;
	} u;
};

#define FREP_IPC(request) (&(((struct file_reply*)reply)->ipcmsg))

struct file_reply {
	struct 	usiipc ipcmsg;
	long	rval;
	union	{
		struct verifyfs_reply 	verifyfsrp;
		struct lookup_reply 	lookuprp;
		struct open_reply	openrp;
		struct write_reply	writerp;
		struct read_reply	readrp;
		struct readdir_reply	readdirrp;
		struct create_reply	createrp;
		struct unlink_reply	unlinkrp;
		struct readlink_reply	readlinkrp;
		struct lock_reply	lockrp;
		struct getattr_reply	getattrrp;
		struct mkdir_reply	mkdirrp;
		struct rmdir_reply	rmdirrp;
		struct mknod_reply	mknodrp;
		struct link_reply	linkrp;
		struct lseek_reply	lseekrp;
		struct statfs_reply	statfsrp;
		struct ioctl_reply	ioctlrp;
		struct getxattr_reply	getxattrrp;
		struct listxattr_reply	listxattrrp;
		struct sync_update_reply	syncupdaterp;
		struct permission_reply	permissionrp;
	} u;
};

/* request info - index by ordinal */
struct per_node {
	int                     count;
	int                     sent;
	int                     node;
	loff_t                  length;
	struct file_request     *request;
	struct file_reply       *reply;
};

/* readpages per node info -- compressed array of actual nodes in use */
typedef struct rps_per_node {
	int			iov_count;
	int			iov_list;  /* index in iovs of usi_iovecs */
	int			iov_last;
	size_t			xfer_total;
	int			nord;
} rps_per_node_t;

typedef struct rps_usi_iovec {
	int			iov_next;
	struct usi_iovec	usi_iov;
} rps_usi_iovec_t;

/* ro_cache per-inode hash structures */
struct ro_cache_fp {
	struct ro_cache_fp *next, *prev;
	int cnode;
	time_t cidentity;
	struct file *fp;
};

struct ro_cache_ihash {
	unsigned long i_ino;
	int writecount;
	int fp_count;
	struct ro_cache_fp *fp_head;
	struct semaphore fp_sem;
};

#define RO_CACHE_READONLY	1
#define RO_CACHE_WRITABLE	2

/* Exported file routines */
extern int dvsutil_init(void);
extern void dvsutil_exit(void);
extern int dvspn_init(void);
extern void dvspn_exit(void);

extern int do_usifile_stats(struct file_request *);
extern void file_node_down(int node);
extern void file_node_up(int node);
extern loff_t compute_file_size (struct inode *, int nnodes, int blksize, 
                                 loff_t fsize, int node);
extern char *get_path(struct dentry *, struct vfsmount *, char *, 
                      struct inode *);
extern int file_ops_retry(struct file *fp, char *opname, int orig_rval);
extern int inode_ops_retry(struct inode *ip, struct dentry *dep, char *opname, 
                           int retry, int orig_rval, int node);
int send_ipc_inode_retry (char *myname, struct inode *ip, struct dentry *dep, 
                          struct file_request *filerq, int rqsz, 
                          struct file_reply *freply, int rpsz, int *node);
extern unsigned long compute_file_blocks(struct inode *ip);
extern char *replacepath(char *bufp, char *path, char *prefix, 
                         struct inode *ip);

/* common client/server routines */
extern long common_retry( char *opname, int retno );
extern int send_ipc_with_retry(struct dvsproc_stat *stats, char *myname,
			       int nord, int node,
			       struct file_request *filerq, int rsz, 
			       struct file_reply *freply, int rpsz);
extern struct semaphore *ihash_find_entry(ht_t *inode_op_table, char *path);
extern int check_processes(int node, struct file *fp, struct inode *ip);
extern void log_request(int, char *, struct inode *, struct file *, u64, int,
			unsigned long);
extern void log_fs(char *, const char *, unsigned long, struct file_request *);

extern int ro_cache_readonly(struct file *fp, char *path, struct usiipc *ipcmsg,
			     struct file *client_fp);
extern int ro_cache_write(struct file *fp, char *path, struct file_request *freq);
extern int ro_cache_remove_fp(struct file *fp, int cnode, struct file *client_fp);
extern int ro_cache_downwrite(struct file *fp);

extern int unlink_filerq(struct file_request *freq, dvs_tx_desc_t tx_cookie,
				int to_node, unlink_mode_t unlnk_mode);
extern int process_iovs(pages_request_t *rq, struct io_parallel_request *ipr,
		struct io_pages_reply *rp, processiovs_mode_t mode);
extern int finalize_request(pages_request_t *rq);
extern int cleanup_reqs(struct inode *ip, cleanup_mode_t mode);
extern int detach_file_from_reqs(struct file *fp);
extern int dvs_attrcache_time_valid(unsigned long timestamp, struct super_block *sb);
extern void set_is_flags(struct file_request *filerq, struct inode *ip);


/*
 * The down versions of the INODE_SEMA_ macros all grab the iotsem
 * lock. This means only one can be in ihash_find_entry at a time.
 * They then retain the iotsem lock until they've downed the
 * semaphore lock(s) they are after.
 *
 * The up versions of the INODE_SEMA_ macros do not need to grab the
 * iotsem lock. It can safely be assumed if up is being called, a
 * down was previously called.
 *
 * This all works correctly because there is no remove operation for
 * the hash table. Once an entry has been added (via ihash_find_entry()),
 * it remains in the table until the machine is rebooted or the modules
 * are unloaded. If a remove operation is added, this locking logic
 * will need to be revisited.
 */
#define INODE_SEMA_DOWN(path) \
		{ struct semaphore *sema; \
		  down(&iotsem); \
		  if (unlikely((sema = ihash_find_entry(inode_op_table, path)) == NULL)) { \
			BUG(); \
		  } \
		  down(sema); \
		  up(&iotsem); \
		}

#define INODE_SEMA_UP(path) \
		{ struct semaphore *sema; \
		  if (unlikely((sema = ihash_find_entry(inode_op_table, path)) == NULL)) { \
			BUG(); \
		  } \
		  up(sema); \
		}

extern struct file_operations upfsfops;

/*
 * Wrappers around
 *
 * send_ipc_request()
 * send_ipc_request_async()
 * wait_for_async_request()
 * send_ipc_reply()
 *
 * These wrappers assist in statistics collection.
 */

/*
 * send_ipc_request_stats
 *   send_ipc_request
 *     dvsipc_ipc_ops.sendrq == dvsipc_send_ipc_request
 *       dvsipc_send_ipc_request_common
 *         write_message_to_transport
 *         dvsipc_wait_for_response
 *   DVSPROC_STAT_IPC_REQUEST (dvs stats)
 * DVSPROC_STAT_REQ (dvs and mnt stats)
 */
static inline int
send_ipc_request_stats(struct dvsproc_stat *stats, int node, int command,
		       struct file_request *request, int request_size,
		       struct file_reply *reply, int reply_size,
		       time_t identity)
{
	int rval;

	rval = send_ipc_request(node, command, FREQ_IPC(request),
				request_size, FREP_IPC(reply),
				reply_size, identity);

	if (request->ipcmsg.reply_address) {
		if (reply->rval == -ESTALE_DVS_RETRY) {
			reply->rval = -ESTALE;
			rval = -ESTALE_DVS_RETRY;
		}
	}

	dvsproc_stat_update(stats, DVSPROC_STAT_REQ, request->request, rval);

	return rval;
}

/*
 * send_ipc_request_async_stats
 *   send_ipc_request_async
 *     dvsipc_ipc_ops.sendrqa == dvsipc_send_ipc_request_async
 *       dvsipc_send_ipc_request_common
 *         write_message_to_transport
 *   DVSPROC_STAT_IPC_REQUEST_ASYNC (dvs stats)
 * DVSPROC_STAT_REQ (dvs and mnt stats)
 */
static inline int
send_ipc_request_async_stats(struct dvsproc_stat *stats, int node, int command,
			     struct file_request *request, int request_size,
			     struct file_reply *reply, int reply_size,
			     time_t identity)
{
	int rval;
	int request_type = request->request;  /* request could be gone after */

	rval = send_ipc_request_async(node, command, FREQ_IPC(request),
				      request_size, FREP_IPC(reply),
				      reply_size, identity);
	/*
	 * Async requests can fail at any time, but can only be considered
	 * to have succeeded once the response has been received.  Therefore,
	 * don't increment DVSPROC_STAT_REQ on success just yet.  An exception
	 * to this is for one-way requests (reply == NULL), since we'll
	 * never get a reply to key off of.
	 */
	if (rval < 0 || reply == NULL) {
		dvsproc_stat_update(stats, DVSPROC_STAT_REQ, request_type,
				    rval);
	}

	return rval;
}

/*
 * wait_for_async_request_stats
 *   wait_for_async_request
 *     dvsipc_ipc_ops.waitrqa == dvsipc_wait_for_async_request
 *       dvsipc_wait_for_response
 * DVSPROC_STAT_REQ (dvs and mnt stats)
 */
static inline int
wait_for_async_request_stats(struct dvsproc_stat *stats,
			     struct file_request *request)
{
	struct file_reply *reply;
	int rval;

	rval = wait_for_async_request(FREQ_IPC(request));

	if (request->ipcmsg.reply_address != NULL) {
		reply = container_of(request->ipcmsg.reply_address, struct file_reply, ipcmsg);
		if (reply->rval == -ESTALE_DVS_RETRY) {
			reply->rval = -ESTALE;
			rval = -ESTALE_DVS_RETRY;
		}
	}

	dvsproc_stat_update(stats, DVSPROC_STAT_REQ, request->request, rval);

	return rval;
}

/*
 * send_ipc_reply_stats
 *   send_ipc_reply
 *     dvsipc_ipc_ops.sendrp == dvsipc_send_ipc_reply
 *       write_message_to_transport
 *   DVSPROC_STAT_IPC_REPLY (dvs stats)
 * DVSPROC_STAT_REQ (dvs and mnt stats)
 */
static inline int
send_ipc_reply_stats(struct dvsproc_stat *stats, struct file_request *request,
		     struct file_reply *reply, int reply_size, int nocopy)
{
	int rval;

	rval = send_ipc_reply(FREQ_IPC(request), FREP_IPC(reply),
			      reply_size, nocopy);
	dvsproc_stat_update(stats, DVSPROC_STAT_REQ, request->request, rval);

	return rval;
}

static inline char *
dvs_dentry_path(struct dentry *dep, char *buff, int len) {

        char *path = dentry_path_raw(dep, buff, len);

        if (IS_ERR(path)) {
                snprintf(buff, len, "ERROR:%ld", PTR_ERR(path));
                path = buff;
        }
        return path;
}

/*
 * We don't want to use the file descriptors for stdin, stdout, or stderr in
 * the init_files struct. Any processes that fork from a process using the
 * init_files struct will inherit the DVS files as their stdin, stdout, or
 * stderr.
 */
static inline int
dvs_get_unused_fd(int flags)
{
	int unusable_fds[3] = {0, 0, 0};
	int fd, i;

	while (1) {
		fd = get_unused_fd_flags(flags);
		if (fd < 0)
			break;

		if (fd != 0 && fd != 1 && fd != 2)
			break;

		unusable_fds[fd] = 1;
	}

	for (i = 0; i < 3; i++) {
		if (unusable_fds[i] == 0)
			continue;

		put_unused_fd(i);
	}

	return fd;
}

#define fd_install_get(_fd_, _fp_) {\
	fd_install((_fd_), (_fp_)); \
	get_file((_fp_)); \
}

#define fd_uninstall(_fd_) { \
	struct files_struct *files = current->files; \
	struct fdtable *fdt; \
	spin_lock(&files->file_lock);	\
	fdt = files_fdtable(files);	\
	rcu_assign_pointer(fdt->fd[_fd_], NULL);	\
	spin_unlock(&files->file_lock);	\
}

/*
 * Determine the depth of a dentry from its root
 * super block. This is used when deciding how
 * many levels of ino checking to ignore.
 */
static inline int
fs_tree_depth(struct dentry *dep) {

	int depth = -1;
	int max_depth = INODE_ICSB(dep->d_inode)->ino_ignore_prefix_depth;
	struct dentry *root = dep->d_sb->s_root;

	while (++depth < max_depth && dep && dep != root)
		dep = dep->d_parent;

	return depth;
}

/* We avoid checking an inode number for these reasons:
 * 1) This is not a true cluster file system
 * 2) We are in an autofs directory (Bug 842634)
 * 3) We are in the tmpfs 'prelude' to the actual mount point, such as
 *      /cray/css before we hit the autofs portions (see bug 842634).
 *      As long as this inode and its parent are tmpfs, we haven't
 *      transitioned to the real parallel file system.
 */
static inline int
ignore_ino_mismatch(struct dentry *dep, struct inode *ip) {

	struct inode *i_parent = dep->d_parent->d_inode;
	if (!INODE_ICSB(ip)->clusterfs ||
		fs_tree_depth(dep) < INODE_ICSB(ip)->ino_ignore_prefix_depth ||
		INODE_PRIVATE(ip)->underlying_magic == AUTOFS_SUPER_MAGIC ||
		(INODE_PRIVATE(i_parent)->underlying_magic == TMPFS_MAGIC &&
		 INODE_PRIVATE(ip)->underlying_magic == TMPFS_MAGIC)) {
		return 1;
	}
	return 0;
}

#endif /* KERNEL_USIFILE_H */
