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
#include <linux/xattr.h>
#include <linux/stat.h>
#include <linux/namei.h>
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
#define KERNEL
#include <linux/in.h>
#include <linux/magic.h>
#include <fs/mount.h>
#include "common/sync.h"
#include "common/log.h"
#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/kernel/usiipc.h"
#include "common/kernel/dvsfs.h"
#include "dvs/kernel/usifile.h"
#include "dvs/kernel/usifileproto.h"
#include "dvs/usisuper.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
struct readlink_data {
	struct inode *inode;
	char *buf;
};
#endif
static struct dentry *upfs_read_super(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *raw_data);

static struct inode *dvs_iget(struct super_block *sp, unsigned long ino,
			      struct inode_attrs *remote_inode);

static struct file_system_type usi_fs_type = {
	.owner = THIS_MODULE,
	.name = "dvs",
	.mount = upfs_read_super,
	.kill_sb = kill_anon_super,
};

/* forward declarations */
static struct inode_operations iops_file;
static struct inode_operations iops_dir;
static struct inode_operations iops_link;
static struct super_operations usi_super_ops;
static struct dentry_operations dops;

int dvspn_init(void)
{
	int rval, i;

	alist = vmalloc_ssi(sizeof(struct list_head) * ssiproc_max_nodes);
	if (!alist)
		return -ENOMEM;

	aretrysem = vmalloc_ssi(sizeof(struct semaphore) * ssiproc_max_nodes);

	if (!aretrysem) {
		vfree_ssi(alist);
		return -ENOMEM;
	}

	for (i = 0; i < ssiproc_max_nodes; i++) {
		INIT_LIST_HEAD(&alist[i]);
		sema_init(&aretrysem[i], 1);
	}

	if ((rval = register_filesystem(&usi_fs_type)) < 0) {
		vfree_ssi(alist);
		vfree_ssi(aretrysem);
		printk(KERN_ERR "DVS: %s: parallel filesystem init "
				"failed %d\n",
		       __func__, rval);
	}

	return rval;
}

void dvspn_exit(void)
{
	KDEBUG_OFC(
		0,
		"DVS: %s: parallel filesystem shutdown "
		"stats: inodes read: %ld max_inodes: %ld mmap pages read: %ld "
		"current_inodes: %ld revalidates done: %ld revalidates "
		"skipped %ld\n",
		__func__, inodes_read, max_inodes, mmap_pages_read,
		current_inodes, revalidates_done, revalidates_skipped);

	vfree_ssi(alist);
	vfree_ssi(aretrysem);
	unregister_filesystem(&usi_fs_type);
}

static int parse_node(char *buf)
{
	int node;

	if (!buf || strlen(buf) > (UPFS_MAXNAME - 1)) {
		printk(KERN_ERR "DVS: %s: "
				"DVS: Bad nodename specified\n",
		       __func__);
		return -1;
	}

	/* Ensure specified node is known to DVS */
	for (node = 0; node < ssiproc_max_nodes; node++) {
		if (node_map[node].name != NULL &&
		    strcmp(node_map[node].name, buf) == 0)
			break;
	}
	if (node == ssiproc_max_nodes) {
		printk(KERN_ERR "DVS: %s: "
				"Nodename %s not in node list\n",
		       __func__, buf);
		return -1;
	}

	return node;
}
/*
 * parse_nodelist - fill in server list for in-core superblock using
 *                  the nodelist string and string separator list provided.
 */
struct dvs_server *parse_nodelist(char *buf, char *sepstr, int *len)
{
	struct dvs_server *node_list_tmp, *node_list;
	char *tok;
	int i, node, nnodes = 0;

	if ((node_list_tmp =
		     kmalloc_ssi(sizeof(struct dvs_server) * MAX_PFS_NODES,
				 GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "DVS: %s: Unable to allocate node list with "
				"size %lu\n",
		       __func__, sizeof(int) * MAX_PFS_NODES);
		return NULL;
	}

	while ((tok = strsep(&buf, sepstr))) {
		if (tok[0] == '\0')
			continue;

		if ((node = parse_node(tok)) < 0)
			goto error_out;

		if (nnodes == MAX_PFS_NODES) {
			printk(KERN_ERR "DVS: %s: More than %d "
					"nodes specified in node list\n",
			       __func__, MAX_PFS_NODES);
			goto error_out;
		}

		node_list_tmp[nnodes].node_map_index = node;
		node_list_tmp[nnodes].up = 1;
		node_list_tmp[nnodes].magic = -1;

		KDEBUG_PNC(0, "DVS: %s: node_list[%d] set to %d (%s)\n",
			   __FUNCTION__, nnodes, node, tok);
		nnodes++;
	}

	if (nnodes < 1) {
		printk(KERN_ERR "DVS: %s: No "
				"nodes specified in node list\n",
		       __func__);
		goto error_out;
	}

	if ((node_list = kmalloc_ssi(sizeof(struct dvs_server) * nnodes,
				     GFP_KERNEL)) == NULL) {
		goto error_out;
	}

	for (i = 0; i < nnodes; i++)
		node_list[i] = node_list_tmp[i];

	*len = nnodes;
	kfree_ssi(node_list_tmp);
	return node_list;

error_out:
	kfree_ssi(node_list_tmp);
	return NULL;
}

static int add_data_servers(struct incore_upfs_super_block *icsb, char *buf,
			    char *sepstr)
{
	int len;
	struct dvs_server *nodes;

	if ((nodes = parse_nodelist(buf, sepstr, &len)) == NULL)
		return -1;

	icsb->data_servers_len = len;
	icsb->data_servers = nodes;

	return 0;
}

static int add_meta_servers(struct incore_upfs_super_block *icsb, char *buf,
			    char *sepstr)
{
	int len;
	struct dvs_server *nodes;

	if ((nodes = parse_nodelist(buf, sepstr, &len)) == NULL)
		return -1;

	icsb->meta_servers_len = len;
	icsb->meta_servers = nodes;

	return 0;
}

static int read_file_into_buffer(char *pathname, char *buf, int bufflen)
{
	struct file *fp = NULL;
	mm_segment_t oldfs;
	int fd = 0, rval;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	fd = dvs_get_unused_fd(0);
	if (fd < 0) {
		set_fs(oldfs);
		printk(KERN_ERR "DVS: parse_options: DVS "
				"(nodefile): no free fds\n");
		return 0;
	}

	fp = filp_open(pathname, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		printk(KERN_ERR "DVS: parse_options: DVS "
				"(nodefile): bad filename %s\n",
		       pathname);
		rval = 0;
		goto out;
	}

	fd_install(fd, fp);

	rval = p_sys_pread64(fd, buf, bufflen - 1, 0);

	if (rval < 0) {
		printk(KERN_ERR "DVS: parse_options: DVS "
				"(nodefile): read of %s failed (%d)\n",
		       pathname, rval);
		goto out;
	} else if (rval == (UPFS_MAXNAME * UPFS_MAXSERVERS)) {
		printk(KERN_ERR "DVS: parse_options: DVS "
				"(nodefile): file too large %s\n",
		       pathname);
		rval = 0;
		goto out;
	}

	buf[rval] = 0;

out:
	if (fp && !IS_ERR(fp))
		filp_close(fp, current->files);
	fd_uninstall(fd);
	put_unused_fd(fd);
	set_fs(oldfs);

	return rval;
}

/**
 * Given a decimal string in seconds, convert the value to jiffies up to the
 * nearest millisecond. Also write the value (to milliseconds) into a char
 * buffer for convenience. Used with the attrcache_timeout option.
 * Returns UPFS_ATTRCACHE_DEFAULT if input is invalid.
 *
 * @param value The string number to be interpreted
 * @param str The ICSB attrcache_timeout_str
 * @param bufflen The length of char array str
 *
 * @return Milliseconds
 */
unsigned long seconds_to_jiffies(char *value, char *str, size_t bufflen)
{
	int n = 0, len = 0, i = 0;
	unsigned long integer = 0;
	unsigned long decimal = 0;
	unsigned long jiffs;
	char decimal_str[4] = "000";
	int bogus = 0;
	int decimal_cnt = 0;

	char *dec_loc = strchr(value, '.');

	/* Validate input: allow digits and [0,1] radix points.
	 * This implies no negative numbers.
	 * Correct also for radix points with no following digit(s).
	 */
	while (value[i] != '\0' && !bogus) {
		char c = value[i];
		if (c == '.')
			decimal_cnt++;

		if (decimal_cnt > 1 || (c == '.' && value[i + 1] == '\0') ||
		    !(c == '.' || (c >= '0' && c <= '9'))) {
			printk(KERN_ERR
			       "DVS: %s: invalid value '%s' for "
			       "attrcache_timeout. Defaulting to %s.\n",
			       __func__, value, UPFS_ATTRCACHE_DEFAULT);
			memset(value, 0, strlen(value));
			snprintf(value, sizeof(UPFS_ATTRCACHE_DEFAULT) + 1,
				 "%s", UPFS_ATTRCACHE_DEFAULT);
			bogus = 1;
		}
		i++;
	}

	if (dec_loc) {
		dec_loc++;
		while (dec_loc[n] != '\0' && n < 3) {
			decimal_str[n] = dec_loc[n];
			n++;
		}
	}

	integer = simple_strtoul(value, NULL, 10);

	/* Cap the attrcache_timeout at a day */
	if (integer > 86400)
		integer = 86400;
	decimal = simple_strtoul(decimal_str, NULL, 10);

	jiffs = (HZ * (1000 * integer + decimal)) / 1000;

	/* Round up if there is a remainder */
	if ((HZ * (1000 * integer + decimal)) % 1000)
		jiffs++;

	len = snprintf(str, bufflen, "%lu", integer);
	if (decimal) {
		snprintf(str + len, bufflen - len, ".%s", decimal_str);
	}
	return jiffs;
}

/*
 * NOTE:
 * Use mount data to point directly at the node with the real filesystem,
 * Get remote mount without having to go thru /
 *
 * To mount a DVS filesystem (similar to nfs):
 *   mount -t dvs -o path=/remote-path,nodename=nnnnn /local-mount-directory
 *
 * options (with defaults):
 *   path=/foobar
 *   nodename=server1:server2:server3
 *   nodefile=filename
 *   blksize=524288
 *   attrcache_timeout=3
 *   mds=server1
 *   {cache|nocache}
 *   {datasync|nodatasync}
 *   {closesync|noclosesync}
 *   {userenv|nouserenv}
 *   {retry|noretry}
 *   {failover|nofailover}
 *   {clusterfs|noclusterfs}
 *   {atomic|noatomic}
 *   {loadbalance|noloadbalance} (forces clusterfs on; default is no)
 *   {killprocess|nokillprocess}
 *   {deferopens|nodeferopens}
 *   {distribute_create_ops|no_distribute_create_ops}
 *   {ro_cache|no_ro_cache}
 *   {dwfs|nodwfs}
 *   {dwcfs|nodwcfs}
 *   {multifsync|nomultifsync}
 *   {parallelwrite|noparallelwrite}
 *   {hash_on_nid|nohash_on_nid}
 *   magic=
 *   cache_read_sz=0
 *   maxnodes=[number of nodes specified in nodename list or
 *             contained in nodefile]
 *
 * Note: the 'clusterfs' option should always be used. It specifies that the
 * underlying filesystem on each DVS server is shared between all servers,
 * such as an NFS filesystem mounted from the same NFS server & path, or a
 * real cluster filesystem, such as GPFS or PanFS. DVS verifies that the
 * specified mountpoint is accessible (and is a directory) on each of the
 * server nodes.  If 'noclusterfs' is specified, DVS behaves just like
 * 'clusterfs' except that all create, remove, mkdir, and rmdir operations
 * are sent to all servers.  This allows us to test DVS performance to RAM
 * file systems on multiple servers in parallel modes since a file/directory
 * will exist regardless of which server is picked for the actual I/O (based
 * on inode hash).
 *
 * If the 'maxnodes' option is specified, the number of servers used from the
 * total set is limited to the value following the option, which must be less
 * than or equal to the number of servers specified on the nodename list.
 *
 * The 'nodefile' option behaves identically to 'nodename'. The only
 * difference being that the node list is contained in a file as opposed to
 * being specified explicitly on the mount line.
 *
 * To make mount options "recyclable" from an existing mount to a new mount,
 * a number of read-only options which the mount operation itself configures
 * are ignored including 'statsfile' and 'nnodes.'
 */

static int parse_options(char *options, struct incore_upfs_super_block *icsb,
			 int *flags)
{
	char *this_char, *value;
	int hash_set = 0, rval;
	char *buf = NULL;

	if (!options || !*options) {
		printk("DVS: %s: No mount options\n", __func__);
		return 0;
	}
	KDEBUG_PNC(0, "DVS: %s: read_super got option string: %s\n", __func__,
		   options);

	for (this_char = strsep(&options, ","); this_char;
	     this_char = strsep(&options, ",")) {
		KDEBUG_PNC(0, "DVS: %s: got option %s 0x%x\n", __func__,
			   this_char, *this_char);

		/* handle trailing , */
		if (*this_char == '\0')
			continue;

		if ((value = strchr(this_char, '=')) != NULL)
			*value++ = 0;

		if (!strcmp(this_char, "path")) {
			if (!value || !*value ||
			    strlen(value) > (UPFS_MAXNAME - 1)) {
				printk(KERN_ERR "DVS: %s: Bad path specified\n",
				       __func__);
				return 0;
			}
			strcpy(icsb->prefix, value);
		} else if (!strcmp(this_char, "nodename") ||
			   !strcmp(this_char, "dataservers")) {
			if (icsb->data_servers != NULL) {
				printk(KERN_WARNING
				       "DVS: %s: warning: nodename/dataservers "
				       "already specified\n",
				       __func__);
			}
			if (add_data_servers(icsb, value, ":") != 0) {
				printk(KERN_ERR "DVS: %s: parse_nodelist "
						"failed\n",
				       __func__);
				return 0;
			}
		} else if (!strcmp(this_char, "mds") ||
			   !strcmp(this_char, "metadataservers")) {
			if (add_meta_servers(icsb, value, ":") < 0) {
				printk(KERN_ERR "DVS: %s: bad mds servers\n",
				       __func__);
				return 0;
			}
		} else if (!strcmp(this_char, "nodefile")) {
			if (!value || !*value) {
				printk(KERN_ERR "DVS: %s: DVS "
						"(nodefile): bad filename\n",
				       __func__);
				return 0;
			}
			if (icsb->data_servers != NULL) {
				printk(KERN_WARNING
				       "DVS: %s: warning: nodename/dataservers "
				       "already specified\n",
				       __func__);
			}
			buf = (char *)vmalloc_ssi(UPFS_MAXNAME *
						  UPFS_MAXSERVERS);

			if (buf == NULL) {
				printk(KERN_ERR "DVS: %s: (nodefile): vmalloc "
						"of read buf failed\n",
				       __func__);
				return 0;
			}

			rval = read_file_into_buffer(
				value, buf, UPFS_MAXNAME * UPFS_MAXSERVERS);

			if (rval == 0) {
				vfree_ssi(buf);
				return 0;
			}

			if (add_data_servers(icsb, buf, " \t\n:") != 0) {
				printk(KERN_ERR "DVS: parse_nodelist failed\n");
				vfree_ssi(buf);
				return 0;
			}
			vfree_ssi(buf);

		} else if (!strcmp(this_char, "blksize")) {
			if (!value || !*value) {
				printk(KERN_ERR "DVS: %s: bad blksize\n",
				       __func__);
				return 0;
			}
			icsb->bsz = simple_strtoul(value, NULL, 0);
			if (icsb->bsz <= 0)
				icsb->bsz = DEFAULT_PFS_STRIPE_SIZE;
			if (icsb->bsz % PAGE_SIZE != 0) {
				printk(KERN_ERR
				       "DVS: %s: Warning: "
				       "Block size is not a multiple of page "
				       "size.\n",
				       __func__);
			}
		} else if (!strcmp(this_char, "attrcache_timeout")) {
			if (!value || !*value) {
				printk(KERN_ERR "DVS: %s: "
						"bad attrcache_timeout\n",
				       __func__);
				return 0;
			}
			icsb->attrcache_timeout = seconds_to_jiffies(
				value, icsb->attrcache_timeout_str,
				sizeof(icsb->attrcache_timeout_str));
			/* attrcache_timeout should not be too large for read
			 * write */
			if (!(*flags & MS_RDONLY) &&
			    (icsb->attrcache_timeout > 3 * HZ)) {
				printk(KERN_ERR
				       "DVS: %s: "
				       "Warning attrcache_timeout greater "
				       "than 3 for read-write mount\n",
				       __func__);
			}
		} else if (!strcmp(this_char, "hash_on_nid")) {
			icsb->data_hash.hash_on_nid = 1;
			icsb->meta_hash.hash_on_nid = 1;
			if (!hash_set) {
				icsb->data_hash.algorithm = HASH_MODULO;
				icsb->meta_hash.algorithm = HASH_MODULO;
			}
		} else if (!strcmp(this_char, "data_hash_on_nid")) {
			icsb->data_hash.hash_on_nid = 1;
			if (!hash_set) {
				icsb->data_hash.algorithm = HASH_MODULO;
			}
		} else if (!strcmp(this_char, "meta_hash_on_nid")) {
			icsb->meta_hash.hash_on_nid = 1;
			if (!hash_set) {
				icsb->meta_hash.algorithm = HASH_MODULO;
			}
		} else if (!strcmp(this_char, "hash")) {
			hash_set = 1;
			if (value && !strcasecmp(value, "jenkins")) {
				icsb->data_hash.algorithm = HASH_JENKINS;
				icsb->meta_hash.algorithm = HASH_JENKINS;
			} else if (value && !strcasecmp(value, "fnv-1a")) {
				icsb->data_hash.algorithm = HASH_FNV_1A;
				icsb->meta_hash.algorithm = HASH_JENKINS;
			} else if (value && !strcasecmp(value, "modulo")) {
				icsb->data_hash.algorithm = HASH_MODULO;
				icsb->meta_hash.algorithm = HASH_JENKINS;
			}
		} else if (!strcmp(this_char, "data_hash")) {
			hash_set = 1;
			if (value && !strcasecmp(value, "jenkins")) {
				icsb->data_hash.algorithm = HASH_JENKINS;
			} else if (value && !strcasecmp(value, "fnv-1a")) {
				icsb->data_hash.algorithm = HASH_FNV_1A;
			} else if (value && !strcasecmp(value, "modulo")) {
				icsb->data_hash.algorithm = HASH_MODULO;
			}
		} else if (!strcmp(this_char, "meta_hash")) {
			hash_set = 1;
			if (value && !strcasecmp(value, "jenkins")) {
				icsb->meta_hash.algorithm = HASH_JENKINS;
			} else if (value && !strcasecmp(value, "fnv-1a")) {
				icsb->meta_hash.algorithm = HASH_FNV_1A;
			} else if (value && !strcasecmp(value, "modulo")) {
				icsb->meta_hash.algorithm = HASH_MODULO;
			}
		} else if (!strcmp(this_char, "nohash_on_nid")) {
			icsb->meta_hash.hash_on_nid = 0;
			icsb->data_hash.hash_on_nid = 0;
		} else if (!strcmp(this_char, "parallelwrite")) {
			icsb->parallel_write = 1;
		} else if (!strcmp(this_char, "noparallelwrite")) {
			icsb->parallel_write = 0;
		} else if (!strcmp(this_char, "dwfs")) {
			icsb->dwfs_flags |= DWFS_BIT;
		} else if (!strcmp(this_char, "nodwfs")) {
			icsb->dwfs_flags &= ~DWFS_BIT;
		} else if (!strcmp(this_char, "dwcfs")) {
			icsb->dwfs_flags |= DWCFS_BIT;
		} else if (!strcmp(this_char, "nodwcfs")) {
			icsb->dwfs_flags &= ~DWCFS_BIT;
		} else if (!strcmp(this_char, "multifsync")) {
			icsb->multi_fsync = 1;
		} else if (!strcmp(this_char, "nomultifsync")) {
			icsb->multi_fsync = 0;
		} else if (!strcmp(this_char, "cache")) {
			icsb->cache = 1;
		} else if (!strcmp(this_char, "nocache")) {
			icsb->cache = 0;
		} else if (!strcmp(this_char, "datasync")) {
			icsb->datasync = 1;
		} else if (!strcmp(this_char, "nodatasync")) {
			icsb->datasync = 0;
		} else if (!strcmp(this_char, "closesync")) {
			icsb->closesync = 1;
		} else if (!strcmp(this_char, "noclosesync")) {
			icsb->closesync = 0;
		} else if (!strcmp(this_char, "retry")) {
			icsb->retry = 1;
		} else if (!strcmp(this_char, "noretry")) {
			icsb->retry = 0;
		} else if (!strcmp(this_char, "failover")) {
			icsb->failover = 1;
		} else if (!strcmp(this_char, "nofailover")) {
			icsb->failover = 0;
		} else if (!strcmp(this_char, "userenv")) {
			icsb->userenv = 1;
		} else if (!strcmp(this_char, "nouserenv")) {
			icsb->userenv = 0;
		} else if (!strcmp(this_char, "clusterfs")) {
			icsb->clusterfs = 1;
		} else if (!strcmp(this_char, "noclusterfs")) {
			icsb->clusterfs = 0;
		} else if (!strcmp(this_char, "atomic")) {
			icsb->atomic = 1;
		} else if (!strcmp(this_char, "noatomic")) {
			icsb->atomic = 0;
		} else if (!strcmp(this_char, "loadbalance")) {
			/* hash_on_nid + no striping = loadbalance */
			icsb->clusterfs = 1;
			icsb->loadbalance = 1;
			icsb->data_stripe_width = 1;
			/* loadbalance means hash_on_nid now */
			icsb->data_hash.hash_on_nid = 1;
			icsb->data_hash.algorithm = HASH_MODULO;
			icsb->meta_hash.hash_on_nid = 1;
			icsb->meta_hash.algorithm = HASH_MODULO;
		} else if (!strcmp(this_char, "noloadbalance")) {
			icsb->loadbalance = 0;
		} else if (!strcmp(this_char, "killprocess")) {
			icsb->killprocess = 1;
		} else if (!strcmp(this_char, "nokillprocess")) {
			icsb->killprocess = 0;
		} else if (!strcmp(this_char, "maxnodes")) {
			icsb->data_stripe_width =
				simple_strtoul(value, NULL, 0);
		} else if (!strcmp(this_char, "open_file_on_meta")) {
			icsb->meta_stripe_width = 1;
		} else if (!strcmp(this_char, "metastripewidth")) {
			icsb->meta_stripe_width =
				simple_strtoul(value, NULL, 0);
		} else if (!strcmp(this_char, "deferopens")) {
			icsb->deferopens = 1;
		} else if (!strcmp(this_char, "nodeferopens")) {
			icsb->deferopens = 0;
		} else if (!strcmp(this_char, "distribute_create_ops")) {
			icsb->distribute_create_ops = 1;
		} else if (!strcmp(this_char, "no_distribute_create_ops")) {
			icsb->distribute_create_ops = 0;
		} else if (!strcmp(this_char, "ro_cache")) {
			icsb->ro_cache = 1;
		} else if (!strcmp(this_char, "no_ro_cache")) {
			icsb->ro_cache = 0;
		} else if (!strcmp(this_char, "ino_ignore_prefix_depth")) {
			icsb->ino_ignore_prefix_depth =
				simple_strtoul(value, NULL, 0);
		} else if (!strcmp(this_char, "cache_read_sz")) {
			if (!value || !*value) {
				printk(KERN_ERR "DVS: %s: bad cache_read_sz\n",
				       __func__);
				return 0;
			}
			icsb->cache_read_sz = simple_strtoul(value, NULL, 0);
			if (icsb->cache_read_sz < 0) {
				printk(KERN_ERR "DVS: %s: bad cache_read_sz\n",
				       __func__);
				return 0;
			}
		} else if (!strcmp(this_char, "magic")) {
			icsb->expected_magic = simple_strtoul(value, NULL, 0);
			if (icsb->expected_magic <= 0) {
				printk(KERN_ERR "DVS: %s: bad file system "
						"magic value 0x%lx\n",
				       __func__, icsb->expected_magic);
				return 0;
			}
		} else if (!strcmp(this_char, "nomagic")) {
			icsb->expected_magic = DEFAULT_MAGIC;
		} else if (!strcmp(this_char, "nnodes")) {
			/* This DVS-configured option is ignored as input. */
			printk(KERN_INFO "DVS: %s: nnodes %s ignored\n",
			       __func__, value);
		} else if (!strcmp(this_char, "statsfile")) {
			/* This DVS-configured option is ignored as input. */
			printk(KERN_INFO "DVS: %s: statsfile %s ignored\n",
			       __func__, value);
		} else {
			printk(KERN_ERR "DVS: %s: "
					"Unrecognized mount option %s\n",
			       __func__, this_char);
			return 0;
		}
	}

	if (icsb->loadbalance) {
		KDEBUG_PNC(0,
			   "DVS: %s: ignoring 'maxnodes' for loadbalance "
			   "file system\n",
			   __func__);
		icsb->data_stripe_width = 1;
	}

	/* Check combinations of options to ensure they make sense */

	if (icsb->data_stripe_width > icsb->data_servers_len) {
		printk(KERN_ERR "DVS: %s: maxnodes %d more than "
				"total nodes specified (%d)\n",
		       __func__, icsb->data_stripe_width,
		       icsb->data_servers_len);
		return 0;
	}

	if ((icsb->dwfs_flags & (DWFS_BIT | DWCFS_BIT))) {
		if (icsb->meta_stripe_width == 0)
			icsb->meta_stripe_width = 1;

		if (!icsb->deferopens) {
			printk(KERN_ERR
			       "DVS: %s: deferopens must be enabled when "
			       "using dwfs/dwcfs option\n",
			       __func__);
			return 0;
		}
	}

	if ((icsb->dwfs_flags & DWFS_BIT) && (icsb->dwfs_flags & DWCFS_BIT)) {
		printk(KERN_ERR "DVS: %s: Error: mount options dwfs and dwcfs "
				"cannot be used together\n",
		       __func__);
		return 0;
	}

	if (!icsb->retry && (icsb->failover || icsb->loadbalance)) {
		printk(KERN_ERR "DVS: %s: Cannot specify both failover and "
				"noretry\n",
		       __func__);
		return 0;
	}

	if (icsb->data_servers == NULL) {
		printk(KERN_ERR "DVS: %s: Node List is not "
				"initialized\n",
		       __func__);
		return 0;
	}

	if (icsb->meta_servers == NULL) {
		icsb->meta_servers = icsb->data_servers;
		icsb->meta_servers_len = icsb->data_servers_len;
	}

	if (icsb->data_servers == NULL || *icsb->prefix == '\0') {
		printk(KERN_ERR "DVS: %s: Not enough mount "
				"options\n",
		       __func__);
		return 0;
	}

	if (icsb->cache && !(*flags & MS_RDONLY)) {
		printk(KERN_ERR "DVS: %s: cache option being enabled"
				" on a writable mountpoint\n",
		       __func__);
	}

	/* Default is to include all nodes in the specified list */
	if (icsb->data_stripe_width == 0) {
		icsb->data_stripe_width = icsb->data_servers_len;
	}
	KDEBUG_PNC(0, "DVS: %s: data_stripe_width %d for mountpoint %s\n",
		   __func__, icsb->data_stripe_width, icsb->prefix);

	if (icsb->dwfs_flags & DWFS_BIT) {
		if (icsb->data_stripe_width > MAX_PFS_NODES) {
			printk(KERN_ERR "DVS: %s: maxnodes must be in the "
					"range [1, %d]\n",
			       __func__, MAX_PFS_NODES);
			return 0;
		}
	} else {
		if (icsb->data_stripe_width > ssiproc_max_nodes) {
			printk(KERN_ERR "DVS: %s: maxnodes must be in the "
					"range [1, %d]\n",
			       __func__, ssiproc_max_nodes);
			return 0;
		}
	}

	if (icsb->loadbalance == 1) {
		if (icsb->data_servers != icsb->meta_servers) {
			printk(KERN_ERR "DVS: loadbalance is not valid "
					"with separate metadata servers\n");
			return -EINVAL;
		}

		if (!icsb->failover) {
			printk("DVS: %s: forcing 'failover' for loadbalance "
			       "file system",
			       __func__);
			icsb->failover = 1;
		}

		icsb->clusterfs = 1;
		icsb->data_stripe_width = 1;
		icsb->cache = 1;
		if (icsb->data_hash.hash_on_nid ||
		    icsb->meta_hash.hash_on_nid) {
			printk("DVS: %s: forcing hash_on_nid off for "
			       "loadbalance",
			       __func__);
			icsb->data_hash.hash_on_nid = 0;
			icsb->meta_hash.hash_on_nid = 0;
		}
	}

	if (icsb->distribute_create_ops &&
	    (icsb->data_hash.hash_on_nid || icsb->meta_hash.hash_on_nid)) {
		printk("DVS: %s: forcing hash_on_nid off for "
		       "distribute_create_ops",
		       __func__);
		icsb->data_hash.hash_on_nid = 0;
		icsb->meta_hash.hash_on_nid = 0;
	}

	if (!icsb->clusterfs) {
		printk("DVS: %s: WARNING: unsupported option 'noclusterfs' in "
		       "use for mountpoint %s\n",
		       __func__, icsb->prefix);
		if (icsb->distribute_create_ops) {
			printk(KERN_ERR
			       "DVS: %s: ignoring 'distribute_create_ops'"
			       " for noclusterfs file system\n",
			       __func__);
			icsb->distribute_create_ops = 0;
		}
		if (icsb->data_hash.hash_on_nid ||
		    icsb->meta_hash.hash_on_nid) {
			printk(KERN_ERR "DVS: %s: ignoring 'hash_on_nid'"
					" for noclusterfs file system\n",
			       __func__);
			icsb->data_hash.hash_on_nid = 0;
			icsb->meta_hash.hash_on_nid = 0;
		}
	}

	return 1;
}

/*
 * See if all servers reported the same magic value.  Not necessary on mount
 * points with expected_magic set since verify_filesystem() checks in those
 * cases.
 */
static void verify_magic(struct incore_upfs_super_block *icsb)
{
	unsigned long magic = -1;
	struct dvs_server *snode = NULL;
	int i;

	if (icsb->expected_magic)
		return;

	for (i = 0; i < icsb->data_servers_len; i++) {
		snode = icsb->data_servers + i;

		if (magic == -1) {
			if (snode->magic != -1)
				magic = snode->magic;
			continue;
		}
		if (snode->magic != -1 && snode->magic != magic) {
			printk(KERN_ERR
			       "DVS: %s: different file system magic "
			       "values discovered across servers (magic 0x%lx "
			       "!= magic 0x%lx). Verify consistency of %s "
			       "across all servers.\n",
			       __func__, snode->magic, magic,
			       icsb->remoteprefix);
		}
	}

	for (i = 0; i < icsb->meta_servers_len; i++) {
		snode = icsb->meta_servers + i;

		if (magic == -1) {
			if (snode->magic != -1)
				magic = snode->magic;
			continue;
		}
		if (snode->magic != -1 && snode->magic != magic) {
			printk(KERN_ERR
			       "DVS: %s: different file system magic "
			       "values discovered across servers (magic 0x%lx "
			       "!= magic 0x%lx). Verify consistency of %s "
			       "across all servers.\n",
			       __func__, snode->magic, magic,
			       icsb->remoteprefix);
		}
	}
}

/*
 * Send RQ_VERIFYFS requests to the servers and validate the mount point
 * and magic value if possible.
 */
static int verify_filesystem(struct incore_upfs_super_block *icsb, int node,
			     unsigned long *magic, struct file_request *filerq,
			     int reqsz, struct file_reply *filerp, int repsz)
{
	int rval, allocated = 0;
	unsigned long elapsed_jiffies;

	if (!reqsz || !repsz) {
		allocated = 1;
		reqsz = sizeof(struct file_request) +
			strlen(icsb->remoteprefix) + 1;
		repsz = sizeof(struct file_reply);
		filerq = (struct file_request *)kmalloc_ssi(reqsz, GFP_KERNEL);
		filerp = (struct file_reply *)kmalloc_ssi(repsz, GFP_KERNEL);
		if (!filerq || !filerp) {
			rval = -ENOMEM;
			goto error;
		}

		filerq->request = RQ_VERIFYFS;
		filerq->u.verifyfsrq.flags = icsb->flags;
		filerq->u.verifyfsrq.hz = HZ;
		/*
		 * Copy mountpoint pathname into request for verification
		 * on servers.
		 */
		memcpy(filerq->u.verifyfsrq.pathname, icsb->remoteprefix,
		       strlen(icsb->remoteprefix) + 1);
		capture_context(&filerq->context);
		set_root_context(&filerq->context);
	}

	KDEBUG_PNC(0, "DVS: %s: sending RQ_VERIFYFS to node %s\n", __func__,
		   SSI_NODE_NAME(node));

	elapsed_jiffies = jiffies;
	rval = send_ipc_request_stats(icsb->stats, node, RQ_FILE, filerq, reqsz,
				      filerp, repsz, NO_IDENTITY);
	if (rval >= 0) {
		if (icsb->superblock && icsb->superblock->s_root) {
			log_request(filerq->request, icsb->remoteprefix,
				    icsb->superblock->s_root->d_inode, NULL, 1,
				    node, jiffies - elapsed_jiffies);
		} else {
			log_request(filerq->request, icsb->remoteprefix, NULL,
				    NULL, 1, node, jiffies - elapsed_jiffies);
		}
		if (filerp->rval < 0)
			rval = filerp->rval;
	}
	if (rval < 0) {
		printk(KERN_ERR
		       "DVS: %s: error %d encountered while "
		       "mounting %s from server %s to %s: excluding server. "
		       "Ensure directory exists and DVS is running on the "
		       "server\n",
		       __func__, rval, icsb->remoteprefix, SSI_NODE_NAME(node),
		       icsb->prefix);
		goto error;
	}

	if (icsb->expected_magic &&
	    (filerp->u.verifyfsrp.magic != icsb->expected_magic)) {
		printk(KERN_ERR
		       "DVS: %s: file system magic value 0x%lx "
		       "retrieved from server %s for %s does not match "
		       "expected value 0x%lx: excluding server. Ensure file "
		       "system is mounted on the server and then restart "
		       "DVS\n",
		       __func__, filerp->u.verifyfsrp.magic,
		       SSI_NODE_NAME(node), icsb->remoteprefix,
		       icsb->expected_magic);
		rval = -ENOENT;
	} else {
		sync_client_add_server(node, filerp->u.verifyfsrp.sync, icsb);
		*magic = filerp->u.verifyfsrp.magic;
	}

error:
	if (allocated) {
		kfree_ssi(filerp);
		kfree_ssi(filerq);
	}

	return rval;
}

static int file_uses_node(struct file *fp, int node)
{
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

static void reset_file_remote_orig_identities(struct file *fp, int node)
{
	int i;
	int len = FILE_PRIVATE(fp)->rf_len;
	struct remote_file *rf = FILE_PRIVATE(fp)->rf;

	for (i = 0; i < len; i++) {
		if (rf[i].remote_node_orig == node &&
		    rf[i].remote_node != node) {
			rf[i].identity = BOGUS_IDENTITY;
		}
	}
}

/*
 * React to a server loading DVS.  Don't break out of loops when a match of
 * the node is found, since nodes may be listed multiple times per mount.
 */
void file_node_up(int node)
{
	struct list_head *p;
	int super_blocks_affected = 0;

	DVS_TRACE("FNU", node, 0);
	KDEBUG_OFS(0, "DVS: %s: node %s\n", __func__, SSI_NODE_NAME(node));

	down(&dvs_super_blocks_sema);
	list_for_each (p, &dvs_super_blocks) {
		struct incore_upfs_super_block *icsb =
			list_entry(p, struct incore_upfs_super_block, list);
		struct open_file_info *finfo;
		int i, new_index, found = 0;
		unsigned long magic = -1;

		if (!icsb->loadbalance && !icsb->failover)
			continue;

		down_write(&failover_sema);
		/* search for recovered node in node list */
		for (i = 0; i < icsb->data_servers_len; i++) {
			if ((node != icsb->data_servers[i].node_map_index) ||
			    icsb->data_servers[i].up)
				continue;
			found++;
		}

		if (icsb->meta_servers != icsb->data_servers) {
			/* search for recovered node in node list */
			for (i = 0; i < icsb->meta_servers_len; i++) {
				if ((node !=
				     icsb->meta_servers[i].node_map_index) ||
				    icsb->meta_servers[i].up)
					continue;
				found++;
			}
		}

		if (found) {
			if (verify_filesystem(icsb, node, &magic, NULL, 0, NULL,
					      0)) {
				goto done;
			}

			for (i = 0; i < icsb->data_servers_len; i++) {
				if (icsb->data_servers[i].node_map_index ==
				    node) {
					icsb->data_servers[i].up = 1;
					icsb->data_servers[i].magic = magic;
				}
			}

			if (icsb->meta_servers != icsb->data_servers) {
				for (i = 0; i < icsb->meta_servers_len; i++) {
					if (icsb->meta_servers[i]
						    .node_map_index == node) {
						icsb->meta_servers[i].up = 1;
						icsb->meta_servers[i].magic =
							magic;
					}
				}
			}

			verify_magic(icsb);

			super_blocks_affected++;

			if (icsb->loadbalance && found) {
				icsb->loadbalance += found;

				new_index = usi_node_addr % icsb->loadbalance;
				icsb->loadbalance_node =
					loadbalance_index(icsb, new_index);
				KDEBUG_OFS(0,
					   "DVS: %s: loadbalance failback "
					   "recovered node %s\n",
					   __func__, SSI_NODE_NAME(node));
				goto done;
			}

			/* non-loadbalance failover configuration */
			spin_lock(&icsb->lock);
			list_for_each_entry (finfo, &icsb->open_files, list) {
				/*
				 * See if the now-alive server was in the
				 * original list of servers being used by
				 * the file when it was created.  If so, trash
				 * the file identity so the next I/O attempt to
				 * that file will fail at which point a new
				 * node will be picked based on the server node
				 * state(s) at that time.  If the file is in
				 * stripe parallel mode, clear all server
				 * identities (except for 'node') to ensure
				 * even striping across servers, etc.  We don't
				 * clear the identity for 'node' as we don't
				 * want RQ_CLOSE to be sent to the server as we
				 * know it was down.
				 */

				if (file_uses_node(finfo->fp, node)) {
					reset_file_remote_orig_identities(
						finfo->fp, node);
				}
			}
			spin_unlock(&icsb->lock);
		}
	done:
		up_write(&failover_sema);
	}
	up(&dvs_super_blocks_sema);

	if (super_blocks_affected) {
		printk(KERN_INFO "DVS: %s: adding %s back to list of available "
				 "servers for %d mount points\n",
		       __func__, SSI_NODE_NAME(node), super_blocks_affected);
	}
}

static int read_clustered_super(struct incore_upfs_super_block *icsb,
				int *flags, const char *dev_name)
{
	int i, rval, reqsz, repsz, index;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	int meta_nodes_succeeded = 0;
	int data_nodes_succeeded = 0;
	unsigned long magic = -1;

	reqsz = sizeof(struct file_request) + strlen(icsb->remoteprefix) + 1;
	repsz = sizeof(struct file_reply);
	filerq = (struct file_request *)kmalloc_ssi(reqsz, GFP_KERNEL);
	filerp = (struct file_reply *)kmalloc_ssi(repsz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto error;
	}

	filerq->request = RQ_VERIFYFS;
	filerq->u.verifyfsrq.flags = icsb->flags;
	filerq->u.verifyfsrq.hz = HZ;
	/* Copy mountpoint pathname into request for verification on servers */
	memcpy(filerq->u.verifyfsrq.pathname, icsb->remoteprefix,
	       strlen(icsb->remoteprefix) + 1);
	capture_context(&filerq->context);
	set_root_context(&filerq->context);

	rval = 0;

	/*
	 * Attempt to send an RQ_VERIFYFS message to icsb->meta_servers_len
	 * DVS metadata server nodes.  If we succeed in sending to at least
	 * icsb->maxnodes of them, then treat it as a success, otherwise fail.
	 * Mark each failed node as down in the node_up list.
	 */
	for (i = 0; i < icsb->meta_servers_len; i++) {
		RESET_FILERQ(filerq);
		rval = verify_filesystem(icsb,
					 icsb->meta_servers[i].node_map_index,
					 &magic, filerq, reqsz, filerp, repsz);
		if (rval < 0) {
			/* Take the bad node out of the list */
			icsb->meta_servers[i].up = 0;
			if (icsb->dwfs_flags & DWFS_BIT) {
				printk(KERN_ERR "DVS: %s: Datawarp mount failed"
						" from server %s\n",
				       icsb->prefix,
				       SSI_NODE_NAME(icsb->meta_servers[i]
							     .node_map_index));
				goto error;
			}

			continue;
		}

		if (meta_nodes_succeeded == 0)
			icsb->root_inode = filerp->u.verifyfsrp.inode_copy;

		icsb->meta_servers[i].magic = magic;
		meta_nodes_succeeded++;
	}

	if (icsb->data_servers == icsb->meta_servers) {
		data_nodes_succeeded = meta_nodes_succeeded;
	} else {
		/*
		 * Attempt to send an RQ_VERIFYFS message to
		 * icsb->data_servers_len DVS server nodes.  If we succeed in
		 * sending to at least icsb->maxnodes of them, then treat it as
		 * a success, otherwise fail. Mark each failed node as down in
		 * the node_up list.
		 */
		for (i = 0; i < icsb->data_servers_len; i++) {
			RESET_FILERQ(filerq);
			rval = verify_filesystem(
				icsb, icsb->data_servers[i].node_map_index,
				&magic, filerq, reqsz, filerp, repsz);
			if (rval < 0) {
				/* Take the bad node out of the list */
				icsb->data_servers[i].up = 0;
				if (icsb->dwfs_flags & DWFS_BIT) {
					printk(KERN_ERR
					       "DVS: %s: Datawarp mount failed"
					       " from server %s\n",
					       icsb->prefix,
					       SSI_NODE_NAME(
						       icsb->meta_servers[i]
							       .node_map_index));
					goto error;
				}

				continue;
			}

			icsb->data_servers[i].magic = magic;
			data_nodes_succeeded++;
		}
	}

	verify_magic(icsb);

	if ((magic == NFS_SUPER_MAGIC) && (icsb->data_stripe_width > 1)) {
		printk(KERN_ERR "DVS: %s: striping data across "
				"multiple DVS servers is not supported for "
				"NFS file systems (mount %s)\n",
		       __func__, icsb->prefix);
		rval = -EACCES;
		goto error;
	}

	if ((magic == NFS_SUPER_MAGIC) && (icsb->distribute_create_ops)) {
		printk(KERN_ERR
		       "DVS: %s: distributing create operations "
		       "is not supported for NFS files systems (mount %s), "
		       "removing distribute_create_ops option\n",
		       __func__, icsb->prefix);
		icsb->distribute_create_ops = 0;
	}

	if ((data_nodes_succeeded < icsb->data_stripe_width) &&
	    !icsb->failover) {
		printk(KERN_ERR
		       "DVS: %s: not enough servers (%d out of %d) "
		       "functioning properly to mount %s from servers to %s\n",
		       __func__, data_nodes_succeeded, icsb->data_stripe_width,
		       icsb->remoteprefix, icsb->prefix);
		rval = -ENXIO;
		goto error;
	}

	if ((meta_nodes_succeeded == 0 || data_nodes_succeeded == 0) &&
	    icsb->failover) {
		printk(KERN_ERR
		       "DVS: %s: no servers functioning properly. "
		       "Unable to mount %s from servers to %s.  Failover mode "
		       "requires at least one functioning server\n",
		       __func__, icsb->remoteprefix, icsb->prefix);
		rval = -ENXIO;
		goto error;
	}

	/* Reset rval in case the last node to be contacted failed */
	rval = 0;

	KDEBUG_PNC(0,
		   "DVS: %s: success sending RQ_VERIFYFS for path "
		   "local %s remote %s to %d meta nodes and %d data nodes\n",
		   __func__, icsb->prefix, icsb->remoteprefix,
		   meta_nodes_succeeded, data_nodes_succeeded);

	if (!icsb->failover)
		icsb->data_servers_len = data_nodes_succeeded;

	/*
	 * parse_options enforces that data servers and meta servers must
	 * be identical when using loadbalance.
	 */
	if (icsb->loadbalance) {
		/* select loadbalance node based on this node nid */
		index = usi_node_addr % data_nodes_succeeded;
		icsb->loadbalance_node = loadbalance_index(icsb, index);
		icsb->loadbalance = data_nodes_succeeded; /* for
							     failover/failback
							   */

		KDEBUG_PNC(0, "DVS: %s: loadbalance picked %s\n", __func__,
			   node_map[icsb->loadbalance_node].name);

		if (!(*flags & MS_RDONLY)) {
			printk("DVS: %s: forcing read-only for loadbalance "
			       "mount %s\n",
			       __func__, dev_name);
			*flags |= MS_RDONLY;
		}
	}

error:
	kfree_ssi(filerp);
	kfree_ssi(filerq);

	return rval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
const struct xattr_handler *dvs_xattr_handlers[];
#endif

static int upfs_fill_super(struct super_block *sb, void *p, int i)
{
	struct inode *root_inode = NULL;
	struct inode_info *pp;
	struct incore_upfs_super_block *icsb = p;

	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
	sb->s_magic = DVS_FTYPE_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &usi_super_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	sb->s_xattr = dvs_xattr_handlers;
#endif
	sb->s_d_op = &dops;

	root_inode = dvs_iget(sb, icsb->root_inode.i_ino, &icsb->root_inode);
	if (IS_ERR(root_inode)) {
		printk(KERN_ERR "DVS: %s: could not get root inode\n",
		       __func__);
		return PTR_ERR(root_inode);
	}

	pp = kmalloc_ssi(sizeof(struct inode_info), GFP_KERNEL);
	if (!pp) {
		iput(root_inode);
		return -ENOMEM;
	}

	init_rwsem(&pp->requests_sem);
	INIT_LIST_HEAD(&pp->requests);
	rwlock_init(&pp->estale_lock);

	init_rwsem(&pp->write_sem);
	sema_init(&pp->oio_sema, 1);
	spin_lock_init(&pp->lock);
	pp->underlying_magic = icsb->data_servers[0].magic;
	root_inode->i_private = pp;
	sb->s_root = d_make_root(root_inode);
	if (sb->s_root == NULL) {
		printk(KERN_ERR "DVS: %s: could not get root dentry\n",
		       __func__);
		kfree_ssi(pp);
		return -ENXIO;
	}

	KDEBUG_PNC(0, "DVS: %s: rootup: 0x%p rootdp: 0x%p %s %s\n", __func__,
		   root_inode, sb->s_root, sb->s_root->d_name.name,
		   sb->s_type->name);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 9) &&                           \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline int dvs_bdi_register(struct backing_dev_info *bdi)
{
	int rval;

	rval = bdi_setup_and_register(bdi, "dvs");
	if (rval) {
		printk(KERN_ERR "DVS: %s failed\n", __func__);
		return rval;
	}

	bdi->ra_pages = 512; /* 2Mb worth of pages readahead value */

	return 0;
}
#endif

static struct dentry *upfs_read_super(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *data)
{
	int rval = 0;
	struct super_block *s = NULL;
	struct incore_upfs_super_block *icsb;
	struct dentry *superd;

	icsb = kmalloc_ssi(sizeof(struct incore_upfs_super_block), GFP_KERNEL);
	if (!icsb) {
		rval = -ENOMEM;
		goto error;
	}
	icsb->bsz = DEFAULT_PFS_STRIPE_SIZE;
	icsb->parallel_write = DEFAULT_PARALLEL_WRITE;
	icsb->attrcache_timeout =
		seconds_to_jiffies(UPFS_ATTRCACHE_DEFAULT,
				   icsb->attrcache_timeout_str,
				   sizeof(icsb->attrcache_timeout_str));
	icsb->attrcache_revalidate_time = jiffies;
	icsb->f_type = DVS_FTYPE_MAGIC;
	icsb->cache = DEFAULT_CACHE;
	icsb->datasync = DEFAULT_DATASYNC;
	icsb->closesync = DEFAULT_CLOSESYNC;
	icsb->userenv = DEFAULT_USERENV;
	icsb->retry = DEFAULT_RETRY;
	icsb->failover = DEFAULT_FAILOVER;
	icsb->clusterfs = DEFAULT_CLUSTERED;
	icsb->killprocess = DEFAULT_KILLPROCESS;
	icsb->atomic = DEFAULT_ATOMIC;
	icsb->deferopens = DEFAULT_DEFEROPENS;
	icsb->expected_magic = DEFAULT_MAGIC;
	icsb->distribute_create_ops = DEFAULT_DISTRIBUTE_CREATE_OPS;
	icsb->ro_cache = DEFAULT_RO_CACHE;
	icsb->cache_read_sz = DEFAULT_CACHE_READ_SZ;
	icsb->multi_fsync = DEFAULT_MULTIFSYNC;
	icsb->dwfs_flags = DEFAULT_DWFS_FLAGS;
	icsb->flags = flags;
	icsb->data_hash.algorithm = HASH_FNV_1A;
	icsb->meta_hash.algorithm = HASH_FNV_1A;
	atomic_set(&icsb->open_dvs_files, 0);
	spin_lock_init(&icsb->lock);
	INIT_LIST_HEAD(&icsb->open_files);
	icsb->data_stripe_width = 0;
	icsb->meta_stripe_width = 0;
	icsb->data_servers = NULL;
	icsb->meta_servers = NULL;
	icsb->root_vfsmount = NULL;

	if (!dev_name || !*dev_name || strlen(dev_name) > (UPFS_MAXNAME - 1)) {
		printk(KERN_ERR "DVS: %s: DVS: Bad dev_name specified\n",
		       __func__);
		goto error;
	}

	strcpy(icsb->remoteprefix, dev_name);
	KDEBUG_PNC(0, "DVS: %s: remoteprefix %s\n", __func__, dev_name);

	rval = parse_options(data, icsb, &flags);
	if (rval == 0) {
		rval = -EINVAL;
		goto error;
	}

	rval = read_clustered_super(icsb, &flags, dev_name);
	if (rval)
		goto error;

	icsb->flags = flags;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 9) &&                           \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	rval = dvs_bdi_register(&icsb->dvs_bdi);
	if (rval)
		goto error;
#endif

	superd = mount_nodev(fs_type, flags, icsb, upfs_fill_super);
	if (IS_ERR(superd)) {
		printk(KERN_ERR "DVS: %s: mount_nodev returned "
				"error %ld\n",
		       __func__, PTR_ERR(superd));
		rval = PTR_ERR(superd);
		goto bdi_error;
	}
	s = superd->d_sb;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	rval = super_setup_bdi(s);
	if (rval)
		goto error;
#endif
	down(&dvs_super_blocks_sema);
	list_add_tail(&icsb->list, &dvs_super_blocks);
	up(&dvs_super_blocks_sema);

	s->s_fs_info = icsb;
	icsb->superblock = s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 9) &&                           \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	s->s_bdi = &icsb->dvs_bdi;
#endif

	/* add a mounts/X entry in the /proc/fs/dvs area */
	dvsproc_add_mountpoint(icsb);

	KDEBUG_PNC(0, "DVS: %s: icsb: %s %s %d\n", __func__, icsb->prefix,
		   icsb->remoteprefix, icsb->bsz);

	return superd;

bdi_error:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 9) &&                           \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	bdi_destroy(&icsb->dvs_bdi);
#endif

error:
	kfree_ssi(icsb);

	if (rval)
		return ERR_PTR(rval);
	else
		return ERR_PTR(-ENXIO);
}

/*
 * super_operations
 */

static int ushow_options(struct seq_file *m,
			 struct incore_upfs_super_block *icsb)
{
	if (icsb != NULL) {
		dvsproc_mount_options_print(m, icsb);
	}
	return 0;
}

static void uread_inode(struct inode *ip)
{
	KDEBUG_PNC(0, "DVS: %s: called for inode %ld\n", __func__, ip->i_ino);

	if (ip->i_sb->s_fs_info)
		dvsdebug_stat_update(INODE_ICSB(ip)->stats, DVSSYS_STAT_CREATE,
				     DVSSYS_STAT_TYPE_INODE, 1);

	if (ip->i_mode & S_IFDIR)
		ip->i_op = &iops_dir;
	else
		ip->i_op = &iops_file;

	ip->i_fop = &upfsfops;
	ip->i_mapping->a_ops = &upfsaops;

	ip->i_uid = KUIDT_INIT(0);
	ip->i_gid = KGIDT_INIT(0);

	inodes_read++;
	current_inodes++;
	if (current_inodes > max_inodes)
		max_inodes = current_inodes;
}

/*
 * Mitigation for the race described in
 *
 *    http://bugzilla.us.cray.com/show_bug.cgi?id=803263#c42
 *
 * Use iget5_locked() in dvs_iget(), with a test() callback that won't
 * allow an existing inode to be reused as one of another type.  This
 * means we may have multiple inodes with the same inum at the same
 * time.
 *
 * It doesn't address inum reuse by inodes of the same type.  We can't
 * deal with this for filesystems such as NFS that don't provide an
 * i_generation.
 *
 * We'll just use "ino" as the hash instead of calculating a hash
 * of <ino,i_mode> as there shouldn't be a difference in collision rate.
 */

/*
 * dvs_find_actor() - iget5_locked() test() callback.  Return 1 if
 * inode matches the inode described by opaque, with respect to inode
 * number and the S_IFMT bits in s_mode.
 */
static int dvs_find_actor(struct inode *inode, void *opaque)
{
	struct inode_info *iip = inode->i_private;
	struct inode_attrs *remote_attr = (struct inode_attrs *)opaque;

	if (inode->i_ino != remote_attr->i_ino)
		return 0;

	if ((inode->i_mode & S_IFMT) != (remote_attr->i_mode & S_IFMT))
		return 0;

	if (inode->i_generation != remote_attr->i_generation)
		return 0;

	/*
	 * This check filters out duplicate ino's from different server
	 * mount points. The mount_path_hash of 0 indicates that something
	 * went wrong on the server (likely a memory allocation) and so
	 * don't use the hash value.
	 */
	if (iip && iip->mount_path_hash && remote_attr->mount_path_hash &&
	    iip->mount_path_hash != remote_attr->mount_path_hash)
		return 0;

	return 1;
}

/*
 * dvs_init_locked() - iget5_locked() set() callback
 * Set up inode enough with attrs from server so that another
 * iget5_locked() with the same params will find it.
 */
static int dvs_init_locked(struct inode *inode, void *opaque)
{
	struct inode_attrs *remote_attr = (struct inode_attrs *)opaque;

	inode->i_mode = remote_attr->i_mode;
	inode->i_ino = remote_attr->i_ino;

	return 0;
}

static struct inode *dvs_iget(struct super_block *sb, unsigned long ino,
			      struct inode_attrs *remote_inode)
{
	struct inode *inode;

	inode = iget5_locked(sb, ino, dvs_find_actor, dvs_init_locked,
			     remote_inode);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
	uread_inode(inode);
	unlock_new_inode(inode);

	return inode;
}

static char *dvs_read_link_cache(struct inode *inode, int size)
{
	struct inode_info *iip;
	char *buf;

	iip = (struct inode_info *)inode->i_private;

	if (iip == NULL)
		return NULL;

	if (iip->link_cache == NULL)
		return NULL;

	if (dvs_attrcache_time_valid(iip->link_time, inode->i_sb) == 0)
		return NULL;

	buf = kmalloc_ssi(size + 1, GFP_KERNEL);
	if (buf == NULL)
		return NULL;

	spin_lock(&iip->link_lock);
	if (iip->link_cache == NULL)
		goto out_error;

	strncpy(buf, iip->link_cache, size);
	buf[size] = '\0';
	spin_unlock(&iip->link_lock);

	KDEBUG_PNC(0, "DVS: %s: Reading link cache for inode %p: %s\n",
		   __func__, inode, buf);

	return buf;

out_error:
	spin_unlock(&iip->link_lock);
	kfree_ssi(buf);

	return NULL;
}

static void dvs_update_link_cache(struct inode *inode, const char *link,
				  int size)
{
	struct inode_info *iip;
	char *cache;

	iip = (struct inode_info *)inode->i_private;
	cache = NULL;

	/* If attribute caching isn't enabled in the superblock then nothing
	 * needs to be done */
	if (INODE_ICSB(inode)->attrcache_timeout == 0)
		return;

	if (size == 0 || link == NULL)
		goto out;

	cache = kmalloc_ssi(size + 1, GFP_KERNEL);
	if (cache == NULL)
		goto out;

	strncpy(cache, link, size);
	cache[size] = '\0';

out:
	KDEBUG_PNC(0, "DVS: %s: setting link cache to %s for inode %p\n",
		   __func__, cache, inode);

	spin_lock(&iip->link_lock);
	kfree_ssi(iip->link_cache);
	iip->link_cache = cache;
	iip->link_time = jiffies;
	spin_unlock(&iip->link_lock);
}

static int ustatfs(struct dentry *dentry, struct kstatfs *buf)
{
	int rval, rsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode *ip = dentry->d_inode;
	struct inode_info *iip;
	char *path, *bufp = NULL;
	int bufsize;
	unsigned long elapsed_jiffies;

	bufsize = sizeof(struct statfs);

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
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

	KDEBUG_PNC(0, "DVS: %s: for %s\n", __func__, path);
	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	strcpy(filerq->u.statfsrq.pathname, path);
	filerq->request = RQ_STATFS;
	filerq->retry = INODE_ICSB(ip)->retry;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("ustatfs", ip, dentry, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	KDEBUG_PNC(0, "DVS: %s: %lu %lu %lu\n", __func__,
		   filerp->u.statfsrp.sbuf.f_blocks,
		   filerp->u.statfsrp.sbuf.f_bfree,
		   filerp->u.statfsrp.sbuf.f_bavail);
	memcpy(buf, &filerp->u.statfsrp.sbuf, bufsize);
	buf->f_type = INODE_ICSB(ip)->f_type;

	rval = 0;
done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

static void uclear_inode(struct inode *ip)
{
	struct inode_info *iip = ip->i_private;

	if (iip) {
		KDEBUG_PNC(0, "DVS: %s: called for 0x%p\n", __func__, ip);
		dvsdebug_stat_update(INODE_ICSB(ip)->stats, DVSSYS_STAT_DELETE,
				     DVSSYS_STAT_TYPE_INODE, 1);

		dvs_update_link_cache(ip, NULL, 0);

		if (!list_empty(&iip->requests)) {
			int rval = 1;
			cleanup_mode_t mode = CLUP_Passive;

			while (rval) {
				rval = cleanup_reqs(ip, mode);
				DVS_TRACEL("RPSUclr", ip, mode, rval, 0, 0);
				KDEBUG_PNC(
					0,
					"DVS: %s: cleanup requests %d 0x%p\n",
					__func__, rval, ip);

				if (rval) {
					mode = CLUP_Forced;
					cond_resched(); /* kill some time */
				}
			}
		}

		if (iip->estale_nodes)
			kfree_ssi(iip->estale_nodes);

		/* Check for any piggybacked open information. If it exists,
		 * that means we're stranding an open file on the server */
		if (iip->openrp) {
			spin_lock(&iip->lock);
			if (iip->openrp) {
				kfree_ssi(iip->openrp);
				iip->openrp = NULL;
			}
			spin_unlock(&iip->lock);
			printk("DVS: %s: Error: openrp information found on "
			       "inode %lu\n",
			       __func__, ip->i_ino);
		}

		kfree_ssi(iip);
		ip->i_private = NULL;
	}
	current_inodes--;
}

static void uevict_inode(struct inode *ip)
{
	truncate_inode_pages(&ip->i_data, 0);
	clear_inode(ip);
	uclear_inode(ip);
}

static void uput_super(struct super_block *s)
{
	struct list_head *p;
	struct incore_upfs_super_block *icsb;

	icsb = (struct incore_upfs_super_block *)s->s_fs_info;

	/* remove /proc entries for mountpoint stats */
	dvsproc_remove_mountpoint(icsb);

	down(&dvs_super_blocks_sema);
	list_for_each (p, &dvs_super_blocks) {
		struct incore_upfs_super_block *sbp =
			list_entry(p, struct incore_upfs_super_block, list);
		if (icsb == sbp) {
			list_del(&sbp->list);
			break;
		}
	}
	up(&dvs_super_blocks_sema);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 9) &&                           \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	bdi_destroy(&icsb->dvs_bdi);
#endif

	if (icsb->meta_servers != icsb->data_servers)
		kfree_ssi(icsb->meta_servers);
	kfree_ssi(icsb->data_servers);
	kfree_ssi(s->s_fs_info);
	KDEBUG_PNC(0, "DVS: %s: called\n", __func__);
}

static struct inode_info *build_inode_info(void)
{
	struct inode_info *pp;

	pp = kmalloc_ssi(sizeof(struct inode_info), GFP_KERNEL);
	if (!pp)
		return NULL;

	init_rwsem(&pp->requests_sem);
	INIT_LIST_HEAD(&pp->requests);
	rwlock_init(&pp->estale_lock);

	sema_init(&pp->oio_sema, 1);
	init_rwsem(&pp->write_sem);
	spin_lock_init(&pp->lock);
	spin_lock_init(&pp->link_lock);
	pp->cache_time = 0;
	pp->link_time = 0;

	atomic64_set(&pp->num_requests_open, 0L);
	pp->ii_create_jiffies = jiffies;

	/* initialize write caching tracking */
	atomic_set(&pp->dirty_pgs, 0);
	atomic64_set(&pp->i_cwc_files, 0);

	return (pp);
}

static struct inode *get_inode(char *path, struct inode_attrs *remote_inode,
			       struct super_block *sb, struct dentry *dep)
{
	struct inode *newip;
	struct inode_info *pp;
	int mode;

	KDEBUG_PNC(0, "DVS: %s: for %s\n", __func__, path);
	newip = dvs_iget(sb, remote_inode->i_ino, remote_inode);
	if (IS_ERR(newip)) {
		printk(KERN_ERR "DVS: %s: failed to get new inode %ld\n",
		       __func__, remote_inode->i_ino);
		return (NULL);
	}

	/* only initialize inode_info if one does not already exist */
	if (newip->i_private) {
		KDEBUG_PNC(0,
			   "DVS: %s: found already initialized "
			   "inode 0x%p %s\n",
			   __func__, newip, path);
	} else {
		pp = build_inode_info();
		if (pp == NULL) {
			printk(KERN_ERR "DVS: %s: failed to allocate inode "
					"info space\n",
			       __func__);
			iput(newip);
			return (NULL);
		}
		newip->i_private = pp;
	}

	update_inode(remote_inode, newip, dep, NULL, 0);
	dvs_update_link_cache(newip, NULL, 0);

	mode = newip->i_mode;
	if (S_ISBLK(mode) || S_ISCHR(mode) || S_ISFIFO(mode) ||
	    S_ISSOCK(mode)) {
		init_special_inode(newip, mode, newip->i_rdev);
		return (newip);
	}

	if (S_ISDIR(mode))
		newip->i_op = &iops_dir;
	else if (S_ISLNK(mode))
		newip->i_op = &iops_link;
	else
		newip->i_op = &iops_file;

	newip->i_fop = &upfsfops;
	newip->i_mapping->a_ops = &upfsaops;

	return (newip);
}

static int ucreate(struct inode *ip, struct dentry *dep, int mode, bool excl)
{
	struct inode *newip;
	struct inode_info *parentiip, *iip;
	int rval, rqsz, rpsz;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *path, *bufp = NULL;
	int nnodes, node;
	size_t node_offset;
	unsigned long elapsed_jiffies;

	KDEBUG_PNC(0, "DVS: %s: name:%s mode:%d\n", __func__, dep->d_name.name,
		   mode);

	parentiip = (struct inode_info *)ip->i_private;
	if (parentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
	}

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		return -EACCES;
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

	/*
	 * nnodes will only be > 0 if noclusterfs is specified, and that
	 * is intended for internal performance testing with RAM file
	 * systems only.  It is used here to send creates to all servers
	 * such that opens will work regardless of where they hash to
	 * (since the underlying file system is not a clusterfs).
	 */
	nnodes = 0;

	if (!INODE_ICSB(ip)->clusterfs)
		nnodes = INODE_ICSB(ip)->meta_servers_len;

	rpsz = sizeof(struct file_reply) + (2 * DWFS_PATH_LEN);
	rqsz = sizeof(struct file_request) + strlen(path) + 1;
	node_offset = rqsz;
	rqsz += sizeof(int) * nnodes;
	filerq = kmalloc_ssi(rqsz, GFP_KERNEL);
	filerp = kmalloc_ssi(rpsz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_CREATE;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->node_offset = node_offset;
	filerq->nnodes = nnodes;

	filerq->u.createrq.mode = mode;
	filerq->u.createrq.flags.o_creat = 1;
	if (excl)
		filerq->u.createrq.flags.o_excl = 1;

	/* This flag will only be passed to DWCFS */
	filerq->flags.is_dwcfs_stripe = (INODE_ICSB(ip)->data_stripe_width > 1);

	/* mode and flags from open */
	KDEBUG_OFS(0, "%s: create %s 0x%x 0x%x\n", __func__, path,
		   recompose_open_flags(&filerq->u.createrq.flags),
		   filerq->u.createrq.mode);

	/*
	 * See if we can piggyback the open request with the create.  We only
	 * do this for single server mount points, since we know that the
	 * create and open will target the same server.  LOOKUP_OPEN must be
	 * present: if it's not, this is likely a mknod/S_IFREG operation.
	 * Piggyback not allowed for ro_cache mode as an fp is needed but
	 * not yet known at create time.
	 */

	strcpy(filerq->u.createrq.pathname, path);
	rpsz = sizeof(struct file_reply) +
	       (2 * filerq->u.createrq.dwfs_path_len);
	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("ucreate", ip, dep, filerq, rqsz, filerp,
				    rpsz, &node);
	if (rval < 0)
		goto done;
	log_request(filerq->request, path, ip, NULL, nnodes, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server: %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	newip = get_inode(filerq->u.createrq.pathname,
			  &filerp->u.createrp.inode_copy, ip->i_sb, dep);
	if (newip == NULL) {
		printk(KERN_ERR "DVS: %s: could not get new inode\n", __func__);
		rval = -USIERR_INTERNAL;
		goto done;
	}

	/* Set the magic value for the underlying file system */
	iip = (struct inode_info *)newip->i_private;
	iip->underlying_magic = filerp->u.createrp.underlying_magic;

	/*
	 * If a create was done for an O_CREAT open, store the pid in the
	 * inode_info to allow that pid ( and only that pid ) to safely do a
	 * dentry_open instead of a normal filp_open on the server for uopen.
	 * dentry_open is crucial for when opening a file for exec and for
	 * proper POSIX semantics of writeability on first create.
	 */
	/*
	 * This is a temporary fix for Bug 820478 and 848690. This should
	 * really be fixed by the method described in 814167 which is to
	 * implement the atomic open which is what the intent/lookup flag was
	 * replaced by.
	 */
	iip->o_creat_pid = current->pid;

	/*
	 * If the server was able to do the open as well, stash the open
	 * file information into the inode_info structure for uopen() to use.
	 * We use a subset of the open_reply data (the magic value) to see
	 * if the open was successfully executed on the server.
	 */
	if (filerp->u.createrp.open_reply.rf.magic) {
		struct open_reply *openrp;

		iip = (struct inode_info *)newip->i_private;
		if (SUPER_DWFS(ip)) {
			openrp = kmalloc_ssi(
				sizeof(struct open_reply) +
					(2 * filerp->u.createrp.open_reply
						     .dwfs_info.path_len),
				GFP_KERNEL);
		} else {
			openrp = kmalloc_ssi(sizeof(struct open_reply),
					     GFP_KERNEL);
		}
		if (!openrp) {
			/* undo setup done by get_inode() */
			kfree_ssi(iip);
			iip = NULL;
			iput(newip);
			rval = -ENOMEM;
			goto done;
		}

		*openrp = filerp->u.createrp.open_reply;
		memcpy(openrp->dwfs_info.path,
		       filerp->u.createrp.open_reply.dwfs_info.path,
		       openrp->dwfs_info.path_len * 2);
		openrp->rf.identity = REMOTE_IDENTITY(&filerp->ipcmsg);
		openrp->rf.remote_node = SOURCE_NODE(&filerp->ipcmsg);
		openrp->rf.valid = 1;
		openrp->rf.quiesced = 0;
		iip->openrp = openrp;
	}

	d_instantiate(dep, newip);
	if (d_unhashed(dep))
		d_rehash(dep);

	KDEBUG_PNC(0, "DVS: %s: called ino: %ld ip: 0x%p dep: 0x%p path: %s\n",
		   __func__, newip->i_ino, newip, dep,
		   filerq->u.createrq.pathname);
	rval = 0;
done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	if (rval < 0)
		d_drop(dep);
	return (rval);
}

static struct dentry *ulookup(struct inode *ip, struct dentry *dep,
			      unsigned int flags)
{
	struct inode *newip;
	struct inode_info *parentiip;
	struct inode_info *newiip;
	struct dentry *new = NULL;
	long rval;
	int rsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *path, *bufp = NULL;
	unsigned long elapsed_jiffies;

	parentiip = (struct inode_info *)ip->i_private;
	if (parentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return ERR_PTR(-USIERR_INTERNAL);
	}

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		return ERR_PTR(-EACCES);
	}

	/*
	 * Performance optimization: if the lookup is being done for a create
	 * and the nd is for the last level of the path, we don't have to send
	 * the last RQ_LOOKUP to the server.  This is because RQ_CREATE will
	 * do its own lookup on the server before attempting the create.
	 */
	if ((flags & LOOKUP_CREATE) && (flags & LOOKUP_OPEN) &&
	    !(flags & (LOOKUP_FOLLOW | LOOKUP_PARENT))) {
		KDEBUG_PNC(0,
			   "DVS: %s: returning NULL dentry due to "
			   "imminent create, flags 0x%x\n",
			   __func__, flags);
		return NULL;
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

	/*
	 * Send lookup to server to get inode data
	 */
	rsz = sizeof(struct file_request) + strlen(path) + 1;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_LOOKUP;
	filerq->retry = INODE_ICSB(ip)->retry;
	strcpy(filerq->u.lookuprq.pathname, path);
	path = filerq->u.lookuprq.pathname;

	KDEBUG_PNC(0, "DVS: %s: path %s ip 0x%p\n", __func__, path, ip);

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("ulookup", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0)
		goto done;
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0,
			   "DVS: %s: got error from server %ld ip 0x%p "
			   "dep 0x%p path %s\n",
			   __func__, filerp->rval, ip, dep, path);
		rval = filerp->rval;
		goto done;
	}

	if (!filerp->u.lookuprp.inode_valid) {
		struct incore_upfs_super_block *icsb = ip->i_sb->s_fs_info;
		struct super_block *sb = icsb->superblock;

		/*
		 * Return w/o error, but with a NULL inode, for read-only
		 * mount points.  If no inode was found, update the dentry's
		 * d_time to ensure that additional lookups to the invalid
		 * path do not result in additional RQ_LOOKUP messages until
		 * the attribute timeout has expired.  If an inode was found
		 * but was not valid, don't touch d_time as we want to
		 * revalidate the inode ASAP.
		 */
		if (sb->s_flags & MS_RDONLY)
			d_add(dep, NULL);
		if (filerp->u.lookuprp.no_inode)
			dep->d_time = jiffies;
		KDEBUG_PNC(0,
			   "DVS: %s: called ino: %ld ip: 0x%p path: %s, "
			   "returning NO new inode\n",
			   __func__, ip->i_ino, ip, path);
		goto done;
	}

	newip = get_inode(path, &filerp->u.lookuprp.inode_copy, ip->i_sb, dep);

	if (newip == NULL) {
		printk(KERN_ERR "DVS: %s: could not get new inode\n", __func__);
		rval = -USIERR_INTERNAL;
		goto done;
	}

	newiip = (struct inode_info *)newip->i_private;
	if (newiip->underlying_magic == 0)
		newiip->underlying_magic = filerp->u.lookuprp.underlying_magic;
	newiip->check_xattrs = filerp->u.lookuprp.check_xattrs;
	if (newiip->check_xattrs) {
		KDEBUG_PNC(0, "DVS: %s: check xattrs for %s\n", __func__, path);
	}

	new = d_splice_alias(newip, dep);

	KDEBUG_PNC(0, "DVS: %s: called ino: %ld ip: 0x%p dep: 0x%p path: %s\n",
		   __func__, newip->i_ino, newip, dep, path);
	rval = filerp->rval;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	if (rval < 0)
		return ERR_PTR(rval);
	return new;
}

static int ulink(struct dentry *olddp, struct inode *newdip,
		 struct dentry *newdp)
{
	struct inode_info *oldparentiip, *newparentiip;
	int rval, rsz, orsz, nrsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode *newip;
	char *o_path, *o_bufp = NULL;
	char *n_path, *n_bufp = NULL;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(newdp->d_name.name)) {
		return -EACCES;
	}

	oldparentiip = (struct inode_info *)olddp->d_inode->i_private;
	if (oldparentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
	}
	newparentiip = (struct inode_info *)newdip->i_private;
	if (newparentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
	}

	d_drop(newdp);

	o_bufp = (char *)__get_free_page(GFP_KERNEL);
	n_bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!o_bufp || !n_bufp) {
		rval = -ENOMEM;
		goto done;
	}
	o_path = get_path(olddp, NULL, o_bufp, olddp->d_inode);
	if (IS_ERR(o_path)) {
		rval = PTR_ERR(o_path);
		goto done;
	}
	n_path = get_path(newdp, NULL, n_bufp, newdip);
	if (IS_ERR(n_path)) {
		rval = PTR_ERR(n_path);
		goto done;
	}

	/* setup request for the file itself */
	orsz = strlen(o_path) + 1;
	nrsz = strlen(n_path) + 1;
	rsz = sizeof(struct file_request) + orsz + nrsz;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_LINK;
	filerq->retry = INODE_ICSB(newdip)->retry;
	/* old path */
	strcpy(&filerq->u.linkrq.pathname[0], o_path);
	/* new path */
	strcpy(&filerq->u.linkrq.pathname[orsz], n_path);

	KDEBUG_PNC(0, "DVS: %s: %s %s\n", __func__,
		   &filerq->u.linkrq.pathname[0],
		   &filerq->u.linkrq.pathname[orsz]);
	filerq->u.linkrq.orsz = orsz;
	filerq->u.linkrq.nrsz = nrsz;
	filerq->u.linkrq.magic =
		INODE_PRIVATE(olddp->d_inode)->underlying_magic;

	/* check if oldpath needs to be revalidated */
	if ((INODE_PRIVATE(olddp->d_inode)->underlying_magic ==
	     NFS_SUPER_MAGIC) &&
	    (INODE_ICSB(olddp->d_inode)->meta_servers_len > 1)) {
		filerq->u.linkrq.invalidate_old =
			inode_meta_server(olddp->d_inode, 0);
	} else {
		filerq->u.linkrq.invalidate_old = -1;
	}

	elapsed_jiffies = jiffies;

	/* use old dentry pointer so we send the link request to the target */
	rval = send_ipc_inode_retry("ulink", newdip, olddp, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0)
		goto done;
	log_request(filerq->request, n_path, newdip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server: %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	KDEBUG_PNC(0, "DVS: %s: oldip: 0x%p newip: 0x%p\n", __func__,
		   olddp->d_inode, newdp->d_inode);
	newip = get_inode(&filerq->u.linkrq.pathname[orsz],
			  &filerp->u.linkrp.inode_copy, newdip->i_sb, newdp);
	if (newip == NULL) {
		printk(KERN_ERR "DVS: %s: could not get new inode\n", __func__);
		rval = -USIERR_INTERNAL;
		goto done;
	}
	d_instantiate(newdp, newip);

	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)o_bufp);
	free_page((unsigned long)n_bufp);
	return (rval);
}

static int uunlink(struct inode *ip, struct dentry *dep)
{
	struct inode_info *parentiip;
	int rval, rsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path;
	int nnodes;
	size_t node_offset;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		return -EACCES;
	}

	parentiip = (struct inode_info *)ip->i_private;
	if (parentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
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

	/*
	 * nnodes will only be > 0 if noclusterfs is specified, and that
	 * is intended for internal performance testing with RAM file
	 * systems only.  It is used here to send unlinks to all servers to
	 * clean up the corresponding creates that were sent to all servers.
	 */
	nnodes = 0;
	if (!INODE_ICSB(ip)->clusterfs)
		nnodes = INODE_ICSB(ip)->meta_servers_len;

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	node_offset = rsz;
	rsz += sizeof(int) * nnodes;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_UNLINK;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->node_offset = node_offset;
	filerq->nnodes = nnodes;
	strcpy(filerq->u.unlinkrq.pathname, path);
	path = filerq->u.unlinkrq.pathname;
	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("uunlink", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0) {
		goto done;
	}

	log_request(filerq->request, path, ip, NULL, nnodes, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval != 0) {
		rval = filerp->rval;
		KDEBUG_PNC(0, "DVS: %s: got error from server: %d\n", __func__,
			   rval);
		goto done;
	}

	update_inode(&filerp->u.unlinkrp.inode_copy, dep->d_inode, dep, NULL,
		     0);
	KDEBUG_PNC(0, "DVS: uunlink: called ip: 0x%p path: %s\n", dep->d_inode,
		   path);
	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

/*
 * usymlink:
 *	ip: inode of the parent directory
 *	dep: dentry (no associated inode yet) of the symbolic link itself
 *	oldname: the path of the target (they call it old but "existing"
 *                                       is a better name for it)
 */
static int usymlink(struct inode *ip, struct dentry *dep, const char *oldname)
{
	struct inode_info *newparentiip, *newiip;
	int rval, rsz, orsz, nrsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode *newip;
	char *bufp = NULL, *path;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		return -EACCES;
	}

	newparentiip = (struct inode_info *)ip->i_private;
	if (newparentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent inode has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
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

	nrsz = strlen(path) + 1;
	orsz = strlen(oldname) + 1;
	rsz = sizeof(struct file_request) + orsz + nrsz;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_SYMLINK;
	filerq->retry = INODE_ICSB(ip)->retry;
	/* old path */
	strcpy(&filerq->u.linkrq.pathname[0], oldname);
	/* new path */
	strcpy(&filerq->u.linkrq.pathname[orsz], path);
	KDEBUG_PNC(0, "DVS: %s: %s %s\n", __func__,
		   &filerq->u.linkrq.pathname[0],
		   &filerq->u.linkrq.pathname[orsz]);
	filerq->u.linkrq.orsz = orsz;
	filerq->u.linkrq.nrsz = nrsz;
	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("usymlink", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0)
		goto done;
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server: %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	newip = get_inode(&filerq->u.linkrq.pathname[orsz],
			  &filerp->u.linkrp.inode_copy, ip->i_sb, dep);
	if (newip == NULL) {
		printk(KERN_ERR "DVS: %s: could not get new inode\n", __func__);
		rval = -USIERR_INTERNAL;
		goto done;
	}

	if (!(newiip = (struct inode_info *)newip->i_private)) {
		printk(KERN_ERR "DVS: %s: link inode has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
	}

	/* We can always set the link cache here since the parent mutex is held
	 * during by the caller of vfs_symlink() so it can't have changed out
	 * from under us. */
	dvs_update_link_cache(newip, oldname, orsz);

	d_instantiate(dep, newip);
	KDEBUG_PNC(0, "DVS: %s: %s 0x%x\n", __func__,
		   &filerq->u.linkrq.pathname[orsz], newip->i_mode);
	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	if (rval < 0)
		d_drop(dep);
	return (rval);
}

static int umkdir(struct inode *ip, struct dentry *dep, umode_t mode)
{
	struct inode_info *parentiip;
	int rval, rsz;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode *newip;
	char *bufp = NULL, *path;
	int nnodes, node;
	size_t node_offset;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		return -EACCES;
	}

	parentiip = (struct inode_info *)ip->i_private;
	if (parentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
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

	/*
	 * nnodes will only be > 0 if noclusterfs is specified, and that
	 * is intended for internal performance testing with RAM file
	 * systems only.  It is used here to send mkdirs to all servers
	 * such that opens will work regardless of where they hash to
	 * (since the underlying file system is not a clusterfs).
	 */
	nnodes = 0;
	if (!INODE_ICSB(ip)->clusterfs)
		nnodes = INODE_ICSB(ip)->meta_servers_len;

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	node_offset = rsz;
	rsz += sizeof(int) * nnodes;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_MKDIR;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->u.mkdirrq.mode = mode;
	filerq->node_offset = node_offset;
	filerq->nnodes = nnodes;
	strcpy(filerq->u.mkdirrq.pathname, path);

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("umkdir", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0)
		goto done;
	log_request(filerq->request, path, ip, NULL, nnodes, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server: %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	newip = get_inode(filerq->u.mkdirrq.pathname,
			  &filerp->u.mkdirrp.inode_copy, ip->i_sb, dep);
	if (newip == NULL) {
		printk(KERN_ERR "DVS: %s: could not get new inode\n", __func__);
		rval = -USIERR_INTERNAL;
		goto done;
	}
	d_instantiate(dep, newip);

	KDEBUG_PNC(0, "DVS: %s: called ip: 0x%p path: %s\n", __func__,
		   dep->d_inode, filerq->u.mkdirrq.pathname);
	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	if (rval < 0)
		d_drop(dep);
	return (rval);
}

static int urmdir(struct inode *ip, struct dentry *dep)
{
	struct inode_info *parentiip;
	int rval, rsz;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *bufp = NULL, *path;
	int nnodes, node;
	size_t node_offset;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(dep->d_name.name)) {
		return -EACCES;
	}

	parentiip = (struct inode_info *)ip->i_private;
	if (parentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
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

	/*
	 * nnodes will only be > 0 if noclusterfs is specified, and that
	 * is intended for internal performance testing with RAM file
	 * systems only.  It is used here to send rmdirs to all servers to
	 * clean up the corresponding mkdirs that were sent to all servers.
	 */
	nnodes = 0;
	if (!INODE_ICSB(ip)->clusterfs)
		nnodes = INODE_ICSB(ip)->meta_servers_len;

	rsz = sizeof(struct file_request) + strlen(path) + 1;
	node_offset = rsz;
	rsz += sizeof(int) * nnodes;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_RMDIR;
	filerq->retry = INODE_ICSB(ip)->retry;
	filerq->node_offset = node_offset;
	filerq->nnodes = nnodes;
	strcpy(filerq->u.rmdirrq.pathname, path);
	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("urmdir", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, nnodes, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server: %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	update_inode(&filerp->u.rmdirrp.inode_copy, dep->d_inode, dep, NULL, 0);
	KDEBUG_PNC(0, "DVS: %s: called ip: 0x%p path: %s\n", __func__,
		   dep->d_inode, filerq->u.rmdirrq.pathname);
	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	return (rval);
}

static int umknod(struct inode *ip, struct dentry *dep, umode_t mode, dev_t dev)
{
	struct inode_info *parentiip;
	int rval, rsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode *newip;
	char *bufp = NULL, *path;
	unsigned long elapsed_jiffies;

	parentiip = (struct inode_info *)ip->i_private;
	if (parentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
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
	filerq->request = RQ_MKNOD;
	strcpy(filerq->u.mknodrq.pathname, path);
	filerq->u.mknodrq.mode = mode;
	filerq->u.mknodrq.dev = dev;
	capture_context((&filerq->context));
	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("umknod", ip, dep, filerq, rsz, filerp,
				    sizeof(struct file_reply), &node);

	if (rval < 0) {
		printk(KERN_ERR "DVS: %s: ipc call failed %d\n", __func__,
		       rval);
		goto done;
	}
	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	newip = get_inode(filerq->u.mknodrq.pathname,
			  &filerp->u.mknodrp.inode_copy, ip->i_sb, dep);
	if (newip == NULL) {
		printk(KERN_ERR "DVS: %s: could not get new inode\n", __func__);
		rval = -USIERR_INTERNAL;
		goto done;
	}
	d_instantiate(dep, newip);
	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);
	if (rval < 0)
		d_drop(dep);
	return (rval);
}

static int urename(struct inode *olddip, struct dentry *oldddp,
		   struct inode *newdip, struct dentry *newddp)
{
	struct inode_info *oldparentiip, *newparentiip;
	int rval, rsz, orsz, nrsz, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *o_path, *o_bufp = NULL;
	char *n_path, *n_bufp = NULL;
	unsigned long elapsed_jiffies;

	if (SUPERBLOCK_NAME(newddp->d_name.name)) {
		return -EACCES;
	}

	oldparentiip = (struct inode_info *)olddip->i_private;
	if (oldparentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
	}
	newparentiip = (struct inode_info *)newdip->i_private;
	if (newparentiip == NULL) {
		printk(KERN_ERR "DVS: %s: parent has no inode info\n",
		       __func__);
		return -USIERR_INTERNAL;
	}

	o_bufp = (char *)__get_free_page(GFP_KERNEL);
	n_bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!o_bufp || !n_bufp) {
		rval = -ENOMEM;
		goto done;
	}
	o_path = get_path(oldddp, NULL, o_bufp, olddip);
	if (IS_ERR(o_path)) {
		rval = PTR_ERR(o_path);
		goto done;
	}
	n_path = get_path(newddp, NULL, n_bufp, newdip);
	if (IS_ERR(n_path)) {
		rval = PTR_ERR(n_path);
		goto done;
	}

	orsz = strlen(o_path) + 1;
	nrsz = strlen(n_path) + 1;
	rsz = sizeof(struct file_request) + orsz + nrsz;
	filerq = kmalloc_ssi(rsz, GFP_KERNEL);
	filerp = kmalloc_ssi(sizeof(struct file_reply), GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}
	filerq->request = RQ_RENAME;
	filerq->retry = INODE_ICSB(newdip)->retry;
	/* old path */
	strcpy(&filerq->u.linkrq.pathname[0], o_path);
	/* new path */
	strcpy(&filerq->u.linkrq.pathname[orsz], n_path);
	KDEBUG_PNC(0, "DVS: %s: %s %s\n", __func__,
		   &filerq->u.linkrq.pathname[0],
		   &filerq->u.linkrq.pathname[orsz]);
	filerq->u.linkrq.orsz = orsz;
	filerq->u.linkrq.nrsz = nrsz;

	/*
	 * We're sending the rename to the old server so no need to invalidate
	 * it. Use a negative number to indicate that it's not a valid server
	 * nid.
	 */
	filerq->u.linkrq.invalidate_old = -1;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("urename", olddip, oldddp, filerq, rsz,
				    filerp, sizeof(struct file_reply), &node);
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, n_path, newdip, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	if (filerp->rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server %ld\n", __func__,
			   filerp->rval);
		rval = filerp->rval;
		goto done;
	}

	KDEBUG_PNC(0, "DVS: %s: ddp inodes: (0x%p 0x%p)  (0x%p 0x%p)\n",
		   __func__, olddip, oldddp->d_inode, newdip, newddp->d_inode);

	if (newddp->d_inode) {
		update_inode(&filerp->u.linkrp.inode_copy, newddp->d_inode,
			     newddp, NULL, 0);
	}

	spin_lock(&newddp->d_lock);
	if (!d_unhashed(newddp))
		__d_drop(newddp);
	spin_unlock(&newddp->d_lock);
	rval = 0;

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)o_bufp);
	free_page((unsigned long)n_bufp);
	return (rval);
}

#define DVS_READLINK_SIZE 512
static int ureadlink(struct dentry *dep, char *buf, int bufsize)
{
	int rval, rqsz, rpsz, rq_bufsize, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	struct inode_info *iip;
	char *bufp = NULL, *path, *link_cache = NULL;
	unsigned long elapsed_jiffies;

	iip = (struct inode_info *)dep->d_inode->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: %s: inode has no inode info\n", __func__);
		return -USIERR_INTERNAL;
	}

	/*
	 * If the link cache is within the attribute timeout and has the link
	 * cached, use that link target instead of sending a server request
	 */
	link_cache = dvs_read_link_cache(dep->d_inode, bufsize);
	if (link_cache != NULL) {
		rval = strlen(link_cache);
		if (copy_to_user(buf, link_cache, rval) != 0)
			rval = -EFAULT;

		kfree_ssi(link_cache);

		return rval;
	}

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}
	path = get_path(dep, NULL, bufp, dep->d_inode);
	if (IS_ERR(path)) {
		rval = PTR_ERR(path);
		goto done;
	}

	/* Use a larger buffer than asked for to try to get the full link
	 * on the first attempt if we're going to cache the result. */
	if (bufsize < DVS_READLINK_SIZE &&
	    SUPER_ICSB(dep->d_sb)->attrcache_timeout)
		rq_bufsize = DVS_READLINK_SIZE;
	else
		rq_bufsize = bufsize;

	KDEBUG_PNC(0, "DVS: %s: %s bufsize: %d rq_bufsize %d\n", __func__, path,
		   bufsize, rq_bufsize);
	rqsz = sizeof(struct file_request) + strlen(path) + 1;
	rpsz = sizeof(struct file_reply) + rq_bufsize + 1;

	/* bufsize isn't limited, so check that the reply won't be too large to
	 * send back */
	if (rpsz > MAX_MSG_SIZE) {
		rq_bufsize = MAX_MSG_SIZE - (sizeof(struct file_reply) + 1);
		printk("DVS: %s: buffer size %d is too large for network. "
		       "Trying truncated length %d\n",
		       __func__, bufsize, rq_bufsize);
		rpsz = MAX_MSG_SIZE;
	}

	filerq = kmalloc_ssi(rqsz, GFP_KERNEL);
	filerp = kmalloc_ssi(rpsz, GFP_KERNEL);
	if (!filerq || !filerp) {
		rval = -ENOMEM;
		goto done;
	}

	filerq->request = RQ_READLINK;
	filerq->retry = INODE_ICSB(dep->d_inode)->retry;
	strcpy(&filerq->u.readlinkrq.pathname[0], path);
	filerq->u.readlinkrq.bufsize = rq_bufsize;

	elapsed_jiffies = jiffies;
	rval = send_ipc_inode_retry("ureadlink", dep->d_inode, dep, filerq,
				    rqsz, filerp, rpsz, &node);
	if (rval < 0) {
		goto done;
	}
	log_request(filerq->request, path, dep->d_inode, NULL, 1, node,
		    jiffies - elapsed_jiffies);
	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: got error from server %d\n", __func__,
			   rval);
		goto done;
	}

	/* If we had to truncate the buffer, check if it was large enough to
	 * hold the link */
	if (bufsize > rq_bufsize && filerp->rval >= rq_bufsize) {
		printk("DVS: %s: truncated buffer length %d was not large "
		       "enough for requested length %d\n",
		       __func__, rq_bufsize, bufsize);
		rval = -EPROTO;
		goto done;
	}

	filerp->u.readlinkrp.pathname[rval] = '\0';
	KDEBUG_PNC(0, "DVS: %s: returning: %s\n", __func__,
		   filerp->u.readlinkrp.pathname);

	if (copy_to_user(buf, filerp->u.readlinkrp.pathname,
			 rval > bufsize ? bufsize : rval)) {
		rval = -EFAULT;
		goto done;
	}

	/* Don't cache the link name if we didn't get all of it */
	if (filerp->rval >= rq_bufsize) {
		KDEBUG_PNC(0,
			   "DVS: %s: not caching partial link %s. User "
			   "buffer size: %d DVS buffer size: %d\n",
			   __func__, filerp->u.readlinkrp.pathname, bufsize,
			   rq_bufsize);
		goto done;
	}

	dvs_update_link_cache(dep->d_inode, filerp->u.readlinkrp.pathname,
			      rval);

done:
	kfree_ssi(filerp);
	kfree_ssi(filerq);
	free_page((unsigned long)bufp);

	return rval;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
static void *ufollow(struct dentry *dentry, struct nameidata *nd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static const char *ufollow(struct dentry *dentry, void **cookie)
#else
static void uputlink_l_stats(void *cookie);
static const char *ufollow(struct dentry *dentry, struct inode *inode,
			   struct delayed_call *delayed_call)
#endif
{
	char *buf;
	int rval;
	mm_segment_t oldfs;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	/* Struct to hold our inode and buf pointers to pass
	   to uputlink_l_stats */
	struct readlink_data *holder = NULL;

	if (!dentry)
		return ERR_PTR(-ECHILD);
#endif

	buf = kmalloc_ssi(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		rval = -ENOMEM;
		goto error;
	}

	KDEBUG_PNC(0, "DVS: %s:%s 0x%x\n", __func__, dentry->d_name.name,
		   dentry->d_inode->i_mode);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	rval = ureadlink(dentry, buf, PATH_MAX);
	set_fs(oldfs);

	if ((long)rval < 0) {
		KDEBUG_PNC(0, "DVS: %s: readlink failed %d\n", __func__, rval);
		kfree_ssi(buf);
		goto error;
	}
	if (rval < PATH_MAX)
		buf[rval] = 0;
	KDEBUG_PNC(0, "DVS: %s: link: %s\n", __func__, buf);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	nd_set_link(nd, buf);
	return buf;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	return *cookie = buf;
#else
	holder = kmalloc_ssi(sizeof(struct readlink_data), GFP_KERNEL);
	if (!holder) {
		rval = -ENOMEM;
		kfree_ssi(buf);
		goto error;
	}
	holder->inode = inode;
	holder->buf = buf;
	set_delayed_call(delayed_call, uputlink_l_stats, holder);
	return buf;
#endif

error:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	nd_set_link(nd, (ERR_PTR(rval)));
	return NULL;
#else
	return ERR_PTR(rval);
#endif
}

/*
 * For link inode_operation put_link.  This function is called by the kernel
 * to free 'buf' allocated in ufollow once the kernel is done working with
 * the returned link path.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
static void uputlink(struct dentry *dentry, struct nameidata *nd, void *cookie)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static void uputlink(struct inode *unused, void *cookie)
#else
static void uputlink(void *cookie)
#endif
{
	if (cookie) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
		struct readlink_data *ibuf = cookie;
		if (ibuf->buf)
			kfree_ssi(ibuf->buf);
#endif
		kfree_ssi(cookie);
	}
}

/*
 * Permission checks are most often performed on the DVS server as part of
 * open and lookup operations.  There are some exceptions however (e.g.
 * the use of dentry_open() in do_usifile() for certain RQ_OPEN requests).
 * To be on the safe side, perform a local permission check as well using
 * generic_permission().
 *
 * In addition, extended attributes may exist for the inode.  To reduce
 * unnecessary permission requests, the existence of xattrs is piggybacked
 * on RQ_LOOKUP replies and stored in the inode_info structure.  If the
 * inode may have extended attributes, a RQ_PERMISSION request is sent
 * to the DVS server in place of the local generic_permission() check to
 * ensure xattrs are taken into account.
 */
static int upermission(struct inode *ip, int mask)
{
	struct inode_info *iip;
	int rsz, rval = 0, node;
	struct file_request *filerq = NULL;
	struct file_reply *filerp = NULL;
	char *path, *bufp = NULL;
	struct dentry *dep;
	unsigned long elapsed_jiffies;

	if (mask & MAY_NOT_BLOCK) {
		return -ECHILD;
	}

	iip = (struct inode_info *)ip->i_private;
	if (iip == NULL) {
		printk(KERN_ERR "DVS: %s: no inode info\n", __func__);
		return -USIERR_INTERNAL;
	}

	if (!iip->check_xattrs &&
	    dvs_attrcache_time_valid(iip->cache_time, ip->i_sb)) {
		KDEBUG_PNC(0, "DVS: %s: call generic_permission for ip 0x%p\n",
			   __func__, ip);
		return generic_permission(ip, mask);
	}

	/* xattrs might exist - send permission check to the server */

	bufp = (char *)__get_free_page(GFP_KERNEL);
	if (!bufp) {
		rval = -ENOMEM;
		goto done;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	dep = container_of(ip->i_dentry.first, struct dentry, d_alias);
#else
	dep = container_of(ip->i_dentry.first, struct dentry, d_u.d_alias);
#endif

	if (SUPERBLOCK_NAME(dep->d_name.name))
		goto done;

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
	filerq->request = RQ_PERMISSION;
	filerq->retry = INODE_ICSB(ip)->retry;
	strcpy(filerq->u.permissionrq.pathname, path);
	filerq->u.permissionrq.mask = mask;
	filerq->u.permissionrq.ino = ip->i_ino;
	filerq->flags.ignore_ino_check = ignore_ino_mismatch(dep, ip);

	KDEBUG_PNC(0, "DVS: %s: sending RQ_PERMISSION for path %s ip 0x%p\n",
		   __func__, path, ip);

	elapsed_jiffies = jiffies;
	rval = (long)send_ipc_inode_retry("upermission", ip, dep, filerq, rsz,
					  filerp, sizeof(struct file_reply),
					  &node);
	if (rval < 0)
		goto done;

	log_request(filerq->request, path, ip, NULL, 1, node,
		    jiffies - elapsed_jiffies);

	rval = filerp->rval;
	if (rval < 0) {
		KDEBUG_PNC(0,
			   "DVS: %s: got error from server %d ip 0x%p dep 0x%p "
			   "path %s\n",
			   __func__, rval, ip, dep, path);
	} else {
		update_inode(&filerp->u.permissionrp.inode_copy, ip, NULL, NULL,
			     0);
	}

done:
	kfree_ssi(filerq);
	kfree_ssi(filerp);
	free_page((unsigned long)bufp);

	return rval;
}

static int ustatfs_stats(struct dentry *dentry, struct kstatfs *buf)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ustatfs(dentry, buf);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_STATFS, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_STATFS,
			     elapsed_jiffies);

	return ret;
}

static void uput_super_stats(struct super_block *s)
{
	unsigned long elapsed_jiffies = jiffies;

	/*
	 * Always succeeds.
	 * Track success in global stats buffers since the mount is going away
	 */
	uput_super(s);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(NULL, DVSSYS_STAT_OPER, VFS_OP_PUT_SUPER, 0);
	dvsdebug_stat_update(NULL, DVSSYS_STAT_OPER_TIME, VFS_OP_PUT_SUPER,
			     elapsed_jiffies);
}

static void uevict_inode_stats(struct inode *ip)
{
	unsigned long elapsed_jiffies = jiffies;

	/*
	 * Always succeeds
	 */
	uevict_inode(ip);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(INODE_ICSB(ip)->stats, DVSSYS_STAT_OPER,
			     VFS_OP_EVICT_INODE, 0);
	dvsdebug_stat_update(INODE_ICSB(ip)->stats, DVSSYS_STAT_OPER_TIME,
			     VFS_OP_EVICT_INODE, elapsed_jiffies);
}

static int ushow_options_stats(struct seq_file *m, struct dentry *dep)
{
	struct incore_upfs_super_block *icsb = dep->d_sb->s_fs_info;
	int ret;
	struct dvsdebug_stat *stats;
	unsigned long elapsed_jiffies = jiffies;

	if (icsb) {
		stats = icsb->stats;
	} else {
		stats = NULL;
	}
	ret = ushow_options(m, icsb);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_SHOW_OPTIONS, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_SHOW_OPTIONS,
			     elapsed_jiffies);

	return ret;
}

/*
 * Directory operation wrappers
 */
static int ucreate_d_stats(struct inode *ip, struct dentry *dep, umode_t mode,
			   bool excl)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ucreate(ip, dep, mode, excl);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_CREATE, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_CREATE,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_CREATE, DVSSYS_STAT_TYPE_FILE,
			     1);

	return ret;
}

static struct dentry *ulookup_d_stats(struct inode *ip, struct dentry *dep,
				      unsigned int flags)
{
	struct dentry *ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ulookup(ip, dep, flags);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_LOOKUP,
			     IS_ERR(ret) ? -1 : 0);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_LOOKUP,
			     elapsed_jiffies);

	return ret;
}

static int ulink_d_stats(struct dentry *olddp, struct inode *newdip,
			 struct dentry *newdp)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(newdip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ulink(olddp, newdip, newdp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_LINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_LINK,
			     elapsed_jiffies);

	return ret;
}

static int uunlink_d_stats(struct inode *ip, struct dentry *dep)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;
	int tag;

	// The ip->i_mode is not what we want to look at
	tag = (S_ISLNK(dep->d_inode->i_mode)) ? DVSSYS_STAT_TYPE_SYMLINK :
						DVSSYS_STAT_TYPE_FILE;

	ret = uunlink(ip, dep);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_UNLINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_UNLINK,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_DELETE, tag, 1);

	return ret;
}

static int usymlink_d_stats(struct inode *ip, struct dentry *dep,
			    const char *oldname)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usymlink(ip, dep, oldname);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_SYMLINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_SYMLINK,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_CREATE,
			     DVSSYS_STAT_TYPE_SYMLINK, 1);

	return ret;
}

static int umkdir_d_stats(struct inode *ip, struct dentry *dep, umode_t mode)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = umkdir(ip, dep, mode);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_MKDIR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_MKDIR,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_CREATE,
			     DVSSYS_STAT_TYPE_DIRECTORY, 1);

	return ret;
}

static int urmdir_d_stats(struct inode *ip, struct dentry *dep)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = urmdir(ip, dep);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_RMDIR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_RMDIR,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_DELETE,
			     DVSSYS_STAT_TYPE_DIRECTORY, 1);

	return ret;
}

static int umknod_d_stats(struct inode *ip, struct dentry *dep, umode_t mode,
			  dev_t dev)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = umknod(ip, dep, mode, dev);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_MKNOD, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_MKNOD,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static int urename_d_stats(struct inode *olddip, struct dentry *oldddp,
			   struct inode *newdip, struct dentry *newddp)
#else
static int urename_d_stats(struct inode *olddip, struct dentry *oldddp,
			   struct inode *newdip, struct dentry *newddp,
			   unsigned int flags)
#endif
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(olddip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = urename(olddip, oldddp, newdip, newddp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_RENAME, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_RENAME,
			     elapsed_jiffies);

	return ret;
}

static int upermission_d_stats(struct inode *ip, int mask)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = upermission(ip, mask);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_PERMISSION, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_PERMISSION,
			     elapsed_jiffies);

	return ret;
}

static int usetattr_d_stats(struct dentry *dep, struct iattr *iattrp)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usetattr(dep, iattrp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_SETATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_SETATTR,
			     elapsed_jiffies);

	return ret;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
ugetattr_d_stats(const struct path *path, struct kstat *kstatp,
		 u32 request_mask, unsigned int flags)
#else
ugetattr_d_stats(struct vfsmount *mnt, struct dentry *dep, struct kstat *kstatp)
#endif
{
	int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct vfsmount *mnt = path->mnt;
	struct dentry *dep = path->dentry;
#endif
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ugetattr(mnt, dep, kstatp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_GETATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_GETATTR,
			     elapsed_jiffies);

	return ret;
}

static int usetxattr_d_stats(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags,
			     const char *prefix, size_t prefix_len)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usetxattr(dentry, name, value, size, flags, prefix, prefix_len);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_SETXATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_SETXATTR,
			     elapsed_jiffies);

	return ret;
}

static ssize_t ugetxattr_d_stats(struct dentry *dentry, const char *name,
				 void *value, size_t size, const char *prefix,
				 size_t prefix_len)
{
	ssize_t ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ugetxattr(dentry, name, value, size, prefix, prefix_len);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_GETXATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_GETXATTR,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static int usetxattr_d_wrapper(struct dentry *dentry, const char *name,
			       const void *value, size_t size, int flags)
{
	return usetxattr_d_stats(dentry, name, value, size, flags, NULL, 0);
}

static ssize_t ugetxattr_d_wrapper(struct dentry *dentry, const char *name,
				   void *value, size_t size)
{
	return ugetxattr_d_stats(dentry, name, value, size, NULL, 0);
}
#endif

static ssize_t ulistxattr_d_stats(struct dentry *dentry, char *list,
				  size_t size)
{
	ssize_t ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ulistxattr(dentry, list, size);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_LISTXATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_LISTXATTR,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static int uremovexattr_d_stats(struct dentry *dentry, const char *name)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = uremovexattr(dentry, name);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_REMOVEXATTR,
			     ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_REMOVEXATTR,
			     elapsed_jiffies);

	return ret;
}
#endif

/*
 * File operation wrappers
 */
static int ucreate_f_stats(struct inode *ip, struct dentry *dep, umode_t mode,
			   bool excl)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ucreate(ip, dep, mode, excl);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_CREATE, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_CREATE,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_CREATE, DVSSYS_STAT_TYPE_FILE,
			     1);

	return ret;
}

static int ulink_f_stats(struct dentry *olddp, struct inode *newdip,
			 struct dentry *newdp)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(newdip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ulink(olddp, newdip, newdp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_LINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_LINK,
			     elapsed_jiffies);

	return ret;
}

static int uunlink_f_stats(struct inode *ip, struct dentry *dep)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;
	int tag;

	// The ip->i_mode is not what we want to look at
	tag = (S_ISLNK(dep->d_inode->i_mode)) ? DVSSYS_STAT_TYPE_SYMLINK :
						DVSSYS_STAT_TYPE_FILE;

	ret = uunlink(ip, dep);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_UNLINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_UNLINK,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_DELETE, tag, 1);

	return ret;
}

static int usymlink_f_stats(struct inode *ip, struct dentry *dep,
			    const char *oldname)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usymlink(ip, dep, oldname);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_SYMLINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_SYMLINK,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_CREATE,
			     DVSSYS_STAT_TYPE_SYMLINK, 1);

	return ret;
}

static int umkdir_f_stats(struct inode *ip, struct dentry *dep, umode_t mode)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = umkdir(ip, dep, mode);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_MKDIR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_MKDIR,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_CREATE,
			     DVSSYS_STAT_TYPE_DIRECTORY, 1);

	return ret;
}

static int urmdir_f_stats(struct inode *ip, struct dentry *dep)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = urmdir(ip, dep);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_RMDIR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_RMDIR,
			     elapsed_jiffies);
	dvsdebug_stat_update(stats, DVSSYS_STAT_DELETE,
			     DVSSYS_STAT_TYPE_DIRECTORY, 1);

	return ret;
}

static int umknod_f_stats(struct inode *ip, struct dentry *dep, umode_t mode,
			  dev_t dev)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = umknod(ip, dep, mode, dev);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_MKNOD, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_MKNOD,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static int urename_f_stats(struct inode *olddip, struct dentry *oldddp,
			   struct inode *newdip, struct dentry *newddp)
#else
static int urename_f_stats(struct inode *olddip, struct dentry *oldddp,
			   struct inode *newdip, struct dentry *newddp,
			   unsigned int flags)
#endif
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(olddip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = urename(olddip, oldddp, newdip, newddp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_RENAME, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_RENAME,
			     elapsed_jiffies);

	return ret;
}

static int upermission_f_stats(struct inode *ip, int mask)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(ip)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = upermission(ip, mask);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_PERMISSION, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_PERMISSION,
			     elapsed_jiffies);

	return ret;
}

static int usetattr_f_stats(struct dentry *dep, struct iattr *iattrp)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usetattr(dep, iattrp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_SETATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_SETATTR,
			     elapsed_jiffies);

	return ret;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
ugetattr_f_stats(const struct path *path, struct kstat *kstatp,
		 u32 request_mask, unsigned int flags)
#else
ugetattr_f_stats(struct vfsmount *mnt, struct dentry *dep, struct kstat *kstatp)
#endif
{
	int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct vfsmount *mnt = path->mnt;
	struct dentry *dep = path->dentry;
#endif
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ugetattr(mnt, dep, kstatp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_GETATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_GETATTR,
			     elapsed_jiffies);

	return ret;
}

static int usetxattr_f_stats(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags,
			     const char *prefix, size_t prefix_len)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usetxattr(dentry, name, value, size, flags, prefix, prefix_len);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_SETXATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_SETXATTR,
			     elapsed_jiffies);

	return ret;
}

static ssize_t ugetxattr_f_stats(struct dentry *dentry, const char *name,
				 void *value, size_t size, const char *prefix,
				 size_t prefix_len)
{
	ssize_t ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ugetxattr(dentry, name, value, size, prefix, prefix_len);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_GETXATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_GETXATTR,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static int usetxattr_f_wrapper(struct dentry *dentry, const char *name,
			       const void *value, size_t size, int flags)
{
	return usetxattr_f_stats(dentry, name, value, size, flags, NULL, 0);
}

static ssize_t ugetxattr_f_wrapper(struct dentry *dentry, const char *name,
				   void *value, size_t size)
{
	return ugetxattr_f_stats(dentry, name, value, size, NULL, 0);
}
#endif

static ssize_t ulistxattr_f_stats(struct dentry *dentry, char *list,
				  size_t size)
{
	ssize_t ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ulistxattr(dentry, list, size);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_LISTXATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_LISTXATTR,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static int uremovexattr_f_stats(struct dentry *dentry, const char *name)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = uremovexattr(dentry, name);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_F_REMOVEXATTR,
			     ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_F_REMOVEXATTR,
			     elapsed_jiffies);

	return ret;
}
#else
static int dvs_xattr_get(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, void *buffer, size_t size)
{
	int ret;

	if (!dentry) { /* can't sleep in rcu mode */
		ret = -ECHILD;
		goto out;
	}

	if (S_ISREG(inode->i_mode)) {
		ret = ugetxattr_f_stats(dentry, name, buffer, size,
					handler->prefix,
					strlen(handler->prefix));
	} else if (S_ISDIR(inode->i_mode)) {
		ret = ugetxattr_d_stats(dentry, name, buffer, size,
					handler->prefix,
					strlen(handler->prefix));
	} else {
		ret = -EOPNOTSUPP;
	}

out:
	return ret;
}

static int dvs_xattr_set(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, const void *buffer, size_t size,
			 int flags)
{
	int ret;

	if (!dentry) { /* can't sleep in rcu mode */
		ret = -ECHILD;
		goto out;
	}

	if (S_ISREG(inode->i_mode)) {
		ret = usetxattr_f_stats(dentry, name, buffer, size, flags,
					handler->prefix,
					strlen(handler->prefix));
	} else if (S_ISDIR(inode->i_mode)) {
		ret = usetxattr_d_stats(dentry, name, buffer, size, flags,
					handler->prefix,
					strlen(handler->prefix));
	} else {
		ret = -EOPNOTSUPP;
	}

out:
	return ret;
}

/*
 * The meaning of .flags in xattr_handler is filesystem private.
 */
enum dvs_xattr_flags {
	XATTR_FLAG_USER,
	XATTR_FLAG_TRUSTED,
	XATTR_FLAG_SECURITY,
	XATTR_FLAG_POSIX_ACL_ACCESS,
	XATTR_FLAG_POSIX_ACL_DEFAULT,
};

static const struct xattr_handler dvs_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.flags = XATTR_FLAG_USER,
	.get = dvs_xattr_get,
	.set = dvs_xattr_set,
};
static const struct xattr_handler dvs_xattr_trusted_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.flags = XATTR_FLAG_TRUSTED,
	.get = dvs_xattr_get,
	.set = dvs_xattr_set,
};
static const struct xattr_handler dvs_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.flags = XATTR_FLAG_SECURITY,
	.get = dvs_xattr_get,
	.set = dvs_xattr_set,
};
#ifdef CONFIG_FS_POSIX_ACL
static const struct xattr_handler dvs_acl_access_xattr_handler = {
	.prefix = XATTR_NAME_POSIX_ACL_ACCESS,
	.flags = XATTR_FLAG_POSIX_ACL_ACCESS,
	.get = dvs_xattr_get,
	.set = dvs_xattr_set,
};
static const struct xattr_handler dvs_acl_default_xattr_handler = {
	.prefix = XATTR_NAME_POSIX_ACL_DEFAULT,
	.flags = XATTR_FLAG_POSIX_ACL_DEFAULT,
	.get = dvs_xattr_get,
	.set = dvs_xattr_set,
};
#endif

const struct xattr_handler *dvs_xattr_handlers[] = {
	&dvs_xattr_user_handler,
	&dvs_xattr_trusted_handler,
	&dvs_xattr_security_handler,
#ifdef CONFIG_FS_POSIX_ACL
	&dvs_acl_access_xattr_handler,
	&dvs_acl_default_xattr_handler,
#endif
	NULL,
};
#endif

/*
 * Link operation wrappers
 */
static int ureadlink_l_stats(struct dentry *dep, char *buf, int bufsize)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ureadlink(dep, buf, bufsize);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_L_READLINK, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_L_READLINK,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
static void *ufollow_l_stats(struct dentry *dentry, struct nameidata *nd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static const char *ufollow_l_stats(struct dentry *dentry, void **cookie)
#else
static const char *ugetlink_l_stats(struct dentry *dentry, struct inode *inode,
				    struct delayed_call *delayed_call)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	void *ret;
#else
	const char *ret;
#endif
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	if (!dentry) /* get_link in RCU mode */
		return ERR_PTR(-ECHILD);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	ret = ufollow(dentry, nd);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	ret = ufollow(dentry, cookie);
#else
	ret = ufollow(dentry, inode, delayed_call);
#endif
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_L_FOLLOW_LINK,
			     ret ? 0 : -1);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_L_FOLLOW_LINK,
			     elapsed_jiffies);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
static void uputlink_l_stats(struct dentry *dentry, struct nameidata *nd,
			     void *cookie)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static void uputlink_l_stats(struct inode *inode, void *cookie)
#else
static void uputlink_l_stats(void *cookie)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct readlink_data *ibuf = cookie;
	struct inode *inode = ibuf->inode;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	struct dvsdebug_stat *stats = INODE_ICSB(dentry->d_inode)->stats;
#else
	struct dvsdebug_stat *stats = INODE_ICSB(inode)->stats;
#endif
	unsigned long elapsed_jiffies = jiffies;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 9)
	uputlink(dentry, nd, cookie);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	uputlink(inode, cookie);
#else
	uputlink(cookie);
#endif
	elapsed_jiffies = jiffies - elapsed_jiffies;
	/*
	 * Always succeeds
	 */
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_L_PUT_LINK, 0);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_L_PUT_LINK,
			     elapsed_jiffies);
	return;
}

static int usetattr_l_stats(struct dentry *dep, struct iattr *iattrp)
{
	int ret;
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = usetattr(dep, iattrp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_L_SETATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_L_SETATTR,
			     elapsed_jiffies);

	return ret;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
ugetattr_l_stats(const struct path *path, struct kstat *kstatp, u32 query_mask,
		 unsigned int flags)
#else
ugetattr_l_stats(struct vfsmount *mnt, struct dentry *dep, struct kstat *kstatp)
#endif
{
	int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct vfsmount *mnt = path->mnt;
	struct dentry *dep = path->dentry;
#endif
	struct dvsdebug_stat *stats = INODE_ICSB(dep->d_inode)->stats;
	unsigned long elapsed_jiffies = jiffies;

	ret = ugetattr(mnt, dep, kstatp);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_L_GETATTR, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_L_GETATTR,
			     elapsed_jiffies);

	return ret;
}

/*
 * dentry operations wrapper(s)
 */
static int urevalidate_stats(struct dentry *dentry, unsigned int flags)
{
	int ret;
	struct inode *ip = dentry->d_inode;
	struct dvsdebug_stat *stats = ip ? INODE_ICSB(ip)->stats : NULL;
	unsigned long elapsed_jiffies = jiffies;

	ret = urevalidate(dentry, flags);
	elapsed_jiffies = jiffies - elapsed_jiffies;
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER, VFS_OP_D_REVALIDATE, ret);
	dvsdebug_stat_update(stats, DVSSYS_STAT_OPER_TIME, VFS_OP_D_REVALIDATE,
			     elapsed_jiffies);

	return ret;
}

static struct super_operations usi_super_ops = {
	.statfs = ustatfs_stats,
	.put_super = uput_super_stats,
	.evict_inode = uevict_inode_stats,
	.show_options = ushow_options_stats,
};

static struct inode_operations iops_dir = {
	.create = ucreate_d_stats,
	.lookup = ulookup_d_stats,
	.link = ulink_d_stats,
	.unlink = uunlink_d_stats,
	.symlink = usymlink_d_stats,
	.mkdir = umkdir_d_stats,
	.rmdir = urmdir_d_stats,
	.mknod = umknod_d_stats,
	.rename = urename_d_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
/*.readlink		= ureadlink,*/
/*.follow_link		= ufollow,*/
#else
	.readlink = ureadlink,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	.follow_link = ufollow,
#else
	.get_link = ufollow,
#endif

#endif
	.permission = upermission_d_stats,
	.setattr = usetattr_d_stats,
	.getattr = ugetattr_d_stats,
	.listxattr = ulistxattr_d_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	.setxattr = usetxattr_d_wrapper,
	.getxattr = ugetxattr_d_wrapper,
	.removexattr = uremovexattr_d_stats,
#endif
};
static struct inode_operations iops_file = {
	.create = ucreate_f_stats,
	.link = ulink_f_stats,
	.unlink = uunlink_f_stats,
	.symlink = usymlink_f_stats,
	.mkdir = umkdir_f_stats,
	.rmdir = urmdir_f_stats,
	.mknod = umknod_f_stats,
	.rename = urename_f_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
/*.readlink		= ureadlink,*/
/*.follow_link		= ufollow,*/
#else
	.readlink = ureadlink,
/*.follow_link		= ufollow,*/
#endif
	.permission = upermission_f_stats,
	.setattr = usetattr_f_stats,
	.getattr = ugetattr_f_stats,
	.listxattr = ulistxattr_f_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	.setxattr = usetxattr_f_wrapper,
	.getxattr = ugetxattr_f_wrapper,
	.removexattr = uremovexattr_f_stats,
#endif
};

static struct inode_operations iops_link = {
	.readlink = ureadlink_l_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	.follow_link = ufollow_l_stats,
	.put_link = uputlink_l_stats,
#else
	.get_link = ugetlink_l_stats,
#endif
	.setattr = usetattr_l_stats,
	.getattr = ugetattr_l_stats,
};

static struct dentry_operations dops = {
	.d_revalidate = urevalidate_stats,
};
