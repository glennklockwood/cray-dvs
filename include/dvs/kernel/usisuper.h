/*
 * $Id:
 */

/*
 * Unpublished Work / 2004 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006-2007, 2010-2017 Cray Inc. All Rights Reserved.
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

#ifndef KERNEL_USISUPER_H
#define KERNEL_USISUPER_H

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file kernel/usisuper.h"
#endif /* __KERNEL__ */

#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6, 5)
#include <linux/uidgid.h>
#endif
#else
#include <linux/uidgid.h>
#endif
#include <linux/backing-dev.h>
#include "common/dvsproc_stat.h"
#include "dvs/usisuper.h"

#define kdev_t unsigned long

struct dvs_server {
	int node_map_index;
	int up;
	unsigned long magic;
};

struct hash_info {
	int hash_on_nid;
	int algorithm;
};

struct inode_attrs {
	unsigned long i_ino;
	struct super_block *i_sb;
	umode_t i_mode;
	struct timespec i_mtime;
	struct timespec i_atime;
	struct timespec i_ctime;
	kuid_t i_uid;
	kgid_t i_gid;
	kdev_t i_dev;
	nlink_t i_nlink;
	loff_t i_size;
	kdev_t i_rdev;
	unsigned long i_blocks;
	unsigned long i_version;
	__u32 i_generation;
	unsigned int i_flags;
	uint64_t mount_path_hash;
};

struct incore_upfs_super_block {
	struct list_head list;
	uint64_t cookie;
	struct inode_attrs root_inode;
	int bsz;
	unsigned long attrcache_timeout; /* Value in jiffies */
	char attrcache_timeout_str[12];
	unsigned long attrcache_revalidate_time; /* Time in jiffies
			      when the cache was last dropped */
	long f_type;
	short cache;
	short datasync;
	short closesync;
	short failover;
	int multi_fsync;
	int retry;
	int userenv;
	int clusterfs;
	int atomic;
	int loadbalance;
	int killprocess;
	int deferopens;
	int distribute_create_ops;
	int ro_cache;
	unsigned int cache_read_sz;
	struct super_block *superblock;
	struct dvsdebug_stat *stats;
	char prefix[UPFS_MAXNAME];
	char remoteprefix[UPFS_MAXNAME];
	unsigned long expected_magic;
	int loadbalance_node;
	atomic_t open_dvs_files;
	spinlock_t lock;
	struct list_head open_files;
	int flags;
	int sync_flags;
	unsigned int dwfs_flags;
	int parallel_write;
	int ino_ignore_prefix_depth;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 9)
	struct backing_dev_info dvs_bdi;
#endif
	/* Servers to target with metadata ops */
	struct dvs_server *meta_servers;
	int meta_servers_len;
	int meta_stripe_width;
	struct hash_info meta_hash;
	/* Servers to target for IO/file ops */
	struct dvs_server *data_servers;
	int data_servers_len;
	int data_stripe_width;
	struct hash_info data_hash;
	struct vfsmount	*root_vfsmount;
};

extern struct semaphore dvs_super_blocks_sema;
extern struct list_head dvs_super_blocks;
extern struct rw_semaphore failover_sema;

#endif /* KERNEL_USISUPER_H */
