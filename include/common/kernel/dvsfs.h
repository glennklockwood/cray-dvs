/*
 * Copyright 2016-2017 Cray Inc. All Rights Reserved.
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

#ifndef DVSFS_H
#define DVSFS_H

#include "common/kernel/hash_table.h"
#include "common/kernel/ssi_util_init.h"

extern ht_t *ro_cache_table;
extern ht_t *inode_op_table;

extern struct semaphore ro_cache_sem;

extern long inodes_read;
extern long current_inodes;
extern long max_inodes;
extern long mmap_pages_read;
extern long revalidates_done;
extern long revalidates_skipped;

extern struct semaphore iotsem;
extern struct semaphore *aretrysem;
extern struct list_head *alist;

extern int dvsof_concurrent_reads;
extern unsigned int dvsof_concurrent_reads_count;
extern struct semaphore dvsof_concurrent_reads_sema;

extern int dvsof_concurrent_writes;
extern unsigned int dvsof_concurrent_writes_count;
extern struct semaphore dvsof_concurrent_writes_sema;

extern struct file_operations upfsfops;
extern struct address_space_operations upfsaops;

extern int async_op_retry(void *);
#endif
