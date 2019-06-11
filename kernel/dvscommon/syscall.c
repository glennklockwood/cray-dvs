/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2011, 2013, 2017 Cray Inc. All Rights Reserved.
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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <asm/uaccess.h>
#ifdef CONFIG_ARM64
/* Pull in deprecated system call definitions */
#define __ARCH_WANT_SYSCALL_NO_AT
#define __ARCH_WANT_SYSCALL_DEPRECATED
#endif
#include <asm/unistd.h>
#include <linux/resource.h>
#include <linux/statfs.h>
#include <linux/dirent.h>
#include "common/kernel/usiipc.h"

#undef USISYSCALL_H
#define extern
#include "common/kernel/usisyscall.h"
#undef extern

typedef void (*sys_call_ptr_t)(void);

int initialize_syscall_linkage(void)
{
	sys_call_ptr_t *ptr_sys_call_table;

	if ((ptr_sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(
		     "sys_call_table")) == NULL)
		return -1;

	p_sys_alarm = (void *)ptr_sys_call_table[__NR_alarm];
	p_sys_close = (void *)ptr_sys_call_table[__NR_close];
	p_sys_exit = (void *)ptr_sys_call_table[__NR_exit];
	p_sys_read = (void *)ptr_sys_call_table[__NR_read];
	p_sys_select = (void *)ptr_sys_call_table[__NR_select];
	p_sys_open = (void *)ptr_sys_call_table[__NR_open];
	p_sys_creat = (void *)ptr_sys_call_table[__NR_creat];
	p_sys_write = (void *)ptr_sys_call_table[__NR_write];
	p_sys_pwrite64 = (void *)ptr_sys_call_table[__NR_pwrite64];
	p_sys_pread64 = (void *)ptr_sys_call_table[__NR_pread64];
	p_sys_getdents64 = (void *)ptr_sys_call_table[__NR_getdents64];
	p_sys_unlink = (void *)ptr_sys_call_table[__NR_unlink];
	p_sys_lseek = (void *)ptr_sys_call_table[__NR_lseek];
	p_sys_ioctl = (void *)ptr_sys_call_table[__NR_ioctl];
	p_sys_fsync = (void *)ptr_sys_call_table[__NR_fsync];
	p_sys_fdatasync = (void *)ptr_sys_call_table[__NR_fdatasync];
	p_sys_readv = (void *)ptr_sys_call_table[__NR_readv];
	p_sys_writev = (void *)ptr_sys_call_table[__NR_writev];
	p_sys_link = (void *)ptr_sys_call_table[__NR_link];
	p_sys_symlink = (void *)ptr_sys_call_table[__NR_symlink];
	p_sys_mkdir = (void *)ptr_sys_call_table[__NR_mkdir];
	p_sys_rmdir = (void *)ptr_sys_call_table[__NR_rmdir];
	p_sys_mknod = (void *)ptr_sys_call_table[__NR_mknod];
	p_sys_chmod = (void *)ptr_sys_call_table[__NR_chmod];
	p_sys_rename = (void *)ptr_sys_call_table[__NR_rename];
	p_sys_readlink = (void *)ptr_sys_call_table[__NR_readlink];
	p_sys_truncate = (void *)ptr_sys_call_table[__NR_truncate];
	p_sys_ftruncate = (void *)ptr_sys_call_table[__NR_ftruncate];
	p_sys_fcntl = (void *)ptr_sys_call_table[__NR_fcntl];
	p_sys_stat = (void *)ptr_sys_call_table[__NR_stat];
	p_sys_statfs = (void *)ptr_sys_call_table[__NR_statfs];
	p_sys_chdir = (void *)ptr_sys_call_table[__NR_chdir];
	p_sys_wait4 = (void *)ptr_sys_call_table[__NR_wait4];
	p_sys_getcwd = (void *)ptr_sys_call_table[__NR_getcwd];
	p_sys_mmap = (void *)ptr_sys_call_table[__NR_mmap];
	p_sys_munmap = (void *)ptr_sys_call_table[__NR_munmap];
	p_sys_getrusage = (void *)ptr_sys_call_table[__NR_getrusage];
	p_sys_setxattr = (void *)ptr_sys_call_table[__NR_setxattr];
	p_sys_getxattr = (void *)ptr_sys_call_table[__NR_getxattr];
	p_sys_listxattr = (void *)ptr_sys_call_table[__NR_listxattr];
	p_sys_removexattr = (void *)ptr_sys_call_table[__NR_removexattr];
	p_sys_fadvise64 = (void *)ptr_sys_call_table[__NR_fadvise64];
	p_sys_readahead = (void *)ptr_sys_call_table[__NR_readahead];
	p_sys_sync = (void *)ptr_sys_call_table[__NR_sync];

	return 0;
}
