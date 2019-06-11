/*
 * Copyright 2006-2008, 2010-2011, 2013 Cray Inc. All Rights Reserved.
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

#ifndef USISYSCALL_H
#define USISYSCALL_H

#include <linux/statfs.h>
#include <linux/version.h>

extern unsigned long (*p_sys_alarm)(unsigned int seconds);

extern long (*p_sys_close)(unsigned int fd);

#define __NR__exit __NR_exit
extern long (*p_sys_exit)(int status);

extern ssize_t (*p_sys_read)(unsigned int fd, char *buf, size_t count);

extern long (*p_sys_select)(int n, fd_set *readfds, fd_set *writefds,
			    fd_set *exceptfds, struct timeval *timeout);

extern long (*p_sys_open)(const char *filename, int flags, int mode);

extern long (*p_sys_creat)(const char *filename, int mode);

extern ssize_t (*p_sys_write)(unsigned int fd, const char *buf, size_t count);

extern ssize_t (*p_sys_pwrite64)(unsigned int fd, char *buf, size_t count,
				 loff_t pos);

extern ssize_t (*p_sys_pread64)(unsigned int fd, char *buf, size_t count,
				loff_t pos);

extern long (*p_sys_fadvise64)(unsigned int fd, loff_t offset, loff_t len,
			       int advice);

extern long (*p_sys_getdents64)(unsigned int fd, struct linux_dirent64 *dirent,
				unsigned int count);

extern long (*p_sys_unlink)(const char *pathname);

extern off_t (*p_sys_lseek)(unsigned int fd, off_t offset, unsigned int origin);

extern long (*p_sys_ioctl)(unsigned int fd, unsigned int cmd,
			   unsigned long arg);

extern long (*p_sys_fsync)(unsigned int fd);

extern long (*p_sys_fdatasync)(unsigned int fd);

extern ssize_t (*p_sys_readv)(unsigned long fd, const struct iovec *vector,
			      unsigned long count);

extern ssize_t (*p_sys_writev)(unsigned long fd, const struct iovec *vector,
			       unsigned long count);

extern long (*p_sys_link)(const char *oldname, const char *newname);

extern long (*p_sys_symlink)(const char *oldname, const char *newname);

extern long (*p_sys_mkdir)(const char *pathname, int mode);

extern long (*p_sys_rmdir)(const char *pathname);

extern long (*p_sys_mknod)(const char *filename, int mde, unsigned dev);

extern long (*p_sys_chmod)(const char *path, mode_t mode);

extern long (*p_sys_rename)(const char *oldname, const char *newname);

extern long (*p_sys_readlink)(const char *path, char *buf, int bufsiz);

extern long (*p_sys_truncate)(const char *path, unsigned long len);

extern long (*p_sys_ftruncate)(unsigned int fd, unsigned long len);

extern long (*p_sys_fcntl)(unsigned int fd, unsigned int cmd,
			   unsigned long arg);

extern long (*p_sys_stat)(char *path, struct __old_kernel_stat *buf);

extern long (*p_sys_statfs)(const char *path, struct statfs *buf);

extern long (*p_sys_chdir)(const char *filename);

extern long (*p_sys_wait4)(pid_t pid, unsigned int *stat_addr, int options,
			   struct rusage *ru);

extern long (*p_sys_getcwd)(char *buf, unsigned long size);

extern long (*p_sys_mmap)(unsigned long addr, unsigned long len,
			  unsigned long prot, unsigned long flags,
			  unsigned long fd, unsigned long pgoff);

extern long (*p_sys_munmap)(unsigned long addr, size_t len);

extern long (*p_sys_getrusage)(int who, struct rusage *ru);

extern long (*p_sys_setxattr)(char *path, char *name, void *value, size_t size,
			      int flags);

extern long (*p_sys_getxattr)(char *path, char *name, void *value, size_t size);

extern long (*p_sys_listxattr)(char *path, char *list, size_t size);

extern long (*p_sys_removexattr)(char *path, char *name);

extern long (*p_sys_readahead)(int fd, loff_t offset, size_t count);

extern long (*p_sys_sync)(void);

#endif /* USISYSCALL_H */
