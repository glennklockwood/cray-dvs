/*
 * Copyright 2013, 2016 Cray Inc. All Rights Reserved.
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

#ifndef VFSOPS_H
#define VFSOPS_H

/*
 * vfsops.h
 * VFS operation names
 */

enum {
	/* struct file_operations */
	VFS_OP_LLSEEK,
	VFS_OP_READ,
	VFS_OP_AIO_READ,
	VFS_OP_WRITE,
	VFS_OP_AIO_WRITE,
	VFS_OP_READDIR,
	VFS_OP_UNLOCKED_IOCTL,
	VFS_OP_MMAP,
	VFS_OP_OPEN,
	VFS_OP_FLUSH,
	VFS_OP_RELEASE,
	VFS_OP_FSYNC,
	VFS_OP_FASYNC,
	VFS_OP_LOCK,
	VFS_OP_FLOCK,

	/* struct address_space_operations */
	VFS_OP_WRITEPAGE,
	VFS_OP_WRITEPAGES,
	VFS_OP_READPAGE,
	VFS_OP_READPAGES,
	VFS_OP_WRITE_BEGIN,
	VFS_OP_WRITE_END,
	VFS_OP_DIRECT_IO,

	/* struct super_operations */
	VFS_OP_STATFS,
	VFS_OP_PUT_SUPER,
	VFS_OP_WRITE_SUPER,
	VFS_OP_EVICT_INODE,
	VFS_OP_SHOW_OPTIONS,

	/* struct inode_operations - directory */
	VFS_OP_D_CREATE,
	VFS_OP_D_LOOKUP,
	VFS_OP_D_LINK,
	VFS_OP_D_UNLINK,
	VFS_OP_D_SYMLINK,
	VFS_OP_D_MKDIR,
	VFS_OP_D_RMDIR,
	VFS_OP_D_MKNOD,
	VFS_OP_D_RENAME,
	VFS_OP_D_TRUNCATE,
	VFS_OP_D_PERMISSION,
	VFS_OP_D_SETATTR,
	VFS_OP_D_GETATTR,
	VFS_OP_D_SETXATTR,
	VFS_OP_D_GETXATTR,
	VFS_OP_D_LISTXATTR,
	VFS_OP_D_REMOVEXATTR,

	/* struct inode_operations - file */
	VFS_OP_F_CREATE,
	VFS_OP_F_LINK,
	VFS_OP_F_UNLINK,
	VFS_OP_F_SYMLINK,
	VFS_OP_F_MKDIR,
	VFS_OP_F_RMDIR,
	VFS_OP_F_MKNOD,
	VFS_OP_F_RENAME,
	VFS_OP_F_TRUNCATE,
	VFS_OP_F_PERMISSION,
	VFS_OP_F_SETATTR,
	VFS_OP_F_GETATTR,
	VFS_OP_F_SETXATTR,
	VFS_OP_F_GETXATTR,
	VFS_OP_F_LISTXATTR,
	VFS_OP_F_REMOVEXATTR,

	/* struct inode_operations - link */
	VFS_OP_L_READLINK,
	VFS_OP_L_FOLLOW_LINK,
	VFS_OP_L_PUT_LINK,
	VFS_OP_L_SETATTR,
	VFS_OP_L_GETATTR,

	/* struct dentry_operations */
	VFS_OP_D_REVALIDATE,

	VFS_OP_END_V1
};

static inline char *
vfs_op_to_string(int request)
{
	switch (request) {
	/* struct file_operations */
	case VFS_OP_LLSEEK: return "llseek";
	case VFS_OP_READ: return "read";
	case VFS_OP_AIO_READ: return "aio_read";
	case VFS_OP_WRITE: return "write";
	case VFS_OP_AIO_WRITE: return "aio_write";
	case VFS_OP_READDIR: return "readdir";
	case VFS_OP_UNLOCKED_IOCTL: return "unlocked_ioctl";
	case VFS_OP_MMAP: return "mmap";
	case VFS_OP_OPEN: return "open";
	case VFS_OP_FLUSH: return "flush";
	case VFS_OP_RELEASE: return "release";
	case VFS_OP_FSYNC: return "fsync";
	case VFS_OP_FASYNC: return "fasync";
	case VFS_OP_LOCK: return "lock";
	case VFS_OP_FLOCK: return "flock";

	/* struct address_space_operations */
	case VFS_OP_WRITEPAGE: return "writepage";
	case VFS_OP_WRITEPAGES: return "writepages";
	case VFS_OP_READPAGE: return "readpage";
	case VFS_OP_READPAGES: return "readpages";
	case VFS_OP_WRITE_BEGIN: return "write_begin";
	case VFS_OP_WRITE_END: return "write_end";
	case VFS_OP_DIRECT_IO: return "direct_io";

	/* struct super_operations */
	case VFS_OP_STATFS: return "statfs";
	case VFS_OP_PUT_SUPER: return "put_super";
	case VFS_OP_WRITE_SUPER: return "write_super";
	case VFS_OP_EVICT_INODE: return "evict_inode";
	case VFS_OP_SHOW_OPTIONS: return "show_options";

	/* struct inode_operations - directory */
	case VFS_OP_D_CREATE: return "d_create";
	case VFS_OP_D_LOOKUP: return "d_lookup";
	case VFS_OP_D_LINK: return "d_link";
	case VFS_OP_D_UNLINK: return "d_unlink";
	case VFS_OP_D_SYMLINK: return "d_symlink";
	case VFS_OP_D_MKDIR: return "d_mkdir";
	case VFS_OP_D_RMDIR: return "d_rmdir";
	case VFS_OP_D_MKNOD: return "d_mknod";
	case VFS_OP_D_RENAME: return "d_rename";
	case VFS_OP_D_TRUNCATE: return "d_truncate";
	case VFS_OP_D_PERMISSION: return "d_permission";
	case VFS_OP_D_SETATTR: return "d_setattr";
	case VFS_OP_D_GETATTR: return "d_getattr";
	case VFS_OP_D_SETXATTR: return "d_setxattr";
	case VFS_OP_D_GETXATTR: return "d_getxattr";
	case VFS_OP_D_LISTXATTR: return "d_listxattr";
	case VFS_OP_D_REMOVEXATTR: return "d_removexattr";

	/* struct inode_operations - file */
	case VFS_OP_F_CREATE: return "f_create";
	case VFS_OP_F_LINK: return "f_link";
	case VFS_OP_F_UNLINK: return "f_unlink";
	case VFS_OP_F_SYMLINK: return "f_symlink";
	case VFS_OP_F_MKDIR: return "f_mkdir";
	case VFS_OP_F_RMDIR: return "f_rmdir";
	case VFS_OP_F_MKNOD: return "f_mknod";
	case VFS_OP_F_RENAME: return "f_rename";
	case VFS_OP_F_TRUNCATE: return "f_truncate";
	case VFS_OP_F_PERMISSION: return "f_permission";
	case VFS_OP_F_SETATTR: return "f_setattr";
	case VFS_OP_F_GETATTR: return "f_getattr";
	case VFS_OP_F_SETXATTR: return "f_setxattr";
	case VFS_OP_F_GETXATTR: return "f_getxattr";
	case VFS_OP_F_LISTXATTR: return "f_listxattr";
	case VFS_OP_F_REMOVEXATTR: return "f_removexattr";

	/* struct inode_operations - link */
	case VFS_OP_L_READLINK: return "l_readlink";
	case VFS_OP_L_FOLLOW_LINK: return "l_follow_link";
	case VFS_OP_L_PUT_LINK: return "l_put_link";
	case VFS_OP_L_SETATTR: return "l_setattr";
	case VFS_OP_L_GETATTR: return "l_getattr";

	/* struct dentry_operations */
	case VFS_OP_D_REVALIDATE: return "d_revalidate";

	default: return "UNKNOWN";
	}
}
#endif /* VFSOPS_H */
