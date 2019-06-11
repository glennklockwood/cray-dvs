/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2011, 2014, 2016 Cray Inc. All Rights Reserved.
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

#ifndef USIFILEPROTO_H
#define USIFILEPROTO_H

#ifndef __KERNEL__
/*
 *  * This header file not for userland!
 *   */
#error "Invalid inclusion of kernel-only header file usifile.h"
#endif /* __KERNEL__ */

extern void update_inode(struct inode_attrs *remoteip, struct inode *newip,
			 struct dentry *dep, struct file *fp, int invalidate);
extern void utruncate(struct inode *ip);
extern int urevalidate(struct dentry *dep, unsigned int flags);
extern int ugetattr(struct vfsmount *mnt, struct dentry *dep,
		    struct kstat *kstatp);
extern int usetattr(struct dentry *dep, struct iattr *iattrp);
extern int usetxattr(struct dentry *dentry, const char *name, const void *value,
		     size_t size, int flags, const char *prefix,
		     size_t prefix_len);
extern ssize_t ugetxattr(struct dentry *dentry, const char *name, void *value,
			 size_t size, const char *prefix, size_t prefix_len);
extern ssize_t ulistxattr(struct dentry *dentry, char *list, size_t size);
extern int uremovexattr(struct dentry *dentry, const char *name);

#endif
