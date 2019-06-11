/*
 * Copyright 2011-2012, 2014 Cray Inc. All Rights Reserved.
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

#ifndef _DVS_IOCTL_H_
#define _DVS_IOCTL_H_

#define DVS_IOCTL_IDENT ((unsigned int)0x42)

/* ioctl to get the remote file system type for a file visible on a DVS mount */
#define DVS_GET_REMOTE_FS_MAGIC _IOWR(DVS_IOCTL_IDENT, 0, unsigned long)

/* ioctls to get/set the DVS block size for a file */
#define DVS_GET_FILE_BLK_SIZE _IOWR(DVS_IOCTL_IDENT, 1, int)

#define DVS_SET_FILE_BLK_SIZE _IOWR(DVS_IOCTL_IDENT, 3, int)

/* ioctls to get/set the DVS stripe width (maxnodes) for a file */
#define DVS_GET_FILE_STRIPE_WIDTH _IOWR(DVS_IOCTL_IDENT, 2, int)

#define DVS_SET_FILE_STRIPE_WIDTH _IOWR(DVS_IOCTL_IDENT, 4, int)

/* ioctls to get/set the DVS datasync option for a file */
#define DVS_GET_FILE_DATASYNC _IOWR(DVS_IOCTL_IDENT, 5, short)

#define DVS_SET_FILE_DATASYNC _IOWR(DVS_IOCTL_IDENT, 6, short)

/* ioctls to get/set the DVS cache option for a file */
#define DVS_GET_FILE_CACHE _IOWR(DVS_IOCTL_IDENT, 7, short)

#define DVS_SET_FILE_CACHE _IOWR(DVS_IOCTL_IDENT, 8, short)

/* ioctls to get/set the DVS closesync  option for a file */
#define DVS_GET_FILE_CLOSESYNC _IOWR(DVS_IOCTL_IDENT, 9, short)

#define DVS_SET_FILE_CLOSESYNC _IOWR(DVS_IOCTL_IDENT, 10, short)

/* ioctls to get/set the DVS killprocess option for a file */
#define DVS_GET_FILE_KILLPROCESS _IOWR(DVS_IOCTL_IDENT, 11, short)

#define DVS_SET_FILE_KILLPROCESS _IOWR(DVS_IOCTL_IDENT, 12, short)

/*
 * Ioctl numbers 13 and 14 used to be DVS_SET/GET_FILE_BULK_RW.
 * The bulk_rw feature has been removed, but the re-use of
 * these ioctl numbers should be avoided
 */

/* ioctls to get/set the DVS atomic option for a file */
#define DVS_GET_FILE_ATOMIC _IOWR(DVS_IOCTL_IDENT, 15, short)

#define DVS_SET_FILE_ATOMIC _IOWR(DVS_IOCTL_IDENT, 16, short)

/* ioctls to get/set the DVS deferopens option for a file */
#define DVS_GET_FILE_DEFEROPENS _IOWR(DVS_IOCTL_IDENT, 17, short)

#define DVS_SET_FILE_DEFEROPENS _IOWR(DVS_IOCTL_IDENT, 18, short)

/* ioctls to get/set the DVS cache_read_sz option for a file */
#define DVS_GET_FILE_CACHE_READ_SZ _IOWR(DVS_IOCTL_IDENT, 19, unsigned int)

#define DVS_SET_FILE_CACHE_READ_SZ _IOWR(DVS_IOCTL_IDENT, 20, unsigned int)

/*
 * ioctl to get the # of nodes currently available for a mountpoint. Has no set
 * option as this is a superblock value that shouldn't be manipulated by users
 */
#define DVS_GET_NNODES _IOWR(DVS_IOCTL_IDENT, 21, int)

/* Generic ioctl tunneling */
struct dvs_ioctl_tunnel {
	unsigned int ioctl_cmd;
	int arg_by_ref;
	int arg_size;
	unsigned long arg[0];
};

/* ioctls to tunnel an ioctl to one/all servers.
 * The ioctl will be unencapsulated at the DVS server
 * meaning that no modification to the underlying
 * filesystem is necessary. */
#define DVS_TUNNEL_IOCTL _IOWR(DVS_IOCTL_IDENT, 22, struct dvs_ioctl_tunnel)

#define DVS_BCAST_IOCTL _IOWR(DVS_IOCTL_IDENT, 23, struct dvs_ioctl_tunnel)

/* ioctls agumented with stripping info */
struct dvs_augmented_ioctl_tunnel {
	unsigned int ioctl_cmd; // User
	int arg_by_ref; // User
	int arg_size; // User
	int stripe_size; // DVS
	int stripe_width; // DVS
	int stripe_index; // DVS
	unsigned long arg[0]; // User
};

/* ioctls to augment an ioctl with file striping information
 * and send it to one/all servers.
 * The underlying filesystem receives and must support this
 *  DVS_AUGMENTED_*_IOCTL and the struct dvs_augmented_ioctl_tunnel */
#define DVS_AUGMENTED_TUNNEL_IOCTL                                             \
	_IOWR(DVS_IOCTL_IDENT, 24, struct dvs_augmented_ioctl_tunnel)

#define DVS_AUGMENTED_BCAST_IOCTL                                              \
	_IOWR(DVS_IOCTL_IDENT, 25, struct dvs_augmented_ioctl_tunnel)

/* ioctl to set the dwfs striping configuration */

struct dvs_dwfs_stripe_config {
	unsigned int stripe_width;
	unsigned int stripe_size;
};

#define DVS_DWFS_SET_STRIPE_CONFIG                                             \
	_IOWR(DVS_IOCTL_IDENT, 26, struct dvs_dwfs_stripe_config)

#endif
