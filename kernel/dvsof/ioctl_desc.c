/*
 * Copyright 2006-2007, 2010-2012, 2014-2016 Cray Inc. All Rights Reserved.
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

#include "common/kernel/ioctl_desc.h"

#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include <fs/ext4/ext4.h>

/* DVS ioctl header files */
#include "dvs/dvs_ioctl.h"

#define DEBUG_IOCTL 0 /* set to 1 to enable ext3 ioctls for debugging */

/*
 * ioctl_descs is a READ ONLY array describing the supported IOCTLS
 * for PanFS filesystems.  The ext3 entries are included for testing
 * purposes only.
 *
 * See ioctl_desc.h for descriptions of the ioctl_desc fields.
 */

static struct ioctl_desc ioctl_descs[] = {

#if DEBUG_IOCTL
	{ "EXT3_IOC_SETFLAGS", EXT3_IOC_SETFLAGS, sizeof(long), 1, 1 },
	{ "EXT3_IOC_GETVERSION", EXT3_IOC_GETVERSION, sizeof(long), 1, 1 },
	{ "EXT3_IOC_GETFLAGS", EXT3_IOC_GETFLAGS, sizeof(long), 1, 1 },
#endif
	/* DVS ioctl descriptions */
	{ "DVS_GET_REMOTE_FS_MAGIC", DVS_GET_REMOTE_FS_MAGIC,
	  sizeof(unsigned long), 1, 1 },
	{ "DVS_GET_FILE_BLK_SIZE", DVS_GET_FILE_BLK_SIZE, sizeof(int), 1, 1 },
	{ "DVS_SET_FILE_BLK_SIZE", DVS_SET_FILE_BLK_SIZE, sizeof(int), 1, 1 },
	{ "DVS_GET_FILE_STRIPE_WIDTH", DVS_GET_FILE_STRIPE_WIDTH, sizeof(int),
	  1, 1 },
	{ "DVS_SET_FILE_STRIPE_WIDTH", DVS_SET_FILE_STRIPE_WIDTH, sizeof(int),
	  1, 1 },
	{ "DVS_GET_FILE_DATASYNC", DVS_GET_FILE_DATASYNC, sizeof(short), 1, 1 },
	{ "DVS_SET_FILE_DATASYNC", DVS_SET_FILE_DATASYNC, sizeof(short), 1, 1 },
	{ "DVS_GET_FILE_CACHE", DVS_GET_FILE_CACHE, sizeof(short), 1, 1 },
	{ "DVS_SET_FILE_CACHE", DVS_SET_FILE_CACHE, sizeof(short), 1, 1 },
	{ "DVS_GET_FILE_CLOSESYNC", DVS_GET_FILE_CLOSESYNC, sizeof(short), 1,
	  1 },
	{ "DVS_SET_FILE_CLOSESYNC", DVS_SET_FILE_CLOSESYNC, sizeof(short), 1,
	  1 },
	{ "DVS_GET_FILE_KILLPROCESS", DVS_GET_FILE_KILLPROCESS, sizeof(short),
	  1, 1 },
	{ "DVS_SET_FILE_KILLPROCESS", DVS_SET_FILE_KILLPROCESS, sizeof(short),
	  1, 1 },
	{ "DVS_GET_FILE_ATOMIC", DVS_GET_FILE_ATOMIC, sizeof(short), 1, 1 },
	{ "DVS_SET_FILE_ATOMIC", DVS_SET_FILE_ATOMIC, sizeof(short), 1, 1 },
	{ "DVS_GET_FILE_DEFEROPENS", DVS_GET_FILE_DEFEROPENS, sizeof(short), 1,
	  1 },
	{ "DVS_SET_FILE_DEFEROPENS", DVS_SET_FILE_DEFEROPENS, sizeof(short), 1,
	  1 },
	{ "DVS_GET_FILE_CACHE_READ_SZ", DVS_GET_FILE_CACHE_READ_SZ,
	  sizeof(unsigned int), 1, 1 },
	{ "DVS_SET_FILE_CACHE_READ_SZ", DVS_SET_FILE_CACHE_READ_SZ,
	  sizeof(unsigned int), 1, 1 },
	{ "DVS_GET_NNODES", DVS_GET_NNODES, sizeof(int), 1, 1 },
	{ "DVS_TUNNEL_IOCTL", DVS_TUNNEL_IOCTL, sizeof(struct dvs_ioctl_tunnel),
	  1, 1 },
	{ "DVS_BCAST_IOCTL", DVS_BCAST_IOCTL, sizeof(struct dvs_ioctl_tunnel),
	  1, 1 },
	{ "DVS_AUGMENTED_TUNNEL_IOCTL", DVS_AUGMENTED_TUNNEL_IOCTL,
	  sizeof(struct dvs_augmented_ioctl_tunnel), 1, 1 },
	{ "DVS_AUGMENTED_BCAST_IOCTL", DVS_AUGMENTED_BCAST_IOCTL,
	  sizeof(struct dvs_augmented_ioctl_tunnel), 1, 1 },
	{ "DVS_DWFS_SET_STRIPE_CONFIG", DVS_DWFS_SET_STRIPE_CONFIG,
	  sizeof(struct dvs_ioctl_tunnel), 1, 1 },
};

#define N_IOCTL_DESCS (sizeof(ioctl_descs) / sizeof(struct ioctl_desc))

struct ioctl_desc *get_ioctl_desc(int cmd)
{
	int i;

	for (i = 0; i < N_IOCTL_DESCS; i++) {
		if (cmd == ioctl_descs[i].cmd)
			return ioctl_descs + i;
	}

	return NULL;
}
