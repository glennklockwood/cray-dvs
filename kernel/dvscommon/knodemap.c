/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006-2011, 2013-2015 Cray Inc. All Rights Reserved.
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

/*
 * If modifications to this file affect the libssi interface please
 * increment LIBSSI_VER in Makefile.in
 */

#ifndef __KERNEL__
#error "Invalid include of kernel header file in user code"
#endif

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include "common/ssi_proc.h"
#include "common/ssi_sysctl.h"
#include "common/kernel/usiipc.h"

int dvs_procfs_get_max_nodes(void)
{
	return (ssiproc_max_nodes);
} /* dvs_procfs_get_max_nodes */

int dvs_procfs_get_my_nodeid(void)
{
	return (ssi_nodeid);
} /* dvs_procfs_get_my_nodeid */

/* REFERENCED */

/* Note: The structure of the node-map file is a plain text file with two items
	 on each line. For the portals interconnect the first item is a
	 hostname and the second a nid.

	 For the sockets interconnect the first item is a hostname and the
	 second is an IP address.

	 In both cases the node listed first is taken to be the resource
	 manager.
*/
struct ssi_node_map *dvs_procfs_parse_mapfile(char *mapbuf, unsigned long count,
					      int *ret)
{
	struct ssi_node_map *nodemap, *nm1;
	char *p, *p1;
	int line_count = 0;
	int err = 0;
	int i;

	nodemap = (struct ssi_node_map *)vmalloc_ssi(
		ssiproc_max_nodes * sizeof(struct ssi_node_map));
	if (!nodemap) {
		err = -ENOMEM;
		goto out;
	}
	nm1 = nodemap;

	p1 = mapbuf;
	while ((p = strsep(&p1, "\t:, \n")) != NULL) {
		/* ignore empty lines */
		if (!strlen(p))
			continue;

		if (line_count == ssiproc_max_nodes) {
			printk(KERN_ERR
			       "DVS: dvs_procfs_parse_mapfile: node map exceeds "
			       "ssiproc_max_nodes (%d)",
			       ssiproc_max_nodes);
			err = -EINVAL;
			break;
		}
		nm1->name = kmalloc_ssi(strlen(p) + 1, GFP_KERNEL);
		if (!nm1->name) {
			err = -ENOMEM;
			break;
		}

		line_count++;

		strcpy(nm1->name, p);

		if ((p = strsep(&p1, "\n")) == NULL)
			break;
		while (isspace(*p) || ispunct(*p))
			p++;

		if (!strlen(p)) {
			err = -EINVAL;
			break;
		}

		nm1->tok = kmalloc_ssi(strlen(p) + 1, GFP_KERNEL);
		if (!nm1->tok) {
			err = -ENOMEM;
			break;
		}
		strcpy(nm1->tok, p);

		spin_lock_init(&nm1->rr_lock);

		nm1++;
	}

	if (ssiproc_max_nodes > line_count)
		ssiproc_max_nodes = line_count;

	if (err) {
		nm1 = nodemap;
		for (i = 0; i < line_count; i++, nm1++) {
			if (nm1->name)
				kfree_ssi(nm1->name);
			if (nm1->tok)
				kfree_ssi(nm1->tok);
		}
		vfree_ssi(nodemap);
		nodemap = NULL;
	}

out:
	*ret = err;
	return nodemap;
}
