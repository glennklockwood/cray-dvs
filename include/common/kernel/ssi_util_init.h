/*
 * Unpublished Work (C) 2004 Cassatt Corporation.   All rights reserved.
 * Copyright 2006, 2008-2009, 2011, 2014-2016 Cray Inc. All Rights Reserved.
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
 * ssi_util_init.h
 *   Externally exported interfaces for the ssiutil.o module, which
 *   handles functions used in common by ssi.o and upfsclient.o modules.
 *   Two examples of this is creating, destroying, and handling requests
 *   for /dev/uss and initializing the ipc layer.
 */

#if !defined(SSI_UTIL_INIT_H)
#define SSI_UTIL_INIT_H

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file ssi_util_init.h"
#endif /* __KERNEL__ */

/*
 * Handlers/callbacks performed by other modules but called from ssiutil.o.
 *
 * The DVS client init and the SSI module's init should set these up.
 */
typedef struct handlers_s {
	int (*receive)(void *);
	void (*node_down)(int node);
	void (*node_up)(int node);
} handlers_t;

enum { handler_receive = 0x100,
       handler_node_up,
       handler_node_down,
       handler_end_v1,
};

/*
 * Callbacks that are registered by DSD users.
 */
struct dsd_ops {
	int (*get_dsd_path)(struct file *file, char *buf, unsigned int size);
	int (*get_dsd_bcstripe_path)(struct file *file, unsigned int *index,
				     char *buf, unsigned int size);
};

struct dwfs_open_info;

extern int ssiutil_register_handlers(int identity, unsigned int instance,
				     void *func);
extern int ssiutil_unregister_handlers(int identity, unsigned int instance,
				       void *func);
extern int register_dsd_ops(struct dsd_ops *dsd_ops);
extern int unregister_dsd_ops(struct dsd_ops *dsd_ops);
extern int get_dwfs_path(struct file *file, struct dwfs_open_info *dwfs_info);
extern int get_dwfs_bcstripe(struct file *file,
			     struct dwfs_open_info *dwfs_info);

#endif /* !defined(SSI_UTIL_INIT_H) */
