/*
 * ssi_util_init.c - handle common initialization and code for the
 *                   UPFS client and SSI remote launch code. These
 *                   common features include transport layer init and
 *                   /dev/uss.
 *
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2011, 2014-2017 Cray Inc. All Rights Reserved.
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
#include <linux/utime.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include "common/usierrno.h"
#include "common/kernel/ssi_util_init.h"
#include "common/kernel/usiipc.h"
#include "dvs/kernel/usifile.h"
#include "common/ssi_proc.h"
#include "common/kernel/ipc_api.h"

extern int usi_transport_callback(int cmd, void *data); /*forward */

/*
 * Handler/callback information for ssi_devfs_ioctl(),
 * usi_transport_callback(), and ipc_init().
 *
 * The UPFS client init and the SSI module's init should set these up.
 */
static handlers_t handlers[DVSIPC_INSTANCE_MAX];
struct dsd_ops *dsd_ops = NULL;

int ssi_initialized = 0;

int dvsutil_init(void)
{
	int rval;

	/*
	 * Initialize all of the handers to be non-existant.
	 * This should be done before initializing other ssi-related code,
	 * like the ipc layer; otherwise, unexpected things can happen.
	 */
	memset(&handlers, 0, sizeof(handlers_t));

	usi_callback = &usi_transport_callback;

	if ((rval = ipc_init(&max_transport_msg_size)) < 0) {
		printk(KERN_ERR "DVS: %s: ipc_init() failed (%d)\n",
		       __FUNCTION__, rval);
		return (rval);
	}

	KDEBUG_INF(0, "DVS: dvsutil module loaded");
	return 0;
}

void dvsutil_exit(void)
{
	usi_callback = NULL;

	ipc_term();

	KDEBUG_INF(0, "DVS: dvsutil module unloaded\n");
}

int usi_transport_callback(int cmd, void *data)
{
	int i;

	if (!suser())
		return (-EPERM);

	switch (cmd) {
	case RQ_FILE:
		if (handlers[DVSIPC_INSTANCE_DVS].receive != NULL)
			return (*handlers[DVSIPC_INSTANCE_DVS].receive)(data);
		else
			return -ENOSYS;
/* DW specific */
#ifdef WITH_DATAWARP
	case RQ_DSD:
		if (handlers[DVSIPC_INSTANCE_KDWFS].receive != NULL)
			return (*handlers[DVSIPC_INSTANCE_KDWFS].receive)(data);
		else
			return -ENOSYS;
	case RQ_DSDB:
		if (handlers[DVSIPC_INSTANCE_KDWFSB].receive != NULL)
			return (*handlers[DVSIPC_INSTANCE_KDWFSB].receive)(
				data);
		else
			return -ENOSYS;
	case RQ_DSDC:
		if (handlers[DVSIPC_INSTANCE_KDWCFS].receive != NULL)
			return (*handlers[DVSIPC_INSTANCE_KDWCFS].receive)(
				data);
		else
			return -ENOSYS;
#endif
	case RQ_IPC_NODE_UP:
		for (i = 0; i < DVSIPC_INSTANCE_MAX; i++) {
			if (handlers[i].node_up == NULL)
				/* ignore since RQ_IPC_NODE_UP requests do not
				 * require a response */
				continue;
			(*handlers[i].node_up)((int)(long)data);
		}
		break;
	case RQ_IPC_NODE_DOWN:
		for (i = 0; i < DVSIPC_INSTANCE_MAX; i++) {
			if (handlers[i].node_down == NULL)
				/* ignore since RQ_IPC_NODE_DOWN requests do not
				 * require a response */
				continue;
			(*handlers[i].node_down)((int)(long)data);
		}
		break;
	default:
		printk(KERN_ERR "DVS: usi_transport_callback: invalid "
				"request %d\n",
		       cmd);
		return -EINVAL;
	}

	return (0);
}

/*
 * ssiutil_register_handlers
 *
 *   Register callback or handler functions that "higher-level" modules
 *   provide to satisfy requests seen by this module.
 *
 */
int ssiutil_register_handlers(int identity, unsigned int instance,
			      void *function)
{
	if (instance >= DVSIPC_INSTANCE_MAX) {
		printk(KERN_ERR "DVS: %s: Invalid instance id %d\n", __func__,
		       instance);

		return -EINVAL;
	}

	switch (identity) {
	case handler_receive:
		if (handlers[instance].receive != NULL) {
			printk(KERN_ERR "DVS: %s: receive handler for "
					"instance %d already registered\n",
			       __func__, instance);
			return -EINVAL;
		}

		handlers[instance].receive = function;
		break;
	case handler_node_up:
		if (handlers[instance].node_up != NULL) {
			printk(KERN_ERR "DVS: %s: node up handler for "
					"instance %d already registered\n",
			       __func__, instance);
			return -EINVAL;
		}

		handlers[instance].node_up = function;
		break;
	case handler_node_down:
		if (handlers[instance].node_down != NULL) {
			printk(KERN_ERR "DVS: %s: node down handler "
					"for instance %d already registered\n",
			       __func__, instance);
			return -EINVAL;
		}

		handlers[instance].node_down = function;
		break;
	default:
		printk(KERN_ERR "DVS: ssiutil_register_handlers "
				"failed %d 0x%p\n",
		       identity, function);
		return -EINVAL;
	}

	return 0;
}

/*
 * ssiutil_unregister_handlers
 *
 *   Remove handlers that have been installed by "higher-level" modules.
 *
 */
int ssiutil_unregister_handlers(int identity, unsigned int instance,
				void *function)
{
	if (instance >= DVSIPC_INSTANCE_MAX) {
		printk(KERN_ERR "DVS: %s: Invalid instance id %d\n", __func__,
		       instance);

		return -EINVAL;
	}

	switch (identity) {
	case handler_receive:
		handlers[instance].receive = NULL;
		break;
	case handler_node_up:
		handlers[instance].node_up = NULL;
		break;
	case handler_node_down:
		handlers[instance].node_down = NULL;
		break;
	default:
		printk(KERN_ERR "DVS: ssiutil_unregister_handlers "
				"failed %d 0x%p\n",
		       identity, function);
		return -EINVAL;
	}

	return 0;
}

int register_dsd_ops(struct dsd_ops *ops)
{
	if (ops == NULL) {
		printk(KERN_ERR "DVS: %s: Invalid dsd_ops 0x%p\n", __func__,
		       dsd_ops);
		return -EINVAL;
	}

	if (dsd_ops != NULL) {
		printk(KERN_ERR "DVS: %s: dsd_ops already set to 0x%p\n",
		       __func__, dsd_ops);
		return -EINVAL;
	}

	dsd_ops = ops;

	return 0;
}

int unregister_dsd_ops(struct dsd_ops *ops)
{
	if (dsd_ops != ops) {
		printk(KERN_ERR "DVS: %s: dsd_ops 0x%p not registered\n",
		       __func__, dsd_ops);
		return -EINVAL;
	}

	dsd_ops = NULL;

	return 0;
}

int get_dwfs_path(struct file *file, struct dwfs_open_info *dwfs_info)
{
	if (dsd_ops == NULL || dsd_ops->get_dsd_path == NULL) {
		printk(KERN_ERR "DVS: %s: No DSD operations registered. Path "
				"for DWFS data files not initialized\n",
		       __func__);
		return -EINVAL;
	}

	return dsd_ops->get_dsd_path(file, dwfs_info->path,
				     dwfs_info->path_len);
}

int get_dwfs_bcstripe(struct file *file, struct dwfs_open_info *dwfs_info)
{
	if (dsd_ops == NULL || dsd_ops->get_dsd_bcstripe_path == NULL) {
		printk(KERN_ERR "DVS: %s: No DSD operations registered. Path "
				"for DSD data files not initialized\n",
		       __func__);
		return -EINVAL;
	}

	return dsd_ops->get_dsd_bcstripe_path(
		file, &dwfs_info->bcstripe,
		dwfs_info->path + dwfs_info->path_len, dwfs_info->path_len);
}

EXPORT_SYMBOL(usi_transport_callback);
EXPORT_SYMBOL(ssiutil_register_handlers);
EXPORT_SYMBOL(ssiutil_unregister_handlers);
EXPORT_SYMBOL(register_dsd_ops);
EXPORT_SYMBOL(unregister_dsd_ops);
