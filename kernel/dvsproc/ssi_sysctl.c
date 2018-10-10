/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006-2011, 2016 Cray Inc. All Rights Reserved.
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
 * Support for /proc/sys/fs/dvs namespace.
 *
 */

#include <linux/sysctl.h>
#include <linux/errno.h>

#include "common/ssi_sysctl.h"
#include "common/resource.h"
#include "common/kernel/usiipc.h"

#define CTL_SSI		526	/* random number */

/* Forward */
static int ssiinfo_do_integer(struct ctl_table *, int, void *, size_t *, loff_t *);

/* CTL_SSI names */
enum
{
	SSI_NODEID=1,		/* intra-system unique node ID */
};

static struct ctl_table ssi_info_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
		.ctl_name	= SSI_NODEID,
#endif
		.procname	= "nodeid",
		.data		= &ssi_nodeid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &ssiinfo_do_integer,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
		.strategy	= &sysctl_intvec,
#endif
	},
	{0}
};

static struct ctl_table  ssi_dvs_root_table[] = {
    	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	CTL_SSI,
#endif
	"dvs",
	NULL,
	0,
	0555,
	ssi_info_table
	},
	{0}
};

static struct ctl_table  ssi_root_table[] = {
    	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	CTL_FS,
#endif
	"fs",
	NULL,
	0,
	0555,
	ssi_dvs_root_table
	},
	{0}
};

int ssi_nodeid = -1;

static struct ctl_table_header *ssi_table_header;

/*
 * Each of these functions is a write-once protection wrapper
 * for the underlying data type (integer or string).  Integer
 * vectors are not tested.  
 */


#if 0
/*
 * We #if this away to avoid build warnings.  We don't want to delete it
 * though because it can be useful in the future.
 */
static int 
ssiinfo_do_string(struct ctl_table *table, int write, struct file *filp,
		     void *buffer, size_t *lenp)
{
	char *t;

	t = (char *) table->data;
	if (write && t && (*t != '\0'))
		return -EINVAL;

	return proc_dostring (table, write, filp, buffer, lenp);

} /* ssiinfo_do_string */
#endif


static int 
ssiinfo_do_integer(struct ctl_table *table, int write,
		     void *buffer, size_t *lenp, loff_t *ppos)
{
	int *t;

	t = (int*) table->data;
	if (write && t && (*t != -1))
		return -EINVAL; 

	return proc_dointvec (table, write, buffer, lenp, ppos);
} /* ssiinfo_do_integer */


void
ssi_sysctl_register(void)
{
    ssi_table_header = register_sysctl_table(ssi_root_table);
} /* ssi_sysctl_register */


void
ssi_sysctl_unregister(void)
{
    if (ssi_table_header)
		unregister_sysctl_table(ssi_table_header);
} /* ssi_sysctl_unregister */

