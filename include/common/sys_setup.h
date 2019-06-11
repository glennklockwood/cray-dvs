/*
 * Copyright 2006-2018 Cray Inc. All Rights Reserved.
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
 * This file creates the directory /sys/fs/dvs.
 * This directory hosts the user-facing interfaces for DVS.
 */

#ifndef _SYS_SETUP_H_
#define _SYS_SETUP_H_

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <asm/uaccess.h>

#include "common/ssi_proc.h"
#include "common/kernel/usiipc.h"
#include "common/ssi_sysctl.h"
#include "dvs/kernel/usifile.h"
#include "common/log.h"
#include "common/sync.h"
#include "common/estale_retry.h"

void dvs_drop_mount_attr_cache(struct incore_upfs_super_block *icsb);

int create_dvs_sysfs_dirs(void);
void remove_dvs_sysfs_dirs(void);

#endif /* _SYS_SETUP_H_ */
