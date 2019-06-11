/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006, 2009, 2011 Cray Inc. All Rights Reserved.
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
 * Attributes maintained within the /proc/sys/fs/dvs namespace,
 * which may be of interest to other kernel modules (especially
 * the SSI infrastructure).
 *
 */

#ifndef __SSI_SYSCTL_H__
#define __SSI_SYSCTL_H__

/* vars */
extern int ssi_nodeid;

/* functions */
extern void ssi_sysctl_register(void);
extern void ssi_sysctl_unregister(void);

#endif /* __SSI_SYSCTL_H__ */
