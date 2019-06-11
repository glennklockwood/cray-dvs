/*
 * $Id:
 */

/*
 * Unpublished Work / 2004 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006-2007, 2009, 2011, 2014-2015, 2017 Cray Inc. All Rights
 * Reserved.
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

#ifndef USISUPER_H
#define USISUPER_H

/* This is needed to get MAX_PFS_NODES. */
#include "common/resource.h"

#define UPFS_SUPER_PREFIX "...dvs_"

#define UPFS_MAXNAME 256
/*
 * Bug: http://bugzilla.us.cray.com/show_bug.cgi?id=799834
 * Increase the default timeout to 3 seconds vs no caching
 */
#define UPFS_ATTRCACHE_DEFAULT "3"
#define UPFS_MAXSERVERS 1024

#define DVS_FTYPE_MAGIC 0x3e3f

#ifdef __KERNEL__
#include "dvs/kernel/usisuper.h"
#endif

#endif /* USISUPER_H */
