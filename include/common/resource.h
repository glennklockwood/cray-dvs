/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006, 2008-2012, 2015 Cray Inc. All Rights Reserved.
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

#ifndef RESOURCE_H
#define RESOURCE_H

#define MAX_PFS_NODES 4096 /* fixed maximum nodes per PFS */
#define DEFAULT_PFS_STRIPE_SIZE 524288 /* default PFS stripe size */

struct ioctl_arg {
	void *p1;
	void *p2;
	void *p3;
};

#endif
