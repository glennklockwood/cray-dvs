/*
 * Copyright 2006, 2011, 2014 Cray Inc. All Rights Reserved.
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

#ifndef IOCTL_DESC_HEADER
#define IOCTL_DESC_HEADER

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file ioctl_desc.h"
#endif /* __KERNEL__ */

struct ioctl_desc {
	char	*cmd_name;	/* string for command */
	unsigned int cmd;	/* IOCTL cmd */
	int 	arg_size;	/* Size of argument or reference */
	char	arg_is_ref:1;	/* Passed by value or reference */
	char	arg_rw:1;	/* Passed by reference and not const */
};

extern struct ioctl_desc *get_ioctl_desc(int cmd);

#endif /* IOCTL_DESC_HEADER */
