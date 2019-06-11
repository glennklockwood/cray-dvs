/*
 * Copyright 2018 Cray Inc. All Rights Reserved.
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
 *
 * Ioctl definitions for the userspace thread generator.
 */

#define DVS_DEV_IOCTL_IDENT ((unsigned int)0x4e656c730d0a)

#define DVS_DEV_IOCTL_GET_NUM_INSTANCES                                        \
	_IOWR(DVS_DEV_IOCTL_IDENT, 0, unsigned long)

#define DVS_DEV_IOCTL_WAIT_ON_THREAD_CREATE                                    \
	_IOWR(DVS_DEV_IOCTL_IDENT, 1, unsigned long)

#define DVS_DEV_IOCTL_THREAD_TRAP _IOWR(DVS_DEV_IOCTL_IDENT, 2, unsigned long)
