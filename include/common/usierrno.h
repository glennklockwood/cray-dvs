/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006, 2009, 2011, 2014, 2016 Cray Inc. All Rights Reserved.
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

#ifndef USIERRNO_H
#define USIERRNO_H

/*
 * NOTE: these error codes are included in end user documentation.
 * Add to the end, leave unused ones in place, and do not change others
 * without having the appropriate documentation changes made
 * as well.
 */

#define USIERR_NODE_DOWN EHOSTDOWN
#define USIERR_FILE_NOTFOUND ENOENT
#define USIERR_NOT_SUPPORTED ENOSYS
#define USIERR_INTERNAL EIO
#define USIERR_IPC_PROTO EPROTO
#define ESTALE_DVS_RETRY (0x100000 + ESTALE)
#define EQUIESCE (0x100000 + EIO)

#endif
