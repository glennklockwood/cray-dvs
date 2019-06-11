/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Copyright 2006-2007, 2009-2011, 2014-2016 Cray Inc. All Rights Reserved.
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
 *
 */

#ifndef USIFUNC_H
#define USIFUNC_H

/*
 * IPC operations.
 */
enum { RQ_FILE = 0x100, /* 0x100 256 */
       RQ_REPLY,
       RQ_RMA_GET,
       RQ_RMA_PUT,
       RQ_CALLBACK,
       RQ_IPC_FAILURE,
       RQ_RESOURCE,
       RQ_IPC_NODE_UP,
       RQ_REPLY_ERROR,
       RQ_IPC_NODE_DOWN,
       RQ_IPC_HEARTBEAT,
       RQ_WAITING_REPLY,
       RQ_RESOURCE_CLIENT,
       RQ_IPC_DISPOSE,
       RQ_SUSPECT,
       RQ_DSD,
       RQ_DSDB,
       RQ_DSDC,
       /* RQ_LAST_IN_LIST must be last */
       RQ_LAST_IN_LIST };

#endif
