/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2017 Cray Inc. All Rights Reserved.
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

#ifndef USIFILE_H
#define USIFILE_H

struct file_request;
struct file_reply;
struct remote_ref;

typedef int (dvs_rq_func_t)(struct file_request *filerq,
			struct file_reply **filerp_ptr,
			struct remote_ref *rr,
			unsigned long debug);

dvs_rq_func_t
	dvs_rq_lookup,
	dvs_rq_open,
	dvs_rq_close,
	dvs_rq_readdir,
	dvs_rq_create,
	dvs_rq_unlink,
	dvs_rq_ioctl,
	dvs_rq_flush,
	dvs_rq_fsync,
	dvs_rq_fasync,
	dvs_rq_lock,
	dvs_rq_link,
	dvs_rq_symlink,
	dvs_rq_mkdir,
	dvs_rq_rmdir,
	dvs_rq_mknod,
	dvs_rq_rename,
	dvs_rq_readlink,
	dvs_rq_truncate,
	dvs_rq_setattr,
	dvs_rq_getattr,
	dvs_rq_parallel_read,
	dvs_rq_parallel_write,
	dvs_rq_statfs,
	dvs_rq_readpage_async,
	dvs_rq_readpage_data,
	dvs_rq_geteoi,
	dvs_rq_setxattr,
	dvs_rq_getxattr,
	dvs_rq_listxattr,
	dvs_rq_removexattr,
	dvs_rq_verifyfs,
	dvs_rq_ro_cache_disable,
	dvs_rq_permission,
	dvs_rq_sync_update,
	dvs_rq_readpages_rq,
	dvs_rq_readpages_rp,
	dvs_rq_writepages_rq,
	dvs_rq_writepages_rp;

/*
 * usifile.h
 * Definitions of file related request and reply
 */

enum {
    RQ_LOOKUP,
    RQ_OPEN,
    RQ_CLOSE,
    RQ_READDIR,
    RQ_CREATE,
    RQ_UNLINK,
    RQ_IOCTL,
    RQ_FLUSH,
    RQ_FSYNC,
    RQ_FASYNC,
    RQ_LOCK,			/* 10 */
    RQ_LINK,
    RQ_SYMLINK,
    RQ_MKDIR,
    RQ_RMDIR,
    RQ_MKNOD,
    RQ_RENAME,
    RQ_READLINK,
    RQ_TRUNCATE,
    RQ_SETATTR,
    RQ_GETATTR,			/* 20 */
    RQ_PARALLEL_READ,
    RQ_PARALLEL_WRITE,
    RQ_STATFS,
    RQ_READPAGE_ASYNC,
    RQ_READPAGE_DATA,
    RQ_GETEOI,
    RQ_SETXATTR,
    RQ_GETXATTR,
    RQ_LISTXATTR,
    RQ_REMOVEXATTR,		/* 30 */
    RQ_VERIFYFS,
    RQ_RO_CACHE_DISABLE,
    RQ_PERMISSION,
    RQ_SYNC_UPDATE,
    RQ_READPAGES_RQ,
    RQ_READPAGES_RP,
    RQ_WRITEPAGES_RQ,
    RQ_WRITEPAGES_RP,
    RQ_DVS_END_V1,
};

	
static inline char *
file_request_to_string(int request)
{
	switch (request) {
	case RQ_LOOKUP: return "RQ_LOOKUP";
	case RQ_OPEN: return "RQ_OPEN";
	case RQ_CLOSE: return "RQ_CLOSE";
	case RQ_READDIR: return "RQ_READDIR";
	case RQ_CREATE: return "RQ_CREATE";
	case RQ_UNLINK: return "RQ_UNLINK";
	case RQ_IOCTL: return "RQ_IOCTL";
	case RQ_FLUSH: return "RQ_FLUSH";
	case RQ_FSYNC: return "RQ_FSYNC";
	case RQ_FASYNC: return "RQ_FASYNC";
	case RQ_LOCK: return "RQ_LOCK";				/* 10 */
	case RQ_LINK: return "RQ_LINK";
	case RQ_SYMLINK: return "RQ_SYMLINK";
	case RQ_MKDIR: return "RQ_MKDIR";
	case RQ_RMDIR: return "RQ_RMDIR";
	case RQ_MKNOD: return "RQ_MKNOD";
	case RQ_RENAME: return "RQ_RENAME";
	case RQ_READLINK: return "RQ_READLINK";
	case RQ_TRUNCATE: return "RQ_TRUNCATE";
	case RQ_SETATTR: return "RQ_SETATTR";
	case RQ_GETATTR: return "RQ_GETATTR";			/* 20 */
	case RQ_PARALLEL_READ: return "RQ_PARALLEL_READ";
	case RQ_PARALLEL_WRITE: return "RQ_PARALLEL_WRITE";
	case RQ_STATFS: return "RQ_STATFS";
	case RQ_READPAGE_ASYNC: return "RQ_READPAGE_ASYNC";
	case RQ_READPAGE_DATA: return "RQ_READPAGE_DATA";
	case RQ_GETEOI: return "RQ_GETEOI";
	case RQ_SETXATTR: return "RQ_SETXATTR";
	case RQ_GETXATTR: return "RQ_GETXATTR";
	case RQ_LISTXATTR: return "RQ_LISTXATTR";
	case RQ_REMOVEXATTR: return "RQ_REMOVEXATTR";		/* 30 */
	case RQ_VERIFYFS: return "RQ_VERIFYFS";
	case RQ_RO_CACHE_DISABLE: return "RQ_RO_CACHE_DISABLE";
	case RQ_PERMISSION: return "RQ_PERMISSION";
	case RQ_SYNC_UPDATE: return "RQ_SYNC_UPDATE";
	case RQ_READPAGES_RQ: return "RQ_READPAGES_RQ";
	case RQ_READPAGES_RP: return "RQ_READPAGES_RP";
	case RQ_WRITEPAGES_RQ: return "RQ_WRITEPAGES_RQ";
	case RQ_WRITEPAGES_RP: return "RQ_WRITEPAGES_RP";
	case RQ_DVS_END_V1: return "RQ_DVS_END_V1";
	default: return "UNKNOWN";
	}
}
#endif
