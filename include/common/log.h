/*
 * Copyright 2013, 2016-2017 Cray Inc. All Rights Reserved.
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

#ifndef LOG_H
#define LOG_H

#include <linux/jiffies.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#define DVS_MAX_LOGS 4
#define LOG_DVS_LOG 0
#define LOG_IPC_LOG 1
#define LOG_RQ_LOG 2
#define LOG_FS_LOG 3

/* maximum message length in bytes. The message size is stored as an unsigned
 * char, so the max size should not exceed 255. */
#define DVS_LOG_MESSAGE_SIZE 255
#define DVS_LOG_MESSAGE_META_SIZE                                              \
	(offsetof(struct log_message, text) + sizeof(char))
#define DVS_LOG_SIZE_KB 256 /* default log buffer length in KB */
#define DVS_RQ_LOG_SIZE_KB 16384 /* default log buffer length in KB */
#define DVS_RQ_LOG_MIN_TIME_SECS 15 /* minimum time for requests to be logged */
#define DVS_FS_LOG_SIZE_KB 32768 /* default log buffer length in KB */
#define DVS_FS_LOG_MIN_TIME_SECS 15 /* minimum time for fs ops to be logged */
#define DVS_LOG_TEXT_SIZE (DVS_LOG_MESSAGE_SIZE - DVS_LOG_MESSAGE_META_SIZE)

/* Log flags */
#define DVS_LOG_TRUNCATED 0x01

/*
 * Define bits for request log 'control', set via writes to
 * /proc/fs/dvs/request_log
 */
#define DVS_DEBUGFS_RQ_LOG_CONTROL_ENABLE 0x1
#define DVS_DEBUGFS_RQ_LOG_CONTROL_RESET 0x2
#define DVS_DEBUGFS_RQ_LOG_CONTROL_VALID_MASK 0x3

/*
 * Define bits for file system log 'control', set via writes to
 * /proc/fs/dvs/fs_log
 */
#define DVS_DEBUGFS_FS_LOG_CONTROL_ENABLE 0x1
#define DVS_DEBUGFS_FS_LOG_CONTROL_RESET 0x2
#define DVS_DEBUGFS_FS_LOG_CONTROL_VALID_MASK 0x3

/*
 * Note, dvs_log_write does not support the specifying of
 * log levels such as KERN_ERR. Doing so will result in a
 * string that contains ^A (0x01 "SOH"), which can halt
 * parsing, and the log level digit, such as "3" for KERN_ERR.
 */
#define DVS_LOG(args...) dvs_log_write(LOG_DVS_LOG, 0, ##args)
#define DVS_LOGP(args...) dvs_log_write(LOG_DVS_LOG, 1, ##args)
#define IPC_LOG(args...) dvs_log_write(LOG_IPC_LOG, 0, ##args)
#define IPC_LOGP(args...) dvs_log_write(LOG_IPC_LOG, 1, ##args)
#define RQ_LOG(args...) dvs_log_write(LOG_RQ_LOG, 0, ##args)
#define RQ_LOGP(args...) dvs_log_write(LOG_RQ_LOG, 1, ##args)
#define FS_LOG(args...) dvs_log_write(LOG_FS_LOG, 0, ##args)
#define FS_LOGP(args...) dvs_log_write(LOG_FS_LOG, 1, ##args)

/*
 * Access the dvs log as a single buffer starting at the head.
 *
 * This returns &head[offset], with wrap-around. Name and syntax is awkward.
 */
#define DVS_LOG_LINEAR(buf, head, size, offset)                                \
	((unsigned char *)((((head - buf) + offset) % size) + buf))

/*
 * The jiffies value should go first so we don't get a large amount of padding.
 */
struct log_message {
	unsigned long timestamp; /* jiffies */
	unsigned char text_size; /* valid bytes in text */
	unsigned char flags; /* message flags */
	char text[]; /* text, terminated with message size */
};

struct log_info {
	struct log_message *message; /* packing/unpacking buffer */
	char *buf; /* main circular buffer */
	char *head; /* pointer to next insertion point */
	uint size_bytes; /* size of buf in bytes */
	uint size_kb; /* size of buf in kbytes */
	char name[32]; /* name of log */
};

extern int dvs_log_init(int n, uint size_kb, char *name);
extern void dvs_log_exit(int n);
extern int dvs_log_print(int n, struct seq_file *m);
extern void dvs_log_write(int n, int pflg, const char *fmt, ...);
extern void dvs_log_clear(int n);
extern int dvs_log_resize(int n, int new_size_kb);
extern void *dvs_log_handle(int n);
extern uint dvs_log_sizekb(int n);
extern uint dvs_request_log_enabled;
extern uint dvs_request_log_min_time_secs;
extern uint dvs_fs_log_enabled;
extern uint dvs_fs_log_min_time_secs;

#endif /* LOG_H */
