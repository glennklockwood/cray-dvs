/* -*- c-basic-offset: 4; indent-tabs-mode: nil-*- */
/*
 * Copyright 2015-2016 Cray Inc. All Rights Reserved.
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

#ifndef _DVSIPC_THREADS_H
#define _DVSIPC_THREADS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/hash.h>
#include <asm/io.h>

#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/ssi_sysctl.h"
#include "common/kernel/usiipc.h"
#include "dvs/kernel/usifile.h"
#include "dvsipc.h"

#define DVSIPC_DESTROY_THREAD_TIMEOUT 60

enum dvsipc_thread_state {
	DVSIPC_THREAD_IDLE,
	DVSIPC_THREAD_BUSY,
	DVSIPC_THREAD_BLOCKED,
	DVSIPC_THREAD_EXIT,
	DVSIPC_THREAD_DESTROY,
	DVSIPC_THREAD_STATE_MAX
};

enum dvsipc_thread_pool_state {
	DVSIPC_THREAD_POOL_INIT,
	DVSIPC_THREAD_POOL_ACTIVE,
	DVSIPC_THREAD_POOL_DESTROY,
	DVSIPC_THREAD_POOL_STATE_MAX
};

struct dvsipc_thread {
	struct list_head list;
	struct list_head state_list;
	struct kref ref;

	struct dvsipc_thread_pool *thread_pool;

	struct task_struct *task;
	struct usiipc *msg;
	unsigned long timestamp;
	enum dvsipc_thread_state state;
};

struct dvsipc_thread_pool {
	struct dvsipc_instance *instance;
	struct dvsipc_incoming_msgq *inmsgq;
	enum dvsipc_thread_pool_state state;

	unsigned int thread_count;
	unsigned int threads_created;
	unsigned int in_progress_creates;
	unsigned int max_concurrent_creates;
	struct list_head thread_list;

	unsigned int state_counts[DVSIPC_THREAD_STATE_MAX];
	struct list_head state_lists[DVSIPC_THREAD_STATE_MAX];
	spinlock_t lock;

	unsigned int thread_limit;
	unsigned int thread_min;
	unsigned int thread_max;
	char thread_name[TASK_COMM_LEN];
	int nice;
};

#define dvsipc_set_thread_idle(t) dvsipc_set_thread_state(t, DVSIPC_THREAD_IDLE)
#define dvsipc_set_thread_busy(t) dvsipc_set_thread_state(t, DVSIPC_THREAD_BUSY)
#define dvsipc_set_thread_blocked(t) dvsipc_set_thread_state(t, DVSIPC_THREAD_BLOCKED)
#define dvsipc_set_thread_exit(t) dvsipc_set_thread_state(t, DVSIPC_THREAD_EXIT)
#define dvsipc_set_thread_destroy(t) dvsipc_set_thread_state(t, DVSIPC_THREAD_DESTROY)

#define dvsipc_idle_threads(p) (p->state_counts[DVSIPC_THREAD_IDLE])
#define dvsipc_busy_threads(p) (p->state_counts[DVSIPC_THREAD_BUSY])
#define dvsipc_blocked_threads(p) (p->state_counts[DVSIPC_THREAD_BLOCKED])
#define dvsipc_exit_threads(p) (p->state_counts[DVSIPC_THREAD_EXIT])
#define dvsipc_destroy_threads(p) (p->state_counts[DVSIPC_THREAD_DESTROY])

#define dvsipc_get_thread(t) kref_get(&t->ref)
#define dvsipc_put_thread(t) kref_put(&t->ref, dvsipc_free_thread)
extern void dvsipc_free_thread(struct kref *ref);

extern int dvsipc_set_thread_state(struct dvsipc_thread *thread, enum dvsipc_thread_state state);

extern int dvsipc_check_exit_thread(struct dvsipc_thread *thread);
extern int dvsipc_check_create_thread(struct dvsipc_thread_pool *thread_pool);

extern int dvsipc_start_thread_pool(struct dvsipc_thread_pool *thread_pool);
extern int dvsipc_stop_thread_pool(struct dvsipc_thread_pool *thread_pool);
extern int dvsipc_remove_thread_pool(struct dvsipc_thread_pool *thread_pool);
extern struct dvsipc_thread_pool *dvsipc_create_thread_pool(const char *name,
                                                            unsigned int max_threads,
                                                            unsigned int min_threads,
                                                            unsigned int start_threads,
                                                            unsigned int concurrent_creates,
                                                            int nice);

#endif  /* _DVSIPC_H */

