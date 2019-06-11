/*
 * Unpublished Work  2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work  2004 Cassatt Corporation    All rights reserved.
 * Copyright 2015-2018 Cray Inc. All Rights Reserved.
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

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/utsname.h>
#include <linux/uio.h>
#include <linux/init.h>
#include <linux/kthread.h>

#include "common/sync.h"
#include "common/log.h"
#include "common/kernel/kernel_interface.h"
#include "dvs/kernel/usifile.h"
#include "dvs/dvs_config.h"
#include "dvsipc_msg_queue.h"
#include "dvsipc_threads.h"

static void msgq_add_to_qlist(struct msgq_qheader **qlist,
			      struct msgq_qheader *qhdr);
static void msgq_free_qlist(struct msgq_qheader **qlist, atomic_t *queue_cnt);
static int dvsipc_inmsgq_thread(void *arg);
static void msgq_free_idle_qheader(unsigned long arg);

int dvsipc_start_incoming_msgq(struct dvsipc_incoming_msgq *inmsgq)
{
	struct task_struct *task;

	if (inmsgq->single_msg_queue != 0)
		return 0;

	task = kthread_run(dvsipc_inmsgq_thread, (void *)inmsgq, "%s",
			   inmsgq->thread_name);
	if (IS_ERR(task)) {
		printk(KERN_ERR "DVS: %s: couldn't start inmsgq thread %s. "
				"Error %ld\n",
		       __func__, inmsgq->thread_name, PTR_ERR(task));
		return (int)PTR_ERR(task);
	}

	return 0;
}

struct dvsipc_incoming_msgq *dvsipc_create_incoming_msgq(
	const char *thread_name, unsigned int init_free_qhdrs,
	unsigned int max_free_qhdrs, int single_msg_queue,
	msgq_key_t (*get_queue_key)(struct dvsipc_incoming_msgq *inmsgq,
				    struct usiipc *msg))
{
	struct dvsipc_incoming_msgq *inmsgq;

	inmsgq = kmalloc_ssi(sizeof(struct dvsipc_incoming_msgq), GFP_KERNEL);
	if (inmsgq == NULL) {
		printk("DVS: %s: Error: Unable to allocate incoming message "
		       "queue\n",
		       __func__);
		return NULL;
	}

	inmsgq->init_free_qhdrs = init_free_qhdrs;
	inmsgq->max_free_qhdrs = max_free_qhdrs;
	inmsgq->single_msg_queue = single_msg_queue;
	inmsgq->get_queue_key = get_queue_key;
	strncpy(inmsgq->thread_name, thread_name, TASK_COMM_LEN);

	sema_init(&inmsgq->sema, 0);
	spin_lock_init(&inmsgq->lock);

	sema_init(&inmsgq->thread_sema, 0);
	inmsgq->thread = NULL;

	spin_lock_init(&inmsgq->freepool_sl);
	inmsgq->freepool_list = NULL;
	inmsgq->current_list = NULL;
	inmsgq->anykey_hdr = NULL;

	atomic_set(&inmsgq->incomingq_len, 0);
	atomic_set(&inmsgq->total_qcnt, 0);
	atomic_set(&inmsgq->freepool_qcnt, 0);

	inmsgq->htb =
		vmalloc_ssi((sizeof(msgq_htb_t)) + (sizeof(msgq_htbheader_t) *
						    (INMSGQ_HT_BUCKETS + 1)));
	if (inmsgq->htb == NULL) {
		printk("DVS: %s: Error: Unable to allocate hash table for "
		       "inmsgq 0x%p\n",
		       __func__, inmsgq);
		goto out_error;
	}
	inmsgq->htb->numbits = INMSGQ_HT_BITS;
	inmsgq->htb->numbuckets = INMSGQ_HT_BUCKETS + 1;

	/* Create free pool of msg queue headers */
	msgq_grow_freepool(inmsgq->init_free_qhdrs, inmsgq);
	if (atomic_read(&inmsgq->freepool_qcnt) != inmsgq->init_free_qhdrs) {
		printk("DVS: %s: Error: Could not allocate free pool msgq "
		       "headers for inmsgq 0x%p\n",
		       __func__, inmsgq);
		goto out_error;
	}
	DEBUG_QHEADER("inmsgq 0x%p: freepool allocated", inmsgq->freepool_list);

	/*
	 * Set up list of queues with one general purpose queue to use
	 * if/when a new queue cannot be created.
	 */
	inmsgq->anykey_hdr = msgq_alloc_qheader(inmsgq);
	if (inmsgq->anykey_hdr == NULL) {
		printk("DVS: %s: Error: Could not allocated anykey header for "
		       "inmsgq 0x%p\n",
		       __func__, inmsgq);
		goto out_error;
	}

	msgq_add_to_qlist(&inmsgq->current_list, inmsgq->anykey_hdr);
	inmsgq->htb->buckets[0].qhdr = inmsgq->anykey_hdr;
	DEBUG_QHEADER("inmsgq 0x%p: anykey_hdr allocated", inmsgq->anykey_hdr);

	return inmsgq;

out_error:
	dvsipc_remove_incoming_msgq(inmsgq);
	return NULL;
}

void dvsipc_remove_incoming_msgq(struct dvsipc_incoming_msgq *inmsgq)
{
	msgq_free_qlist(&inmsgq->current_list, &inmsgq->total_qcnt);
	msgq_free_qlist(&inmsgq->freepool_list, &inmsgq->freepool_qcnt);
	vfree_ssi(inmsgq->htb);
	inmsgq->htb = NULL;
	kfree_ssi(inmsgq);
}

void dvsipc_stop_incoming_msgq(struct dvsipc_incoming_msgq *inmsgq)
{
	inmsgq->stop_thread = 1;

	while (inmsgq->thread) {
		up(&inmsgq->thread_sema);
		nap();
	}
}

static inline void msgq_init_qheader(struct msgq_qheader *qhdr)
{
	qhdr->htb_key = 0;
	qhdr->next_htb_chain = NULL;
	qhdr->prev_htb_chain = NULL;
	qhdr->next_queue = NULL;
	qhdr->prev_queue = NULL;
	qhdr->msgq_head = NULL;
	qhdr->msgq_tail = NULL;
}

struct msgq_qheader *msgq_alloc_qheader(struct dvsipc_incoming_msgq *inmsgq)
{
	struct msgq_qheader *qhdr;

	qhdr = kmalloc_ssi(sizeof(msgq_qheader_t), GFP_ATOMIC);
	if (qhdr == NULL) {
		KDEBUG_IPC(0,
			   "DVS: %s: Failed to allocate message queue header "
			   "(ENOMEM).\n",
			   __func__);
	} else {
		msgq_init_qheader(qhdr);
		qhdr->inmsgq = inmsgq;
		setup_timer(&qhdr->idle_timer, msgq_free_idle_qheader,
			    (unsigned long)((void *)qhdr));
		atomic_inc(&inmsgq->total_qcnt);
	}

	return qhdr;
}

static void msgq_free_qheader(struct msgq_qheader *qhdr)
{
	if (qhdr->msgq_head != NULL) {
		printk(KERN_ERR
		       "DVS: %s: Attempt to free queue with "
		       "unprocessed messages; qhdr = 0x%p; msg = 0x%p\n",
		       __func__, qhdr, qhdr->msgq_head);
	}

	del_singleshot_timer_sync(&qhdr->idle_timer);
	kfree_ssi(qhdr);
}

/* Add a qheader to the end of the specified qlist */
void msgq_add_to_qlist(struct msgq_qheader **qlist, struct msgq_qheader *qhdr)
{
	if (*qlist == NULL) {
		qhdr->next_queue = qhdr;
		qhdr->prev_queue = qhdr;
		*qlist = qhdr;
	} else {
		/* add to end of list */
		qhdr->next_queue = *qlist;
		qhdr->prev_queue = (*qlist)->prev_queue;

		(*qlist)->prev_queue->next_queue = qhdr;
		(*qlist)->prev_queue = qhdr;
	}
}

/* Remove the specified queue header from the queue list */
static void msgq_remove_from_qlist(struct msgq_qheader **qlist,
				   struct msgq_qheader *qhdr)
{
	if (*qlist == qhdr) {
		*qlist = qhdr->next_queue;
	}

	qhdr->prev_queue->next_queue = qhdr->next_queue;
	qhdr->next_queue->prev_queue = qhdr->prev_queue;

	if (qhdr->next_queue == qhdr) {
		*qlist = NULL;
	}

	qhdr->next_queue = NULL;
	qhdr->prev_queue = NULL;
}

/* Free all memory associated with a specified queue list */
static void msgq_free_qlist(struct msgq_qheader **qlist, atomic_t *queue_cnt)
{
	struct msgq_qheader *qhdr;
	struct msgq_qheader *next;

	qhdr = *qlist;
	while (qhdr != NULL) {
		next = qhdr->next_queue;
		msgq_free_qheader(qhdr);
		qhdr = (next == *qlist ? NULL : next);
	}

	*qlist = NULL;
	atomic_set(queue_cnt, 0);
}

/* Adds specified number of queue headers to freepool if possible */
void msgq_grow_freepool(int count, struct dvsipc_incoming_msgq *inmsgq)
{
	struct msgq_qheader *qhdr;
	unsigned long flags;
	int idx;

	KDEBUG_IPC(0, "DVS: %s: Grow count %d\n", __func__, count);
	for (idx = 0; idx < count; idx++) {
		qhdr = msgq_alloc_qheader(inmsgq);
		if (qhdr != NULL) {
			spin_lock_irqsave(&inmsgq->freepool_sl, flags);
			msgq_add_to_qlist(&inmsgq->freepool_list, qhdr);
			spin_unlock_irqrestore(&inmsgq->freepool_sl, flags);
			atomic_inc(&inmsgq->freepool_qcnt);
		}
	}
}

/* Frees specified number of queue headers from freepool if possible */
void msgq_shrink_freepool(int count, struct dvsipc_incoming_msgq *inmsgq)
{
	unsigned long flags;
	struct msgq_qheader *qhdr;
	int idx;

	KDEBUG_IPC(0, "DVS: %s: Shrink count %d\n", __func__, count);

	for (idx = 0; idx < count; idx++) {
		spin_lock_irqsave(&inmsgq->freepool_sl, flags);
		qhdr = inmsgq->freepool_list;

		if (qhdr != NULL) {
			msgq_remove_from_qlist(&inmsgq->freepool_list, qhdr);
			spin_unlock_irqrestore(&inmsgq->freepool_sl, flags);
			msgq_free_qheader(qhdr);
			atomic_dec(&inmsgq->freepool_qcnt);
			atomic_dec(&inmsgq->total_qcnt);
		} else {
			spin_unlock_irqrestore(&inmsgq->freepool_sl, flags);
			break;
		}
	}
}

static inline void msgq_add_to_htb(struct msgq_qheader *qhdr, msgq_key_t key)
{
	struct dvsipc_incoming_msgq *inmsgq;
	int32_t hash;

	inmsgq = qhdr->inmsgq;
	hash = MSGQ_HASH(key, inmsgq);

	KDEBUG_IPC(0, "DVS: %s: inmsgq 0x%p, qhdr 0x%p, key %ld, hash %d\n",
		   __func__, inmsgq, qhdr, (long int)key, hash);

	qhdr->htb_key = key;
	qhdr->next_htb_chain = inmsgq->htb->buckets[hash].qhdr;
	qhdr->prev_htb_chain = NULL;
	if (inmsgq->htb->buckets[hash].qhdr != NULL) {
		inmsgq->htb->buckets[hash].qhdr->prev_htb_chain = qhdr;
	}
	inmsgq->htb->buckets[hash].qhdr = qhdr;
}

static inline void msgq_remove_from_htb(struct msgq_qheader *qhdr)
{
	struct dvsipc_incoming_msgq *inmsgq;

	inmsgq = qhdr->inmsgq;

	if (qhdr->prev_htb_chain == NULL) {
		int32_t hash = MSGQ_HASH(qhdr->htb_key, inmsgq);
		inmsgq->htb->buckets[hash].qhdr = qhdr->next_htb_chain;
	} else {
		qhdr->prev_htb_chain->next_htb_chain = qhdr->next_htb_chain;
	}

	if (qhdr->next_htb_chain != NULL) {
		qhdr->next_htb_chain->prev_htb_chain = qhdr->prev_htb_chain;
	}
}

/*
 * Removes a queue header from the hash table and list of active
 * queues; adds qhdr to freepool. Caller must hold incomingq_sl lock.
 */
static void msgq_remove_qheader(struct msgq_qheader *qhdr)
{
	struct dvsipc_incoming_msgq *inmsgq;
	unsigned long flags;

	inmsgq = qhdr->inmsgq;
	if (qhdr == inmsgq->anykey_hdr)
		return;

	DEBUG_QHEADER("", qhdr);

	/* remove from hash table */
	msgq_remove_from_htb(qhdr);

	/* move from list of incoming message queues to free pool */
	msgq_remove_from_qlist(&inmsgq->current_list, qhdr);
	msgq_init_qheader(qhdr); /* reset all the fields */

	spin_lock_irqsave(&inmsgq->freepool_sl, flags);
	msgq_add_to_qlist(&inmsgq->freepool_list, qhdr);
	spin_unlock_irqrestore(&inmsgq->freepool_sl, flags);
	atomic_inc(&inmsgq->freepool_qcnt);
}

/*
 * Move a free qheader to the hash table and qlist. Caller
 * must hold incomingq_sl lock.
 */
static inline struct msgq_qheader *
msgq_get_new_qheader(msgq_key_t key, struct dvsipc_incoming_msgq *inmsgq)
{
	unsigned long flags;
	struct msgq_qheader *qhdr;

	spin_lock_irqsave(&inmsgq->freepool_sl, flags);
	if (inmsgq->freepool_list == NULL) {
		spin_unlock_irqrestore(&inmsgq->freepool_sl, flags);
		up(&inmsgq->thread_sema); /* repopulate freepool in background
					   */

		KDEBUG_IPC(0, "DVS: %s: msgq freepool empty \n", __func__);
		qhdr = msgq_alloc_qheader(inmsgq);
		if (qhdr == NULL)
			return inmsgq->anykey_hdr;
	} else {
		qhdr = inmsgq->freepool_list->next_queue;
		msgq_remove_from_qlist(&inmsgq->freepool_list, qhdr);
		spin_unlock_irqrestore(&inmsgq->freepool_sl, flags);

		atomic_dec(&inmsgq->freepool_qcnt);
		if (atomic_read(&inmsgq->freepool_qcnt) == 0)
			up(&inmsgq->thread_sema);
	}

	msgq_add_to_qlist((void *)&inmsgq->current_list, qhdr);
	msgq_add_to_htb(qhdr, key);

	return qhdr;
}

/*
 * Does a round robin search for the next incoming queue with
 * a message that needs to be processed.
 */
struct msgq_qheader *msgq_get_next_queue(struct dvsipc_incoming_msgq *inmsgq)
{
	struct msgq_qheader *qhdr;

	qhdr = inmsgq->current_list;
	while (qhdr->msgq_head == NULL) {
		qhdr = qhdr->next_queue;

		/* all queues empty */
		if (qhdr == inmsgq->current_list)
			return NULL;
	}

	inmsgq->current_list = qhdr->next_queue;

	return qhdr;
}

/*
 * Removes queue header from active list if no messages have
 * arrived on the queue since the timer was set
 */
static void msgq_free_idle_qheader(unsigned long arg)
{
	struct dvsipc_incoming_msgq *inmsgq;
	unsigned long flags;
	struct msgq_qheader *qhdr;

	qhdr = (struct msgq_qheader *)arg;
	inmsgq = qhdr->inmsgq;

	spin_lock_irqsave(&inmsgq->lock, flags);
	if (qhdr->msgq_head == NULL) {
		/* queue is inactive so move to freepool */
		KDEBUG_IPC(0, "DVS: %s, Found idle queue. qhdr 0x%p now %lu\n",
			   __func__, qhdr, jiffies);
		msgq_remove_qheader(qhdr);
	}
	spin_unlock_irqrestore(&inmsgq->lock, flags);
}

/*
 * Sets time when idle queue timer will trigger; timer struct
 * is initialized when queue header is allocated
 */
void msgq_set_idle_qheader_timer(struct msgq_qheader *qhdr)
{
	unsigned long reset_interval = DVSIPC_INMSGQ_TIMEOUT / 2;
	unsigned long expire;

	if (qhdr == qhdr->inmsgq->anykey_hdr)
		return;

	expire = jiffies + DVSIPC_INMSGQ_TIMEOUT;
	/*
	 * Avoid resetting the timer when queue empties repeatedly in a
	 * short interval. Only reset when the new expire time is more
	 * than half a timeout interval after the current expire time.
	 */
	if (timer_pending(&qhdr->idle_timer) &&
	    time_after(qhdr->idle_timer.expires, expire - reset_interval)) {
		KDEBUG_IPC(0,
			   "DVS: %s: Skip idle timer, qhdr 0x%p, now %lu, cur "
			   "%lu, new %lu\n",
			   __func__, qhdr, jiffies, qhdr->idle_timer.expires,
			   expire);
		return;
	}

	mod_timer(&(qhdr->idle_timer), expire);
	KDEBUG_IPC(0,
		   "DVS: %s: Set idle timer, qhdr 0x%p, now %lu, expires %lu\n",
		   __func__, qhdr, jiffies, expire);
}

msgq_key_t dvsipc_get_queue_key(struct dvsipc_incoming_msgq *inmsgq,
				struct usiipc *msg)
{
	if (msg->command != RQ_FILE)
		return -1;

	return GET_INMSGQ_KEY(msg);
}

int dvsipc_add_msg_to_qheader(struct dvsipc_incoming_msgq *inmsgq,
			      struct usiipc *msg)
{
	struct msgq_qheader *qhdr;
	unsigned long flags;
	msgq_key_t key;
	int hash = 0;

	if (inmsgq->get_queue_key)
		key = inmsgq->get_queue_key(inmsgq, msg);
	else
		key = -1;

	if (key != -1)
		hash = MSGQ_HASH(key, inmsgq);

	KDEBUG_IPC(0, "DVS: %s: msg 0x%p, key 0x%lx, hash %d\n", __FUNCTION__,
		   msg, (long int)key, hash);

	spin_lock_irqsave(&inmsgq->lock, flags);

	/* Invalid keys get put on the anykey header. This includes anything
	 * that isn't an RQ_FILE in the dvs instance */
	if (key == -1) {
		qhdr = inmsgq->anykey_hdr;
		goto found;
	}

	/* Search hash table for msg queue */
	qhdr = inmsgq->htb->buckets[hash].qhdr;
	while (qhdr != NULL) {
		if (qhdr->htb_key == key || inmsgq->single_msg_queue != 0)
			goto found;
		qhdr = qhdr->next_htb_chain;
	}

	/* Not found in hash table so add a queue header for the key */
	qhdr = msgq_get_new_qheader(key, inmsgq);

found:
	add_to_queue(&(qhdr->msgq_head), &(qhdr->msgq_tail), NULL,
		     &inmsgq->sema, msg);
	msg->state = ST_SV_MSG_QUEUED;
	spin_unlock_irqrestore(&inmsgq->lock, flags);

	MSGQ_INC_QLEN(qhdr);
	DEBUG_QHEADER("", qhdr);

	return 0;
}

static void wakeup_inmsgq_thread(unsigned long arg)
{
	struct dvsipc_incoming_msgq *inmsgq;

	inmsgq = (struct dvsipc_incoming_msgq *)arg;
	up(&inmsgq->thread_sema);
}

/*
 * Manages the incoming message queue freepool; moves inactive
 * queues to freepool.
 */
static int dvsipc_inmsgq_thread(void *arg)
{
	struct dvsipc_incoming_msgq *inmsgq;
	int count;

	KDEBUG_IPC(0, "DVS: dvsipc_inmsgq_thread: IN\n");
	inmsgq = (struct dvsipc_incoming_msgq *)arg;
	inmsgq->thread = current;

	while (!inmsgq->stop_thread) {
		thread_wait(DVSIPC_INMSGQ_TIMEOUT, &inmsgq->thread_sema,
			    wakeup_inmsgq_thread, (unsigned long)inmsgq);

		/* Immediate need for more free queue headers */
		count = atomic_read(&inmsgq->freepool_qcnt);
		if (count < inmsgq->init_free_qhdrs) {
			count = inmsgq->init_free_qhdrs - count;
			msgq_grow_freepool(count, inmsgq);
			continue;
		}

		/* Don't let the free pool get too large */
		count = atomic_read(&inmsgq->freepool_qcnt) -
			inmsgq->max_free_qhdrs;
		if (count > 0 && !inmsgq->stop_thread)
			msgq_shrink_freepool(count, inmsgq);
	}

	inmsgq->thread = NULL;

	return 0;
}
