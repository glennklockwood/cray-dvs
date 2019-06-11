/* -*- c-basic-offset: 4; indent-tabs-mode: nil-*- */
/*
 * Copyright 2015-2017 Cray Inc. All Rights Reserved.
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

#ifndef _DVSIPC_INCOMING_MSGQ_H
#define _DVSIPC_INCOMING_MSGQ_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/page-flags.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/hash.h>

#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/ssi_sysctl.h"
#include "common/kernel/usiipc.h"

/*
 * Incoming message queue hash table
 *
 * Hash table inmsgq_htb is used to find the queue in which to place an
 * incoming message. inmsgq_current is a linked list of the queues
 * that determines the order in which messages are processed. The
 * linked list always contains at least one entry (inmsgq_anykey_hdr)
 * in case memory cannot be allocated for a new entry when one is
 * needed. The inmsgq_anykey_hdr pointer is saved in the first entry of
 * the hash table; it is never deleted while dvs is running. A pool of
 * free queues is maintained in a separate list (inmsgq_freepool).
 *
 * Access to the hash table, the linked list of active queues and the
 * attached message queues are controlled through a single lock
 * (incomingq_sl). Access to the freepool is through a separate lock
 * (inmsgq_freepool_sl).
 */

/*
#define INMSGQ_HT_BITS 10
*/
#define INMSGQ_HT_BITS 10
#define INMSGQ_HT_BUCKETS (1 << INMSGQ_HT_BITS) /* 1024 */

typedef int64_t msgq_key_t;

struct dvsipc_incoming_msgq {
	struct semaphore sema;
	spinlock_t lock;

	struct dvsipc_thread_pool *thread_pool;

	spinlock_t freepool_sl;
	struct msgq_qheader *freepool_list;
	struct msgq_qheader *current_list;
	struct msgq_qheader *anykey_hdr;

	struct msgq_htb *htb;

	atomic_t incomingq_len;
	atomic_t total_qcnt; /* includes freepool */
	atomic_t freepool_qcnt;

	int single_msg_queue;
	int init_free_qhdrs;
	int max_free_qhdrs;
	msgq_key_t (*get_queue_key)(struct dvsipc_incoming_msgq *inmsgq,
				    struct usiipc *msg);

	struct task_struct *thread;
	char thread_name[TASK_COMM_LEN];
	struct semaphore thread_sema;
	int stop_thread;
};

typedef struct msgq_qheader {
	msgq_key_t htb_key;
	/* hash table collision chain */
	struct msgq_qheader *next_htb_chain;
	struct msgq_qheader *prev_htb_chain;

	/* list of active or free queue headers */
	struct msgq_qheader *next_queue;
	struct msgq_qheader *prev_queue;

	/* list of messages assigned to this queue */
	struct usiipc *msgq_head;
	struct usiipc *msgq_tail;

	struct dvsipc_incoming_msgq *inmsgq;

	/*
	 * Check for idle queues: when timer is triggered, free the queue
	 * if the queue is still empty. Timer is allocated and freed with
	 * the queue header; expiration time is updated when the last
	 * message is processed.
	 */
	struct timer_list idle_timer;
} msgq_qheader_t;

typedef struct msgq_htbheader {
	struct msgq_qheader *qhdr;
	/*
	 *# messages that hash to queues in this bucket; summed by bucket
	 * instead of by queue to approx. msgs per queue w/o requiring the
	 * active queue list to be locked
	 */
	atomic_t qlen;
} msgq_htbheader_t;

typedef struct msgq_htb *msgq_htb_ptr;
typedef struct msgq_htb {
	int32_t numbits;
	int32_t numbuckets;
	msgq_htbheader_t buckets[0];
} msgq_htb_t;

#define GET_INMSGQ_KEY(msg) (((struct file_request *)(msg))->context.jobid)

#define MSGQ_HASH(key, inmsgq)                                                 \
	(inmsgq->single_msg_queue ?                                            \
		 0 :                                                           \
		 (hash_long(key, inmsgq->htb->numbits) + 1))

/* controls cleanup of inactive incoming message queues */
#define DVSIPC_INMSGQ_TIMEOUT (360 * HZ)

#define DVSIPC_INMSGQ_FREEPOOL_MIN                                             \
	dvs_cur_config_params->msgq_init_free_qhdrs / 4

#define MSGQ_INC_QLEN(qhdr)                                                    \
	{                                                                      \
		atomic_inc(&qhdr->inmsgq->incomingq_len);                      \
		qhdr == qhdr->inmsgq->anykey_hdr ?                             \
			atomic_inc(&qhdr->inmsgq->htb->buckets[0].qlen) :      \
			atomic_inc(                                            \
				&(qhdr->inmsgq->htb                            \
					  ->buckets[MSGQ_HASH(qhdr->htb_key,   \
							      qhdr->inmsgq)]   \
					  .qlen));                             \
	}
#define MSGQ_DEC_QLEN(qhdr)                                                    \
	{                                                                      \
		atomic_dec(&qhdr->inmsgq->incomingq_len);                      \
		qhdr == qhdr->inmsgq->anykey_hdr ?                             \
			atomic_dec(&qhdr->inmsgq->htb->buckets[0].qlen) :      \
			atomic_dec(                                            \
				&(qhdr->inmsgq->htb                            \
					  ->buckets[MSGQ_HASH(qhdr->htb_key,   \
							      qhdr->inmsgq)]   \
					  .qlen));                             \
	}

#define DEBUG_QHEADER(str, qhdr)                                               \
	if (qhdr == NULL) {                                                    \
		KDEBUG_IPC(0, "DVS: %s: %s: qhdr (null)\n", __FUNCTION__,      \
			   str);                                               \
	} else {                                                               \
		KDEBUG_IPC(                                                    \
			0,                                                     \
			"DVS: %s: %s: qhdr 0x%p, key %ld, qlist 0x%p:0x%p, "   \
			"msghead 0x%p:0x%p, chain 0x%p:0x%p\n",                \
			__FUNCTION__, str, qhdr, (long int)qhdr->htb_key,      \
			qhdr->prev_queue, qhdr->next_queue, qhdr->msgq_tail,   \
			qhdr->msgq_head, qhdr->prev_htb_chain,                 \
			qhdr->next_htb_chain);                                 \
	}

extern int dvsipc_start_incoming_msgq(struct dvsipc_incoming_msgq *inmsgq);
struct dvsipc_incoming_msgq *dvsipc_create_incoming_msgq(
	const char *thread_name, unsigned int init_free_qhdrs,
	unsigned int max_free_qhdrs, int single_msg_queue,
	msgq_key_t (*get_queue_key)(struct dvsipc_incoming_msgq *inmsgq,
				    struct usiipc *msg));
extern void dvsipc_remove_incoming_msgq(struct dvsipc_incoming_msgq *inmsgq);
extern void dvsipc_stop_incoming_msgq(struct dvsipc_incoming_msgq *inmsgq);

extern void msgq_shrink_freepool(int count,
				 struct dvsipc_incoming_msgq *inmsgq);
extern void msgq_grow_freepool(int count, struct dvsipc_incoming_msgq *inmsgq);
extern struct msgq_qheader *
msgq_alloc_qheader(struct dvsipc_incoming_msgq *inmsgq);
extern struct msgq_qheader *
msgq_get_next_queue(struct dvsipc_incoming_msgq *inmsgq);

extern msgq_key_t dvsipc_get_queue_key(struct dvsipc_incoming_msgq *inmsgq,
				       struct usiipc *msg);

int dvsipc_add_msg_to_qheader(struct dvsipc_incoming_msgq *inmsgq,
			      struct usiipc *msg);
void msgq_set_idle_qheader_timer(struct msgq_qheader *qhdr);

#endif /* _DVSIPC_INCOMING_MSGQ_H */
