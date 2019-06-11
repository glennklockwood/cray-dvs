/* -*- c-basic-offset: 4; indent-tabs-mode: nil-*- */
/*
 * Copyright 2009-2017 Cray Inc. All Rights Reserved.
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

#ifndef _DVSIPC_H
#define _DVSIPC_H

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
#include "dvs/dvs_lnetconfig.h"
#include "dvsipc_threads.h"
#include "dvsipc_msg_queue.h"

#if defined(CONFIG_CRAY_ARIES)
#include <aries/aries_timeouts.h>
#endif

#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 10, 55, 0)
typedef struct lnet_handle_eq lnet_handle_eq_t;
typedef struct lnet_handle_me lnet_handle_me_t;
typedef struct lnet_handle_md lnet_handle_md_t;
typedef struct lnet_event lnet_event_t;
typedef enum lnet_event_kind lnet_event_kind_t;
typedef struct lnet_process_id lnet_process_id_t;
typedef struct lnet_md lnet_md_t;
#endif

/*
 * Used in the buffer free code called from the lower transport.  In most cases
 * the "item" passed to it would be a message contained in the buffer.  In some
 * rarer cases, the item is a pointer to the rx buffer itself.
 */
typedef enum { RXSCOPE_Msg, RXSCOPE_Buffer } rxbuf_scope_t;

/*
 * Prototypes for IPC routines implmented by this this
 * module.
 */
uint64_t dvsipc_lnode_to_node(int lnode);
int dvsipc_node_to_lnode(uint64_t node);
void dvsipc_clear_rma_list(int node);
void dvsipc_nak_cleanup(void);
int dvsipc_nak_thread(void *arg);
int dvsipc_alloc_rx_buf(void);

int validate_node(int node);
int node_is_up(int node);
void shutdown_node(int node);
void revive_node(int node, time_t new_identity);

/*
 * Buf header for cached data buffers.
 */
typedef struct dvs_data_buf_hdr {
	struct list_head list;
	unsigned int size;
	unsigned long freetime;
	char buf[1];
} dvs_data_buf_hdr_t;

/*
 * The limit on bytes for the total of all buffers used
 * to hold file system data.
 */
#define DVSIPC_CLIENT_DATA_BUF_LIMIT 0
#define DVSIPC_SERVER_DATA_BUF_LIMIT (100 * 1024 * 1024)

/*
 * The limit on the number of reception buffers used to hold incoming
 * messages.  We don't want this number to be too large.
 *
 * For clients, the likelyhood of ever getting close to this number is
 * small since they're just used to hold replies the ability to process
 * replies is goverened only by the number of message threads.  Buffers
 * can be reused much more quickly in this case.
 *
 * For servers it's a slightly different story.  The ability to process
 * messages is really determined by the underlying file system.  DVS
 * can't just queue incoming messages unbounded since for each message
 * there is a client (with node health watching..) waiting and if a
 * server queues up too many, the possibility of the time to process a
 * given message could be beyond what node health will tolerate and we
 * could lose a client as a result.
 *
 * We'll cap the number of buffers to be a reasonable number.
 */
#define DVSIPC_CLIENT_RX_BUF_LIMIT 512
#define DVSIPC_SERVER_RX_BUF_LIMIT 6144

/*
 * The buffer thread now monitors both data buffers and reception buffers.
 * This is the amount of time in seconds that it sleeps between checks.
 */
#define DVSIPC_CLIENT_BUF_MON_SLEEP (5 * 60)
#define DVSIPC_SERVER_BUF_MON_SLEEP (30)

/*
 * The DVS buffer monitor thread samples every so often to compute the
 * average number of outstanding message buffers.
 * This is that sample rate and is the number of times it wakes up
 * before computing the current average.
 */
#define DVSIPC_BUF_MON_SAMPLE_BITS 3
#define DVSIPC_BUF_MON_SAMPLE_ITERS (1 << DVSIPC_BUF_MON_SAMPLE_BITS)

/*
 * Module tunables.
 */
extern int dvsipc_num_rx_mds;
extern uint dvsipc_tx_timeout;
extern uint dvsipc_response_timeout;
extern uint dvsipc_tx_resend_limit;
extern int dvsipc_msg_thread_limit;
extern int dvsipc_msg_thread_max;
extern int dvsipc_msg_thread_min;
extern int dvsipc_single_msg_queue;

/*
 * Utility macros.
 */
#define IPC_WAIT_FOR_REPLY(msg)                                                \
	(!((msg)->async && ((msg)->reply_address == NULL)))

#define IS_IOPAGE_REQUEST(msg)                                                 \
	((msg)->command == RQ_FILE &&                                          \
	 (((struct file_request *)(msg))->request == RQ_READPAGES_RQ ||        \
	  ((struct file_request *)(msg))->request == RQ_READPAGES_RP ||        \
	  ((struct file_request *)(msg))->request == RQ_READPAGE_ASYNC ||      \
	  ((struct file_request *)(msg))->request == RQ_READPAGE_DATA ||       \
	  ((struct file_request *)(msg))->request == RQ_WRITEPAGES_RQ ||       \
	  ((struct file_request *)(msg))->request == RQ_WRITEPAGES_RP))

#define DVSIPC_MAX_EQS 3

#define DVSIPC_USE_CALLBACK 0
#define DVSIPC_TX_EVENTQ_LEN DVSIPC_USE_CALLBACK
#define DVSIPC_RX_EVENTQ_LEN DVSIPC_USE_CALLBACK
#define DVSIPC_RMA_EVENTQ_LEN DVSIPC_USE_CALLBACK
#define DVSIPC_RMAPUT_EVENTQ_LEN DVSIPC_USE_CALLBACK

#define DVSIPC_MAX_IOVEC 65536

#define DVSIPC_MAX_TX_TICKS 3 /* Ticks to wait for tx response */
#define DVSIPC_RESEND_REQ 0x10101010 /* Tag for resend (nak) requests */
#define DVSIPC_ORPH_REQ 0x01010101 /* Tag for abandoned requests */
#define DVSIPC_IGNORE_NONE 0LL
#define DVSIPC_IGNORE_ONE 1LL /* Certain LNet's need an ignore bit */
#define DVSIPC_IGNORE_ALL ~0LL

#define DVSIPC_NAK_MATCH (~0 ^ 1) /* Match bits for nak request */

#define DVSIPC_ORPH_MATCH                                                      \
	(~0 + 1) /*                                                            \
		  * Match bits for orph request.                               \
		  * Perhaps the hardest way to get a 0?                        \
		  */
#define DVSIPC_ORPH_IGNORE DVSIPC_IGNOREALL

#define DVSIPC_RX_MATCHBITS 0LL

#define DVSIPC_OVERFLOW_TAG (~0) /* User data tag for overflow MD */

/* Buffer size configuration */
#define IPC_MAX_MSG_SIZE MAX_MSG_SIZE /* Size of largest rx buffer */

#define DVSIPC_MAX_MDS 2048
#define DVSIPC_MAX_RX_MDS 128

/* In-flight transmit states */
#define DVSIPC_TX_ORPHANED -1
#define DVSIPC_TX_EXPIRED -2
#define DVSIPC_TX_FAILED -3
#define DVSIPC_TX_COMPLETE -4
#define DVSIPC_TX_RESEND -5

#define DVSIPC_RESPONSE_TIMEOUT 0 /* Timeout for target response */

#if defined(CONFIG_CRAY_ARIES)
#define DVSIPC_TX_TIMEOUT TIMEOUT_SECS(TO_DVS_TX_timeout)
/* Defined in aries_timeouts.h */
#else
#define DVSIPC_TX_TIMEOUT 15 /* Timeout for tx state change */
#endif

#define DVSIPC_RESEND_LIMIT 1000 /* Number of nak/resends per tx */

#define DVSIPC_MSG_THREAD_LIMIT 1000 /* Limit on message threads */

#define DVSIPC_INVALID_NODE (uint64_t)(~0)

#define DVSIPC_DESTROY_THREAD_TIMEOUT 60

#define DVS_DEVICE_FILENAME "dvsipc"

#define _DVS_THREAD_GENERATOR_PATH(prefix) prefix "/dvs_thread_generator"

#ifdef WITH_PREFIX
#define DVS_THREAD_GENERATOR_PATH _DVS_THREAD_GENERATOR_PATH(WITH_PREFIX)
#else
#define DVS_THREAD_GENERATOR_PATH _DVS_THREAD_GENERATOR_PATH("/usr/sbin")
#endif /* WITH_PREFIX */

/* Node type configuration */
typedef enum {
	dvs_config_type_client,
	dvs_config_type_server
} dvs_config_type_t;

extern int dvsipc_config_type;

/*
 * Node states.
 */
enum { NODE_UNKNOWN, /*  0 */
       NODE_READY, /*  1 */
       NODE_DOWN, /*  2 */
       NODE_STATE_END_V1 /*  3 */
};

#define NODE_STATE(__state)                                                    \
	(__state == NODE_READY ? "Ready" :                                     \
				 (__state == NODE_DOWN ? "Down" : "UKNOWN"))

/*
 * The following structure is placed at the head of each rx message
 * buffer.  This allows each buffer to be used for multiple messages.
 */

typedef enum {
	RXBUF_Initial,
	RXBUF_FreelistChained,
	RXBUF_FreelistUnchained,
	RXBUF_NetworkLinked,
	RXBUF_NetworkUnlinked,
	RXBUF_Free,
} rxbuf_state_t;

typedef struct rx_buf_info {
	struct list_head rx_free_list;
	atomic_t rxbuf_state;
	atomic_t rxbuf_refcount;
	int rxbuf_size;
	unsigned long changed_jiffies;
} rx_buf_info_t;

typedef enum {
	RXSLOT_Empty,
	RXSLOT_Filling,
	RXSLOT_Expired,
	RXSLOT_Full
} rx_slot_state_t;

typedef struct rx_buf {
	rx_buf_info_t *rxbuf;
	atomic_t rx_slot_state;
	unsigned int use_count;
} rx_buf_t;

extern rx_buf_t rx_buf_table[];

typedef struct tx_status {
	atomic_t upper_status;
	atomic_t lower_status;
} tx_status_t;

typedef struct {
	struct list_head list;
	uint64_t nid;
	void *rqp;
} ipc_nak_req_t;

/*
 * Special structure for managing in-flight transmits.
 */
typedef struct dvsipc_tx {
	struct semaphore sema;
	struct usiipc msg;
} dvsipc_tx_t;

/*
 * dvsipc_dup_msg() - Utility function to clone a ipc request.
 *
 * This routine handles requests from interrupt mode and
 * handles message aggregation in cases where a message
 * payload is supplied.
 *
 * The wait semaphore is allocated outside of the main structure
 * which prevents the structure from being modified during a
 * transmit operation where checksums may be computed.
 */
static inline struct usiipc *dvsipc_dup_msg(struct usiipc *msg)
{
	int mlen = msg->request_length + sizeof(struct semaphore);
	struct usiipc *newmsg;
	struct semaphore *semap;
	dvsipc_tx_t *txp;

	txp = kmalloc_ssi(mlen, GFP_KERNEL);
	if (!txp) {
		DVS_TRACE("!ssdupms", msg, mlen);
		return NULL;
	}

	newmsg = &txp->msg;
	semap = &txp->sema;

	memcpy((char *)newmsg, msg, msg->request_length);
	sema_init(semap, 0);

	return (newmsg);
}

struct dvsipc_instance_parameters {
	/* can be passed in during module load
	 * 0 - thread_min
	 * 1 - thread_max
	 * 2 - thread_limit
	 * 3 - thread_concurrent_creates
	 * 4 - nice
	 * 5 - single_msg_queue
	 * 6 - init_free_qhdrs
	 * 7 - max_free_qhdrs
	 */
	int param_array[8];
	int count;

	/* thread pool params */
	char thread_name[TASK_COMM_LEN];
	int thread_min;
	int thread_max;
	int thread_limit;
	int thread_concurrent_creates;
	int thread_nice;

	/* inmsgq params */
	char inmsgq_name[TASK_COMM_LEN];
	int single_msg_queue;
	int init_free_qhdrs;
	int max_free_qhdrs;
	msgq_key_t (*get_queue_key)(struct dvsipc_incoming_msgq *inmsgq,
				    struct usiipc *msg);
};

struct dvsipc_instance {
	struct usiipc *mq_active;
	struct kref ref;

	struct dvsipc_thread_pool *thread_pool;
};

int start_thread_generator(struct dvsipc_instance *instance, int instance_id);

void thread_wait(int wait_time, struct semaphore *sema,
		 void (*wakeup_function)(unsigned long), unsigned long arg);
int process_message_thread(void *param);
struct dvsipc_instance *
dvsipc_find_instance(enum dvsipc_instance_id instance_id);

#define dvsipc_get_instance(t) kref_get(&t->ref)
#define dvsipc_put_instance(t) kref_put(&t->ref, dvsipc_free_instance)
extern void dvsipc_free_instance(struct kref *ref);

void add_to_queue(struct usiipc **head, struct usiipc **tail, spinlock_t *qlock,
		  struct semaphore *qsema, struct usiipc *rp);

typedef struct dvsipc_upper_api {
	void (*nak)(uint64_t nid, uint64_t data);
	int (*node_state)(int nid);
	void (*expire_request)(unsigned long arg);
	void (*tx_complete)(struct usiipc *msg, int failed);
	void (*rcv)(struct usiipc *msg);
	void (*putdone)(struct ipc_mapping *handle, int status, void *addr,
			size_t length);
	void (*rx_free)(rxbuf_scope_t buf_scope, void *buf_item);
	void (*rx_detach)(int slot);
} dvsipc_upper_api_t;

/*
 * lower api
 */
extern void ipclower_send_nak(uint64_t nid, void *rqp);
extern int ipclower_tx_request(uint64_t nid, struct usiipc *rq,
			       int resend_limit, int tx_timeout);
extern void *ipclower_mapkvm(char *uvm, ssize_t length, int rw);
extern int ipclower_unmapkvm(void *handle);
extern void *ipclower_mapuvm(char *uvm, ssize_t length, int rw);
extern int ipclower_unmapuvm(void *handle);
extern void *ipclower_rma_put(uint64_t node, char *to, char *from,
			      ssize_t length, rma_info_t *ri, int rma_timeout,
			      int async);
extern void *ipclower_rma_get(uint64_t node, char *to, char *from,
			      ssize_t length, rma_info_t *ri, int rma_timeout,
			      int async);
extern void ipclower_rma_wait(rma_info_t *rip);
extern int ipclower_fill_rx_slot(int i, rx_buf_info_t *bip, int size,
				 unsigned int seq, int invalidate_old);
extern uint64_t ipclower_str2phys(char *tok);
extern int ipclower_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper,
			 ssize_t *max_msg_size, int num_mds);
extern void ipclower_term(void);

#endif /* _DVSIPC_H */
