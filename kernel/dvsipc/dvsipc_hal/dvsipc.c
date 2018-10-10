/*
 * Unpublished Work  2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work  2004 Cassatt Corporation    All rights reserved.
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

/*
 * Upper half dvsipc driver. The interfaces implemented in this file are
 * shared between the portals and lnet lower half modules.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mount.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/hardirq.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/utsname.h>
#include <linux/uio.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include <asm/system.h>
#else
#include <asm/barrier.h>
#include <asm/mmu_context.h>
#endif
#include <asm/bitops.h>
#include <asm/dma.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/nmi.h>
#include <linux/kthread.h>
#include <linux/fs_struct.h>
#include <linux/mman.h>
#include <linux/buffer_head.h>

#if USE_RCA
#include <krca_lib.h>
#include <rsms/rs_sm_states.h>
#endif

#undef MAX_MSG_SIZE
#define MAX_MSG_SIZE        (34*1024)

#include "common/sync.h"
#include "common/log.h"
#include "common/kernel/kernel_interface.h"
#include "dvs/kernel/usifile.h"
#include "dvsipc.h"
#include "dvsipc_threads.h"
#include "dvsipc_msg_queue.h"

static struct dvsipc_instance *dvsipc_instances[DVSIPC_INSTANCE_MAX];
static DEFINE_SPINLOCK(dvsipc_instance_lock);
static struct dvsipc_instance_parameters instance_params[DVSIPC_INSTANCE_MAX] =
{
	{ /* DVS */
		/* most of the defaults from DVS come from the config params */
		.thread_name = "DVS-IPC_msg",
		.thread_concurrent_creates = 0,
		.thread_nice = 0,
		.inmsgq_name = "DVS-IPC_inmsgq",
		.get_queue_key = dvsipc_get_queue_key,
	},
	{ /* kdwfs */
		.thread_name = "kdwfs_msg",
		.thread_min = 1,
		.thread_max = 1,
		.thread_limit = 1024,
		.thread_concurrent_creates = 4,
		.thread_nice = -10,
		.inmsgq_name = "kdwfs_inmsgq",
		.single_msg_queue = 1,
		.init_free_qhdrs = 1,
		.max_free_qhdrs = 1,
		.get_queue_key = NULL,
	},
	{ /* kdwfsb (broadcast) */
		.thread_name = "kdwfsb_msg",
		.thread_min = 1,
		.thread_max = 1,
		.thread_limit = 1024,
		.thread_concurrent_creates = 4,
		.thread_nice = -10,
		.inmsgq_name = "kdwfsb_inmsgq",
		.single_msg_queue = 1,
		.init_free_qhdrs = 1,
		.max_free_qhdrs = 1,
		.get_queue_key = NULL,
	},
	{ /* DWCFS */
		.thread_name = "kdwcfs_msg",
		.thread_min = 1,
		.thread_max = 1,
		.thread_limit = 1024,
		.thread_concurrent_creates = 4,
		.thread_nice = -10,
		.inmsgq_name = "kdwcfs_inmsgq",
		.single_msg_queue = 1,
		.init_free_qhdrs = 1,
		.max_free_qhdrs = 1,
		.get_queue_key = NULL,
	}
};

struct usiipc *mq_head;
struct usiipc *mq_tail;
struct usiipc *mq_waiting;
static DEFINE_SPINLOCK(mq_sl);
static long direct_sends, indirect_sends;

uint ipc_log_size_kb = DVS_LOG_SIZE_KB;

static atomic64_t requests_killed = ATOMIC_INIT(0);
atomic_t rx_buffer_count = ATOMIC_INIT(0);
int rx_buffer_count_minimum = 0;
atomic_t freelist_buffer_count = ATOMIC_INIT(0);
unsigned long freelist_jiffies;

LIST_HEAD(dvsipc_free_list);
DEFINE_SPINLOCK(dvsipc_free_list_lock);
LIST_HEAD(dvsipc_resend_list);
DEFINE_SPINLOCK(dvsipc_resend_list_lock);
LIST_HEAD(dvsipc_rma_list);
DEFINE_SPINLOCK(dvsipc_rma_list_lock);
LIST_HEAD(dvsipc_buf_list);
DEFINE_SPINLOCK(dvsipc_buf_list_lock);

typedef enum { Node_Status_Up, Node_Status_Down, Node_Status_Revive } node_status_t;

static struct task_struct *hb_thread = NULL;
static struct task_struct *refill_thread = NULL;
static struct task_struct *nak_thread = NULL;
static struct task_struct *buf_thread = NULL;
int dvsipc_buf_thread(void *arg);

static int dvsipc_rma_page_limit = 256;

static int shutdown = 0;
static sigset_t sigmask;
int max_nodes = 0;

static int dvsipc_init_complete = 0;

static int dvsipc_buf_cache_bytes = 0;
static int dvsipc_alloc_msg_threads;
static int max_buffer_count;

typedef struct dvs_config_params {
    int msg_threads;     /* # threads created */
    int max_msg_threads; /* # entries in msg_threads table */
    int rsv_bufs;        /* init # bufs on free list */
    int msg_per_buf;     /* determines buf size */
    int tx_credits;
    int msgq_init_free_qhdrs; /* initial length of inmsgq_freepool */
    int msgq_max_free_qhdrs;  /* max length of inmsgq_freepool */

    /* config params that can be overriden by module params */
    int buf_limit;
    int buf_timeout;

    int send_rca_event;  /* tell others we're here? */
} dvs_config_params_t;

static dvs_config_params_t dvs_config_params[2] =
{
	{ /*client */
		.msg_threads = 4,
		.max_msg_threads = 16,
		.rsv_bufs = 4,
		.msg_per_buf =8,
		.tx_credits = 32,
		.msgq_init_free_qhdrs = 1,
		.msgq_max_free_qhdrs = 1,
		.buf_limit = 0,
		.buf_timeout = 0,
		.send_rca_event = 0
	},
	{ /* server */
		.msg_threads = 16,
		.max_msg_threads = 64,
		.rsv_bufs = 16,
		.msg_per_buf = 64,
		.tx_credits = 256,
		.msgq_init_free_qhdrs = 64,
		.msgq_max_free_qhdrs = 2048,
		.buf_limit = DVSIPC_BUF_LIMIT,
		.buf_timeout = DVSIPC_BUF_TIMEOUT,
		.send_rca_event = 1
	},
};

static dvs_config_params_t *dvs_cur_config_params = NULL;

#define DVSIPC_THREE_MINUTE 180*HZ
#define DVSIPC_ONE_MINUTE    60*HZ

#define DVSIPC_RX_BUF_SIZE ((dvs_cur_config_params->msg_per_buf * MAX_MSG_SIZE) \
				+ sizeof(rx_buf_info_t))

struct remote_info {
    time_t		identity;
    struct list_head	msgs;
    spinlock_t		lock;
    node_status_t	node_status;
};
static struct remote_info *remote_node_info = NULL;
static time_t local_identity = 0;

/*
 * Link in-process messages to their per-node list.
 */
static void
link_rx_msg(struct usiipc *msg)
{
    unsigned long flags;
    struct remote_info *rni = &remote_node_info[msg->source_node];

    spin_lock_irqsave(&rni->lock, flags);
    msg->state = ST_SV_RECEIVED;
    list_add(&msg->active_rx, &rni->msgs);
    spin_unlock_irqrestore(&rni->lock, flags);
}

/*
 * Remove completed message from the in-process list.
 */
static void
unlink_rx_msg(struct usiipc *msg)
{
    unsigned long flags;
    struct remote_info *rni = &remote_node_info[msg->source_node];

    if (list_empty(&msg->active_rx)) {
        return;
    }

    spin_lock_irqsave(&rni->lock, flags);
    if (list_empty(&rni->msgs)) {
        spin_unlock_irqrestore(&rni->lock, flags);
        return;
    } 
    BUG_ON(msg->state == ST_FREE);
    list_del(&msg->active_rx);
    msg->state = ST_FREE;

    spin_unlock_irqrestore(&rni->lock, flags);
}

/* forward */
static int do_callback(struct usiipc *request);
static void process_incoming_request (struct usiipc *rq);
static void dvsipc_do_process_ipc_reply(struct usiipc *reply);
static void *dvsipc_rma_get(int node, char *to, char *from, 
				ssize_t length, void *rma_handle, int async);
static void *dvsipc_rma_put(int node, char *to, char *from, 
				ssize_t length, void *rma_handle, int async);
static void dvsipc_rma_wait(rma_info_t *rip);
static dvs_tx_desc_t dvsipc_register_ipc_request(struct usiipc *request);
static int dvsipc_send_ipc_request(struct usiipc *request);
static int dvsipc_send_ipc_request_async(struct usiipc *request);
static void cleanup_stale_messages(int node, time_t identity);
extern void uss_reset_pidbase(int);
static void dvsipc_nak(uint64_t nid, uint64_t hdr_data);
static int dvsipc_node_state(int node);
static void dvsipc_expire_request(unsigned long arg);
static void dvsipc_tx_complete(struct usiipc *msg, int failed);
static void dvsipc_do_rcv(struct usiipc *msg);
static void dvsipc_rma_put_complete(struct ipc_mapping *handle, int status,
				void *addr, size_t length);
static int dvsipc_wait_for_async_request(struct usiipc *request);
static int write_message_to_transport(struct usiipc *);
static void dvsipc_block_thread(void);
static void dvsipc_release_thread(void);
static inline char *dvsipc_requests_fp_path(struct file_request *filerq, char *path);
static char *dvsipc_requests_get_path(struct file_request *filerq, char *path);

static int dvsipc_proc_init(void);
static void dvsipc_proc_term(void);
static void dvsipc_ipc_term(void);
void   dvsipc_cleanup_freelist(void);

int (*usi_callback)(int cmd, void *data) = NULL;
EXPORT_SYMBOL(usi_callback);

extern struct ssi_node_map *node_map;

struct semaphore nak_sema;
struct semaphore ipc_tx_sema;
struct semaphore refill_sema;
struct semaphore buf_sema;

/* 
 * The following structures and macros are used for the collection of
 * message activity statistics within the ipc code. This data is made
 * available through the /proc/fs/dvs/ipc/stats file.
 */

typedef struct ipcstats {
    char   *str;
    uint64_t val;
} ipcstats_t;

enum {DVSIPC_STAT_PUT, DVSIPC_STAT_GET, DVSIPC_STAT_TX, DVSIPC_STAT_RX,
      DVSIPC_STAT_REPLY, DVSIPC_STAT_PUT_BYTES, DVSIPC_STAT_GET_BYTES,
      DVSIPC_STAT_TX_BYTES, DVSIPC_STAT_RX_BYTES, DVSIPC_STAT_REPLY_BYTES,
      DVSIPC_STAT_MAPUVM, DVSIPC_STAT_UNMAPUVM,
      DVSIPC_STAT_MAPKVM, DVSIPC_STAT_UNMAPKVM,
      DVSIPC_STAT_MAPUPGS, DVSIPC_STAT_UNMAPUPGS,
      DVSIPC_STAT_MAPKPGS, DVSIPC_STAT_UNMAPKPGS,
      DVSIPC_STAT_ERROR, DVSIPC_STAT_NAK,
      DVSIPC_STAT_REFILL, DVSIPC_STAT_DUPS,
      DVSIPC_NSTATS};

static ipcstats_t ipcstats[DVSIPC_NSTATS] = {
     {"RMA Puts", 0},
     {"RMA Gets", 0},
     {"Transmits", 0},
     {"Receives", 0},
     {"Replies", 0},
     {"RMA Put Bytes", 0},
     {"RMA Get Bytes", 0},
     {"Tx Bytes", 0},
     {"Rx Bytes", 0},
     {"Reply Bytes", 0},
     {"User Maps", 0},
     {"User Unmaps", 0},
     {"Kernel Maps", 0},
     {"Kernel Unmaps", 0},
     {"User Pages Mapped", 0},
     {"User Pages Unmapped", 0},
     {"Kernel Pages Mapped", 0},
     {"Kernel Pages Unmapped", 0},
     {"Errors", 0},
     {"NAKs", 0},
     {"Rx Buffer Refills", 0},
     {"Rx Dups", 0},
};

#define DVSIPC_TX_NTYPES        5
#define DVSIPC_SIZE_NBUCKETS    8

static uint64_t ipcsizes[DVSIPC_TX_NTYPES][DVSIPC_SIZE_NBUCKETS];
static char *ipcsizestr[DVSIPC_SIZE_NBUCKETS] = {"<=512B", "<=1KB", "<=2KB",
                                          "<=4KB", "<=16KB", "<=64KB", 
                                          "<=1MB", ">1MB"};
static char *ipcopstr[DVSIPC_TX_NTYPES] = {"Put", "Get", "Tx", "Rx", "Rply"};

#define DVSIPC_SIZE_BUCKET(size)((size) <= 512 ?          0 : \
                                 (size) <= (1*1024) ?     1 : \
                                 (size) <= (2*1024) ?     2 : \
                                 (size) <= (4*1024) ?     3 : \
                                 (size) <= (16*1024) ?    4 : \
                                 (size) <= (64*1024) ?    5 : \
                                 (size) <= (1024*1024) ?  6 : \
                                 7)

#define DVSIPC_STAT_INC(x,y)    ipcstats[(x)].val += (y);
#define DVSIPC_SIZE_INC(x,y)    ipcsizes[(x)][DVSIPC_SIZE_BUCKET(y)]++;

/*
 * If DVS is using RCA for event notification, we define a few required
 * service interface parameters.
 */
#if USE_RCA
#define DVS_RCA_RX          RCA_RX_SVC_TYPE(RCA_SVCTYPE_DVS)
#define DVS_RCA_TX(nodeid)  RCA_TX_SVC_TYPE_NODE(RCA_SVCTYPE_DVS, nodeid)

/*
 * RCA identifier debugging routines.
 */
static inline char *
svctype(rs_service_t t)
{
    static char s[16];
    switch(t)
    {
        case RCA_SVCTYPE_NONE:
            return "NONE";
        case RCA_SVCTYPE_CLIENT:
            return "CLIENT";
        case RCA_SVCTYPE_NODE:
            return "NODE";
        case RCA_SVCTYPE_RCAD:
            return "RCAD";
        case RCA_SVCTYPE_L0:
            return "L0";
        case RCA_SVCTYPE_RCADSVCS:
            return "RCADSVCS";
        case RCA_SVCTYPE_CONS:
            return "CONS";
        case RCA_SVCTYPE_LOGGER:
            return "LOGGER";
        case RCA_SVCTYPE_SDBD:
            return "SDBD";
        case RCA_SVCTYPE_TEST0:
            return "TEST0";
        case RCA_SVCTYPE_TEST1:
            return "TEST1";
        case RCA_SVCTYPE_TEST2:
            return "TEST2";
        case RCA_SVCTYPE_TEST3:
            return "TEST3";
        case RCA_SVCTYPE_FAILMNGR:
            return "FAILMNGR";
        case RCA_SVCTYPE_BND:
            return "BND";
        case RCA_SVCTYPE_LUSTRE_PROXY:
            return "LUSTRE_PROXY";
        case RCA_SVCTYPE_DVS:
            return "DVS";
        case RCA_SVCTYPE_ANY:
            return "ANY";
        default:
            sprintf(s,"<%d>",(int)t);
            return s;
    }
}

static inline char *
instype(rs_instance_t t)
{
    static char s[16];

    switch(t)
    {
        case RCA_INST_NONE:
            return "NONE";
        case RCA_INST_ANY:
            return "ANY";
        default:
            sprintf(s,"%d",t);
            return s;
    }
}

static inline char *
nodetype(rs_node_t t)
{
    static char s[16];

    /* Cast rsn_type to an unsigned int to avoid compiler warning about rt_last
        being too large to fit into rsn_type's number of bits */
    switch((unsigned int) t.rsn_type)
    {
        case rt_node:
            return "node";
        case rt_l0:
            return "l0";
        case rt_cage:
            return "cage";
        case rt_l1:
            return "l1";
        case rt_smw:
            return "smw";
        case rt_sicproc:
            return "sicproc";
        case rt_link:
            return "link";
        case rt_section:
            return "section";
        case rt_proc_unit:
            return "proc_unit";
        case rt_none:
            return "none";
        case rt_part:
            return "part";
        case rt_service_all:
            return "service_all";
        case rt_compute_all:
            return "compute_all";
        case rt_all:
            return "all";
        case rt_last:
            return "last";
        default:
            sprintf(s,"%d",t.rsn_type); return s;
    }
}

static inline char *
evttype(rs_event_code_t t)
{
    static char s[16];

    switch(t)
    {
        case ec_dvs_service_started:
            return "ec_dvs_service_started";
        case ec_rca_l0_subscribe:
            return "rca_l0_subscribe";
        case ec_rca_l0_unsubscribe:
            return "rca_l0_unsubscribe";
        case ec_rca_get_meshcoords:
            return "rca_get_meshcoords";
        case ec_console_log:
            return "console_log";
        case ec_node_failed:
            return "node_failed";
        case ec_node_unavailable:
            return "ec_node_unavailable";
        case ec_node_available:
            return "ec_node_available";
        case ec_service_failed:
            return "service_failed";
        case ec_rca_shutdown:
            return "rca_shutdown";
        case ec_service_started:
            return "service_started";
        case ec_rca_svcgone:
            return "rca_svcgone";
        case ec_rca_init:
            return "rca_init";
        case ec_rca_exit:
            return "rca_exit";
        case ec_rca_host_cmd:
            return "rca_host_cmd";
        case ec_rca_host_cmd_rsp:
            return "rca_host_cmd_rsp";
        case ec_any_event:
            return "any_event";
        default:
            sprintf(s,"<%x>",(int)t);
            return s;
    }
}
#endif

/*
 * dvsipc upper-half API callbacks
 */
static dvsipc_upper_api_t upper_api = {
    .nak            = dvsipc_nak,
    .node_state     = dvsipc_node_state,
    .expire_request = dvsipc_expire_request,
    .tx_complete    = dvsipc_tx_complete,
    .rcv            = dvsipc_do_rcv,
    .putdone        = dvsipc_rma_put_complete,
    .free           = dvsipc_free,
};

/*
 * The following are used to provide logical (dvs) to physical (transport) node
 * ID translation.
 */
struct node_entry {
    uint64_t pnode; /* opaque physical transport id */
} *node_list = NULL;

static void
dvsipc_init_node_list(void) 
{
    if (node_list == NULL && node_map != NULL) {
        int node;
        node_list = vmalloc_ssi(max_nodes * sizeof(struct node_entry));
        if (node_list == NULL) {
            KDEBUG_IPC(0, "%s: can't allocate node_list\n", __FUNCTION__);
            return;
        }

        KDEBUG_IPC(0, "%s: node_list = 0x%p\n", __FUNCTION__, node_list);
        memset(node_list, -1, sizeof(struct node_entry) * max_nodes);

        for (node = 0; node < max_nodes && node_map[node].tok; node++) {
            node_list[node].pnode = ipclower_str2phys(node_map[node].tok);
            KDEBUG_IPC(0, "%s: lnode[%d] = 0x%Lx\n", __FUNCTION__,
                node, node_list[node].pnode);
        }
    } else {
        KDEBUG_IPC(0, "%s: node_list=0x%p, node_map=0x%p\n",
		__FUNCTION__, node_list, node_map);
    }
}

uint64_t
dvsipc_lnode_to_node(int lnode) 
{
    if (lnode >= max_nodes || node_list == NULL) {
        return DVSIPC_INVALID_NODE;
    }

    return node_list[lnode].pnode;
}

int
dvsipc_node_to_lnode(uint64_t node) 
{
    int lnode;
    if (node_list == NULL) {
        return -1;
    }

    for (lnode=0; lnode < max_nodes; lnode++) {
        if (node_list[lnode].pnode == node) {
            return lnode;
        }
    }

    return -1;
}

/*
 * Under heavy load, we can block the node heartbeat for
 * an extended period. We touch the heartbeat here to avoid
 * false node-down detections.
 */
static inline void 
dvs_alive(void) 
{
#if defined(CONFIG_CRAY_XT)
    static unsigned int callback_count = 0;
    extern void send_hb_2_l0(void) __attribute__ ((weak));

    if ((++callback_count % 0x1ff) == 0) {
        touch_nmi_watchdog();
        if (send_hb_2_l0 != NULL) {
            send_hb_2_l0();
        }
    }
#endif
}

/*
 * The following routines are used to manage receive buffers for inbound
 * requests.
 */
rx_buf_t rx_buf_table[DVSIPC_MAX_RX_MDS] = { { 0 } };    /* receive buffers */

void *
dvsipc_new_rx_buf(void)
{
    rx_buf_info_t *buf;

    buf = vmalloc_ssi(DVSIPC_RX_BUF_SIZE);
    if (buf == NULL) {
        printk(KERN_ERR "DVS: %s: can't allocate space for rx buffer, size = %ld\n",
                __FUNCTION__, DVSIPC_RX_BUF_SIZE);
    } else {
        buf->size = DVSIPC_RX_BUF_SIZE;
        atomic_set(&buf->rxbuf_state, RXBUF_Initial);
        atomic_inc(&rx_buffer_count);
    }
    return buf;
}

/*
 * Allocate landing buffer and add to free list.
 */
void
dvsipc_alloc_rx_buf(void) 
{
    rx_buf_info_t	*buf;
    unsigned long	flags;

    /*
     * Allocate new buffers only if the memory used up by the existing buffers 
     * with one or more pending operations is lower than half the available memory. 
     */
    if(atomic_read(&rx_buffer_count) >=  max_buffer_count) {
        return;
    }
    buf = dvsipc_new_rx_buf();
    if (!buf) return;

    DVS_TRACE("NEWRX", buf, 0);
    INIT_LIST_HEAD(&buf->rx_free_list);

    spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    list_add(&buf->rx_free_list, &dvsipc_free_list);
    atomic_set(&buf->rxbuf_state, RXBUF_Chained);
    atomic_inc(&freelist_buffer_count);
    spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);

}

/*
 * Check whether first rx buf in dvsipc_free_list needs to be
 * resized. Can happen when switching client/server config type.
 */
void
dvsipc_check_resize_buffer(void)
{
    rx_buf_info_t *bip;
    unsigned long flags;
    int bstate;

    dvsipc_cleanup_freelist();
    spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    if (list_empty(&dvsipc_free_list)) {
        spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
        return;
    }
    bip = container_of(dvsipc_free_list.next, rx_buf_info_t, rx_free_list);
    if (unlikely((bstate = atomic_read(&bip->rxbuf_state)) != RXBUF_Chained)) {
       printk(KERN_EMERG "RX buffer in invalid state %d !!\n", bstate);
       BUG();
    }
    if (bip->unused_list.prev || bip->unused_list.next) BUG();

    if (bip->size != DVSIPC_RX_BUF_SIZE) {
        list_del(&bip->rx_free_list);
        atomic_set(&bip->rxbuf_state, RXBUF_Unchained);
        spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
        atomic_dec(&freelist_buffer_count);
        atomic_dec(&rx_buffer_count);
        atomic_set(&bip->rxbuf_state, RXBUF_Free);
        vfree_ssi(bip);
        dvsipc_alloc_rx_buf();

        KDEBUG_IPC(0, "%s: resizing dvsipc_free_list buffer 0x%p, "
                   "old size %d, new size %ld\n",
                    __FUNCTION__, bip, bip->size, DVSIPC_RX_BUF_SIZE);
    }
    else {
        spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
    }
}

/*
 * Free md buffer if it is marked for recycle and there are
 * no more transactions are in-flight.
 */
void
dvsipc_free(struct usiipc *msg) 
{
    rx_buf_info_t *bip;
    unsigned long lflags, flags;
    int nops, unlinked;
    int bstate;

    /*
     * The LNet callback handler for receives places the pointer to the
     * reception buffer header in transport_handle in the normal case.
     * But, if the message was suspect it may have been that way because
     * it was received too small for example, due to protocol incompatibilities.
     * In that case, the receive handler places it in reply_address which it
     * verifies is in range.   Ultimately transport_handle should be moved up
     * in the usiipc structure so there's no need for this.
     */
    bip = (msg->command != RQ_SUSPECT)
		? msg->transport_handle /* normal case */
		: msg->reply_address; /* protocol mismatch */

    bstate = atomic_read(&bip->rxbuf_state);
    if (unlikely(bstate != RXBUF_LNetLinked && bstate != RXBUF_LNetUnlinked)) {
        printk(KERN_EMERG "RX buffer in invalid state %d !!\n", bstate);
	BUG();
    }
    if (bip->unused_list.prev || bip->unused_list.next) BUG();

    if (msg->command != RQ_SUSPECT) {
        unlink_rx_msg(msg);  /* remove from live message list */
    }

    local_irq_save(lflags);

    KDEBUG_IPC(0, "dvsipc_free: msg: 0x%p\n", msg);

    smp_mb();
    unlinked = bip->unlinked;
    nops = atomic_dec_return(&bip->outstanding_ops);
    smp_mb();

    if (unlinked && !nops) {
        DVS_TRACE("ipcssfrq", msg, bip);

        if (unlikely((bstate = atomic_read(&bip->rxbuf_state))
				!= RXBUF_LNetUnlinked)) {
           printk(KERN_EMERG "RX buffer in invalid state %d !!\n", bstate);
           BUG();
        }
        if (bip->unused_list.prev || bip->unused_list.next) BUG();
        bip->freed_jiffies = jiffies;
        spin_lock_irqsave(&dvsipc_free_list_lock, flags);

        INIT_LIST_HEAD(&bip->rx_free_list);
        list_add(&bip->rx_free_list, &dvsipc_free_list);
        atomic_set(&bip->rxbuf_state, RXBUF_Chained);
        atomic_inc(&freelist_buffer_count);
        spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
        up(&refill_sema);
    }

    local_irq_restore(lflags);
}

/*
 * dvsipc_fill_rx_slot - present receive buffer to transport for its use.
 */
static inline int
dvsipc_fill_rx_slot(int i, rx_buf_info_t *bip, int size)
{
    int ret;

    DVS_TRACE("isfillrx", i, bip);

    /* make it appear that a brand new buffer is being used */
    (void) atomic_cmpxchg(&bip->rxbuf_state, RXBUF_Initial, RXBUF_Unchained);

    rx_buf_table[i].seq++;
    rx_buf_table[i].buf = bip;
    if ((ret = ipclower_fill_rx_slot(i, bip, size)) != 0)
    {
        DVS_TRACE("isfillE", i, bip);
        rx_buf_table[i].seq--;
        rx_buf_table[i].buf = NULL;
        return ret;
    }
    bip->index = i;

    return 0;
}

/*
 * dvsipc_cleanup_freelist - Release buffer from freelist if they are in the list 
 * for more then three minutes.
 */
void
dvsipc_cleanup_freelist(void)
{
   unsigned long flags;
   rx_buf_info_t *bip = NULL;

   /*
    * Clean up free list every one minute 
    */
   if(jiffies - freelist_jiffies <= DVSIPC_ONE_MINUTE)
	return;

   freelist_jiffies = jiffies;
    
   if(atomic_read(&freelist_buffer_count) <=  DVSIPC_MAX_RX_MDS) {
       return;
   }

   spin_lock_irqsave(&dvsipc_free_list_lock, flags);
restart:
   list_for_each_entry(bip, &dvsipc_free_list, rx_free_list) { 
       if (jiffies - bip->freed_jiffies >= DVSIPC_THREE_MINUTE &&
           atomic_read(&rx_buffer_count) > rx_buffer_count_minimum) {

          list_del(&bip->rx_free_list);
          atomic_set(&bip->rxbuf_state, RXBUF_Unchained);
          spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
          atomic_dec(&rx_buffer_count);
          atomic_dec(&freelist_buffer_count);
          atomic_set(&bip->rxbuf_state, RXBUF_Free);
          vfree_ssi(bip);
          spin_lock_irqsave(&dvsipc_free_list_lock, flags);
          goto restart;
       }
   }
   spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
}

/*
 * The following routine is used to determine the max number the RX buffers 
 * can be capped to depending on the availability of free 
 * memory
 */
int
dvsipc_dynamic_max_buffer_count(void)
{
   int max_buffer_count = 0;
   struct sysinfo sysinf;

   /* Check available free memory */
   si_meminfo(&sysinf);

   max_buffer_count = ((sysinf.freeram / 2) * PAGE_SIZE) / DVSIPC_RX_BUF_SIZE; 
   return max_buffer_count;

}

/*
 * dvsipc_refill_thread - Refill an MD buffer from the free list.
 */
static int
dvsipc_refill_thread(void *arg) 
{
    int i;
    int error_on_refill;
    int refill_count;
    int err;

    DVS_TRACE("ipcTLI", 0, 0);

    sema_init(&refill_sema, 0);
    refill_thread = current;
    kernel_set_task_nice(current, -10);

    do {
        int ignore;

	error_on_refill = 0;
	refill_count = 0;

           
        for (i = 0; i < dvsipc_num_rx_mds; i++) {
            if (rx_buf_table[i].buf == NULL) {
                rx_buf_info_t *bip;
                unsigned long flags;
                int bstate;
    
                DVS_TRACE("ipcTLR", i, 0);
                spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    
                if (list_empty(&dvsipc_free_list)) {
                    spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
                    DVS_TRACE("ipcTL!BF", i, 0);
                    break;
                }
    
                bip = container_of(dvsipc_free_list.next, rx_buf_info_t,
					rx_free_list);
                if (bip->unused_list.prev || bip->unused_list.next) BUG();
                DVS_TRACEL("ipcTLRF", bip, bip->rx_free_list.prev,
				bip->rx_free_list.next, 0, 0);
    
                list_del(&bip->rx_free_list);
                bstate = atomic_cmpxchg(&bip->rxbuf_state, RXBUF_Chained,
						RXBUF_Unchained);
   
                spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
                atomic_dec(&freelist_buffer_count);
                if (unlikely(bstate != RXBUF_Chained)) {
                    printk(KERN_EMERG "RX buffer in invalid state %d !!\n",
				bstate);
                    BUG();
                }

                if (bip->size != DVSIPC_RX_BUF_SIZE) {
                    KDEBUG_IPC(0, "%s: reallocating buffer for slot %d, "
                               "old size %d, new size %lu\n",
                                __FUNCTION__, i, bip->size, DVSIPC_RX_BUF_SIZE);
                    atomic_set(&bip->rxbuf_state, RXBUF_Free);
		    atomic_dec(&rx_buffer_count);	
                    vfree_ssi(bip);
                    bip = dvsipc_new_rx_buf();
                    if (bip == NULL) continue; /* try again */
                }

                if ((err = dvsipc_fill_rx_slot(i, bip, DVSIPC_RX_BUF_SIZE))) {
		    error_on_refill++;
                    spin_lock_irqsave(&dvsipc_free_list_lock, flags);
                    list_add(&bip->rx_free_list, &dvsipc_free_list);
                    bstate = atomic_cmpxchg(&bip->rxbuf_state, RXBUF_Unchained,
						RXBUF_Chained);
                    atomic_inc(&freelist_buffer_count);
                    spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
                    DVS_TRACEL("RefillER", bip, err, bstate, error_on_refill,
				0);
                    if (unlikely(bstate != RXBUF_Unchained)) {
                        printk(KERN_EMERG "RX buffer in invalid state %d !!\n",
				bstate);
                        BUG();
                    }

                    continue;
                }

                refill_count++;
                KDEBUG_IPC(0, "%s: refilled slot %d\n", __FUNCTION__, i);
                DVSIPC_STAT_INC(DVSIPC_STAT_REFILL, 1);
    
            }
        }

        if (error_on_refill) {
            cond_resched();  /* Give somebody a chance to free memory perhaps */
        }
        else {
            up(&nak_sema);
            dvsipc_check_resize_buffer();
            ignore = down_interruptible(&refill_sema);
            DVS_TRACE("Refill", refill_count, 0);
        }
    } while (!shutdown);

    refill_thread = NULL;

    DVS_TRACE("ipcRFX", 0, 0);
    return 0;
}

/*
 * The following routines are used to manage the reliable (re)transmission
 * of ipc requests.
 */

/*
 * dvsipc_nak_thread - Send nak messages (resend requests) to nodes
 *                     from which we've dropped inbound requests.
 *
 */
int
dvsipc_nak_thread(void *arg) 
{
    KDEBUG_IPC(0, "dvsipc_nak_thread: IN\n");

    nak_thread = current;
    while (!shutdown) {
        ipc_nak_req_t *nak_req;
        unsigned long flags;
        int ignore;

        /*
         * Check for the next nak request and honor it.
         */
        spin_lock_irqsave(&dvsipc_resend_list_lock, flags);

        if (list_empty(&dvsipc_resend_list)) {
            DVS_TRACE("ssnakMT", 0, 0);
            spin_unlock_irqrestore(&dvsipc_resend_list_lock, flags);

            /*
             * Allocate a landing buffer if none available.
             */
            spin_lock_irqsave(&dvsipc_free_list_lock, flags);
            if (list_empty(&dvsipc_free_list)) {
                spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
                dvsipc_alloc_rx_buf();
            } else {
                spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
            }

            ignore = down_interruptible(&nak_sema);
            continue;
        }

        nak_req = (ipc_nak_req_t *)dvsipc_resend_list.prev;
        list_del(&nak_req->list);
        spin_unlock_irqrestore(&dvsipc_resend_list_lock, flags);

        KDEBUG_IPC(0, "%s: send nak to %s\n", __FUNCTION__,
            SSI_NODE_NAME(dvsipc_node_to_lnode(nak_req->nid)));

        DVS_TRACE("ssnaksnd", nak_req->nid, nak_req->rqp);
        ipclower_send_nak(nak_req->nid, nak_req->rqp);

        DVSIPC_STAT_INC(DVSIPC_STAT_NAK, 1);

        kfree_ssi(nak_req);
	
	/*
	* We're clearly out of resources so just wake the refill 
	* which will wake up and resources are restored. This would prevent
	* resend list from growing out of control and dvs getting stuck in 
	* nak thread. 
	*/
	spin_lock_irqsave(&dvsipc_free_list_lock, flags);
        if (list_empty(&dvsipc_free_list)) {
            spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
            up(&refill_sema);
            ignore = down_interruptible(&nak_sema);
        } else {
            spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
        }

    }
    nak_thread = NULL;
    return 0;
}

/*
 * Clean up any currently active nak requests.
 */
void
dvsipc_nak_cleanup(void) 
{
    unsigned long flags;
    spin_lock_irqsave(&dvsipc_resend_list_lock, flags);

    while (!list_empty(&dvsipc_resend_list)) {
        ipc_nak_req_t *nak_req;
        nak_req = (ipc_nak_req_t *)dvsipc_resend_list.next;
        list_del(&nak_req->list);
        kfree_ssi(nak_req);
    }
    spin_unlock_irqrestore(&dvsipc_resend_list_lock, flags);

    up (&nak_sema);
}

/*
 * dvsipc_nak - We did not have buffer space for the inbound message.
 *              Ask for a retransmit from the originator.
 */
static void
dvsipc_nak(uint64_t nid, uint64_t hdr_data) 
{
    unsigned long flags;
    ipc_nak_req_t *nak_req;

    DVS_TRACE("ipcNAKin", nid, hdr_data);

    KDEBUG_IPC(0, "%s: queue nak for %s\n", __FUNCTION__,
                 SSI_NODE_NAME(dvsipc_node_to_lnode(nid)));

    nak_req = (ipc_nak_req_t*)kmalloc_ssi( sizeof(ipc_nak_req_t), GFP_ATOMIC);

    if (nak_req == NULL) {
        printk(KERN_ERR "DVS: %s: no space for nak req to %s\n", __FUNCTION__,
            SSI_NODE_NAME(dvsipc_node_to_lnode(nid)));
        return;
    }

    INIT_LIST_HEAD( &nak_req->list );
    nak_req->rqp = (void*)hdr_data;
    nak_req->nid = nid;

    spin_lock_irqsave(&dvsipc_resend_list_lock, flags);
    list_add(&nak_req->list, &dvsipc_resend_list);
    spin_unlock_irqrestore(&dvsipc_resend_list_lock, flags);

    /*
     * Don't wake the nak thread yet, we're clearly out of resources so that may just
     * dig us in further.  Wake the refill which will wake up the nak at the end once
     * resources are restored.
     */
    up(&refill_sema);
}

int
dvsipc_identity_valid(int node, time_t identity) 
{
    if (!remote_node_info) {
	return 0;
    }
    if (node < 0 || node > max_nodes) {
        KDEBUG_IPC(0, "%s: invalid node 0x%x\n", __FUNCTION__, node);
	return 0;
    }

    if (remote_node_info[node].identity != identity) {
        DVS_TRACEL("SS!ID", node,
            remote_node_info[node].identity, identity, 0, 0);
        return 0;
    }
    return 1;
}

static int
dvsipc_node_state(int node) 
{
    if (!remote_node_info) {
	return NODE_UNKNOWN;
    }
    if (node < 0 || node > max_nodes) {
        KDEBUG_IPC(0, "%s: invalid node 0x%x\n", __FUNCTION__, node);
	return NODE_UNKNOWN;
    }

    if (remote_node_info[node].node_status == Node_Status_Down) {
        return NODE_DOWN;
    } else if (remote_node_info[node].node_status == Node_Status_Up) {
        return NODE_READY;
    }
    /*
     * This should never happen, but just to be safe.
     */
    printk_once(KERN_ERR "DVS: %s() %d UNKNOWN STATUS=%d node=%d\n", __func__, __LINE__,
		remote_node_info[node].node_status,node);
    return NODE_UNKNOWN;
}

int
validate_node (int node) 
{
    int node_state;

    if ((node_state=dvsipc_node_state(node)) != NODE_READY) {
        DVS_TRACEL("valFAIL", node, max_nodes, node_state, 0, 0);
        return 1;
    }

    return 0;
}

/*
 * The following routines are used to manage the various lists of in-process
 * ipc messages.
 */
void
add_to_queue (struct usiipc **head, struct usiipc **tail, spinlock_t *qlock,
			struct semaphore *qsema, struct usiipc *rp) 
{
    struct usiipc *m;
    unsigned long flags = 0;

    if (qlock)
        spin_lock_irqsave(qlock, flags);

    if (*tail) {
        m = *tail;
#ifdef DISABLED
        /* insert by priority */
        while ((rp->priority < m->priority) && m->prev)
            m = m->prev;
#endif
        if (!m->prev) {
            /* insert at head */
            (*head)->prev = rp;
            rp->next = *head;
            rp->prev = NULL;
            *head = rp;
        } else {
            /* insert after m */
            rp->next = m->next;
            rp->prev = m;
            if (m->next) {
                m->next->prev = rp;
            } else {
                *tail = rp;
            }
            m->next = rp;
        }
    } else {
        rp->next = NULL;
        rp->prev = NULL;
        *head = *tail = rp;
    }
    if (qlock)
        spin_unlock_irqrestore(qlock, flags);

    KDEBUG_IPC(0, "queued msg 0x%p for node %s to send queue\n", rp,
        SSI_NODE_NAME(rp->target_node));

    /* wakeup waiting thread */
    if (qsema)
        up(qsema);
}

static void
remove_from_queue(struct usiipc *rp, struct usiipc **head,
                  struct usiipc **tail)
{
    struct usiipc *prev, *next;

    prev = rp->prev;
    next = rp->next;

    if (prev)
        prev->next = next;
    else
        *head = next;

    if (next)
        next->prev = prev;
    else
        *tail = prev;
}

static void
remove_from_wait_queue(struct usiipc *msg) 
{
    struct usiipc *next, *prev;

    BUG_ON(msg->state >= ST_WAIT_COMPL);
    prev = msg->prev;
    next = msg->next;
    if (prev)
        prev->next = next;
    else
        mq_waiting = next;
    if (next)
        next->prev = prev;
    msg->state = ST_WAIT_COMPL;
    msg->next = msg->prev = msg;

    KDEBUG_IPC(0, "de-queued msg 0x%p for node %s from wait queue\n", msg,
        SSI_NODE_NAME(msg->target_node));
}

static void
add_to_wait_queue(struct usiipc *msg) 
{

    /* add to the waiting queue */
    BUG_ON(msg->state != ST_INITIAL);
    msg->next = mq_waiting;
    msg->prev = NULL;
    msg->state = ST_WAIT_QUEUED;
    if (mq_waiting)
        mq_waiting->prev = msg;
    mq_waiting = msg;
    KDEBUG_IPC(0, "queued msg 0x%p for node %s 0x%p 0x%p 0x%p %d %d to wait queue\n",
        msg, SSI_NODE_NAME(msg->target_node), msg->original_request,
        msg->reply_address, msg->wakeup_word, msg->async,
        msg->command);
}

static void
remove_from_active_queue(struct usiipc *msg, struct dvsipc_instance *instance) 
{
    struct usiipc *next, *prev;

    BUG_ON(msg->state != ST_SV_MSG_ACTIVE);
    prev = msg->prev;
    next = msg->next;
    if (prev)
        prev->next = next;
    else
        instance->mq_active = next;
    if (next)
        next->prev = prev;
    msg->state = ST_SV_MSG_PROCESSED;
    msg->next = msg->prev = msg;
}

static void
add_to_active_queue(struct usiipc *msg, struct dvsipc_instance *instance) 
{

    /* add to the waiting queue */
    msg->next = instance->mq_active;
    msg->prev = NULL;
    msg->state = ST_SV_MSG_ACTIVE;
    if (instance->mq_active)
        instance->mq_active->prev = msg;
    instance->mq_active = msg;
}

static void
move_send_to_wait(struct usiipc *msg) 
{
    remove_from_queue(msg, &mq_head, &mq_tail);
    BUG_ON(msg->state != ST_SEND_COMPL);

    /* some messages do not go on the waiting queue */
    if (msg->free_required) {
        if (msg->command == RQ_REPLY)
            return;
        if (!msg->reply_address)
            return;
    }

    add_to_wait_queue(msg);
}

/*
 * The following routines are used to initiate and manage dvs 
 * message transmit requests.
 */

/*
 * Callback routine for timing out dvs-initiated transmits.
 */
static void
dvsipc_expire_request(unsigned long arg) 
{
    struct usiipc *rq = (struct usiipc *)arg;
    tx_status_t *tx_status = (tx_status_t *)&rq->transport_handle;
    dvsipc_tx_t *txp = container_of(rq, dvsipc_tx_t, msg);

    KDEBUG_IPC(0, "%s: tx expired\n", __FUNCTION__);
    DVS_TRACE("ipc_txXP", rq, 0);
    /*
     * If the transmit has left the node we begin counting wait intervals.
     * If no response is received to the request (ACK or NAK) within a
     * reasonable time, the transmit will be dropped.
     */
    if (atomic_read(&tx_status->upper_status) > 0) {
        atomic_inc(&tx_status->upper_status);
    }

    up(&txp->sema);
}

/*
 * Utility function to handle the dvs portion of transmit completion events.
 */
static void
dvsipc_tx_complete(struct usiipc *msg, int failed) 
{
    dvsipc_tx_t *txp = container_of(msg, dvsipc_tx_t, msg);
    tx_status_t *tx_status = (tx_status_t*)&msg->transport_handle;
    int lower_status;

    lower_status = atomic_cmpxchg(&tx_status->lower_status,
        0, failed ? DVSIPC_TX_FAILED : DVSIPC_TX_COMPLETE);

    /*
     * Notify sender of completion. If the request was abandoned, free
     * the buffer.
     */
    if (lower_status == DVSIPC_TX_ORPHANED) {
        kfree_ssi(txp);
    } else {
        up(&txp->sema);
    }
}

/*
 * Terminate an in-process request. Response has not
 * arrived and we must move on.
 */
static void 
dvsipc_kill_request(unsigned long arg)
{
    struct usiipc *rq = (struct usiipc *)arg;
    struct usiipc reply;
 
    printk("DVS: %s: killing request %s to %s\n", __FUNCTION__,
           rq_cmd_name(rq), SSI_NODE_NAME(rq->target_node));

    DVS_TRACE("rq_kill", rq, rq->target_node);
    reply.command = RQ_IPC_FAILURE;
    reply.rval = -ETIMEDOUT;
    reply.target_node = usi_node_addr;
    reply.source_node = usi_node_addr;
    reply.request_length = sizeof(reply);
    reply.reply_length = sizeof(reply);
    reply.free_required = 0;
    reply.reply_address = rq->reply_address;
    reply.wakeup_word = rq->wakeup_word;
    reply.original_request = rq->original_request;
    reply.source_request = rq->source_request;
    reply.source_seqno = rq->seqno;

    memcpy(rq->reply_address, &reply, sizeof(reply));
    dvsipc_do_process_ipc_reply(&reply);

    rq->command = RQ_IPC_FAILURE;

    atomic64_inc(&requests_killed);
}

/*
 * Wait for the remote to respond to our request. We know at
 * this point that dvs was alive on the remote at the time
 * the request was sent because we've received an ACK.
 */
static void 
dvsipc_wait_for_response(struct usiipc *rq) 
{
    /*
     * If the system is configured to terminate hung server
     * requests, allow the task to be killed if something goes wrong
     * on the remote before it can respond. Otherwise, we'll wait
     * indefinitely for the server to handle the request.
     */
    if (dvsipc_response_timeout == 0) {
        down(&rq->msgwait);
    } else if (down_killable(&rq->msgwait)) {
        struct timer_list timer;
        unsigned long expire;

        expire = jiffies + (dvsipc_response_timeout*HZ);
        setup_timer_on_stack(&timer, dvsipc_kill_request, (unsigned long)((void*)rq));
        mod_timer(&timer, expire);

        down(&rq->msgwait);
        del_singleshot_timer_sync(&timer);
    } 
}

/*
 * Current IPC registration method at the moment is the old seqno.
 */
static atomic64_t cur_seqno = ATOMIC_INIT(0);

static dvs_tx_desc_t dvsipc_register_ipc_request(struct usiipc *request)
{
    dvs_tx_desc_t rval = 0;

    rval = request->seqno = atomic64_add_return(1, &cur_seqno);

    return rval;
}

static int
write_message_to_transport(struct usiipc *msg) 
{
    int rval = 0, request_length;
    uint64_t nid;
    mm_segment_t oldfs;
    int async_freed = IS_IOPAGE_REQUEST(msg);

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    if ((nid = dvsipc_lnode_to_node(msg->target_node)) == DVSIPC_INVALID_NODE) {
        printk(KERN_ERR "DVS: %s: Attempt to send to invalid node %s (%d)\n",
                        __FUNCTION__, SSI_NODE_NAME(msg->target_node), 
                        msg->target_node);
        rval = -EINVAL;
        goto errout;
    }

    /* write message to transport */
    KDEBUG_IPC(0, "writing msg 0x%p %d bytes cmd %d(%s) to node %s from %s\n",
        msg, msg->request_length, msg->command,
        rq_cmd_name(msg), SSI_NODE_NAME(msg->target_node),
        SSI_NODE_NAME(msg->source_node));

    if (!msg->seqno) {
       msg->seqno = dvsipc_register_ipc_request(msg);
    }
    msg->retry = 0;

    /*
     * Stash request_length in a local variable.  We can't reference msg after
     * ipclower_tx_request() since msg is freed asynchronously in cases like
     * RQ_READPAGE_ASYNC.
     */
    request_length = msg->request_length;

    down(&ipc_tx_sema);
    msg->state = ST_WAITING;
    rval = ipclower_tx_request(nid, msg, dvsipc_tx_resend_limit, 
                               dvsipc_tx_timeout);
    if (!async_freed) {
       msg->state = ST_SEND_COMPL;
    }
    up(&ipc_tx_sema);

errout:
    /* update statistics */
    if (rval < 0) {
        DVSIPC_STAT_INC(DVSIPC_STAT_ERROR, 1);
    } else {
        DVSIPC_STAT_INC(DVSIPC_STAT_TX, 1);
        DVSIPC_SIZE_INC(DVSIPC_STAT_TX, request_length);
        DVSIPC_STAT_INC(DVSIPC_STAT_TX_BYTES, request_length);
    }

    set_fs(oldfs);
    return(rval);
}

/* 
 * Common interface routine for synchronous and asynchronous transmits.
 *
 * If async, success means message was sent successfully.
 * If not async, success means success status returned from remote node.
 */
static int
dvsipc_send_ipc_request_common(struct usiipc *request)
{
    int async = 0, mlen;
    int free_required = request->free_required;
    struct usiipc *reply = request->reply_address;
    unsigned long flags;
    int ret;

    /*
     * Node-up indication handled by rca/heartbeat.
     */
    if (request->command == RQ_IPC_NODE_UP) {
        KDEBUG_IPC(0, "DVS: dvsipc_send_ipc_request: skipping node_up to %s\n",
            SSI_NODE_NAME(request->target_node));
        return 0;
    }

    KDEBUG_IPC(0, "dvsipc_send_ipc_request: node %s command %d\n",
        SSI_NODE_NAME(request->target_node), request->command);
    if (validate_node(request->target_node)) {
        if (free_required)
            free_msg(request);
        return -USIERR_NODE_DOWN;
    }

    request->source_node = usi_node_addr;
    request->sender_identity = local_identity;
    request->source_request = NULL;
    request->usiipc_len = sizeof(struct usiipc);
    if (request->command == RQ_DSD)
        request->instance_id = DVSIPC_INSTANCE_KDWFS;
    else if (request->command == RQ_DSDB)
        request->instance_id = DVSIPC_INSTANCE_KDWFSB;
    else if (request->command == RQ_DSDC)
        request->instance_id = DVSIPC_INSTANCE_KDWCFS;
    else
        request->instance_id = DVSIPC_INSTANCE_DVS;

    mlen = request->request_length;

    if (mlen > MAX_MSG_SIZE) {
        DVS_TRACEL("sstx2big", request, mlen, MAX_MSG_SIZE, 0, 0);
        KDEBUG_IPC(0, "ssi_send_ipc_request: request too large 0x%x > 0x%x\n",
            mlen, MAX_MSG_SIZE);
        if (free_required)
            free_msg(request);
        return -USIERR_IPC_PROTO;
    }

    if (reply == NULL) {
        request->reply_address = NULL;
        request->wakeup_word = NULL;
        async = request->async = 1;
    }
    else {
        /*
         * we use the message passed directly, and
         * do not make a copy.
         */
        request->wakeup_word = &request->msgwait;
        async = request->async;
        reply->callback = NULL;
        reply->command = RQ_WAITING_REPLY;
        reply->source_seqno = request->seqno;
    }

    /* send directly */
    if (reply) {
        spin_lock_irqsave(&mq_sl, flags);
        add_to_wait_queue(request);
        spin_unlock_irqrestore(&mq_sl, flags);

        /* clear callback value */
        reply->command = 0;
    }

    KDEBUG_IPC(0, "direct write request 0x%p\n", request);

    sema_init(&request->msgwait, 0);
    if ((ret=write_message_to_transport(request))) {
        KDEBUG_IPC(0, "DVS: %s: write_message_to_transport failed request "
            "%s to %s: %d\n", __FUNCTION__, rq_cmd_name(request),
            SSI_NODE_NAME(request->target_node), ret);
        DVS_TRACEL("srwm2ssE", request, async, reply, 0, 0);

        if (reply) {
            spin_lock_irqsave(&mq_sl, flags);
            if (request->state == ST_SEND_COMPL) {
                remove_from_wait_queue(request);
            }
            else {
                free_required = 0;  /* it's still on the wait queue */
            }
            spin_unlock_irqrestore(&mq_sl, flags);
        }
        if (free_required) {
            free_msg(request);
        }
        return ret;
    }

    KDEBUG_IPC(0, "direct write request complete (0x%p)\n", request);

    direct_sends++;

    if (async) {
        if (free_required) {
            free_msg(request);
	}
        return 0;
    }

resume:
    /* wait for reply */
    dvsipc_wait_for_response(request);

    spin_lock_irqsave(&mq_sl, flags);
    /* Process callbacks here */
    if (reply->command == RQ_CALLBACK) {
        struct usiipc *msg;

        msg = reply->callback;
        reply->callback = NULL;
        reply->command = RQ_WAITING_REPLY;
        spin_unlock_irqrestore(&mq_sl, flags);
        KDEBUG_IPC(0, "DVS: %s: IPC Callback: %d \n", __FUNCTION__,
            msg->command);

        /* Process the message in this task context */
        if (usi_callback) {
            ret = usi_callback(msg->command, msg);
            if (ret < 0)
                IPC_LOG("callback error %d for message 0x%p\n", ret, msg);
        } else {
            printk(KERN_ERR "DVS: %s: Cannot process incoming "
                "message\n", __FUNCTION__);
        }

        if (msg->free_required) {
            free_msg(msg);
        }

        /* wait for the original reply again */
        goto resume;
    }

    /* remove from waiting queue */
    remove_from_wait_queue(request);
    spin_unlock_irqrestore(&mq_sl, flags);

    /* validate reply */
    if (reply->command == RQ_IPC_FAILURE) {
        DVS_TRACEL("sndfail", request, current->pid, 
                  request->command, 0, 0);
        KDEBUG_IPC(0, "DVS: %s: SS IPC "
            "failure on %s to %s\n", __FUNCTION__,
            rq_cmd_name(request), SSI_NODE_NAME(request->target_node));

        if (request->command == RQ_IPC_FAILURE) {
            ret = -EIO;
        } else {
            switch (reply->rval) {
               case 0:
               case -ENOSYS:
               case -EHOSTDOWN:
                  ret = -USIERR_NODE_DOWN;
                  break;
               case -EQUIESCE:
                  ret = -EQUIESCE;
                  break;

               default:
                  ret = reply->rval;
                  printk("DVS: %s: IPC reply received with error %d for message "
                         "0x%p\n", __func__, reply->rval, request);
            }
        }
    }

    if (free_required) {
        free_msg(request);
    }

    return(ret);
}

static int
dvsipc_send_ipc_request(struct usiipc *request) 
{
    int ret;
    request->async = 0;
    ret = dvsipc_send_ipc_request_common(request);
    return ret;
}

static int
dvsipc_send_ipc_request_async(struct usiipc *request)
{
    int ret;
    request->async = 1;
    ret = dvsipc_send_ipc_request_common(request);
    return ret;
}

static int
dvsipc_wait_for_async_request(struct usiipc *request) 
{
    int sts;
    unsigned long flags;

    dvsipc_wait_for_response(request);

    spin_lock_irqsave(&mq_sl, flags);
    /* remove from waiting queue */
    remove_from_wait_queue(request);
    spin_unlock_irqrestore(&mq_sl, flags);
    sts = ((struct usiipc *)request->reply_address)->command;

    /* validate reply */
    if (sts == RQ_IPC_FAILURE) {
        DVS_TRACEL("wfARf", request, &request->msgwait,
                  request->command, 0, 0);
        KDEBUG_IPC(0, "DVS: %s: SS IPC failure\n", __FUNCTION__);
        if (request->command == RQ_IPC_FAILURE) {
            return -EIO;
        } else if (((struct usiipc *)request->reply_address)->rval == -EQUIESCE) {
                return -EQUIESCE;
	} else {
            return -USIERR_NODE_DOWN;
        }
    }
    return(0);
}

static int
dvsipc_send_ipc_reply(struct usiipc *request, struct usiipc *reply,
			int reply_size) 
{
    struct usiipc *rp = reply;
    int rval, node = reply->target_node;

    /* allow error reply to down node (for id mismatch) */
    if (validate_node(node)) {
        if (reply->command != RQ_REPLY_ERROR) {
            if (rp->free_required) {
                free_msg(rp);
            }
            DVS_TRACEL("sndrplyE", request, reply, request->seqno, 
                      reply_size, 0);
            return -USIERR_NODE_DOWN;
        }
    }

    rp->source_seqno = request->seqno;
    rp->source_node = usi_node_addr;
    rp->sender_identity = local_identity;
    rp->source_request = request->source_request;
    rp->usiipc_len = sizeof(struct usiipc);

    /* send directly */

    KDEBUG_IPC(0, "direct write reply 0x%p\n", rp);

    if ((rval = write_message_to_transport(rp)) != 0) {
        DVS_TRACEL("snd_rpX", rp, rp->free_required, rval, 0, 0);
    }
    direct_sends++;

    DVS_TRACEL("snd_rply", request, reply, rp->target_node, 
                                   request->seqno, 0);

    /* update statistics */
    if (rval < 0) {
        DVSIPC_STAT_INC(DVSIPC_STAT_ERROR, 1);
    } else {
        DVSIPC_STAT_INC(DVSIPC_STAT_REPLY, 1);
        DVSIPC_SIZE_INC(DVSIPC_STAT_REPLY, rp->request_length);
        DVSIPC_STAT_INC(DVSIPC_STAT_REPLY_BYTES, rp->request_length);
    }

    if (rp->free_required) {
        free_msg(rp);
    }
    if (rval < 0) {
        KDEBUG_IPC(0, "DVS: %s: reply to %s failed (%d)\n",
                        __FUNCTION__, SSI_NODE_NAME(rp->target_node), rval);
        return(rval);
    }

    return(0);
}

static int
reply_with_error(struct usiipc *ipc_header, int error) 
{
    struct usiipc reply;

    if (ipc_header->command == RQ_REPLY)
        return 0;
    if (ipc_header->reply_address == NULL)
        return 0;
    /* reply to the message with an error */
    reply.command = RQ_REPLY_ERROR;
    reply.rval = error;
    reply.target_node = ipc_header->source_node;
    reply.request_length = sizeof(reply);
    reply.reply_address = ipc_header->reply_address;
    reply.reply_length = ipc_header->reply_length;
    reply.wakeup_word = ipc_header->wakeup_word;
    reply.original_request = ipc_header->original_request;
    reply.source_request = ipc_header->source_request;
    reply.source_seqno = ipc_header->seqno;
    reply.free_required = 0;
    reply.priority = kernel_get_task_nice(current);
    reply.receiver_identity = 0;
    KDEBUG_IPC(0, "DVS: reply_with_error: sending error reply to node %s\n",
        SSI_NODE_NAME(reply.target_node));
    DVS_TRACE("RWE", reply.target_node, 0);
    return dvsipc_send_ipc_reply(ipc_header, &reply, sizeof(reply));
}

/*
 * ipc interface routines for mapping user buffers into the transport's
 * address space.
 */
void *
dvsipc_mapuvm(char *uvm, ssize_t length, int rw) 
{
    struct ipc_mapping *rval = ipclower_mapuvm(uvm, length, rw);

    /* update statistics */
    if (IS_ERR_OR_NULL(rval)) {
        DVSIPC_STAT_INC(DVSIPC_STAT_ERROR, 1);
    } else {
        DVSIPC_STAT_INC(DVSIPC_STAT_MAPUVM, 1);
        DVSIPC_STAT_INC(DVSIPC_STAT_MAPUPGS, rval->page_count);

        KDEBUG_IPC(0, "%s: 0x%p, %ld, %d, %d\n", __FUNCTION__, uvm, length,
               rval->page_count, rw);
    }
    return rval;
}

int
dvsipc_unmapuvm(void *handle) 
{
    struct ipc_mapping *ipc_handle = (struct ipc_mapping *) handle;
    int	rval;

    KDEBUG_IPC(0, "%s: 0x%p\n", __FUNCTION__, handle);
    rval = ipclower_unmapuvm(handle);

    if (!rval) {
	DVSIPC_STAT_INC(DVSIPC_STAT_UNMAPUVM, 1);
	DVSIPC_STAT_INC(DVSIPC_STAT_UNMAPUPGS, ipc_handle->page_count);
    }

    return rval;
}

void *
dvsipc_mapkvm(char *kvm, ssize_t length, int rw) 
{
    struct ipc_mapping *rval = ipclower_mapkvm(kvm, length, rw);

    /* update statistics */
    if (IS_ERR_OR_NULL(rval)) {
        DVSIPC_STAT_INC(DVSIPC_STAT_ERROR, 1);
    } else {
        DVSIPC_STAT_INC(DVSIPC_STAT_MAPKVM, 1);
        DVSIPC_STAT_INC(DVSIPC_STAT_MAPKPGS, rval->page_count);

        KDEBUG_IPC(0, "%s: 0x%p, %ld, %d, %d\n", __FUNCTION__, kvm, length,
               rval->page_count, rw);
    }
    return rval;
}

int
dvsipc_unmapkvm(void *handle) 
{
    struct ipc_mapping *ipc_handle = (struct ipc_mapping *) handle;
    int	rval;

    KDEBUG_IPC(0, "%s: 0x%p\n", __FUNCTION__, handle);
    rval = ipclower_unmapkvm(handle);

    if (!rval) {
	DVSIPC_STAT_INC(DVSIPC_STAT_UNMAPKVM, 1);
	DVSIPC_STAT_INC(DVSIPC_STAT_UNMAPKPGS, ipc_handle->page_count);
    }

    return rval;
}

/*
 * Mark an IPC thread as potentially blocked for an indeterminate amount
 * time.  process_message_thread() will take this into account when
 * determining if new threads should be created for incoming requests.
 */
static void
dvsipc_block_thread(void)
{
    struct dvsipc_instance *instance;
    struct dvsipc_thread *thread;
    unsigned long flags;
    int i;

    for (i = 0; i < DVSIPC_INSTANCE_MAX; i++) {
        instance = dvsipc_find_instance(i);
        if (instance == NULL)
            continue;

        spin_lock_irqsave(&instance->thread_pool->lock, flags);
        list_for_each_entry(thread,
                            &instance->thread_pool->state_lists[DVSIPC_THREAD_BUSY],
                            state_list) {
            if (thread->task == current) {
                dvsipc_get_thread(thread);
                spin_unlock_irqrestore(&instance->thread_pool->lock, flags);
                dvsipc_set_thread_blocked(thread);

                dvsipc_put_thread(thread);
                dvsipc_put_instance(instance);

                return;
            }
        }
        spin_unlock_irqrestore(&instance->thread_pool->lock, flags);

        dvsipc_put_instance(instance);
    }

    printk("DVS: %s: Error: Unable to find active thread to set as blocked "
           "for process 0x%p\n", __func__, current);

    return;
}

/*
 * Mark an IPC thread as no longer blocked.
 */
static void
dvsipc_release_thread(void)
{
    struct dvsipc_instance *instance;
    struct dvsipc_thread *thread;
    unsigned long flags;
    int i;

    for (i = 0; i < DVSIPC_INSTANCE_MAX; i++) {
        instance = dvsipc_find_instance(i);
        if (instance == NULL)
            continue;

        spin_lock_irqsave(&instance->thread_pool->lock, flags);
        list_for_each_entry(thread,
                            &instance->thread_pool->state_lists[DVSIPC_THREAD_BLOCKED],
                            state_list) {
            if (thread->task == current) {
                dvsipc_get_thread(thread);
                spin_unlock_irqrestore(&instance->thread_pool->lock, flags);
                dvsipc_set_thread_busy(thread);

                dvsipc_put_thread(thread);
                dvsipc_put_instance(instance);

                return;
            }
        }
        spin_unlock_irqrestore(&instance->thread_pool->lock, flags);

        dvsipc_put_instance(instance);
    }

    printk("DVS: %s: Error: Unable to find active thread to set as blocked "
           "for process 0x%p\n", __func__, current);

    return;
}

/*
 * For threads that are potentially used to handle file operations, we 
 * need to retain the fs and mm but want to daemonize (reparent to
 * init) so that termination cleanup is handled properly.  In SLES12 we
 * have already been reparented to init during thread creation, so just
 * setup the private fs and mm structs.
 */
static int
dvs_daemonize(const char *name)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct fs_struct *fs = current->fs;
    struct mm_struct *mm = current->mm;

    /*
     * Increment the fs count since daemonize() will decrement it when it
     * tries (unsuccessfully) to decrement/free the fs.
     */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,0)
    spin_lock(&fs->lock);
    fs->users++;
    spin_unlock(&fs->lock);
#else
    write_lock(&fs->lock);
    fs->users++;
    write_unlock(&fs->lock);
#endif

    task_lock(current);
    current->mm = NULL;
    task_unlock(current);

    daemonize(name);

    /*
     * We operate on 'current' here because daemonize() has changed our fs
     * to be init's fs_struct, so we need to back out of that assigniment
     * and restore what we saved off before the call to daemonize().  Since
     * daemonize has decremented our original fs count, we just need to
     * decrement the current one (i.e. init's count).
     */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,0)
    spin_lock(&current->fs->lock);
    current->fs->users--;
    spin_unlock(&current->fs->lock);
#else
    write_lock(&current->fs->lock);
    current->fs->users--;
    write_unlock(&current->fs->lock);
#endif

    /* Now that the fs counts are sane, we can get our private fs back. */
    current->fs = fs;

    task_lock(current);
    current->mm = mm;
    task_unlock(current);

#else /* > KERNEL_VERSION(3,10,0) */
    struct mm_struct *active_mm, *mm = mm_alloc();

    if (!mm) {
        KDEBUG_IPC(0, "%s: mm_alloc failed\n", __FUNCTION__);
        return -ENOMEM;
    }

    /*
     * Create our own private copy of the init process fs_struct we have been
     * provided via kthread_run.
     */
    if (unshare_fs_struct() < 0) {
        KDEBUG_IPC(0, "%s: unshare_fs_struct failed\n", __FUNCTION__);
        return -ENOMEM;
    }

    /*
     * Kernel threads do not have a private mm_struct after creation.  Set the
     * current task mm to the newly allocated mm.  mm_alloc creates a new 
     * mm_struct from the slab cache and initializes it.  activate_mm makes it
     * immediately active.  mmdrop releases the DVS reference on the mm_struct
     * that was assigned at kernel thread creation that is being replaced.
     */
    task_lock(current);
    active_mm = current->active_mm;
    current->mm = mm;
    current->active_mm = mm;
    activate_mm(active_mm, mm);
    /* Set the mm->get_unmapped_area -- required for O_DIRECT */
    arch_pick_mmap_layout(current->mm);
    task_unlock(current);

    mmdrop(active_mm);

    KDEBUG_IPC(0, "%s: fs_struct 0x%p, mm_struct 0x%p\n", __FUNCTION__, current->fs,
                current->mm);
#endif

    return 0;
}

static inline int
msg_match(struct usiipc *rq1, struct usiipc *rq2) 
{
    if ((rq1->source_node == rq2->source_node) &&
                (rq1->seqno == rq2->seqno)) {
	return 1;
    }
    return 0;
}

/*
 * Check this message to determine if it is a duplicate from
 * the source. 
 */
int
msg_is_dup(struct usiipc *msg)
{
    struct usiipc *rq;
    unsigned long flags;
    struct remote_info *rni = &remote_node_info[msg->source_node];

    if (msg->retry == 0) {
        return 0;
    }

    spin_lock_irqsave(&rni->lock, flags);
    if (list_empty(&rni->msgs)) {
        spin_unlock_irqrestore(&rni->lock, flags);
        return 0;
    } 

    list_for_each_entry(rq, &rni->msgs, active_rx) {
        if (msg_match(rq, msg)) {
            spin_unlock_irqrestore(&rni->lock, flags);
            DVS_TRACEL("msgdup", rq, msg, rq->seqno, msg->seqno, 0);
            DVSIPC_STAT_INC(DVSIPC_STAT_DUPS, 1);
            return 1;
        }
    }
    spin_unlock_irqrestore(&rni->lock, flags);

    return 0;
}

struct dvsipc_instance *
dvsipc_find_instance(enum dvsipc_instance_id instance_id)
{
    struct dvsipc_instance *instance;
    unsigned long flags;

    if (instance_id >= DVSIPC_INSTANCE_MAX) {
        printk("DVS: %s: Error: Invalid instance ID %u\n", __func__,
               instance_id);
        return NULL;
    }

    spin_lock_irqsave(&dvsipc_instance_lock, flags);
    if ((instance = dvsipc_instances[instance_id]) == NULL) {
        spin_unlock_irqrestore(&dvsipc_instance_lock, flags);
        return NULL;
    }

    dvsipc_get_instance(instance);
    spin_unlock_irqrestore(&dvsipc_instance_lock, flags);

    return instance;
}

int
dvsipc_add_instance(struct dvsipc_instance *instance,
                    enum dvsipc_instance_id instance_id)
{
    unsigned long flags;

    spin_lock_irqsave(&dvsipc_instance_lock, flags);
    if (dvsipc_instances[instance_id] != NULL) {
        spin_unlock_irqrestore(&dvsipc_instance_lock, flags);
        return -EEXIST;
    }

    dvsipc_instances[instance_id] = instance;
    spin_unlock_irqrestore(&dvsipc_instance_lock, flags);

    return 0;
}

static struct dvsipc_instance *
dvsipc_create_instance(void)
{
    struct dvsipc_instance *instance;

    instance = kmalloc_ssi(sizeof(struct dvsipc_instance), GFP_KERNEL);
    if (instance == NULL)
        return NULL;

    instance->thread_pool = NULL;
    instance->mq_active = NULL;
    kref_init(&instance->ref);

    return instance;
}

void
dvsipc_free_instance(struct kref *ref)
{
    struct dvsipc_incoming_msgq *inmsgq;
    struct dvsipc_instance *instance;

    instance = container_of(ref, struct dvsipc_instance, ref);

    if (instance->thread_pool == NULL) {
        kfree_ssi(instance);
        return;
    }

    dvsipc_stop_thread_pool(instance->thread_pool);

    if (instance->thread_pool->inmsgq)
        dvsipc_stop_incoming_msgq(instance->thread_pool->inmsgq);

    nap();

    inmsgq = instance->thread_pool->inmsgq;
    dvsipc_remove_thread_pool(instance->thread_pool);

    if (inmsgq)
        dvsipc_remove_incoming_msgq(inmsgq);

    instance->thread_pool = NULL;

    kfree_ssi(instance);
}

void
dvsipc_remove_instance(enum dvsipc_instance_id instance_id)
{
    struct dvsipc_instance *instance;
    unsigned long flags;

    spin_lock_irqsave(&dvsipc_instance_lock, flags);
    instance = dvsipc_instances[instance_id];
    dvsipc_instances[instance_id] = NULL;
    spin_unlock_irqrestore(&dvsipc_instance_lock, flags);

    if (instance == NULL)
        return;

    dvsipc_put_instance(instance);

    return;
}

int
dvsipc_start_instance(enum dvsipc_instance_id instance_id, struct dvsipc_instance_parameters *params)
{
    struct dvsipc_instance *instance = NULL;
    struct dvsipc_thread_pool *thread_pool = NULL;
    struct dvsipc_incoming_msgq *inmsgq = NULL;
    int rval;

    instance = dvsipc_create_instance();
    if (instance == NULL)
        return -ENOMEM;

    thread_pool = dvsipc_create_thread_pool(params->thread_name,
                                            params->thread_min,
                                            params->thread_max,
                                            params->thread_limit,
                                            params->thread_concurrent_creates,
                                            params->thread_nice);
    if (thread_pool == NULL) {
        rval = -ENOMEM;
        goto out_error;
    }
    thread_pool->instance = instance;
    instance->thread_pool = thread_pool;

    inmsgq = dvsipc_create_incoming_msgq(params->inmsgq_name,
                                         params->init_free_qhdrs,
                                         params->max_free_qhdrs,
                                         params->single_msg_queue,
                                         params->get_queue_key);
    if (inmsgq == NULL) {
        rval = -ENOMEM;
        goto out_error;
    }
    inmsgq->thread_pool = thread_pool;
    thread_pool->inmsgq = inmsgq;

    rval = dvsipc_start_incoming_msgq(inmsgq);
    if (rval < 0)
        goto out_error;

    rval = dvsipc_start_thread_pool(thread_pool);
    if (rval < 0)
        goto out_error;

    rval = dvsipc_add_instance(instance, instance_id);
    if (rval < 0)
        goto out_error;

    IPC_LOG("Added instance %d\n", instance_id);

    return 0;

out_error:
    if (thread_pool)
        dvsipc_stop_thread_pool(thread_pool);
    if (inmsgq)
        dvsipc_stop_incoming_msgq(inmsgq);
    dvsipc_put_instance(instance);

    return rval;
}

static noinline struct usiipc *get_queue_msg(struct dvsipc_thread *thread);
static noinline void queue_msg_cleanup(struct usiipc *, struct dvsipc_instance *instance);

/*
 * Inbound message processing interface.
 */
int
process_message_thread(void *param)
{
    struct dvsipc_thread_pool *thread_pool;
    struct dvsipc_thread *thread;
    struct usiipc *msg;
    unsigned long flags;
    unsigned long debug = 0;
    int rval;

    thread = (struct dvsipc_thread *)param;
    thread_pool = thread->thread_pool;

    KDEBUG_IPC(0, "%s: msgthread_init: thread = 0x%p\n", __FUNCTION__,
               thread);

    if (dvs_daemonize(thread_pool->thread_name) < 0) {
        KDEBUG_IPC(0, "%s: dvs_daemonize failure: exiting.\n", __FUNCTION__);
        spin_lock_irqsave(&thread_pool->lock, flags);
        thread_pool->thread_count -= 1;
        thread_pool->in_progress_creates -= 1;
        spin_unlock_irqrestore(&thread_pool->lock, flags);

        dvsipc_put_thread(thread);
        return(0);
    }

    thread->task = current;
    spin_lock_irqsave(&thread_pool->lock, flags);
    list_add_tail(&thread->list, &thread_pool->thread_list);
    thread_pool->threads_created += 1;
    thread_pool->in_progress_creates -= 1;
    spin_unlock_irqrestore(&thread_pool->lock, flags);

    kernel_set_task_nice(current, thread_pool->nice);
    dvsipc_set_thread_busy(thread);

    KDEBUG_IPC(0, "msgthread_init: entering while\n");

    while (1) {
        if ((msg = get_queue_msg(thread)) == NULL) {
            if (dvsipc_check_exit_thread(thread))
                break;

            printk("DVS: %s: Error: Unexpected NULL message for thread 0x%p\n",
                   __func__, thread);

            continue;
        }
	debug = msg->debug;
        thread->msg = msg;
        dvsipc_check_create_thread(thread_pool);

        if (msg->command == RQ_IPC_NODE_DOWN) {
            struct ipc_node_down *ndm = (struct ipc_node_down *)msg;
            KDEBUG_IPC(debug, "Processing node down for node %s\n",
                SSI_NODE_NAME(ndm->down_node));
            if (ndm->down_node != usi_node_addr)
                shutdown_node(ndm->down_node);
        }
        else if (usi_callback) {
            if (msg->command == RQ_IPC_NODE_UP) {
                KDEBUG_IPC(debug, "Entering usi_callback with "
                    "RQ_IPC_NODE_UP for node %d.\n",
                    SOURCE_NODE(msg));
                rval = usi_callback(msg->command,
                                    (void *)(long)SOURCE_NODE(msg));
            } else {
                rval = usi_callback(msg->command, msg);
            }

            if (rval < 0 && REPLY_REQUESTED(msg)) {
                if (rval != -EQUIESCE)
                    IPC_LOG("callback error %d for message 0x%p\n", rval, msg);
                if (reply_with_error(msg, rval) < 0)
                    printk("DVS: %s: Could not send error reply for msg 0x%p to "
                           "node %d\n", __func__, msg, msg->source_node);
            }
        } else {
            printk(KERN_ERR "DVS: %s: "
                "Cannot process incoming message (%s)\n",
                __FUNCTION__, rq_cmd_name(msg));
        }

        thread->msg = NULL;
        queue_msg_cleanup(msg, thread_pool->instance);

        if (dvsipc_check_exit_thread(thread))
            break;
    }

    KDEBUG_IPC(debug, "DVS: %s: exiting: pid %d \n", __FUNCTION__,
               current->pid);

    /* sys_exit() isn't needed since the return will clean up the thread */
    return(0);
}

static void
update_base_path(struct fs_struct *fs, struct fs_struct *init_fs)
{
	 KDEBUG_IPC(0, "DVS: %s pid %d reset fs_struct\n",
	       __FUNCTION__, current->pid);

	task_lock(current);
#ifdef RHEL_RELEASE_CODE /* bug 831441 */
	write_lock(&current->fs->lock);
#else
	spin_lock(&current->fs->lock);
#endif

	fs = current->fs;
	init_fs = init_task.fs;

	/* First drop ref on original root and pwd dentry */
	path_put(&fs->root);
	path_put(&fs->pwd);

	/*
	 * Update the current task to point to the same
	 * root and pwd as init.
	 */
#ifdef RHEL_RELEASE_CODE /* bug 831441 */
	read_lock(&init_fs->lock);
#else
	spin_lock(&init_fs->lock);
	write_seqcount_begin(&fs->seq);
#endif

	fs->umask = init_fs->umask;
	fs->root = init_fs->root;
	path_get(&fs->root);
	fs->pwd = init_fs->pwd;
	path_get(&fs->pwd);
#ifdef RHEL_RELEASE_CODE /* bug 831441 */
	read_unlock(&init_fs->lock);
	write_unlock(&current->fs->lock);
#else
	spin_unlock(&init_fs->lock);

	write_seqcount_end(&fs->seq);
	spin_unlock(&current->fs->lock);
#endif
	task_unlock(current);
}

static noinline struct usiipc *
get_queue_msg(struct dvsipc_thread *thread)
{
    struct dvsipc_thread_pool *thread_pool;
    struct usiipc *msg;
    struct msgq_qheader *qhdr;
    unsigned long flags;
    unsigned long debug = 0;

    thread_pool = thread->thread_pool;

retry:
    dvsipc_set_thread_idle(thread);

    /* wait for message */
    if (down_interruptible(&thread_pool->inmsgq->sema)) {
        /* interrupted by a signal */
        flush_signals(current);
        IPC_LOG("Thread 0x%p interrupted by signal\n", thread);
    }

    /*
     * Check to see if the current thread is pointing to the same super block
     * as the init process if not update the root and pwd dentry pointers to
     * match init. This should only happen once right after the switch root
     * has flipped to the actual system root. For rhine systems this will
     * probably be an overlayfs filesystem.
     */
    if (init_task.fs->root.dentry->d_sb !=
        current->fs->root.dentry->d_sb) {
        update_base_path(current->fs, init_task.fs);
    }

    dvsipc_set_thread_busy(thread);
    spin_lock_irqsave(&thread_pool->inmsgq->lock, flags);

    qhdr = msgq_get_next_queue(thread_pool->inmsgq);
    msg = (qhdr == NULL) ? NULL: qhdr->msgq_head;

    if (msg)
        debug = msg->debug;

    KDEBUG_IPC(debug, "DVS: %s: thread 0x%p qhdr 0x%p; msg 0x%p\n",
            __FUNCTION__, thread, qhdr, msg);

    if (msg == NULL) {
        spin_unlock_irqrestore(&thread_pool->inmsgq->lock, flags);
        KDEBUG_IPC(0, "DVS: %s: no message\n", __FUNCTION__);

        /* Check if we were asked to exit */
        if (thread->state == DVSIPC_THREAD_DESTROY)
            return NULL;

        IPC_LOG("NULL message for thread 0x%p\n", thread);
        dvs_alive();

        goto retry;
    }

    if (thread->state == DVSIPC_THREAD_DESTROY)
        dvs_alive(); /* just in case there are 1000s of queues */

    remove_from_queue(msg, &(qhdr->msgq_head), &(qhdr->msgq_tail));
    if (qhdr->msgq_head == NULL) {
        msgq_set_idle_qheader_timer(qhdr);
    }
    spin_unlock_irqrestore(&thread_pool->inmsgq->lock, flags);
    MSGQ_DEC_QLEN(qhdr);

    /*
     * Reply to errant inbound message
     */
    if (msg->command == RQ_IPC_DISPOSE ||
        msg->sender_identity !=
            remote_node_info[msg->source_node].identity ||
        (msg->receiver_identity != 0 &&
        msg->receiver_identity != local_identity)) {
            DVS_TRACEL("rcvDISP", local_identity,
                msg->receiver_identity, msg->sender_identity,
                remote_node_info[msg->source_node].identity, 0);
            if (reply_with_error(msg, 0) < 0)
                printk("DVS: %s: Could not send error reply for msg 0x%p to node "
                       "%d\n", __func__, msg, msg->source_node);

            dvsipc_free(msg);
            goto retry;
    }

    DVS_TRACEL("PMT", msg, msg->command, (msg->command==RQ_FILE) ?
            ((struct file_request *)(msg))->request : 0,
            msg->seqno, msg->source_seqno);

    if (signal_pending(current)) {
        printk(KERN_ERR "DVS: %s: "
                "signal pending at start of request: 0x%lx\n",
                __FUNCTION__,
                current->pending.signal.sig[0]);
        flush_signals(current);
    }

    /*
     * Current's pts_usiipc must point to message being processed
     * for use in a callback
     */
    spin_lock_irqsave(&thread_pool->inmsgq->lock, flags);
    BUG_ON(msg->state != ST_SV_MSG_QUEUED);
    add_to_active_queue(msg, thread_pool->instance);
    spin_unlock_irqrestore(&thread_pool->inmsgq->lock, flags);

    return msg;
}

static noinline void
queue_msg_cleanup(struct usiipc *msg, struct dvsipc_instance *instance)
{
    unsigned long flags;

    spin_lock_irqsave(&instance->thread_pool->inmsgq->lock, flags);
    remove_from_active_queue(msg, instance);
    spin_unlock_irqrestore(&instance->thread_pool->inmsgq->lock, flags);

    if (signal_pending(current)) {
        KDEBUG_IPC(0, "DVS: %s: signal "
                "pending at end of request: 0x%lx\n",
                __FUNCTION__,
                current->pending.signal.sig[0]);
        flush_signals(current);
    }

    if (msg->free_required) {
        dvsipc_free(msg);
    }

    return;
}

void
process_incoming_request (struct usiipc *rq) 
{
    struct dvsipc_instance *instance;

    instance = dvsipc_find_instance(rq->instance_id);
    if (instance == NULL) {
        printk("DVS: %s: Error: NULL instance for msg 0x%p\n", __func__, rq);
        return;
    }

    dvsipc_add_msg_to_qheader(instance->thread_pool->inmsgq, rq);

    dvsipc_put_instance(instance);
}

/*
 * Verify the validity of a pending transmit. If the message is
 * authenticated by request address and transmit sequence number.
 */
int
dvsipc_validate_request(struct usiipc *rq, ipc_seqno_t seqno) 
{
    struct usiipc *msg = mq_waiting;

    struct usiipc *cmp_msg = rq->source_request;

    if (cmp_msg == NULL) {
        cmp_msg = container_of(rq->wakeup_word, struct usiipc, msgwait);
    }

    while (msg) {
        if (msg == cmp_msg) {
            if (msg->seqno == seqno) {
                return 1;
            }
        }
        msg = msg->next;
    }

    DVS_TRACE("val!fnd", cmp_msg, seqno);
    return 0;
}

/*
 * Process an incoming reply
 */
static void
dvsipc_do_process_ipc_reply(struct usiipc *reply) 
{
    unsigned long flags;

    /* 
     * Make sure the original request has not been dropped due to
     * a false node-down event. If it has, we avoid further
     * processing of this reply.
     */
    spin_lock_irqsave(&mq_sl, flags);
    if (!dvsipc_validate_request(reply, reply->source_seqno)) {
        DVS_TRACE("RPLY!VAL", reply, reply->source_request);
        spin_unlock_irqrestore(&mq_sl, flags);
        return;
    }
    if (reply->source_request) {
        remove_from_wait_queue(reply->source_request);
    }
    spin_unlock_irqrestore(&mq_sl, flags);

    memcpy(reply->reply_address, reply, reply->request_length);

    /* wakeup reply->wakeup_word */
    up ((struct semaphore *)reply->wakeup_word);
}

/*
 * handle incoming ipc messages
 */
static void
dvsipc_do_rcv(struct usiipc *ipc_header) 
{
    int node;
    unsigned long flags;
    struct remote_info *rni;
    rx_buf_info_t *bip = (void*)ipc_header->transport_handle;

    dvs_alive();                             /* keep rca happy */

    INIT_LIST_HEAD(&ipc_header->active_rx);
    node = ipc_header->source_node;
    KDEBUG_IPC(0, "DVS: ipc msg (%s) recvd from %s len: %d \n",
        rq_cmd_name(ipc_header),
        SSI_NODE_NAME(node), ipc_header->request_length);

    if (bip->unlinked) {
        DVS_TRACE("CLRBUF", bip->index, rx_buf_table[bip->index].buf);
        rx_buf_table[bip->index].buf = NULL;
        KDEBUG_IPC(0, "%s: buf %d unlinked\n", __FUNCTION__, bip->index);
        up(&refill_sema);
    } else {
        smp_mb();
    }

    if ((node < 0) || (node >= max_nodes)) {
        printk(KERN_ERR "DVS: %s: "
            "Message from impossible node %d\n", __FUNCTION__, node);
        if (ipc_header->free_required) {
            ipc_header->command = RQ_SUSPECT;
            ipc_header->reply_address = bip;  /* convention for suspect */
            dvsipc_free(ipc_header);
        }
        return;
    }

    if (!dvsipc_init_complete || shutdown) {
        printk(KERN_INFO "DVS: %s: rx path not initialized "
            "or is shutting down, dropping %s from node %s\n", __FUNCTION__,
            rq_cmd_name(ipc_header), SSI_NODE_NAME(node));
        if (ipc_header->free_required) {
            dvsipc_free(ipc_header);
        }
        return;
    }

    if (ipc_header->command == RQ_IPC_DISPOSE || msg_is_dup(ipc_header)) {
        dvsipc_free(ipc_header);
        return;
    }

    /* Add this message to the live message list */
    link_rx_msg(ipc_header);

    /* update statistics */
    DVSIPC_STAT_INC(DVSIPC_STAT_RX, 1);
    DVSIPC_SIZE_INC(DVSIPC_STAT_RX, ipc_header->request_length);
    DVSIPC_STAT_INC(DVSIPC_STAT_RX_BYTES, ipc_header->request_length);

    /*
     * Don't lock the remote_node_info in this case so that we don't
     * impact performance by serializing messages from the same
     * client. If the node goes down after this point, we'll see that
     * when we attempt to send the reply.
     */
    rni = &remote_node_info[node];
    if (rni->identity != ipc_header->sender_identity) {
	    /*
	     * The local copy of the nodes identity gets incremented on a failure.
	     * If the messages identity is bigger than the local copy, the node must
	     * have rebooted while we were sleeping.  If the local copy of the
	     * identity is bigger, that means a failure came in.
	     */
        if (rni->identity < ipc_header->sender_identity) {


            /*
             * cleanup state from previous instantiation.
             */
	    cleanup_stale_messages (node, ipc_header->sender_identity);

            KDEBUG_IPC(0, "DVS: %s: Node discovered: %s %ld != %ld %d old_status = %d\n",
                   __FUNCTION__, SSI_NODE_NAME(node), 
                   ipc_header->sender_identity, rni->identity,
                   ipc_header->command,rni->node_status);

            DVS_TRACEL("nd", node, ipc_header->sender_identity,
				rni->identity,
				ipc_header->command, 0);


	    /*
	     * It's possible that while we weren't holding the lock, an
	     * error came in to cause the identity to change.  We don't
	     * want to erase that information.
	     *
	     * This is one of just 2 places where we'll use the rni->lock to
	     * protect a series of decisions and actions using the remote_node_info.
	     * The other place is in shutdown_node().
	     */
	    spin_lock_irqsave(&rni->lock, flags);
            if (rni->identity < ipc_header->sender_identity) {
		    rni->identity = ipc_header->sender_identity;
		    rni->node_status = Node_Status_Up;
	    }
	    spin_unlock_irqrestore(&rni->lock, flags);
        } else {
            /*
             * Node that was previously downed has
             * resumed execution.  Must discard all
             * messages from that node instance
             * until it restarts.
             */
            if (rni->node_status == Node_Status_Down) {
                printk(KERN_ERR "DVS: %s: Message (%s) from "
                    "downed node %s discarded (%ld != %ld -> %ld %ld)\n",
                    __FUNCTION__, rq_cmd_name(ipc_header),
                    SSI_NODE_NAME(node), rni->identity,
                    ipc_header->sender_identity, local_identity,
                    ipc_header->receiver_identity);
            } else {
                printk(KERN_ERR "DVS: %s: Message (%s) from "
                    "NOT DOWNED node %s discarded (%ld != %ld -> %ld %ld) status = %d\n",
                    __FUNCTION__, rq_cmd_name(ipc_header),
                    SSI_NODE_NAME(node), rni->identity,
                    ipc_header->sender_identity, local_identity,
                    ipc_header->receiver_identity,rni->node_status);
	    }
            ipc_header->command = RQ_IPC_DISPOSE;
	    process_incoming_request(ipc_header);
            return;
        }
    }

    /*
     * validate local node message identity
     */
    if (ipc_header->receiver_identity != 0) {
        if (ipc_header->receiver_identity != local_identity) {
            /*
             * Since error reply may sleep, pass this on
             * to a handler thread.
             */
            ipc_header->command = RQ_IPC_DISPOSE;
            process_incoming_request(ipc_header);
            return;
        }
    }

    if (ipc_header->target_node != usi_node_addr) {
        KDEBUG_IPC(0, "DVS: bad target node (0x%x,0x%x)\n",
            ipc_header->target_node, usi_node_addr);
        dvsipc_free(ipc_header);
    } else if (ipc_header->command == RQ_REPLY) {
        dvsipc_do_process_ipc_reply(ipc_header);
        dvsipc_free(ipc_header);
    } else if (ipc_header->command == RQ_REPLY_ERROR) {
        KDEBUG_IPC(0, "DVS: %s: Got REPLY_ERROR from node %d 0x%p "
            "0x%p \n", __FUNCTION__, ipc_header->source_node,
            ipc_header->reply_address, ipc_header->wakeup_word);
        ipc_header->command = RQ_IPC_FAILURE;
        dvsipc_do_process_ipc_reply(ipc_header);
        dvsipc_free(ipc_header);
    } else if (ipc_header->command == RQ_CALLBACK) {
        ipc_header->free_required = 1;
        if (do_callback(ipc_header)) {
            /* failure */
            KDEBUG_IPC(0, "DVS: do_callback failed (0x%p)\n",
                ipc_header);
        }
    } else if (ipc_header->command == RQ_IPC_HEARTBEAT) {
        printk(KERN_ERR "DVS: %s: dropping RQ_IPC_HEARTBEAT from 0x%x\n",
            __FUNCTION__,
            SOURCE_NODE(ipc_header));
        dvsipc_free(ipc_header);
    } else {
        ipc_header->free_required = 1;
        process_incoming_request(ipc_header);
    }
}

/*
 * Handle an incoming IPC RMA Put notification.
 */
static void
dvsipc_rma_put_complete(struct ipc_mapping *handle, int status, void *addr,
			size_t length)
{
	if (handle->read_handler) {
		handle->read_handler(handle->prq, status, addr, length);
	}
}

/*
 * Process a callback request
 * Fake a reply to trigger the originating thread to process the callback.
 */
static int
do_callback(struct usiipc *request) 
{
    struct usiipc *crequest, *creply;

    /* forward to original client; callback_handle is original request */
    request->command = request->callback_command;
    crequest = request->original_request;
    if (crequest == NULL) {
        printk(KERN_ERR "DVS: do_callback: client request is null \n");
        return(-USIERR_INTERNAL);
    }
    creply = crequest->reply_address;
    if (creply == NULL) {
        printk(KERN_ERR "DVS: do_callback: no reply \n");
        return(-USIERR_INTERNAL);
    }
    if (creply->callback != NULL) {
        printk(KERN_ERR "DVS: do_callback: callback already queued \n");
        return(-USIERR_INTERNAL);
    }

    DVS_TRACEL("do_cb", request, creply, crequest->wakeup_word, 0, 0);

    creply->callback = request;
    creply->command = RQ_CALLBACK;
    up ((struct semaphore *)crequest->wakeup_word);
    return(0);
}

/*
 * Implementation of dvs ipc remote memory access (RMA) interface.
 */
void *
dvsipc_rma_get(int node, char *to, char *from, ssize_t length, 
               void *rma_handle, int async)
{
    unsigned long flags;
    rma_info_t *rip;
    u64 nid;
    void *ret;

    KDEBUG_IPC(0, "DVS: %s: (%d:0x%p:0x%p:0x%lx:0x%p)\n", __FUNCTION__,
        node, to, from, length, rma_handle);

    nid = dvsipc_lnode_to_node(node);
    if (nid == DVSIPC_INVALID_NODE) {
        printk(KERN_ERR "DVS: %s: attempt to perform get rma from bad node %s (%d)\n", 
                         __FUNCTION__, SSI_NODE_NAME(node), node);
        DVS_TRACE("!DRMAG", node, 0); 
        return ERR_PTR(-EINVAL);
    }

    rip = (rma_info_t*)kmalloc_ssi(sizeof(rma_info_t), GFP_KERNEL);
    if (rip == NULL) {
        return ERR_PTR(-ENOMEM);
    }
    DVS_TRACE("drmaget", rip, 0);

    INIT_LIST_HEAD((struct list_head *)&rip->list);
    spin_lock_irqsave(&dvsipc_rma_list_lock, flags);
    list_add(&rip->list, &dvsipc_rma_list);
    spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);

    while (1) {
        rip->rma_type = RMA_GET;
        rip->retval = 0;
        rip->length = length;
        rip->handle = (uint64_t)((void *)(rma_handle));
        rip->nid = nid;
        rip->lnid = node;
        sema_init(&rip->sema, 0);

        ret = ipclower_rma_get(nid, to, from, length, rip, 
                               dvsipc_tx_timeout*2, async);
        if (!IS_ERR(ret) || PTR_ERR(ret) == -EHOSTDOWN)
            break;

        sleep(1);
        printk("DVS: %s: Retrying RMA GET from nid %llu with length %ld\n",
               __func__, nid, length);
    }

    if (async == 0 || IS_ERR(ret)) {
        spin_lock_irqsave(&dvsipc_rma_list_lock, flags);
        list_del(&rip->list);
        spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);

        /* update statistics */
        if (IS_ERR(ret)) {
            DVSIPC_STAT_INC(DVSIPC_STAT_ERROR, 1);
        } else {
            DVSIPC_STAT_INC(DVSIPC_STAT_GET, 1);
            DVSIPC_SIZE_INC(DVSIPC_STAT_GET, (long)ret);
            DVSIPC_STAT_INC(DVSIPC_STAT_GET_BYTES, (long)ret);
        }

        kfree_ssi(rip);
        DVS_TRACE("drmagF", rip, 0);
        return ret;
    }

    return rip;
}

void *
dvsipc_rma_put(int node, char *to, char *from, ssize_t length, 
               void *rma_handle, int async)
{
    rma_info_t *rip;
    u64 nid;
    void *ret;
    unsigned long flags;

    KDEBUG_IPC(0, "DVS: %s (%d:0x%p:0x%p:0x%lx:0x%p)\n", __FUNCTION__,
        node, to, from, length, rma_handle);

    nid = dvsipc_lnode_to_node(node);
    if (nid == DVSIPC_INVALID_NODE) {
        printk(KERN_ERR "DVS: %s: attempt to perform put rma to bad node %s (%d)\n", 
                         __FUNCTION__, SSI_NODE_NAME(node), node);
        DVS_TRACE("!DRMAP", node, 0); 
        return ERR_PTR(-EINVAL);
    }

    rip = (rma_info_t*)kmalloc_ssi(sizeof(rma_info_t), GFP_KERNEL);
    if (rip == NULL) {
        return ERR_PTR(-ENOMEM);
    }

    INIT_LIST_HEAD((struct list_head *)&rip->list);
    spin_lock_irqsave(&dvsipc_rma_list_lock, flags);
    list_add(&rip->list, &dvsipc_rma_list);
    spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);

    while (1) {
        rip->rma_type = RMA_PUT;
        rip->retval = 0;
        rip->length = length;
        rip->handle = (uint64_t)((void*)rma_handle);
        rip->nid = nid;
        rip->lnid = node;
        sema_init(&rip->sema, 0);

        ret = ipclower_rma_put(nid, to, from, length, rip, 
                               dvsipc_tx_timeout, async);
        if (!IS_ERR(ret) || PTR_ERR(ret) == -EHOSTDOWN)
            break;

        sleep(1);
        printk("DVS: %s: Retrying RMA PUT to nid %llu with length %ld\n",
               __func__, nid, length);
    }

    if (async == 0 || IS_ERR(ret)) {
        spin_lock_irqsave(&dvsipc_rma_list_lock, flags);
        list_del(&rip->list);
        spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);

        /* update statistics */
        if (IS_ERR(ret)) {
            DVSIPC_STAT_INC(DVSIPC_STAT_ERROR, 1);
        } else {
            DVSIPC_STAT_INC(DVSIPC_STAT_PUT, 1);
            DVSIPC_SIZE_INC(DVSIPC_STAT_PUT, (long)ret);
            DVSIPC_STAT_INC(DVSIPC_STAT_PUT_BYTES, (long)ret);
        }
        kfree_ssi(rip);
        DVS_TRACE("drmapF", rip, 0);
        return ret;
    }

    return rip;
}

void
dvsipc_rma_wait(rma_info_t *rip)
{
    unsigned long flags;
    ipclower_rma_wait(rip);
    spin_lock_irqsave(&dvsipc_rma_list_lock, flags);
    list_del(&rip->list);
    spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);
}

void
dvsipc_setup_rma(struct rma_state *rmasp) 
{
    KDEBUG_IPC(0, "DVS: %s: 0x%p 0x%p 0x%p\n",  __FUNCTION__,
        rmasp, rmasp->remote_addr, rmasp->handle);
}

int
dvsipc_end_rma(struct rma_state *rmasp) 
{
    int rval = 0;

    if (rmasp->flush && rmasp->buffer) {
        if (rmasp->valid_size != 0) {
            KDEBUG_IPC(0, "DVS: %s: flushing buffer "
                "(final): %d 0x%p 0x%p %d 0x%p\n", __FUNCTION__,
                rmasp->node, rmasp->buffer_remote_start,
                rmasp->buffer, rmasp->valid_size,
                rmasp->handle);
            rval = ipc_rma_put(rmasp->node,
                rmasp->buffer_remote_start, rmasp->buffer,
                rmasp->valid_size, rmasp);
            if (rval != rmasp->valid_size) {
                DVS_TRACEL("ssErmaF", 
                    rmasp->buffer_remote_start,
                    rmasp->buffer, rmasp->valid_size,
                    rval, 0);
                KDEBUG_IPC(0, "DVS: %s: error 0x%x\n", __FUNCTION__, rval);
            }
        }
    }

    KDEBUG_IPC(0, "%s: out %d\n", __FUNCTION__, rval);
    DVS_TRACE("endOUT", rval, 0);
    return rval;
}

/*
 * Allow RCA interface to be disabled for simulation environments.
 */
#if USE_RCA

static krca_ticket_t krt = KRCA_NULL_TICKET;

/*
 * The following routine is used to provide a safe shutdown
 * mechanism for the heartbeat thread.
 */
static void
wakeup_heartbeat(unsigned long arg) 
{
    krca_wakeup_wait_event(&krt);
}

/*
 * Translate a rs_node_t structure into a logically formatted c-name.
 */
static inline void
rs_node2cname(char *cname, rs_node_t *rs_nodep)
{
	int type = RSN_GET_FLD(rs_nodep->rs_node_flat, TYPE);

#if !defined(CRAY_ATHENA)
	sprintf(cname, "c%d-%dc%ds%dn%d%s",
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, X),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, ROW),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, CAGE),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, SLOT),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, MODCOMP),
		type == rt_accel ? "a0" : "");
#else  /* defined(CRAY_ATHENA) */
	uint64_t x,row;
 
	x =  RSN_GET_FLD(rs_nodep->rsn_intval,X);
	row = RSN_GET_FLD(rs_nodep->rsn_intval,ROW);

	sprintf(cname, "r%ds%dc%dn%d%s",
		(int)RSN_ATHENA_RACK_FROM_X_ROW(x,row),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, CAGE),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, SLOT),
		(int)RSN_GET_FLD(rs_nodep->rs_node_flat, MODCOMP),
		type == rt_accel ? "a0" : "");
#endif /* !defined(CRAY_ATHENA) */
}

/*
 * Certain node failure events are soft and should be
 * ignored. This routine filters those events.
 */
static inline int
ignore_event(rs_event_t *event)
{
    if (event->ev_id == ec_node_failed && event->ev_len > 0) {
        KDEBUG_IPC(0, "DVS: %s: %s ignored, len=%d\n", __FUNCTION__,
                    evttype(event->ev_id), event->ev_len);
        DVS_TRACE("ignevt", event->ev_id, event->ev_len);
        return 1;
    }
    KDEBUG_IPC(0, "DVS: %s: %s not ignored, len=%d\n", __FUNCTION__,
                        evttype(event->ev_id), event->ev_len);
    DVS_TRACE("!ignevt", event->ev_id, event->ev_len);
    return 0;
}

#define NUM_RCA_EVENTS	5
struct rcadata {
	rca_ticket_t	ticket;
	int		subscribed;
	rs_event_code_t	code;
	rs_service_id_t	generator;
};

/*
 * heartbeat_thread - Monitor general node health through
 *                    RCA event subscription.
 */
static int
heartbeat_thread(void *param) 
{
    int rval;
    int i, retries = 0;
    rs_node_t nodeid;
    int false_down = 0;
    dvs_config_params_t *dvs_prev_config_params = NULL;
    struct rcadata rd[NUM_RCA_EVENTS] = {
	{0, 0, ec_service_failed, DVS_RCA_RX},
	{0, 0, ec_node_unavailable, RCA_RX_SVC_ANY},
	{0, 0, ec_node_available, RCA_RX_SVC_ANY},
	{0, 0, ec_node_failed, RCA_RX_SVC_ANY},
	{0, 0, ec_dvs_service_started, RCA_RX_SVC_ANY}
    };

    KDEBUG_IPC(0, "DVS: heartbeat_thread: Heartbeat thread started (%d)\n",
        current->pid);
    kernel_set_task_nice(current, -10);

    hb_thread = current;

    /*
     * Register our service with RCA and subscribe to events
     * of interest.
     */
    rval = krca_register(&krt, RCA_SVCTYPE_DVS, current->pid, 0);
    if (rval < 0) {
        printk(KERN_ERR "DVS: heartbeat_thread(0x%x): register ret %d\n",
            current->pid, rval);
        goto done;
    }

    for (i = 0; i < NUM_RCA_EVENTS; i++) {
retry_subscribe:
	if ((rval = krca_subscribe(&krt, rd[i].code, rd[i].generator,
				   &rd[i].ticket)) < 0) {
	    if ((rval == -EINTR) && (retries++ < 5))
		goto retry_subscribe;
	    printk(KERN_ERR "DVS: %s: rca subscription failed (%d,%d)\n",
		   __FUNCTION__, i, rval);
	    goto done;
	}
	IPC_LOG("Successfully subscribed to event %d in list\n", i);
	rd[i].subscribed = 1;
	retries = 0;
    }

    if ((rval = krca_get_nodeid(&nodeid)) < 0 ) {
        printk(KERN_ERR "DVS: %s: can't determine node ID (%d)\n", 
               __FUNCTION__, rval);
        goto done;
    }

    while (!shutdown) {
        rs_event_t event;
        rs_state_t state;

	/* let others know we're here on startup or switch to server config */
        if (dvs_cur_config_params->send_rca_event &&
			   (dvs_cur_config_params != dvs_prev_config_params)) {
	    KDEBUG_IPC(0, "DVS: server node available \n");
	    (void)krca_send(&krt, ec_dvs_service_started, DVS_RCA_TX(nodeid),
			    "dvs_service", RCA_LOG_INFO);
        }
	dvs_prev_config_params = dvs_cur_config_params;

retry_wait:
	/* block waiting for a message or for someone to wake us */
	rval = krca_wait_event(&krt);
	if (rval < 0) {
	    if (rval == -ERESTARTSYS) {
		if (retries++ < 5)
		    goto retry_wait;
	    }
	    printk_once(KERN_ERR "DVS: %s: krca_wait_event returned %d\n",
			__FUNCTION__, rval);
	}
	retries = 0;

        while ((rval = krca_check_message(&krt)) == 1) {
            if (krca_get_message(&krt, &event) == 0) {
                int nid = RSMS_GET_COMP_NID(event.ev_gen.svid_node);
                long lnid;
		char cname[32];
		char krca_payload[64];

		rs_node2cname(&cname[0], &event.ev_gen.svid_node);
		if ((lnid = dvsipc_name2nid(cname)) < 0)
			continue;

		IPC_LOG("Received event %s for %s, nid %ld\n", evttype(event.ev_id), cname, lnid);

		/*
		 * Ignore overloaded ec_node_unavailable events generated
		 * by 'xtcli set_reserve'.
		 */
		if (event.ev_id == ec_node_unavailable) {
		    state = RSN_GET_FLD(event.ev_gen.svid_node.rsn_intval,
					STATE);
		    if (RS_GET_CS_STATE(state) == RS_CS_READY) {
			KDEBUG_IPC(0, "DVS: %s: ignoring event %s with "
				   "RS_CS_READY state from 0x%x/0x%lx/%s\n",
				   __FUNCTION__, evttype(event.ev_id), nid,
				   lnid, SSI_NODE_NAME(lnid));
			continue;
		    }
		}

                KDEBUG_IPC(0, "DVS: heartbeat_thread: %s %s %s %s "
                    "0x%x/0x%lx/%s/%s\n", evttype(event.ev_id),
                    svctype(event.ev_src.svid_type),
                    instype(event.ev_src.svid_inst),
                    nodetype(event.ev_src.svid_node), nid, lnid,
                    SSI_NODE_NAME(lnid), event.ev_data);

                switch(event.ev_id) {
                    case ec_node_available:
			/* might have been generated by 'xtcli clr_reserve' */
                        if ((lnid == usi_node_addr) && false_down) {
                            printk(KERN_ERR "DVS: %s: node revived\n", 
                               __FUNCTION__);
                            false_down = 0;
			    snprintf(krca_payload, sizeof(krca_payload), "dvs_service 0x%lx", local_identity);
                            (void)krca_send(&krt, ec_dvs_service_started, 
                                DVS_RCA_TX(nodeid),
                                krca_payload, RCA_LOG_INFO);
                        }
                        break;
                    case ec_node_failed:
                        if (ignore_event(&event)) {
                           break;
                        }
                    case ec_node_unavailable:
                        if (lnid == usi_node_addr) {
                           printk(KERN_ERR "DVS: %s: detected false node down "
                                           "event.\n", __FUNCTION__);
                           false_down++;
                           DVS_TRACE("hbLND", nid, lnid);
                           cleanup_stale_messages(-1, NO_IDENTITY);
                           if (usi_callback) {
                                usi_callback(RQ_IPC_NODE_DOWN, (void *)lnid);
                           }
                        } else {
                           KDEBUG_IPC(0, "DVS: %s: Node down event for %s\n",
                                           __FUNCTION__, SSI_NODE_NAME(lnid));
                        }
                    case ec_service_failed:
                        DVS_TRACE("hbNF", nid, lnid);
                        if (lnid != usi_node_addr) {
                            if (lnid >= 0) {
                                shutdown_node(lnid);
                                if (usi_callback) {
                                    usi_callback(RQ_IPC_NODE_DOWN,
                                                 (void *)lnid);
                                }
                            }
                        }
                        break;
                    case ec_dvs_service_started:
                        DVS_TRACE("hbSS", nid, lnid);
                        KDEBUG_IPC(0, "DVS: %s: detected revived node %s\n",
                               __FUNCTION__, SSI_NODE_NAME(lnid));
                        if (!strncmp(event.ev_data,
                            "dvs_service", strlen("dvs_service")) &&
                            usi_callback && lnid != usi_node_addr && lnid >= 0) {
                            KDEBUG_IPC(0, "DVS: %s now active.\n",
                                SSI_NODE_NAME(lnid));
                            revive_node(lnid);
                            usi_callback(RQ_IPC_NODE_UP, (void *)lnid);
                        }
                        break;
                    default:
                        printk(KERN_ERR "DVS: heartbeat_thread: "
                            "unknown event 0x%x (0x%x,%s)\n",
                            event.ev_id, nid, SSI_NODE_NAME(lnid));
                        break;
                }
            } else {
                printk(KERN_ERR "DVS: heartbeat_thread: krca_get_message "
                    "FAILED\n");
            }
        }
    }

done:
    KDEBUG_IPC(0, "DVS: heartbeat_thread: DONE\n");

    for (i = 0; i < NUM_RCA_EVENTS; i++) {
	if (rd[i].subscribed)
	    (void) krca_unsubscribe(&krt, rd[i].ticket);
    }

    /* Let others know that we're gone. */
    (void)krca_send(&krt, ec_service_failed, DVS_RCA_TX(nodeid), 
                    "dvs_service", RCA_LOG_INFO);

    krca_unregister(&krt);

    hb_thread = NULL;
    /* sys_exit() not needed since the return will get us out of here and
       the thread code will clean up */

    return(0);
}
#endif /* USE_RCA */

/*
 * Translate a c-name string to a logical node ordinal from
 * the node map.
 */
int
dvsipc_name2nid(char *name)
{
    int node;

    for (node=0; node < max_nodes; node++) {
        if (node_map[node].name && (strcmp(node_map[node].name, name) == 0)) {
            KDEBUG_IPC(0, "DVS: %s: %s = %d\n", __FUNCTION__, name, node);
            return node;
        }
    }
    KDEBUG_IPC(0, "DVS: %s: %s not found\n", __FUNCTION__, name);
    return -1;
}

/* Initialize params that distinguish between client and server configs */
#define CLIENT_PARAMS dvs_config_params[dvs_config_type_client]
#define SERVER_PARAMS dvs_config_params[dvs_config_type_server]

static int
dvsipc_init_config_type_params(void)
{
    if (dvsipc_config_type == dvs_config_type_client) {
        dvs_cur_config_params = &CLIENT_PARAMS;
    } else if (dvsipc_config_type == dvs_config_type_server) {
        dvs_cur_config_params = &SERVER_PARAMS;
    } else {
        printk(KERN_ERR "DVS: %s: bad dvsipc_config_type value specified (%d)\n",
               __FUNCTION__, dvsipc_config_type);
        return(-EINVAL);
    }

    if (dvsipc_num_rx_mds > DVSIPC_MAX_RX_MDS) {
        printk(KERN_ERR "DVS: %s: bad dvsipc_num_rx_mds value "
               "specified (%d); exceeds max (%d)\n",
               __FUNCTION__, dvsipc_config_type, DVSIPC_MAX_RX_MDS);
        return(-EINVAL);
    }

    /* module params override defaults */
    if (dvsipc_buf_limit != -1) {
        CLIENT_PARAMS.buf_limit = dvsipc_buf_limit;
        SERVER_PARAMS.buf_limit = dvsipc_buf_limit;
    }
    if (dvsipc_buf_timeout != -1) {
        CLIENT_PARAMS.buf_timeout = dvsipc_buf_timeout;
        SERVER_PARAMS.buf_timeout = dvsipc_buf_timeout;
    }
    if (dvsipc_msg_thread_max != -1) {
        if (dvsipc_msg_thread_max <= 0) {
            printk(KERN_ERR "DVS: %s: Error: Invalid value %d for "
                   "dvsipc_msg_thread_max\n", __func__,
                   dvsipc_msg_thread_max);
            return -EINVAL;
        }

        CLIENT_PARAMS.max_msg_threads = dvsipc_msg_thread_max;
        SERVER_PARAMS.max_msg_threads = dvsipc_msg_thread_max;
    }

    if (dvsipc_msg_thread_min != -1) {
        if (dvsipc_msg_thread_min <= 0) {
            printk(KERN_ERR "DVS: %s: Error: Invalid value %d for "
                   "dvsipc_msg_thread_min\n", __func__,
                   dvsipc_msg_thread_min);
            return -EINVAL;
        }

        CLIENT_PARAMS.msg_threads = dvsipc_msg_thread_min;
        SERVER_PARAMS.msg_threads = dvsipc_msg_thread_min;
    }

    if (CLIENT_PARAMS.msg_threads > CLIENT_PARAMS.max_msg_threads) {
        printk(KERN_ERR "DVS: %s: Error: msg_threads is greater than "
               "max_msg_threads. %d > %d\n", __func__, CLIENT_PARAMS.msg_threads,
               CLIENT_PARAMS.max_msg_threads);
        return -EINVAL;
    }

    if (SERVER_PARAMS.msg_threads > SERVER_PARAMS.max_msg_threads) {
        printk(KERN_ERR "DVS: %s: Error: msg_threads is greater than "
               "max_msg_threads. %d > %d\n", __func__, SERVER_PARAMS.msg_threads,
               SERVER_PARAMS.max_msg_threads);
        return -EINVAL;
    }

    if (dvsipc_single_msg_queue != 0) {
        /* set values so freepool is always empty */
        CLIENT_PARAMS.msgq_init_free_qhdrs = 0;
        CLIENT_PARAMS.msgq_max_free_qhdrs  = 0;
        SERVER_PARAMS.msgq_init_free_qhdrs = 0;
        SERVER_PARAMS.msgq_max_free_qhdrs  = 0;
    }

    dvsipc_alloc_msg_threads =
        max(CLIENT_PARAMS.max_msg_threads, SERVER_PARAMS.max_msg_threads);

    return 0;
}

/*
 * Initialize the ipc interface.
 */
static int
dvsipc_ipc_init(ssize_t *max_transport_msg_size) 
{
    int i, rval;
    uint64_t dvsipc_lower_nodeid;
    struct task_struct *task;
    struct dvsipc_instance_parameters *params;

    if (max_nodes == 0) {
        printk(KERN_ERR "DVS: %s: max_nodes not set.\n", __FUNCTION__);
        return(-EINVAL);
    }

    if ((rval=ipclower_init(&dvsipc_lower_nodeid, &upper_api, 
                            max_transport_msg_size, dvsipc_num_rx_mds)) < 0) {
        printk(KERN_ERR "DVS: transport init failed (%d)\n", rval);
        return(rval);
    }

    KDEBUG_IPC(0, "%s: lower addr 0x%Lx\n", __FUNCTION__, dvsipc_lower_nodeid);
    atomic_set(&freelist_buffer_count, 0);
    atomic_set(&rx_buffer_count, 0);
    /*
     * Create receive buffers for normal in-band and unreliable ipc traffic.
     */
    for (i = dvsipc_num_rx_mds-1; i >= 0; i--) {
        int ret;

        DVS_TRACE("fill", i, dvsipc_num_rx_mds);
        rx_buf_table[i].buf = dvsipc_new_rx_buf();
        if ((ret = dvsipc_fill_rx_slot(i, rx_buf_table[i].buf,
				DVSIPC_RX_BUF_SIZE))) {
            dvsipc_ipc_term();
            return ret;
        } 
    }
    max_buffer_count = dvsipc_dynamic_max_buffer_count();
    freelist_jiffies = jiffies;
    /*
     * Allocate a few extra refill buffers.
     */
    for (i=0; i < dvs_cur_config_params->rsv_bufs; i++)
	    dvsipc_alloc_rx_buf();

    rx_buffer_count_minimum = atomic_read(&rx_buffer_count);

    ssi_nodeid = dvsipc_node_to_lnode(dvsipc_lower_nodeid);

    if (ssi_nodeid == -1) {
        printk(KERN_ERR "DVS: logical node ID for physical node 0x%Lx "
            "not found.  Please check node-map file.\n",
            dvsipc_lower_nodeid);
        dvsipc_ipc_term();
        return -EINVAL;
    }

    usi_node_addr = ssi_nodeid;

    for (i=1; i<=_NSIG; i++)
        sigaddset(&sigmask, i);

    local_identity = CURRENT_TIME.tv_sec;

    remote_node_info = vmalloc_ssi(max_nodes * sizeof(struct remote_info));

    if (!remote_node_info) {
        dvsipc_ipc_term();
        return -ENOMEM;
    }

    /* Initialize per node rx state */
    for (i=0; i<max_nodes; i++) {
        remote_node_info[i].node_status = Node_Status_Up;
        remote_node_info[i].identity = 0L;
	INIT_LIST_HEAD(&remote_node_info[i].msgs);
        spin_lock_init(&remote_node_info[i].lock); 
    }
        
    remote_node_info[usi_node_addr].identity = local_identity;

    /* start the refill thread */
    task = kthread_run(dvsipc_refill_thread, NULL, "%s", "DVS-refill");
    if (IS_ERR(task)) {
        printk(KERN_ERR "DVS: %s: couldn't start refill thread (%ld)\n",
            __FUNCTION__, PTR_ERR(task));
        dvsipc_ipc_term();
        vfree(remote_node_info);
        return PTR_ERR(task);
    }

#if USE_RCA
    /* start the heartbeat thread */
    task = kthread_run(heartbeat_thread, NULL, "%s", "DVS-heartbeat");
    if (IS_ERR(task)) {
        printk(KERN_ERR "DVS: %s: couldn't start heartbeat thread (%ld)\n",
            __FUNCTION__, PTR_ERR(task));
        dvsipc_ipc_term();
        vfree(remote_node_info);
        shutdown = 1;
        while (hb_thread || refill_thread) {
            up(&refill_sema);
            nap();
        }
        return PTR_ERR(task);
    }
#endif

    /* Start nak generation thread */
    task = kthread_run(dvsipc_nak_thread, NULL, "%s", "DVS-IPC_nak");
    if (IS_ERR(task)) {
        printk(KERN_ERR "DVS: %s: couldn't start nak thread (%ld)\n",
            __FUNCTION__, PTR_ERR(task));
        dvsipc_ipc_term();
        vfree(remote_node_info);
        shutdown = 1;
#if USE_RCA
        wakeup_heartbeat(0);
#endif
        while (hb_thread || refill_thread) {
	    up (&refill_sema);
            nap();
        }
        return PTR_ERR(task);
    }

    /* Start cached buffer manager thread */
    if (dvs_cur_config_params->buf_timeout) {
        task = kthread_run(dvsipc_buf_thread, NULL, "%s", "DVS-IPC_buf");
        if (IS_ERR(task)) {
            printk(KERN_ERR "DVS: %s: couldn't start buf thread (%ld)\n",
                __FUNCTION__, PTR_ERR(task));
            dvsipc_ipc_term();
            vfree(remote_node_info);
            shutdown = 1;
#if USE_RCA
            wakeup_heartbeat(0);
#endif
            while (hb_thread || refill_thread || nak_thread) {
                up (&refill_sema);
                up (&nak_sema);
                nap();
            }
            return PTR_ERR(task);
        }
    }

    params = &instance_params[DVSIPC_INSTANCE_DVS];
    /* Choose between the defaults or module parameter */
    if (params->count == 8) {
        params->thread_min = params->param_array[0];
        params->thread_max = params->param_array[1];
        params->thread_limit = params->param_array[2];
        params->thread_concurrent_creates = params->param_array[3];
        params->thread_nice = params->param_array[4];
        params->single_msg_queue = params->param_array[5];
        params->init_free_qhdrs = params->param_array[6];
        params->max_free_qhdrs = params->param_array[7];
    } else {
        if (params->count != 0)
            printk("DVS: %s: Warning: Ignoring short dvs_instance_info "
                   "parameter list\n", __func__);
        params->thread_min = dvs_cur_config_params->msg_threads;
        params->thread_max = dvs_cur_config_params->max_msg_threads;
        params->thread_limit = dvsipc_msg_thread_limit;
        params->single_msg_queue = dvsipc_single_msg_queue;
        params->init_free_qhdrs = dvs_cur_config_params->msgq_init_free_qhdrs;
        params->max_free_qhdrs = dvs_cur_config_params->msgq_max_free_qhdrs;
    }

    if ((rval = dvsipc_start_instance(DVSIPC_INSTANCE_DVS,
                                      &instance_params[DVSIPC_INSTANCE_DVS])) < 0) {
        printk(KERN_ERR "DVS: %s: couldn't create dvs instance. Error %d\n",
               __func__, rval);
        dvsipc_ipc_term();
        vfree(remote_node_info);
        shutdown = 1;
#if USE_RCA
        wakeup_heartbeat(0);
#endif
        while (hb_thread || refill_thread || nak_thread || buf_thread) {
            up (&refill_sema);
            up (&nak_sema);
            up (&buf_sema);
            nap();
        }
        return rval;
    }

    params = &instance_params[DVSIPC_INSTANCE_KDWFS];
    /* Alter the defaults if a module parameter was passed in */
    if (params->count == 8) {
        params->thread_min = params->param_array[0];
        params->thread_max = params->param_array[1];
        params->thread_limit = params->param_array[2];
        params->thread_concurrent_creates = params->param_array[3];
        params->thread_nice = params->param_array[4];
        params->single_msg_queue = params->param_array[5];
        params->init_free_qhdrs = params->param_array[6];
        params->max_free_qhdrs = params->param_array[7];
    } else if (params->count != 0) {
        printk("DVS: %s: Warning: Ignoring short kdwfs_instance_info parameter "
               "list\n", __func__);
    }

    if ((rval = dvsipc_start_instance(DVSIPC_INSTANCE_KDWFS,
                                      &instance_params[DVSIPC_INSTANCE_KDWFS])) < 0) {
        printk(KERN_ERR "DVS: %s: couldn't create kdwfs instance. Error %d\n",
               __func__, rval);
        /* dvs instance cleaned up in shutdown_node() */
        dvsipc_ipc_term();
        vfree(remote_node_info);
        shutdown = 1;
#if USE_RCA
        wakeup_heartbeat(0);
#endif
        while (hb_thread || refill_thread || nak_thread || buf_thread) {
            up (&refill_sema);
            up (&nak_sema);
            up (&buf_sema);
            nap();
        }
        return rval;
    }

    params = &instance_params[DVSIPC_INSTANCE_KDWFSB];
    /* Alter the defaults if a module parameter was passed in */
    if (params->count == 8) {
        params->thread_min = params->param_array[0];
        params->thread_max = params->param_array[1];
        params->thread_limit = params->param_array[2];
        params->thread_concurrent_creates = params->param_array[3];
        params->thread_nice = params->param_array[4];
        params->single_msg_queue = params->param_array[5];
        params->init_free_qhdrs = params->param_array[6];
        params->max_free_qhdrs = params->param_array[7];
    } else if (params->count != 0) {
        printk("DVS: %s: Warning: Ignoring short kdwfsb_instance_info parameter "
               "list\n", __func__);
    }

    if ((rval = dvsipc_start_instance(DVSIPC_INSTANCE_KDWFSB,
                                      &instance_params[DVSIPC_INSTANCE_KDWFSB])) < 0) {
        printk(KERN_ERR "DVS: %s: couldn't create kdwfsb instance. Error %d\n",
               __func__, rval);
        /* instances cleaned up in shutdown_node() */
        dvsipc_ipc_term();
        vfree(remote_node_info);
        shutdown = 1;
#if USE_RCA
        wakeup_heartbeat(0);
#endif
        while (hb_thread || refill_thread || nak_thread || buf_thread) {
            up (&refill_sema);
            up (&nak_sema);
            up (&buf_sema);
            nap();
        }
        return rval;
    }

    params = &instance_params[DVSIPC_INSTANCE_KDWCFS];
    /* Alter the defaults if a module parameter was passed in */
    if (params->count == 8) {
        params->thread_min = params->param_array[0];
        params->thread_max = params->param_array[1];
        params->thread_limit = params->param_array[2];
        params->thread_concurrent_creates = params->param_array[3];
        params->thread_nice = params->param_array[4];
        params->single_msg_queue = params->param_array[5];
        params->init_free_qhdrs = params->param_array[6];
        params->max_free_qhdrs = params->param_array[7];
    } else if (params->count != 0) {
        printk("DVS: %s: Warning: Ignoring short kdwcfs_instance_info parameter "
               "list\n", __func__);
    }

    if ((rval = dvsipc_start_instance(DVSIPC_INSTANCE_KDWCFS,
                                      &instance_params[DVSIPC_INSTANCE_KDWCFS])) < 0) {
        printk(KERN_ERR "DVS: %s: couldn't create dwcfs instance. Error %d\n",
               __func__, rval);
        /* instances cleaned up in shutdown_node() */
        dvsipc_ipc_term();
        vfree(remote_node_info);
        shutdown = 1;
#if USE_RCA
        wakeup_heartbeat(0);
#endif
        while (hb_thread || refill_thread || nak_thread || buf_thread) {
            up (&refill_sema);
            up (&nak_sema);
            up (&buf_sema);
            nap();
        }
        return rval;
    }

    KDEBUG_IPC(0, "DVS: node ID (0x%x:0x%Lx) initialized\n", ssi_nodeid,
                dvsipc_lower_nodeid);

    dvsipc_init_complete = 1;

    return(0);
}

/*
 * Interfaces for node shutdown/cleanup.
 * node:  The individual node, or all nodes if -1.
 * identity:  The nodes current identity, or NO_IDENTITY
 *            to indicate all messages in the queue.
 */
static void
cleanup_stale_messages(int node, time_t identity) 
{
    struct usiipc *msg, *next, reply;
    struct file_request *filerq;
    int mc = 0, retry_requests = 0;
    unsigned long flags;

    spin_lock_irqsave(&mq_sl, flags);

    reply.command = RQ_IPC_FAILURE;
    reply.rval = -EHOSTDOWN;
    reply.target_node = usi_node_addr;
    reply.source_node = usi_node_addr;
    reply.request_length = sizeof(reply);
    reply.reply_length = sizeof(reply);
    reply.free_required = 0;
    /*
     * Remainder of reply fields are initialized dynamically below for
     * each message.
     */

    /* move queued messages to waiting */
    msg = mq_head;
    while (msg) {
        next = msg->next;
        if ((node == -1) || ((msg->target_node == node) && 
            ((identity == NO_IDENTITY) || 
            (identity != msg->sender_identity))))
            move_send_to_wait(msg);
        msg = next;
    }

    /* reply to waiting messages */
    msg = mq_waiting;
    while (msg) {
        next = msg->next;
        if (((node == -1) ||
             ((msg->target_node == node) && 
              ((identity == NO_IDENTITY) || 
               (identity != msg->sender_identity)))) && 
             (msg->state > ST_WAITING) &&
             msg->reply_address && msg->wakeup_word && 
             (((struct usiipc *)msg->reply_address)->command != RQ_REPLY) &&
             (((struct usiipc *)msg->reply_address)->command != 
                 RQ_IPC_FAILURE)) {

            BUG_ON(msg->state == ST_FREE);
            filerq = (struct file_request *)msg;
            if (filerq->retry)
                retry_requests++;
            mc++;
            reply.reply_address = msg->reply_address;
            reply.wakeup_word = msg->wakeup_word;
            reply.original_request = msg->original_request;
            reply.source_request = msg->source_request;
            reply.source_seqno = msg->seqno;
            KDEBUG_IPC(0, "DVS: cleanup_stale_messages: "
                "waiting message dropped: 0x%p %d \n", msg,
                msg->command);
            memcpy(msg->reply_address, &reply, sizeof(reply));
            msg->state = ST_WAIT_CLEANUP;
            spin_unlock_irqrestore(&mq_sl, flags);
            dvsipc_do_process_ipc_reply(&reply);
            /* restart the search because lock was dropped */
            spin_lock_irqsave(&mq_sl, flags);
            msg = mq_waiting;
            continue;
        }
        msg = next;
    }
    spin_unlock_irqrestore(&mq_sl, flags);
    if (mc) {
        KDEBUG_IPC(0, "DVS: cleanup_stale_messages: terminated "
            "%d messages to %s, retries=%d\n",
            mc, (node > 0) ? SSI_NODE_NAME(node) : "remote nodes", 
            retry_requests);
        DVS_TRACE("csm", node, retry_requests);
    }

    dvsipc_clear_rma_list(node);
}

/* 
 * A node has come online. Do the proper accounting to
 * allow communication.
 */
void
revive_node(int node) 
{
    unsigned long flags;

    KDEBUG_IPC(0, "DVS: %s: reviving %d (%s)\n", __FUNCTION__, node,
            SSI_NODE_NAME(node));

    DVS_TRACE("RV_NODE", node, 0);

    if ((node < 0) || (node >= max_nodes))
	return;

    spin_lock_irqsave(&mq_sl, flags);

    /*
     * Not clear why the shutdown check under spinlock here vs. other places
     * but we'll leave it as is for now..
     */
    if (shutdown || !remote_node_info) {
        spin_unlock_irqrestore(&mq_sl, flags);
        return;
    }

    /*
     * Set remote node's status.
     * It's not necessary to set the nodes identity since it
     * would have gotten incremented on a failure or set to the current
     * value, when the first message came in with that id.
     */
    remote_node_info[node].node_status = Node_Status_Up;
    spin_unlock_irqrestore(&mq_sl, flags);
}

void
shutdown_node(int node) 
{
    int i;
    unsigned long flags;
    unsigned long flags2;
    struct remote_info *rni;

    if ((node < 0) || (node >= max_nodes))
        node = -1;

    DVS_TRACEL("SD_NODE", node, shutdown, remote_node_info, 0, 0);

    if (shutdown || !remote_node_info) {
        return;
    }

    cleanup_stale_messages(node, NO_IDENTITY);

    spin_lock_irqsave(&mq_sl, flags);
    if ((node == -1) || (node == usi_node_addr)) {
	for (i=0; i < max_nodes; i++) {
	    remote_node_info[i].node_status = Node_Status_Down;
	}
        shutdown = 1;
    } else {
        rni = &remote_node_info[node];
        spin_lock_irqsave(&rni->lock, flags2);
        if (rni->node_status == Node_Status_Down) {
		/*
		 * If the node is already marked Down, we
		 * don't need to do anything.
		 */
	    spin_unlock_irqrestore(&rni->lock, flags2);
            spin_unlock_irqrestore(&mq_sl, flags);
            return;
        } else if (rni->node_status == Node_Status_Up) {
            /* change identity so stale messages are dropped */
            rni->identity++;
	}
        rni->node_status = Node_Status_Down;
	spin_unlock_irqrestore(&rni->lock, flags2);
    }
    spin_unlock_irqrestore(&mq_sl, flags);

    /*
     * Complete cleanup only if total shutdown
     */
    if (node == -1) {
#if USE_RCA
        /* force hb thread to terminate */
        if (hb_thread) {
            KDEBUG_IPC(0, "DVS: shutdown_node: Waiting for hb thread "
                "to terminate %d\n", hb_thread->pid);
            wakeup_heartbeat(0);
            while (hb_thread)
                nap();
        }
#endif

        /* Force refill thread to terminate */
        while (refill_thread) {
	    up (&refill_sema);
            nap();
        }

        dvsipc_nak_cleanup();

        while (buf_thread) {
            up(&buf_sema);
            nap();
        }

        if (mq_waiting) {
            printk(KERN_ERR "DVS: shutdown_node: Waiting for "
                "outstanding messages to abort\n");
            while (mq_waiting)
                nap();
        }

        dvsipc_remove_instance(DVSIPC_INSTANCE_DVS);
        dvsipc_remove_instance(DVSIPC_INSTANCE_KDWFS);
        dvsipc_remove_instance(DVSIPC_INSTANCE_KDWFSB);
        dvsipc_remove_instance(DVSIPC_INSTANCE_KDWCFS);

        nap();
        dvsipc_clear_rma_list(-1);

        sleep(1);

    }
}

/*
 * Clean up any outstanding rma operations to a remote node. This is
 * necessary since the remote may have shutdown portals, which would
 * cause our operation to be silently dropped. The heartbeat thread
 * will detect the node has gone down and shutdown_node() will cleanup
 * the in-flight transactions.
 */
void
dvsipc_clear_rma_list(int nid) 
{
    rma_info_t *rip;
    unsigned long flags;

    DVS_TRACE("crmalstI", nid, 0);

    spin_lock_irqsave(&dvsipc_rma_list_lock, flags);
    if (list_empty(&dvsipc_rma_list)) {
        spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);
        DVS_TRACE("crmalstO",  nid, 0);
        return;
    }

    DVS_TRACEL("crmalst+", dvsipc_rma_list.next,
        dvsipc_rma_list.prev, &dvsipc_rma_list.next,
        &dvsipc_rma_list.prev, 0);

    rip = (rma_info_t *)dvsipc_rma_list.next;
    do {
        if (nid == -1 || rip->nid == nid) {
            DVS_TRACEL("crmalst", rip->nid, rip->handle,
                rip->length, rip->rma_type, 0);
            rip->retval = -EINTR;
            up(&rip->sema);
            printk(KERN_ERR "DVS: %s: rma cleared\n", __FUNCTION__);
        }
        DVS_TRACEL("crmalst+", dvsipc_rma_list.next, rip,
            rip->list.next, 0, 0);
        rip = (rma_info_t *)rip->list.next;
    } while (rip != (rma_info_t*)&dvsipc_rma_list.next);

    spin_unlock_irqrestore(&dvsipc_rma_list_lock, flags);
    DVS_TRACE("crmalstO", nid, 0);
}

static void
dvsipc_ipc_term(void) 
{
    static int terminated = 0;
    rx_buf_info_t *bip;
    unsigned long flags;
    int i;

    if (terminated) {
        return;
    }

    DVS_TRACE("sipcterm", 0, 0);

    terminated = 1;

    shutdown_node(-1);

    /* Shutdown nic */
    ipclower_term();

    for (i = 0; i < DVSIPC_MAX_RX_MDS; i++) {
	bip = (rx_buf_info_t *) rx_buf_table[i].buf;
        if (bip) {
            atomic_set(&bip->rxbuf_state, RXBUF_Free);
            atomic_dec(&rx_buffer_count);
            vfree_ssi(bip);
        }
    }

    spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    while (!list_empty(&dvsipc_free_list)) {
        bip = container_of(dvsipc_free_list.next, rx_buf_info_t, rx_free_list);
        list_del(&bip->rx_free_list);
	atomic_set(&bip->rxbuf_state, RXBUF_Unchained);
        spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
        atomic_dec(&freelist_buffer_count);
        atomic_dec(&rx_buffer_count);
        DVS_TRACE("termFree", bip, 0);
	atomic_set(&bip->rxbuf_state, RXBUF_Free);
        vfree_ssi(bip);
        spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    }
    spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);

    spin_lock_irqsave(&dvsipc_buf_list_lock, flags);
    while (!list_empty(&dvsipc_buf_list)) {
        struct list_head *buf;

        buf = dvsipc_buf_list.next;
        list_del(buf);
        spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
        vfree_ssi(buf);
        spin_lock_irqsave(&dvsipc_buf_list_lock, flags);
    }
    spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
}

void
dvsipc_do_error(struct usiipc *request) 
{
    printk(KERN_ERR "DVS: %s: Shutting down node %s due "
        "to communication error\n", __FUNCTION__,
        SSI_NODE_NAME(request->target_node));
    shutdown_node(request->target_node);
}

static int
dvsipc_get_params(int *ic_type, int *ic_limit) 
{
    *ic_type = IC_TYPE_SEASTAR;
    *ic_limit = 1;
    return(0);
}

void
thread_wait(int wait_time, struct semaphore *sema,
            void (*wakeup_function)(unsigned long),
            unsigned long arg)
{
    struct timer_list timer;
    unsigned long expire;
    int ignore;

    expire = jiffies + (wait_time);
    setup_timer_on_stack(&timer, wakeup_function, arg);
    mod_timer(&timer, expire);
    ignore = down_interruptible(sema);
    del_singleshot_timer_sync(&timer);
}

static void
wakeup_buf_thread(unsigned long arg) 
{
    up(&buf_sema);
}

/*
 * dvsipc_buf_thread - Monitor cached transfer buffers for expiration.
 */
int
dvsipc_buf_thread(void *arg) 
{
    KDEBUG_IPC(0, "dvsipc_buf_thread: IN\n");

    buf_thread = current;
    while  (!shutdown) {
        dvs_buf_hdr_t *bhp;
        unsigned long flags;
        struct list_head *head;

        thread_wait((dvs_cur_config_params->buf_timeout*HZ), &buf_sema,
                    wakeup_buf_thread, 0);

        spin_lock_irqsave(&dvsipc_buf_list_lock, flags);

restart:
        list_for_each(head, &dvsipc_buf_list) {
            bhp = list_entry(head, dvs_buf_hdr_t, list);
            DVS_TRACEL("bufC", bhp->size, bhp->freetime, jiffies, 0, 0);
            if ((bhp->freetime + dvs_cur_config_params->buf_timeout)<= jiffies) {
                list_del(&bhp->list);
                dvsipc_buf_cache_bytes -= bhp->size;
                spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
                KDEBUG_IPC(0, "%s: release stale buf 0x%x\n", __FUNCTION__,
                                bhp->size);
                vfree(bhp);
                spin_lock_irqsave(&dvsipc_buf_list_lock, flags);
                        
                goto restart;
            }
            DVS_TRACEL("bufCN", bhp->size, bhp->freetime, jiffies, 0, 0);
        }
        spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
    }
    buf_thread = NULL;
    return 0;
}

void *
dvs_alloc_buf(int size)
{
    dvs_buf_hdr_t *bhp;
    unsigned long flags;
    struct list_head *head;
    int allocsize;

    spin_lock_irqsave(&dvsipc_buf_list_lock, flags);
    list_for_each(head, &dvsipc_buf_list) {
        bhp = list_entry(head, dvs_buf_hdr_t, list);
        if (bhp->size >= size) {
            list_del(&bhp->list);
            dvsipc_buf_cache_bytes -= bhp->size;
            spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
            KDEBUG_IPC(0, "%s: alloc cached 0x%x\n", __FUNCTION__, bhp->size);
            return &bhp->buf;
        }
    }
    spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);

    /* 
     * Missed the cache. Allocate a buffer of the specified size. Use vmalloc
     * directly so we don't waste time clearing the buffer.
     */
    allocsize = (size+PAGE_SIZE-1) & PAGE_MASK;
    if ((bhp = vmalloc(allocsize + sizeof(*bhp))) == NULL) {
        DVS_TRACE("dabF", size, allocsize);
        return NULL;
    }

    DVS_TRACEL("dabA", bhp, size, allocsize, 0, 0);
    INIT_LIST_HEAD( &bhp->list );
    bhp->size = allocsize;
    return &bhp->buf;
}

void 
dvs_free_buf(void *buf)
{
    unsigned long flags;
    dvs_buf_hdr_t *bhp = container_of(buf, struct dvs_buf_hdr, buf);
    struct list_head *head;
    
    bhp->freetime = jiffies;
    INIT_LIST_HEAD( &bhp->list );

    spin_lock_irqsave(&dvsipc_buf_list_lock, flags);
    if (dvsipc_buf_cache_bytes < dvs_cur_config_params->buf_limit) {
        /*
         * Insert into the cached list, sorted by size.
         */
        dvsipc_buf_cache_bytes += bhp->size;
        KDEBUG_IPC(0, "%s: caching 0x%x (tot=0x%x)\n", __FUNCTION__, bhp->size,
                         dvsipc_buf_cache_bytes);
        list_for_each(head, &dvsipc_buf_list) {
            dvs_buf_hdr_t *tbhp = list_entry(head, dvs_buf_hdr_t, list);
            if (bhp->size <= tbhp->size) {

                list_add(&bhp->list, &tbhp->list);
                spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
                return;
            }
        }
        list_add_tail(&bhp->list, &dvsipc_buf_list);
        spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
    } else {
        spin_unlock_irqrestore(&dvsipc_buf_list_lock, flags);
        KDEBUG_IPC(0, "%s: hit cache limit 0x%x\n", __FUNCTION__,
                         bhp->size);
	DVS_TRACE("dfbF", bhp, bhp->size);
        vfree(bhp);
    }
}

void *
dvs_direct_buf_alloc(int count, struct page ***pglist, void **mmva)
{
    int npages = (count+(PAGE_SIZE-1)) / PAGE_SIZE;
    struct page **pages = NULL;
    int p, ret;
    void *datap, *vaddr;

    datap = (void *)p_sys_mmap((unsigned long)0, count,
        PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_POPULATE|MAP_PRIVATE, -1, 0);
    if (IS_ERR(datap)) {
        KDEBUG_IPC(0, "DVS: %s: failure %ld (%d) at %d\n",
            __FUNCTION__, PTR_ERR(datap), count, __LINE__);
        return(NULL);
    }

    pages = kmalloc_ssi(npages*sizeof(*pages), GFP_KERNEL);
    if (!pages) {
        KDEBUG_IPC(0, "DVS: %s: kmalloc failure at %d\n", __FUNCTION__, __LINE__);
        goto cleanup;
    }

    down_read(&current->mm->mmap_sem);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,73)
    ret = get_user_pages(current, current->mm, (unsigned long)datap, npages, 
			    1, 0, pages, NULL);
#else
    ret = get_user_pages((unsigned long)datap, npages, 
			    FOLL_WRITE, pages, NULL);
#endif    
    up_read(&current->mm->mmap_sem);
    if (ret != npages) {
        KDEBUG_IPC(0, "DVS: %s: get_user_pages %d < %d\n", __FUNCTION__, ret, npages);
        npages = ret;
        goto cleanup;
    }

    vaddr = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
    if (vaddr == NULL) {
        KDEBUG_IPC(0, "DVS: %s: vmap failure at %d\n", __FUNCTION__, __LINE__);
        goto cleanup;
    }

    KDEBUG_IPC(0, "DVS: alloc direct: %d %d 0x%p 0x%p 0x%p\n", count, npages, datap, vaddr, pages);

    *pglist = pages;
    *mmva = datap;
    return(vaddr);

cleanup:
    if (pages) {
        for (p = 0; p < npages; p++) {
            page_cache_release(pages[p]);
        }
        kfree_ssi(pages);
    }
    p_sys_munmap((unsigned long)datap, count);

    return(NULL);
}

void
dvs_direct_buf_free(int count, struct page **pages, void *mmva, void *kva)
{
    int npages = (count+(PAGE_SIZE-1)) / PAGE_SIZE;
    int p;

    KDEBUG_IPC(0, "DVS: free direct: %d %d 0x%p 0x%p 0x%p\n", count, npages, mmva, kva, pages);
    vunmap(kva);

    for (p = 0; p < npages; p++) {
        SetPageUptodate(pages[p]);
        if (page_has_buffers(pages[p]))
            __set_page_dirty_buffers(pages[p]);
        else
            __set_page_dirty_nobuffers(pages[p]);
        page_cache_release(pages[p]);
    }

    kfree_ssi(pages);
    p_sys_munmap((unsigned long)mmva, count);
}

/*
 * IPC callback vector provided to dvs.
 */
struct ipc_operations dvsipc_ipc_ops = {
    regisrq:        dvsipc_register_ipc_request,
    sendrq:         dvsipc_send_ipc_request,
    sendrqa:        dvsipc_send_ipc_request_async,
    waitrqa:        dvsipc_wait_for_async_request,
    sendrp:         dvsipc_send_ipc_reply,
    mapkvm:         dvsipc_mapkvm,
    unmapkvm:       dvsipc_unmapkvm,
    mapuvm:         dvsipc_mapuvm,
    unmapuvm:       dvsipc_unmapuvm,
    rmaget:         dvsipc_rma_get,
    rmaput:         dvsipc_rma_put,
    rmawait:        dvsipc_rma_wait,
    setup_rma:      dvsipc_setup_rma,
    end_rma:        dvsipc_end_rma,
    init:           dvsipc_ipc_init,
    term:           dvsipc_ipc_term,
    get_params:     dvsipc_get_params,
    identity_valid: dvsipc_identity_valid,
    block_thread:   dvsipc_block_thread,
    release_thread: dvsipc_release_thread
};

/* Module stuff */

static int __init
init_dvsipc(void) 
{
    int rc = 0;

    if (vipc) {
        printk(KERN_ERR "DVS: %s: already initialized \n",
            __FUNCTION__);
        return(0);
    }

    rc = dvsipc_init_config_type_params();
    if (rc != 0) return rc;

    INIT_LIST_HEAD( &dvsipc_free_list );
    INIT_LIST_HEAD( &dvsipc_rma_list );
    INIT_LIST_HEAD( &dvsipc_resend_list );

    sema_init(&ipc_tx_sema, dvs_cur_config_params->tx_credits);
    sema_init(&nak_sema, 0);
    sema_init(&buf_sema, 0);

    initialize_syscall_linkage();

    max_nodes = ssiproc_get_max_nodes();

    if (max_nodes == 0) {
        printk(KERN_ERR "DVS: %s: Kernel map file "
            "corrupt - max_nodes not set.\n", __FUNCTION__);
        return(-EINVAL);
    }

    /* set up the dvs log */
    if (dvs_log_init(LOG_IPC_LOG, ipc_log_size_kb, "IPC log") != 0) {
        printk(KERN_ERR "DVS: %s cannot init IPC log\n", __FUNCTION__);
        return -ENOMEM;
    }

    dvsipc_proc_init();

    dvsipc_init_node_list();

    shutdown = 0;
    vipc = &dvsipc_ipc_ops;

    KDEBUG_INF(0, "DVS: dvsipc (ss) module loaded\n");
    KDEBUG_IPC(0, "DVS: init_uss: max_nodes: %d\n", max_nodes);
    return 0;
}

static void __exit
exit_dvsipc(void) 
{

    /* just in case */
    shutdown_node(-1);

    sleep(1);
    vipc = NULL;

    if (remote_node_info) {
        vfree(remote_node_info);
    }

    if (node_list) {
        vfree(node_list);
    }

    dvsipc_proc_term();

    dvs_log_exit(LOG_IPC_LOG);

    KDEBUG_INF(0, "DVS: %s: IPC direct sends %ld indirect "
        "sends %ld\n", __FUNCTION__, direct_sends, indirect_sends);

    KDEBUG_INF(0, "DVS: dvsipc (ss) module unloaded\n");
}

/*
 * The following interfaces are for the collection of transport
 * level message statistics. Data can be retrieved through the
 * /proc/fs/dvs/ipc/stats file and the statistics can be cleared at
 * any time by writing any value to that same file.
 */
static int dvsipc_stats_open(struct inode *inode, struct file *file);
static ssize_t dvsipc_stats_write(struct file *file, const char *buffer,
                                  size_t count, loff_t *offp);
static int dvsipc_stats_release(struct inode *inode, struct file *file);

static struct file_operations dvsipc_stats_operations = {
    open:    dvsipc_stats_open,
    read:    seq_read,
    write:   dvsipc_stats_write,
    release: dvsipc_stats_release,
};

static void *
dvsipc_stats_seq_start(struct seq_file *m, loff_t *pos)
{
    loff_t n = *pos;

    if (n >= 1) {
        return (NULL);
    }
    return ((void *)&dvsipc_stats_operations);
}

static void
dvsipc_stats_seq_stop(struct seq_file *m, void *p)
{
    return;
}

static void *
dvsipc_stats_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
    return(NULL);
}

/*
 * dvsipc_stats_seq_show() - Display the ipc counters in a human-consumable
 *                           form.
 */
static int
dvsipc_stats_seq_show(struct seq_file *m, void *p)
{
    struct dvsipc_instance *instance;
    struct dvsipc_thread_pool *thread_pool;
    struct dvsipc_incoming_msgq *inmsgq;
    int i,j;
    int qlen;
    int printcnt = 0;

    seq_printf(m, "DVS IPC Transport Statistics Version %s LNet %s\n",
		SVNREV, LNETVER);
    for (i=0; i<DVSIPC_NSTATS; i++) {
        seq_printf(m, "%22s %16Ld\n", ipcstats[i].str, ipcstats[i].val);
    }

    seq_printf(m, "Refill Stats:\n");
    for (i = 0; i < dvsipc_num_rx_mds; i++) {
        seq_printf(m, "%8d", rx_buf_table[i].seq);
        if ((i % 10) == 9)
            seq_printf(m, "\n");
    }
    seq_printf(m, "\n\n");

    for (i = 0; i < DVSIPC_INSTANCE_MAX; i++) {
        if ((instance = dvsipc_instances[i]) == NULL)
            continue;

        thread_pool = instance->thread_pool;
        inmsgq = thread_pool->inmsgq;

        seq_printf(m, "Instance %d:\n", i);
        seq_printf(m, "%21s        %8d\n",
                   "Total Threads", thread_pool->thread_count);
        seq_printf(m, "%21s        %8d\n",
                   "Created Threads", thread_pool->threads_created);
        seq_printf(m, "%21s        %8d\n",
                   "Active Threads",
                   thread_pool->state_counts[DVSIPC_THREAD_BUSY]);
        seq_printf(m, "%21s        %8d\n",
                   "Idle Threads",
                   thread_pool->state_counts[DVSIPC_THREAD_IDLE]);
        seq_printf(m, "%21s        %8d\n",
                   "Blocked Threads",
                   thread_pool->state_counts[DVSIPC_THREAD_BLOCKED]);
        seq_printf(m, "%21s        %8d\n",
                   "Thread Limit", thread_pool->thread_limit);
        seq_printf(m, "%21s        %8d\n",
                   "Total Queues", atomic_read(&inmsgq->total_qcnt));
        seq_printf(m, "%21s        %8d\n",
                   "Active Queues", atomic_read(&inmsgq->total_qcnt) -
                                atomic_read(&inmsgq->freepool_qcnt));
        seq_printf(m, "%21s        %8d\n",
                   "Free Queues", atomic_read(&inmsgq->freepool_qcnt));
        seq_printf(m, "%21s        %8d\n",
                   "Queued Messages", atomic_read(&inmsgq->incomingq_len));

        seq_printf(m, "  Queue Lengths:\n");
        for (j = 0; j < inmsgq->htb->numbuckets; j++) {
            qlen = atomic_read(&(inmsgq->htb->buckets[j].qlen));
            if (qlen > 0) {
                seq_printf(m, "%6d/ %-4d", j, qlen);
                if ((printcnt++ % 8) == 7) { 
                    seq_printf(m, "\n");
                }
            }
        }
        if (printcnt > 0 ) {
            seq_printf(m, "\n\n");
        } else {
            seq_printf(m, "%12s\n\n", "all/ 0");
        }
    }

    seq_printf(m, "%21s        %8d\n", 
               "Cached Buffer Space", dvsipc_buf_cache_bytes);

    seq_printf(m, "%21s        %8ld\n",
               "Requests Killed", atomic64_read(&requests_killed));

    seq_printf(m, "\nSize Distributions\n");
    seq_printf(m, "%5s ", "Type");
    for (i=0; i<DVSIPC_SIZE_NBUCKETS; i++) {
        seq_printf(m, "%9s", ipcsizestr[i]);
    }
    seq_printf(m, "\n");

    for (i=0; i<DVSIPC_TX_NTYPES; i++) {
        seq_printf(m, "%5s ", ipcopstr[i]);
        for (j=0; j<DVSIPC_SIZE_NBUCKETS; j++) {
            seq_printf(m, "%9Ld", ipcsizes[i][j]);
        }
        seq_printf(m, "\n");
    }
    return 0;
}

static struct seq_operations dvsipc_stats_ops = {
    start:   dvsipc_stats_seq_start,
    next:    dvsipc_stats_seq_next,
    stop:    dvsipc_stats_seq_stop,
    show:    dvsipc_stats_seq_show,
};

/*
 * dvsipc_stats_reset() - Reset transport counter state.
 */
static void
dvsipc_stats_reset(void)
{
    int i,j;
    for (i=0; i<DVSIPC_NSTATS; i++) {
        ipcstats[i].val = 0;
    }
    for (i=0; i<DVSIPC_TX_NTYPES ;i++) {
        for (j=0; j<DVSIPC_SIZE_NBUCKETS ;j++) {
            ipcsizes[i][j] = 0;
        }
    }
    for (i = 0; i < DVSIPC_MAX_RX_MDS; i++) {
        rx_buf_table[i].seq = 0;
    }
    atomic64_set(&requests_killed, 0);
}

static int
dvsipc_stats_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &dvsipc_stats_ops);
}

static ssize_t
dvsipc_stats_write(struct file *file, const char *buffer,
                   size_t count, loff_t *offp)
{
    int ret = count;
  
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_ERR "DVS: %s: ERR\n", __FUNCTION__);
        ret = -EACCES;
    } else {
        dvsipc_stats_reset();
        *offp += count;
        ret = count;
    }
    return ret;
}

static int
dvsipc_stats_release(struct inode *inode, struct file *file)
{
    return seq_release(inode, file);
}

static int dvsipc_config_type_open(struct inode *inode,
                                  struct file *file);

static ssize_t dvsipc_config_type_write(struct file *file,
                                  const char *buffer,
                                  size_t count, loff_t *offp);

static struct file_operations dvsipc_config_type_operations = {
    open:    dvsipc_config_type_open,
    read:    seq_read,
    write:   dvsipc_config_type_write,
    release: seq_release,
};

static void *
dvsipc_config_type_seq_start(struct seq_file *m, loff_t *pos)
{
    loff_t n = *pos;

    if (n >= 1) {
        return (NULL);
    }
    return ((void *)&dvsipc_config_type_operations);
}

static void
dvsipc_config_type_seq_stop(struct seq_file *m, void *p)
{
    return;
}

static void *
dvsipc_config_type_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
    return(NULL);
}

static int
dvsipc_config_type_seq_show(struct seq_file *m, void *p)
{
    seq_printf(m, "%d\n", dvsipc_config_type);
    return 0;
}

static struct seq_operations dvsipc_config_type_ops = {
    start:   dvsipc_config_type_seq_start,
    next:    dvsipc_config_type_seq_next,
    stop:    dvsipc_config_type_seq_stop,
    show:    dvsipc_config_type_seq_show,
};

static void
dump_config_params(dvs_config_params_t *params)
{
    KDEBUG_IPC(0, "DVS: %s: dvsipc_num_rx_mds = %d \n", __FUNCTION__, dvsipc_num_rx_mds);
    KDEBUG_IPC(0, "DVS: %s: msg_threads = %d \n", __FUNCTION__, params->msg_threads);
    KDEBUG_IPC(0, "DVS: %s: max_msg_threads = %d \n", __FUNCTION__, params->max_msg_threads);
    KDEBUG_IPC(0, "DVS: %s: rsv_bufs = %d \n", __FUNCTION__, params->rsv_bufs);
    KDEBUG_IPC(0, "DVS: %s: msg_per_buf = %d \n", __FUNCTION__, params->msg_per_buf);
    KDEBUG_IPC(0, "DVS: %s: tx_credits = %d \n", __FUNCTION__, params->tx_credits);
    KDEBUG_IPC(0, "DVS: %s: buf_limit = %d \n", __FUNCTION__, params->buf_limit);
    KDEBUG_IPC(0, "DVS: %s: buf_timeout = %d \n", __FUNCTION__, params->buf_timeout);
    KDEBUG_IPC(0, "DVS: %s: send_rca_event = %d \n", __FUNCTION__, params->send_rca_event);
    KDEBUG_IPC(0, "DVS: %s: alloc_msg_threads = %d \n", __FUNCTION__, dvsipc_alloc_msg_threads);
}

static int
dvsipc_switch_config_type(int new_config)
{
    struct dvsipc_instance *dvs_instance;
    struct dvsipc_incoming_msgq *inmsgq;
    unsigned long flags;
    int buf_cnt = 0;
    int idx;
    int count;
    struct task_struct *task;
    int bstate;
    rx_buf_info_t *bip = NULL;

    /* Reset config parameters */
    dvsipc_config_type = new_config;
    dvs_cur_config_params = &dvs_config_params[new_config];

    dump_config_params(dvs_cur_config_params);

    /*
     * Reallocate reserve pool with buffers of new size.
     * Buffers currently in use will be resized the next time
     * dvsipc_refill_thread assigns them to rx_buf_table.
     */
    spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    while (!list_empty(&dvsipc_free_list)) {
        bip = container_of(dvsipc_free_list.next, rx_buf_info_t, rx_free_list);
        BUG_ON(bip->unused_list.prev || bip->unused_list.next);

        list_del_init(&bip->rx_free_list);
        bstate = atomic_cmpxchg(&bip->rxbuf_state, RXBUF_Chained, RXBUF_Unchained);
        spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);
        atomic_dec(&freelist_buffer_count);
        atomic_dec(&rx_buffer_count);
        if (unlikely(bstate != RXBUF_Chained)) {
           printk(KERN_EMERG "RX buffer in invalid state %d !!\n", bstate);
           BUG();
        }
        atomic_set(&bip->rxbuf_state, RXBUF_Free);
        vfree_ssi(bip);
        buf_cnt++;
        spin_lock_irqsave(&dvsipc_free_list_lock, flags);
    }
    spin_unlock_irqrestore(&dvsipc_free_list_lock, flags);

    DVS_TRACE("swtchCfg", buf_cnt, bip);
    KDEBUG_IPC(0, "DVS: %s: freed buf pool count = %d \n", __FUNCTION__, buf_cnt);

    for (idx = 0; idx < dvs_cur_config_params->rsv_bufs; idx++) {
        dvsipc_alloc_rx_buf();
    }

    /*
     * Adjust the size of the incoming queue header freepool
     */

    dvs_instance = dvsipc_find_instance(DVSIPC_INSTANCE_DVS);
    BUG_ON(dvs_instance == NULL);

    spin_lock_irqsave(&dvs_instance->thread_pool->lock, flags);
    dvs_instance->thread_pool->thread_min = dvs_cur_config_params->msg_threads;
    dvs_instance->thread_pool->thread_max = dvs_cur_config_params->max_msg_threads;
    spin_unlock_irqrestore(&dvs_instance->thread_pool->lock, flags);

    inmsgq = dvs_instance->thread_pool->inmsgq;

    KDEBUG_IPC(0, "DVS: %s: adjust freepool_cnt %d\n", __FUNCTION__,
               atomic_read(&inmsgq->freepool_qcnt));

    inmsgq->init_free_qhdrs = dvs_cur_config_params->msgq_init_free_qhdrs;
    inmsgq->max_free_qhdrs = dvs_cur_config_params->msgq_max_free_qhdrs;
    count = inmsgq->init_free_qhdrs - atomic_read(&inmsgq->freepool_qcnt);
    if (count > 0) {
        msgq_grow_freepool(count, inmsgq);
    } else if (count < 0) {
        msgq_shrink_freepool(-count, inmsgq);
    }

    dvsipc_put_instance(dvs_instance);

    /*
     * Create cached buffer manager thread when switching from client
     * to server. Leave thread alive when switching from server to
     * client; it will clean up any existing buffers and then go idle.
     */
    if ((!buf_thread) && dvs_cur_config_params->buf_timeout) {
        task = kthread_run(dvsipc_buf_thread, NULL, "%s", "DVS-IPC_buf");
        if (IS_ERR(task)) {
            /* can't create thread so run without buffer cache */
            printk(KERN_WARNING "DVS: %s: couldn't start buf thread (%ld)\n",
                    __FUNCTION__, PTR_ERR(task));
            dvs_cur_config_params->buf_limit = 0;
            dvs_cur_config_params->buf_timeout = 0;
        }
    }
#if USE_RCA
    wakeup_heartbeat(0);
#endif
    return 0;
}

static int
dvsipc_config_type_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &dvsipc_config_type_ops);
}

static ssize_t
dvsipc_config_type_write(struct file *file, const char *buffer,
                   size_t count, loff_t *offp)
{
    int config;
    char str[16];
    int val;
    int rval = 0;

    if (!capable(CAP_SYS_ADMIN)) {
        rval = -EACCES;
        goto errout;
    }

    if (count >= sizeof(str))  {
        rval = -EINVAL;
        goto errout;
    }

    memset(str, 0, sizeof(str));
    if (copy_from_user(str, buffer, count)) {
        rval = -EFAULT;
        goto errout;
    }

    val = (int) simple_strtol(str, NULL, 0);
    switch (val) {
        case 0:    config = dvs_config_type_client;
                   break;
        case 1:    config = dvs_config_type_server;
                   break;
        default:   rval = -EINVAL;
                   dump_config_params(dvs_cur_config_params);
                   goto errout;
    }

    printk(KERN_INFO "DVS: %s: setting dvsipc_config_type "
           "to 0x%x - %s\n", __FUNCTION__, config,
           (config == dvs_config_type_client ?  "client" : "server"));

    if (config != dvsipc_config_type) {
            dvsipc_switch_config_type(config);
    }

errout:
    if (rval < 0) {
        printk(KERN_ERR "DVS: %s: ERROR switching config type (%d)\n",
               __FUNCTION__, rval);
        return rval;
    }
    return count;
}

static int dvsipc_requests_open(struct inode *inode, struct file *file);

static struct file_operations dvsipc_requests_operations = {
    open:    dvsipc_requests_open,
    read:    seq_read,
    release: seq_release,
};

static void*
dvsipc_requests_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1) {
		return (NULL);
	}
	return ((void *)&dvsipc_requests_operations);
}

static void
dvsipc_requests_seq_stop(struct seq_file *m, void *p)
{
	return;
}

static void *
dvsipc_requests_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
	return (NULL);
}

static int 
dvsipc_requests_seq_show(struct seq_file *m, void *p)
{
	struct file_request *filerq;
	char *path, *buf;
	unsigned long flags, wait_time;

	if ((buf = (char *)__get_free_page(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	
	spin_lock_irqsave(&mq_sl, flags);
	filerq = container_of(mq_waiting, struct file_request, ipcmsg);
	
	while (filerq) {
		wait_time = jiffies_to_msecs(jiffies - filerq->ipcmsg.jiffies_val);
		path = dvsipc_requests_get_path(filerq, buf);
		seq_printf(m, "server: %s  ", node_map[filerq->ipcmsg.target_node].name);
		seq_printf(m, "request: %s  ", file_request_to_string(filerq->request));
		seq_printf(m, "path: %s  ", path ? path : "UNKNOWN");
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		seq_printf(m, "user: %d  ", filerq->context.uid);
#else
		seq_printf(m, "user: %d  ", __kuid_val(filerq->context.uid));
#endif

		seq_printf(m, "time: %ld.%03ld sec  ", wait_time / 1000, wait_time % 1000);
#ifdef CONFIG_CRAY_ACCOUNTING
		seq_printf(m, "apid: %llu",
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
			(CTX_JOBID_UID_MASK & filerq->context.jobid)
				? 0 : filerq->context.jobid);
#else
			(__kuid_val(filerq->context.uid) == filerq->context.jobid)
				? 0 : filerq->context.jobid);
#endif
#endif
		seq_printf(m, "\n");
		filerq = container_of(filerq->ipcmsg.next, struct file_request, ipcmsg);
	}
	spin_unlock_irqrestore(&mq_sl, flags);
	free_page((unsigned long) buf);

	return 0;
}

static inline char *
dvsipc_requests_fp_path(struct file_request *filerq, char *path)
{
	if (filerq->client_fp == NULL)
		return NULL;

	return d_path(&filerq->client_fp->f_path, path, PAGE_SIZE);
}

/*
 * returns a pointer to the file path for a request. Only works on
 * the client side.
 */
static char *
dvsipc_requests_get_path(struct file_request *filerq, char *path)
{
	switch (filerq->request) {
	case RQ_OPEN:
	case RQ_CLOSE:
	case RQ_READDIR:
	case RQ_IOCTL:
	case RQ_FLUSH:
	case RQ_FSYNC:
	case RQ_FASYNC:
	case RQ_LOCK:
	case RQ_PARALLEL_READ:
	case RQ_PARALLEL_WRITE:
	case RQ_READPAGES_RQ:
	case RQ_READPAGES_RP:
	case RQ_WRITEPAGES_RQ:
	case RQ_WRITEPAGES_RP:
	case RQ_READPAGE_ASYNC:
	case RQ_GETEOI:
		return dvsipc_requests_fp_path(filerq, path);
	case RQ_LINK:
	case RQ_SYMLINK:
	case RQ_RENAME:
		return &filerq->u.linkrq.pathname[filerq->u.linkrq.orsz];
	case RQ_RMDIR:
	case RQ_UNLINK:
		return filerq->u.unlinkrq.pathname;
	case RQ_LOOKUP:
		return filerq->u.lookuprq.pathname;
	case RQ_CREATE:
		return filerq->u.createrq.pathname;
	case RQ_MKDIR:
		return filerq->u.mkdirrq.pathname;
	case RQ_MKNOD:
		return filerq->u.mknodrq.pathname;
	case RQ_READLINK:
		return filerq->u.readlinkrq.pathname;
	case RQ_TRUNCATE:
		return filerq->u.truncaterq.pathname;
	case RQ_SETATTR:
		return filerq->u.setattrrq.pathname;
	case RQ_GETATTR:
		return filerq->u.getattrrq.pathname;
	case RQ_STATFS:
		return filerq->u.statfsrq.pathname;
	case RQ_SETXATTR:
		return filerq->u.setxattrrq.data;
	case RQ_GETXATTR:
		return filerq->u.getxattrrq.data;
	case RQ_LISTXATTR:
		return filerq->u.listxattrrq.data;
	case RQ_REMOVEXATTR:
		return filerq->u.removexattrrq.data;
	case RQ_PERMISSION:
		return filerq->u.permissionrq.pathname;
	case RQ_DVS_END_V1:
	case RQ_VERIFYFS:
	case RQ_RO_CACHE_DISABLE:
	case RQ_READPAGE_DATA:
	default:
		return NULL;
	}

	return NULL;
}

static struct seq_operations dvsipc_requests_ops = {
    start:   dvsipc_requests_seq_start,
    next:    dvsipc_requests_seq_next,
    stop:    dvsipc_requests_seq_stop,
    show:    dvsipc_requests_seq_show,
};

static int
dvsipc_requests_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvsipc_requests_ops);
}

static int dvsipc_log_open(struct inode *inode, struct file *file);

static struct file_operations dvsipc_log_operations = {
    open:    dvsipc_log_open,
    read:    seq_read,
    release: seq_release,
};

static void*
dvsipc_log_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1) {
		return (NULL);
	}

	return dvs_log_handle(LOG_IPC_LOG);
}

static void
dvsipc_log_seq_stop(struct seq_file *m, void *p)
{
	return;
}

static void *
dvsipc_log_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
	return (NULL);
}

static int 
dvsipc_log_seq_show(struct seq_file *m, void *p)
{
	return(dvs_log_print(LOG_IPC_LOG, m));
}	

static struct seq_operations dvsipc_log_ops = {
    start:   dvsipc_log_seq_start,
    next:    dvsipc_log_seq_next,
    stop:    dvsipc_log_seq_stop,
    show:    dvsipc_log_seq_show,
};

static int
dvsipc_log_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvsipc_log_ops);
}

static int dvsipc_log_size_open(struct inode *inode, struct file *file);
static ssize_t  dvsipc_log_size_write(struct file *file, const char *buffer, size_t count, loff_t *offp);

static struct file_operations dvsipc_log_size_operations = {
    open:    dvsipc_log_size_open,
    read:    seq_read,
    release: seq_release,
    write:   dvsipc_log_size_write,
};

static ssize_t 
dvsipc_log_size_write(struct file *file, const char *buffer, 
			size_t count, loff_t *offp)
{
	int ret, size;
	char sizestr[16];
	
	if (count > 16)
		return -EFBIG;

	if (copy_from_user(sizestr, buffer, count))
		return -EFAULT;

	if (sscanf(sizestr, "%u", &size) != 1)
		return -EINVAL;

	if ((ret = dvs_log_resize(LOG_IPC_LOG, size)) == 0)
		ret = count;

	return ret;
}

static void*
dvsipc_log_size_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1) {
		return (NULL);
	}

	return ((void *)&ipc_log_size_kb);
}

static void
dvsipc_log_size_seq_stop(struct seq_file *m, void *p)
{
	return;
}

static void *
dvsipc_log_size_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
	return (NULL);
}

static int 
dvsipc_log_size_seq_show(struct seq_file *m, void *p)
{
	seq_printf(m, "%d\n", dvs_log_sizekb(LOG_IPC_LOG));
	return 0;
}	

static struct seq_operations dvsipc_log_size_ops = {
    start:   dvsipc_log_size_seq_start,
    next:    dvsipc_log_size_seq_next,
    stop:    dvsipc_log_size_seq_stop,
    show:    dvsipc_log_size_seq_show,
};

static int
dvsipc_log_size_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dvsipc_log_size_ops);
}

/*
 * dvsipc_proc_init() - Create the /proc/fs/dvs/ipc node
 */
static struct proc_dir_entry *dvsipc_proc_dir;
static int
dvsipc_proc_init(void)
{
    struct proc_dir_entry *ipcproc_stats;
    struct proc_dir_entry *ipcproc_config_type;
    struct proc_dir_entry *ipcproc_requests;
    struct proc_dir_entry *ipcproc_log;
    struct proc_dir_entry *ipcproc_log_size;
    char target_dir[32];

    sprintf(target_dir, "%s/%s", SSIPROC_DIR, SSIPROC_IPC_DIR);

    if ((dvsipc_proc_dir = proc_mkdir(target_dir, NULL)) == NULL) {
        printk(KERN_ERR "DVS: %s: cannot init /proc/%s\n", 
               __FUNCTION__, target_dir);
        return -ENOMEM;
    }

    if ((ipcproc_stats = proc_create(SSIPROC_STATS,
                                   S_IFREG | S_IRUGO | S_IWUSR,
                                   dvsipc_proc_dir,
                                   &dvsipc_stats_operations)) == NULL) {
            remove_proc_entry(target_dir, NULL);
            printk(KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
                   __FUNCTION__, target_dir, SSIPROC_STATS);
            return -ENOMEM;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    ipcproc_stats->uid = 0;
#else
    proc_set_user(ipcproc_stats, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

    if ((ipcproc_config_type = proc_create(SSIPROC_CONFIG_TYPE,
                                   S_IFREG | S_IRUGO | S_IWUSR,
                                   dvsipc_proc_dir,
                                   &dvsipc_config_type_operations)) == NULL) {
            remove_proc_entry(SSIPROC_STATS, NULL);
            remove_proc_entry(target_dir, NULL);
            printk(KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
                   __FUNCTION__, target_dir, SSIPROC_CONFIG_TYPE);
            return -ENOMEM;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    ipcproc_config_type->uid = 0;
#else
    proc_set_user(ipcproc_config_type, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

    if ((ipcproc_requests = proc_create(SSIPROC_REQ,
                                   S_IFREG | S_IRUSR,
                                   dvsipc_proc_dir,
                                   &dvsipc_requests_operations)) == NULL) {
            remove_proc_entry(SSIPROC_CONFIG_TYPE, NULL);
            remove_proc_entry(SSIPROC_STATS, NULL);
            remove_proc_entry(target_dir, NULL);
            printk(KERN_ERR "DVS: %s: connot init /proc/%s/%s\n",
            		__FUNCTION__, target_dir, SSIPROC_REQ);
            return -ENOMEM;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    ipcproc_requests->uid = 0;
#else
    proc_set_user(ipcproc_requests, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

    if ((ipcproc_log = proc_create(SSIPROC_IPC_LOG,
                                   S_IFREG | S_IRUSR,
                                   dvsipc_proc_dir,
                                   &dvsipc_log_operations)) == NULL) {
            remove_proc_entry(SSIPROC_CONFIG_TYPE, NULL);
            remove_proc_entry(SSIPROC_STATS, NULL);
            remove_proc_entry(SSIPROC_REQ, NULL);
            remove_proc_entry(target_dir, NULL);
            printk(KERN_ERR "DVS: %s: connot init /proc/%s/%s\n",
            		__FUNCTION__, target_dir, SSIPROC_IPC_LOG);
            return -ENOMEM;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    ipcproc_log->uid = 0;
#else
    proc_set_user(ipcproc_log, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

    if ((ipcproc_log_size = proc_create(SSIPROC_IPC_LOG_SIZE,
                                   S_IFREG | S_IRUSR,
                                   dvsipc_proc_dir,
                                   &dvsipc_log_size_operations)) == NULL) {
            remove_proc_entry(SSIPROC_IPC_LOG, NULL);
            remove_proc_entry(SSIPROC_CONFIG_TYPE, NULL);
            remove_proc_entry(SSIPROC_STATS, NULL);
            remove_proc_entry(SSIPROC_REQ, NULL);
            remove_proc_entry(target_dir, NULL);
            printk(KERN_ERR "DVS: %s: connot init /proc/%s/%s\n",
            		__FUNCTION__, target_dir, SSIPROC_IPC_LOG_SIZE);
            return -ENOMEM;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    ipcproc_log_size->uid = 0;
#else
    proc_set_user(ipcproc_log_size, KUIDT_INIT(0), KGIDT_INIT(0));
#endif

    return 0;
}

/*
 * Clean up the /proc linkage for statistics collection.
 */
static void
dvsipc_proc_term()
{
    char target_dir[32];

    if (dvsipc_proc_dir == NULL) {
        return;
    }

    sprintf(target_dir, "%s/%s", SSIPROC_DIR, SSIPROC_IPC_DIR);

    remove_proc_entry(SSIPROC_CONFIG_TYPE, dvsipc_proc_dir);
    remove_proc_entry(SSIPROC_STATS, dvsipc_proc_dir);
    remove_proc_entry(SSIPROC_REQ, dvsipc_proc_dir);
    remove_proc_entry(SSIPROC_IPC_LOG, dvsipc_proc_dir);
    remove_proc_entry(SSIPROC_IPC_LOG_SIZE, dvsipc_proc_dir);
    remove_proc_entry(target_dir, NULL);
    dvsipc_proc_dir = NULL;
}

module_init(init_dvsipc);
module_exit(exit_dvsipc);

EXPORT_SYMBOL(max_nodes);
EXPORT_SYMBOL(dvsipc_lnode_to_node);
EXPORT_SYMBOL(dvsipc_node_to_lnode);
EXPORT_SYMBOL(dvs_alloc_buf);
EXPORT_SYMBOL(dvs_free_buf);
EXPORT_SYMBOL(dvs_direct_buf_alloc);
EXPORT_SYMBOL(dvs_direct_buf_free);
EXPORT_SYMBOL(dvsipc_name2nid);

/* Load-time tunable parameters */
uint dvsipc_response_timeout = DVSIPC_RESPONSE_TIMEOUT;
uint dvsipc_tx_timeout = DVSIPC_TX_TIMEOUT;
uint dvsipc_tx_resend_limit = DVSIPC_RESEND_LIMIT;
int dvsipc_msg_thread_limit = DVSIPC_MSG_THREAD_LIMIT;
int dvsipc_single_msg_queue = 0;
int dvsipc_heartbeat_timeout = 0; /* REMOVE IN RHINE */

/*
 * Prior to the Rhine release, dvsipc_config_type was set to
 * dvs_config_type_client for CONFIG_CRAY_COMPUTE builds, and to
 * dvs_config_type_server for all other builds.  Now that Rhine System
 * Management allows for dynamic and fine-grained configuration, we
 * default to dvs_config_type_client for all builds, and allow the
 * IMPS config set to define which nodes are DVS servers.  These nodes
 * will load the DVS modules with dvsipc_config_type set to
 * dvs_config_type_server.
 */
int dvsipc_config_type = dvs_config_type_client;

int dvsipc_msg_thread_max = -1;
int dvsipc_msg_thread_min = -1;
int dvsipc_buf_limit = -1;
int dvsipc_buf_timeout = -1;
int dvsipc_num_rx_mds = 34;

module_param_array_named(dvs_instance_info, instance_params[0].param_array, int, &instance_params[0].count, 0444);
MODULE_PARM_DESC(dvs_instance_info, "dvs_instance_info: thread_min, thread_max, thread_limit, "
                 "thread_concurrent_creates, thread_nice, single_msg_queue, init_free_qhdrs, max_free_qhdrs");
module_param_array_named(kdwfs_instance_info, instance_params[1].param_array, int, &instance_params[1].count, 0444);
MODULE_PARM_DESC(kdwfs_instance_info, "kdwfs_instance_info: thread_min, thread_max, thread_limit, "
                 "thread_concurrent_creates, thread_nice, single_msg_queue, init_free_qhdrs, max_free_qhdrs");
module_param_array_named(kdwfsb_instance_info, instance_params[2].param_array, int, &instance_params[2].count, 0444);
MODULE_PARM_DESC(kdwfsb_instance_info, "kdwfsb_instance_info: thread_min, thread_max, thread_limit, "
                 "thread_concurrent_creates, thread_nice, single_msg_queue, init_free_qhdrs, max_free_qhdrs");
module_param_array_named(kdwcfs_instance_info, instance_params[3].param_array, int, &instance_params[3].count, 0444);
MODULE_PARM_DESC(kdwcfs_instance_info, "kdwcfs_instance_info: thread_min, thread_max, thread_limit, "
                 "thread_concurrent_creates, thread_nice, single_msg_queue, init_free_qhdrs, max_free_qhdrs");
module_param(ipc_log_size_kb, uint, 0444);
MODULE_PARM_DESC(ipc_log_size_kb, "size of the IPC log buffer in KB");
module_param(dvsipc_response_timeout, uint, 0);
MODULE_PARM_DESC(dvsipc_response_timeout, "timeouts for request responses");
module_param(dvsipc_tx_timeout, uint, 0);
MODULE_PARM_DESC(dvsipc_tx_timeout, "timeouts for network transmits");
module_param(dvsipc_tx_resend_limit, uint, 0);
MODULE_PARM_DESC(dvsipc_tx_resend_limit, "resend limit for transmit requests");
module_param(dvsipc_config_type, int, 0444);
MODULE_PARM_DESC(dvsipc_config_type, "dvs configuration type");
module_param(dvsipc_buf_timeout, int, 0444);
MODULE_PARM_DESC(dvsipc_buf_timeout, "dvs cache buf expiration timeout");
module_param(dvsipc_buf_limit, int, 0444);
MODULE_PARM_DESC(dvsipc_buf_limit, "dvs cache buf size limit");
module_param(dvsipc_msg_thread_max, int, 0444);
MODULE_PARM_DESC(dvsipc_msg_thread_max, "maximum persistent threads");
module_param(dvsipc_msg_thread_min, int, 0444);
MODULE_PARM_DESC(dvsipc_msg_thread_min, "threads created at startup");
module_param(dvsipc_msg_thread_limit, int, 0444);
MODULE_PARM_DESC(dvsipc_msg_thread_limit, "cap on active message threads");
module_param(dvsipc_num_rx_mds, int, 0444);
MODULE_PARM_DESC(dvsipc_num_rx_mds, "number of receive buffers");
module_param(dvsipc_single_msg_queue, int, 0444);
MODULE_PARM_DESC(dvsipc_single_msg_queue, "use only one incoming message queue");
module_param(dvsipc_rma_page_limit, int, 0444);
MODULE_PARM_DESC(dvsipc_rma_page_limit, "number of pages per rma");
module_param(dvsipc_heartbeat_timeout, int, 0444);
