/*
 * Copyright 2009-2018 Cray Inc. All Rights Reserved.
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
 * This file contains impingement code linking the seastar ipc
 * transport to the lnet API.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 14)
#include <linux/sched/mm.h>
#endif
#include "dvs/dvs_lnetconfig.h"
#if DVS_LNET_VERSION < LNET_VERSION_CODE(2, 10, 55, 0)
#include <lnet.h>
#endif
#include <lnet/lib-lnet.h>
#include <lnet/lib-types.h>

#include "dvsipc.h"

#include "common/ssi_proc.h"
#include "common/log.h"
#include "dvs/dvs_config.h"

static char *node_prefix = "10.128.0";
module_param(node_prefix, charp, 0);

static int trace_disable = 0;
module_param(trace_disable, uint, 0);

/* LND_NAME defined in dvs/dvs_config.h */
static char *lnd_name = LND_NAME;
module_param(lnd_name, charp, 0);

MODULE_LICENSE("GPL");

#define IPC_LNET_PORTAL 63 /* Portal reserved for dvs ipc */

#define make_rx_buf_desc(idx, seq) ((void *)(((uint64_t)IPC_LNET_PORTAL << 48) \
					| (((uint64_t)idx) << 32) | seq))

#define get_rx_buf_seq(rx_desc) (((uint64_t)rx_desc) & 0xffffffff)

#define get_rx_buf_idx(rx_desc) ((((uint64_t)rx_desc) >> 32) & 0xffff)

/*
 * PIDs are not unique in LNet so use whatever Lustre tells us to use.
 *
 */
/* some 2.5 versions didn't have this change */
#ifdef LNET_PID_LUSTRE
#define IPC_LNET_PID LNET_PID_LUSTRE
#else
#define IPC_LNET_PID LUSTRE_SRV_LNET_PID
#endif

static lnet_handle_eq_t lnet_rx_eq; /* rx and tx event queues */
static lnet_handle_eq_t lnet_tx_eq;
static lnet_handle_eq_t lnet_rma_eq; /* for server RMA puts/gets */
static lnet_handle_eq_t lnet_rma_io_eq; /* client RMA io get/put tracking */

typedef struct {
	lnet_handle_me_t me_handle;
	lnet_handle_md_t md_handle; // normally not needed but in case..
	unsigned int md_seq; // sequence number specified when the MD was bound
} lnet_m_handles_t;

static lnet_m_handles_t lnet_rx_m_table[DVSIPC_MAX_RX_MDS] = { { { 0 },
								 { 0 } } };

/* Match entries to control landing zone overflow and retransmit requests */
static lnet_handle_me_t lnet_rx_me_guard = { 0 };
static lnet_handle_me_t lnet_rx_me_resend = { 0 };
static lnet_handle_me_t lnet_rx_me_orphan = { 0 };

static void lnet_rx_callback(lnet_event_t *event);
static void lnet_tx_callback(lnet_event_t *event);
static void lnet_rma_callback(lnet_event_t *event);
static void lnet_rma_io_callback(lnet_event_t *event);

static lnet_process_id_t my_lnet_process_id = { 0 };

/*
 * Forward definitions for lower half interface routines.
 */
static void lnet_send_nak(uint64_t nid, void *rq);
static int lnet_tx_request(uint64_t nid, struct usiipc *rq, int resend_limit,
			   int tx_timeout);
static void *lnet_mapkvm(char *kvm, ssize_t length, int rw);
static int lnet_unmapkvm(void *handle);
static void *lnet_mapuvm(char *uvm, ssize_t length, int rw);
static int lnet_unmapuvm(void *handle);
static void *lnet_rma(uint64_t node, char *to, char *from, ssize_t length,
		      rma_info_t *ri, int timeout, int async);
static void lnet_rma_wait(rma_info_t *rip);
static int lnet_fill_rx_slot(int slot, rx_buf_info_t *bip, int size,
			     unsigned int seq, int invalidate_old);
static int dvs_lnet_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper,
			 ssize_t *max_msg_size, int num_mds);
static void lnet_term(void);

dvsipc_upper_api_t *upper_api = NULL;

typedef struct lnet_rma_info {
	struct semaphore sema;
	int lnode;
	int retval;
	uint64_t length;
	rma_type_t rma_type;
	lnet_handle_md_t mdh;
} lnet_rma_info_t;

static int ipc_num_mds;

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>

/*
 * The following structures are used to create a node at
 * /proc/sys/fs/dvs/ipc/trace_disable to allow dvs debug
 * tracing to be enabled or disabled at runtime via sysctl.
 */
static struct ctl_table var_table[] = {
	{
		.procname = "trace_disable",
		.data = &trace_disable,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec,
	},
	{}
};

static struct ctl_table ipc_table[] = {
	{
		.procname = "ipc",
		.mode = 0555,
		.child = var_table,
	},
	{}
};

static struct ctl_table dvs_table[] = {
	{
		.procname = "dvs",
		.mode = 0555,
		.child = ipc_table,
	},
	{}
};

static struct ctl_table root_table[] = {
	{
		.procname = "fs",
		.mode = 0555,
		.child = dvs_table,
	},
	{}
};

static struct ctl_table_header *lnet_sysctl_table;

#endif

static inline void lnet_invalidate_md_handle(lnet_handle_md_t *h)
{
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 54, 0)
	LNetInvalidateMDHandle(h);
#else
	LNetInvalidateHandle(h);
#endif
}

static inline void lnet_invalidate_eq_handle(lnet_handle_eq_t *h)
{
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 54, 0)
	LNetInvalidateEQHandle(h);
#else
	LNetInvalidateHandle(h);
#endif
}

/*
 * Convert LNet event type to string.
 */
static char *lnet_event_str(lnet_event_kind_t ev)
{
	static char s[32];
	switch (ev) {
	case LNET_EVENT_GET:
		return "LNET_EVENT_GET";
	case LNET_EVENT_PUT:
		return "LNET_EVENT_PUT";
	case LNET_EVENT_REPLY:
		return "LNET_EVENT_REPLY";
	case LNET_EVENT_ACK:
		return "LNET_EVENT_ACK";
	case LNET_EVENT_SEND:
		return "LNET_EVENT_SEND";
	case LNET_EVENT_UNLINK:
		return "LNET_EVENT_UNLINK";
	default:
		sprintf(s, "Invalid LNet Event %d", (int)ev);
		return s;
	}
}

/*
 * Functions for translating to/from nid to lnet(ptl) address space
 */

/*
 * Translation functions for moving between physical nid
 * number and lnet identifiers.
 */
static lnet_nid_t nid2lnetnid(int nid)
{
	lnet_nid_t lnet_nid;
	char nidstr[128];

	if (strncmp(lnd_name, "gni_ip", 6) == 0) {
		sprintf(nidstr, "%s.%d@%s", node_prefix, nid + 1, "gni");
	} else if ((strncmp(lnd_name, "ptl", 3) == 0) ||
		   (strncmp(lnd_name, "gni", 3) == 0)) {
		sprintf(nidstr, "%d@%s", nid, lnd_name);
	} else {
		DVS_TRACE("badlnd", 0, 0);
		DVS_TRACEP(lnd_name, 0, 0);
		return DVSIPC_INVALID_NODE;
	}

	lnet_nid = libcfs_str2nid(nidstr);

	KDEBUG_IPC(0, "%s: %d = %s (0x%Lx)\n", __FUNCTION__, nid, nidstr,
		   lnet_nid);
	DVS_TRACE("n2lnn", nid, lnet_nid);
	if (lnet_nid == LNET_NID_ANY) {
		printk(KERN_ERR "DVS: %s: nid translation failed for %s\n",
		       __FUNCTION__, nidstr);
		lnet_nid = DVSIPC_INVALID_NODE;
	}
	return lnet_nid;
}

/*
 * Utility functions for building and managing lnet MDs and MEs.
 */

#define DVSIPC_LNET_IGNORE_LOWBITS 0xff

#define DVSIPC_LNET_MATCH_TYPE(type)                                           \
	((DVSIPC_RX_MATCHBITS & ~DVSIPC_LNET_IGNORE_LOWBITS) |                 \
	 (1 << (type + 1)))
#define DVSIPC_LNET_IGNORE_TYPE(type) ((uint64_t)(1 << (type + 1)) - 1)

#define DVSIPC_LNET_MATCH_SLOT(slot)                                           \
	DVSIPC_LNET_MATCH_TYPE(lnet_rx_slot_type(slot))
#define DVSIPC_LNET_MATCH_SIZE(size)                                           \
	DVSIPC_LNET_MATCH_TYPE(lnet_rx_size_to_type(size))

#define DVSIPC_LNET_IGNORE_SLOT(slot)                                          \
	DVSIPC_LNET_IGNORE_TYPE(lnet_rx_slot_type(slot))
#define DVSIPC_LNET_IGNORE_SIZE(size)                                          \
	DVSIPC_LNET_IGNORE_TYPE(lnet_rx_size_to_type(slot))

typedef enum { rx_small, rx_med, rx_large } rx_slot_type_t;

static char *rx_slot_str[] = { "rx_small", "rx_med", "rx_large" };

static unsigned long rx_slot_sizes[] = { 1024, 8192, IPC_MAX_MSG_SIZE };

/*
 * lnet_rx_slot_type - return the buffer assignment type for the
 *                     specified receive type.
 *
 * To support the handling of variable length unexpected messages,
 * the module creates a set of receive buckets associated with
 * various sizes. This helps distribute the receive load across
 * the MDs and avoid cases were MDS become 'mostly' full and
 * we start having to drop larger messages.
 */
static rx_slot_type_t lnet_rx_slot_type(int slot_id)
{
	rx_slot_type_t which_slot;

	if ((slot_id <= (ipc_num_mds >> 2)))
		which_slot = rx_small;
	else if (slot_id < ((ipc_num_mds >> 1) + (ipc_num_mds >> 2)))
		which_slot = rx_med;
	else
		which_slot = rx_large;

	KDEBUG_IPC(0, "%s: slot %d = %s\n", __FUNCTION__, slot_id,
		   rx_slot_str[which_slot]);

	return which_slot;
}

/*
 * lnet_rx_size_to_type - return the type of slot into which
 *                        a message of the specified size will
 *                        fit.
 */
static rx_slot_type_t lnet_rx_size_to_type(unsigned long size)
{
	if (size <= rx_slot_sizes[rx_small])
		return rx_small;
	if (size <= rx_slot_sizes[rx_med])
		return rx_med;
	return rx_large;
}

/*
 * lnet_rx_slot_to_size - Return the max size of message handled by
 *                        md residing in the specified slot.
 */
static unsigned int lnet_rx_slot_to_size(unsigned int slot)
{
	return rx_slot_sizes[lnet_rx_slot_type(slot)];
}

/*
 * lnet_build_rx_md - Initialize a LNet MD for a receive buffer
 *
 * This routine is used to initialize a LNet Memory Descriptor for
 * a buffer that will be used to hold inbound messages.
 *
 * The pointer to the buffer (bip) must be specified by the caller.
 *
 * On success, 0 is returned to the caller. Otherwise, -ENOMEM is returned.
 */
static int lnet_build_rx_md(rx_buf_info_t *bip, int size, int me_idx,
			    lnet_md_t *md, int seq)
{
	int ret = 0;

	KDEBUG_IPC(0, "%s: IN (0x%p:%d:%d:%u:0x%p)\n", __FUNCTION__, bip, size,
		   me_idx, seq, md);

	DVS_TRACEL("bldrxIN", me_idx, seq, bip, size, 0);

	/*
	 * Clear it to start since there are flags/etc in there and over
	 * time with different Lustre releases things are added.
	 */
	memset(md, 0, sizeof(lnet_md_t));

	/*
	 * Divide the ME table up into sections where the message size in
	 * each section is S, M and L.
	 */
	md->max_size = lnet_rx_slot_to_size(me_idx);

	md->start = (char *)bip + sizeof(rx_buf_info_t); /* force character math
							  */
	md->length = size - sizeof(rx_buf_info_t);
	md->options = LNET_MD_OP_PUT | LNET_MD_MAX_SIZE;
	md->threshold = md->length / md->max_size;
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 52, 0)
	lnet_invalidate_md_handle(&(md->bulk_handle));
#endif

	KDEBUG_IPC(0, "%s: %d:%u 0x%p:0x%x:0x%x:0x%x\n", __FUNCTION__, me_idx,
		   seq, md->start, md->options, md->threshold, md->max_size);

	DVS_TRACEL("bldrxMD", me_idx, seq, md->threshold, md->max_size, bip);

	md->eq_handle = lnet_rx_eq;
	md->user_ptr = make_rx_buf_desc(me_idx, seq);

	/* Initialize buffer state */
	atomic_set(&bip->rxbuf_refcount, 0);

	return ret;
}

static int lnet_build_backstop_me(lnet_handle_me_t *mehp, __u64 match,
				  __u64 ignore, void *user_ptr)
{
	lnet_md_t md;
	lnet_handle_md_t mdh;
	int ret;

	if ((ret = LNetMEAttach(IPC_LNET_PORTAL,
				(lnet_process_id_t){ .nid = LNET_NID_ANY,
						     .pid = LNET_PID_ANY },
				match, ignore, LNET_RETAIN, LNET_INS_AFTER,
				mehp)) < 0) {
		DVS_LOGP("DVS: %s: LNetMEAttach failed (%d)\n", __FUNCTION__,
			 ret);
		return -ENOSPC;
	}

	/*
	 * Clear it to start since there are flags/etc in there and over
	 * time with different Lustre releases things are added.
	 */
	memset(&md, 0, sizeof(lnet_md_t));
	md.start = NULL;
	md.length = 0;
	md.options = LNET_MD_OP_PUT | LNET_MD_TRUNCATE | LNET_MD_ACK_DISABLE;
	md.threshold = LNET_MD_THRESH_INF;
	md.eq_handle = lnet_rx_eq;
	md.user_ptr = user_ptr;
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 52, 0)
	lnet_invalidate_md_handle(&md.bulk_handle);
#endif

	if ((ret = LNetMDAttach(*mehp, md, LNET_RETAIN, &mdh)) < 0) {
		DVS_LOGP("DVS: %s: LNetMDAttach failed (%d)\n", __FUNCTION__,
			 ret);
		return -ENOSPC;
	}

	return 0;
}

/*
 * lnet_bind_buf - Map a buffer into lnet space.
 *
 * This routine is used to bind a buffer to a lnet
 * handle for subsequent transmission.
 *
 * If no buffer is supplied, -ENOMEM is returned. Otherwise,
 * the result of the call to LNetMDBind is returned to the caller.
 */
static int lnet_bind_buf(void *buf, int size, int evt_thresh, int md_opt,
			 lnet_handle_eq_t eq, void *user_ptr, int bind_opt,
			 lnet_handle_md_t *mdhp)
{
	lnet_md_t md;
	int ret;

	KDEBUG_IPC(0, "%s: IN (0x%p 0x%x 0x%p)\n", __FUNCTION__, buf, size,
		   mdhp);
	if (buf == NULL && size) {
		DVS_TRACEL("ipc_bE", buf, size, mdhp, 0, 0);
		return (-ENOMEM);
	}

	/*
	 * Clear it to start since there are flags/etc in there and over
	 * time with different Lustre releases things are added.
	 */
	memset(&md, 0, sizeof(lnet_md_t));
	md.start = buf;
	md.length = size;
	md.threshold = evt_thresh;
	md.options = md_opt;
	md.eq_handle = eq;
	md.user_ptr = user_ptr;
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 52, 0)
	lnet_invalidate_md_handle(&md.bulk_handle);
#endif

	ret = LNetMDBind(md, bind_opt, mdhp);
	if (ret != 0) {
		DVS_TRACEL("lnbb", buf, size, ret, 0, 0);
		DVS_LOGP("DVS: %s: LNetMDBind failed for 0x%p:0x%x (%d)\n",
			 __FUNCTION__, buf, size, ret);
	}
	return ret;
}

/*
 * Handlers for lnet event callbacks.
 */

/*
 * lnet_tx_callback - Callback for a lnet transmit event.
 *
 * When a lnet transmit request is made, this callback routine
 * is specified. When lnet fires an event of interest on the
 * change of transmit state, this routine will be called. If the
 * event happens to be a PTL_EVENT_SEND_END, we know that the transmit
 * has completed and the ipc layer is notified as appropriate.
 *
 * If the transport should free an asynchronous message on transmit
 * completion, free_required will be set to 2. Otherwise, an interested
 * waiter will block on the msgwait semaphore.
 */
static void lnet_tx_callback(lnet_event_t *event)
{
	struct usiipc *msg = (struct usiipc *)event->md.start;

	KDEBUG_IPC(0, "DVS: %s: event type (0x%x)\n", __FUNCTION__,
		   event->type);

	/* nak requests have no payload */
	if (msg == NULL) {
		DVS_TRACE("ipc_txrsnd", event->rlength, event->hdr_data);
		return;
	}

	if (event->status != 0) {
		KDEBUG_IPC(0, "DVS: %s: failed (error %d on %s to %s)\n",
			   __FUNCTION__, event->status, rq_cmd_name(msg),
			   SSI_NODE_NAME(msg->target_node));
	}

	if (event->type == LNET_EVENT_SEND) {
		KDEBUG_IPC(0, "DVS: %s: tx complete (0x%p:0x%p:%s)\n",
			   __FUNCTION__, msg, event->md.user_ptr,
			   rq_cmd_name(msg));

		if (event->status != 0) {
			KDEBUG_IPC(0, "DVS: %s: tx failed (%s:%d:%s)\n",
				   __FUNCTION__,
				   SSI_NODE_NAME(msg->target_node),
				   event->status, rq_cmd_name(msg));

			upper_api->tx_complete(msg, 1);
		} else if (event->md.user_ptr ==
			   0 /*!IPC_WAIT_FOR_REPLY(msg)*/) {
			upper_api->tx_complete(msg, 0);
		} else {
			/* transmit has hit the destination node */
			tx_status_t *tx_status =
				(tx_status_t *)&msg->transport_handle;
			dvsipc_tx_t *txp = container_of(msg, dvsipc_tx_t, msg);

			/* ACK could have already hit */
			if (atomic_read(&tx_status->upper_status) != 0) {
				upper_api->tx_complete(msg, 0);
				/* ... as could a NAK */
			} else if (atomic_read(&tx_status->lower_status) ==
				   DVSIPC_TX_RESEND) {
				DVS_TRACE("nak<tx", msg, msg->target_node);
				up(&txp->sema);
			} else {
				atomic_inc(&tx_status->upper_status);
			}
		}
	} else if (event->type == LNET_EVENT_ACK) {
		tx_status_t *tx_status = (tx_status_t *)&msg->transport_handle;

		/* ACK could hit before SEND_END */
		if (atomic_read(&tx_status->upper_status) > 0) {
			upper_api->tx_complete(msg, 0);
		} else {
			atomic_dec(&tx_status->upper_status);
		}
	} else if (event->type != LNET_EVENT_UNLINK) {
		printk(KERN_ERR
		       "DVS: %s: unexpected event (%s) match 0x%Lx user_ptr 0x%p\n",
		       __FUNCTION__, lnet_event_str(event->type),
		       event->match_bits, (void *)event->md.user_ptr);
	} else {
		KDEBUG_IPC(0, "%s: LNET_EVENT_UNLINK 0x%x\n", __FUNCTION__,
			   event->rlength);
	}
}

/*
 * lnet_rx_callback - Callback for a lnet receive event.
 *
 * When a lnet message is received, this callback routine is
 * called. We perform accounting on the shared rx buf and pass the
 * message along to higher ipc layers for handling unless there were
 * issues with the message.
 */
static void lnet_rx_callback(lnet_event_t *event)
{
	unsigned long debug = 0;
	uint64_t current_time_us;
	KDEBUG_IPC(0, "lnet_rx_callback: event type (0x%x)\n", event->type);

	if (event->type == LNET_EVENT_PUT) {
		rx_buf_info_t *bip;
		struct usiipc *msg;
		int me_idx = get_rx_buf_idx(event->md.user_ptr);
		u32 md_seq = get_rx_buf_seq(event->md.user_ptr);
		int valid_msg = !event->status;
		int bstate;

		/*
		 * Check for overflow md.
		 */
		if (event->md.user_ptr == (uint64_t *)(DVSIPC_OVERFLOW_TAG)) {
			DVS_TRACEL("ipc_rxG", event->hdr_data, event->type,
				   event->initiator.nid, event->initiator.pid,
				   0);
			KDEBUG_IPC(0, "%s: naking message from %s\n",
				   __FUNCTION__,
				   libcfs_nid2str(event->initiator.nid));
			if (event->hdr_data == 0) {
				/* ignore, no reply expected */
			} else {
				/* resend */
				upper_api->nak(event->initiator.nid,
					       event->hdr_data);
			}
			return;
			/*
			 * Check for resend md.
			 */
		} else if (event->md.user_ptr == (void *)DVSIPC_RESEND_REQ) {
			struct usiipc *rq = (struct usiipc *)(event->hdr_data);
			tx_status_t *tx_status =
				(tx_status_t *)&rq->transport_handle;
			dvsipc_tx_t *txp = container_of(rq, dvsipc_tx_t, msg);
			int lower_status;

			/* Notify sending thread to retransmit */
			lower_status = atomic_cmpxchg(&tx_status->lower_status,
						      0, DVSIPC_TX_RESEND);

			DVS_TRACEL("ipc_rxRS", rq, &rq->msgwait,
				   event->hdr_data, lower_status, 0);

			if (lower_status == DVSIPC_TX_ORPHANED) {
				kfree_ssi(txp);
			} else {
				if (lower_status != 0) {
					if (lower_status < 0) {
						DVS_LOGP(
							"DVS: %s: lower status unexpectedly < 0 "
							"for resend request\n",
							__FUNCTION__);
					}
				} else {
					DVS_TRACE("ipcRs<Tx", rq->target_node,
						  lower_status);
					KDEBUG_IPC(
						0,
						"%s: resend before tx complete\n",
						__FUNCTION__);
				}
				up(&txp->sema);
			}
			return;
			/*
			 * Check for orphaned rdma.
			 */
		} else if (event->md.user_ptr == (void *)DVSIPC_ORPH_REQ) {
			DVS_TRACE("ipcrxorp", event->initiator.nid, 0);
			return;
		}

		/*
		 * OK, it didn't hit any of the special backstop MEs so it's in
		 * one of our standard message slots.  Do some validation that
		 * that slot is what we think it should be now.
		 */
		if (unlikely(md_seq != lnet_rx_m_table[me_idx].md_seq)) {
			printk(KERN_EMERG
			       "MD event seq %d for slot %d doesn't match DVS view %d\n",
			       md_seq, me_idx, lnet_rx_m_table[me_idx].md_seq);
			DVS_TRACEL("lnrxMDE!", me_idx, md_seq,
				   lnet_rx_m_table[me_idx].md_seq, 0, 0);
			KDEBUG_IPC(
				debug,
				"%s: MD event seq %d for slot %d does not match "
				"DVS view %d\n",
				__func__, md_seq, me_idx,
				lnet_rx_m_table[me_idx].md_seq);
		}
		msg = (struct usiipc *)((char *)event->md.start +
					event->offset);

		bip = (void *)((char *)(event->md.start -
					sizeof(rx_buf_info_t)));
		atomic_inc(&bip->rxbuf_refcount);

		bstate = atomic_read(&bip->rxbuf_state);
		if (unlikely(bstate != RXBUF_NetworkLinked)) {
			printk(KERN_EMERG "RX buffer in invalid state %d !!\n",
			       bstate);
			DVS_BUG();
		}

		if (valid_msg) {
			if (unlikely(sizeof(struct usiipc) !=
				     msg->usiipc_len)) {
				/*
				 * Until we have some sort of versioning where
				 * we can land on our feet in situations like
				 * this, ignore messages from a node that's
				 * running a different protocol or we'd likely
				 * panic or corrupt something.
				 *
				 * We're going to free this as soon as possible
				 * but the free routine needs a pointer to the
				 * rx_buf_info_t structure that only we can
				 * provide.  Make sure there's enough space and
				 * use the reply_address field to transport this
				 * pointer.  If for some reason there's not even
				 * enough room for that -- panic.
				 */
				if (msg->usiipc_len <
				    offsetof(struct usiipc, command) +
					    sizeof(msg->command)) {
					printk(KERN_EMERG
					       "DVS: invalid message length %d\n",
					       msg->usiipc_len);
					DVS_BUG();
				}
				msg->command = RQ_SUSPECT;
				msg->reply_address = bip;
				printk(KERN_EMERG
				       "DVS: ignoring message from %s due to protocol "
				       "incompatibilities: usiipc size %d expected %ld\n",
				       SSI_NODE_NAME(msg->source_node),
				       msg->usiipc_len, sizeof(struct usiipc));
				DVS_TRACEL("ipc_rxPE", msg, msg->source_node,
					   msg->usiipc_len,
					   sizeof(struct usiipc), 0);
			} else {
				DVS_TRACEL("ipc_rx", msg, msg->source_node,
					   msg->command, event->md.start, 0);

				if (lnet_rx_size_to_type(event->md.max_size) !=
				    lnet_rx_size_to_type(msg->request_length)) {
					debug = msg->debug;
					KDEBUG_IPC(
						debug,
						"%s: me_idx 0x%x caught msg of size 0x%x\n",
						__FUNCTION__, me_idx,
						msg->request_length);
				}
			}
		} else {
			/*
			 * If LNet returned an error we don't know if there was
			 * a message placed at md.start or not so we can't touch
			 * msg (md.start might now be used for the next message
			 * received)   We still need to do the unlinked check so
			 * we'll tippy-toe around and exit as soon as possible.
			 */
			DVS_TRACEL("ipcrxcvF", msg, bip, event->status, 0, 0);
			DVS_LOGP("DVS: %s: rx failed with error %d\n",
				 __FUNCTION__, event->status);
		}

		bstate = atomic_read(&bip->rxbuf_state);
		if (unlikely(bstate != RXBUF_NetworkLinked)) {
			printk(KERN_EMERG "RX buffer in invalid state %d !!\n",
			       bstate);
			DVS_BUG();
		}

		if (event->unlinked == 1) {
			KDEBUG_IPC(debug, "%s: %d unlinked(0x%p)\n",
				   __FUNCTION__, me_idx, bip);
			DVS_TRACEL("ipcrxcvU", bstate, me_idx, msg, bip,
				   atomic_read(&bip->rxbuf_refcount));

			atomic_set(&bip->rxbuf_state, RXBUF_NetworkUnlinked);

			/*
			 * The reference count has to be at least 2 here since
			 * there's one for the fact that it was "linked" (in use
			 * by the ME/MDs) and one for the message in the buffer
			 * that we just received.  Since it's no longer
			 * MD-linked, we'll drop that one now.
			 */
			atomic_dec(&bip->rxbuf_refcount);

			/*
			 * Notify the upper layer that it's been unlinked so
			 * they can do whatever's necessary at that level.
			 */
			upper_api->rx_detach(me_idx);
		}

		if (msg->command == RQ_SUSPECT) {
			/* OK, we're done -- have the upper layer free it
			 * immediately */
			upper_api->rx_free(RXSCOPE_Msg, msg);
			return;
		}

		if (!valid_msg) {
			/*
			 * It could be the last message in the buffer so we'll
			 * need to go through the free code so it isn't
			 * stranded.
			 */
			upper_api->rx_free(RXSCOPE_Buffer, bip);
			return;
		}

		/* Perform state management for the shared md. */
		msg->transport_handle = bip;
		msg->free_required = 1;
		current_time_us = dvs_time_get_us();
		msg->network_time_us = current_time_us;
		if (msg->command == RQ_FILE)
			msg->queue_time_us = current_time_us;

		KDEBUG_IPC(debug, "%s: RCV msg from %s: %s\n", __FUNCTION__,
			   SSI_NODE_NAME(msg->source_node), rq_cmd_name(msg));

		upper_api->rcv(msg);

		KDEBUG_IPC(debug, "%s: RCV OUT msg: 0x%p:0x%p\n", __FUNCTION__,
			   event->md.start, msg);
	} else {
		KDEBUG_IPC(
			0,
			"%s: unexpected event (%s) match 0x%Lx user_ptr 0x%p (0x%x:0x%x)\n",
			__FUNCTION__, lnet_event_str(event->type),
			event->match_bits, (void *)event->md.user_ptr,
			event->rlength, event->mlength);
	}

	return;
}

/*
 * lnet_rma_callback - Callback for a lnet rma event.
 *
 * When a lnet transmit request is made, this callback routine
 * is specified. When lnet fires an event of interest on the
 * change of transmit state, this routine will be called. If the
 * event happens to be a PTL_EVENT_SEND_END, we know that the transmit
 * has completed and the ipc layer is notified as appropriate.
 */
static void lnet_rma_callback(lnet_event_t *event)
{
	lnet_rma_info_t *ri = (lnet_rma_info_t *)(event->md.user_ptr);
	struct semaphore *semap;

	KDEBUG_IPC(0, "%s: %s (0x%Lx,0x%p)\n", __FUNCTION__,
		   lnet_event_str(event->type), event->match_bits,
		   ri ? &ri->sema : NULL);

	/*
	 * No special handling required for unlink events.
	 */
	if (event->type == LNET_EVENT_UNLINK) {
		return;
	}

	/*
	 * If the initiating node has been marked down, we can return now since
	 * shutdown processing will cleanup in-flight rma operations.
	 */
	if (event->initiator.nid != LNET_NID_ANY && ri &&
	    upper_api->node_state(ri->lnode) != NODE_READY) {
		KDEBUG_IPC(
			0,
			"%s: node %s marked down while RMA in flight (%d:0x%Lx:%d)\n",
			__FUNCTION__, libcfs_nid2str(event->initiator.nid),
			upper_api->node_state(ri->lnode), event->initiator.nid,
			event->type);
		DVS_TRACE("rmacb!up", event->initiator.nid, event->type);
		return;
	}

	if (!ri) {
		KDEBUG_IPC(
			0,
			"%s: unexpected rma event (%s) match 0x%Lx user_ptr 0x%p\n",
			__FUNCTION__, lnet_event_str(event->type),
			event->match_bits, (void *)ri);
		DVS_TRACE("rmacb!ri", event->type, event->match_bits);
		return;
	}

	DVS_TRACEL("rmacb", ri->rma_type, event->type, event->status,
		   event->match_bits, 0);

	semap = &ri->sema;

	if (event->type == LNET_EVENT_SEND) {
		KDEBUG_IPC(0, "lnet_rma_callback: send complete (0x%p:0x%p)\n",
			   event->md.start, event->md.user_ptr);

		if (event->status != 0) {
			DVS_TRACEL("rmaCBE", ri->rma_type, event->match_bits,
				   ri, semap, 0);
			KDEBUG_IPC(
				0,
				"lnet_rma_callback: tx failed (0x%p:0x%x:0x%Lx:0x%x:%s)\n",
				event->md.start, event->mlength, ri->length,
				event->status,
				(ri->rma_type == RMA_GET) ? "rma_get" :
							    "rma_put");
			/*
			 * If the send failed, we won't receive the reply.
			 * Inflate the semaphore to allow the originator to
			 * continue.
			 */
			if (ri->rma_type == RMA_GET) {
				up(semap);
			} else {
				ri->retval = event->status;
			}
		}

		/*
		 * Allow for reply event prior to send event. In this case,
		 * ri->retval will have already been set to a non-zero value.
		 */
		if (ri->retval == 0) {
			if (ri->rma_type == RMA_GET) {
				ri->retval = event->status;
			} else {
				ri->retval = event->mlength;
			}
		}
		up(semap);
	} else if (event->type == LNET_EVENT_REPLY) {
		KDEBUG_IPC(
			0,
			"lnet_rma_callback: REPLY (0x%p:%d) (0x%x:0x%x:0x%Lx)\n",
			event->md.start, event->type, event->rlength,
			event->mlength, ri->length);
		/*
		 * The RMA can fail if the remote has cleaned up the MD for the
		 * transfer or because of a communication error. In either case,
		 * return EIO.
		 */
		if (event->mlength != ri->length || event->status != 0) {
			DVS_TRACEL("rmaCBREE", ri->length, event->status,
				   event->mlength, event->match_bits, 0);
			KDEBUG_IPC(0, "%s: REPLY_END failed (0x%x)\n",
				   __FUNCTION__, event->status);
			if (event->status < 0)
				ri->retval = event->status;
			else
				ri->retval = -EIO;
		} else {
			ri->retval = event->mlength;
		}
		up(semap);
	} else {
		DVS_TRACE("rmaCBUNX", ri, event->type);
		KDEBUG_IPC(
			0,
			"%s: unexpected rma event (%s) match 0x%Lx user_ptr 0x%p\n",
			__FUNCTION__, lnet_event_str(event->type),
			event->match_bits, (void *)ri);
	}
}

/*
 * lnet_rma_io_callback - Callback registered for RMA transfers on a client.
 * Used primarily so that the upper layers could know when it's safe to tear
 * things down related to a RMA transaction.  Used for both RMA puts and gets.
 */
static void lnet_rma_io_callback(lnet_event_t *event)
{
	if (event->type == LNET_EVENT_UNLINK) {
		return;
	}

	if ((event->type == LNET_EVENT_PUT) ||
	    (event->type == LNET_EVENT_GET)) {
		if (upper_api->putdone == NULL)
			return;

		/*
		 * Let the upper layers do the tracing/etc since they may have a
		 * a better context of what's going on.
		 */
		upper_api->putdone(event->md.user_ptr, event->status,
				   event->md.start + event->offset,
				   event->mlength);
	} else {
		DVS_TRACE("rmaPcbUX", event->type, event->md.user_ptr);
		IPC_LOG("%s: unexpected rma event (%s) match 0x%Lx user_ptr 0x%p\n",
			__FUNCTION__, lnet_event_str(event->type),
			event->match_bits, event->md.user_ptr);
	}
}

/*
 * dvsipc lower half API implementation for lnet.
 */

/*
 * lnet_tx_request - Send an ipc request to the target node.
 *
 * This routine is used to send an outbound request over the
 * seastar interface. To do this, the requested message is mapped
 * onto a lnet memory descriptor and the resulting md is passed
 * to lnet for transmission via a non-ACK'd LNetPut. The dvs
 * ipc layer will manage responses from the target if necessary.
 *
 */
static int lnet_tx_request(uint64_t nid, struct usiipc *rq, int resend_limit,
			   int tx_timeout)
{
	int ret = 0;
	int rval = 0;
	lnet_process_id_t dest;
	int retries = 0;
	int forced_resend = 0;
	lnet_handle_md_t mdh;
	int MD_valid = 0;
	uint64_t user_data = 0;
	struct usiipc *trq = NULL, *orq = rq;
	struct usiipc *rp =
		(rq->command == RQ_REPLY || rq->command == RQ_REPLY_ERROR) ?
			NULL :
			rq->reply_address;
	tx_status_t *tx_status = NULL;
	int upper_status = 0, lower_status;
	dvsipc_tx_t *txp;
	int len = rq->request_length;
	int terminated = 0;
	int completed = 0;

	KDEBUG_IPC(0, "SS_TX: (%d:%s) %s/%s\n", rq->command, rq_cmd_name(rq),
		   SSI_NODE_NAME(rq->target_node),
		   SSI_NODE_NAME(rq->target_node));

	DVS_TRACEL("ipc_tx", rq->target_node, nid, rq->command, rq->seqno,
		   rq->source_seqno);

	dest.nid = nid;
	dest.pid = IPC_LNET_PID;

	sema_init(&rq->msgwait, 0);

	/* Clear response */
	if (rp) {
		rp->command = 0;
	}

again:
	if (MD_valid) {
		if ((rval = LNetMDUnlink(mdh)) < 0) {
			DVS_LOGP("DVS: %s: LNetMDUnlink failed (%d)\n",
				 __FUNCTION__, rval);
			DVS_TRACE("ipc_txFu", rval, rq);
		}
		MD_valid = 0;
	}
	trq = dvsipc_dup_msg(orq);
	if (trq == NULL) {
		return -ENOMEM;
	}

	/*
	 * print a simple diagnostic to help identify
	 * unresponsive node.
	 */
	if (retries == 0 && orq->retry == 1 && !forced_resend) {
		DVS_LOGP("DVS: %s: awaiting response for %s from %s\n",
			 __FUNCTION__, rq_cmd_name(rq),
			 SSI_NODE_NAME(rq->target_node));
	}

	/* bump retry for next pass */
	orq->retry++;

	txp = container_of(trq, dvsipc_tx_t, msg);
	rq = trq;

	tx_status = (tx_status_t *)&rq->transport_handle;

	/*
	 * Pass along request pointer if we need to send this request
	 * reliably.
	 */
	if (IPC_WAIT_FOR_REPLY(rq) || IS_IOPAGE_REQUEST(rq)) {
		user_data = (uint64_t)(rq);
	}

	if ((uint64_t)rq & 0x3) {
		KDEBUG_IPC(0, "%s: questionable alignment (0x%p:%s)\n",
			   __FUNCTION__, rq, rq_cmd_name(rq));
	}

	if ((ret = lnet_bind_buf(rq, len, LNET_MD_THRESH_INF, 0, lnet_tx_eq,
				 (void *)user_data, LNET_RETAIN, &mdh)) < 0) {
		DVS_LOGP("DVS: %s: lnet_bind_buf failed (%d)\n", __FUNCTION__,
			 ret);
		DVS_TRACE("ipc_txFb", rq->target_node, rq->command);
		kfree_ssi(txp);
		return -ENXIO;
	}
	MD_valid = 1;

	sema_init(&txp->sema, 0);

	do {
		struct timer_list timer;
		unsigned long expire;
		int loopcnt;

		atomic_set(&tx_status->lower_status, 0);
		atomic_set(&tx_status->upper_status, 0);
		loopcnt = 0;

		/*
		 * Give the target node a break.
		 */
		if (retries) {
			KDEBUG_IPC(0, "DVS: %s: resend #%d of %s to %s\n",
				   __FUNCTION__, retries, rq_cmd_name(rq),
				   SSI_NODE_NAME(rq->target_node));
			DVS_TRACEL("ipc_txRT", rq, user_data, rq->target_node,
				   0, 0);

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((retries % 10) + 1);
			set_current_state(TASK_RUNNING);
		}

		if ((ret = LNetPut(my_lnet_process_id.nid, mdh,
				   user_data ? LNET_ACK_REQ : LNET_NOACK_REQ,
				   dest, IPC_LNET_PORTAL,
				   DVSIPC_LNET_MATCH_SIZE(len), 0, user_data)) <
		    0) {
			LNetMDUnlink(mdh);
			DVS_TRACEL("ipc_txFp", 4, ret, rq, rq->target_node,
				   rq->command);
			DVS_LOGP(
				"DVS: %s: LNetPut failed (%d:0x%Lx:%s:0x%Lx%s)\n",
				__FUNCTION__, ret, mdh.cookie, rq_cmd_name(rq),
				dest.nid, libcfs_id2str(dest));
			kfree_ssi(txp);
			return -EIO;
		}

		do {
			/*
			 * We've initiated the requested transfer via lnet. We
			 * now wait for the transmit to complete. If dvs is not
			 * running on the target or the target is down, the
			 * transmit will eventually fail.
			 */

			if (tx_timeout) {
				expire = jiffies + (tx_timeout * HZ);
				setup_timer_on_stack(&timer,
						     upper_api->expire_request,
						     (unsigned long)rq);
				mod_timer(&timer, expire);

				down(&txp->sema);

				del_singleshot_timer_sync(&timer);

				upper_status =
					atomic_read(&tx_status->upper_status);
				lower_status =
					atomic_read(&tx_status->lower_status);

				if (upper_status) {
					loopcnt++;
				}

				/*
				 * Check for anomalous or long-delayed transmit
				 * completions.
				 */
				if ((loopcnt > DVSIPC_MAX_TX_TICKS) &&
				    (lower_status == 0)) {
					/*
					 * Are we awaiting the ACK or SEND_END?
					 */
					if ((loopcnt % DVSIPC_MAX_TX_TICKS) ==
					    0) {
						/*
						 * Check target node status
						 * before going further.
						 */
						if (upper_api->node_state(
							    rq->target_node) ==
						    NODE_DOWN) {
							break;
						}

						/*
						 * If we've received a SEND_END
						 * or ACK but not both,
						 * something is amiss.
						 *
						 *       There are two cases
						 * that we can handle easily.
						 *       Dropped replies and
						 * responses to incomplete
						 *       transmits.
						 *
						 *       1. Since replies are
						 * validated against the
						 *       originating request,
						 * duplicates will be dropped.
						 *       2. If a request has
						 * been handled and a response
						 * is recieved, we know the
						 * request made it to the
						 * destination so we can quit
						 *       waiting for it to
						 * complete.
						 *
						 *       The final case is a
						 * stuck request transmit. We
						 * resend these and allow the
						 * target to drop the request if
						 * it is a duplicate of a
						 * request already in progress.
						 */

						/* resend if REPLY */
						if (rq->command == RQ_REPLY ||
						    rq->command ==
							    RQ_READPAGE_DATA) {
							(void)atomic_cmpxchg(
								&tx_status->lower_status,
								lower_status,
								DVSIPC_TX_ORPHANED);
							DVS_TRACEL(
								"ipc_txRS", rq,
								loopcnt,
								rq->target_node,
								lower_status,
								0);
							KDEBUG_IPC(
								0,
								"%s: resend %s to %s "
								"(lower=0x%x,upper=0x%x)\n",
								__FUNCTION__,
								rq_cmd_name(rq),
								SSI_NODE_NAME(
									rq->target_node),
								lower_status,
								upper_status);
							goto again;
						}

						/* Check for request completion
						 */
						if (rp && rp->command != 0) {
							KDEBUG_IPC(
								0,
								"DVS: %s: tx completed "
								"%s to %s (lower=0x%x,upper=0x%x) "
								"(rval=%ld)\n",
								__FUNCTION__,
								rq_cmd_name(rq),
								SSI_NODE_NAME(
									rq->target_node),
								lower_status,
								upper_status,
								((struct file_reply
									  *)(rp))
									->rval);
							completed = 1;
							goto cleanup;
						}

						/*
						 * Last resort. Resend request.
						 * Remote will drop this if the
						 * request is still in-progress.
						 */
						if ((loopcnt /
						     DVSIPC_MAX_TX_TICKS) > 4) {
							(void)atomic_cmpxchg(
								&tx_status->lower_status,
								lower_status,
								DVSIPC_TX_ORPHANED);
							DVS_TRACEL(
								"ipc_txRS", rq,
								loopcnt,
								rq->target_node,
								0, 0);
							KDEBUG_IPC(
								0,
								"DVS: %s: resend %s to %s "
								"(lower=0x%x,upper=0x%x)\n",
								__FUNCTION__,
								rq_cmd_name(rq),
								SSI_NODE_NAME(
									rq->target_node),
								lower_status,
								upper_status);
							goto again;
						}

						KDEBUG_IPC(
							0,
							"DVS: %s: waiting for %s for "
							"%s to %s (lower=0x%x,upper=0x%x), "
							"(rval=%ld)\n",
							__FUNCTION__,
							(upper_status < 0) ?
								"SEND_END" :
								"ACK",
							rq_cmd_name(rq),
							SSI_NODE_NAME(
								rq->target_node),
							lower_status,
							upper_status,
							rp ? ((struct file_reply
								       *)(rp))
									->rval :
							     -1);
					}
				}
				/*
				 * If the lower status wasn't 0, let's get out
				 * of this loop and resend.
				 */
			} else {
				down(&txp->sema);
			}
		} while (atomic_read(&tx_status->lower_status) == 0 &&
			 upper_api->node_state(rq->target_node) != NODE_DOWN);

		lower_status =
			atomic_cmpxchg(&tx_status->lower_status,
				       DVSIPC_TX_RESEND, DVSIPC_TX_ORPHANED);
		if (lower_status == DVSIPC_TX_RESEND) {
			DVS_TRACEL("ipc_txRs", rq, loopcnt, rq->target_node, 0,
				   0);
			KDEBUG_IPC(
				0,
				"DVS: %s: resend %s to %s (lower=0x%x,upper=0x%x)\n",
				__FUNCTION__, rq_cmd_name(rq),
				SSI_NODE_NAME(rq->target_node), lower_status,
				upper_status);
			forced_resend++;

			/*
			 * If the SEND_END hit, free the old message here since
			 * we know that the DVSIPC_RESEND_REQ was in lieu of an
			 * ACK.
			 */
			if (atomic_read(&tx_status->upper_status) > 0) {
				kfree_ssi(txp);
			}
			goto again;
		}

		/*
		 * Keep retrying until we get a successful transmit or we see
		 * that the target is down.
		 */
	} while (
		(atomic_read(&tx_status->lower_status) != DVSIPC_TX_COMPLETE) &&
		(++retries < resend_limit) &&
		upper_api->node_state(rq->target_node) == NODE_READY);

cleanup:
	if (MD_valid && (rval = LNetMDUnlink(mdh)) < 0) {
		DVS_LOGP("DVS: %s: LNetMDUnlink failed (%d)\n", __FUNCTION__,
			 rval);
		DVS_TRACE("ipc_txFu", rval, rq);
	}

	lower_status =
		atomic_cmpxchg(&tx_status->lower_status, 0, DVSIPC_TX_ORPHANED);

	/*
	 * Handle abnormal tx disposition.
	 */
	if (completed == 0 && lower_status != DVSIPC_TX_COMPLETE) {
		DVS_TRACEL("ipc_txHD", rq->target_node, rq,
			   rq->transport_handle, retries, 0);
		upper_status = atomic_read(&tx_status->upper_status);
		if (upper_api->node_state(rq->target_node) == NODE_READY) {
			DVS_TRACEL("ipc_txERR", rq->target_node, retries,
				   (uint64_t)lower_status,
				   (uint64_t)upper_status, 0);

			KDEBUG_IPC(
				0,
				"DVS: %s: tx of %s to %s failed (0x%x:0x%x) %s\n",
				__FUNCTION__, rq_cmd_name(rq),
				SSI_NODE_NAME(rq->target_node), lower_status,
				upper_status,
				retries >= resend_limit ?
					"(retry limit exceeded)" :
					upper_status >= DVSIPC_MAX_TX_TICKS ?
					"(unresponsive)" :
					terminated ? "(terminated)" : "");

			ret = -EIO;
		} else {
			DVS_TRACEL("ipc_txHD", rq->target_node,
				   (uint64_t)lower_status,
				   (uint64_t)upper_status,
				   upper_api->node_state(rq->target_node), 0);
			ret = -EHOSTDOWN;
		}
	}

	/* Discard buffer if lower half is done using it. */
	if (lower_status != 0) {
		kfree_ssi(txp);
	}

	/* Notifiy caller of tx disposition. */
	return ret;
}

/*
 * lnet_send_nak - send a NAK to a node from which a request was
 *                   dropped.
 */
static void lnet_send_nak(uint64_t nid, void *rq)
{
	int ret;
	lnet_process_id_t dest;
	lnet_handle_md_t mdh;
	lnet_handle_eq_t eq_handle;

	KDEBUG_IPC(0, "%s: nak to 0x%Lx\n", __FUNCTION__, nid);
	DVS_TRACE("tx_nak", nid, rq);

	lnet_invalidate_eq_handle(&eq_handle);

	if (lnet_bind_buf(NULL, 0, 1, 0, eq_handle, NULL, LNET_UNLINK, &mdh) <
	    0) {
		return;
	}

	DVS_TRACE("ipc_txN2", 0, 0);

	dest.nid = nid;
	dest.pid = IPC_LNET_PID;

	if ((ret = LNetPut(my_lnet_process_id.nid, mdh, LNET_NOACK_REQ, dest,
			   IPC_LNET_PORTAL, DVSIPC_NAK_MATCH, 0,
			   (uint64_t)rq)) < 0) {
		DVS_LOGP("DVS: %s: LNetPut failed (%d:0x%Lx)\n", __FUNCTION__,
			 ret, mdh.cookie);
		DVS_TRACE("ipc_Nfp", ret, 0);
	}

	return;
}

static void *lnet_mapkvm(char *kvm, ssize_t length, int rw)
{
	struct ipc_mapping *ipcmap = NULL;
	lnet_handle_me_t meh;
	lnet_handle_md_t mdh;
	lnet_handle_eq_t puthandle;
	lnet_md_t md;

	int ret = 0;
	int page_count = 0;
	int offset = 0;
	__u64 ignore_bits = 0;

	ignore_bits = ((__u64)1 << 63); /* keep them all on 1 chain */

	lnet_invalidate_md_handle(&mdh);

#ifdef WITH_LEGACY_CRAY
	if (rw == DVS_NEED_HANDLER) {
#else
	if (rw == READ || rw == DVS_NEED_HANDLER) {
#endif
		puthandle = lnet_rma_io_eq;
	} else {
		puthandle.cookie = LNET_WIRE_HANDLE_COOKIE_NONE;
	}

	/*
	 * Passing in DVS_NEED_HANDLER signifies that this mapping requires a
	 * put handler which is used by the read page code. Revert the
	 * DVS_NEED_HANDLER flag to a READ
	 * now that we've added the handler.\
	 */
	if (rw == DVS_NEED_HANDLER)
		rw = READ;

	/*
	 * Note that kvm here is really the address of a kernel buffer which
	 * could be non-page aligned.   Account for that when determining how
	 * many pages this whole deal is and use that page count when unmapping.
	 */
	offset = (uint64_t)kvm & (PAGE_SIZE - 1);
	page_count = (offset + length + (PAGE_SIZE - 1)) / PAGE_SIZE;

	/* Allocate icpmap with space for page mappings and iovec pointer */
	ipcmap = kmalloc_ssi(sizeof(struct ipc_mapping) + sizeof(void *),
			     GFP_KERNEL);

	if (ipcmap == NULL) {
		DVS_LOGP("DVS: %s: failed to allocate ipcmap buffer\n",
			 __func__);
		goto cleanup;
	}

	ipcmap->addr = kvm;
	ipcmap->length = length;
	ipcmap->page_count = page_count;
	ipcmap->rw = rw;
	ipcmap->read_handler = NULL;
	ipcmap->dma_length = 0;
	ipcmap->dma[0] = 0;
	ipcmap->dma[1] = (uint64_t)kvm;

	if ((ret = LNetMEAttach(IPC_LNET_PORTAL,
				(lnet_process_id_t){ .nid = LNET_NID_ANY,
						     .pid = LNET_PID_ANY },
				(__u64)ipcmap, ignore_bits, LNET_UNLINK,
				LNET_INS_BEFORE, &meh)) < 0) {
		DVS_LOGP("DVS: %s: LNetMEAttach failed (%d)\n", __func__, ret);
		goto cleanup;
	}

	/*
	 * Clear it to start since there are flags/etc in there and over
	 * time with different Lustre releases things are added.
	 */
	memset(&md, 0, sizeof(lnet_md_t));
	md.start = kvm;
	md.length = length;
	md.user_ptr = (void *)ipcmap;
	md.eq_handle = puthandle;
	md.options = LNET_MD_OP_PUT | LNET_MD_OP_GET | LNET_MD_MANAGE_REMOTE;
	md.threshold = LNET_MD_THRESH_INF;
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 52, 0)
	lnet_invalidate_md_handle(&md.bulk_handle);
#endif

	DVS_TRACEL("lnetmkvm", kvm, offset, kvm, length, 0);
	if ((ret = LNetMDAttach(meh, md, LNET_UNLINK, &mdh)) < 0) {
		DVS_LOGP("DVS: %s: LNetMDAttach failed (%d) length=0x%lx, "
			 "options=0x%x\n",
			 __func__, ret, length,
			 LNET_MD_OP_PUT | LNET_MD_OP_GET | LNET_MD_PHYS |
				 LNET_MD_IOVEC | LNET_MD_MANAGE_REMOTE);
		LNetMEUnlink(meh);
		goto cleanup;
	}

	/* store handle for manual unlink */
	ipcmap->dma[0] = (u64)meh.cookie;

	KDEBUG_IPC(0, "%s: OUT: 0x%p 0x%p %Ld %d 0x%Lx 0x%Lx\n", __func__, kvm,
		   ipcmap, (__u64)length, page_count, meh.cookie, mdh.cookie);

	return ipcmap;

cleanup:
	if (ipcmap) {
		kfree_ssi(ipcmap);
	}

	/* Pass error codes back up to the caller. */
	if (ret < 0)
		return ERR_PTR(ret);

	return NULL;
}

static int lnet_unmapkvm(void *handle)
{
	struct ipc_mapping *ipcmap = (struct ipc_mapping *)handle;
	lnet_handle_me_t meh;
	int ret;

	meh.cookie = (u64)ipcmap->dma[0];

	DVS_TRACEL("lnet_ukm", handle, meh.cookie, ipcmap->length,
		   (void *)ipcmap->dma[1], 0);

	KDEBUG_IPC(0, "%s: Unlinking handles 0x%Lx\n", __func__, meh.cookie);

	if ((ret = LNetMEUnlink(meh))) {
		DVS_LOGP("DVS: %s: unlink failed (%d)\n", __func__, ret);
		DVS_TRACE("lnet_ukE", meh.cookie, ret);
	}

	kfree_ssi(ipcmap);

	return 0;
}

static void *lnet_mapuvm(char *uvm, ssize_t length, int rw)
{
	struct ipc_mapping *ipcmap = NULL;
	lnet_handle_me_t meh;
	lnet_handle_md_t mdh;
	lnet_handle_eq_t puthandle;
	lnet_md_t md;
	int ret = 0;
	int i;

	void *vmap_addr = NULL;
	struct page **pages = NULL;
	int page_count = 0;
	int offset = 0;
	__u64 ignore_bits = 0;

	ignore_bits = ((__u64)1 << 63); /* keep them all on 1 chain */

	lnet_invalidate_md_handle(&mdh);

	/*
	 * Note that uvm here is really the address of the user's buffer which
	 * could be non-page aligned.   Account for that when determining how
	 * many pages this whole deal is and use that page count when unmapping.
	 *
	 * Keep track of the offset into the page since we'll need to apply that
	 * same offset to the actual page address returned from the vmap call so
	 * that the I/O matches up.
	 */
	offset = (uint64_t)uvm & (PAGE_SIZE - 1);

#ifdef CONFIG_CRAY_SEASTAR
	/*
	 * For seastar/ptllnd, we need to make sure that the start of
	 * the buffer is aligned properly or we could run into issues
	 * when lnet prepends its header
	 */
	if (offset & 0x3) {
		KDEBUG_IPC(0, "%s: Unaligned memory 0x%p:0x%lx\n", __FUNCTION__,
			   uvm, length);
		DVS_TRACEL("lnmuvmcp", uvm, length, rw, offset, 0);
		vmap_addr = vmalloc_ssi(length);
		if (vmap_addr == NULL) {
			DVS_TRACEL("lnmuvmE", uvm, length, rw, offset, 0);
			return NULL;
		}
		offset = 0;
		if (copy_from_user(vmap_addr, uvm, length)) {
			DVS_TRACEL("lnmuvmE1", uvm, length, rw, offset, 0);
			vfree_ssi(vmap_addr);
			return NULL;
		}
	} else
#endif
	{
		page_count = (offset + length + (PAGE_SIZE - 1)) / PAGE_SIZE;

		pages = (struct page **)vmalloc_ssi(page_count *
						    sizeof(struct page *));
		if (pages == NULL) {
			DVS_TRACE("lnmuvm!a", uvm, (uint64_t)page_count);
			DVS_LOGP("DVS: %s: can't allocate pages struct "
				 "(count = %d)\n",
				 __func__, page_count);
			goto cleanup;
		}

		down_read(&current->mm->mmap_sem);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 73)
		ret = get_user_pages(current, current->mm, (unsigned long)uvm,
				     page_count, rw == READ, 0, pages, NULL);
#else
		ret = get_user_pages((unsigned long)uvm, page_count,
				     (rw == READ ? FOLL_WRITE : 0), pages,
				     NULL);
#endif

		up_read(&current->mm->mmap_sem);

		if (page_count != ret) {
			DVS_TRACEL("lnmuvm!p", uvm, (uint64_t)ret,
				   (uint64_t)page_count, 0, 0);
			KDEBUG_IPC(
				0,
				"DVS: %s: page count mismatch on user buffer (%d:%d)\n",
				__func__, page_count, ret);
			page_count = ret;
			goto cleanup;
		}

		vmap_addr = vmap(pages, page_count, VM_MAP, PAGE_KERNEL);
		if (vmap_addr == NULL) {
			printk(KERN_ERR "DVS: %s: failed to vmap user pages\n",
			       __func__);
			goto cleanup;
		}

		KDEBUG_IPC(0, "%s: 0x%p 0x%p 0x%lx 0x%x\n", __func__, uvm,
			   vmap_addr, length, rw);
	}

	/* Allocate ipcmap with space for page mappings and iovec pointer */
	ipcmap = kmalloc_ssi(sizeof(struct ipc_mapping) + sizeof(void *),
			     GFP_KERNEL);

	if (ipcmap == NULL) {
		DVS_LOGP("DVS: %s: failed to allocate ipcmap buffer\n",
			 __func__);
		goto cleanup;
	}

	ipcmap->addr = uvm;
	ipcmap->length = length;
	ipcmap->pages = pages;
	ipcmap->page_count = page_count;
	ipcmap->rw = rw;
	ipcmap->read_handler = NULL;
	ipcmap->dma_length = 0;
	ipcmap->dma[0] = 0;
	ipcmap->dma[1] = (uint64_t)vmap_addr;

	if ((ret = LNetMEAttach(IPC_LNET_PORTAL,
				(lnet_process_id_t){ .nid = LNET_NID_ANY,
						     .pid = LNET_PID_ANY },
				(__u64)ipcmap, ignore_bits, LNET_UNLINK,
				LNET_INS_BEFORE, &meh)) < 0) {
		DVS_LOGP("DVS: lnet_mapuvm: LNetMEAttach failed (%d)\n", ret);
		goto cleanup;
	}

#ifndef WITH_LEGACY_CRAY
	if (rw == READ)
		puthandle = lnet_rma_io_eq;
	else
		puthandle.cookie = LNET_WIRE_HANDLE_COOKIE_NONE;
#else
	puthandle.cookie = LNET_WIRE_HANDLE_COOKIE_NONE;
#endif

	/*
	 * Clear it to start since there are flags/etc in there and over
	 * time with different Lustre releases things are added.
	 */
	memset(&md, 0, sizeof(lnet_md_t));
	md.start = vmap_addr + offset;
	md.length = length;
	md.user_ptr = (void *)ipcmap;
	md.eq_handle = puthandle;
	md.options = LNET_MD_OP_PUT | LNET_MD_OP_GET | LNET_MD_MANAGE_REMOTE;
	md.threshold = LNET_MD_THRESH_INF;
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 52, 0)
	lnet_invalidate_md_handle(&md.bulk_handle);
#endif

	DVS_TRACEL("lnetmuvm", vmap_addr, offset, uvm, length, 0);
	if ((ret = LNetMDAttach(meh, md, LNET_UNLINK, &mdh)) < 0) {
		DVS_LOGP(
			"DVS: %s: LNetMDAttach failed (%d) length=0x%lx, options=0x%x\n",
			__FUNCTION__, ret, length,
			LNET_MD_OP_PUT | LNET_MD_OP_GET | LNET_MD_PHYS |
				LNET_MD_IOVEC | LNET_MD_MANAGE_REMOTE);
		LNetMEUnlink(meh);
		goto cleanup;
	}

	/* store handle for manual unlink */
	ipcmap->dma[0] = (u64)meh.cookie;

	KDEBUG_IPC(0, "lnet_mapuvm OUT: 0x%p 0x%p %Ld %d 0x%Lx 0x%Lx\n", uvm,
		   ipcmap, (__u64)length, page_count, meh.cookie, mdh.cookie);

	return ipcmap;

cleanup:
#ifdef CONFIG_CRAY_SEASTAR
	vfree_ssi(vmap_addr);
#else
	if (vmap_addr)
		vunmap(vmap_addr);

	if (pages) {
		for (i = 0; i < page_count; i++) {
			if (rw == READ) {
				set_page_dirty_lock(pages[i]);
			}
			put_page(pages[i]);
		}
		vfree_ssi(pages);
	}
#endif

	kfree_ssi(ipcmap);

	/* Pass error codes back up to the caller. */
	if (ret < 0) {
		return (ERR_PTR(ret));
	}

	return NULL;
}

static int lnet_unmapuvm(void *handle)
{
	struct ipc_mapping *ipcmap = (struct ipc_mapping *)handle;
	lnet_handle_me_t meh;
	int i;
	int ret;
	void *vmap_addr = (void *)ipcmap->dma[1];

	meh.cookie = (u64)ipcmap->dma[0];

	DVS_TRACEL("lnet_um", handle, meh.cookie, ipcmap->length, vmap_addr, 0);

	KDEBUG_IPC(0, "lnet_unmapuvm: Unlinking handles 0x%Lx\n", meh.cookie);

	if ((ret = LNetMEUnlink(meh))) {
		DVS_LOGP("DVS: %s: unlink failed (%d)\n", __func__, ret);
		DVS_TRACE("lnet_umE", meh.cookie, ret);
	}

#ifdef CONFIG_CRAY_SEASTAR
	vfree_ssi(vmap_addr);
#else
	vunmap(vmap_addr);

	if (ipcmap->pages != NULL) {
		for (i = 0; i < ipcmap->page_count; i++) {
			if (ipcmap->rw == READ) {
				set_page_dirty_lock(ipcmap->pages[i]);
			}
			put_page(ipcmap->pages[i]);
		}

		vfree_ssi(ipcmap->pages);
	}
#endif

	kfree_ssi(ipcmap);

	return 0;
}

static void expire_rma_request(unsigned long arg)
{
	lnet_rma_info_t *ri = (lnet_rma_info_t *)arg;
	ri->retval = -ETIME;
	up(&ri->sema);
}

/* Wait for an RMA operation to complete  */
static void wait_for_rma(lnet_rma_info_t *ri, int timeout)
{
	/* Wait for the transmit to complete.*/
	down(&ri->sema);

	/*
	 * For GET operations, we wait for the response
	 * from the target. Since we don't know the state
	 * the return connection, it is possible that the response
	 * could be dropped due to transport-level issues.
	 * For this reason, we set a timer to expire if
	 * no response is received in a reasonable window.
	 *
	 * Note: When the lnet_notify callback infrastructure
	 *       is in place, we should get notification on
	 *       connection breaks and trigger retransmission
	 *       if applicable.
	 */
	if (ri->rma_type == RMA_GET) {
		struct timer_list timer;
		if (timeout > 0) {
			unsigned long expire;

			expire = jiffies + (timeout * HZ);
			setup_timer_on_stack(&timer, expire_rma_request,
					     (unsigned long)ri);
			mod_timer(&timer, expire);
		}
		down(&ri->sema);
		if (timeout > 0) {
			del_singleshot_timer_sync(&timer);
		}
	}
}

/*
 * Wait for all pieces of an in-flight RMA to complete. Save result
 * in rma_info structure for subsequent handling.
 */
void lnet_rma_wait(rma_info_t *rip)
{
	int ntx = (rip->length + LNET_MAX_PAYLOAD - 1) / LNET_MAX_PAYLOAD;
	lnet_rma_info_t *lrip = rip->transport_handle;
	int i;

	DVS_TRACE("lnrmaw", ntx, rip);
	for (i = 0; i < ntx; i++) {
		DVS_TRACE("lnrmawB", ntx, i);
		wait_for_rma(lrip, -1);
		DVS_TRACEL("lnrmawA", ntx, i, lrip->retval, 0, 0);
		LNetMDUnlink(lrip->mdh);
		if (rip->retval < 0 || lrip->retval < 0) {
			rip->retval = -EIO;
		} else {
			rip->retval += lrip->retval;
		}
		lrip++;
	}
	kfree_ssi(rip->transport_handle);
	DVS_TRACE("lnrmaR", rip->retval, 0);
}

/*
 * Service a remote memory access request to/from a remote node.
 */
static void *lnet_rma(uint64_t node, char *to, char *from, ssize_t length,
		      rma_info_t *ri, int timeout, int async)
{
	lnet_process_id_t dest;
	struct rma_state *rmasp = (struct rma_state *)ri->handle;
	__u64 match = (__u64)rmasp->handle;
	ssize_t total_length;
	lnet_rma_info_t *lri, *rip;
	int ntx = (length + LNET_MAX_PAYLOAD - 1) / LNET_MAX_PAYLOAD;
	int ret = 0, i;
	int cleanup = 0;

	lri = (void *)kmalloc_ssi(sizeof(*lri) * ntx, GFP_KERNEL);
	if (lri == NULL) {
		DVS_LOG("DVS: %s: failed to allocate lnet_rma_info\n",
			__FUNCTION__);
		DVS_TRACE("lnet_rmaX", ntx, 0);
		return ERR_PTR(-ENOMEM);
	}

	ri->transport_handle = lri;

	KDEBUG_IPC(0, "DVS: %s (0x%Lx:0x%p:0x%p:0x%lx:0x%p:0x%p:%d)\n",
		   __FUNCTION__, node, to, from, length, rmasp, rmasp->handle,
		   async);

	/* Initialize RMA state structure */
	if (ri->rma_type == RMA_GET) {
		ri->handle = (uint64_t)match;
	}

	dest.nid = node;
	dest.pid = IPC_LNET_PID;

	DVS_TRACEL("lnet_rma", to, from, length, node, 0);

	/*
	 * Break up the RMA operation if necessary. LNet limits valid
	 * PUT operation to a maximum size of LNET_MAX_PAYLOAD.
	 */
	total_length = 0;
	for (i = 0; i < ntx; i++) {
		ssize_t txlen;

		rip = &lri[i];
		rip->retval = 0;
		rip->rma_type = ri->rma_type;
		lnet_invalidate_md_handle(&rip->mdh);
		rip->length = txlen = MIN(length, LNET_MAX_PAYLOAD);
		rip->lnode = rmasp->node;

		sema_init(&rip->sema, 0);

		KDEBUG_IPC(0, "DVS: %s: bind chunk %d, len=0x%lx\n",
			   __FUNCTION__, i, txlen);

		if ((ret = lnet_bind_buf((rip->rma_type == RMA_PUT) ? from : to,
					 txlen, 2, 0, lnet_rma_eq, (void *)rip,
					 LNET_RETAIN, &rip->mdh)) < 0) {
			printk(KERN_ERR "DVS: %s: lnet_bind_buf failed (%d)\n",
			       __FUNCTION__, ret);
			DVS_TRACEL("rmaRPF", node, from, to, txlen, 0);
			ntx = i;
			cleanup = 1;
			ret = -ENXIO;
			break;
		}

		KDEBUG_IPC(
			0,
			"DVS: %s: %s to match=0x%llx on 0x%Lx (0x%p,0x%p,0x%x,0x%lx)\n",
			__FUNCTION__,
			(ri->rma_type == RMA_PUT) ? "RMA_PUT" : "RMA_GET",
			match, dest.nid, to, rmasp->remote_addr,
			(unsigned int)(to - rmasp->remote_addr), txlen);
		KDEBUG_IPC(0, "DVS: %s: send chunk %d, len=%ld\n", __FUNCTION__,
			   i, txlen);

		if (ri->rma_type == RMA_PUT) {
			ret = LNetPut(my_lnet_process_id.nid, rip->mdh,
				      LNET_NOACK_REQ, dest, IPC_LNET_PORTAL,
				      match,
				      (unsigned int)(to - rmasp->remote_addr),
				      0);
		} else {
			ret = LNetGet(
				my_lnet_process_id.nid, rip->mdh, dest,
				IPC_LNET_PORTAL, match,
				(unsigned int)(from - rmasp->remote_addr));
		}

		if (ret < 0) {
			DVS_LOGP("DVS: %s: transfer failed (%d)\n",
				 __FUNCTION__, ret);
			LNetMDUnlink(rip->mdh);
			ntx = i;
			cleanup = 1;
			ret = -EIO;
			break;
		}

		length -= txlen;
		total_length += txlen;
		from += txlen;
		to += txlen;
	}

	if (async == 0) {
		ret = 0;
		for (i = 0; i < ntx; i++) {
			rip = &lri[i];

			KDEBUG_IPC(
				0,
				"%s: tx (0x%Lx) scheduled, waiting on 0x%p\n",
				__FUNCTION__, match, &rip->sema);

			wait_for_rma(rip, timeout);

			KDEBUG_IPC(0, "%s: transfer of 0x%p complete\n",
				   __FUNCTION__, to);

			LNetMDUnlink(rip->mdh);
			lnet_invalidate_md_handle(&rip->mdh);

			if (rip->retval < 0) {
				printk(KERN_ERR
				       "DVS: %s: RMA length %lu to match=0x%llx on %Ld "
				       "off 0x%p failed (%d)\n",
				       __func__, (unsigned long)rip->length,
				       match, dest.nid,
				       (char *)(to - rmasp->remote_addr),
				       rip->retval);
				DVS_TRACEL("rmartry", node, rip, rip->retval, 0,
					   0);

				if (upper_api->node_state(rip->lnode) !=
				    NODE_READY) {
					DVS_TRACE("rmaE", rip->retval, 0);
					ret = -EHOSTDOWN;
				} else {
					ret = rip->retval;
				}

				cleanup = 1;
			}
		}
	} else if (ret >= 0) {
		return NULL;
	}

	KDEBUG_IPC(0, "DVS: %s: rma complete ret=%d\n", __FUNCTION__, ret);

	if (cleanup)
		goto error;
	kfree_ssi(lri);
	return (void *)total_length;

error:
	KDEBUG_IPC(0, "DVS: %s: rma complete ret=%d\n", __FUNCTION__, ret);
	for (i = 0; i < ntx; i++) {
#if DVS_LNET_VERSION >= LNET_VERSION_CODE(2, 9, 54, 0)
		if (!LNetMDHandleIsInvalid(lri[i].mdh)) {
#else
		if (!LNetHandleIsInvalid(lri[i].mdh)) {
#endif
			LNetMDUnlink(lri[i].mdh);
		}
	}
	kfree_ssi(lri);
	return ERR_PTR(ret);
}

static int lnet_fill_rx_slot(int slot, rx_buf_info_t *bip, int size,
			     unsigned int seq, int invalidate_old)
{
	int ret = 0;
	lnet_md_t md;
	int bstate;

	DVS_TRACEL("lnetfill", slot, seq, size, bip, invalidate_old);

	if (bip == NULL) {
		DVS_TRACEL("lnetflBN", slot, seq, size, bip, invalidate_old);
		return -ENOSPC;
	}

	if (unlikely(!lnet_rx_m_table[slot].me_handle.cookie)) {
		/* Map it for the first time */
		if ((ret = LNetMEAttach(
			     IPC_LNET_PORTAL,
			     (lnet_process_id_t){ .nid = LNET_NID_ANY,
						  .pid = LNET_PID_ANY },
			     DVSIPC_LNET_MATCH_SLOT(slot),
			     DVSIPC_LNET_IGNORE_SLOT(slot), LNET_RETAIN,
			     LNET_INS_BEFORE,
			     &lnet_rx_m_table[slot].me_handle)) < 0) {
			DVS_TRACEL("lnetMEA!", slot, seq, bip, ret,
				   invalidate_old);
			DVS_LOGP("DVS: %s: LNetMEAttach failed slot %d (%d)\n",
				 __func__, slot, ret);
			goto errout;
		}
	}

	if ((ret = lnet_build_rx_md(bip, size, slot, &md, seq))) {
		DVS_TRACEL("lnetflB!", slot, seq, size, bip, ret);
		printk(KERN_ERR
		       "DVS: %s: lnet_build_rx_md failed slot %d (%d)\n",
		       __func__, slot, ret);
		KDEBUG_IPC(0, "DVS: %s: build rx MD failed ret=%d\n", __func__,
			   ret);
		ret = -EIO;
		goto errout;
	}

	/*
	 * Check to see if the upper layers want this slot invalidated.  This
	 * would be because there were errors that didn't make sense.  We'll
	 * unlink whatever MD is attached to the ME in that case based on what
	 * should be the MD handle for it.  Obviously this is last resort to
	 * keep the slot viable.
	 */
	if (invalidate_old) {
		DVS_TRACE("lnetMDIn", slot,
			  lnet_rx_m_table[slot].md_handle.cookie);
		KDEBUG_IPC(0,
			   "DVS: %s: build MD force unlink slot %d mdh=%llx\n",
			   __func__, slot,
			   lnet_rx_m_table[slot].md_handle.cookie);
		ret = LNetMDUnlink(lnet_rx_m_table[slot].md_handle);
		if (ret) {
			DVS_TRACE("lnetMDI!", slot, ret);
			DVS_LOGP(
				"DVS: %s: LNetMDUnlink failed slot %d MD %llx (%d)\n",
				__func__, slot, lnet_rx_m_table[slot].md_handle,
				ret);
			printk(KERN_ERR
			       "DVS: %s: forced LNetMDUnlink failed with %d\n",
			       __func__, ret);
		}
	}

	/*
	 * OK, let's give the new buffer to LNet.  It's in it's initial state at
	 * the moment and it's reference count is zero.  We need to place an
	 * additional reference on it now (vs. after LNetMDAttach for the
	 * reference LNet has on it being linked) otherwise if a message slipped
	 * in before we could set it, the free routine would immediately free
	 * it.
	 *
	 * Same issue with the sequence number.  Update the table first since we
	 * know the slot is empty since we're here and nobody should call us
	 * back with the previous sequence number.
	 */
	lnet_rx_m_table[slot].md_seq = seq;
	atomic_inc(&bip->rxbuf_refcount);
	bstate = atomic_cmpxchg(&bip->rxbuf_state, RXBUF_FreelistUnchained,
				RXBUF_NetworkLinked);

	if ((ret = LNetMDAttach(lnet_rx_m_table[slot].me_handle, md,
				LNET_UNLINK,
				&lnet_rx_m_table[slot].md_handle)) < 0) {
		atomic_dec(&bip->rxbuf_refcount);
		atomic_set(&bip->rxbuf_state, RXBUF_FreelistUnchained);
		lnet_rx_m_table[slot].md_seq = -1; // anything to show it's not
						   // valid
		DVS_TRACEL("lnetMDA!", slot, seq, bip, ret, 0);
		DVS_LOGP(
			"DVS: %s: LNetMDAttach (0x%p) failed slot %d seq %d (%d)\n",
			__func__, bip, slot, seq, ret);
		KDEBUG_IPC(0, "DVS: %s: attach rx MD failed ret=%d\n", __func__,
			   ret);
		goto errout;
	}

	if (unlikely(bstate != RXBUF_FreelistUnchained)) {
		printk(KERN_EMERG "RX buffer in invalid state %d !!\n", bstate);
		BUG();
	}

	return ret;

errout:
	DVS_TRACEL("lnetfilE", slot, seq, size, bip, ret);

	return ret;
}

/*
 * lnet_str2phys - Translate the node identifier string to a physical
 *                 transport ID.
 */
uint64_t lnet_str2phys(char *tok)
{
	KDEBUG_IPC(0, "%s: %s\n", __FUNCTION__, tok);
	if (strchr(tok, '@')) {
		lnet_nid_t lnet_nid = libcfs_str2nid(tok);
		if (lnet_nid == LNET_NID_ANY) {
			return DVSIPC_INVALID_NODE;
		} else {
			return (uint64_t)lnet_nid;
		}
	} else {
		return (uint64_t)nid2lnetnid(simple_strtol(tok, NULL, 10));
	}
}

/*
 * dvs_lnet_init - Initialize a lnet network interface for use by dvs/ipc.
 *
 * This routine is called by the dvs ipc initialization routine to
 * setup the lnet network interface. To do this, a number of receive
 * buffers are posted for use for inbound message traffic. A receive thread
 * is created to monitor and manage this inbound traffic. In addition,
 * transmit event queue is initialized for use in the management of outbound
 * message traffic.
 */
static int lnet_is_initialized = 0;
static int dvs_lnet_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper,
			 ssize_t *max_msg_size, int num_mds)
{
	lnet_process_id_t id = { 0 };
	int ret, n = 0;

	KDEBUG_IPC(0, "%s: LNetNIInit \n", __FUNCTION__);

	/* validate supplied lnd name */
	if ((strncmp(lnd_name, "ptl", 3) != 0) &&
	    (strncmp(lnd_name, "gni", 3) != 0) &&
	    (strncmp(lnd_name, "tcp", 3) != 0) &&
	    (strncmp(lnd_name, "gni_ip", 6) != 0)) {
		printk(KERN_ERR "DVS: %s: unsupported lnd specified: %s\n",
		       __FUNCTION__, lnd_name);
		return -EINVAL;
	}

	upper_api = upper;
	ipc_num_mds = num_mds;
	*max_msg_size = LNET_MAX_PAYLOAD;
	max_transport_msg_pages = *max_msg_size >> PAGE_SHIFT;

	/* # dirty pages before writeback - 8Mb */
	wb_threshold_pages = max_transport_msg_pages * 8;

	if ((ret = LNetNIInit(IPC_LNET_PID)) < 0) {
		DVS_LOGP("DVS: %s: LNetNIInit failed (%d)\n", __FUNCTION__,
			 ret);
		return -EINVAL;
	}

	/*
	 * Search through the configured lnds to find the correct network id.
	 */
	while ((ret = LNetGetId(n++, &id)) != -ENOENT) {
		char *lndp;
		lndp = strchr(libcfs_nid2str(id.nid), '@');
		if (lndp) {
			lndp++;
			if (strncmp(lndp, lnd_name, strlen(lndp)) == 0) {
				KDEBUG_IPC(0, "%s: found %s\n", __FUNCTION__,
					   libcfs_nid2str(id.nid));
				break;
			}
		}
		KDEBUG_IPC(0, "%s: %s !match\n", __FUNCTION__,
			   libcfs_nid2str(id.nid));
	}

	if (ret == -ENOENT) {
		DVS_LOGP(
			"DVS: %s: No network ID found on configured lnd (%s)\n",
			__FUNCTION__, lnd_name);
		(void)LNetNIFini();
		return -ENOENT;
	}

	KDEBUG_IPC(0, "%s: my process id %s (0x%Lx)\n", __FUNCTION__,
		   libcfs_nid2str(id.nid), id.nid);

	*nodeidp = id.nid;

	my_lnet_process_id = id;

	if ((ret = LNetEQAlloc(DVSIPC_TX_EVENTQ_LEN, &lnet_tx_callback,
			       &lnet_tx_eq)) < 0) {
		DVS_LOGP("DVS: %s: LNetEQAlloc(tx) failed (%d)\n", __FUNCTION__,
			 ret);
		(void)LNetNIFini();
		return -ENOSPC;
	}

	if ((ret = LNetEQAlloc(DVSIPC_RX_EVENTQ_LEN, &lnet_rx_callback,
			       &lnet_rx_eq)) < 0) {
		DVS_LOGP("DVS: %s: LNetEQAlloc(rx) failed (%d)\n", __FUNCTION__,
			 ret);
		(void)LNetEQFree(lnet_tx_eq);
		(void)LNetNIFini();
		return -ENOSPC;
	}

	if ((ret = LNetEQAlloc(DVSIPC_RMA_EVENTQ_LEN, &lnet_rma_callback,
			       &lnet_rma_eq)) < 0) {
		DVS_LOGP("DVS: %s: LNetEQAlloc(rma) failed (%d)\n",
			 __FUNCTION__, ret);
		(void)LNetEQFree(lnet_rx_eq);
		(void)LNetEQFree(lnet_tx_eq);
		(void)LNetNIFini();
		return -ENOSPC;
	}

	/* Used on the clients for RMA Put notifications */
	if ((ret = LNetEQAlloc(DVSIPC_RMAPUT_EVENTQ_LEN, &lnet_rma_io_callback,
			       &lnet_rma_io_eq)) < 0) {
		DVS_LOGP("DVS: %s: LNetEQAlloc(rmaput) failed (%d)\n",
			 __FUNCTION__, ret);
		(void)LNetEQFree(lnet_rma_eq);
		(void)LNetEQFree(lnet_rx_eq);
		(void)LNetEQFree(lnet_tx_eq);
		(void)LNetNIFini();
		return -ENOSPC;
	}

	LNetSetLazyPortal(IPC_LNET_PORTAL);

	/*
	 * Add a backstop ME. This ME will catch all inbound requests that
	 * got past all of the other receive buffers. In this case we need
	 * to notify the originator that their request was dropped on the
	 * floor.
	 */
	if ((ret = lnet_build_backstop_me(&lnet_rx_me_guard,
					  DVSIPC_RX_MATCHBITS,
					  DVSIPC_LNET_IGNORE_LOWBITS,
					  (void *)DVSIPC_OVERFLOW_TAG)) < 0) {
		printk(KERN_ERR
		       "DVS: %s: lnet_build_backstop_me(guard) failed (%d)\n",
		       __FUNCTION__, ret);
		(void)LNetClearLazyPortal(IPC_LNET_PORTAL);
		(void)LNetEQFree(lnet_rma_io_eq);
		(void)LNetEQFree(lnet_rma_eq);
		(void)LNetEQFree(lnet_rx_eq);
		(void)LNetEQFree(lnet_tx_eq);
		(void)LNetNIFini();
		return -ENOSPC;
	}

	KDEBUG_IPC(0, "%s: backstop create complete %s\n", __FUNCTION__,
		   libcfs_nid2str(id.nid));

	/*
	 * Add a resend request ME.
	 */
	if ((ret = lnet_build_backstop_me(&lnet_rx_me_resend, DVSIPC_NAK_MATCH,
					  DVSIPC_IGNORE_ONE,
					  (void *)DVSIPC_RESEND_REQ)) < 0) {
		printk(KERN_ERR
		       "DVS: %s: lnet_build_backstop_me(resend) failed (%d)\n",
		       __FUNCTION__, ret);
		(void)LNetClearLazyPortal(IPC_LNET_PORTAL);
		(void)LNetMEUnlink(lnet_rx_me_guard);
		(void)LNetEQFree(lnet_rma_io_eq);
		(void)LNetEQFree(lnet_rma_eq);
		(void)LNetEQFree(lnet_rx_eq);
		(void)LNetEQFree(lnet_tx_eq);
		(void)LNetNIFini();
		return -ENOSPC;
	}

	KDEBUG_IPC(0, "%s: resend create complete %s\n", __FUNCTION__,
		   libcfs_nid2str(id.nid));

	/*
	 * Add an orphan request ME. This ME/MD will be used as a backstop for
	 * RMA operations from this node. If a mapped region is removed before
	 * the server can service the request, this MD will catch the RMA
	 * operation and provide an appropriate response.
	 */
	if ((ret = lnet_build_backstop_me(&lnet_rx_me_orphan, DVSIPC_ORPH_MATCH,
					  DVSIPC_IGNORE_ALL,
					  (void *)DVSIPC_ORPH_REQ)) < 0) {
		printk(KERN_ERR
		       "DVS: %s: lnet_build_backstop_me(orph) failed (%d)\n",
		       __FUNCTION__, ret);
		(void)LNetClearLazyPortal(IPC_LNET_PORTAL);
		(void)LNetMEUnlink(lnet_rx_me_resend);
		(void)LNetMEUnlink(lnet_rx_me_guard);
		(void)LNetEQFree(lnet_rma_io_eq);
		(void)LNetEQFree(lnet_rma_eq);
		(void)LNetEQFree(lnet_rx_eq);
		(void)LNetEQFree(lnet_tx_eq);
		(void)LNetNIFini();
		return -ENOSPC;
	}

#ifdef CONFIG_SYSCTL
	lnet_sysctl_table = register_sysctl_table(root_table);
#endif

	KDEBUG_IPC(0, "%s: orph create complete %s\n", __FUNCTION__,
		   libcfs_nid2str(id.nid));

	DVS_TRACE("lninitok", 0, 0);

	lnet_is_initialized = 1;

	return 0;
}

/*
 * lnet_term - Shutdown the lnet interface.
 *
 */
static void lnet_term(void)
{
	int slot = DVSIPC_MAX_RX_MDS;

	if (!lnet_is_initialized) {
		DVS_TRACE("lnt!init", 0, 0);
		return;
	}

#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(lnet_sysctl_table);
#endif

	LNetClearLazyPortal(IPC_LNET_PORTAL);

	while (--slot >= 0) {
		if (lnet_rx_m_table[slot].me_handle.cookie != 0) {
			LNetMEUnlink(lnet_rx_m_table[slot].me_handle);
		}
	}

	LNetMEUnlink(lnet_rx_me_guard);
	LNetMEUnlink(lnet_rx_me_resend);
	LNetMEUnlink(lnet_rx_me_orphan);

	LNetEQFree(lnet_rma_io_eq);
	LNetEQFree(lnet_rma_eq);
	LNetEQFree(lnet_tx_eq);
	LNetEQFree(lnet_rx_eq);

	(void)LNetNIFini();

	DVS_TRACE("lnterm", 0, 0);
}

/*
 * Export lower interface.
 */

void ipclower_send_nak(uint64_t nid, void *rqp)
{
	lnet_send_nak(nid, rqp);
}

int ipclower_tx_request(uint64_t nid, struct usiipc *rq, int resend_limit,
			int tx_timeout)
{
	return lnet_tx_request(nid, rq, resend_limit, tx_timeout);
}

void *ipclower_mapkvm(char *kvm, ssize_t length, int rw)
{
	return lnet_mapkvm(kvm, length, rw);
}

int ipclower_unmapkvm(void *handle)
{
	return lnet_unmapkvm(handle);
}

void *ipclower_mapuvm(char *uvm, ssize_t length, int rw)
{
	return lnet_mapuvm(uvm, length, rw);
}

int ipclower_unmapuvm(void *handle)
{
	return lnet_unmapuvm(handle);
}

void *ipclower_rma_put(uint64_t node, char *to, char *from, ssize_t length,
		       rma_info_t *ri, int timeout, int async)
{
	return lnet_rma(node, to, from, length, ri, timeout, async);
}

void *ipclower_rma_get(uint64_t node, char *to, char *from, ssize_t length,
		       rma_info_t *ri, int timeout, int async)
{
	return lnet_rma(node, to, from, length, ri, timeout, async);
}

void ipclower_rma_wait(rma_info_t *rip)
{
	lnet_rma_wait(rip);
}

int ipclower_fill_rx_slot(int slot, rx_buf_info_t *bip, int size,
			  unsigned int seq, int invalidate_old)
{
	return lnet_fill_rx_slot(slot, bip, size, seq, invalidate_old);
}

uint64_t ipclower_str2phys(char *tok)
{
	return lnet_str2phys(tok);
}

int ipclower_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper,
		  ssize_t *max_msg_size, int num_mds)
{
	return dvs_lnet_init(nodeidp, upper, max_msg_size, num_mds);
}

void ipclower_term(void)
{
	lnet_term();
}

EXPORT_SYMBOL(ipclower_send_nak);
EXPORT_SYMBOL(ipclower_tx_request);
EXPORT_SYMBOL(ipclower_mapkvm);
EXPORT_SYMBOL(ipclower_unmapkvm);
EXPORT_SYMBOL(ipclower_mapuvm);
EXPORT_SYMBOL(ipclower_unmapuvm);
EXPORT_SYMBOL(ipclower_rma_put);
EXPORT_SYMBOL(ipclower_rma_get);
EXPORT_SYMBOL(ipclower_rma_wait);
EXPORT_SYMBOL(ipclower_fill_rx_slot);
EXPORT_SYMBOL(ipclower_str2phys);
EXPORT_SYMBOL(ipclower_init);
EXPORT_SYMBOL(ipclower_term);
