/*
 * Copyright 2009-2011, 2013-2014, 2016-2017 Cray Inc. All Rights Reserved.
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
 * transport to the Portals API.
 */

#include "dvsipc.h"

#include <portals/p30.h>
#include <portals/defines.h>
#include <portals/reserved_ptls.h>

MODULE_LICENSE(DVS_LICENSE);

#define DVSIPC_PORTAL_ID     3               /* Portal reserved for dvs ipc */
#define DVSIPC_PORTALS_PID   3               /* Pid reserved for dvs ipc */

static ptl_handle_eq_t ptl_rx_eq;            /* rx and tx event queues */
static ptl_handle_eq_t ptl_tx_eq;
static ptl_handle_eq_t ptl_rma_eq;
static ptl_handle_me_t ptl_rx_me_table[DVSIPC_MAX_RX_MDS] = {0};

/* Match entries to control landing zone overflow and retransmit requests */
static ptl_handle_me_t ptl_rx_me_guard = {0};
static ptl_handle_me_t ptl_rx_me_resend = {0};
static ptl_handle_me_t ptl_rx_me_orphan = {0};

static ptl_handle_ni_t ni;                   /* Portals network interface handle */
static ptl_process_id_t my_ptl_process_id = {0};

static void ptl_rx_callback(ptl_event_t *event);
static void ptl_tx_callback(ptl_event_t *event);
static void ptl_rma_callback(ptl_event_t *event);

static void ptl_send_nak(uint64_t nid, void *rqp);
static int ptl_tx_request(uint64_t nid, struct usiipc *rq,
				int resend_limit, int tx_timeout);
static void *ptl_mapuvm(char *uvm, ssize_t length, int rw);
static int ptl_unmapuvm(void *handle);
static void *ptl_rma_put(int node, char *to, char *from,
			ssize_t length, rma_info_t *ri, int async);
static void *ptl_rma_get(int node, char *to, char *from,
			ssize_t length, rma_info_t *ri, int async);
static void ptl_rma_wait(rma_info_t *ri);
static int ptl_fill_rx_slot(int slot, void *buf, int size);
static int ptl_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper, int num_mds);
static void ptl_term(void);

static dvsipc_upper_api_t *upper_api = NULL;
static int ipc_num_mds;

const char *ptl_event_str[] = {
    NULL, "PTL_EVENT_ACK", "PTL_EVENT_PUT_START", "PTL_EVENT_PUT_END",
    "PTL_EVENT_GET_START", "PTL_EVENT_GET_END", "PTL_EVENT_REPLY_START",
    "PTL_EVENT_REPLY_END", "PTL_EVENT_SEND_START", "PTL_EVENT_SEND_END",
    "PTL_EVENT_UNLINK", NULL, "PTL_INTERNAL_EVENT_NOP_START",
    "PTL_INTERNAL_EVENT_NOP_END", "PTL_INTERNAL_EVENT_RELEASE_START",
    "PTL_INTERNAL_EVENT_RELEASE_END", "PTL_EVENT_GETPUT_START",
    "PTL_EVENT_GETPUT_END", NULL, NULL, NULL, NULL, NULL, NULL,
    "PTL_EVENT_CGETPUT_START", "PTL_EVENT_CGETPUT_END", NULL,
    "PTL_EVENT_GETADD_END"
};

typedef enum {rx_small, rx_med, rx_large, rx_unrl} rx_slot_type_t;
static char *rx_slot_str[] = {"rx_small", "rx_med", "rx_large", "rx_unrl"};

/*
 * ptl_rx_slot_type - return the buffer assignment type.
 *
 * To support the handling of variable length unexpected messages,
 * the module creates a set of receive buckets associated with 
 * various sizes. This helps distribute the receive load across
 * the MDs and avoid cases were MDS become 'mostly' full and
 * we start having to drop larger messages.
 */
static rx_slot_type_t
ptl_rx_slot_type(int slot_id)
{
    rx_slot_type_t which_slot;

    if ((slot_id <= (ipc_num_mds>>2)))
        which_slot = rx_small;
    else if (slot_id > (ipc_num_mds-3))
        which_slot = rx_unrl;
    else if (slot_id < ((ipc_num_mds>>1)+(ipc_num_mds>>2)))
        which_slot = rx_med;
    else
        which_slot = rx_large;

    KDEBUG_IPC(0, "%s: slot %d = %s\n", __FUNCTION__, slot_id,
           rx_slot_str[which_slot]);

    return which_slot;
}

/*
 * ptl_build_rx_md - Initialize a portals md for a receive buffer
 *
 * This routine is used to initialize a portals memory descriptor for
 * a buffer that will be used to hold an inbound message. If a buffer
 * pointer is supplied on the call, it will be used. Otherwise, we attempt
 * to allocate memory based on the supplied size.
 *
 * On success, 0 is returned to the caller. Otherwise, -ENOMEM is returned.
 */
static int
ptl_build_rx_md(void *buf, int size, int me_idx, ptl_md_t *md, int seq) 
{
    rx_buf_info_t *bip;
    KDEBUG_IPC(0, "%s: IN (0x%p:0x%x:%d:0x%p)\n",
        __FUNCTION__, buf, size, me_idx, md);

    DVS_TRACEL("bldrxIN", me_idx, buf, size, 0, 0);

    /* If the caller did not supply a buffer, allocate one now. */
    if (buf == NULL) {
        buf = vmalloc_ssi(size);
        if (buf == NULL) {
            DVS_TRACE("badbldrx", me_idx, 0);
            printk(KERN_ERR "%s: vmalloc_ssi (size 0x%x) failed\n",
                __FUNCTION__, size);
            return (-ENOMEM);
        }
    }

    /* 
     * Set md size based on me array index. This is intended to make
     * more efficient use of buffer space with variable sized inbound
     * requests.
     */
    switch(ptl_rx_slot_type(me_idx)) {
    case rx_small:
        md->max_size = sizeof(struct file_request) * 2;
        break;
    case rx_med:
        md->max_size = sizeof(struct file_request) + DEFAULT_PFS_STRIPE_SIZE;
        break;
    case rx_large:
        md->max_size = IPC_MAX_MSG_SIZE;
        break;
    case rx_unrl:
        md->max_size = sizeof(struct usiipc) * 16;
        break;
    }

    /* Setup default memory descriptor parameters */
    md->start = (char*)buf + sizeof(rx_buf_info_t);
    md->length = size - sizeof(rx_buf_info_t);
    md->options = PTL_MD_OP_PUT | PTL_MD_EVENT_START_DISABLE | PTL_MD_MAX_SIZE;
    md->threshold = md->length / md->max_size;
    md->eq_handle = ptl_rx_eq;
    md->user_ptr = (void*)(((uint64_t)(me_idx)<<32) | seq);

    KDEBUG_IPC(0, "%s: %d: 0x%p:0x%x:0x%x:0x%x\n", __FUNCTION__, me_idx,
        md->start, md->options, md->threshold, md->max_size);

    DVS_TRACEL("bldrxmd", me_idx, md->threshold, md->max_size, buf, 0);

    /* Initialize buffer state */
    bip = (void *)buf;
    atomic_set(&bip->outstanding_ops, 0);
    bip->unlinked = 0;

    return 0;
}

static int
ptl_build_backstop_me(ptl_handle_me_t *mep, ptl_match_bits_t match,
			ptl_match_bits_t ignore, void *user_ptr) 
{
    ptl_md_t md;
    ptl_handle_md_t mdh;
    ptl_process_id_t id;
    int ret;

    id.nid = PTL_NID_ANY;
    id.pid = PTL_PID_ANY;

    if ((ret=PtlMEAttach(ni, DVSIPC_PORTAL_ID, id, match, ignore,
        PTL_RETAIN, PTL_INS_AFTER, mep)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlMEAttach failed (0x%x)\n", __FUNCTION__,
            ret);
        return -ENOSPC;
    }

    md.start = NULL;
    md.length = 0;
    md.options = PTL_MD_OP_PUT | PTL_MD_EVENT_START_DISABLE |
        PTL_MD_TRUNCATE | PTL_MD_ACK_DISABLE;
    md.threshold = PTL_MD_THRESH_INF;

    md.eq_handle = ptl_rx_eq;
    md.user_ptr = user_ptr;

    if ((ret=PtlMDAttach(*mep, md, PTL_RETAIN, &mdh)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlMDAttach failed (0x%x)\n",
            __FUNCTION__, ret);
        return -ENOSPC;
    }

    return 0;
}

/*
 * ptl_bind_buf - Map a buffer into portals space.
 *
 * This routine is used to bind a buffer to a portals
 * handle for subsequent transmission.
 *
 * If no buffer is supplied, -ENOMEM is returned. Otherwise,
 * the result of the call to PtlMDBind is returned to the caller.
 */
static int
ptl_bind_buf(void *buf, int size, int evt_thresh,
			int md_opt, ptl_handle_eq_t eq,
			void *user_ptr, int bind_opt,
			ptl_handle_md_t *mdh) 
{
    ptl_md_t md;

    KDEBUG_IPC(0, "%s: IN (0x%p 0x%x 0x%p)\n", __FUNCTION__, buf, size, mdh);
    DVS_TRACE("ipc_btxmd", buf, size);
    if (buf == NULL) {
        DVS_TRACE("ipc_btxE", buf, size);
        return (-ENOMEM);
    }
    md.start = buf;
    md.length = size;
    md.threshold = evt_thresh;
    md.options = PTL_MD_EVENT_START_DISABLE | md_opt;
    md.eq_handle = eq;
    md.user_ptr = user_ptr;

    return PtlMDBind(ni, md, bind_opt, mdh);
}

/*
 * ptl_tx_callback - Callback for a portals transmit event.
 *
 * When a portals transmit request is made, this callback routine
 * is specified. When portals fires an event of interest on the
 * change of transmit state, this routine will be called. If the
 * event happens to be a PTL_EVENT_SEND_END, we know that the transmit
 * has completed and the ipc layer is notified as appropriate.
 *
 * If the transport should free an asynchronous message on transmit
 * completion, free_required will be set to 2. Otherwise, an interested
 * waiter will block on the msgwait semaphore.
 */
static void
ptl_tx_callback(ptl_event_t *event) 
{
    struct usiipc *msg = (struct usiipc *)event->md.start;

    KDEBUG_IPC(0, "ptl_tx_callback: event type (0x%x)\n", event->type);

    DVS_TRACEL("ipc_txcb", event->type, event->ni_fail_type, msg, 0, 0);

    /* nak requests have no payload */
    if (msg == NULL) {
        DVS_TRACE("ipc_txrsnd", event->rlength, event->hdr_data);
        return;
    }

    if (event->type == PTL_EVENT_SEND_END) {

        KDEBUG_IPC(0, "ptl_tx_callback: tx complete (0x%p:0x%p:%s)\n",
            msg, event->md.user_ptr, rq_cmd_name(msg));

        DVS_TRACEL("ipc_txcb", msg, msg->target_node, msg->command,
                   IPC_WAIT_FOR_REPLY(msg), 0);

        if (event->ni_fail_type != 0) {
            DVS_TRACEL("ipc_txcbF", msg, event->ni_fail_type, 
                      msg->command, 0, 0);
            KDEBUG_IPC(0, "ptl_tx_callback: tx failed (%s:0x%x:%s)\n",
                SSI_NODE_NAME(msg->target_node),
                event->ni_fail_type, rq_cmd_name(msg));

            upper_api->tx_complete(msg, 1);
        } else if (!(IPC_WAIT_FOR_REPLY(msg) || IS_IOPAGE_REQUEST(msg))) {
            upper_api->tx_complete(msg, 0);
        } else {
            /* transmit has hit the destination node */
            tx_status_t *tx_status =
                 (tx_status_t *)&msg->transport_handle;
            dvsipc_tx_t *txp = container_of(msg, dvsipc_tx_t, msg);

            /* ACK could hit first */
            if (atomic_read(&tx_status->upper_status) != 0) {
                upper_api->tx_complete(msg, 0);
            /* ... as could NAK */
            } else if (atomic_read(&tx_status->lower_status) ==
                                          DVSIPC_TX_RESEND) {
                DVS_TRACE("nak<tx", msg, msg->target_node);
                up(&txp->sema);
            } else {
                atomic_inc(&tx_status->upper_status);
            }
        }
    } else if (event->type == PTL_EVENT_ACK) {
        tx_status_t *tx_status =
             (tx_status_t *)&msg->transport_handle;
        DVS_TRACE("ipc_txup", msg, &msg->msgwait);
        /* ACK could hit before SEND_END */
        if (atomic_read(&tx_status->upper_status) > 0) {
            upper_api->tx_complete(msg, 0);
        } else {
            atomic_dec(&tx_status->upper_status);
        }
    } else {
        KDEBUG_IPC(0, "%s: unexpected event (%s) match 0x%Lx user_ptr 0x%p\n",
            __FUNCTION__, ptl_event_str[event->type], event->match_bits,
            (void*)event->md.user_ptr);
    }
}

/*
 * ptl_rx_callback - Callback for a portals receive event.
 *
 * When a portals message is received, this callback routine is
 * called. We perform accounting on the shared rx buf and pass the
 * message along to higher ipc layers for handling.
 */
static void
ptl_rx_callback(ptl_event_t *event) 
{
    KDEBUG_IPC(0, "ptl_rx_callback: event type (0x%x)\n", event->type);
    DVS_TRACEL("ipcrxcb", event->type, event->md.user_ptr,
               event->hdr_data, 0, 0);

    if (event->type == PTL_EVENT_PUT_END) {
        rx_buf_info_t *bip;
        struct usiipc *msg;
        char *cmd;
        int me_idx = (uint64_t)(event->md.user_ptr)>>32;

        /*
         * Check for overflow md.
         */
        if (event->md.user_ptr == (uint64_t*)(DVSIPC_OVERFLOW_TAG)) {
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
        } else if(event->md.user_ptr == (void*)DVSIPC_RESEND_REQ) {
            struct usiipc *rq = (struct usiipc *)(event->hdr_data);
            tx_status_t *tx_status =
                (tx_status_t*)&rq->transport_handle;
            dvsipc_tx_t *txp = container_of(rq, dvsipc_tx_t, msg);
            int lower_status;

            KDEBUG_IPC(0, "%s: resend requested from %d\n", __FUNCTION__,
                       event->initiator.nid);

            lower_status = atomic_cmpxchg(&tx_status->lower_status,
                0, DVSIPC_TX_RESEND);

            /* 
             * Notify sending thread to retransmit if it is
             * still interested
             */
            if (lower_status == DVSIPC_TX_ORPHANED) {
                kfree_ssi(txp);
            } else {
                up(&txp->sema);
            }
            return;
        /*
         * Check for orphaned rdma.
         */
        } else if(event->md.user_ptr == (void*)DVSIPC_ORPH_REQ) {
            DVS_TRACE("ipcrxorp", event->initiator.nid, 0);
            return;
        }

        msg = (struct usiipc *)((char*)event->md.start + event->offset);
        bip = (void*)((char*)(event->md.start - sizeof(rx_buf_info_t)));
        cmd = rq_cmd_name(msg);

        DVS_TRACEL("ipc_rx", msg->source_node, msg->command, 
                   event->md.start, 0, 0);
        DVS_TRACEP(cmd, 0, 0);

        atomic_inc(&bip->outstanding_ops);

        if (event->unlinked == 1) {
            DVS_TRACEL("ipcrxcvU", me_idx, msg, bip,
                       atomic_read(&bip->outstanding_ops), 0);

            /* 
             * Mark the buffer for recyle and inform the refill tasklet
             * that the MD needs to be replaced.
             */
            bip->unlinked = 1;
        }

        if (event->ni_fail_type != 0) {
            printk(KERN_ERR "%s: rx failed (%s:0x%x:%s)\n", __FUNCTION__,
                SSI_NODE_NAME(msg->target_node),
                event->ni_fail_type, rq_cmd_name(msg));
            DVS_TRACEL("ipcrxcvF", msg, bip, event->ni_fail_type, 0, 0);
            msg->transport_handle = bip;
            msg->command = RQ_IPC_DISPOSE;   /* mark for disposal */
        }

        /* Perform state management for the shared md. */
        msg->transport_handle = bip;
        msg->free_required = 1;

        KDEBUG_IPC(0, KERN_ERR "%s: RCV msg from %s: %s\n", __FUNCTION__,
            SSI_NODE_NAME(msg->source_node), rq_cmd_name(msg));

        upper_api->rcv(msg);

        KDEBUG_IPC(0, "%s: RCV OUT msg: 0x%p:0x%p\n", __FUNCTION__,
            event->md.start,msg);
    } else {
        KDEBUG_IPC(0, "%s: unexpected event (%s) match 0x%Lx user_ptr 0x%p (0x%Lx:0x%Lx)\n",
            __FUNCTION__, ptl_event_str[event->type], event->match_bits,
            (void*)event->md.user_ptr, event->rlength, event->mlength);
    }
}

/*
 * ptl_rma_callback - Callback for a portals rma event.
 *
 * When a portals transmit request is made, this callback routine
 * is specified. When portals fires an event of interest on the
 * change of transmit state, this routine will be called. If the
 * event happens to be a PTL_EVENT_SEND_END, we know that the transmit
 * has completed and the ipc layer is notified as appropriate.
 */
static void
ptl_rma_callback(ptl_event_t *event) 
{
    rma_info_t *ri = (rma_info_t *)(event->md.user_ptr);
    struct semaphore *semap;

    KDEBUG_IPC(0, "%s: %s\n", __FUNCTION__, ptl_event_str[event->type]);

    /*
     * If the initiating node has been marked down, we can return now
     * since shutdown processing will ceanup in-flight rma operations.
     */
    if (event->initiator.nid != my_ptl_process_id.nid && ri &&
        upper_api->node_state(ri->lnid) != NODE_READY) {
        KDEBUG_IPC(0, "%s: node %d marked down with rma in-flight\n",
                __FUNCTION__, event->initiator.nid);
        DVS_TRACE("rmacb!up", event->initiator.nid, event->type);
        return;
    }

    if (!ri) {
        KDEBUG_IPC(0, "%s: unexpected rma event (%s) match 0x%Lx user_ptr 0x%p\n",
            __FUNCTION__, ptl_event_str[event->type], event->match_bits, (void*)ri);
        DVS_TRACE("rmacb!ri", event->type, event->match_bits);
        return;
    }

    DVS_TRACEL("rmacb", ri->rma_type, event->type, event->ni_fail_type, 0, 0);

    semap = &ri->sema;

    DVS_TRACEL("rmaCB", event->match_bits, ri, semap, 0, 0);

    if (event->type == PTL_EVENT_SEND_END) {
        KDEBUG_IPC(0, "ptl_rma_callback: send complete (0x%p:0x%p)\n",
            event->md.start, event->md.user_ptr);

        DVS_TRACEL("rmaCBSE", ri->rma_type, event->match_bits, ri, semap, 0);

        if (event->ni_fail_type != 0) {
            DVS_TRACEL("rmaCBE", ri->rma_type, event->match_bits, ri, semap, 0);
            KDEBUG_IPC(0, "ptl_rma_callback: tx failed (0x%p:0x%x:%d)\n",
                event->md.start, event->ni_fail_type, ri->rma_type);
        }

        /* Ignore SEND_END for GET operations unless there was an error */
        if (ri->rma_type == RMA_PUT) {
            ri->retval = event->ni_fail_type;
            up(semap);
        } else if (event->ni_fail_type != PTL_NI_OK) {
            ri->retval = -EIO;
            up(semap);
        }
    } else if (event->type == PTL_EVENT_REPLY_END) {
        DVS_TRACEL("rmaCBRE", ri->rma_type, event->match_bits, ri, semap, 0);
        KDEBUG_IPC(0, "ptl_rma_callback: REPLY_END (0x%p:%d) (0x%Lx:0x%Lx:0x%Lx)\n",
            event->md.start, event->type, event->rlength,
            event->mlength, ri->length);
        /*
         * The RMA can fail if the remote has cleaned up the MD for the
         * transfer or because of a communication error. In either case,
         * return EIO.
         */
        if (event->mlength == 0 || event->ni_fail_type != PTL_NI_OK) {
            DVS_TRACEL("rmaCBREE", ri->length, event->ni_fail_type,
                       event->mlength, event->match_bits, 0);
            KDEBUG_IPC(0, "%s: REPLY_END failed\n", __FUNCTION__);
            ri->retval = -EIO;
        } else {
            ri->retval = event->mlength;
        }
        up(semap);
    } else {
        DVS_TRACE("rmaCBUNX", ri, event->type);
        KDEBUG_IPC(0, KERN_ERR "%s: unexpected rma event (%s) match 0x%Lx user_ptr 0x%p\n",
            __FUNCTION__, ptl_event_str[event->type], event->match_bits, (void*)ri);
    }
}

/***********************
 *** Lower half API  ***
 ***********************/

/*
 * ptl_tx_request - Send an ipc request to the target node.
 *
 * This routine is used to send an outbound request over the
 * seastar interface. To do this, the requested message is mapped
 * onto a portals memory descriptor and the resulting md is passed
 * to portals for transmission via a non-ACK'd PtlPut. The dvs
 * ipc layer will manage responses from the target if necessary.
 *
 */
static int
ptl_tx_request(uint64_t nid, struct usiipc *rq, int resend_limit, int tx_timeout) 
{
    int ret = 0;
    int rval = 0;
    ptl_process_id_t dest;
    int retries = 0;
    ptl_handle_md_t mdh;
    uint64_t user_data = 0;
    struct usiipc *trq = NULL;
    tx_status_t *tx_status = NULL;
    int lower_status;
    dvsipc_tx_t *txp;

    KDEBUG_IPC(0, "SS_TX: (%d:%s) %s/%s\n", rq->command, rq_cmd_name(rq),
        SSI_NODE_NAME(rq->target_node), SSI_NODE_NAME(rq->target_node));

    DVS_TRACEL("ipc_tx", rq->target_node, rq->command,
               rq->request_length, 0, 0);

    dest.nid = nid;
    dest.pid = DVSIPC_PORTALS_PID;

    sema_init(&rq->msgwait, 0);

    trq = dvsipc_dup_msg(rq, 1);
    if (trq == NULL) {
        return -ENOMEM;
    }

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

    if ((ret=ptl_bind_buf(rq, rq->request_length, PTL_MD_THRESH_INF,
        0, ptl_tx_eq, 0, PTL_RETAIN, &mdh)) != PTL_OK) {
        printk(KERN_ERR "%s: ptl_bind_buf failed (0x%x)\n",
            __FUNCTION__, ret);
        DVS_TRACEL("ipc_txF1", rq->target_node, rq->command, ret, 0, 0);
        kfree_ssi(txp);
        return -ENXIO;
    }

    sema_init(&txp->sema, 0);

    do {
        struct timer_list timer;
        unsigned long expire;
        int loopcnt = 0;

        atomic_set(&tx_status->lower_status, 0);
        atomic_set(&tx_status->upper_status, 0);

        DVS_TRACEL("ipc_txFM", rq, &rq->msgwait, rq->target_node, mdh, 0);

        /*
         * Give the target node a break.
         */
        if (retries) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout((retries%10)+1);
            set_current_state(TASK_RUNNING);
        }

        /*
         * If this is a RM inquiry, send it on the unreliable channel.
         */
        if ((ret = PtlPut(mdh, user_data?PTL_ACK_REQ:PTL_NOACK_REQ, dest,
            rq->command == RQ_RESOURCE_CLIENT ?
            PTL_PT_INDEX_UNRELIABLE : DVSIPC_PORTAL_ID,
            0, DVSIPC_RX_MATCHBITS, DVSIPC_IGNORE_NONE, user_data)) != PTL_OK) {
            PtlMDUnlink(mdh);
            DVS_TRACEL("ipc_txF3", rq->target_node, rq->command,
                       ret, mdh, 0);
            printk(KERN_ERR "%s: PtlPut failed (0x%x:0x%x:%s)\n", __FUNCTION__,
                ret, mdh, rq_cmd_name(rq));
            kfree_ssi(txp);
            return -EIO;
        }

        do {
            /*
             * We've initiated the requested transfer via portals. We now
             * set a local timer for the request to allow for reasonable
             * response time if the target happens to be unable to handle
             * our request.  If the target is down, we'll be informed
             * through the call to node_state(). If we need to abandon the
             * request, we tell the tx callback routine to free our
             * transmit buffer via the DVSIPC_TX_ORPHANED flag.
             */

            expire = jiffies + (tx_timeout*HZ);
            setup_timer(&timer, upper_api->expire_request,
                (unsigned long)rq);
            mod_timer(&timer, expire);

            down(&txp->sema);

            del_singleshot_timer_sync(&timer);

            DVS_TRACEL("ipc_txFC", rq, loopcnt, rq->target_node,
                       rq->transport_handle, 0);
            loopcnt++;

        } while (atomic_read(&tx_status->lower_status) == 0 &&
            atomic_read(&tx_status->upper_status) < DVSIPC_MAX_TX_TICKS &&
            upper_api->node_state(rq->target_node) == NODE_READY);

    } while ((atomic_read(&tx_status->lower_status) == DVSIPC_TX_RESEND) &&
        (++retries < resend_limit) &&
        upper_api->node_state(rq->target_node) == NODE_READY);

    if ((rval = PtlMDUnlink(mdh)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlMDUnlink failed (%d)\n", __FUNCTION__, rval);
        DVS_TRACE("ipc_txF4", rval, mdh);
    }

    lower_status = atomic_cmpxchg(&tx_status->lower_status,
        0, DVSIPC_TX_ORPHANED);

    /*
     * Handle abnormal tx disposition.
     */
    if (lower_status != DVSIPC_TX_COMPLETE) {
        DVS_TRACEL("ipc_txHD", rq->target_node, rq,
                   rq->transport_handle, retries, 0);
        if (upper_api->node_state(rq->target_node) == NODE_READY) {
            int upper_status = atomic_read(&tx_status->upper_status);
            printk(KERN_ERR "DVS: %s: tx of %s to %s failed %s\n",
                __FUNCTION__, rq_cmd_name(rq),
                SSI_NODE_NAME(rq->target_node),
                lower_status == DVSIPC_TX_RESEND ?
		    "(retry limit exceeded)" : 
                upper_status >= DVSIPC_MAX_TX_TICKS ?  "(unresponsive)" : "");
            ret = -EIO;
        } else {
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
 * ptl_send_nak - send a NAK to a node from which a request was
 *                   dropped.
 */
static void
ptl_send_nak(uint64_t nid, void *rqp) 
{
    int ret;
    ptl_process_id_t dest;
    ptl_md_t md = {0};
    ptl_handle_md_t mdh;

    KDEBUG_IPC(0, "%s: nak to %Ld\n", __FUNCTION__, nid);
    DVS_TRACE("tx_nak", nid, rqp);

    dest.nid = (ptl_nid_t)nid;
    dest.pid = DVSIPC_PORTALS_PID;

    md.threshold = 1;
    md.options = PTL_MD_EVENT_START_DISABLE;

    if ((ret = PtlMDBind(ni, md, PTL_UNLINK, &mdh)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlMDBind failed (0x%x)\n", __FUNCTION__, ret);
        DVS_TRACE("ipc_txN1", ret, 0);
        return;
    }

    if ((ret = PtlPut(mdh, PTL_NOACK_REQ, dest,
        DVSIPC_PORTAL_ID, 0, DVSIPC_NAK_MATCH, 0, (uint64_t)rqp)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlPut failed (0x%x:0x%x)\n",
            __FUNCTION__, ret, mdh);
        DVS_TRACE("ipc_txN2", ret, 0);
        return;
    }

    return;
}

static void *
ptl_mapuvm(char *uvm, ssize_t length, int rw) 
{
    struct ipc_mapping *ipcmap = NULL;
    struct page **pages = NULL;
    ptl_process_id_t id;
    ptl_pt_index_t ptlid = DVSIPC_PORTAL_ID;
    ptl_match_bits_t ignore = 0;
    ptl_match_bits_t match;
    ptl_handle_md_t rmah = PTL_MD_INVALID;
    ptl_handle_md_t mdh = PTL_MD_INVALID;
    ptl_md_iovec_t *iovec = NULL;
    int page_count, offset;
    ptl_md_t md;
    int ret = 0;
    int i;

    KDEBUG_IPC(0, "ptl_mapuvm: 0x%p 0x%lx 0x%x\n", uvm, length, rw);

    offset = (uint64_t)uvm & (PAGE_SIZE-1);
    page_count = ((offset+length-1) / PAGE_SIZE) + 1;

    pages = (struct page **)vmalloc_ssi(page_count * sizeof(struct page *));
    if (pages == NULL) {
        printk(KERN_EMERG "%s: can't allocate pages struct (count=%d)\n",
            __FUNCTION__, page_count);
        goto cleanup;
    }

    /* Gather user pages */
    down_read(&current->mm->mmap_sem);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,73)
    ret = get_user_pages(current, current->mm, (unsigned long)uvm, page_count,
			rw == READ, 0, pages, NULL);
#else
    ret = get_user_pages((unsigned long)uvm, page_count,
			(rw == READ ? FOLL_WRITE : 0), pages, NULL);
#endif
    up_read(&current->mm->mmap_sem);

    if (page_count != ret) {
        KDEBUG_IPC(0, "%s: page count mismatch on user buffer (%d:%d)\n",
            __FUNCTION__, page_count, ret);
        page_count = ret;
        goto cleanup;
    }

    /* Allocate icpmap with space for page mappings and iovec pointer */
    ipcmap = vmalloc_ssi(sizeof(struct ipc_mapping) + sizeof(u64));

    if (ipcmap == NULL) {
        printk(KERN_ERR "%s: failed to allocate ipcmap buffer\n", __FUNCTION__);
        goto cleanup;
    }

    ipcmap->uvm = uvm;
    ipcmap->length = length;
    ipcmap->offset = offset;
    ipcmap->pages = pages;
    ipcmap->rw = rw;
    ipcmap->dma_length = 0;
    ipcmap->dma[0] = page_count;

    KDEBUG_IPC(0, "ptl_mapuvm: 0x%p(0x%p) 0x%lx 0x%x (%d)\n",
        uvm, (void*)virt_to_phys(uvm), length, offset, page_count);

    /* Create, init ss/ipc management structure */
    iovec = (void *)vmalloc_ssi(sizeof(ptl_md_iovec_t) * (page_count+1));
    if (iovec == NULL) {
        printk(KERN_ERR "%s: can't allocate iovec (count=%d)\n",
            __FUNCTION__, page_count);
        goto cleanup;
    }

    KDEBUG_IPC(0, "ptl_mapuvm: 0x%p(0x%p) 0x%lx 0x%x %d\n", uvm, iovec,
        length, offset, page_count);

    /* Provide ipc/portals translation */
    for (i=0; i<page_count; i++) {
        int len;

        len = PAGE_SIZE - offset;
        iovec[i].iov_base = (void*)(page_to_phys(pages[i]) + offset);
        iovec[i].iov_len = len;

        KDEBUG_IPC(0, "ptl_mapuvm: iovec[%d] (0x%p, 0x%p, 0x%llx)\n",
            i, uvm, iovec[i].iov_base, iovec[i].iov_len);

        uvm += len;
        offset = 0;
    }

    ipcmap->dma[1] = (uint64_t)iovec; /* save for later cleanup */

    id.nid = PTL_NID_ANY;
    id.pid = PTL_PID_ANY;

    match = (ptl_match_bits_t)ipcmap;

    if ((ret=PtlMEAttach(ni, ptlid, id, match, ignore, PTL_UNLINK,
        PTL_INS_BEFORE, &rmah)) != PTL_OK) {
        KDEBUG_IPC(0, "ptl_mapuvm: PtlMEAttach failed (0x%x)\n", ret);
        goto cleanup;
    }

    KDEBUG_IPC(0, "ptl_mapuvm MATCH: 0x%p 0x%llx\n", uvm, match);

    md.threshold = PTL_MD_THRESH_INF;
    md.options = PTL_MD_OP_PUT | PTL_MD_OP_GET | PTL_MD_EVENT_START_DISABLE |
        PTL_MD_PHYS | PTL_MD_IOVEC | PTL_MD_MANAGE_REMOTE;
    md.eq_handle = PTL_EQ_NONE;
    md.user_ptr = NULL;
    md.start = iovec;
    md.length = page_count;

    if ((ret=PtlMDAttach(rmah, md, PTL_UNLINK, &mdh)) != PTL_OK) {
        KDEBUG_IPC(0, "ptl_mapuvm: PtlMDAttach failed (0x%x)\n", ret);
        goto cleanup;
    }

    iovec[page_count].iov_len = rmah;        /* store handles for manual unlink */

    DVS_TRACEL("ipc_MuvM", iovec[page_count].iov_len, mdh, rmah, 0, 0);

    KDEBUG_IPC(0, "ptl_mapuvm OUT: 0x%p 0x%x 0x%x\n", uvm, rmah, mdh);

    return ipcmap;

cleanup:
    if (pages) {
        for (i=0; i<page_count; i++) {
            if (rw == READ) {
                set_page_dirty_lock(pages[i]);
            }
            page_cache_release(pages[i]);
        }
        vfree_ssi(pages);
    }

    if (ipcmap) {
        if (iovec) {
            vfree_ssi(iovec);
        }
        vfree_ssi(ipcmap);
    }

    if (rmah != PTL_MD_INVALID) {
        PtlMEUnlink(rmah);
    }

    /* Pass error code back up to the caller. */	 
    if (ret < 0) {
        return (ERR_PTR(ret));
    }

    return NULL;
}

static int
ptl_unmapuvm(void *handle) 
{
    struct ipc_mapping *ipcmap = (struct ipc_mapping *)handle;
    ptl_md_iovec_t *iovec =
        (ptl_md_iovec_t *)(ipcmap->dma[1]);
    ptl_handle_md_t meh;
    int page_count = ipcmap->dma[0];
    int i;
    int ret;

    KDEBUG_IPC(0, "ptl_unmapuvm: 0x%p 0x%p\n", ipcmap, iovec);

    meh = iovec[page_count].iov_len;

    KDEBUG_IPC(0, "ptl_unmapuvm: Unlinking handles %d\n", meh);

    DVS_TRACE("ipc_um", meh, 0);
    if ((ret=PtlMEUnlink(meh))) {
        printk(KERN_ERR "%s: unlink failed (%d)\n", __FUNCTION__, ret);
        DVS_TRACE("ipc_umE", meh, ret);
    }

    for (i=0; i<page_count; i++) {
        if (ipcmap->rw == READ) {
            set_page_dirty_lock(ipcmap->pages[i]);
        }
        page_cache_release(ipcmap->pages[i]);
    }

    vfree_ssi(ipcmap->pages);
    vfree_ssi(iovec);
    vfree_ssi(ipcmap);

    return 0;
}

static void *
ptl_rma_put(int node, char *to, char *from, ssize_t length, 
            rma_info_t *ri, int async) 
{
    ptl_handle_md_t mdh;
    ptl_process_id_t dest;
    struct rma_state *rmasp = (struct rma_state *)ri->handle;
    ptl_match_bits_t match = (ptl_match_bits_t)rmasp->handle;
    int ret;

    KDEBUG_IPC(0, "ptl_rma_put (%d:0x%p:0x%p:0x%lx:0x%p:0x%p)\n",
        node, to, from, length, ri, rmasp->handle);

    if ((ret=ptl_bind_buf(from, length, 1, 0, ptl_rma_eq,
        (void*)ri, PTL_UNLINK, &mdh)) != PTL_OK) {
        printk(KERN_ERR "%s: ptl_bind_buf failed (0x%x)\n", __FUNCTION__, ret);
        DVS_TRACEL("rmaRPF", node, from, to, length, 0);
        return ERR_PTR(-ENXIO);
    }

    DVS_TRACE("rmaPB0", match, ri);

    dest.nid = ri->nid;
    dest.pid = DVSIPC_PORTALS_PID;

    KDEBUG_IPC(0, "ptl_rma_put: Put to match=0x%llx on %d (0x%p,0x%p,0x%lx)\n",
        match, dest.nid, to, rmasp->remote_addr, length);

    if ((ret = PtlPutRegion(mdh, 0, length, PTL_NOACK_REQ, dest,
        DVSIPC_PORTAL_ID, 0, match, to - rmasp->remote_addr, 0)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlPutRegion failed (0x%x)\n", __FUNCTION__, ret);
        PtlMDUnlink(mdh);
        return ERR_PTR(-EIO);
    }

    KDEBUG_IPC(0, "ptl_rma_put: PtlPutRegion of 0x%p complete\n", to);

    if (async == 0) {
        DVS_TRACEL("rmaPB", match, ri, ri->semap, 0, 0);

        down(ri->semap);

        DVS_TRACEL("rmaPA", match, ri, ri->semap, 0, 0);

        KDEBUG_IPC(0, "ptl_rma_put: PtlPutRegion of 0x%p complete\n", to);

        if (ri->retval != PTL_NI_OK) {
            KDEBUG_IPC(0, "ptl_rma_put: Put 0x%lx to match=0x%llx on %d "
                "off 0x%p failed (0x%x)\n",
                length, match, dest.nid, (char*)(to-rmasp->remote_addr),
                ri->retval);
            DVS_TRACE("rma_putE", ri->retval, 0);
            return ERR_PTR(-ENXIO);
        }

        return ERR_PTR(length);
    }

    return NULL;
}

static void *
ptl_rma_get(int node, char *to, char *from, ssize_t length, 
            rma_info_t *ri, int async) 
{
    ptl_handle_md_t mdh;
    ptl_process_id_t dest;
    struct rma_state *rmasp = (struct rma_state *)ri->handle;
    ptl_match_bits_t match = (ptl_match_bits_t)rmasp->handle;
    int ret;

    /* Complete initialization of RMA state structure */
    ri->handle = (uint64_t)match;

    KDEBUG_IPC(0, "ptl_rma_get (%d:0x%p:0x%p:0x%lx:0x%p:0x%p)\n",
        node, to, from, length, ri, rmasp->handle);

    if ((ret=ptl_bind_buf(to, length, 2,
        0, ptl_rma_eq, (void*)ri, PTL_UNLINK, &mdh)) != PTL_OK) {

        printk(KERN_ERR "%s: ptl_bind_buf failed (0x%x)\n", __FUNCTION__, ret);
        DVS_TRACEL("rmaRGF", node, from, to, length, 0);
        return ERR_PTR(-ENXIO);
    }

    DVS_TRACEL("rmaPGF", match, &ri, ri->semap, 0, 0);

    dest.nid = ri->nid;
    dest.pid = DVSIPC_PORTALS_PID;
    sema_init(&ri->sema, 0);

    KDEBUG_IPC(0, "ptl_rma_get: Get 0x%lx from match=0x%llx on %d off 0x%p, usr_ptr 0x%p\n",
        length, match, dest.nid, (char*)(from-rmasp->remote_addr),
        (void*)&ri);

    if ((ret = PtlGetRegion(mdh, 0, length, dest,
        DVSIPC_PORTAL_ID, 0, match, from - rmasp->remote_addr)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlGet failed (0x%x)\n", __FUNCTION__, ret);
        PtlMDUnlink(mdh);
        return ERR_PTR(-EIO);
    }

    KDEBUG_IPC(0, "%s: PtlGet complete, waiting on 0x%p\n", __FUNCTION__, ri->semap);

    if (async == 0) {
        DVS_TRACEL("rmaPGB", match, &ri, ri->semap, 0, 0);
        down(ri->semap);
        DVS_TRACEL("rmaPGA", match, &ri, ri->semap, 0, 0);

        KDEBUG_IPC(0, "%s: PtlGet of 0x%p complete\n", __FUNCTION__, from);

        if (ri->retval < 0) {
            KDEBUG_IPC(0, "ptl_rma_get: Get 0x%lx from match=0x%llx on %d "
                "off 0x%p failed (0x%x)\n",
                length, match, dest.nid, (char*)(from-rmasp->remote_addr),
                ri->retval);
            DVS_TRACE("rma_getE", ri->retval, 0);
            PtlMDUnlink(mdh);

        }

        return ERR_PTR(ri->retval);
    }

    return NULL:
}

void
ptl_rma_wait(rma_info_t *rip)
{
    DVS_TRACE("prmaw", rip, &rip->sema);
    down(&rip->sema);
    DVS_TRACE("prmawF", rip, &rip->sema);
}

static int
ptl_fill_rx_slot(int slot, void *buf, int size) 
{
    int ret;
    ptl_md_t md;
    ptl_process_id_t id = {PTL_NID_ANY, PTL_PID_ANY};
    int index = ptl_rx_slot_type(slot) == rx_unrl ? PTL_PT_INDEX_UNRELIABLE :
                                                      DVSIPC_PORTAL_ID;
    rx_buf_info_t *bip = NULL;
    ptl_handle_md_t mdh;

    DVS_TRACE("ipcfill", slot, buf);

    if (ptl_rx_me_table[slot] == 0) {
        if ((ret=PtlMEAttach(ni, index, id, DVSIPC_RX_MATCHBITS,
            DVSIPC_IGNORE_NONE, PTL_RETAIN, PTL_INS_BEFORE,
            &ptl_rx_me_table[slot])) != PTL_OK) {
            printk(KERN_ERR "%s: PtlMEAttach failed (0x%x)\n",
                __FUNCTION__, ret);
            goto errout;
        }
    }

    if ((ret=ptl_build_rx_md(buf, size, slot, &md, 0))) {
        printk(KERN_ERR "%s: ptl_build_rx_md failed (0x%x)\n",
            __FUNCTION__, ret);
        goto errout;
    }

    bip = (void*)((char*)(md.start - sizeof(rx_buf_info_t)));
    if ((ret=PtlMDAttach(ptl_rx_me_table[slot], 
                         md, PTL_UNLINK, &mdh)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlMDAttach (0x%p) failed (0x%x)\n", __FUNCTION__,
            bip, ret);
        goto errout;
    }

    KDEBUG_IPC(0, "%s: rcv buf %d:%d:0x%x:0x%p\n", __FUNCTION__, slot,
        ptl_rx_me_table[slot], mdh, bip);

    return 0;

errout:
    DVS_TRACE("ipcfillE", slot, buf);

    return ret;
}

/*
 * ptl_str2phys - Translate a node token into a physical transport endpoint.
 */
static uint64_t
ptl_str2phys(char *tok)
{
    int pnode;
    int toklen = strlen(tok);
    char *transp = tok + (toklen-4);

    if (toklen > 4 && *transp == '@')  {
        if (strncmp(transp+1, "ptl", 3) != 0) {
            return pnode;
        }
    }

    sscanf(tok, "%d", &pnode);

    DVS_TRACE("ptls2p", (uint64_t)pnode, 0);
    DVS_TRACEP(tok, 0, 0);

    return (uint64_t)pnode;
}

/*
 * ptl_init - Initialize a portals network interface for use by dvs/ipc.
 *
 * This routine is called by the seastar ipc initialization routine to
 * setup the portals network interface. To do this, a number of receive
 * buffers are posted for use for inbound message traffic. A receive thread
 * is created to monitor and manage this inbound traffic. In addition,
 * transmit event queue is initialized for use in the management of outbound
 * message traffic.
 */
static int ptl_is_initialized = 0;
static int
ptl_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper, int num_mds)
{
    int ret, num_interfaces;
    ptl_ni_limits_t ptl_limits = {
        DVSIPC_MAX_MDS, DVSIPC_MAX_MDS,
        DVSIPC_MAX_EQS, 0,
        PTL_PT_INDEX_UNRELIABLE,
        DVSIPC_MAX_IOVEC,
        DVSIPC_MAX_RX_MDS, 0
    };

    upper_api = upper;
    ipc_num_mds = num_mds;

    KDEBUG_IPC(0, "%s: PtlInit \n", __FUNCTION__);

    /* Initialize portals interface */
    if ((ret=PtlInit(&num_interfaces)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlInit failed (0x%x)\n", __FUNCTION__, ret);
        return -EINVAL;
    }

    if (((ret=PtlNIInit(PTL_IFACE_SS, DVSIPC_PORTALS_PID, &ptl_limits,
        &ptl_limits, &ni)) != PTL_OK) && (ret != PTL_IFACE_DUP)) {
        printk(KERN_ERR "%s: PtlNIInit failed (0x%x)\n", __FUNCTION__, ret);
        return -EINVAL;
    }

    ptl_is_initialized = 1;

    if ((ret=PtlGetId(ni, &my_ptl_process_id)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlGetId failed (0x%x)\n", __FUNCTION__, ret);
        return -EINVAL;
    }

    *nodeidp = (uint64_t)my_ptl_process_id.nid;
    KDEBUG_IPC(0, "%s: nodeID=%Ld, pid=%d\n", __FUNCTION__, *nodeidp,
               my_ptl_process_id.pid);

    /* Setup the event queues */
    if ((ret=PtlEQAlloc(ni, DVSIPC_TX_EVENTQ_LEN,
        &ptl_tx_callback, &ptl_tx_eq)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlEQAlloc(tx) failed 0x%x\n", __FUNCTION__, ret);
        return -ENOSPC;
    }

    if ((ret=PtlEQAlloc(ni, DVSIPC_RX_EVENTQ_LEN,
        &ptl_rx_callback, &ptl_rx_eq)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlEQAlloc(tx) failed 0x%x\n",
            __FUNCTION__, ret);
        return -ENOSPC;
    }

    if ((ret=PtlEQAlloc(ni, DVSIPC_RMA_EVENTQ_LEN,
        &ptl_rma_callback, &ptl_rma_eq)) != PTL_OK) {
        printk(KERN_ERR "%s: PtlEQAlloc(rma) failed 0x%x\n", __FUNCTION__, ret);
        return -ENOSPC;
    }

    /*
     * Add a general backstop ME. This ME will catch all inbound requests that
     * got past all of the other receive buffers. In this case we need to
     * notify the originator that their request was dropped on the  floor.
     */
    if ((ret=ptl_build_backstop_me(&ptl_rx_me_guard, DVSIPC_RX_MATCHBITS,
        DVSIPC_IGNORE_NONE, (void*)DVSIPC_OVERFLOW_TAG)) < 0) {
        printk(KERN_ERR "%s: ptl_build_backstop_me failed (0x%x)\n",
            __FUNCTION__, ret);
        return -ENOSPC;
    }

    /*
     * Add a resend request ME.
     */
    if ((ret=ptl_build_backstop_me(&ptl_rx_me_resend, DVSIPC_NAK_MATCH,
        DVSIPC_IGNORE_NONE, (void*)DVSIPC_RESEND_REQ)) < 0) {
        printk(KERN_ERR "%s: ptl_build_backstop_me failed (0x%x)\n",
            __FUNCTION__, ret);
        return -ENOSPC;
    }

    /*
     * Add an orphan request ME. This ME/MD will be used as a backstop for
     * RMA operations from this node. If a mapped region is removed before
     * the server can service the request, this MD will catch the RMA operation
     * and provide an appropriate response.
     */
    if ((ret=ptl_build_backstop_me(&ptl_rx_me_orphan, DVSIPC_ORPH_MATCH,
        DVSIPC_IGNORE_ALL, (void*)DVSIPC_ORPH_REQ)) < 0) {
        printk(KERN_ERR "%s: ptl_build_backstop_me failed (0x%x)\n",
            __FUNCTION__, ret);
        return -ENOSPC;
    }

    DVS_TRACE("INITFL", 0, 0);

    return 0;
}

/*
 * ptl_term - Shutdown the portals interface.
 *
 */
static void
ptl_term(void) 
{
    if (ptl_is_initialized)
        (void)PtlNIFini(ni);
}

/*
 * Export lower interface.
 */

void
ipclower_send_nak(uint64_t nid, void *rqp) 
{
    ptl_send_nak(nid, rqp);
}

int
ipclower_tx_request(uint64_t nid, struct usiipc *rq,
			int resend_limit, int tx_timeout) 
{
    return ptl_tx_request(nid, rq, resend_limit, tx_timeout);
}

void *
ipclower_mapuvm(char *uvm, ssize_t length, int rw) 
{
    return ptl_mapuvm(uvm, length, rw);
}

int
ipclower_unmapuvm(void *handle) 
{
    return ptl_unmapuvm(handle);
}

void *
ipclower_rma_put(uint64_t node, char *to, char *from,
			ssize_t length, rma_info_t *ri, 
                        int timeout, int async) 
{
    return ptl_rma_put(node, to, from, length, ri, async);
}

void *
ipclower_rma_get(uint64_t node, char *to, char *from,
			ssize_t length, rma_info_t *ri, 
                        int timeout, int async) 
{
    return ptl_rma_get(node, to, from, length, ri, int async);
}

void
ipclower_rma_wait(rma_info_t *rip)
{
    ptl_rma_wait(rip);
}

int
ipclower_fill_rx_slot(int slot, void *buf, int size)
{
    return ptl_fill_rx_slot(slot, buf, size);
}

uint64_t
ipclower_str2phys(char *tok)
{
    return ptl_str2phys(tok);
}

int
ipclower_init(uint64_t *nodeidp, dvsipc_upper_api_t *upper, int num_mds)
{
    return ptl_init(nodeidp, upper, num_mds);
}

void
ipclower_term(void) 
{
    ptl_term();
}

EXPORT_SYMBOL(ipclower_send_nak);
EXPORT_SYMBOL(ipclower_tx_request);
EXPORT_SYMBOL(ipclower_mapuvm);
EXPORT_SYMBOL(ipclower_unmapuvm);
EXPORT_SYMBOL(ipclower_rma_put);
EXPORT_SYMBOL(ipclower_rma_get);
EXPORT_SYMBOL(ipclower_rma_wait);
EXPORT_SYMBOL(ipclower_fill_rx_slot);
EXPORT_SYMBOL(ipclower_str2phys);
EXPORT_SYMBOL(ipclower_init);
EXPORT_SYMBOL(ipclower_term);
