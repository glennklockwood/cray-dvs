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

/*
 * usiipc.h
 * Definitions shared by the client and server usi ipc
 */

#ifndef USIIPC_H
#define USIIPC_H

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file usiipc.h"
#endif /* __KERNEL__ */

extern void initialize_syscall_linkage(void);

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/syscalls.h>

#include <linux/version.h>
#ifdef CONFIG_CRAY_TRACE
#include <cray/craytrace.h>
#endif

#define suser() capable(CAP_SYS_ADMIN)
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/semaphore.h>

#include <stdarg.h>

extern int dvs_trace_idx;
#ifdef CONFIG_CRAY_TRACE
#define DVS_TRACE(str, a, b)            CRAYTRACE_BUF(dvs_trace_idx,         \
                                                CT_MAKENAME(str "      "),   \
                                                (a),(b))
#define DVS_TRACEP(str, a, b)           CRAYTRACE_BUF(dvs_trace_idx,         \
                                                ct_tag_from_string(str),(a), \
                                                (b))
#define DVS_TRACEL(str, a, b, c, d, e)  CRAYTRACEL_BUF(dvs_trace_idx,        \
                                                CT_MAKENAME(str "      "),   \
                                                (a),(b),(c),(d),(e))
#define DVS_TRACEPL(str, a, b, c, d, e) CRAYTRACE_BUF(dvs_trace_idx,         \
                                                ct_tag_from_string(str),(a), \
                                                (b), (c), (d), (e))
#else
#define DVS_TRACE(...)
#define DVS_TRACEP(...)
#define DVS_TRACEL(...)
#define DVS_TRACEPL(...)
#endif

extern void si_meminfo(struct sysinfo *);

#define USI_DEBUG_MALLOC 0	// Set to 1 to trace {kmalloc,kfree}_ssi calls

extern unsigned long dvs_debug_mask;

#define DVS_DEBUG_OFCLIENT	0x0001
#define DVS_DEBUG_OFSERVER	0x0002
#define DVS_DEBUG_PNCLIENT	0x0004
#define DVS_DEBUG_PNSERVER	0x0008
#define DVS_DEBUG_PNSUPER	0x0010
#define DVS_DEBUG_FSERR		0x0020
#define DVS_DEBUG_QUIESCE       0x0040
#define DVS_DEBUG_INFRA		0x0080
#define DVS_DEBUG_IPC		0x0100
#define DVS_DEBUG_KVMALLOC	0x0200
#define DVS_DEBUG_RPS		0x0400
/*
 * DVS_FOLLOW_MSG is a modifier for the other debug values, indicating
 * that they should be sent to the server for the server to use as well.
 */
#define DVS_DEBUG_FOLLOW_MSG	0x80000000 /* Bit 31 set */
#define DVS_DEBUG_MAX		12

struct dvs_debug_name {
	char *name;
	unsigned long flag;
};

static struct dvs_debug_name dvs_debug_names[DVS_DEBUG_MAX] __attribute__ ((unused)) = {
	{"OFC",	DVS_DEBUG_OFCLIENT},
	{"OFS",	DVS_DEBUG_OFSERVER},
	{"PNC",	DVS_DEBUG_PNCLIENT},
	{"PNS",	DVS_DEBUG_PNSERVER},
	{"SUP",	DVS_DEBUG_PNSUPER},
	{"FSE",	DVS_DEBUG_FSERR},
	{"QSC",	DVS_DEBUG_QUIESCE},
	{"INF",	DVS_DEBUG_INFRA},
	{"IPC",	DVS_DEBUG_IPC},
	{"KVM",	DVS_DEBUG_KVMALLOC},
	{"RPS",	DVS_DEBUG_RPS},
	{"FLW",	DVS_DEBUG_FOLLOW_MSG},
};

#include "common/log.h"
#include "common/usifunc.h"
#include "common/kernel/usisyscall.h"
#include "common/kernel/ipc_api.h"

typedef ipc_seqno_t dvs_tx_desc_t;

#define IC_TYPE_ETHERNET	0
#define IC_TYPE_MYRINET		1
#define IC_TYPE_QUADRICS	2
#define IC_TYPE_SEASTAR		3

#define SOURCE_NODE(msg) (msg)->source_node
#define REMOTE_IDENTITY(msg) (msg)->sender_identity
#define NO_IDENTITY	0
#define BOGUS_IDENTITY	1

#define REPLY_REQUESTED(__ipc) \
	(((__ipc)->reply_address != NULL) && ((__ipc)->reply_length != 0))

struct ipc_rma_get_request {
	struct usiipc ipcmsg;
	char	*from;
	char	*to;
	u64	rma;
	ssize_t	length;
	void	*rma_handle;
};

struct ipc_rma_get_reply {
	struct usiipc ipcmsg;
	int	rval;
	char	data[0]; /* must be [0] */
};

struct ipc_rma_put_request {
	struct usiipc ipcmsg;
	char	*from;
	char	*to;
	u64	rma;
	ssize_t	length;
	void	*rma_handle;
	char	data[0]; /* must be [0] */
};

struct ipc_rma_put_reply {
	struct usiipc ipcmsg;
	int	rval;
};

struct ipc_node_down {
	struct usiipc ipcmsg;
	int down_node;
};

#define CALLBACK_RMA_HANDLE ((void *)-1)
#define KERNEL_RMA_HANDLE ((void *)-2)

/* RMA definitions */
struct ipc_mapping {
	char    *addr;
	ssize_t length;
	int	rw;
	int	page_count;
	struct	page **pages;
	void	*prq;
	void	(*read_handler)(void *rq, int status,
				void *addr, size_t length);
	/* array of dma addresses */
	int     dma_length;  /* old sockipc stuff - 0 for LNet */
	u64     dma[1];
};

/* 
 * Structures to map RMA completion events to their
 * initiator.
 */
typedef enum {RMA_GET, RMA_PUT} rma_type_t;
typedef struct rma_info {
    struct list_head        list;
    struct semaphore        sema;
    int                     lnid;
    u64                     nid; 
    u64                     handle;
    u64                     length;
    rma_type_t              rma_type;
    int                     retval;
    void                    *transport_handle;
} rma_info_t;


int inode_data_server(struct inode *, int);
int inode_meta_server(struct inode *, int);

/* syscall api */
extern int identity_valid(int node, time_t identity);
extern int usi_transport_callback(int cmd, void *data);
extern int (*usi_callback)(int cmd, void *data);

/* kernel api */
extern dvs_tx_desc_t register_ipc_request(struct usiipc *request);

extern int ipc_rma_wait(rma_info_t *rip);

extern int ipc_get_params(int *ic_type, int *ic_limit);
extern int ipc_init(ssize_t *max_transport_msg_size);
extern void ipc_term(void);

/* virtual ipc ops definition */
struct ipc_operations {
	dvs_tx_desc_t (*regisrq) (struct usiipc *request);
	int (*sendrq) (struct usiipc *request);
	int (*sendrqa) (struct usiipc *request);
	int (*waitrqa) (struct usiipc *request);
	int (*sendrp) (struct usiipc *request,
		       struct usiipc *reply, int reply_size);
	void *(*mapkvm) (char *kvm, ssize_t length, int rw);
	int (*unmapkvm) (void *rma_handle);
	void *(*mapuvm) (char *uvm, ssize_t length, int rw);
	int (*unmapuvm) (void *rma_handle);
	void *(*rmaget) (int node, char *to, char *from, ssize_t length, 
                       void *rma_handle, int async);
	void *(*rmaput) (int node, char *to, char *from, ssize_t length, 
                       void *rma_handle, int async);
	void (*rmawait) (rma_info_t *rip);
	int (*get_params)(int *ic_type, int *ic_limit);
	void (*setup_rma) (struct rma_state *rmasp);
	int (*end_rma) (struct rma_state *rmasp);
	int (*init) (ssize_t *max_transport_msg_size);
	void (*term) (void);
	int (*identity_valid) (int, time_t);
	void (*block_thread) (void);
	void (*release_thread) (void);
};

void dump_request(struct usiipc *request);

/* IPC transport ops table - initialized by the transport layer */
extern struct ipc_operations *vipc;

extern ssize_t max_transport_msg_size;
extern int max_transport_msg_pages;
extern int wb_threshold_pages;

/* this nodes node number */
extern int usi_node_addr;

/* max nodes in configuration - assumed contiguous */
extern int max_nodes;

#ifdef CONFIG_CRAY_ACCOUNTING
#define DVS_LOG_APID current->csa_apid
#else
#define DVS_LOG_APID 0ULL
#endif

#define KDEBUG(flag, local_debug, fmt, args...) { if (dvs_debug_mask & flag || local_debug & flag) printk(KERN_INFO fmt, ## args); }

#define KDEBUG_OFC(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_OFCLIENT, local_debug, fmt, ## args)
#define KDEBUG_OFS(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_OFSERVER, local_debug, fmt, ## args)
#define KDEBUG_PNC(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_PNCLIENT, local_debug, fmt, ## args)
#define KDEBUG_PNS(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_PNSERVER, local_debug, fmt, ## args)
#define KDEBUG_SUP(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_PNSUPER,  local_debug, fmt, ## args)
#define KDEBUG_INF(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_INFRA,    local_debug, fmt, ## args)
#define KDEBUG_IPC(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_IPC,      local_debug, fmt, ## args)
#define KDEBUG_KVM(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_KVMALLOC, local_debug, fmt, ## args)
#define KDEBUG_RPS(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_RPS,      local_debug, fmt, ## args)
#define KDEBUG_QSC(local_debug, fmt, args...) KDEBUG(DVS_DEBUG_QUIESCE,  local_debug, fmt, ## args)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define KDEBUG_FSE(local_debug, fmt, args...) \
	do {				\
		KDEBUG(DVS_DEBUG_FSERR, local_debug, "DVS: APID: %llu UID: %u " fmt, DVS_LOG_APID, CRED->uid, ## args); \
		DVS_LOG("APID: %llu UID: %u " fmt, DVS_LOG_APID, CRED->uid, ## args);	\
	} while(0)
#else
#define KDEBUG_FSE(local_debug, fmt, args...) \
	do {				\
		KDEBUG(DVS_DEBUG_FSERR, local_debug, "DVS: APID: %llu UID: %u " fmt, DVS_LOG_APID, __kuid_val(CRED->uid), ## args);	\
		DVS_LOG("APID: %llu UID: %u " fmt, DVS_LOG_APID, __kuid_val(CRED->uid), ## args);	\
	} while(0)
#endif

static char *rq_cmd_names[] = {
    "RQ_FILE",
    "RQ_REPLY",
    "RQ_RMA_GET",
    "RQ_RMA_PUT",
    "RQ_CALLBACK",
    "RQ_IPC_FAILURE",
    "RQ_RESOURCE",
    "RQ_IPC_NODE_UP",
    "RQ_REPLY_ERROR",
    "RQ_IPC_NODE_DOWN",
    "RQ_IPC_HEARTBEAT",
    "RQ_WAITING_REPLY",
    "RQ_RESOURCE_CLIENT",
    "RQ_IPC_DISPOSE",
    "RQ_SUSPECT",
    "RQ_DSD",
    "RQ_DSDB",
    "RQ_DSDC",
};

static inline char * 
rq_cmd_name(struct usiipc *rq)
{
    int cmd = rq->command;

    if (cmd >= RQ_FILE && cmd < RQ_LAST_IN_LIST) {
        return rq_cmd_names[cmd-RQ_FILE];
    } else {
        return "BOGUS";
    }
}

static inline void
dvs_update_timespec(struct timespec *old, struct timespec *new)
{
	if (timespec_compare(old, new) < 0)
		*old = *new;
}

static inline void sleep(int seconds)
{
	wait_queue_head_t wqh;
	DEFINE_WAIT(wait);

	init_waitqueue_head(&wqh);
        prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
        schedule_timeout(seconds*HZ);
        finish_wait(&wqh, &wait);
}

static inline void interruptible_sleep(int seconds)
{
	wait_queue_head_t wqh;
	DEFINE_WAIT(wait);

	init_waitqueue_head(&wqh);
        prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
        schedule_timeout(seconds*HZ);
        finish_wait(&wqh, &wait);
}

/* nap -- sleep .1
 * for when a sleep(1) is just too darn long
 * and a yield() is too short
 */
static inline void nap(void)
{
	wait_queue_head_t wqh;
	DEFINE_WAIT(wait);

	init_waitqueue_head(&wqh);
        prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
        schedule_timeout(HZ/10);
        finish_wait(&wqh, &wait);
}

static inline void
dump_rma_state(struct rma_state *rmasp)
{
	sleep(1);
	KDEBUG_IPC(0, "dump_rma_state: dumping state struct at 0x%p\n", rmasp);
	KDEBUG_IPC(0, "    handle = 0x%p\n", rmasp->handle);
	KDEBUG_IPC(0, "    buffer = 0x%p\n", rmasp->buffer);
	KDEBUG_IPC(0, "    valid_size = 0x%x\n", rmasp->valid_size);
	KDEBUG_IPC(0, "    remote_addr = 0x%p\n", rmasp->remote_addr);
	KDEBUG_IPC(0, "    flush = %d\n", rmasp->flush);
	KDEBUG_IPC(0, "    node = %d\n", rmasp->node);
	KDEBUG_IPC(0, "    bsz = %d\n", rmasp->bsz);
	KDEBUG_IPC(0, "    buffer_remote_start = 0x%p\n", rmasp->buffer_remote_start);
	sleep(1);
}

static inline void
_vfree_ssi(void *buf, const char *function, int line)
{
	KDEBUG_KVM(0, "_vfree_ssi:     0x%p %s\n", buf, function);

	vfree(buf);
}

static inline void 
_kfree_ssi(void *buf, const char *function, int line)
{
	KDEBUG_KVM(0, "_kfree_ssi:     0x%p %s\n", buf, function);

	if (unlikely(is_vmalloc_addr(buf))) {
		_vfree_ssi(buf, function, line);
	}
	else {
		kfree(buf);
	}
}

#define kfree_ssi(buf)		_kfree_ssi(buf, __FUNCTION__, __LINE__)
#define vfree_ssi(buf)		_vfree_ssi(buf, __FUNCTION__, __LINE__)

#undef kfree
#undef vfree
#define kfree(buf)		_kfree_ssi(buf, __FUNCTION__, __LINE__)
#define vfree(buf)		_vfree_ssi(buf, __FUNCTION__, __LINE__)

static inline void *
_vmalloc_ssi(unsigned long size, const char *function, const char *file, int line)
{
	void *v = NULL;
	
	v = vmalloc(size);
	if (v) {
		memset(v, 0, size);
	}

	KDEBUG_KVM(0, "_vmalloc_ssi: 0x%p func: %s file: %s line: %d size: %ld\n",
	           v, function, file, line, size);

	return v;
}

static inline void *
_kmalloc_ssi(size_t size, int flags, const char *function, const char *file, int line)
{
	void *v = NULL;
	
	v = kzalloc(size, flags);
	KDEBUG_KVM(0, "_kmalloc_ssi: 0x%p func: %s file: %s line: %d size: %ld\n",
	           v, function, file, line, size);

	/* 
	 * vmalloc can sleep indefinitely, so don't do a fall back if GFP_ATOMIC
	 * is specified as a flag. This logic may need to be updated if DVS ends
	 * up using flags beyond GFP_KERNEL and GFP_ATOMIC.
	 */
	if (v || flags == GFP_ATOMIC) {
		return v;
	}

	return _vmalloc_ssi(size, function, file, line);
}

#define kmalloc_ssi(sz, fl)	_kmalloc_ssi  (sz, fl, __FUNCTION__, __FILE__, __LINE__)
#define vmalloc_ssi(sz)		_vmalloc_ssi  (sz,     __FUNCTION__, __FILE__, __LINE__)

static inline void free_msg(void *msg)
{
	if (unlikely(!msg)) {
		KDEBUG_KVM(0, "tried to free NULL pointer at %s:%d\n",
			__FILE__, __LINE__);
	}
	else {
		((struct usiipc *) msg)->state = ST_FREE;
		kfree(msg);
	}
}

#endif
