/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2011, 2013-2018 Cray Inc. All Rights Reserved.
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
 * The virtual ipc layer
 * The routines here just forward the request to the ipc implementation
 * previously configured
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include "common/log.h"
#include "common/sync.h"
#include "common/usierrno.h"
#include "common/ssi_proc.h"
#include "common/kernel/kernel_interface.h"
#include "common/kernel/usiipc.h"

MODULE_LICENSE("GPL");

/* The transport layer init sets the ops table pointer during it's
 * initialization */
struct ipc_operations *vipc = NULL;

/* forward */
static void *generic_map_ipc_user_memory(char *uvm, ssize_t length, int rw);
static int generic_unmap_ipc_user_memory(void *handle);
static void *generic_map_ipc_kernel_memory(char *kvm, ssize_t length, int rw);
static int generic_unmap_ipc_kernel_memory(void *handle);

static inline void setup_request(struct usiipc *request)
{
	request->original_request = request;
	request->free_required = 0;
	request->async = 0;
	request->priority = kernel_get_task_nice(current);
	request->sender_pid = current->pid;
	request->jiffies_val = jiffies;
}

static inline void setup_reply(struct usiipc *reply)
{
	reply->free_required = 0;
	reply->priority = kernel_get_task_nice(current);
	reply->sender_pid = current->pid;
}

int ipc_init(ssize_t *max_transport_msg_size)
{
	int ret;
	if (vipc && vipc->init)
		ret = vipc->init(max_transport_msg_size);
	else {
		printk("%s not initialized\n", __func__);
		ret = -1;
	}
	return ret;
}

void ipc_term(void)
{
	vipc->term();
}

dvs_tx_desc_t register_ipc_request(struct usiipc *request)
{
	return (vipc->regisrq(request));
}

/*
 * send an ipc request to the specified node
 */
int send_ipc_request(int node, int command, struct usiipc *request,
		     int request_size, struct usiipc *reply, int reply_size,
		     time_t identity)
{
	int rval;

	if ((reply == NULL) || (reply_size <= 0)) {
		printk(KERN_ERR "DVS: send_ipc_request: IPC synchronous "
				"message without reply\n");
		return -USIERR_IPC_PROTO;
	}

	setup_request(request);
	if (dvs_debug_mask & DVS_DEBUG_FOLLOW_MSG)
		request->debug = dvs_debug_mask;
	request->request_length = request_size;
	request->target_node = node;
	request->reply_address = reply;
	request->reply_length = reply_size;
	request->command = command;
	request->receiver_identity = identity;

	if (request->notify_of_abnormal_send) {
		printk(KERN_ERR
		       "DVS: send_ipc_request: IPC synchronous "
		       "unexpectedly requests abnormal notification!\n");
	}

	if ((identity != 0) && (!identity_valid(node, identity))) {
		rval = -EHOSTDOWN;
		KDEBUG_IPC(0,
			   "DVS: send_ipc_request forced EHOSTDOWN node %s\n",
			   SSI_NODE_NAME(node));
	} else {
		rval = vipc->sendrq(request);
		if (rval < 0) {
			KDEBUG_IPC(0,
				   "DVS: send_ipc_request failed node %s rval "
				   "%d\n",
				   SSI_NODE_NAME(node), rval);
		}
		dvsdebug_stat_update(NULL, DVSSYS_STAT_IPC_REQUEST, 0, rval);
	}

	return (rval);
}

/*
 * send an ipc request to the specified node asynchronously
 */
int send_ipc_request_async(int node, int command, struct usiipc *request,
			   int request_size, struct usiipc *reply,
			   int reply_size, time_t identity)
{
	int rval;

	setup_request(request);
	request->request_length = request_size;

	if (request->notify_of_abnormal_send &&
	    (request->retry || (request->target_node != node))) {
		request->abnormal_handler(request, node);
	}
	request->target_node = node;

	if (dvs_debug_mask & DVS_DEBUG_FOLLOW_MSG)
		request->debug = dvs_debug_mask;
	request->reply_address = reply;
	request->reply_length = reply_size;
	request->command = command;
	request->async = 1;
	request->receiver_identity = identity;
#ifdef IPC_DUMP_EVENTS
	KDEBUG_IPC(0, "DVS: send_ipc_request_async: request contents\n");
	dump_request(request);
#endif
	if ((identity != 0) && (!identity_valid(node, identity))) {
		rval = -EHOSTDOWN;
		KDEBUG_IPC(0,
			   "DVS: send_ipc_request_async forced EHOSTDOWN node "
			   "%s %ld %d \n",
			   SSI_NODE_NAME(node), identity,
			   identity_valid(node, identity));
	} else {
		rval = vipc->sendrqa(request);
		if (rval < 0) {
			KDEBUG_IPC(0,
				   "DVS: send_ipc_request_async: failed node "
				   "%s rval %d\n",
				   SSI_NODE_NAME(node), rval);
		}
		dvsdebug_stat_update(NULL, DVSSYS_STAT_IPC_REQUEST_ASYNC, 0,
				     rval);
	}
	return (rval);
}

/*
 * wait for an asynchronous request to complete
 */
int wait_for_async_request(struct usiipc *request)
{
	DVS_BUG_ON(request->state != ST_SEND_COMPL &&
		   request->state != ST_WAIT_CLEANUP);

	if (request->reply_address == NULL) {
		printk(KERN_ERR "DVS: wait_for_async_request: Cannot wait for "
				"a null reply\n");
		return (-USIERR_IPC_PROTO);
	}

	return vipc->waitrqa(request);
}

/*
 * send an ipc reply to the node specified in the original request
 * if nocopy is false, the reply message will be copied by the ipc layer and
 * the original is not modified if nocopy is true, the reply message is "given"
 * to the ipc layer and will be freed (must have been kmalloc'd)
 */
int send_ipc_reply(struct usiipc *request, struct usiipc *reply, int reply_size,
		   int nocopy)
{
	int rval;

	setup_reply(reply);
	reply->free_required = nocopy;
	reply->command = RQ_REPLY;
	if (request->process_time_us > 0)
		reply->process_time_us =
			dvs_time_get_us() - request->process_time_us;
	reply->queue_time_us = request->queue_time_us;
	reply->target_node = request->source_node;
	reply->request_length = reply_size;
	reply->reply_address = request->reply_address;
	reply->reply_length = request->reply_length;
	reply->wakeup_word = request->wakeup_word;
	reply->receiver_identity = request->sender_identity;

	/*
	 * Sanity check the reply lengths
	 * Must avoid corrupting memory
	 */
	if (reply_size > request->reply_length) {
		printk(KERN_ERR "DVS: send_ipc_reply: reply length "
				"error: %d %d\n",
		       reply_size, request->reply_length);
		if (reply->free_required) {
			free_msg(reply);
		}
		return (-USIERR_IPC_PROTO);
	}

#ifdef IPC_DUMP_EVENTS
	KDEBUG_IPC(0, "DVS: send_ipc_reply: reply contents\n");
	dump_request(reply);
#endif
	/*
	 * ignore reply if request did want one
	 */
	if (request->reply_address == NULL) {
		if (reply->free_required) {
			free_msg(reply);
		}
		return (0);
	}

	rval = vipc->sendrp(request, reply, reply_size);
	dvsdebug_stat_update(NULL, DVSSYS_STAT_IPC_REPLY, 0, rval);

	return (rval);
}

int ipc_get_params(int *ic_type, int *ic_limit)
{
	if (vipc->get_params) {
		return (vipc->get_params(ic_type, ic_limit));
	} else {
		return (-USIERR_IPC_PROTO);
	}
}

/*
 * create an IPC mapping for user memory
 */
void *map_ipc_user_memory(char *uvm, ssize_t length, int rw)
{
	if (vipc->mapuvm) {
		return vipc->mapuvm(uvm, length, rw);
	} else {
		/* must use generic in all other cases */
		return generic_map_ipc_user_memory(uvm, length, rw);
	}
}

/*
 * Free an IPC mapping
 */
int unmap_ipc_user_memory(void *handle)
{
	if (handle == NULL)
		return 0;

	if (vipc->unmapuvm) {
		return vipc->unmapuvm(handle);
	} else {
		return generic_unmap_ipc_user_memory(handle);
	}
}

/*
 * create an IPC mapping for user memory
 */
void *map_ipc_kernel_memory(char *kvm, ssize_t length, int rw)
{
	if (vipc->mapkvm) {
		return vipc->mapkvm(kvm, length, rw);
	} else {
		/* must use generic in all other cases */
		return generic_map_ipc_kernel_memory(kvm, length, rw);
	}
}

/*
 * Free an IPC mapping
 */
int unmap_ipc_kernel_memory(void *handle)
{
	if (handle == NULL)
		return 0;

	if (vipc->unmapkvm) {
		return vipc->unmapkvm(handle);
	} else {
		return generic_unmap_ipc_kernel_memory(handle);
	}
}

void *map_ipc_memory(char *addr, ssize_t length, int rw)
{
	if ((unsigned long)addr >= TASK_SIZE) {
		return map_ipc_kernel_memory(addr, length, rw);
	} else {
		return map_ipc_user_memory(addr, length, rw);
	}
}

int unmap_ipc_memory(void *addr, void *handle)
{
	if (handle == NULL)
		return 0;

	if ((unsigned long)addr >= TASK_SIZE) {
		return unmap_ipc_kernel_memory(handle);
	} else {
		return unmap_ipc_user_memory(handle);
	}
}

/*
 * Send get request to remote node
 */
int ipc_rma_get(int node, char *to, char *from, ssize_t length,
		void *rma_handle)
{
	if (vipc->rmaget) {
		return (PTR_ERR(
			vipc->rmaget(node, to, from, length, rma_handle, 0)));
	} else {
		return (-USIERR_IPC_PROTO);
	}
}

/*
 * Send put request to remote node
 */
int ipc_rma_put(int node, char *to, char *from, ssize_t length,
		void *rma_handle)
{
	if (vipc->rmaput) {
		return (PTR_ERR(
			vipc->rmaput(node, to, from, length, rma_handle, 0)));
	} else {
		return (-USIERR_IPC_PROTO);
	}
}

/*
 * Send get request to remote node
 */
void *ipc_rma_get_async(int node, char *to, char *from, ssize_t length,
			void *rma_handle)
{
	if (vipc->rmaget) {
		return (vipc->rmaget(node, to, from, length, rma_handle, 1));
	} else {
		return (ERR_PTR(-USIERR_IPC_PROTO));
	}
}

/*
 * Send put request to remote node
 */
void *ipc_rma_put_async(int node, char *to, char *from, ssize_t length,
			void *rma_handle)
{
	if (vipc->rmaput) {
		return (vipc->rmaput(node, to, from, length, rma_handle, 1));
	} else {
		return (ERR_PTR(-USIERR_IPC_PROTO));
	}
}

int ipc_rma_wait(rma_info_t *rip)
{
	if (vipc->rmawait) {
		vipc->rmawait(rip);
	} else {
		return (-USIERR_IPC_PROTO);
	}
	return 0;
}

void register_ipc_read_complete(void *handle,
				void (*read_handler)(void *rq, int status,
						     void *addr, size_t length),
				void *rq)
{
	struct ipc_mapping *ipcmap = (struct ipc_mapping *)handle;

	ipcmap->read_handler = read_handler;
	ipcmap->prq = rq;
}

static void *generic_map_ipc_user_memory(char *uvm, ssize_t length, int rw)
{
	struct ipc_mapping *ipcmap;
	struct page **pages;
	void *retp;
	int npages;
	int i;
	int ret;
	int offset;

	retp = NULL;

	/*
	 * Note that uvm here is really the address of the user's buffer which
	 * could be non-page aligned.  Keep track of the number of pages and
	 * use that value in the unmapping.
	 */
	offset = (uint64_t)uvm & (PAGE_SIZE - 1);
	npages = (offset + length + (PAGE_SIZE - 1)) / PAGE_SIZE;

	pages = (struct page **)kmalloc_ssi(npages * sizeof(struct page *),
					    GFP_KERNEL);
	if (!pages) {
		goto out;
	}

	ipcmap =
		kmalloc_ssi(sizeof(struct ipc_mapping) + (npages * sizeof(u64)),
			    GFP_KERNEL);
	if (!ipcmap) {
		kfree_ssi(pages);
		goto out;
	}

	down_read(&current->mm->mmap_sem);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 73)
	ret = get_user_pages(current, current->mm, (unsigned long)uvm, npages,
			     rw == READ, 0, pages, NULL);
#else
	ret = get_user_pages((unsigned long)uvm, npages,
			     (rw == READ ? FOLL_WRITE : 0), pages, NULL);
#endif
	up_read(&current->mm->mmap_sem);

	if (((ret * PAGE_SIZE) < length) || (ret != npages)) {
		KDEBUG_IPC(0, "DVS: ipc failed to map user buffer\n");
		goto err;
	}

	ipcmap->addr = uvm;
	ipcmap->length = length;
	ipcmap->pages = pages;
	ipcmap->page_count = npages;
	ipcmap->rw = rw;
	ipcmap->dma_length = ret;

	for (i = 0; i < ipcmap->dma_length /* also page_count */; i++) {
		ipcmap->dma[i] = page_to_phys(pages[i]);
	}
	retp = ipcmap;

out:
	return retp;

err:
	for (i = 0; i < ret; i++) {
		put_page(pages[i]);
	}
	kfree_ssi(ipcmap);
	kfree_ssi(pages);

	/* Pass error codes back up to the caller. */
	if (ret < 0) {
		return (ERR_PTR(ret));
	}

	return NULL;
}

static int generic_unmap_ipc_user_memory(void *handle)
{
	struct ipc_mapping *ipcmap = handle;
	int i;

	if (handle == CALLBACK_RMA_HANDLE || ipcmap == NULL) {
		return 0;
	}

	for (i = 0; i < ipcmap->page_count /* also dma_length */; i++) {
		/*
		 * If we did a read, mark the page dirty so that we don't
		 * end up discarding the data we need.
		 */
		if (ipcmap->rw == READ) {
			set_page_dirty_lock(ipcmap->pages[i]);
		}
		put_page(ipcmap->pages[i]);
	}

	kfree_ssi(ipcmap->pages);
	kfree_ssi(ipcmap);

	return 0;
}

static void *generic_map_ipc_kernel_memory(char *kvm, ssize_t length, int rw)
{
	struct ipc_mapping *ipcmap;
	struct page **pages;
	void *retp;
	int i, npages, offset;

	retp = NULL;

	offset = (uint64_t)kvm & (PAGE_SIZE - 1);
	npages = (offset + length + (PAGE_SIZE - 1)) / PAGE_SIZE;

	pages = kmalloc_ssi(npages * sizeof(struct page *), GFP_KERNEL);
	if (pages == NULL)
		return NULL;

	ipcmap =
		kmalloc_ssi(sizeof(struct ipc_mapping) + (npages * sizeof(u64)),
			    GFP_KERNEL);
	if (ipcmap == NULL) {
		kfree_ssi(pages);
		return NULL;
	}

	ipcmap->addr = kvm;
	ipcmap->length = length;
	ipcmap->pages = pages;
	ipcmap->page_count = npages;
	ipcmap->rw = rw;
	ipcmap->dma_length = npages;

	kvm -= offset;

	for (i = 0; i < npages; i++) {
		if (is_vmalloc_addr(kvm)) {
			ipcmap->pages[i] = vmalloc_to_page(kvm);
		} else if (virt_addr_valid(kvm)) {
			ipcmap->pages[i] = virt_to_page(kvm);
		} else {
			DVS_BUG();
		}

		ipcmap->dma[i] = page_to_phys(pages[i]);
		kvm += (i * PAGE_SIZE);
	}

	return ipcmap;
}

static int generic_unmap_ipc_kernel_memory(void *handle)
{
	struct ipc_mapping *ipcmap = handle;

	if (handle == CALLBACK_RMA_HANDLE || ipcmap == NULL)
		return 0;

	kfree_ssi(ipcmap->pages);
	kfree_ssi(ipcmap);

	return 0;
}

int count_ipc_memory(void *handle)
{
	struct ipc_mapping *ipcmap = handle;

	if (handle == CALLBACK_RMA_HANDLE)
		return (0);

	return (ipcmap->dma_length);
}

void build_rma_list(void *handle, u64 *pages)
{
	struct ipc_mapping *ipcmap = handle;
	int i;

	if (handle == CALLBACK_RMA_HANDLE)
		return;

	for (i = 0; i < ipcmap->dma_length; i++) {
		pages[i] = ipcmap->dma[i];
	}
}

void setup_rma(struct rma_state *rmasp, int node, void *handle,
	       char *remote_addr, int flush)
{
	KDEBUG_IPC(
		0,
		"DVS: setup_rma: remap 0x%p, node %s, handle 0x%p, raddr 0x%p, "
		" flush %d\n",
		rmasp, SSI_NODE_NAME(node), handle, remote_addr, flush);

	rmasp->handle = handle;
	rmasp->node = node;
	rmasp->buffer = NULL;
	rmasp->valid_size = 0;
	rmasp->remote_addr = remote_addr;
	rmasp->flush = flush;

	if (vipc->setup_rma) {
		vipc->setup_rma(rmasp);
	}
}

int end_rma(struct rma_state *rmasp, void *handle)
{
	int rval = 0;
	if (rmasp->handle != handle) {
		printk(KERN_ERR "DVS: end_rma: handle mismatch\n");
		rmasp->flush = 0; /* avoid flush RMA for busted handle */
		rval = -EINVAL;
	}

	if (vipc->end_rma) {
		int ret;
		ret = vipc->end_rma(rmasp);
		if (rval == 0) {
			rval = ret; /* propagate end_rma errors */
		}
	}
	return rval;
}

#define DUMP_VERBOSE 0
void dump_request(struct usiipc *request)
{
	KDEBUG_IPC(0, "DVS: dump_request: dumping request at 0x%p:\n", request);
#if DUMP_VERBOSE
	sleep(1);
	KDEBUG_IPC(0, "    request_length %d\n", request->request_length);
	KDEBUG_IPC(0, "    target_node %s\n",
		   SSI_NODE_NAME(request->target_node));
	KDEBUG_IPC(0, "    source_node %s\n",
		   SSI_NODE_NAME(request->source_node));
	KDEBUG_IPC(0, "    reply_address 0x%p\n", request->reply_address);
	KDEBUG_IPC(0, "    reply_length %d\n", request->reply_length);
	KDEBUG_IPC(0, "    wakeup_word 0x%p\n", request->wakeup_word);
#endif
	KDEBUG_IPC(0, "    command %d (%s)\n", request->command,
		   rq_cmd_name(request));
#if DUMP_VERBOSE
	KDEBUG_IPC(0, "    callback_command %d\n", request->callback_command);
	KDEBUG_IPC(0, "    free_required %d\n", request->free_required);
	KDEBUG_IPC(0, "    async %d\n", request->async);
	KDEBUG_IPC(0, "    next 0x%p\n", request->next);
	KDEBUG_IPC(0, "    prev 0x%p\n", request->prev);
	KDEBUG_IPC(0, "    callback 0x%p\n", request->callback);
	KDEBUG_IPC(0, "    original_request 0x%p\n", request->original_request);
	KDEBUG_IPC(0, "    priority %ld\n", request->priority);
	KDEBUG_IPC(0, "    msgwait 0x%p\n", &request->msgwait);
	KDEBUG_IPC(0, "    sender_identity %ld\n", request->sender_identity);
	KDEBUG_IPC(0, "    receiver_identity %ld\n",
		   request->receiver_identity);
	KDEBUG_IPC(0, "    sender_pid %d\n", request->sender_pid);
	sleep(1);
#endif
}

int identity_valid(int node, time_t identity)
{
	int rval;

	rval = vipc->identity_valid(node, identity);

	return rval;
}

void ipc_block_thread(void)
{
	return vipc->block_thread();
}

void ipc_release_thread(void)
{
	return vipc->release_thread();
}

EXPORT_SYMBOL(register_ipc_request);
EXPORT_SYMBOL(send_ipc_request);
EXPORT_SYMBOL(send_ipc_request_async);
EXPORT_SYMBOL(send_ipc_reply);
EXPORT_SYMBOL(wait_for_async_request);
EXPORT_SYMBOL(ipc_get_params);
EXPORT_SYMBOL(map_ipc_user_memory);
EXPORT_SYMBOL(unmap_ipc_user_memory);
EXPORT_SYMBOL(map_ipc_kernel_memory);
EXPORT_SYMBOL(unmap_ipc_kernel_memory);
EXPORT_SYMBOL(map_ipc_memory);
EXPORT_SYMBOL(unmap_ipc_memory);
EXPORT_SYMBOL(ipc_rma_get);
EXPORT_SYMBOL(ipc_rma_put);
EXPORT_SYMBOL(ipc_rma_get_async);
EXPORT_SYMBOL(ipc_rma_put_async);
EXPORT_SYMBOL(register_ipc_read_complete);
EXPORT_SYMBOL(count_ipc_memory);
EXPORT_SYMBOL(build_rma_list);
EXPORT_SYMBOL(setup_rma);
EXPORT_SYMBOL(end_rma);
EXPORT_SYMBOL(ipc_init);
EXPORT_SYMBOL(ipc_term);
EXPORT_SYMBOL(ipc_block_thread);
EXPORT_SYMBOL(ipc_release_thread);
EXPORT_SYMBOL(dump_request);
EXPORT_SYMBOL(identity_valid);
