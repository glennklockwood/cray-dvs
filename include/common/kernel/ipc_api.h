/*
 * Copyright 2014-2017 Cray Inc. All Rights Reserved.
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
 *   NOTE: IF you change, add or remove anything from this file make sure that
 *         DVSNET-IF still works.  Modifiy DVSNET-IF as needed.
 *         include/dvsnet-if-ipc-api.h
 */

#ifndef IPC_API_H
#define IPC_API_H

#include <linux/semaphore.h>
#include <linux/list.h>

/* limited by transports */
#define MAX_MSG_SIZE (34*1024)

/* reply copy options */
#define REPLY_COPY 0
#define REPLY_NOCOPY 1

/* this node's node number */
extern int usi_node_addr;

/* max nodes in configuration - assumed contiguous */
extern int max_nodes;

/*
 * State:
 *
 * A macro-level view of where this message is at.
 *
 * It's possible that at some point we'd want state to be an atomic
 * variable but for the moment we're typically either holding a lock
 * to protect the message or we know we're the only one using it.
 *
 * We have three versions of states.  Client, server and common.
 */
enum {
    /* Common */
    ST_INITIAL = 0,  /* ensure it's in this state after a malloc */
    ST_WAIT_QUEUED,
    ST_WAITING,
    ST_SEND_COMPL,
    ST_WAIT_CLEANUP,
    ST_WAIT_COMPL,
    ST_FREE,

    /* Client */

    /* Server */
    ST_SV_RECEIVED,
    ST_SV_MSG_QUEUED,
    ST_SV_MSG_ACTIVE,
    ST_SV_MSG_PROCESSED,

    ST_END,
};

enum dvsipc_instance_id {
	DVSIPC_INSTANCE_DVS,
	DVSIPC_INSTANCE_KDWFS,
	DVSIPC_INSTANCE_KDWFSB,
	DVSIPC_INSTANCE_KDWCFS,
	DVSIPC_INSTANCE_MAX
};

typedef uint64_t ipc_seqno_t;

#define SIZEOF_DEBUG_SEMAPHORE 96
struct usiipc {
	ipc_seqno_t seqno;
	unsigned short retry;
	unsigned int usiipc_len;
	unsigned long debug;
	int	state;
	int	rval;
	int	request_length;
	int	target_node;
	int	source_node;
	ipc_seqno_t source_seqno;
	void	*reply_address;
	int	reply_length;
	void	*wakeup_word;
	int	instance_id;
	int	command;
	int	callback_command;
	short	free_required, async, notify_of_abnormal_send;
	void	(*abnormal_handler)(struct usiipc *freq, int to_node);
	struct	usiipc *next, *prev;
	struct	usiipc *callback, *original_request, *source_request;
	long	priority;
	union {
		struct semaphore msgwait;
		char non_debug_pad[SIZEOF_DEBUG_SEMAPHORE];
	};
	time_t	sender_identity, receiver_identity;
	pid_t	sender_pid;
	void	*transport_handle;
	struct list_head active_rx;
	/*
	 * dual purpose field. For file requests, this holds the jiffies value
	 * for when the request was sent. For file replies, this holds sync
	 * timing information.
	 */
	unsigned long jiffies_val;
	char	body[0];
};

struct rma_state {
	void	*handle;
	char	*buffer;
	int	valid_size;
	char	*remote_addr;
	int	flush;
	int	node;
	int	bsz;
	char	*buffer_remote_start;
};

extern int send_ipc_request (int node, int command,
			     struct usiipc *request, int request_size,
			     struct usiipc *reply, int reply_size,
			     time_t identity);
extern int send_ipc_callback(int node, int command,
			     struct usiipc *request, int request_size,
			     struct usiipc *reply, int reply_size,
			     time_t identity);
extern int send_ipc_request_async (int node, int command,
				   struct usiipc *request, int request_size,
				   struct usiipc *reply, int reply_size,
				   time_t identity);
extern int wait_for_async_request(struct usiipc *request);
extern int send_ipc_reply (struct usiipc *request,
			   struct usiipc *reply, int reply_size, int nocopy);
extern void *map_ipc_user_memory(char *uvm, ssize_t length, int rw);
extern int unmap_ipc_user_memory(void *rma_handle);
extern void *map_ipc_kernel_memory(char *kvm, ssize_t length, int rw);
extern int unmap_ipc_kernel_memory(void *rma_handle);
extern void *map_ipc_memory(char *addr, ssize_t length, int rw);
extern int unmap_ipc_memory(void *addr, void *rma_handle);
extern int count_ipc_memory(void *rma_handle);
extern void build_rma_list(void *rma_handle, u64 *pages);
extern int ipc_rma_get(int node, char *to, char *from, ssize_t length,
		       void *rma_handle);
extern int ipc_rma_put(int node, char *to, char *from, ssize_t length,
		       void *rma_handle);
extern void *ipc_rma_get_async(int node, char *to, char *from, ssize_t length, 
                               void *rma_handle);
extern void *ipc_rma_put_async(int node, char *to, char *from, ssize_t length, 
                               void *rma_handle);
extern void register_ipc_read_complete(void *rma_handle,
		void (*read_handler)(void *rq, int status,
					void *addr, size_t length),
		void *rq);

extern void setup_rma(struct rma_state *, int, void *, char *, int);
extern int end_rma(struct rma_state *, void *);

void *dvs_alloc_buf(int size);
void dvs_free_buf(void *buf);
void *dvs_direct_buf_alloc(int count, struct page ***pglist, void **mmva);
void dvs_direct_buf_free(int count, struct page **pages, void *mmva, void *kva);

extern void ipc_block_thread(void);
extern void ipc_release_thread(void);

extern int dvsipc_name2nid(char *name);
#endif
