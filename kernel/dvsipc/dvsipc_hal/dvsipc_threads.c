/*
 * Copyright 2015-2016,2018 Cray Inc. All Rights Reserved.
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
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/kmod.h>

#include "common/sync.h"
#include "common/log.h"
#include "common/kernel/kernel_interface.h"
#include "dvs/kernel/usifile.h"
#include "dvsipc.h"
#include "dvsipc_threads.h"
#include "dvsipc_msg_queue.h"

#include "common/dvs_dev_ioctl.h"

/*
 * Change what state the thread is in. The main states are busy and idle,
 * corresponding to whether the thread is processing a message. When the state
 * is changed, we adjust the state counts in the thread_pool struct and add the
 * thread to the proper list.
 */
int dvsipc_set_thread_state(struct dvsipc_thread *thread,
			    enum dvsipc_thread_state state)
{
	struct dvsipc_thread_pool *thread_pool;
	unsigned long flags;

	thread_pool = thread->thread_pool;

	spin_lock_irqsave(&thread_pool->lock, flags);
	if (thread->state == state) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return -EEXIST;
	}

	/* Don't let a thread escape the destroy state unless it's exiting */
	if (thread->state == DVSIPC_THREAD_DESTROY &&
	    state != DVSIPC_THREAD_EXIT) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	if (!list_empty(&thread->state_list)) {
		thread_pool->state_counts[thread->state] -= 1;
		list_del_init(&thread->state_list);
	}

	list_add_tail(&thread->state_list, &thread_pool->state_lists[state]);
	thread_pool->state_counts[state] += 1;
	thread->state = state;
	thread->timestamp = jiffies;

	spin_unlock_irqrestore(&thread_pool->lock, flags);

	return 0;
}

/*
 * Once a thread has been created, run it through here to set up some info.
 */
struct dvsipc_thread *dvsipc_initialize_thread(
		struct dvsipc_thread_pool *thread_pool)
{
	struct dvsipc_thread *thread;

	thread = kmalloc_ssi(sizeof(struct dvsipc_thread), GFP_KERNEL);
	if (thread == NULL)
		return NULL;

	INIT_LIST_HEAD(&thread->list);
	INIT_LIST_HEAD(&thread->state_list);
	thread->thread_pool = thread_pool;
	thread->task = current;
	thread->msg = NULL;
	thread->state = DVSIPC_THREAD_STATE_MAX;
	kref_init(&thread->ref);

	return thread;
}

/*
 * Wake up a newly-created proxy thread.
 */
static void dvsipc_wake_proxy_thread(struct dvsipc_thread_pool *thread_pool)
{
	up(&thread_pool->thread_beckon_sema);
}

/*
 * Called by a thread when it exits. Put the thread in the exit state, and
 * remove it from the thread pool's list of threads. The thread still exists
 * on the thread pool's state list until the last reference is dropped.
 */
static int dvsipc_exit_thread(struct dvsipc_thread *thread)
{
	struct dvsipc_thread_pool *thread_pool;
	unsigned long flags;

	thread_pool = thread->thread_pool;

	if (dvsipc_set_thread_exit(thread) < 0) {
		printk("DVS: %s: Thread 0x%p already exiting\n", __func__,
		       thread);
		return -EINVAL;
	}

	spin_lock_irqsave(&thread_pool->lock, flags);
	if (!list_empty(&thread->list))
		list_del_init(&thread->list);
	spin_unlock_irqrestore(&thread_pool->lock, flags);

	dvsipc_put_thread(thread);

	return 0;
}

/*
 * Called by the put of the final reference.
 */
void dvsipc_free_thread(struct kref *ref)
{
	struct dvsipc_thread_pool *thread_pool;
	struct dvsipc_thread *thread;
	unsigned long flags;

	thread = container_of(ref, struct dvsipc_thread, ref);
	thread_pool = thread->thread_pool;

	/* Remove the last traces of this thread from the thread pool */
	spin_lock_irqsave(&thread_pool->lock, flags);
	if (!list_empty(&thread->state_list)) {
		list_del_init(&thread->state_list);
		thread_pool->state_counts[DVSIPC_THREAD_EXIT] -= 1;
	}
	spin_unlock_irqrestore(&thread_pool->lock, flags);

	DVS_BUG_ON(!list_empty(&thread->list));
	DVS_BUG_ON(thread->task);

	kfree_ssi(thread);
}

/*
 * Check whether this thread is still needed. If we've dynamically expanded
 * the number of threads past max_threads, then we need to remove threads once
 * the request activity has died down.
 */
int dvsipc_check_exit_thread(struct dvsipc_thread *thread)
{
	struct dvsipc_thread_pool *thread_pool;
	unsigned long flags;

	thread_pool = thread->thread_pool;
	spin_lock_irqsave(&thread_pool->lock, flags);

	/* We might have been given the signal to exit, but don't exit until
	 * all the messages on the incoming queue are gone. */
	if (!(thread->state == DVSIPC_THREAD_DESTROY &&
	      atomic_read(&thread_pool->inmsgq->incomingq_len) == 0)) {
		/* Always keep at least thread_max threads around */
		if (thread_pool->thread_count <= thread_pool->thread_max) {
			spin_unlock_irqrestore(&thread_pool->lock, flags);
			return 0;
		}

		/* To perform better with bursts of requests, try to keep
		 * threads around for as long as possible before dropping down
		 * to the thread_max level. The first "thread_max" threads to
		 * enter the idle state get to stick around, and the last
		 * threads to go idle have to exit. */
		if (dvsipc_idle_threads(thread_pool) <
		    thread_pool->thread_max) {
			spin_unlock_irqrestore(&thread_pool->lock, flags);
			return 0;
		}

		/* Last ditch effort to keep this thread around. If it looks
		 * like there are enough messages queued to keep all the idle
		 * threads busy, then don't exit */
		if (atomic_read(&thread_pool->inmsgq->incomingq_len) >
		    dvsipc_idle_threads(thread_pool)) {
			spin_unlock_irqrestore(&thread_pool->lock, flags);
			return 0;
		}
	}

	/* Too many threads. Time for us to exit. */
	thread_pool->thread_count -= 1;
	thread->task = NULL;
	spin_unlock_irqrestore(&thread_pool->lock, flags);

	dvsipc_exit_thread(thread);

	return 1;
}

/*
 * Check and create a new thread if it's needed.
 */
int dvsipc_check_create_thread(struct dvsipc_thread_pool *thread_pool)
{
	unsigned long flags;

	spin_lock_irqsave(&thread_pool->lock, flags);
	if (dvsipc_idle_threads(thread_pool) > 0) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	if (thread_pool->thread_count >=
	    thread_pool->thread_limit + dvsipc_blocked_threads(thread_pool)) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	if (thread_pool->state != DVSIPC_THREAD_POOL_ACTIVE) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	if (thread_pool->max_concurrent_creates > 0 &&
	    thread_pool->in_progress_creates >=
		    thread_pool->max_concurrent_creates) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	thread_pool->thread_count += 1;
	thread_pool->in_progress_creates += 1;
	spin_unlock_irqrestore(&thread_pool->lock, flags);

	dvsipc_wake_proxy_thread(thread_pool);

	return 0;
}

int start_thread_generator(struct dvsipc_instance *instance, int instance_id)
{
	int rval = 0;
	char inst_id[32];
	char *thread_name = instance->thread_pool->thread_name;
	char *argv[6];

	static char *envp[] = { "HOME=/", "TERM=linux",
				"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

	snprintf(inst_id, sizeof(inst_id), "%d", instance_id);

	argv[0] = DVS_THREAD_GENERATOR_PATH;
	argv[1] = "-n";
	argv[2] = inst_id;
	argv[3] = "-p";
	argv[4] = thread_name;
	argv[5] = NULL;

	if ((rval = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC))) {
		printk(KERN_ERR
		       "DVS: Starting %s for instance %d (%s) failed with %d!!!\n",
		       DVS_THREAD_GENERATOR_PATH, instance_id, thread_name,
		       rval);
	}

	return rval;
}

/*
 * Called after a thread pool is created to start up all the threads in it.
 */
int dvsipc_start_thread_pool(struct dvsipc_thread_pool *thread_pool)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&thread_pool->lock, flags);
	if (thread_pool->state != DVSIPC_THREAD_POOL_INIT) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return -EINVAL;
	}

	for (i = 0; i < thread_pool->thread_min; i++) {
		thread_pool->thread_count += 1;
		thread_pool->in_progress_creates += 1;
		spin_unlock_irqrestore(&thread_pool->lock, flags);

		dvsipc_wake_proxy_thread(thread_pool);

		spin_lock_irqsave(&thread_pool->lock, flags);
	}

	thread_pool->state = DVSIPC_THREAD_POOL_ACTIVE;
	spin_unlock_irqrestore(&thread_pool->lock, flags);

	return 0;
}

/*
 * Stop all the threads in a thread pool. This doesn't guarantee that all the
 * threads are actually stopped. If there are still a large number of requests
 * to be handled, then it might take a while before the thread can exit.
 */
int dvsipc_stop_thread_pool(struct dvsipc_thread_pool *thread_pool)
{
	struct dvsipc_thread *thread;
	unsigned long flags;
	int rval, i, count;

	spin_lock_irqsave(&thread_pool->lock, flags);
	if (thread_pool->state == DVSIPC_THREAD_POOL_DESTROY) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	thread_pool->state = DVSIPC_THREAD_POOL_DESTROY;
	count = 0;

	while (!list_empty(&thread_pool->thread_list)) {
		thread = list_first_entry(&thread_pool->thread_list,
					  struct dvsipc_thread, list);
		dvsipc_get_thread(thread);
		list_del_init(&thread->list);
		spin_unlock_irqrestore(&thread_pool->lock, flags);

		if ((rval = dvsipc_set_thread_destroy(thread)) < 0) {
			dvsipc_put_thread(thread);
			printk("DVS: %s: Error: Unable to destroy thread 0x%p\n",
			       __func__, thread);

			spin_lock_irqsave(&thread_pool->lock, flags);
			continue;
		}

		dvsipc_put_thread(thread);
		spin_lock_irqsave(&thread_pool->lock, flags);

		count++;
	}
	spin_unlock_irqrestore(&thread_pool->lock, flags);

	/* Wake up all the threads so they see the destroy flag */
	for (i = 0; i < count; i++)
		up(&thread_pool->inmsgq->sema);

	return 0;
}

/*
 * Free the thread pool. This makes sure that there aren't any threads left
 * in the thread pool by forcefully killing them.
 */
int dvsipc_remove_thread_pool(struct dvsipc_thread_pool *thread_pool)
{
	struct dvsipc_thread *thread;
	struct list_head temp_head;
	unsigned long flags;
	int i;

	if (thread_pool->state != DVSIPC_THREAD_POOL_DESTROY)
		return -EINVAL;

	spin_lock_irqsave(&thread_pool->lock, flags);
	if (thread_pool->thread_count == 0) {
		spin_unlock_irqrestore(&thread_pool->lock, flags);
		return 0;
	}

	INIT_LIST_HEAD(&temp_head);

	while (!list_empty(&thread_pool->state_lists[DVSIPC_THREAD_DESTROY])) {
		thread = list_first_entry(
			&thread_pool->state_lists[DVSIPC_THREAD_DESTROY],
			struct dvsipc_thread, state_list);
		list_del_init(&thread->state_list);
		list_add_tail(&thread->state_list, &temp_head);
		dvsipc_get_thread(thread);
		spin_unlock_irqrestore(&thread_pool->lock, flags);

		printk("DVS: %s: Sending SIGKILL to task 0x%p\n", __func__,
		       thread->task);

		send_sig(SIGKILL, thread->task, 1);

		dvsipc_put_thread(thread);
		spin_lock_irqsave(&thread_pool->lock, flags);
	}

	if (!list_empty(&temp_head))
		list_replace_init(
			&thread_pool->state_lists[DVSIPC_THREAD_DESTROY],
			&temp_head);

	/* Wait for the threads to respond to the signal */
	for (i = 0; i < DVSIPC_DESTROY_THREAD_TIMEOUT; i++) {
		if (dvsipc_exit_threads(thread_pool) == 0 &&
		    dvsipc_destroy_threads(thread_pool) == 0)
			break;

		spin_unlock_irqrestore(&thread_pool->lock, flags);

		printk("DVS: %s: Waiting for %d threads in exit, %d threads in "
		       "destroy\n",
		       __func__, dvsipc_exit_threads(thread_pool),
		       dvsipc_destroy_threads(thread_pool));

		dvsipc_clear_rma_list(-1);
		sleep_full(1);

		spin_lock_irqsave(&thread_pool->lock, flags);
	}

	spin_unlock_irqrestore(&thread_pool->lock, flags);

	if (dvsipc_exit_threads(thread_pool) > 0 ||
			dvsipc_destroy_threads(thread_pool) > 0) {
		printk(KERN_ERR
		       "DVS: %s done, have %d exiting, %d being destroyed?\n",
		       __func__, dvsipc_exit_threads(thread_pool),
		       dvsipc_destroy_threads(thread_pool));
		/*
		 * There's going to be a use-after-free panic, because
		 * we still have at least one thread running. So just go
		 * ahead and panic cleanly.
		 */
		DVS_BUG();
	}

	kfree_ssi(thread_pool);

	printk("DVS: dvsipc_remove_thread_pool complete\n");

	return 0;
}

/*
 * Allocate a thread pool. This doesn't start any of the threads in the pool.
 */
struct dvsipc_thread_pool *
dvsipc_create_thread_pool(const char *name, unsigned int thread_min,
			  unsigned int thread_max, unsigned int thread_limit,
			  unsigned int concurrent_creates, int nice)
{
	struct dvsipc_thread_pool *thread_pool;
	int i;

	thread_pool =
		kmalloc_ssi(sizeof(struct dvsipc_thread_pool), GFP_KERNEL);
	if (thread_pool == NULL)
		return NULL;

	/* specified parameters */
	thread_pool->thread_min = thread_min;
	thread_pool->thread_max = thread_max;
	thread_pool->thread_limit = thread_limit;
	thread_pool->max_concurrent_creates = concurrent_creates;
	thread_pool->nice = nice;
	strncpy(thread_pool->thread_name, name, TASK_COMM_LEN);

	/* initialization */
	thread_pool->state = DVSIPC_THREAD_POOL_INIT;
	thread_pool->thread_count = 0;
	thread_pool->threads_created = 0;
	thread_pool->in_progress_creates = 0;
	INIT_LIST_HEAD(&thread_pool->thread_list);
	spin_lock_init(&thread_pool->lock);
	sema_init(&thread_pool->thread_beckon_sema, 0);
	for (i = 0; i < DVSIPC_THREAD_STATE_MAX; i++) {
		INIT_LIST_HEAD(&thread_pool->state_lists[i]);
		thread_pool->state_counts[i] = 0;
	}

	return thread_pool;
}

/*
 * The following is code related to capturing userspace threads using the
 * /dev/dvs device file. The code has been included in this file as presently
 * it is only used for capturing threads. If the device ever has other uses the
 * code could be broken out into another file.
 */

static int wait_on_thread_create(int instance_id)
{
	int rval;
	struct dvsipc_instance *instance = NULL;
	struct dvsipc_thread_pool *pool = NULL;

	if ((instance = dvsipc_find_instance(instance_id)) == NULL)
		return -EINVAL;

	if ((pool = instance->thread_pool) == NULL) {
		dvsipc_put_instance(instance);
		return -EINVAL;
	}

	rval = down_interruptible(&pool->thread_beckon_sema);
	dvsipc_put_instance(instance);

	return rval;
}

static int thread_capture(int pool_id)
{
	struct dvsipc_instance *instance = NULL;
	struct dvsipc_thread_pool *pool = NULL;
	struct dvsipc_thread *thread;

	if ((instance = dvsipc_find_instance(pool_id)) == NULL)
		return -EINVAL;

	if ((pool = instance->thread_pool) == NULL) {
		dvsipc_put_instance(instance);
		return -EINVAL;
	}

	thread = dvsipc_initialize_thread(pool);
	dvsipc_put_instance(instance);

	if (thread == NULL) {
		return -ENOMEM;
	}

	/* Dispatch this thread forthwith to perform some work */
	process_message_thread(thread);

	return 0;
}

static long dvs_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	int rval;
	int pool_id = -1;
	int num_instances = DVSIPC_INSTANCE_MAX;

	switch (cmd) {
	case DVS_DEV_IOCTL_GET_NUM_INSTANCES:
		return put_user(num_instances, (int __user *)arg);

	case DVS_DEV_IOCTL_WAIT_ON_THREAD_CREATE:
		if ((rval = get_user(pool_id, (int __user *)arg)) < 0)
			return rval;
		return wait_on_thread_create(pool_id);

	case DVS_DEV_IOCTL_THREAD_TRAP:
		if ((rval = get_user(pool_id, (int __user *)arg)) < 0)
			return rval;
		return thread_capture(pool_id);

	default:
		break;
	}
	return -EINVAL;
}

static int dvs_dev_open(struct inode *ip, struct file *fp)
{
	return 0;
}

static int dvs_dev_release(struct inode *ip, struct file *fp)
{
	return 0;
}

static struct file_operations dvs_dev_fops = {
	.owner = THIS_MODULE,
	.open = dvs_dev_open,
	.release = dvs_dev_release,
	.unlocked_ioctl = dvs_dev_ioctl,
};

static struct miscdevice dvs_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DVS_DEVICE_FILENAME,
	.fops = &dvs_dev_fops,
};

int init_dev_file(void)
{
	return misc_register(&dvs_device);
}

void remove_dev_file(void)
{
	misc_deregister(&dvs_device);
}
