/*
 * Copyright 2013-2017 Cray Inc. All Rights Reserved.
 *
 * This file is part of Cray Data Virtualization Service (DVS).
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

#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/kthread.h>

#include "common/kernel/usiipc.h"
#include "common/log.h"
#include "common/ssi_proc.h"
#include "common/sync.h"

struct timer_list sync_timer;
struct semaphore sync_sema;
struct task_struct *sync_task = NULL;
struct list_head sync_client_server_list;
rwlock_t sync_client_server_lock;
int sync_client_num_servers = 0;
int sync_thread_exit = 0;
int sync_server_enable = 0;

#ifdef CONFIG_CRAY_COMPUTE
/* Compute nodes short circuit some of the server code by not starting the
 * fsync threads or creating the inode_ref hashtable. */
unsigned int sync_period_secs = 600;
unsigned int sync_hash_size = 0;
unsigned int sync_dirty_timeout_secs = 300;
unsigned int sync_num_threads = 0;
unsigned int sync_num_threads_update = 0;
#else
unsigned int sync_period_secs = 300;
unsigned int sync_hash_size = 128;
unsigned int sync_dirty_timeout_secs = 300;
unsigned int sync_num_threads = 8;
unsigned int sync_num_threads_update = 8;
#endif
atomic64_t closing_time;
atomic64_t closing_syncs;
atomic64_t synced_inodes;
atomic64_t syncing_time;
atomic64_t opened_inodes;
atomic64_t closed_inodes;
atomic64_t sync_requests_rx;
atomic64_t sync_requests_tx;

static void sync_wakeup_thread(unsigned long data);
static void sync_restart_timer(void);
static void sync_server_do_timer(void);
static void sync_client_mark_server_down(int node);
static void sync_client_remove_server(int node);
static int sync_client_do_timer(void);
static int sync_client_force_update(int *servers, int num_servers);
static void sync_remove_fsync_thread(struct fsync_thread_info *fsync_info);
static int sync_add_fsync_thread(struct fsync_thread_info *fsync_info, int num);
static void fsync_stop_threads(void);
static int fsync_thread(void *data);

struct inode_hashlist *inode_hashtable = NULL;
struct fsync_thread_info *fsync_threads = NULL;

module_param(sync_period_secs, uint, 0444);
module_param(sync_dirty_timeout_secs, uint, 0444);
module_param(sync_num_threads, uint, 0444);
module_param(sync_hash_size, uint, 0444);

/* ----- Generic sync functions ----- */

unsigned int *sync_period_get(void)
{
	return &sync_period_secs;
}

unsigned int *sync_timeout_get(void)
{
	return &sync_dirty_timeout_secs;
}

unsigned int *sync_threads_get(void)
{
	return &sync_num_threads;
}

void sync_stats_print(struct seq_file *m)
{
	seq_printf(m, "opened inodes: %lu\n", atomic64_read(&opened_inodes));
	seq_printf(m, "closed inodes: %lu\n", atomic64_read(&closed_inodes));
	seq_printf(m, "synced inodes: %lu\n", atomic64_read(&synced_inodes));
	seq_printf(m, "syncing time:  %u (msecs)\n",
		   jiffies_to_msecs(atomic64_read(&syncing_time)));
	seq_printf(m, "closing syncs: %lu\n", atomic64_read(&closing_syncs));
	seq_printf(m, "closing time:  %u (msecs)\n",
		   jiffies_to_msecs(atomic64_read(&closing_time)));
	seq_printf(m, "updates rcvd:  %lu\n", atomic64_read(&sync_requests_rx));
	seq_printf(m, "updates sent:  %lu\n", atomic64_read(&sync_requests_tx));
}

int sync_stats_control(unsigned int control)
{
	if (!control) {
		atomic64_set(&opened_inodes, 0);
		atomic64_set(&closed_inodes, 0);
		atomic64_set(&synced_inodes, 0);
		atomic64_set(&syncing_time, 0);
		atomic64_set(&closing_syncs, 0);
		atomic64_set(&closing_time, 0);
		atomic64_set(&sync_requests_rx, 0);
		atomic64_set(&sync_requests_tx, 0);
	} else
		return -EINVAL;

	// TODO add an enable/disable switch like DVS stats

	return 0;
}

int sync_timeout_update(unsigned int timeout)
{
	DVS_LOG("Sync: sync_dirty_timeout_secs set to %u\n", timeout);
	sync_dirty_timeout_secs = timeout;

	return 0;
}

int sync_threads_update(unsigned int threads)
{
	if (threads > SYNC_MAX_FSYNC_THREADS)
		return -EFBIG;

	DVS_LOG("Sync: sync_num_threads set to %u\n", threads);
	sync_num_threads_update = threads;

	return 0;
}

int sync_period_update(unsigned int period)
{
	DVS_LOG("Sync: sync_period_secs set to %u\n", period);
	sync_period_secs = period;
	up(&sync_sema);

	return 0;
}

static struct sync_proc_ops sync_ops = {
	.sync_period_get = sync_period_get,
	.sync_timeout_get = sync_timeout_get,
	.sync_threads_get = sync_threads_get,
	.sync_stats_print = sync_stats_print,
	.sync_stats_control = sync_stats_control,
	.sync_period_update = sync_period_update,
	.sync_timeout_update = sync_timeout_update,
	.sync_threads_update = sync_threads_update,
};

static void sync_wakeup_thread(unsigned long data)
{
	up(&sync_sema);
}

static int sync_thread(void *data)
{
	SYNC_LOG("Sync: sync_thread started (%d)\n", current->pid);
	kernel_set_task_nice(current, -10);
	sync_task = current;
	sema_init(&sync_sema, 0);

	setup_timer(&sync_timer, sync_wakeup_thread, 0);
	DVS_LOG("Sync: created timer with period %u seconds\n",
		sync_period_secs);

	while (!sync_thread_exit) {
		if (sync_period_secs) {
			SYNC_LOG("Sync: sync_thread running\n");

			sync_server_do_timer();

			if (sync_client_do_timer() < 0)
				DVS_LOG("Sync: could not send server requests\n");
		}

		sync_restart_timer();

		/* loop until the next timer interrupt */
		while (down_interruptible(&sync_sema))
			;
	}

	/* cue sync_exit that sync_thread is exiting */
	sync_task = NULL;

	return 0;
}

int sync_init(void)
{
	int i;
	struct task_struct *task;

	INIT_LIST_HEAD(&sync_client_server_list);
	rwlock_init(&sync_client_server_lock);

	atomic64_set(&opened_inodes, 0);
	atomic64_set(&closed_inodes, 0);
	atomic64_set(&synced_inodes, 0);
	atomic64_set(&syncing_time, 0);
	atomic64_set(&closing_syncs, 0);
	atomic64_set(&closing_time, 0);
	atomic64_set(&sync_requests_rx, 0);
	atomic64_set(&sync_requests_tx, 0);

	if (sync_hash_size > SYNC_MAX_HASH_SIZE) {
		DVS_LOGP("Sync: sync_hash_size too large. Setting "
			 "sync_hash_size to %d\n",
			 SYNC_MAX_HASH_SIZE);
		sync_hash_size = SYNC_MAX_HASH_SIZE;
	}

	if (sync_hash_size &&
	    (inode_hashtable =
		     kmalloc_ssi(sizeof(struct inode_hashlist) * sync_hash_size,
				 GFP_KERNEL)) == NULL) {
		DVS_LOGP("Sync: error could not allocate inode_hashtable\n");
		return -ENOMEM;
	}

	for (i = 0; i < sync_hash_size; i++) {
		INIT_LIST_HEAD(&inode_hashtable[i].inode_list);
		rwlock_init(&inode_hashtable[i].lock);
	}

	if (sync_num_threads > SYNC_MAX_FSYNC_THREADS) {
		DVS_LOGP("Sync: sync_num_threads too large. Setting "
			 "sync_num_threads to %d\n",
			 SYNC_MAX_FSYNC_THREADS);
		sync_num_threads = SYNC_MAX_FSYNC_THREADS;
	}

	sync_num_threads_update = sync_num_threads;

	if ((fsync_threads = kmalloc_ssi(sizeof(struct fsync_thread_info) *
						 SYNC_MAX_FSYNC_THREADS,
					 GFP_KERNEL)) == NULL) {
		DVS_LOGP("Sync: error could not allocate fsync_threads\n");
		return -ENOMEM;
	}

	for (i = 0; i < sync_num_threads; i++) {
		if (sync_add_fsync_thread(&fsync_threads[i], i)) {
			if (i != 0) {
				DVS_LOGP("Sync: could not start all fsync "
					 "threads. Defaulting to %d threads\n",
					 i);
				sync_num_threads = i;
				sync_num_threads_update = i;
				break;
			} else {
				DVS_LOGP(
					"Sync: could not start fsync threads\n");
				return -EINVAL;
			}
		}
	}

	/*
	 * Create a thread that will govern the sync threads on server nodes and
	 * request sync updates from servers on all nodes.
	 */
	task = kthread_run(sync_thread, NULL, "%s", "DVS-sync");
	if (IS_ERR(task)) {
		DVS_LOGP("Sync: could not create DVS-sync thread\n");
		return PTR_ERR(task);
	}

	sync_proc_register(&sync_ops);

	return 0;
}

void sync_exit(void)
{
	int i;

	/* This will turn off syncing on the servers */
	sync_hash_size = 0;

	for (i = 0; i < ssiproc_max_nodes; i++)
		sync_client_remove_server(i);

	sync_proc_unregister(&sync_ops);

	fsync_stop_threads();
	kfree_ssi(inode_hashtable);
	inode_hashtable = NULL;

	sync_thread_exit = 1;
	up(&sync_sema);
	while (sync_task) {
		nap();
	}
	del_singleshot_timer_sync(&sync_timer);

	kfree_ssi(fsync_threads);
	fsync_threads = NULL;

	return;
}

static void sync_restart_timer(void)
{
	if (sync_period_secs)
		mod_timer(&sync_timer,
			  jiffies + msecs_to_jiffies(sync_period_secs * 1000));
	else
		del_singleshot_timer_sync(&sync_timer);
}

/* ----- Server specific sync functions ----- */

int sync_is_inode_dirty(struct remote_ref *rr)
{
	struct inode_ref *ir;

	if (!(ir = rr->inode_ref))
		return 0;

	if (ir->last_write && ir->last_sync <= ir->last_write)
		return 1;

	return 0;
}

static int sync_add_fsync_thread(struct fsync_thread_info *fsync_info, int num)
{
	struct task_struct *task;

	sema_init(&fsync_info->sema, 0);
	fsync_info->num = num;
	fsync_info->run = 1;

	task = kthread_run(fsync_thread, fsync_info, "%s", "DVS-fsync");
	if (IS_ERR(task)) {
		DVS_LOGP("Sync: Could not create fsync_thread[%d] - "
			 "Sync disabled.",
			 num);
		return PTR_ERR(task);
	}

	return 0;
}

static void sync_remove_fsync_thread(struct fsync_thread_info *fsync_info)
{
	if (fsync_info->run != 1)
		return;

	fsync_info->run = 0;
	up(&fsync_info->sema);

	SYNC_LOG("Sync: Stopping fsync_thread[%d]\n", fsync_info->num);
	/* don't return until we know the thread is stopped */
	while (fsync_info->task)
		nap();
}

static void fsync_stop_threads(void)
{
	int i;

	for (i = 0; i < sync_num_threads; i++)
		sync_remove_fsync_thread(&fsync_threads[i]);
}

int fsync_inode_ref(struct inode_ref *ir, struct remote_ref *rr)
{
	unsigned long sync_time;

	sync_time = jiffies;

	if (vfs_fsync(rr->fp, 0) == 0) {
		SYNC_LOG("Sync: inode %lu: fsynced\n", ir->ino);
		ir->last_sync = sync_time;
		return 0;
	}

	return 1;
}

/*
 * fsync_thread() creates a thread that will run on a DVS server to fsync files.
 * Each thread will walk through the lists of inodes in the inode_hashtable and
 * assign itself an inode_hashlist if hashsize % num_threads is equal to the
 * thread's fsync thread number. We then walk through the list of inodes in the
 * inode_hashlist and check if the inode is dirty. If it is dirty and the inode
 * hasn't been written to for sync_dirty_timeout_secs, then the inode is
 * fsynced. To do the fsync, we take the file pointer from the first remote_ref
 * on the rr_list and use vfs_fsync(). We make note of the remote_ref we're
 * using in the inode_ref->sync_rr field. When a file is closed, we make sure
 * that the remote_ref we're closing isn't the same as sync_rr. If it is, we
 * wait for the fsync to complete before calling close. */

static int fsync_thread(void *data)
{
	struct fsync_thread_info *fsync_info;
	struct inode_hashlist *inode_hashentry;
	struct inode_ref *ir;
	struct remote_ref *rr;
	unsigned long start_jiffies;
	int i, inode_count;

	fsync_info = (struct fsync_thread_info *)data;

	SYNC_LOG("Sync: fsync_thread[%d] started (%d)\n", fsync_info->num,
		 current->pid);
	kernel_set_task_nice(current, -10);
	fsync_info->task = current;

	while (fsync_info->run) {
		SYNC_LOG("Sync: fsync_thread[%d] running\n", fsync_info->num);

		start_jiffies = jiffies;
		inode_count = 0;
		for (i = 0; i < sync_hash_size; i++) {
			if (!sync_num_threads)
				break;

			/* This thread covers multiple hashtable lists */
			if (i % sync_num_threads != fsync_info->num)
				continue;

			inode_hashentry = &inode_hashtable[i];

			read_lock(&inode_hashentry->lock);
			list_for_each_entry (ir, &inode_hashentry->inode_list,
					     inode_list) {
				spin_lock(&ir->lock);

				/* We need to borrow a file pointer for the
				 * fsync, so we use the first remote_ref on the
				 * list. sync_rr holds the rr we're using so
				 * we know not to close that file until the
				 * fsync is done. */
				rr = list_first_entry(&ir->rr_list,
						      struct remote_ref,
						      inode_list);
				ir->sync_rr = rr;

				/* We don't need to reference the remote_ref
				 * here since we've set sync_rr. That ensures
				 * that both remove_remote_ref() and
				 * free_remote_ref() won't be able to proceed
				 * passed their calls to sync_remove_inode_ref()
				 * until we're done with the fsync. */
				spin_unlock(&ir->lock);
				read_unlock(&inode_hashentry->lock);

				/* This is where we do the actual fsync. It only
				 * takes place if the file hasn't been written
				 * to for at least sync_dirty_timeout_secs. */
				if (ir->last_sync < ir->last_write &&
				    (jiffies - ir->last_write) >
					    (sync_dirty_timeout_secs * HZ)) {
					if (!fsync_inode_ref(ir, ir->sync_rr))
						inode_count++;
				}

				read_lock(&inode_hashentry->lock);
				spin_lock(&ir->lock);
				ir->sync_rr = NULL;
				spin_unlock(&ir->lock);

				/* We are guaranteed that the inode_ref we're
				 * using hasn't been removed from the hash list
				 * since the call to sync_remove_inode_ref()
				 * won't remove the inode_ref unless sync_rr is
				 * NULL. */
			}
			read_unlock(&inode_hashentry->lock);
		}

		atomic64_add(inode_count, &synced_inodes);
		atomic64_add(jiffies - start_jiffies, &syncing_time);

		/* loop until the next timer interrupt */
		while (down_interruptible(&fsync_info->sema))
			;
	}

	/* cue fsync_stop_threads() that this thread is exiting */
	fsync_info->task = NULL;

	return 0;
}

int sync_add_inode_ref(struct remote_ref *rr)
{
	struct inode_hashlist *inode_hashentry;
	struct inode_ref *new_ref, *current_ref;
	unsigned long ino;

	/* We only need to keep track of writable files */
	if (!(rr->fp->f_mode & FMODE_WRITE) || !sync_hash_size)
		return 0;

	ino = file_inode(rr->fp)->i_ino;
	inode_hashentry =
		&inode_hashtable[hash_fnv_1a(&ino, sizeof(unsigned long)) %
				 sync_hash_size];

	read_lock(&inode_hashentry->lock);
	list_for_each_entry (current_ref, &inode_hashentry->inode_list,
			     inode_list) {
		/* This is the common case where the inode_ref entry already
		 * exists. We simply add our remote_ref to the rr_list and
		 * return. */
		if (current_ref->ino == ino) {
			spin_lock(&current_ref->lock);

			list_add_tail(&rr->inode_list, &current_ref->rr_list);
			rr->inode_ref = current_ref;

			spin_unlock(&current_ref->lock);
			read_unlock(&inode_hashentry->lock);
			return 0;
		}
	}

	read_unlock(&inode_hashentry->lock);

	/* If we made it here, then the inode_ref entry doesn't exist yet. */
	if ((new_ref = kmalloc_ssi(sizeof(struct inode_ref), GFP_KERNEL)) ==
	    NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_ref->inode_list);
	INIT_LIST_HEAD(&new_ref->rr_list);
	list_add_tail(&rr->inode_list, &new_ref->rr_list);
	new_ref->ino = ino;
	spin_lock_init(&new_ref->lock);
	new_ref->hashentry = inode_hashentry;
	new_ref->last_sync = 0;
	new_ref->last_write = 0;

	/* We have to walk the list again before we add our inode to make sure
	 * no one added the same inode while we were switching from a reader to
	 * writer. */
	write_lock(&inode_hashentry->lock);
	list_for_each_entry (current_ref, &inode_hashentry->inode_list,
			     inode_list) {
		/* If we do find the inode we're looking for, we add our
		 * remote_ref to it and free the new inode_ref we just
		 * allocated. */
		if (current_ref->ino == ino) {
			spin_lock(&current_ref->lock);

			list_del_init(&rr->inode_list);
			list_add(&rr->inode_list, &current_ref->rr_list);
			rr->inode_ref = current_ref;

			spin_unlock(&current_ref->lock);
			write_unlock(&inode_hashentry->lock);
			kfree_ssi(new_ref);
			return 0;
		}
	}

	/* If we made it here then no one else is using this inode yet. We add
	 * it to the hashtable of inode_refs. */
	list_add(&new_ref->inode_list, &inode_hashentry->inode_list);
	rr->inode_ref = new_ref;
	write_unlock(&inode_hashentry->lock);

	atomic64_inc(&opened_inodes);

	SYNC_LOG("Sync: inode %lu: created inode_ref\n",
		 rr->fp->f_dentry->d_inode->i_ino);
	return 0;
}

void sync_remove_inode_ref(struct remote_ref *rr)
{
	struct inode_ref *ir;
	struct inode_hashlist *inode_hashentry;

	/* If this file was read only or the inode allocation failed we catch
	 * it here. */
	if ((ir = rr->inode_ref) == NULL)
		return;

	inode_hashentry = ir->hashentry;

	spin_lock(&ir->lock);
	while (ir->sync_rr == rr) {
		/* Rare case where an fsync thread is borrowing the file pointer
		 * from this remote_ref. We need to wait until the fsync is done
		 * before we can close the file. */
		spin_unlock(&ir->lock);
		schedule();
		spin_lock(&ir->lock);
	}

	list_del_init(&rr->inode_list);
	if (!list_empty(&ir->rr_list)) {
		/* Another remote_ref is still referencing this inode. We can
		 * just return. */
		rr->inode_ref = NULL;
		spin_unlock(&ir->lock);
		return;
	}

	/* Add the remote_ref back to the rr_list so no one removes the
	 * inode_ref while we grab the hash write lock */
	list_add_tail(&rr->inode_list, &ir->rr_list);
	spin_unlock(&ir->lock);

	/* If we made it here then we are the last remote_ref to close this
	 * file and we need to remove the inode_ref. */
	write_lock(&inode_hashentry->lock);
	spin_lock(&ir->lock);

	while (ir->sync_rr == rr) {
		/* see comment above */
		spin_unlock(&ir->lock);
		write_unlock(&inode_hashentry->lock);
		schedule();
		write_lock(&inode_hashentry->lock);
		spin_lock(&ir->lock);
	}

	list_del_init(&rr->inode_list);

	if (!list_empty(&ir->rr_list)) {
		/* someone else started using this inode entry when we dropped
		 * the inode_ref lock, so we can just return. */
		rr->inode_ref = NULL;
		spin_unlock(&ir->lock);
		write_unlock(&inode_hashentry->lock);
		return;
	}

	list_del_init(&ir->inode_list);
	rr->inode_ref = NULL;
	spin_unlock(&ir->lock);
	write_unlock(&inode_hashentry->lock);
	kfree_ssi(ir);

	atomic64_inc(&closed_inodes);

	SYNC_LOG("Sync: inode %lu: removed inode_ref\n",
		 rr->fp->f_dentry->d_inode->i_ino);
}

void sync_server_data_written(struct remote_ref *rr)
{
	if (!sync_hash_size)
		return;

	if (!rr->inode_ref)
		return;

	spin_lock(&rr->inode_ref->lock);
	rr->inode_ref->last_write = jiffies;
	spin_unlock(&rr->inode_ref->lock);
}

void sync_server_bulk_update(unsigned long *inodes, unsigned long *sync_times,
			     int size)
{
	int i;
	unsigned long jiffies_val;
	struct inode_hashlist *inode_hashentry;
	struct inode_ref *ir;

	jiffies_val = jiffies;

	for (i = 0; i < size; i++) {
		/* In case we don't find the correct inode, we set the delta
		 * value to the special case of no sync. */
		sync_times[i] = LONG_MIN;

		if (sync_hash_size)
			inode_hashentry =
				&inode_hashtable[hash_fnv_1a(
							 &inodes[i],
							 sizeof(unsigned long)) %
						 sync_hash_size];
		else
			/* we still loop here to fill in sync_times with
			 * LONG_MIN */
			continue;

		read_lock(&inode_hashentry->lock);
		list_for_each_entry (ir, &inode_hashentry->inode_list,
				     inode_list) {
			if (ir->ino == inodes[i]) {
				sync_times[i] = jiffies_val - ir->last_sync;
				break;
			}
		}
		read_unlock(&inode_hashentry->lock);
	}

	atomic64_inc(&sync_requests_rx);
}

static void sync_server_do_timer(void)
{
	int i, threads;

	threads = sync_num_threads_update;

	if (threads < sync_num_threads)
		for (i = threads; i < sync_num_threads; i++)
			sync_remove_fsync_thread(&fsync_threads[i]);

	if (threads > sync_num_threads)
		for (i = sync_num_threads; i < threads; i++)
			sync_add_fsync_thread(&fsync_threads[i], i);

	sync_num_threads = threads;
	for (i = 0; i < sync_num_threads; i++)
		up(&fsync_threads[i].sema);
}

/* ----- Client specific sync functions ----- */

static void sync_client_bulk_update(struct per_node *pna,
				    struct ssi_server_info *server_info,
				    struct remote_file **dirty_rf)
{
	int finished_inodes, i;
	struct remote_file *rf;

	spin_lock(&server_info->lock);

	/* we can't rely on the remote_file structure still being valid, so
	 * we have to walk the list again and match up the remote file to the
	 * inode number/sync time.  */
	finished_inodes = 0;
	list_for_each_entry (rf, &server_info->rf_list, list) {
		for (i = finished_inodes; i < pna->request->u.syncupdaterq.size;
		     i++) {
			if (rf == dirty_rf[i]) {
				if (i == finished_inodes)
					finished_inodes++;
				sync_client_sync_update(
					pna->reply->u.syncupdaterp.sync_times[i],
					pna->request->ipcmsg.jiffies_val, rf);
				break;
			}
		}
	}
	spin_unlock(&server_info->lock);

	SYNC_LOG("Sync: server %s bulk update complete for %d files\n",
		 node_map[pna->request->ipcmsg.target_node].name,
		 pna->request->u.syncupdaterq.size);
}

/*
 * This function takes a list of servers and sends an empty request to each
 * of them. This is used to get an updated sync time from the server
 */

static int sync_client_force_update(int *servers, int num_servers)
{
	struct per_node *pna;
	struct file_request *filerq;
	struct file_reply *filerp;
	struct ssi_server_info *server_info;
	struct remote_file *rf;
	struct remote_file ***dirty_rf;
	int nord, ret, dirty_count, open_files;
	int rqsize, rpsize;
	unsigned long elapsed_jiffies;

	if ((pna = kmalloc_ssi(sizeof(struct per_node) * num_servers,
			       GFP_KERNEL)) == NULL)
		return -ENOMEM;

	if ((dirty_rf = kmalloc_ssi(sizeof(struct remote_file **) * num_servers,
				    GFP_KERNEL)) == NULL) {
		kfree_ssi(pna);
		return -ENOMEM;
	}

	ret = 0;

	for (nord = 0; nord < num_servers; nord++) {
		server_info = node_map[servers[nord]].server_info;

		open_files = atomic_read(&server_info->open_files);
		if (open_files == 0)
			continue;

		if (open_files < 0) {
			printk(KERN_ERR "DVS: open_files %d less than zero!\n",
			       open_files);
			continue;
		}

		rqsize = sizeof(struct file_request) +
			 (sizeof(unsigned long) * open_files);
		rpsize = sizeof(struct file_reply) +
			 (sizeof(unsigned long) * open_files);

		if ((filerq = kmalloc_ssi(rqsize, GFP_KERNEL)) == NULL) {
			ret = -ENOMEM;
			break;
		}
		pna[nord].request = filerq;
		if ((filerp = kmalloc_ssi(rpsize, GFP_KERNEL)) == NULL) {
			ret = -ENOMEM;
			break;
		}
		pna[nord].reply = filerp;

		if ((dirty_rf[nord] = kmalloc_ssi(sizeof(struct remote_file *) *
							  open_files,
						  GFP_KERNEL)) == NULL) {
			ret = -ENOMEM;
			break;
		}

		dirty_count = 0;
		spin_lock(&server_info->lock);
		list_for_each_entry (rf, &server_info->rf_list, list) {
			if (rf->last_write > rf->last_sync &&
			    rf->last_write <
				    (jiffies - sync_dirty_timeout_secs * HZ)) {
				/* We didn't hold the server_info->lock while
				 * allocating space for the request, so the
				 * number of files on this server could have
				 * changed. */
				if (dirty_count == open_files) {
					SYNC_LOG("Sync: server %s: not enough "
						 "space to update all files\n",
						 node_map[rf->node].name);
					break;
				}

				filerq->u.syncupdaterq.inodes[dirty_count] =
					rf_inode(rf);
				(dirty_rf[nord])[dirty_count] = rf;
				dirty_count++;
			}
		}
		spin_unlock(&server_info->lock);

		/* resize the request and reply to the actual size we used */
		rqsize = sizeof(struct file_request) +
			 (sizeof(unsigned long) * dirty_count);
		rpsize = sizeof(struct file_reply) +
			 (sizeof(unsigned long) * dirty_count);
		filerq->u.syncupdaterq.size = dirty_count;
		filerq->request = RQ_SYNC_UPDATE;
		capture_context(&filerq->context);
		set_root_context(&filerq->context);

		/* Don't send an update request if we don't actually have any
		 * inodes in it. */
		if (!dirty_count)
			continue;

		elapsed_jiffies = jiffies;
		if ((ret = send_ipc_request_async_stats(
			     NULL, servers[nord], RQ_FILE, filerq, rqsize,
			     filerp, rpsize, NO_IDENTITY)) < 0) {
			if (ret == -EHOSTDOWN)
				sync_client_mark_server_down(servers[nord]);

			/* still send requests to the other servers */
			ret = 0;
			continue;
		}
		log_request(filerq->request, NULL, NULL, NULL, 1, servers[nord],
			    jiffies - elapsed_jiffies);
		atomic64_inc(&sync_requests_tx);
		pna[nord].sent = 1;
	}

	/* wait for the messages to come back.*/
	for (nord = 0; nord < num_servers; nord++) {
		if (pna[nord].sent) {
			if (!wait_for_async_request_stats(NULL,
							  pna[nord].request))
				sync_client_bulk_update(
					&pna[nord],
					node_map[servers[nord]].server_info,
					dirty_rf[nord]);
		}
		kfree_ssi(pna[nord].request);
		kfree_ssi(pna[nord].reply);
		kfree_ssi(dirty_rf[nord]);
	}

	kfree_ssi(pna);
	kfree_ssi(dirty_rf);
	return ret;
}

/*
 * This function is run on the client by the timer that goes off. It walks
 * through the list of servers and checks whether any of them need to have
 * their sync times updated.
 */
static int sync_client_do_timer(void)
{
	struct ssi_server_info *server_info;
	int *servers = NULL;
	int server_count, ret;

	ret = 0;
	server_count = 0;

	read_lock(&sync_client_server_lock);
	list_for_each_entry (server_info, &sync_client_server_list, list) {
		if (server_info->flags & SYNC_SERVER_DOWN)
			continue;
		if (!servers && (servers = (int *)kmalloc_ssi(
					 sync_client_num_servers * sizeof(int),
					 GFP_ATOMIC)) == NULL) {
			ret = -ENOMEM;
			break;
		}
		servers[server_count] = server_info->node;
		server_count++;
	}
	read_unlock(&sync_client_server_lock);

	if (server_count > 0)
		ret = sync_client_force_update(servers, server_count);

	kfree_ssi(servers);
	return ret;
}

/*
 * The server provides the difference between the file's last sync time and its
 * jiffies value in the reply->ipcmsg.jiffies_val field. We use this delta value
 * on the client to find the time of the last file sync in terms of our
 * local value of jiffies. The client does this by making note of the jiffies
 * value before sending a request to a server and subtracting the delta value
 * from this jiffies value to find the time of the file's sync.
 */
void sync_client_sync_update(long delta, long start, struct remote_file *rf)
{
	long sync_time;

	if (delta == LONG_MIN)
		return;

	sync_time = start - delta;

	if (rf->last_sync < sync_time) {
		rf->last_sync = sync_time;
		SYNC_LOG("Sync: server %s inode %lu: last sync 0x%lx\n",
			 node_map[rf->node].name, rf_inode(rf), sync_time);
	}
}

void sync_client_data_written(struct remote_file *rf)
{
	rf->last_write = jiffies;

	SYNC_LOG("Sync: server %s inode %lu: last write 0x%lx\n",
		 node_map[rf->node].name, rf_inode(rf), jiffies);
}

static void sync_client_mark_server_down(int node)
{
	read_lock(&sync_client_server_lock);
	if (node_map[node].server_info)
		node_map[node].server_info->flags |= SYNC_SERVER_DOWN;

	read_unlock(&sync_client_server_lock);
	SYNC_LOG("Sync: server %s - marked EHOSTDOWN\n", node_map[node].name);
}

static void sync_client_remove_server(int node)
{
	struct ssi_server_info *server_info;

	write_lock(&sync_client_server_lock);

	/* Remove the server from the linked list and the node_map */
	if ((server_info = node_map[node].server_info) != NULL) {
		sync_client_num_servers--;
		list_del_init(&server_info->list);
		node_map[node].server_info = NULL;
		SYNC_LOG("Sync: server %s - removed\n", node_map[node].name);
	}
	write_unlock(&sync_client_server_lock);

	kfree_ssi(server_info);
}

int sync_client_add_server(int node, int flags,
			   struct incore_upfs_super_block *icsb)
{
	struct ssi_server_info *server_info;

	icsb->sync_flags = flags;

	/* Ignore syncing for read only mount points */
	if (icsb->flags & MS_RDONLY) {
		icsb->sync_flags |= SYNC_SERVER_NOSYNC;
		return 0;
	}

	/* We could grab server_info->lock, but locking sync_client_server_lock
	 * for writing insures that we'll be the only one with access to the
	 * server list */
	write_lock(&sync_client_server_lock);
	if (node_map[node].server_info == NULL) {
		if ((server_info = (struct ssi_server_info *)kmalloc_ssi(
			     sizeof(struct ssi_server_info), GFP_ATOMIC)) ==
		    NULL) {
			/* mark the server as unable to sync if we can't get
			 * a server_info struct to keep track of the sync
			 * time */
			icsb->sync_flags |= SYNC_SERVER_NOSYNC;
			write_unlock(&sync_client_server_lock);
			return -ENOMEM;
		}
		sync_client_num_servers++;
		list_add_tail(&server_info->list, &sync_client_server_list);
		INIT_LIST_HEAD(&server_info->rf_list);
		spin_lock_init(&server_info->lock);
		server_info->node = node;
		server_info->sync = LONG_MIN;
		node_map[node].server_info = server_info;
		SYNC_LOG("Sync: server %s - added\n", node_map[node].name);
	}
	node_map[node].server_info->flags |= flags;
	node_map[node].server_info->flags &= ~SYNC_SERVER_DOWN;
	write_unlock(&sync_client_server_lock);

	return 0;
}

int sync_client_check_dirty(int node, struct file *fp)
{
	struct open_file_info *finfo;
	struct incore_upfs_super_block *icsb;
	int i, server;

	if ((icsb = FILE_ICSB(fp)) == NULL)
		return 0;

	if ((finfo = FILE_PRIVATE(fp)) == NULL)
		return 0;

	for (i = 0; i < finfo->data_rf_len; i++) {
		server = DATA_RF(fp, i)->remote_node;
		if (server == node || node == ALL_SERVERS) {
			if (icsb->flags & MS_RDONLY)
				continue;

			if (!node_map[server].server_info) {
				if (DATA_RF(fp, i)->last_write)
					return 1;
				else
					continue;
			}

			if ((node_map[server].server_info->flags &
			     SYNC_SERVER_NOSYNC) &&
			    DATA_RF(fp, i)->last_write)
				return 1;

			/* The file is dirty if there has been a write, and
			 * it was more recent than the last sync. */
			if (DATA_RF(fp, i)->last_write &&
			    (DATA_RF(fp, i)->last_write >=
			     DATA_RF(fp, i)->last_sync)) {
				SYNC_LOG("Sync: dirty file 0x%p\n", finfo->fp);
				return 1;
			}
		}
	}
	return 0;
}

EXPORT_SYMBOL(sync_client_add_server);
EXPORT_SYMBOL(sync_client_check_dirty);
