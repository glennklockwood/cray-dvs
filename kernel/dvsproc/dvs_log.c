/*
 * Copyright 2013-2014, 2016 Cray Inc. All Rights Reserved.
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

#include <linux/module.h>

#include "common/log.h"
#include "common/kernel/usiipc.h"

/* Note on spin locks. The older code used spin_lock_irqsave(),
 * which disables interrupts. There is no reason for this code
 * to disable interrupts, since none of this code, or the memory
 * it accesses, will ever be used inside an interrupt context.
 */

/*
 * These are the logs. We currently support only three.
 */
static struct log_info *dvs_logs[DVS_MAX_LOGS];

/*
 * Note that locks are now global. They are initialized once, on the first of
 * potentially racy calls to dvs_log_init(), and are never deleted. This means
 * that even if logs are created or destroyed, the locks will always be valid.
 */
static spinlock_t dvs_log_locks[DVS_MAX_LOGS];

/*
 * This spinlock is used only once, during initialization of the other locks.
 */
DEFINE_SPINLOCK(dvs_log_init_lock);

/**
 * One-time code to initialize the log spinlocks to an unlocked
 * state. This can be safely called at any time. It must be
 * called at least once before attempting to lock or unlock a
 * log. It's very fast: after the first use, it just checks the
 * static 'init' and drops out.
 *
 * @author jnemeth (7/27/16)
 *
 * @param void
 */
static inline void init_locks_once(void)
{
	static int init = 0;
	if (!init) {
		/* could have multiple CPUs contending for first */
		spin_lock(&dvs_log_init_lock);
		/* check again to see if someone beat us */
		if (!init) {
			/* we're the first, so initialize */
			int i;
			for (i = 0; i < DVS_MAX_LOGS; i++)
				spin_lock_init(&dvs_log_locks[i]);
			/* never call this again */
			init = 1;
		}
		spin_unlock(&dvs_log_init_lock);
	}
}

/**
 * Acquire a lock on the specified log and return a pointer to
 * it. This also does sanity checking. You should always lock
 * the log and use the returned pointer. You must release the
 * lock when done.
 *
 * @author jnemeth (7/27/16)
 *
 * @param n = index of log
 * @param pirqflags = pointer to an IRQ flag holder
 *
 * @return struct log_info*
 */
static inline struct log_info *lock_log(int n)
{
	init_locks_once();
	if (n >= DVS_MAX_LOGS) {
		printk(KERN_ERR "DVS: Attempt to lock log[%d], max %d\n", n,
		       DVS_MAX_LOGS);
		return NULL;
	}
	spin_lock(&dvs_log_locks[n]);
	if (!dvs_logs[n]) {
		spin_unlock(&dvs_log_locks[n]);
		printk(KERN_ERR "DVS: Attempt to lock uninitialized log[%d]\n",
		       n);
		return NULL;
	}
	return dvs_logs[n];
}

/**
 * Release the lock on a log. Once released, you must not access
 * the log.
 *
 * @author jnemeth (7/27/16)
 *
 * @param n = index of log
 * @param pirqflags = IRQ flag holder from lock_log()
 */
static inline void unlock_log(int n)
{
	init_locks_once();
	if (n >= DVS_MAX_LOGS) {
		printk(KERN_ERR "DVS: Attempt to unlock log[%d], max %d\n", n,
		       DVS_MAX_LOGS);
		return;
	}
	spin_unlock(&dvs_log_locks[n]);
}

/**
 * Copy a message from the log to a message structure. This
 * manages the wrap-around at the end of the buffer.
 *
 * This is only used to pull out a message for rendering.
 *
 * @author jnemeth (7/25/16)
 *
 * @param to = pointer to a message structure to receive data
 * @param from = pointer to start of message in log buffer
 * @param length = total length of the message
 * @param log_start = start of the log buffer
 * @param log_length = length of the log buffer
 */
static void *dvs_log_copy_from(void *to, void *from, int length,
			       void *log_start, int log_length)
{
	int offset = 0;

	/* Handle the case where the message wraps around */
	if ((from + length) > log_start + (log_length - 1)) {
		/* 'offset' == length of portion at end of log buffer */
		offset = (log_start + log_length) - from;
		memcpy(to, from, offset);
		from = log_start;
		to += offset;
		length -= offset;
	}
	/* Handle any remaining data */
	memcpy(to, from, length);
	from += length;
	return from;
}

static void *dvs_log_copy_to(void *to, void *from, int length, void *log_start,
			     int log_length)
{
	int offset = 0;

	if ((to + length) > (log_start + (log_length - 1))) {
		/* 'offset' == length of space at end of log buffer */
		offset = (log_start + log_length) - to;
		memcpy(to, from, offset);
		to = log_start;
		from += offset;
		length -= offset;
	}
	memcpy(to, from, length);
	to += length;
	return to;
}

/**
 * Initialize a log.
 *
 * @author jnemeth (7/25/16)
 *
 * @param n = index of the log to initialize
 * @param size_kb = desired size of the log in KB
 * @param name = name of the log (max 31 chars)
 *
 * @return int = 0 on success, negative error code on failure
 */
int dvs_log_init(int n, uint size_kb, char *name)
{
	struct log_info *log;

	/* Make sure the locks are properly initialized */
	init_locks_once();

	/* Sanity errors */
	if (n >= DVS_MAX_LOGS) {
		printk(KERN_ERR "DVS: Attempt to init log[%d], max %d\n", n,
		       DVS_MAX_LOGS);
		return -EINVAL;
	}
	if (!name) {
		printk(KERN_ERR "DVS: Attempt to init log[%d] with no name\n",
		       n);
		return -EINVAL;
	}

	/* Allocate kernel memory for the log structure */
	if (!(log = kmalloc_ssi(sizeof(struct log_info), GFP_KERNEL)))
		return -ENOMEM;
	/* kmalloc_ssi() does memset to zero  */

	/* Initialize the name and the sizes */
	snprintf(log->name, sizeof(log->name), "%s", name);
	log->size_kb = size_kb;
	log->size_bytes = log->size_kb * 1024;

	/* Allocate the unpacking buffer */
	if (!(log->message = vmalloc_ssi(DVS_LOG_MESSAGE_SIZE))) {
		kfree_ssi(log);
		return -ENOMEM;
	}
	/* vmalloc_ssi() does memset to zero  */

	/* A zero-length log is disabled, don't acquire memory */
	if (log->size_bytes) {
		/* the minimum buf size should fit at least one message */
		if (log->size_bytes < DVS_LOG_MESSAGE_SIZE)
			log->size_bytes = DVS_LOG_MESSAGE_SIZE;
		if (!(log->buf = vmalloc_ssi(log->size_bytes))) {
			vfree_ssi(log->message);
			kfree_ssi(log);
			return -ENOMEM;
		}
		/* vmalloc_ssi() does memset to zero  */
		/* head is initially set to the start of the buffer */
		log->head = log->buf;
	}

	/* Lock the log -- don't use lock_log, it will fail */
	spin_lock(&dvs_log_locks[n]);
	if (dvs_logs[n]) {
		/* Oops, someone beat us to it */
		spin_unlock(&dvs_log_locks[n]);
		vfree_ssi(log->message);
		vfree_ssi(log->buf);
		kfree_ssi(log);
		printk(KERN_ERR "DVS: Attempt to init existing log[%d]\n", n);
		return -EINVAL;
	}

	/* Make the log available */
	dvs_logs[n] = log;
	spin_unlock(&dvs_log_locks[n]);
	return 0;
}

/**
 * Destroy a log.
 *
 * @author jnemeth (7/25/16)
 *
 * @param n = index of log to destroy
 */
void dvs_log_exit(int n)
{
	struct log_info *log;

	/* clobber the log for public access */
	if (!(log = lock_log(n)))
		return;
	dvs_logs[n] = NULL;
	unlock_log(n);
	/* free the memory */
	vfree_ssi(log->message);
	vfree_ssi(log->buf);
	kfree_ssi(log);
}

/**
 * Walk backward from the end of the DVS log to find the first full message.
 *
 * The buffer contains messages that look like this:
 *
 * ...{msg}{msg}...
 *      	^head
 *
 * Each message looks like this:
 *
 * {hdr}{text...}{length of msg}
 *
 * The text is not NUL-terminated, but is instead terminated
 * with a byte value indicating the total length of the message.
 *
 * (head - head[-1]) gives the start of the last message.
 *
 * This is complicated by the fact that message wrap around at
 * the end of the buffer, overwriting anything that was at the
 * start of the buffer, and losing track of where the "first"
 * message is located. We could maintain a second 'tail' pointer
 * that advances with every message to point to the first valid
 * message in the buffer, but the original implementation
 * elected to simply count backward by messages.
 *
 * This only happens on a log dump, which is infrequent, so a
 * delay here is preferable to the cumulative delay of updating
 * a 'tail' pointer on every log write.
 *
 * @author jnemeth (7/25/16)
 *
 * @param buf = pointer to the log buffer
 * @param head = pointer to the next space to be written
 * @param size = size of the log buffer
 *
 * @return char* = pointer to the first complete message in the
 *         buffer, or NULL if there are no messages
 */
static char *dvs_log_find_first(char *buf, char *head, unsigned long size)
{
	unsigned char *len;
	char *first;
	int offset = 1; /* offset from the end */

	first = NULL;
	/* consume the entire buffer */
	while (offset < size) {
		/* find the length of the previous message */
		/* len = &head[size-offset] with wrap-around.
		 * Since offset == 1 initially, this is &head[-1], or the last
		 * byte before the current head, which should be the length of
		 * the last message placed in the buffer. It will be NUL only if
		 * the buffer is empty.
		 */
		len = DVS_LOG_LINEAR(buf, head, size, size - offset);
		if (*len == '\0')
			break;

		/* consume that message -- incr offset moves backward */
		offset += *len - 1;
		/* early check for termination condition */
		if (offset >= size)
			break;

		/* this is a valid message */
		first = DVS_LOG_LINEAR(buf, head, size, size - offset);
		/* go back to the end of the previous message */
		offset += 1;
	}

	return first;
}

/**
 * Render a single log message in printable form.
 *
 * @author jnemeth (7/25/16)
 *
 * @param fmessage = PAGE_SIZE buffer into which to render
 * @param message = pointer to the message to render
 * @param curr_time = reference time
 * @param curr_jiffies = reference jiffies ~ curr_time
 */
static void dvs_log_format_message(char *fmessage, struct log_message *message,
				   struct timeval *curr_time,
				   unsigned long curr_jiffies)
{
	struct timeval log_time;
	struct tm htime;
	time_t secs;
	int len;

	jiffies_to_timeval(curr_jiffies - message->timestamp, &log_time);
	secs = curr_time->tv_sec - log_time.tv_sec;
	if (curr_time->tv_usec < log_time.tv_usec)
		secs--;
	time_to_tm(secs, 0, &htime);

	/* this overwrites the length field in the last byte of the message */
	message->text[(int)message->text_size] = '\0';

	/* render into fmessage */
	len = snprintf(fmessage, PAGE_SIZE, "%ld-%d-%d %02d:%02d:%02d-UTC: %s",
		       1900 + htime.tm_year, 1 + htime.tm_mon, htime.tm_mday,
		       htime.tm_hour, htime.tm_min, htime.tm_sec,
		       message->text);

	/*
	 * Add a NULL byte if the string was too large. This should already have
	 * been done by snprintf(), but maybe there was a broken snprintf() out
	 * there at some point....
	 */
	if (len > (PAGE_SIZE - 1))
		fmessage[PAGE_SIZE - 1] = '\0';
}

/**
 * Render all of the messages in a log using seq_printf()
 *
 * @author jnemeth (7/25/16)
 *
 * @param n = index of log to render
 * @param m = seq_printf() output handle
 *
 * @return int = 0 on success, -error if failure
 */
int dvs_log_print(int n, struct seq_file *m)
{
	struct log_message *message;
	struct log_info *log;
	struct timeval curr_time;
	unsigned long curr_jiffies;
	unsigned long tmp_size;
	unsigned char message_size;
	char *fmessage, *head;
	char *tmp_head, *tmp_buf;

	/* acquire a spin lock on the log */
	if (!(log = lock_log(n)))
		return -EINVAL;

	/* capture the size of the log */
	tmp_size = log->size_bytes;
	unlock_log(n);

	/* size_bytes == 0 if log is disabled */
	if (!tmp_size)
		return 0;

	/* buffer for the formatted message string */
	if ((fmessage = vmalloc_ssi(PAGE_SIZE)) == NULL)
		return -ENOMEM;
	/* vmalloc_ssi() does memset to zero  */

	/* buffer for the raw message */
	if ((message = vmalloc_ssi(DVS_LOG_MESSAGE_SIZE)) == NULL) {
		vfree_ssi(fmessage);
		return -ENOMEM;
	}
	/* vmalloc_ssi() does memset to zero  */

	/* reference time to convert jiffies to time values */
	/* Fine point: there is a race between these two calls. It doesn't
	 * matter, because we truncate the time to the nearest second
	 * when rendering.
	 */
	do_gettimeofday(&curr_time);
	curr_jiffies = jiffies;

	/*
	 * Formatting the messages could take long enough on large log sizes
	 * that we don't want to hold the log lock the entire time. If we
	 * can, copy the log to a separate buffer and work off of that.
	 */
	tmp_buf = vmalloc_ssi(tmp_size);
	/* vmalloc_ssi() does memset to zero  */
	/* memory alloc failure handled below */

	/* if the size changed on us just use the log buffer */
	log = lock_log(n);
	if (log && tmp_buf && tmp_size != log->size_bytes) {
		unlock_log(n);
		/* Don't alloc or free while lock is held */
		vfree_ssi(tmp_buf);
		tmp_buf = NULL;
		/* Lock again, after simulating memory failure */
		log = lock_log(n);
	}

	/* Now we check, and if someone killed the log, we're done */
	if (!log) {
		vfree_ssi(tmp_buf);
		vfree_ssi(message);
		vfree_ssi(fmessage);
		return -EINVAL;
	}
	/* log != NULL at this point */

	/* if the allocation failed we'll use the log buffer instead and hold
	 * the spin lock while we format the messages. Otherwise, we can copy
	 * the log buffer into our allocated local buffer, and release the
	 * spin lock on the log.
	 */
	if (tmp_buf == NULL) {
		/* hold the lock and use the log buffer */
		tmp_buf = log->buf;
		tmp_size = log->size_bytes;
		tmp_head = log->head;
	} else { /* tmp_buf != NULL && tmp_size == log->size_bytes */
		memcpy(tmp_buf, log->buf, tmp_size);
		tmp_head = tmp_buf + (log->head - log->buf);
		unlock_log(n);
		log = NULL;
	}

	/* get a pointer to the first full log message */
	head = dvs_log_find_first(tmp_buf, tmp_head, tmp_size);
	while (head) {
		/* copy the message into a contiguous buffer. This also
		 * properly aligns the unsigned long that holds the
		 * jiffies value.
		 *
		 * This pulls the text size from head->text_size, which may
		 * be wrapped around, then adds the metadata size to get the
		 * total message size.
		 */
		message_size = *(DVS_LOG_LINEAR(tmp_buf, head, tmp_size,
						offsetof(struct log_message,
							 text_size))) +
			       DVS_LOG_MESSAGE_META_SIZE;

		/* zero size text means we ran off the end of the log. This
		 * can only happen if the log is empty, but in that case, we
		 * will get head == NULL from finding the first.
		 */
		if (message_size == DVS_LOG_MESSAGE_META_SIZE)
			break;

		/* render the message */
		head = dvs_log_copy_from(message, head, message_size, tmp_buf,
					 tmp_size);
		dvs_log_format_message(fmessage, message, &curr_time,
				       curr_jiffies);
		seq_printf(m, "%s", fmessage);

		if (message->flags & DVS_LOG_TRUNCATED)
			seq_printf(m, " [message truncated]\n");

		/* terminal condition -- we reached the head */
		if (head == tmp_head)
			break;
	}

	if (log)
		unlock_log(n);
	else
		vfree_ssi(tmp_buf);
	vfree_ssi(fmessage);
	vfree_ssi(message);

	return 0;
}

/**
 * Write a message to the log.
 *
 * Because this takes variadic arguments (...), it cannot be
 * inlined, as the previous code was: if you try to inline it,
 * the compiler will ignore the inline directive.
 *
 * @author jnemeth (7/25/16)
 *
 * @param n = index of the log
 * @param pflg = 1 to add printk() as well
 * @param fmt = printf() format string
 * @param ... = arguments to printf()
 */
void dvs_log_write(int n, int pflg, const char *fmt, ...)
{
	va_list args;
	struct log_info *log;
	int len = 0;
	unsigned char message_size;
	char buffer[DVS_LOG_TEXT_SIZE];

	/* We may need this string twice, so build it here */
	va_start(args, fmt);
	if (len < sizeof(buffer))
		len += snprintf(&buffer[len], sizeof(buffer) - len,
				"pid=%d cmd=%s ", current->pid, current->comm);
	if (len < sizeof(buffer))
		len += vsnprintf(&buffer[len], sizeof(buffer) - len, fmt, args);
	va_end(args);

	/* If pflg is set, do a printk here, even if the log is bogus */
	if (pflg)
		printk("%s", buffer);

	/* If no log, we are finished */
	if (!(log = lock_log(n)))
		return;

	/* If log is disabled, we're finished */
	if (!log->size_bytes) {
		unlock_log(n);
		return;
	}

	/* Check if log message was truncated to fit */
	log->message->flags = 0;
	if (len > DVS_LOG_TEXT_SIZE) {
		len = DVS_LOG_TEXT_SIZE;
		log->message->flags |= DVS_LOG_TRUNCATED;
	}

	/*
	 * include the message length in the first and last byte of the message.
	 * This is so we can find the beginning of the message when we translate
	 * the timestamps from seconds to wall time.
	 */
	message_size = len + DVS_LOG_MESSAGE_META_SIZE;

	log->message->timestamp = jiffies;
	log->message->text_size = len;
	memcpy(log->message->text, buffer, len);
	log->message->text[len] = message_size;
	log->head = dvs_log_copy_to(log->head, log->message, message_size,
				    log->buf, log->size_bytes);

	/* done with the log */
	unlock_log(n);
}

/**
 * Clear all data in the specified log.
 *
 * @author jnemeth (7/27/16)
 *
 * @param n = index of log to clear
 */
void dvs_log_clear(int n)
{
	struct log_info *log;

	if (!(log = lock_log(n)))
		return;
	if (log->size_bytes)
		memset(log->buf, 0, log->size_bytes);
	log->head = log->buf;
	unlock_log(n);
}

/**
 * Resize the log buffer. This is called in response to writing
 * a new size value into the proc file that displays the log.
 *
 * @author jnemeth (7/25/16)
 *
 * @param n = index of log to resize
 * @param new_size_kb = new size in KB
 *
 * @return int = 0 if successful, -error if failure
 */
int dvs_log_resize(int n, int new_size_kb)
{
	char *new_buf = NULL;
	char *old_buf = NULL;
	int new_size_bytes = new_size_kb * 1024;
	struct log_info *log;

	/* If allocation is requested, do this first */
	if (new_size_bytes) {
		/*
		 * the minimum buf size should fit at least one message.
		 */
		if (new_size_bytes < DVS_LOG_MESSAGE_SIZE)
			new_size_bytes = DVS_LOG_MESSAGE_SIZE;

		if ((new_buf = vmalloc_ssi(new_size_bytes)) == NULL)
			return -ENOMEM;
		/* vmalloc_ssi() does memset to zero  */
	}

	/* lock the log */
	if (!(log = lock_log(n))) {
		vfree_ssi(old_buf);
		return -EINVAL;
	}

	/* we are going to destroy the old buffer either way */
	old_buf = log->buf;
	if (new_buf) {
		/* replace the old buffer with the new buffer */
		log->buf = new_buf;
		log->head = new_buf;
		log->size_kb = new_size_kb;
		log->size_bytes = new_size_bytes;
	} else {
		/* clobber the buffer */
		log->buf = NULL;
		log->head = NULL;
		log->size_kb = 0;
		log->size_bytes = 0;
	}
	/* we're done with the log structure */
	unlock_log(n);
	/* delete the old buf -- harmless if NULL */
	vfree_ssi(old_buf);
	return 0;
}

/**
 * Return a non-NULL handle if the log exists.
 *
 * Note that the handle is a dummy. It is returned as a pointer
 * from the proc seq_start routines, and passed to the seq_next
 * and seq_stop routines. Those routines are dummies, and the
 * only requrement here is that the pointer be non-NULL.
 *
 * @author jnemeth (7/28/16)
 *
 * @param n = index of log
 *
 * @return void* = dummy non-NULL pointer
 */
void *dvs_log_handle(int n)
{
	static uint x = 0;
	struct log_info *log;
	void *rtn = NULL;

	if ((log = lock_log(n))) {
		rtn = (void *)&x;
		unlock_log(n);
	}
	return rtn;
}

/**
 * Return the size (in KB) of the specified log.
 *
 * @author jnemeth (7/28/16)
 *
 * @param n = index of log
 *
 * @return uint = size of log buffer in KB
 */
uint dvs_log_sizekb(int n)
{
	struct log_info *log;
	uint rtn = 0;

	if ((log = lock_log(n))) {
		rtn = log->size_kb;
		unlock_log(n);
	}
	return rtn;
}

EXPORT_SYMBOL(dvs_log_sizekb);
EXPORT_SYMBOL(dvs_log_handle);
EXPORT_SYMBOL(dvs_log_resize);
EXPORT_SYMBOL(dvs_log_clear);
EXPORT_SYMBOL(dvs_log_write);
EXPORT_SYMBOL(dvs_log_print);
EXPORT_SYMBOL(dvs_log_init);
EXPORT_SYMBOL(dvs_log_exit);
