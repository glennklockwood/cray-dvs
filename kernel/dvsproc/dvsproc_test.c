/*
 * Copyright 2016 Cray Inc. All Rights Reserved.
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

#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>

#include "common/ssi_proc.h"
#include "common/dvsproc_test.h"

/*********************************************************************/
#ifndef	DVSPROC_TEST_ENABLE
/*********************************************************************/

int
dvsproc_test_init(struct proc_dir_entry *ssiproc_dir)
{
	/* NOOP if not compile-enabled */
	return 0;
}

void
dvsproc_test_exit(struct proc_dir_entry *ssiproc_dir)
{
	/* NOOP if not compile-enabled */
}

/*********************************************************************/
#else	/* DVSPROC_TEST_ENABLE */
/*********************************************************************/

/* Name of proc file */
#define	SSIPROC_TEST	"test"

/* Private data space */
typedef struct {
	unsigned long	version;
} testdata_t;
testdata_t testdata = {
	.version = 1 
};

/* Stores command between write to file, and read from file */
static char command[256];

/**********************************************************************
 * proc system push-ups.
 */

struct proc_dir_entry	*ssiproc_test = NULL;

static void _init_globals(void);
static int ssiproc_test_open(struct inode *, struct file *);
static void *ssiproc_test_seq_start(struct seq_file *, loff_t *);
static void *ssiproc_test_seq_next(struct seq_file *, void *, loff_t *);
static void ssiproc_test_seq_stop(struct seq_file *, void *);
static ssize_t ssiproc_test_write(struct file *, const char *, size_t, loff_t *);
static int ssiproc_test_seq_show(struct seq_file *, void *);

static struct seq_operations ssiproc_test_ops = {
    	start:		ssiproc_test_seq_start,
	next:		ssiproc_test_seq_next,
	stop:		ssiproc_test_seq_stop,
	show:		ssiproc_test_seq_show,
};

static struct file_operations ssiproc_test_operations = {
    	open:		ssiproc_test_open,
	read:		seq_read,
	write:		ssiproc_test_write,
	release:	seq_release,
};

int
dvsproc_test_init(struct proc_dir_entry *ssiproc_dir)
{
    	int error;

	/* Create the 'test' file in the proc directory */
	if ((ssiproc_test = proc_create(SSIPROC_TEST, 
					S_IFREG | S_IRUGO | S_IWUSR, ssiproc_dir,
					&ssiproc_test_operations)) == NULL) {
	    	printk (KERN_ERR "DVS: %s: cannot init /proc/%s/%s\n",
			__FUNCTION__, SSIPROC_DIR, SSIPROC_TEST);
		error = -ENOMEM;
		goto error;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	ssiproc_test->uid = 0;
#else
	proc_set_user(ssiproc_test, KUIDT_INIT(0), KGIDT_INIT(0));
#endif
	return 0;

error:
	dvsproc_test_exit(ssiproc_dir);
	return (error);
}

void
dvsproc_test_exit(struct proc_dir_entry *ssiproc_dir)
{
	if (ssiproc_test) {
		remove_proc_entry(SSIPROC_TEST, ssiproc_dir);
		ssiproc_test = NULL;
	}
}

static int 
ssiproc_test_open(struct inode *inode, struct file *file)
{
	_init_globals();
    	return seq_open(file, &ssiproc_test_ops);
} /* ssiproc_test_open */

static void *
ssiproc_test_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	if (n >= 1)
		return (NULL);

	return (void *)&testdata;
} /* ssiproc_test_seq_start */


static void *
ssiproc_test_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
    	loff_t n = ++*pos;

	if (n > 0) {
		return NULL;
	}
	return p;

} /*ssiproc_test_seq_next */


static void
ssiproc_test_seq_stop(struct seq_file *m, void *p)
{
	return;
} /* ssiproc_test_seq_stop */

/**********************************************************************
 * Test performance of different means of doing an atomic operation
 */
static atomic64_t test_atom_register;
static spinlock_t test_lock;

static void
dump_lock(struct seq_file *m)
{
	unsigned char *b = (unsigned char *)&test_lock;
	int ii;
	for (ii=0; ii<sizeof(test_lock); ii++) {
		if (ii && !(ii%16)) {
			seq_printf(m, "\n");
		}
		seq_printf(m, " %02x", b[ii]);
	}
	seq_printf(m, "\n");
}

static void
test_null(void)
{
}

static void
test_spin(void)
{
	spin_lock(&test_lock);
	spin_unlock(&test_lock);
}

static void
test_atom(void)
{
	volatile unsigned long old;
	old = atomic64_read(&test_atom_register);
	atomic64_cmpxchg(&test_atom_register, old, old+1);
	old = atomic64_read(&test_atom_register);
}

static size_t
test_speed(void (*func)(void))
{
	unsigned long beg, end, cnt;
	cnt = 0;
	beg = jiffies + 1;
	end = beg + 100;
	while (jiffies < beg) {
		cnt++;
	}
	cnt = 0;
	while (jiffies < end) {
		func();
		cnt++;
	}
	return cnt;
}

/**********************************************************************
 * Start the useful code.
 */

/*
 * Display usage information
 */
static void
_syntax(struct seq_file *m, testdata_t *p)
{
	char *syntax =
		"echo 'command' > /proc/fs/dvs/test\n"
		"cat /proc/fs/dvs/test\n"
		"\n"
		"Commands:\n"
		"   spinlock\n"
		;
	seq_printf(m, "test file version %ld\n", p->version);
	seq_printf(m, "%s", syntax);
}

/*
 * One-time initialization of globals, called any time the proc file
 * is opened.
 */
static void
_init_globals(void)
{
static	int init = 0;
	if (! init) {
		init = 1;
		memset(command, 0, sizeof(command));
		spin_lock_init(&test_lock);
		atomic64_set(&test_atom_register, 0);
	}
}

/* 
 * Handle writes to this proc file.
 *
 * All we do is take the incoming string
 * and save it. This is then consumed when we try to read the file.
 */
static ssize_t 
ssiproc_test_write(struct file *file, const char *buffer,
		      size_t count, loff_t *offp)
{
	if (count >= sizeof(command)) {
		return -EINVAL;
	}

	memset(command, 0, sizeof(command));
	if (copy_from_user(command, buffer, count)) {
		return -EFAULT;
	}

	return count;
}

/*
 * Handle reads from this proc file.
 *
 * We process the command at this time, and display output.
 */
static int 
ssiproc_test_seq_show(struct seq_file *m, void *p)
{
#define	MAXARGS 32
	char *argv[MAXARGS];
	char *ptr;
	int argc;

	/* Simple-minded argument parsing */
	argc = 0;
	ptr = command;
	while (*ptr && argc < MAXARGS) {
		while (isspace(*ptr)) ptr++;
		if (! *ptr) break;
		argv[argc++] = ptr;
		while (*ptr && !isspace(*ptr)) ptr++;
		if (*ptr) *ptr++ = 0;
	}

	if (argc < 1) {
		_syntax(m, p);
	} else if (! strcmp(argv[0], "spinlock")) {
		spin_lock_init(&test_lock);
		dump_lock(m);
		seq_printf(m, "null cnt = %ld\n", test_speed(test_null));
		dump_lock(m);
		seq_printf(m, "spin cnt = %ld\n", test_speed(test_spin));
		dump_lock(m);
		seq_printf(m, "atom cnt = %ld\n", test_speed(test_atom));
		dump_lock(m);
	} else {
		_syntax(m, p);
	}
	/* Clear the command after each use */
	memset(command, 0, sizeof(command));
	return 0;
}

/*********************************************************************/
#endif	/* DVSPROC_TEST_ENABLE */
/*********************************************************************/
