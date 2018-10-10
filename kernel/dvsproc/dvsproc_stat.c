/*
 * Copyright 2009-2010, 2013, 2016-2017 Cray Inc. All Rights Reserved.
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
#include <linux/seq_file.h>
#include "dvs/usifile.h"
#include "dvs/vfsops.h"
#include "common/ssi_proc.h"
#include "common/dvsproc_stat.h"
#include "common/kernel/usiipc.h"

/* 
 * Legacy behavior of dvsproc_stat_control: If set to 0 as module option,
 * statistics could not be turned on. This has been fixed, AND the feature
 * has been deprecated in favor of the more flexible dvsproc_stat_defaults.
 *
 * The new dvsproc_stat_defaults sets the default values at module load
 * time. Every new stats file will take these defaults, but can be changed
 * at any later time for each stats file.
 */
unsigned int dvsproc_stat_control = 1;
static char *dvsproc_stat_defaults = "enable,legacy";

module_param(dvsproc_stat_control, int, 0644);
module_param(dvsproc_stat_defaults, charp, 0644);

MODULE_PARM_DESC(dvsproc_stat_control, "0=disable,1=enable "
				       "(deprecated, use dvsproc_stat_defaults)");
MODULE_PARM_DESC(dvsproc_stat_defaults, "enable,disable,legacy,flat,json,"
					"help,brief,verbose,plain,pretty,"
					"test,notest");

/* 
 * Used when the /proc/fs/dvs/stats file is specified, which is invoked
 * by specifying a stats pointer of NULL in calls.
 */
struct dvsproc_stat aggregate_stats;
#define	GETSTATS(stats)	((stats) ? (stats) : &aggregate_stats)

/*
 * Get the counters from the stats object, or NULL if stats are disabled.
 */
static struct dvsproc_stat_counters *
dvsproc_stat_get_counters(struct dvsproc_stat *stats)
{
	/* If no stats pointer given, this is an aggregate statistic. */
	stats = GETSTATS(stats);

	/* 
	 * Corrected buggy behavior that prevented stats from being
	 * enabled if dvsproc_stat_control was set to zero.
	 */
	if (stats->control) {
		return &stats->counters;
	}

	return NULL;
}


static inline void
_update_len(atomic64_t *ary, ssize_t value)
{
	/* set max before min to ensure max >= min */
	atomic64_max(&ary[1], value);	/* max_len */
	atomic64_min(&ary[0], value);	/* min_len */
	atomic64_inc(&ary[2]);		/* iops */
	atomic64_add(value, &ary[3]);	/* bytes */
	atomic64_inc(&ary[4]);		/* iops/sample */
	atomic64_add(value, &ary[5]);	/* bytes/sample */
}

static inline void
_update_off(atomic64_t *ary, ssize_t value)
{
	atomic64_max(&ary[7], value);	/* max_off */
}


/*
 * Update the specified DVS statistic counter, identified by a type
 * and tag.
 */
void
dvsproc_stat_update(struct dvsproc_stat *stats,
		    unsigned int type, unsigned int tag, ssize_t value)
{
	struct dvsproc_stat_counters *counters;

	counters = dvsproc_stat_get_counters(stats);
	if (!counters) {
		/* statistic counting is disabled! */
		return;
	}

	switch (type) {
	case DVSPROC_STAT_REQ:
		/*
		 * IRQ requests initiated on this node.
		 *   send_ipc_request_stats
		 *   send_ipc_request_async_stats
		 *   wait_fo_async_request_stats
		 *   send_ipc_reply_stats
		 */
		if (tag < DVSPROC_STAT_REQ_COUNTERS) {
			if (value < 0) /* update failure */
				atomic64_inc(&counters->request[tag][1]);
			else /* update success */
				atomic64_inc(&counters->request[tag][0]);
		}
		break;
	case DVSPROC_STAT_IO:
		/*
		 * Client per-mount:
		 *   uread2 on receipt of replies to RQ_PARALLEL_READ
		 *   uwrite2 on receipt of replies to RQ_PARALLEL_WRITE
		 * Client aggregate:
		 *   dvs_req_readpages_data (deprecated) RQ_READPAGE_ASYNC
		 * Server aggregate:
		 *   dvs_rq_readpage_async (deprecated) RQ_READPAGE_DATA
		 *   dvs_read_common RQ_PARALLEL_READ
		 *   dvs_read_common RQ_READPAGES_RQ
		 *   dvs_rq_parallel_write
		 */
		switch (tag) {
		case RQ_PARALLEL_READ:	/* (srv agg, cli mnt) no-cache read */
		case RQ_READPAGES_RQ:	/* (srv agg) page read */
		case RQ_READPAGES_RP:	/* unused */
		case RQ_READPAGE_ASYNC:	/* (srv agg) dvs_rq_readpage_async() (deprecated) */
		case RQ_READPAGE_DATA:	/* (cli mnt) dvs_rq_readpage_data() (deprecated) */
			/*
			 * Set maxval first, so that maxval >= minval is always true.
			 */
			atomic64_max(&counters->read_max, value);
			atomic64_min(&counters->read_min, value);
			break;
		case RQ_PARALLEL_WRITE:	/* (srv agg, cli mnt) no-cache write */
		case RQ_WRITEPAGES_RQ:
		case RQ_WRITEPAGES_RP:
			/*
			 * Set maxval first, so that maxval >= minval is always true.
			 */
			atomic64_max(&counters->write_max, value);
			atomic64_min(&counters->write_min, value);
			break;
		default:
			break;
		}
		break;
	case DVSPROC_STAT_IPC_REQUEST:
		/*
		 * send_ipc_request
		 */
		if (value < 0)
			atomic64_inc(&counters->ipc_request[1]);
		else
			atomic64_inc(&counters->ipc_request[0]);
		break;
	case DVSPROC_STAT_IPC_REQUEST_ASYNC:
		/*
		 * send_ipc_request_async
		 */
		if (value < 0)
			atomic64_inc(&counters->ipc_request_async[1]);
		else
			atomic64_inc(&counters->ipc_request_async[0]);
		break;
	case DVSPROC_STAT_IPC_REPLY:
		/*
		 * send_ipc_reply
		 */
		if (value < 0)
			atomic64_inc(&counters->ipc_reply[1]);
		else
			atomic64_inc(&counters->ipc_reply[0]);
		break;
	case DVSPROC_STAT_OPEN_FILES:
		/*
		 * uopen increments
		 * urelease decrements
		 * add_remote_ref increments
		 * free_remote_ref decrements
		 */
		if (value < 0)
			atomic64_dec(&counters->open_files);
		else
			atomic64_inc(&counters->open_files);
		break;
	case DVSPROC_STAT_OPER:
		/*
		 * uwhatever_stats
		 */
		if (tag < DVSPROC_STAT_OPER_COUNTERS) {
			if (value < 0) /* update failure */
				atomic64_inc(&counters->vfsops[tag][1]);
			else /* update success */
				atomic64_inc(&counters->vfsops[tag][0]);
		}
		break;
	case DVSPROC_STAT_OPER_TIME:
		/*
		 * uwhatever_stats
		 */
		if (tag < DVSPROC_STAT_OPER_COUNTERS) {
			/*
			 * Set max time first so that dvsproc_stat_print()
			 * output always has max time data >= the last
			 * operation time
			 */
			atomic64_max(&counters->vfsops[tag][3], value);
			atomic64_set(&counters->vfsops[tag][2], value);
		}
		break;
	case DVSPROC_STAT_REQP:
		/*
		 * receipt of IPC request from remote node
		 */
		if (tag < DVSPROC_STAT_REQP_COUNTERS) {
			if (value < 0) /* update failure */
				atomic64_inc(&counters->requestp[tag][1]);
			else /* update success */
				atomic64_inc(&counters->requestp[tag][0]);
		}
		break;
	case DVSPROC_STAT_REQP_TIME:
		/*
		 * receipt of IPC request from remote node
		 */
		if (tag < DVSPROC_STAT_REQP_COUNTERS) {
			/*
			 * Set max time first so that dvsproc_stat_print()
			 * output always has max time data >= the last
			 * operation time
			 */
			atomic64_max(&counters->requestp[tag][3], value);
			atomic64_set(&counters->requestp[tag][2], value);
		}
		break;
	case DVSPROC_STAT_CLIENT_LEN:
		/*
		 * completion of I/O operations
		 */
		switch (tag) {
		case VFS_OP_AIO_READ:
			_update_len(counters->user_read_stats, value);
			break;
		case VFS_OP_AIO_WRITE:
			_update_len(counters->user_write_stats, value);
			break;
		case VFS_OP_READPAGES:
			_update_len(counters->page_read_stats, value);
			break;
		case VFS_OP_WRITEPAGES:
			_update_len(counters->page_write_stats, value);
			break;
		}
		break;
	case DVSPROC_STAT_CLIENT_OFF:
		/*
		 * completion of I/O operations
		 */
		switch (tag) {
		case VFS_OP_AIO_READ:
			_update_off(counters->user_read_stats, value);
			break;
		case VFS_OP_AIO_WRITE:
			_update_off(counters->user_write_stats, value);
			break;
		case VFS_OP_READPAGES:
			_update_off(counters->page_read_stats, value);
			break;
		case VFS_OP_WRITEPAGES:
			_update_off(counters->page_write_stats, value);
			break;
		}
		break;
	case DVSPROC_STAT_CREATE:
		switch (tag) {
		case DVSPROC_STAT_TYPE_INODE:
			atomic64_inc(&counters->inodes_created);
			break;
		case DVSPROC_STAT_TYPE_FILE:
			atomic64_inc(&counters->files_created);
			break;
		case DVSPROC_STAT_TYPE_SYMLINK:
			atomic64_inc(&counters->links_created);
			break;
		case DVSPROC_STAT_TYPE_DIRECTORY:
			atomic64_inc(&counters->dirs_created);
			break;
		}
		break;
	case DVSPROC_STAT_DELETE:
		switch (tag) {
		case DVSPROC_STAT_TYPE_INODE:
			atomic64_inc(&counters->inodes_deleted);
			break;
		case DVSPROC_STAT_TYPE_FILE:
			atomic64_inc(&counters->files_deleted);
			break;
		case DVSPROC_STAT_TYPE_SYMLINK:
			atomic64_inc(&counters->links_deleted);
			break;
		case DVSPROC_STAT_TYPE_DIRECTORY:
			atomic64_inc(&counters->dirs_deleted);
			break;
		}
		break;
	default:
		break;
	}

	return;
}

/* 
 * Legacy output format. This is unchanged from before this upgrade. It
 * does not include any of the new statistics. If you want the new stats,
 * you need to use a current display format.
 */
void
dvsproc_stat_print_legacy(struct seq_file *m, struct dvsproc_stat *stats)
{
	int i;
	struct dvsproc_stat_counters *counters;
	unsigned long time_last, time_max;

	/* Legacy behavior is to show nothing if disabled */
	counters = dvsproc_stat_get_counters(stats);
	if (!counters) {
		/* statistic counting is disabled! */
		return;
	}
	/* Legacy format output */
	for (i = 0; i < DVSPROC_STAT_REQ_COUNTERS; i++) {
		time_last = jiffies_to_msecs(
			atomic64_read(&counters->requestp[i][2]));
		time_max = jiffies_to_msecs(
			atomic64_read(&counters->requestp[i][3]));
		seq_printf(m, "%s: %lu %lu %lu %lu %ld.%03ld %ld.%03ld\n",
			   file_request_to_string(i),
			   atomic64_read(&counters->request[i][0]),
			   atomic64_read(&counters->request[i][1]),
			   atomic64_read(&counters->requestp[i][0]),
			   atomic64_read(&counters->requestp[i][1]),
			   time_last / 1000, time_last % 1000,
			   time_max / 1000, time_max % 1000);
	}
	for (i = 0; i < DVSPROC_STAT_OPER_COUNTERS; i++) {
		time_last = jiffies_to_msecs(
			atomic64_read(&counters->vfsops[i][2]));
		time_max = jiffies_to_msecs(
			atomic64_read(&counters->vfsops[i][3]));
		seq_printf(m, "%s: %lu %lu %ld.%03ld %ld.%03ld\n",
			   vfs_op_to_string(i),
			   atomic64_read(&counters->vfsops[i][0]),
			   atomic64_read(&counters->vfsops[i][1]),
			   time_last / 1000, time_last % 1000,
			   time_max / 1000, time_max % 1000);
	}

	seq_printf(m, "read_min_max: %lu %lu\n",
		   atomic64_read(&counters->read_min),
		   atomic64_read(&counters->read_max));
	seq_printf(m, "write_min_max: %lu %lu\n",
		   atomic64_read(&counters->write_min),
		   atomic64_read(&counters->write_max));

	seq_printf(m, "IPC requests: %lu %lu\n",
		   atomic64_read(&counters->ipc_request[0]),
		   atomic64_read(&counters->ipc_request[1]));
	seq_printf(m, "IPC async requests: %lu %lu\n",
		   atomic64_read(&counters->ipc_request_async[0]),
		   atomic64_read(&counters->ipc_request_async[1]));
	seq_printf(m, "IPC replies: %lu %lu\n",
		   atomic64_read(&counters->ipc_reply[0]),
		   atomic64_read(&counters->ipc_reply[1]));

	seq_printf(m, "Open files: %lu\n",
		   atomic64_read(&counters->open_files));

	seq_printf(m, "Inodes created: %lu\n",
		   atomic64_read(&counters->inodes_created));
	seq_printf(m, "Inodes removed: %lu\n",
		   atomic64_read(&counters->inodes_deleted));
}

/* 
 * Create a control string for display, consisting of the comma-separated set
 * of control options.
 */
static const char *
_stat_flags_to_string(char *buf, int siz, struct dvsproc_stat *stats)
{
	const char *ena;
	const char *fmt;
	const char *vrb;
	const char *prt;
	const char *tst;
	switch (stats->format) {
	case DVSPROC_STAT_FMT_LEGACY:
		fmt = "legacy";
		break;
	case DVSPROC_STAT_FMT_HELP:
		fmt = "help";
		break;
	case DVSPROC_STAT_FMT_FLAT:
		fmt = "flat";
		break;
	case DVSPROC_STAT_FMT_JSON:
		fmt = "json";
		break;
	default:
		fmt = "unknown";
		break;
	}
	vrb = (stats->fflags & DVSPROC_STAT_FFLG_VERBOSE) ? "verbose" : "brief";
	prt = (stats->fflags & DVSPROC_STAT_FFLG_PRETTY) ? "pretty" : "plain";
	tst = (stats->fflags & DVSPROC_STAT_FFLG_TEST) ? "test" : "notest";
	ena = (stats->control) ? "enable" : "disable";
	snprintf(buf, siz, "%s,%s,%s,%s,%s", ena, fmt, vrb, prt, tst);
	return (const char *)buf;
}

/*************************************************************************/
/* 
 * Structured output utilities. This produces structure output in key/value
 * pairs. These stream output as called.
 *
 * For TEXT output, the general model is that each push extends the key value,
 * and each print produces a single line of output containing the key/value
 * pair, with a LF at the end.
 *
 * For JSON output, the general model is that each push nests a new object
 * inside the previous object, and each print generates a key/value pair.
 * Rendering the structure is lazy: it's held in memory until a key/value pair
 * is rendered. This means that if a structure is pushed, then popped, with no
 * intervening key-value pair, the structure will not be rendered.
 *
 * The JSON LF is always deferred until the next call, so indenting can be done
 * properly after the LF. The if the pretty flag is turned off, all spaces and
 * LFs are omitted, except the final LF at the end of the output.
 */

/*
 * Structured output control structure.
 */
typedef struct {
	char		tags[256];	/* buffer for tags */
	char		sep[256];	/* buffer for separators */
	int		lengths[32];	/* stack of length values */
	int		counts[32];	/* stack of count values*/
	int		depth;		/* depth of stacks */
	int		flushed;	/* amount of data flushed */
	int		length;		/* offset to the end of tags */
	int		count;		/* count of tags at this level */
	int		lines;		/* count of lines printed */
	int		format;		/* specified format */
	int		pretty;		/* format pretty flag */
	struct seq_file *m;		/* seq_printf() stream */
} statnode_t;

/*
 * Pretty or non-pretty key/value JSON key/value separator.
 */
static inline const char *
_json_colon(statnode_t *snp)
{
	return (snp->pretty) ? ": " : ":";
}

/*
 * Pretty or non-pretty JSON LF and indent.
 *
 * We write this into the snp->sep buffer, which is effectively a
 * stack buffer for this call, and thus isn't subject to corruption
 * from sharing.
 *
 * The pfx value is typically ",", which adds a comma before the LF
 * if specified.
 *
 * For flat format, we return an empty string.
 */
static inline const char *
_json_LF(statnode_t *snp, const char *pfx)
{
	char *lf;
	int spc;

	snp->sep[0] = 0;
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* allow for a NULL pfx pointer */
		if (! pfx)
			pfx = "";
		/* indent is 2*depth of nesting */
		spc = (snp->pretty) ? 2*snp->depth : 0;
		/* avoid actual LF if not pretty, or if first line */
		lf = (snp->pretty && snp->lines++ > 0) ? "\n" : "";
		snprintf(snp->sep, sizeof(snp->sep), "%s%s%*s", pfx, lf, spc, "");
		break;
	}
	return snp->sep;
}

/*
 * Pretty or non-pretty JSON comma, used in both objects and arrays.
 */
static inline const char *
_json_comma(statnode_t *snp)
{
	char *comma = "";
	/* length measures number of items in this object */
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* only need comma if multiple at same level */
		comma = (snp->count++ > 0) ? "," : "";
		break;
	}
	return _json_LF(snp, comma);
}

/*
 * Reset the statnode structure.
 */
static inline void
_stat_clear(statnode_t *snp)
{
	snp->tags[0]	= 0;
	snp->depth	= 0;
	snp->flushed	= 0;
	snp->length	= 0;
	snp->count	= 0;
	snp->lines	= 0;
}

/*
 * Prepare the statnode structure.
 */
static void
_stat_init(statnode_t *snp, struct seq_file *m, struct dvsproc_stat *stats)
{
	_stat_clear(snp);
	snp->format	= stats->format;
	snp->pretty	= (stats->fflags & DVSPROC_STAT_FFLG_PRETTY) != 0;
	snp->m		= m;
}

/*
 * Push a level of abstraction.
 */
static void
_stat_push(statnode_t *snp, const char *tag)
{
	const char *fmt = "%s";
	char *p = snp->tags + snp->length;
	char *e = snp->tags + sizeof(snp->tags);

	/* Allow NULL to serve as "" */
	if (! tag) 
		tag = "";

	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		/* empty tags are completely ignored */
		if (! *tag)
			return;
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* empty tags are fine, but tags must be quoted */
		if (*tag)
			fmt = "\"%s\"";
		break;
	}
	/* Push current length, count onto the stack */
	snp->lengths[snp->depth] = snp->length;
	snp->counts[snp->depth] = snp->count;
	snp->depth++;
	/* This new level has no items in it */
	snp->count = 0;
	/* Append tag to tags buffer, and include the trailing NUL char */
	snp->length += snprintf(p, e-p, fmt, tag) + 1;
}

/*
 * Pop a level of abstraction.
 *
 * In the JSON case, we also print out the closing brackets.
 */
static void
_stat_pop(statnode_t *snp)
{
	/*
	 * Pop values off the stacks. Note that if these have not been
	 * flushed, they simply vanish.
	 */
	--snp->depth;
	snp->count = snp->counts[snp->depth];
	snp->length = snp->lengths[snp->depth];
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* Don't close the object unless it has been flushed */
		while (snp->flushed > snp->depth) {
			seq_printf(snp->m, "%s}", _json_LF(snp, ""));
			snp->flushed--;
		}
		break;
	}
}

/*
 * Flush the accumulated structure.
 */
static void
_stat_flush(statnode_t *snp)
{
	const char *tag;
	const char *sep;
	int depth = snp->depth;
	int length = 0;

	/* Reset stack to wherever already flushed */
	snp->depth = snp->flushed;
	/* Replay the stack, writing */
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		/* Always starts at zero, so this dumps the entire key */
		while (snp->depth < depth) {
			snp->length = snp->lengths[snp->depth];
			/* Pick off the next tag */
			tag = &snp->tags[snp->length];
			/* On second and subsequent, prefix with '.' */
			sep = (snp->depth && *tag) ? "." : "";
			seq_printf(snp->m, "%s%s", sep, tag);
			length += strlen(sep) + strlen(tag);
			snp->depth++;
		}
		if (snp->pretty) {
			int len = (length < 40) ? 40 : (length+8) & ~0x7;
			int pad = len - length;
			seq_printf(snp->m, "%*s", pad, "");
		} else {
			seq_printf(snp->m, " ");
		}
		/* Always return to zero */
		snp->flushed = 0;
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* Generally does not start at zero */
		while (snp->depth < depth) {
			snp->count = snp->counts[snp->depth];
			snp->length = snp->lengths[snp->depth];
			/* Pick off the next tag */
			tag = &snp->tags[snp->length];
			/* Print colon separator for tags */
			sep = (snp->depth && *tag) ? _json_colon(snp) : "";
			seq_printf(snp->m, "%s%s%s{", _json_comma(snp), tag, sep);
			/* _json_comma() may have incremented snp->count */
			snp->counts[snp->depth] = snp->count;
			/* count should be zero for next level */
			snp->count = 0;
			snp->depth++;
		}
		/* Up-to-date */
		snp->flushed = snp->depth;
		break;
	}
}

/*
 * Quick little routine to count decimal places and return the power-of-ten
 * needed for the numbers. For instance, places=3 implies 1000.
 */
static inline unsigned long
_divisor(int places)
{
	unsigned long div = 1;
	while (places-- > 0)
		div *= 10;
	return div;
}

/*
 * Print a tagged number. If places > 0, number will be divided by 10^places
 * and shown as a pseudo-floating point number.
 */
static void
_stat_prnum(statnode_t *snp, const char *tag, unsigned long value, int places)
{
	unsigned long div = _divisor(places);
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		/* Easy way is to push the tag as a level of one element */
		_stat_push(snp, tag);
		_stat_flush(snp);
		if (!places) {
			seq_printf(snp->m, "%lu\n", value);
		} else {
			seq_printf(snp->m, "%lu.%0*lu\n",
				   value/div, places, value%div);
		}
		/* Clean up after easy cheat */
		_stat_pop(snp);
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* We may have accumulated several levels -- flush now */
		_stat_flush(snp);
		if (!places) {
			seq_printf(snp->m, "%s\"%s\"%s%lu",
				   _json_comma(snp), tag,
				   _json_colon(snp), value);
		} else {
			seq_printf(snp->m, "%s\"%s\"%s%lu.%0*lu",
				   _json_comma(snp), tag,
				   _json_colon(snp), value/div, places, value%div);
		} 
		break;
	}
}

/*
 * Print a tagged string value.
 */
static void
_stat_prstr(statnode_t *snp, const char *tag, const char *value)
{
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		_stat_push(snp, tag);
		_stat_flush(snp);
		seq_printf(snp->m, "%s\n", value);
		_stat_pop(snp);
		break;
	case DVSPROC_STAT_FMT_JSON:
		_stat_flush(snp);
		seq_printf(snp->m, "%s\"%s\"%s\"%s\"",
			   _json_comma(snp), tag,
			   _json_colon(snp), value);
		break;
	}
}

/*
 * Finish up the representation.
 */
static void
_stat_term(statnode_t *snp)
{
	switch (snp->format) {
	case DVSPROC_STAT_FMT_FLAT:
		/* nothing to do */
		break;
	case DVSPROC_STAT_FMT_JSON:
		/* close all open objects, final LF */
		while (snp->depth > 0)
			_stat_pop(snp);
		seq_printf(snp->m, "\n");
		break;
	}
	_stat_clear(snp);
}

/* 
 * End of structured formatting helper routines.
 */
/*************************************************************************/

/*
 * Print test output for unit tests of formatting routines.
 */
void
dvsproc_stat_print_test(struct seq_file *m, struct dvsproc_stat *stats)
{
	statnode_t sn;
	int verbose = (stats->fflags & DVSPROC_STAT_FFLG_VERBOSE) != 0;

	_stat_init(&sn, m, stats);
	_stat_push(&sn, NULL);
	 _stat_push(&sn, "container");
	  _stat_push(&sn, "nevervisible");
	  _stat_pop(&sn);
	  _stat_prnum(&sn, "value1", 1, 0);
	  _stat_push(&sn, "sub");
	   _stat_prnum(&sn, "value2", 2, 0);
	   _stat_prnum(&sn, "value3", 3, 0);
	  _stat_pop(&sn);
	  _stat_prnum(&sn, "value4", 4, 0);
	  _stat_prnum(&sn, "value5_1", 5000, 1);
	  _stat_prnum(&sn, "value5_2", 5000, 2);
	  _stat_prnum(&sn, "value5_3", 5000, 3);
	  _stat_prnum(&sn, "value5_4", 5000, 4);
	  _stat_prstr(&sn, "string1", "string1");
	  _stat_push(&sn, "invisible");
	   if (verbose)
		_stat_prstr(&sn, "invisible1", "invisible1");
	  _stat_pop(&sn);
	  _stat_push(&sn, "invisible1");
	   _stat_push(&sn, "invisible2");
	   _stat_pop(&sn);
	   if (verbose)
		_stat_prstr(&sn, "invisible2", "invisible2");
	  _stat_pop(&sn);
	  _stat_push(&sn, "visible1");
	   _stat_push(&sn, "visible2");
	    _stat_prstr(&sn, "string2", "string2");
	    _stat_prstr(&sn, "string22", "string2");
	    _stat_prstr(&sn, "string222", "string2");
	    _stat_prstr(&sn, "string2222", "string2");
	    _stat_prstr(&sn, "string22222", "string2");
	    _stat_prstr(&sn, "string222222", "string2");
	   _stat_pop(&sn);
	  _stat_pop(&sn);
	_stat_term(&sn);
}

/*
 * Print statistics in the HELP format, which describes the output.
 */
void
dvsproc_stat_print_help(struct seq_file *m, struct dvsproc_stat *stats)
{
	static char *help =
		"STATS HELP VERSION %ld\n"
		"SECTIONS\n"
		"  STATS         = DVS stats file flags\n"
		"  RQ            = DVS Request counters\n"
		"  OP            = DVS Operation counters\n"
		"  IPC           = DVS Inter-Process Communication counters\n"
		"  PERF          = DVS Performance counters\n"
		;
	static char *help_stats =
		"\n"
		"STATS\n"
		"  version       = current stats version number\n"
		"  flags         = current stats enable state and format flags\n"
		;
	static char *help_rq =
		"\n"
		"RQ\n"
		"  reqtype       = type of IPC message request\n"
		"    req         = IPC operation initiated on this node\n"
		"    reqp        = IPC operation initiated by remote request\n"
		"      ok        = count of successes\n"
		"      err       = count of errors\n"
		"      dur       = duration of operation\n"
		"        prv     = last operation time in msec\n"
		"        max     = maximum operation time in msec\n"
		;
	static char *help_op =
		"OP\n"
		"  optype        = type of FS operation\n"
		"    ok          = count of successes\n"
		"    err         = count of errors\n"
		"    dur         = duration of operation\n"
		"      prv       = last operation time in msec\n"
		"      max       = maximum operation time in msec\n"
		;
	static char *help_ipc =
		"\n"
		"IPC\n"
		"  optype        = type of IPC request\n"
		"    ok          = count of successes\n"
		"    err         = count of failures\n"
		;
	static char *help_perf =
		"\n"
		"PERF\n"
		"  user          = application requests\n"
		"  cache         = cache or mmap requests\n"
		"    read        = read operations\n"
		"    write       = write operations\n"
		"      min_len   = low-water mark length\n"
		"      max_len   = high-water mark length\n"
		"      max_off   = high-water mark position\n"
		"        total   = accumulated totals since module load\n"
		"        rate    = accumulated totals since last stats read\n"
		"          iops  = count of operations\n"
		"          bytes = count of bytes\n"
		"  files         = file information\n"
		"    inodes      = local inode statistics\n"
		"      created   = count of local inodes created\n"
		"      deleted   = count of local inodes deleted\n"
		"    created     = count of remote files created\n"
		"    open        = count of files currently open\n"
		;
	seq_printf(m, help, stats->version);
	seq_printf(m, help_stats);
	seq_printf(m, help_rq);
	seq_printf(m, help_op);
	seq_printf(m, help_ipc);
	seq_printf(m, help_perf);
}

/*
 * Compute the iops/sec and bytes/sec.
 */
static void
_compute_rate(atomic64_t *data, unsigned long *iops, unsigned long *bytes)
{
	/* Note the use of atomic read-and-set */
	unsigned long last_iops = atomic64_xchg(&data[4], 0);
	unsigned long last_bytes = atomic64_xchg(&data[5], 0);
	unsigned long curr_jiffies = jiffies;	
	unsigned long last_jiffies = atomic64_xchg(&data[6], curr_jiffies);
	unsigned long elapsed = curr_jiffies - last_jiffies;
	if (elapsed > 0) {
		elapsed = jiffies_to_msecs(elapsed);
		*iops = (1000 * last_iops) / elapsed;
		*bytes = (1000 * last_bytes) / elapsed;
	} else {
		*iops = 0;
		*bytes = 0;
	}
}

/*
 * Print statistics in any of the new structured formats.
 */
void
dvsproc_stat_print_data(struct seq_file *m, struct dvsproc_stat *stats)
{
#if	defined(PSH) || defined(POP)
#error	PSH and POP must not be already defined
#endif
#define	PSH(_txt_)	_stat_push(&sn, _txt_); do
#define	POP()		while(0); _stat_pop(&sn);
	struct dvsproc_stat_counters *counters;
	statnode_t sn;
	unsigned long good;
	unsigned long fail;
	unsigned long bmin;
	unsigned long bmax;
	unsigned long tprv;
	unsigned long tmax;
	unsigned long iops;
	unsigned long bytes;
	int verbose = (stats->fflags & DVSPROC_STAT_FFLG_VERBOSE) != 0;
	int i;
	char buf[256];

	/* Render options as readable text */
	_stat_flags_to_string(buf, sizeof(buf), stats);

	_stat_init(&sn, m, stats);
	_stat_push(&sn, NULL);

	PSH("STATS") {
	  _stat_prnum(&sn, "version", stats->version, 0);
	  _stat_prstr(&sn, "flags", buf);
	} POP()

	/* If disabled, all we show is version and flags */
	if (! (counters = dvsproc_stat_get_counters(stats)))
		goto done;

	PSH("RQ") {
	  for (i = 0; i < DVSPROC_STAT_REQ_COUNTERS; i++) {
		const char *tag = file_request_to_string(i);
		PSH(tag) {
		  good = atomic64_read(&counters->request[i][0]);
		  fail = atomic64_read(&counters->request[i][1]);
		  if (verbose || good || fail) {
			PSH("req") {
			  _stat_prnum(&sn, "ok", good, 0);
			  _stat_prnum(&sn, "err", fail, 0);
			} POP()
		  }
		  good = atomic64_read(&counters->requestp[i][0]);
		  fail = atomic64_read(&counters->requestp[i][1]);
		  tprv = atomic64_read(&counters->requestp[i][2]);
		  tmax = atomic64_read(&counters->requestp[i][3]);
		  if (verbose || good || fail) {
			tprv = jiffies_to_msecs(tprv);
			tmax = jiffies_to_msecs(tmax);
			PSH("reqp") {
			  _stat_prnum(&sn, "ok", good, 0);
			  _stat_prnum(&sn, "err", fail, 0);
			  PSH("dur") {
			    _stat_prnum(&sn, "prv", tprv, 3);
			    _stat_prnum(&sn, "max", tmax, 3);
			  } POP()
			} POP()
		  }
		  switch (i) {
		  case RQ_PARALLEL_READ:	/* (srv agg, cli mnt) sync read */
		  case RQ_READPAGES_RQ:		/* (srv agg) page read */
		  case RQ_READPAGES_RP:		/* unused */
		  case RQ_READPAGE_ASYNC:	/* (srv agg) dvs_rq_readpage_async() (deprecated) */
		  case RQ_READPAGE_DATA:	/* (cli mnt) dvs_rq_readpage_data() (deprecated) */
			bmin = atomic64_read(&counters->read_min);
			bmax = atomic64_read(&counters->read_max);
			if (verbose || bmin || bmax) {
				PSH("read") {
				  _stat_prnum(&sn, "min", bmin, 0);
				  _stat_prnum(&sn, "max", bmax, 0);
				} POP()
			}
			break;
		  case RQ_PARALLEL_WRITE:	/* (srv agg, cli mnt) sync write */
			bmin = atomic64_read(&counters->write_min);
			bmax = atomic64_read(&counters->write_max);
			if (verbose || bmin || bmax) {
				PSH("write") {
				  _stat_prnum(&sn, "min", bmin, 0);
				  _stat_prnum(&sn, "max", bmax, 0);
				} POP()
			}
			break;
		  }
		} POP()
	  }
	} POP()

	PSH("OP") {
	  for (i = 0; i < DVSPROC_STAT_OPER_COUNTERS; i++) {
		const char *tag = vfs_op_to_string(i);
		atomic64_t *ary = counters->vfsops[i];

		PSH(tag) {
		  good = atomic64_read(&ary[0]);
		  fail = atomic64_read(&ary[1]);
		  tprv = atomic64_read(&ary[2]);
		  tmax = atomic64_read(&ary[3]);

		  if (verbose || good || fail) {
			tprv = jiffies_to_msecs(tprv);
			tmax = jiffies_to_msecs(tmax);
			_stat_prnum(&sn, "ok", good, 0);
			_stat_prnum(&sn, "err", fail, 0);
			PSH("dur") {
			  _stat_prnum(&sn, "prv", tprv, 3);
			  _stat_prnum(&sn, "max", tmax, 3);
			} POP()
		  }
		} POP()
	  }
	} POP()

	PSH("IPC") {
		good = atomic64_read(&counters->ipc_request[0]);
		fail = atomic64_read(&counters->ipc_request[1]);
		if (verbose || good || fail) {
			PSH("requests") {
			  _stat_prnum(&sn, "ok", good, 0);
			  _stat_prnum(&sn, "err", fail, 0);
			} POP()
		}
		good = atomic64_read(&counters->ipc_request_async[0]);
		fail = atomic64_read(&counters->ipc_request_async[1]);
		if (verbose || good || fail) {
			PSH("async_requests") {
			  _stat_prnum(&sn, "ok", good, 0);
			  _stat_prnum(&sn, "err", fail, 0);
			} POP()
		}
		good = atomic64_read(&counters->ipc_reply[0]);
		fail = atomic64_read(&counters->ipc_reply[1]);
		if (verbose || good || fail) {
			PSH("replies") {
			  _stat_prnum(&sn, "ok", good, 0);
			  _stat_prnum(&sn, "err", fail, 0);
			} POP()
		}
	} POP()

	PSH("PERF") {
	  PSH("user") {
	    PSH("read") {
	      atomic64_t *ary = counters->user_read_stats;
	      bmin = atomic64_read(&ary[0]);
	      bmax = atomic64_read(&ary[1]);
	      if (verbose || bmin || bmax) {
		      _stat_prnum(&sn, "min_len", bmin, 0);
		      _stat_prnum(&sn, "max_len", bmax, 0);
		      _stat_prnum(&sn, "max_off", atomic64_read(&ary[7]), 0);
		      PSH("total") {
			_stat_prnum(&sn, "iops", atomic64_read(&ary[2]), 0);
			_stat_prnum(&sn, "bytes", atomic64_read(&ary[3]), 0);
		      } POP()
		      PSH("rate") {
			_compute_rate(ary, &iops, &bytes);
			_stat_prnum(&sn, "iops", iops, 0);
			_stat_prnum(&sn, "bytes", bytes, 0);
		      } POP()
	      }
	    } POP()
	    PSH("write") {
	      atomic64_t *ary = counters->user_write_stats;
	      bmin = atomic64_read(&ary[0]);
	      bmax = atomic64_read(&ary[1]);
	      if (verbose || bmin || bmax) {
		      _stat_prnum(&sn, "min_len", bmin, 0);
		      _stat_prnum(&sn, "max_len", bmax, 0);
		      _stat_prnum(&sn, "max_off", atomic64_read(&ary[7]), 0);
		      PSH("total") {
			_stat_prnum(&sn, "iops", atomic64_read(&ary[2]), 0);
			_stat_prnum(&sn, "bytes", atomic64_read(&ary[3]), 0);
		      } POP()
		      PSH("rate") {
			_compute_rate(ary, &iops, &bytes);
			_stat_prnum(&sn, "iops", iops, 0);
			_stat_prnum(&sn, "bytes", bytes, 0);
		      } POP()
	      }
	    } POP()
	  } POP()
	  PSH("cache") {
	    PSH("read") {
	      atomic64_t *ary = counters->page_read_stats;
	      bmin = atomic64_read(&ary[0]);
	      bmax = atomic64_read(&ary[1]);
	      if (verbose || bmin || bmax) {
		      _stat_prnum(&sn, "min_len", bmin, 0);
		      _stat_prnum(&sn, "max_len", bmax, 0);
		      _stat_prnum(&sn, "max_off", atomic64_read(&ary[7]), 0);
		      PSH("total") {
			_stat_prnum(&sn, "iops", atomic64_read(&ary[2]), 0);
			_stat_prnum(&sn, "bytes", atomic64_read(&ary[3]), 0);
		      } POP()
		      PSH("rate") {
			_compute_rate(ary, &iops, &bytes);
			_stat_prnum(&sn, "iops", iops, 0);
			_stat_prnum(&sn, "bytes", bytes, 0);
		      } POP()
	      }
	    } POP()
	    PSH("write") {
	      atomic64_t *ary = counters->page_write_stats;
	      bmin = atomic64_read(&ary[0]);
	      bmax = atomic64_read(&ary[1]);
	      if (verbose || bmin || bmax) {
		      _stat_prnum(&sn, "min_len", bmin, 0);
		      _stat_prnum(&sn, "max_len", bmax, 0);
		      _stat_prnum(&sn, "max_off", atomic64_read(&ary[7]), 0);
		      PSH("total") {
			_stat_prnum(&sn, "iops", atomic64_read(&ary[2]), 0);
			_stat_prnum(&sn, "bytes", atomic64_read(&ary[3]), 0);
		      } POP()
		      PSH("rate") {
			_compute_rate(ary, &iops, &bytes);
			_stat_prnum(&sn, "iops", iops, 0);
			_stat_prnum(&sn, "bytes", bytes, 0);
		      } POP()
	      }
	    } POP()
	  } POP()
	  PSH("legacy") {
	    PSH("inodes") {
	      bmin = atomic64_read(&counters->inodes_created);
	      if (verbose || bmin)
		    _stat_prnum(&sn, "created", bmin, 0);
	      bmin= atomic64_read(&counters->inodes_deleted);
	      if (verbose || bmin)
		    _stat_prnum(&sn, "deleted", bmin, 0);
	    } POP()
	  } POP()
	  PSH("files") {
	    bmin = atomic64_read(&counters->files_created);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "created", bmin, 0);
	    bmin = atomic64_read(&counters->files_deleted);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "deleted", bmin, 0);
	    bmin = atomic64_read(&counters->open_files);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "open", bmin, 0);
	  } POP()
	  PSH("symlinks") {
	    bmin = atomic64_read(&counters->links_created);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "created", bmin, 0);
	    bmin = atomic64_read(&counters->links_deleted);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "deleted", bmin, 0);
	  } POP()
	  PSH("directories") {
	    bmin = atomic64_read(&counters->dirs_created);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "created", bmin, 0);
	    bmin = atomic64_read(&counters->dirs_deleted);
	    if (verbose || bmin)
		    _stat_prnum(&sn, "deleted", bmin, 0);
	  } POP()
	} POP()

done:
	_stat_term(&sn);
#undef	PSH
#undef	POP
}

/*
 * Print the statistics in the selected format.
 */
void
dvsproc_stat_print(struct seq_file *m, struct dvsproc_stat *stats)
{
	stats = GETSTATS(stats);
	if (stats->fflags & DVSPROC_STAT_FFLG_TEST) {
		dvsproc_stat_print_test(m, stats);
		return;
	}
	switch (stats->format) {
	case DVSPROC_STAT_FMT_LEGACY:
		dvsproc_stat_print_legacy(m, stats);
		break;
	case DVSPROC_STAT_FMT_HELP:
		dvsproc_stat_print_help(m, stats);
		break;
	case DVSPROC_STAT_FMT_FLAT:
	case DVSPROC_STAT_FMT_JSON:
		dvsproc_stat_print_data(m, stats);
		break;
	}
}

/*
 * Reset the counters. Done at initialization time, and if reset.
 */
void
dvsproc_stat_counters_reset(struct dvsproc_stat_counters *counters)
{
	atomic64_t open_files_tmp;

	open_files_tmp = counters->open_files;
	memset(counters, 0, sizeof(struct dvsproc_stat_counters));
	counters->open_files = open_files_tmp;
}

/*
 * Return 1 if character c is in the string s.
 */
static inline int
_charin(char c, char *s)
{
	while (*s)
		if (c == *s++)
			return 1;
	return 0;
}

/*
 * Parse the configuration string written to the proc file.
 */
int
dvsproc_stat_set_control(struct dvsproc_stat *stats, char *control)
{
	char *ptr, *key;
	char local[32];
	int value;

	/*
	 * Legacy behavior. Deprecated, but still supported. Input is
	 * a pure number, which means that simple_strtol() will consume
	 * the entire string.
	 */
	value = simple_strtol(control, &ptr, 0);
	if (*ptr == 0) {
		switch (value) {
		case 0:
			control = local;
			strcpy(control, "disable");
			break;
		case 1:
			control = local;
			strcpy(control, "enable");
			break;
		case 2:
			control = local;
			strcpy(control, "reset");
			break;
		case 3:
			control = local;
			strcpy(control, "enable,reset");
			break;
		default:
			printk(KERN_ERR
			       "DVS: invalid control code '%s'"
			       " for mount %d\n",
			       control, stats->mountpoint_id);
			return -EINVAL;
		}
	}

	/*
	 * Parse the supplied string. We allow comma, semicolon, space, or LF
	 * as the parameter separator. Bad parameters produce an error message
	 * in the logs, but are otherwise ignored.
	 */
	ptr = control;
	while (*ptr) {
		/* Chop off the next value */
		key = ptr;
		while (*ptr && ! _charin(*ptr, ", ;\n")) ptr++;
		if (*ptr) *ptr++ = 0;

		if (!strcmp(key, "disable")) {
			stats->control = 0;
			KDEBUG_INF(0, "DVS: statistics DISABLED for mount %d\n",
				   stats->mountpoint_id);
		} else if (!strcmp(key, "enable")) {
			stats->control = 1;
			KDEBUG_INF(0, "DVS: statistics ENABLED for mount %d\n",
				   stats->mountpoint_id);
		} else if (!strcmp(key, "reset")) {
			dvsproc_stat_counters_reset(&stats->counters);
			KDEBUG_INF(0, "DVS: statistics RESET for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "legacy")) {
			stats->format = DVSPROC_STAT_FMT_LEGACY;
			KDEBUG_INF(0, "DVS: LEGACY format set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "help")) {
			stats->format = DVSPROC_STAT_FMT_HELP;
			KDEBUG_INF(0, "DVS: HELP format set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "flat")) {
			stats->format = DVSPROC_STAT_FMT_FLAT;
			KDEBUG_INF(0, "DVS: TEXT format set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "json")) {
			stats->format = DVSPROC_STAT_FMT_JSON;
			KDEBUG_INF(0, "DVS: JSON format set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "test")) {
			stats->fflags |= DVSPROC_STAT_FFLG_TEST;
			KDEBUG_INF(0, "DVS: TEST output set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "notest")) {
			stats->fflags &= ~DVSPROC_STAT_FFLG_TEST;
			KDEBUG_INF(0, "DVS: NOTEST output set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "verbose")) {
			stats->fflags |= DVSPROC_STAT_FFLG_VERBOSE;
			KDEBUG_INF(0, "DVS: VERBOSE output set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "brief")) {
			stats->fflags &= ~DVSPROC_STAT_FFLG_VERBOSE;
			KDEBUG_INF(0, "DVS: BRIEF output set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "pretty")) {
			stats->fflags |= DVSPROC_STAT_FFLG_PRETTY;
			KDEBUG_INF(0, "DVS: PRETTY output set for mount %d\n",
			       stats->mountpoint_id);
		} else if (!strcmp(key, "raw") || !strcmp(key, "plain")) {
			stats->fflags &= ~DVSPROC_STAT_FFLG_PRETTY;
			KDEBUG_INF(0, "DVS: RAW output set for mount %d\n",
			       stats->mountpoint_id);
		} else {
			printk(KERN_ERR
			       "DVS: invalid control directive '%s'"
			       " for mount %d\n",
			       key, stats->mountpoint_id);
		}
	}
	return 0;
}

/*
 * Start up the module.
 */
void
dvsproc_stat_init(struct dvsproc_stat *stats, int mountpoint_id)
{
	/* Note: if too small, this will simply truncate the options */
	char defaults[128];

	/* calling error */
	if (! stats) BUG();
	/* Set the mountpoint ID before anything else, for debug messages */
	stats->mountpoint_id = mountpoint_id;
	/* Set the magic number  */
	stats->magic = DVSPROC_STAT_MAGIC;
	/* version is a fixed number for this compile */
	stats->version = DVSPROC_STAT_VERSION;
	/* deprecated: use this to pre-load the default state */
	stats->control = dvsproc_stat_control;
	/* make a writable copy of the module parameter */
	snprintf(defaults, sizeof(defaults), "%s", dvsproc_stat_defaults);
	/* parse the writable copy */
	dvsproc_stat_set_control(stats, defaults);
	/* always reset the counters */
	dvsproc_stat_counters_reset(&stats->counters);
}

EXPORT_SYMBOL(dvsproc_stat_update);
