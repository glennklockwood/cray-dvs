/*
 * Copyright 2016-2017 Cray Inc. All Rights Reserved.
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

#define	_GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <regex.h>
#include "common.h"

#define	RED	"\033[31m"
#define	GRN	"\033[32m"
#define	BLK	"\033[39m"

static int  _verbose = 1;
static int  _color = 1;
static FILE *_logfd = NULL;
static char *_suite = NULL;
static char **_names = NULL;
static int  *_errors = NULL;
static struct timeval *_times = NULL;
static int  _depth = 0;
static int  _maxdepth = 0;
static char *_prefix = NULL;
static int  _prelen = 0;
static int  _maxprelen = 0;
static int  _failcnt = 0;
static struct timeval _starttime = {0,0};

static int  *errp = NULL;

typedef struct {
	int	index;		// preserves order as presented from file
	char	key[48];	// flat format key
	char	val[16];	// flat format value
} keyval_t;

static keyval_t *_kvp = NULL;	// cache of values, refresh with read_stats()
static int _kvlen = 0;		// number of keys seen
static int _kvsiz = 0;		// space allocated for keys

/*
 * Sort routine to implement bsearch().
 */
static int
_sort_key(const void *v1, const void *v2)
{
	keyval_t *k1 = (keyval_t *)v1;
	keyval_t *k2 = (keyval_t *)v2;
	return strcmp(k1->key, k2->key);
}

static int
_parse_mount(char *buffer, char **rem, char **loc, char **typ, char **stats)
{
static  char *regpat = "^([^ ]+) on ([^ ]+) type ([^ ]+).*,statsfile=([^,]+),";
static  regex_t regex;
static  int init = 0;
        regmatch_t regmatch[5];
        char *sub[5];
        int ii;

        if (! init) {
                init = 1;
                if (regcomp(&regex, regpat, REG_EXTENDED) < 0) {
                        perror("regcomp");
                        return -1;
                }
        }

        if (regexec(&regex, buffer, 5, regmatch, 0) < 0)
                return -1;
        for (ii = 1; ii < 5; ii++) {
                sub[ii] = &buffer[regmatch[ii].rm_so];
                buffer[regmatch[ii].rm_eo] = 0;
        }
        if (rem) *rem = sub[1];
        if (loc) *loc = sub[2];
        if (typ) *typ = sub[3];
        if (stats) *stats = sub[4];
        return 0;
}

/*
 * Parse the 'mount -t dvs' output to find the current mntid number for
 * the mnt_path. Returns the path pointer (filled in with the path) if
 * found, otherwise NULL.
 */
char *
stats_file_path(char *path, int siz, const char *mnt_path)
{
	memset(path, 0, siz);
	if (! mnt_path) {
		snprintf(path, siz, "/proc/fs/dvs/stats");
	} else {
		char buffer[1024];
		FILE *fd;
		if (!(fd = popen("mount -t dvs", "r"))) {
			perror("popen mount");
			return NULL;
		}
		while (fgets(buffer, sizeof(buffer), fd)) {
                        char *rem, *loc, *typ, *stats;
                        if (_parse_mount(buffer, &rem, &loc, &typ, &stats) < 0)
                                continue;
                        if (strcmp(typ, "dvs"))
				continue;
                        if (strcmp(loc, mnt_path))
				continue;
                        snprintf(path, siz, "%s", stats);
			break;
		}
		pclose(fd);
	}
	if (! *path) {
		errno = ENOENT;
		perror(mnt_path);
		return NULL;
	}
	return path;
}

/*
 * Write to the stats file. Note that the correct stats file path must
 * be provided, NOT the mount path. This is static, and is used only in
 * this code module.
 */
int
stats_write(const char *path, const char *options)
{
	FILE *fd;
	/* Force the format */
	if (!(fd = fopen(path, "w"))) {
		perror("stats write");
		return -1;
	}
	fprintf(fd, "%s\n", options);
	fclose(fd);
	return 0;
}

/* 
 * Populate the kvp array with data from the appropriate stats file, and
 * sort the results for quick retrieval by key.
 *
 * This finds the appropriate stats file based on mount_path of the DVS
 * file system.
 */
int
stats_read(const char *path)
{
	char buffer[1024];
	FILE *fd;

	/* Force the format */
	if (stats_write(path, "flat,verbose,raw") < 0) {
		perror("stats write");
		return -1;
	}

	/* Open the stats file to read */
	if (!(fd = fopen(path, "r"))) {
		perror("fopen read");
		return -1;
	}

	/* Read the entire file into structured memory */
	_kvlen = 0;
	while (fgets(buffer, sizeof(buffer), fd)) {
		char *src;
		char *dst;
		char *end;

		/* Standard self-expanding memory */
		if (_kvlen >= _kvsiz) {
			_kvsiz += 128;
			_kvp = realloc(_kvp, _kvsiz * sizeof(keyval_t));
		}

		/* Copy the key into the memory structure */
		src = buffer;
		dst = _kvp[_kvlen].key;
		end = dst + sizeof(_kvp[_kvlen].key) - 1;
		while (*src && !isspace(*src) && dst < end)
			*dst++ = *src++;
		*dst = 0;

		/* Skip the whitespace */
		while (isspace(*src)) src++;

		/* Copy the value into the memory structure */
		dst = _kvp[_kvlen].val;
		end = dst + sizeof(_kvp[_kvlen].val) - 1;
		while (*src && !isspace(*src) && dst < end)
			*dst++ = *src++;
		*dst = 0;

		/* Add the index value */
		_kvp[_kvlen].index = _kvlen;

		/* Advance to the next spot in the array */
		_kvlen++;
	}
	fclose(fd);

	/* Sort this array into key-order */
	qsort(_kvp, _kvlen, sizeof(keyval_t), _sort_key);

	return 0;
}

/*
 * Fetch the value associated with a particular key.
 *
 * This returns NULL if the stats have never been loaded, or if the specified
 * key is not found.
 */
const char *
stats_getval(const char *key)
{
	keyval_t kkey, *pkey;
	if (! _kvp) {
		errno = ENOENT;
		return NULL;
	}
	snprintf(kkey.key, sizeof(kkey.key), "%s", key);
	pkey = bsearch(&kkey, _kvp, _kvlen, sizeof(keyval_t), _sort_key);
	if (! pkey) {
		errno = ENOENT;
		return NULL;
	}
	return pkey->val;
}

int
dvs_mkdir_p(const char *dirpath)
{
	FILE *fd;
	char cmd[256];
	char buf[256];

	snprintf(cmd, sizeof(cmd), "mkdir -p %s", dirpath);
	if (! (fd = popen(cmd, "r")))
		return -1;
	while (fgets(buf, sizeof(buf), fd))
		;
	pclose(fd);
	return 0;
}

int
dvs_umount_all(void)
{
        FILE *fd;
        char buffer[1024];
        int err = 0;
        test_debug("Unmount all\n");
        if (!(fd = popen("mount -t dvs", "r"))) {
                perror("popen mount");
                return -1;
        }
        while (fgets(buffer, sizeof(buffer), fd)) {
                char *rem, *loc, *typ, *stats;
                int retry = 10;
                if (_parse_mount(buffer, &rem, &loc, &typ, &stats) < 0)
                        continue;
                if (strcmp(typ, "dvs"))
                        continue;
                while (retry-- > 0) {
                        test_debug("Unmount %s\n", loc);
                        if (! umount2(loc, 0))
                                break;
                        if (errno != EBUSY) {
                                perror("unmount");
                                fprintf(stderr, "Could not unmount %s\n", loc);
                                err++;
                                break;
                        }
                        sleep(1);
                }
                if (retry < 0 && umount2(loc, MNT_FORCE) < 0) {
                        perror("unmount force");
                        fprintf(stderr, "Could not unmount force %s\n", loc);
                        err++;
                }
        }
        pclose(fd);
        return (!err) ? 0 : -1;
}

int
dvs_mount(const char *remote, const char *local, const char *host, ...)
{
	char cmd[256];
	char buf[256];
	char *p = &cmd[0];
	char *e = &cmd[sizeof(cmd)];
	va_list args;
	char *opt;
	FILE *fd;

        test_debug("Mount %s:%s on %s\n", host, remote, local);
        p += snprintf(p, e-p, "mount -t dvs -o \"");
	p += snprintf(p, e-p, "path=%s", remote);
	p += snprintf(p, e-p, ",nodename=%s", host);
	va_start(args, host);
	while ((opt = va_arg(args, char *))) {
		p += snprintf(p, e-p, ",%s", opt);
	}
	va_end(args);
	p += snprintf(p, e-p, "\" %s %s", remote, local);
	if (!(fd = popen(cmd, "r")))
		return -1;
	while (fgets(buf, sizeof(buf), fd))
		;
	pclose(fd);
	sleep(1);
	return 0;
}

/**
 * Full cleanup of memory allocation.
 *
 * @author jnemeth (9/30/16)
 */
static void
_reset_suite(void)
{
	free(_prefix);
	free(_suite);
	free(_names);
	free(_times);
	free(_errors);
	_prefix = NULL;
	_suite = NULL;
	_names = NULL;
	_times = NULL;
	_errors = NULL;
	_depth = 0;
	_maxdepth = 0;
	_prelen = 0;
	_maxprelen = 0;
	_failcnt = 0;
	errp = NULL;
}

/**
 * Initialize the start time value.
 *
 * @author jnemeth (9/30/16)
 *
 * @param force - if non-zero, reset start time even if already set
 */
static inline void
_initstarttime(int force)
{
	if (force || (!_starttime.tv_sec && !_starttime.tv_usec))
		gettimeofday(&_starttime, NULL);
}

/**
 * Compute elapsed time since the specified time.
 *
 * @author jnemeth (9/30/16)
 *
 * @param elapsed - pointer to return structure
 * @param since - starting time, or NULL to use _starttime
 */
static inline void
_elapsed(struct timeval *elapsed, struct timeval *since)
{
	_initstarttime(0);
	if (!since)
		since = &_starttime;
	gettimeofday(elapsed, NULL);
	if (elapsed->tv_usec < since->tv_usec) {
		elapsed->tv_usec += 1000000;
		elapsed->tv_sec  -= 1;
	}
	elapsed->tv_usec -= since->tv_usec;
	elapsed->tv_sec  -= since->tv_sec;
}

/**
 * Provide [FAIL] or [pass] string, with color decorators.
 *
 * If errcnt < 0, this returns an empty string.
 * If errcnt == 0, this returns the pass string.
 * If errcnt > 0, this returns the fail string.
 *
 * If color is set to 0, this will suppress color decorators. Otherwise, the
 * color decorators will be based on the value of global _color, set by
 * test_set_color().
 *
 * @author jnemeth (9/28/16)
 *
 * @param errcnt - determines string to return
 * @param color  - set to zero to suppress color
 *
 * @return const char* pass/fail string
 */
static inline const char *
_passfailtxt(int errcnt, int color)
{
	if (errcnt < 0)
		return "";
	if (color && _color)
		return (errcnt > 0) ? RED "[FAIL] " BLK : GRN "[pass] " BLK;
	return (errcnt > 0) ? "[FAIL] " : "[pass] ";
}

/**
 * Provide ERROR string with color decorators.
 *
 * If iserr == 0, this returns an empty string.
 * If iserr != 0, this returns the ERROR string.
 *
 * If color is set to 0, this will suppress color decorators. Otherwise, the
 * color decorators will be based on the value of global _color, set by
 * test_set_color().
 *
 * @author jnemeth (9/28/16)
 *
 * @param iserr - determines string to return
 * @param color - set to zero to suppress color
 *
 * @return const char* error string
 */
static inline const char *
_errortxt(int iserr, int color)
{
	if (! iserr)
		return "";
	if (color && _color)
		return RED "ERROR " BLK;
	return "ERROR ";
}

/**
 * Provides a default name, if none specified.
 *
 * @author jnemeth (9/28/16)
 *
 * @param name - name to return, or NULL
 *
 * @return const char* non-NULL name string
 */
static inline const char *
_nametxt(const char *name)
{
	return (name) ? name : "test";
}

/**
 * Provide a default prefix, if none defined.
 *
 * @author jnemeth (9/28/16)
 *
 * @return const char* non-NULL prefix name
 */
static inline const char *
_prefixtxt(void)
{
	return (_prelen) ? _prefix : "";
}

/**
 * Provide a space, if _prefix is defined, or an empty string otherwise.
 *
 * @author jnemeth (9/28/16)
 *
 * @return const char* space or empty string
 */
static inline const char *
_prefixspace(void)
{
	return (_prelen) ? " " : "";
}

/**
 * Provide a default suite name, if none specified.
 *
 * @author jnemeth (9/28/16)
 *
 * @return const char* non-NULL suite name
 */
static inline const char *
_suitetxt(void)
{
	return (_suite) ? _suite : "all tests";
}

/**
 * Open the specified log file.
 *
 * @author jnemeth (9/28/16)
 *
 * @param logpath - path of file to open
 *
 * @return int 0 on success, -1 on failure
 */
int
test_openlog(const char *logpath)
{
	if (logpath && *logpath) {
		test_closelog();
		_logfd = fopen(logpath, "wb");
	}
	return (_logfd) ? 0 : -1;
}

/**
 * Close the log file, if open.
 *
 * @author jnemeth (9/28/16)
 */
void
test_closelog(void)
{
	if (_logfd) {
		fclose(_logfd);
		_logfd = NULL;
	}
}

/**
 * Set the test suite name.
 *
 * @author jnemeth (9/28/16)
 *
 * @param name - test suite name, or NULL to restore default
 */
void
test_set_suite_name(const char *name)
{
	free(_suite);
	_suite = (name) ? strdup(name) : NULL;
}

/**
 * Set the test suite failure count.
 *
 * @author jnemeth (9/30/16)
 *
 * @param count - failure count to set
 */
void
test_set_fail_count(int count)
{
	_failcnt = count;
}

/**
 * Set the color decorator flag.
 *
 * @author jnemeth (9/28/16)
 *
 * @param enable - 0 to disable, else enable
 *
 * @return int - old value
 */
int
test_set_color(int enable)
{
	int old = _color;
	_color = enable;
	return old;
}

/**
 * Set verbosity level. Range is enforced.
 *
 * @author jnemeth (9/28/16)
 *
 * @param verbose - verbosity level to set
 *
 * @return int - old value
 */
int
test_set_verbose(int verbose)
{
	int old = _verbose;
	if (verbose < 0)
		verbose = 0;
	if (verbose > TEST_LOG_MAX)
		verbose = TEST_LOG_MAX;
	_verbose = verbose;
	return old;
}

/**
 * Increment verbosity by one.
 *
 * @author jnemeth (9/28/16)
 */
void
test_verboser(void)
{
        if (_verbose < TEST_LOG_MAX)
                _verbose++;
}

/**
 * Decrement verbosity by one.
 *
 * @author jnemeth (9/28/16)
 */
void
test_quieter(void)
{
        if (_verbose > 0)
                _verbose--;
}

/**
 * Internal service routine to log test messages.
 *
 * The errcnt value is passed to _passfailtxt().
 *
 * The threshold value is the verbosity threshold necessary to display this
 * message. If the value is between 0 and TEST_LOG_MAX, this is treated as a log
 * message, otherwise this is treated as an error message.
 *
 * Log messages are delivered to stdout IF the verbosity is high enough for the
 * threshold. Log messages are delivered to the log file if the threshold is
 * below TEST_LOG_DEBUG, OR if the verbosity is TEST_LOG_DEBUG. The philosophy
 * is that tests will normally be run at verbosity 0, which means that only
 * error messages, explicit test log messages, and the final result will be
 * displayed. However, if there is a failure, the log will contain everything
 * but debug level messages, so that it will be potentially useful to supply
 * more information without re-running the tests.
 *
 * Error messages are delivered to stderr, and to the log file.
 *
 * @author jnemeth (9/28/16)
 *
 * @param errcnt - see _passfailtxt()
 * @param threshold - verbosity threshold for this message
 * @param fmt - printf-like format
 * @param args - printf-like argument list
 */
static void
_vlog2(int errcnt, int threshold, const char *fmt, va_list args)
{
	struct timeval elapsed;
	FILE *fd1 = NULL;	// stdout, stderr, or NULL
	FILE *fd2 = NULL;	// _logfd, or NULL

	_elapsed(&elapsed, NULL);
	if (threshold >= 0 && threshold <= TEST_LOG_MAX) {
		fd1 = (_verbose >= threshold) ? stdout : NULL;
		fd2 = (_verbose >= threshold || threshold < TEST_LOG_DEBUG) ?
			_logfd : NULL;
	} else {
		fd1 = stderr;
		fd2 = _logfd;
	}

	if (fd1) {
		va_list args2;
		va_copy(args2, args);
		fprintf(fd1, "%s%s%s%s",
			_prefixtxt(),
			_prefixspace(),
			_passfailtxt(errcnt, 1),
			_errortxt((fd1 == stderr), 1));
		vfprintf(fd1, fmt, args2);
		va_end(args2);
	}
	if (fd2) {
		fprintf(fd2, "%4lld.%06lld %s%s%s%s",
			(long long) elapsed.tv_sec,
			(long long) elapsed.tv_usec,
			_prefixtxt(),
			_prefixspace(),
			_passfailtxt(errcnt, 0),
			_errortxt((fd1 == stderr), 0));
		vfprintf(fd2, fmt, args);
	}
}

/**
 * Variable-argument wrapper for _vlog2()
 *
 * @author jnemeth (9/28/16)
 *
 * @param errcnt - see _vlog2()
 * @param threshold - see _vlog2()
 * @param fmt - see _vlog2()
 */
static void
_log2(int errcnt, int threshold, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	_vlog2(errcnt, threshold, fmt, args);
	va_end(args);
}

/**
 * Post a debug message.
 *
 * @author jnemeth (9/28/16)
 *
 * @param fmt - printf-like format
 */
void
test_debug(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        _vlog2(-1, TEST_LOG_DEBUG, fmt, args);
        va_end(args);
}

/**
 * Post an info message.
 *
 * @author jnemeth (9/28/16)
 *
 * @param fmt - printf-like format
 */
void
test_info(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	_vlog2(-1, TEST_LOG_INFO, fmt, args);
	va_end(args);
}

/**
 * Post a log message (always printed)
 *
 * @author jnemeth (9/28/16)
 *
 * @param fmt - printf-like format
 */
void
test_log(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	_vlog2(-1, TEST_LOG_NONE, fmt, args);
	va_end(args);
}

/**
 * Post an error message.
 *
 * @author jnemeth (9/28/16)
 *
 * @param fmt - printf-like format
 */
void
test_err(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	_vlog2(-1, -1, fmt, args);
	va_end(args);
	_failcnt++;
	if (errp)
		(*errp)++;
}

/**
 * Begin a test or subtest.
 *
 * The name is used to identify this test. Each log line will be displayed with
 * an accumulation of parent-tests for this test, allowing sequences of tests to
 * be re-run under different parent tests that set up different conditions.
 *
 * This posts an INFO message indicating that the test has started.
 *
 * @author jnemeth (9/28/16)
 *
 * @param name - name of this test
 */
void
test_begin(const char *name)
{
	_initstarttime(0);
	name = _nametxt(name);
	if (_depth >= _maxdepth) {
		_maxdepth += 16;
		_names = realloc(_names, _maxdepth * sizeof(char *));
		_times = realloc(_times, _maxdepth * sizeof(struct timeval));
		_errors = realloc(_errors, _maxdepth * sizeof(int));
	}
	if (_prelen + strlen(name) + 1 >= _maxprelen) {
		_maxprelen += strlen(name) + 256;
		_prefix = realloc(_prefix, _maxprelen);
	}
	_prelen += sprintf(&_prefix[_prelen], "%s:", name);
	_names[_depth] = strdup(name);
	_errors[_depth] = 0;
	errp = &_errors[_depth];
	gettimeofday(&_times[_depth], NULL);
	_depth++;
	_log2(-1, TEST_LOG_INFO, "started\n");
}

/**
 * Complete a test or subtest.
 *
 * This posts a final pass/fail message at the INFO level, indicating the number
 * of times the test_err() function was called during this test, and if there
 * were any errors, it counts toward the total failure count for the suite. It
 * then returns to the parent test (if any).
 *
 * When the topmost parent completes, this posts a final pass/fail message at
 * the NONE level, indicating the count of failed tests in the entire suite.
 *
 * @author jnemeth (9/28/16)
 *
 * @return int - 0 if the test passed, -1 otherwise
 */
int
test_complete(void)
{
	struct timeval elapsed;
	char *newname;
	int errcnt;

	if (--_depth < 0) {
		_depth = 0;
		test_err("Coding error, test_complete() called without test_begin()\n");
		return -1;
	}
	_elapsed(&elapsed, &_times[_depth]);
	newname = _names[_depth];
	errcnt = _errors[_depth];
	errp = &_errors[_depth];
	_log2(errcnt, TEST_LOG_INFO, "completed with %d errors (%d.%06d sec)\n",
	      errcnt, elapsed.tv_sec, elapsed.tv_usec);
	_prelen -= strlen(newname) + 1;
	_prefix[_prelen] = 0;
	free(newname);
	if (errcnt && _depth-1 >= 0)
		_errors[_depth-1] += errcnt;
	return (errcnt) ? -1 : 0;
}

void
test_suite_begin(const char *name)
{
	_initstarttime(1);
	_reset_suite();
	test_set_suite_name(name);
	_log2(-1, TEST_LOG_NONE, "\n'%s' started\n", _suitetxt());
}

int
test_suite_complete(void)
{
	struct timeval elapsed;
	int errcnt = _failcnt;

	_elapsed(&elapsed, NULL);
	_log2(errcnt, TEST_LOG_NONE, "'%s' completed with %d errors (%d.%06d sec)\n",
	      _suitetxt(), errcnt, elapsed.tv_sec, elapsed.tv_usec);
	_reset_suite();
	return (errcnt) ? -1 : 0;
}

/**
 * Helper function to check the return value of test_complete().
 *
 * This increments the failure count by one if the err value does not match the
 * expected value.
 *
 * @author jnemeth (9/29/16)
 *
 * @param err - return value from test_complete()
 * @param exp - expected return value
 * @param fail - current failure count
 *
 * @return int - new failure count
 */
static int
_check_complete_return(int err, int exp, int fail)
{
	if (err != exp) {
		fprintf(stderr, "Unexpected test_complete result %d != %d\n", err, exp);
		fail++;
	}
	return fail;
}

/**
 * Helper function to count lines in the log file.
 *
 * This compares the line count to the expected line count, and increments the
 * failure count if they do not match, and also dumps the lines in the file to
 * aid in diagnosing the problem. It then deletes the log file.
 *
 * @author jnemeth (9/29/16)
 *
 * @param path - log file path
 * @param exp  - expected count of lines
 * @param fail - current failure count
 *
 * @return int - new failure count
 */
static int
_count_log_lines(const char *path, int exp, int fail)
{
	char buffer[256];
	FILE *fd;
	int count = 0;

	if (!(fd = fopen(path, "r"))) {
		fprintf(stderr, "Could not open log file to read\n");
		fail++;
		return fail;
	}
	while (fgets(buffer, sizeof(buffer), fd)) {
		count++;
	}
	if (exp < 0) {
		fprintf(stdout, "Log file contents:\n");
		rewind(fd);
		while (fgets(buffer, sizeof(buffer), fd)) {
			fprintf(stdout, ">> %s", buffer);
		}
	} else if (count != exp) {
		fprintf(stderr, "Log file line count not expected, %d != %d\n", count, exp);
		rewind(fd);
		while (fgets(buffer, sizeof(buffer), fd)) {
			fprintf(stderr, ">> %s", buffer);
		}
		fail++;
	}
	fclose(fd);
	unlink(path);
	return fail;
}

/**
 * Selftest code for the message logging.
 *
 * @author jnemeth (9/28/16)
 *
 * @return int - 0 if the test is successful, -1 otherwise
 */
int
selftest_common(void)
{
	char *logname = "/tmp/selftest_common.log";
	int fail = 0;

	/*
	 * Heuristic: Any use of test_err() during a test causes that test to
	 * fail. Any failed test causes the parent test to fail, and the suite
	 * to fail. We should see start, finish, and error messages for all
	 * tests because of TEST_LOG_INFO verbosity.
	 */
	test_set_verbose(TEST_LOG_INFO);

	test_begin("level0");
	fail = _check_complete_return(test_complete(), 0, fail);

	test_suite_begin("Simple Test");
	test_begin("level1");
	fail = _check_complete_return(test_complete(), 0, fail);
	fail = _check_complete_return(test_suite_complete(), 0, fail);

	test_suite_begin("Test with sublevel");
	test_begin("level21");
	test_begin("level22");
	fail = _check_complete_return(test_complete(), 0, fail);
	fail = _check_complete_return(test_complete(), 0, fail);
	fail = _check_complete_return(test_suite_complete(), 0, fail);

	test_suite_begin("Test with sublevel, failure");
	test_begin("level31");
	test_begin("level32a");
	fail = _check_complete_return(test_complete(), 0, fail);
	test_begin("level32b");
	test_err("oops!\n");
	fail = _check_complete_return(test_complete(), -1, fail);
	fail = _check_complete_return(test_complete(), -1, fail);
	fail = _check_complete_return(test_suite_complete(), -1, fail);

	/*
	 * Heuristic: Same as above, except that only error and suite completion
	 * messages should be seen because of TEST_LOG_NONE verbosity.
	 */
	test_set_verbose(TEST_LOG_NONE);

	test_suite_begin("Test with sublevel and success, quiet");
	test_begin("level41");
	test_begin("level42a");
	fail = _check_complete_return(test_complete(), 0, fail);
	test_begin("level42b");
	fail = _check_complete_return(test_complete(), 0, fail);
	fail = _check_complete_return(test_complete(), 0, fail);
	fail = _check_complete_return(test_suite_complete(), 0, fail);

	test_suite_begin("Test with sublevel and failure, quiet");
	test_begin(NULL);
	test_begin("level52a");
	test_err("oops!\n");
	fail = _check_complete_return(test_complete(), -1, fail);
	test_begin("level52b");
	fail = _check_complete_return(test_complete(), 0, fail);
	fail = _check_complete_return(test_complete(), -1, fail);
	fail = _check_complete_return(test_suite_complete(), -1, fail);

	/*
	 * Heuristic: Unbalanced test_complete() calls should show an error.
	 * Unbalanced test_suite_complete() should succeed (unless _failcnt is
	 * greater than zero).
	 */
	test_log("\nTest stand-alone test_complete()\n");
	fail = _check_complete_return(test_complete(), -1, fail);
	fail = _check_complete_return(test_suite_complete(), -1, fail);
	fail = _check_complete_return(test_suite_complete(), 0, fail);

	/*
	 * Heuristic: Messages should print to stdout/stderr according to the
	 * verbosity setting. Messages to log should always show all but debug
	 * messages, unless the verbosity is at debug, in which case debug
	 * messages should also appear in the log.
	 */
	test_log("\nTest stand-alone log file, verbosity 0\n");
	test_openlog(logname);
	test_set_verbose(TEST_LOG_NONE);
	test_debug("debug message\n");
	test_info("info message\n");
	test_log("log message\n");
	test_err("error message\n");
	test_closelog();
	fail = _count_log_lines(logname, 3, fail);	// err, log, info

	test_log("\nTest stand-alone log file, verbosity 1\n");
	test_openlog(logname);
	test_set_verbose(TEST_LOG_INFO);
	test_debug("debug message\n");
	test_info("info message\n");
	test_log("log message\n");
	test_err("error message\n");
	test_closelog();
	fail = _count_log_lines(logname, 3, fail);	// err, log, info

	test_log("\nTest stand-alone log file, verbosity 2\n");
	test_openlog(logname);
	test_set_verbose(TEST_LOG_DEBUG);
	test_debug("debug message\n");
	test_info("info message\n");
	test_log("log message\n");
	test_err("error message\n");
	test_closelog();
	fail = _count_log_lines(logname, 4, fail);	// err, log, info, debug

	test_log("\nTest log file format, verbosity 2\n");
	test_openlog(logname);
	test_set_verbose(TEST_LOG_DEBUG);
	test_debug("debug message\n");
	test_info("info message\n");
	test_log("log message\n");
	test_err("error message\n");
	test_closelog();
	fail = _count_log_lines(logname, -1, fail);	// display only

	/*
	 * Final message
	 */
	test_set_verbose(TEST_LOG_NONE);
	test_set_suite_name("common C logging regression");
	test_set_fail_count(fail);
	test_log("\n");
	return test_suite_complete();
}


