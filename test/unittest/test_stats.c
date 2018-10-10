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
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <regex.h>
#include <aio.h>
#include <time.h>
#include "common.h"

/**********************************************************************
 * File creation counters.
 */

static int
_do_open(const char *filename, int flags, int expret)
{
	int fn;
	int ret;

	fn = open(filename, flags, 0666);
	ret = (fn < 0) ? -1 : 0;
	if (ret != expret) {
		test_err("open('%s', 0x%x) = %d, expected %d\n",
			 filename, flags, ret, expret);
		return -2;
	}
	return fn;
}

static int
_do_create(const char *stats_path, const char *filename, int flags, int expret, int expcnt)
{
	int fn;
	int cnt;
	stats_write(stats_path, "reset");
	fn = _do_open(filename, flags, expret);
	if (fn == -2)
		return -1;
	if (fn >= 0)
		close(fn);
	stats_read(stats_path);
	cnt = atoi(stats_getval("PERF.files.created"));
	if (cnt != expcnt) {
		test_err("open('%s', 0x%x) PERF.files.created = %d, expected %d\n",
			 filename, flags, cnt, expcnt);
		return -1;
	}
        test_debug("open('%s', 0x%x) PERF.files.created = %d\n",
		  filename, flags, cnt);
	return 0;
}

static int
_test_create_count(const char *stats_path, const char *filename)
{
	test_begin("file create count");

	unlink(filename);
	_do_create(stats_path, filename, O_RDWR|O_CREAT|O_EXCL, 0, 1);
	unlink(filename);
	_do_create(stats_path, filename, O_RDWR|O_CREAT, 0, 1);
	_do_create(stats_path, filename, O_RDWR|O_CREAT, 0, 0);
	_do_create(stats_path, filename, O_RDWR|O_CREAT|O_EXCL, -1, 0);
	_do_create(stats_path, filename, O_RDWR, 0, 0);

	unlink(filename);
	_do_create(stats_path, filename, O_WRONLY|O_CREAT|O_EXCL, 0, 1);
	unlink(filename);
	_do_create(stats_path, filename, O_WRONLY|O_CREAT, 0, 1);
	_do_create(stats_path, filename, O_WRONLY|O_CREAT, 0, 0);
	_do_create(stats_path, filename, O_WRONLY|O_CREAT|O_EXCL, -1, 0);
	_do_create(stats_path, filename, O_WRONLY, 0, 0);

	unlink(filename);
	_do_create(stats_path, filename, O_RDONLY|O_CREAT|O_EXCL, 0, 1);
	unlink(filename);
	_do_create(stats_path, filename, O_RDONLY|O_CREAT, 0, 1);
	_do_create(stats_path, filename, O_RDONLY|O_CREAT, 0, 0);
	_do_create(stats_path, filename, O_RDONLY|O_CREAT|O_EXCL, -1, 0);
	_do_create(stats_path, filename, O_RDONLY, 0, 0);

	return test_complete();
}

/**********************************************************************
 * Read/write counters.
 */
#define	MAX_BUF	(2*1024*1024)
#define	MSK_BUF 0xa5a5a5a55a5a5a5a

static void
_setbuf(void *buf, ssize_t len, ssize_t off)
{
	unsigned long *p = (unsigned long *)buf;
	unsigned long rem;
	unsigned char *s, *d;

	if (len > MAX_BUF)
		len = MAX_BUF;
	while (len > sizeof(*p)) {
		*p++ = (off ^ MSK_BUF);
		off += sizeof(*p);
		len -= sizeof(*p);
	}
	rem = (off ^ MSK_BUF);
	s = (unsigned char *)&rem;
	d = (unsigned char *)p;
	while (len-- > 0)
		*d++ = *s++;
}

static int
_chkbuf(void *buf, ssize_t len, ssize_t off)
{
	unsigned long *p = (unsigned long *)buf;
	unsigned long rem;
	unsigned char *s, *d;

	if (len > MAX_BUF)
		len = MAX_BUF;
	while (len > sizeof(*p)) {
		rem = (off ^ MSK_BUF);
                if (*p != rem) {
                        test_err("Data error at off=%ld, exp 0x%lx, saw 0x%lx\n",
                                 off, rem, *p);
			return -1;
                }
		off += sizeof(*p);
		len -= sizeof(*p);
                p++;
	}
	rem = (off ^ MSK_BUF);
	s = (unsigned char *)&rem;
	d = (unsigned char *)p;
        while (len-- > 0) {
                if (*d != *s) {
                        test_err("Data error at off=%ld, exp 0x%x, saw 0x%x\n",
                                 off, *s, *d);
			return -1;
                }
                d++;
                s++;
        }
	return 0;
}

static int
_chkcnt(const char *key, ssize_t expect)
{
	ssize_t actual;
        if ((actual = strtol(stats_getval(key), NULL, 0)) != expect) {
		test_err("%s = %ld, expected %ld\n", key, actual, expect);
                return -1;
        }
        return 0;
}

typedef ssize_t (*wrfunc)(int, const void *, size_t);
typedef ssize_t (*rdfunc)(int, void *, size_t);
typedef ssize_t (*pwrfunc)(int, const void *, size_t, off_t);
typedef ssize_t (*prdfunc)(int, void *, size_t, off_t);

static ssize_t
_write(int fn, const void *buf, size_t len)
{
        return write(fn, buf, len);
}

static ssize_t
_read(int fn, void *buf, size_t len)
{
        return read(fn, buf, len);
}

static ssize_t
_writev(int fn, const void *buf, size_t len)
{
        struct iovec iov;
        iov.iov_base = (void *)buf;
        iov.iov_len = len;
        return writev(fn, &iov, 1);
}

static ssize_t
_readv(int fn, void *buf, size_t len)
{
        struct iovec iov;
        iov.iov_base = buf;
        iov.iov_len = len;
        return readv(fn, &iov, 1);
}

static ssize_t
_pwrite(int fn, const void *buf, size_t len, off_t off)
{
        return pwrite(fn, buf, len, off);
}

static ssize_t
_pread(int fn, void *buf, size_t len, off_t off)
{
        return pread(fn, buf, len, off);
}

static ssize_t
_pwritev(int fn, const void *buf, size_t len, off_t off)
{
        struct iovec iov;
        iov.iov_base = (void *)buf;
        iov.iov_len = len;
        return pwritev(fn, &iov, 1, off);
}

static ssize_t
_preadv(int fn, void *buf, size_t len, off_t off)
{
        struct iovec iov;
        iov.iov_base = buf;
        iov.iov_len = len;
        return preadv(fn, &iov, 1, off);
}

static ssize_t
_aio_pwrite(int fn, const void *buf, size_t len, off_t off)
{
static  struct timespec delay = {0, 1000000};
        struct aiocb cb;
        ssize_t rtn;
        int err;

        memset(&cb, 0, sizeof(cb));
        cb.aio_fildes = fn;
        cb.aio_buf = (void *)buf;
        cb.aio_nbytes = len;
        cb.aio_offset = off;
        if (aio_write(&cb) < 0)
                return -1;
        while ((err = aio_error(&cb) == EINPROGRESS))
                nanosleep(&delay, NULL);
        rtn = aio_return(&cb);
        if (err > 0)
                errno = err;
        return rtn;
}

static ssize_t
_aio_pread(int fn, void *buf, size_t len, off_t off)
{
static  struct timespec delay = {0, 1000000};
        struct aiocb cb;
        ssize_t rtn;
        int err;

        memset(&cb, 0, sizeof(cb));
        cb.aio_fildes = fn;
        cb.aio_buf = (void *)buf;
        cb.aio_nbytes = len;
        cb.aio_offset = off;
        if (aio_read(&cb) < 0)
                return -1;
        while ((err = aio_error(&cb) == EINPROGRESS))
                nanosleep(&delay, NULL);
        rtn = aio_return(&cb);
        if (err > 0)
                errno = err;
        return rtn;
}

static int
_test_write_read(const char *hdr, const char *stats_path, const char *filename,
                 wrfunc _wr, rdfunc _rd, int notaio, int notcache)
{
        void *buf = malloc(MAX_BUF);
        ssize_t len, cnt, off, act, ii;
        int fn;

        test_begin(hdr);
        fn = _do_open(filename, O_RDWR|O_CREAT|O_TRUNC, 0);
        if (fn < 0)
                return fn;
        for (len = 16; len < MAX_BUF; len *= 2) {
                stats_write(stats_path, "reset");
                test_debug("testing block size of %ld bytes\n", len);
                cnt = (MAX_BUF/len)*2;
                if (cnt > 32)
                        cnt = 32;
                off = 0;
                lseek(fn, off, SEEK_SET);
                for (ii = 0; ii < cnt; ii++) {
                        _setbuf(buf, len, off);
                        if ((act = _wr(fn, buf, len)) < len) {
                                if (act < 0)
                                        perror("write");
                                test_err("write(%d,%d) = %d, expected %d\n", len, off, act, len);
                                goto done;
                        }
                        stats_read(stats_path);
                        _chkcnt("PERF.user.write.min_len", len);
                        _chkcnt("PERF.user.write.max_len", len);
                        _chkcnt("PERF.user.write.max_off", off + len);
                        _chkcnt("PERF.user.write.total.iops", ii+1);
                        _chkcnt("PERF.user.write.total.bytes", (ii+1) * len);
                        off += len;
                }
                _chkcnt("OP.write.ok", notaio*cnt);
                _chkcnt("OP.aio_write.ok", cnt);
                off = 0;
                lseek(fn, off, SEEK_SET);
                for (ii = 0; ii < cnt; ii++) {
                        memset(buf, 0, len);
                        if ((act = _rd(fn, buf, len)) < len) {
                                if (act < 0)
                                        perror("read");
                                test_err("read(%d,%d) = %d, expected %d\n", len, off, act, len);
                                goto done;
                        }
                        if (_chkbuf(buf, len, off))
                                goto done;
                        stats_read(stats_path);
                        _chkcnt("PERF.user.read.min_len", len);
                        _chkcnt("PERF.user.read.max_len", len);
                        _chkcnt("PERF.user.read.max_off", off + len);
                        _chkcnt("PERF.user.read.total.iops", ii+1);
                        _chkcnt("PERF.user.read.total.bytes", (ii+1) * len);
                        off += len;
                }
                _chkcnt("OP.read.ok", notaio*cnt);
                _chkcnt("OP.aio_read.ok", cnt);
        }
        close(fn);
        if (notcache) {
                _chkcnt("PERF.cache.read.min_len", 0);
                _chkcnt("PERF.cache.read.max_len", 0);
                _chkcnt("PERF.cache.read.max_off", 0);
                _chkcnt("PERF.cache.read.total.iops", 0);
                _chkcnt("PERF.cache.read.total.bytes", 0);
                _chkcnt("PERF.cache.write.min_len", 0);
                _chkcnt("PERF.cache.write.max_len", 0);
                _chkcnt("PERF.cache.write.max_off", 0);
                _chkcnt("PERF.cache.write.total.iops", 0);
                _chkcnt("PERF.cache.write.total.bytes", 0);
        }
done:
        free(buf);
        return test_complete();
}

static int
_test_pwrite_pread(const char *hdr, const char *stats_path, const char *filename,
                   pwrfunc _wr, prdfunc _rd, int notaio, int notcache)
{
	void *buf = malloc(MAX_BUF);
        ssize_t len, cnt, off, act, gap, ii;
	int fn;

        test_begin(hdr);
        fn = _do_open(filename, O_RDWR|O_CREAT|O_TRUNC, 0);
	if (fn < 0)
		return fn;
	for (gap = 0; gap < 4; gap++) {
		for (len = 16; len < MAX_BUF; len *= 2) {
			stats_write(stats_path, "reset");
                        test_debug("testing block size of %ld bytes\n", len);
			cnt = (MAX_BUF/len)*2;
			if (cnt > 32)
				cnt = 32;
			off = gap;
			for (ii = 0; ii < cnt; ii++) {
				_setbuf(buf, len, off);
                                if ((act = _wr(fn, buf, len, off)) < len) {
                                        if (act < 0)
                                                perror("write");
                                        test_err("write(%d,%d) = %d, expected %d\n", len, off, act, len);
                                        goto done;
				}
				stats_read(stats_path);
				_chkcnt("PERF.user.write.min_len", len);
				_chkcnt("PERF.user.write.max_len", len);
				_chkcnt("PERF.user.write.max_off", off + len);
				_chkcnt("PERF.user.write.total.iops", ii+1);
				_chkcnt("PERF.user.write.total.bytes", (ii+1) * len);
				off += len + gap;
			}
                        _chkcnt("OP.write.ok", notaio*cnt);
                        _chkcnt("OP.aio_write.ok", cnt);
                        off = gap;
                        for (ii = 0; ii < cnt; ii++) {
                                memset(buf, 0, len);
                                if ((act = _rd(fn, buf, len, off)) < len) {
                                        if (act < 0)
                                                perror("read");
                                        test_err("read(%d,%d) = %d, expected %d\n", len, off, act, len);
                                        goto done;
                                }
                                if (_chkbuf(buf, len, off))
                                        goto done;
                                stats_read(stats_path);
                                _chkcnt("PERF.user.read.min_len", len);
                                _chkcnt("PERF.user.read.max_len", len);
                                _chkcnt("PERF.user.read.max_off", off + len);
                                _chkcnt("PERF.user.read.total.iops", ii+1);
                                _chkcnt("PERF.user.read.total.bytes", (ii+1) * len);
                                off += len + gap;
                        }
                        _chkcnt("OP.read.ok", notaio*cnt);
                        _chkcnt("OP.aio_read.ok", cnt);
		}
	}
	close(fn);
        if (notcache) {
                _chkcnt("PERF.cache.read.min_len", 0);
                _chkcnt("PERF.cache.read.max_len", 0);
                _chkcnt("PERF.cache.read.max_off", 0);
                _chkcnt("PERF.cache.read.total.iops", 0);
                _chkcnt("PERF.cache.read.total.bytes", 0);
                _chkcnt("PERF.cache.write.min_len", 0);
                _chkcnt("PERF.cache.write.max_len", 0);
                _chkcnt("PERF.cache.write.max_off", 0);
                _chkcnt("PERF.cache.write.total.iops", 0);
                _chkcnt("PERF.cache.write.total.bytes", 0);
        }
done:
	free(buf);
	return test_complete();
}

static int
_syntax(char *prog)
{
        fprintf(stderr, "Usage: %s --host server [tests...]\n", basename(prog));
	return 1;
}

int
main(int argc, char **argv)
{
static	char *optstr = "vq";
static	struct option longopts[] = {
		{"verbose", no_argument, 0, 'v'},
		{"quiet",   no_argument, 0, 'q'},
		{0,0,0,0}
	};
	char *prog = argv[0];
	int opt;
        char *server;
	char *mnt_path;
	char stats_path[PATH_MAX];
	char filename[PATH_MAX];

	while ((opt = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
		switch (opt) {
                case 'v': test_verboser(); break;
                case 'q': test_quieter(); break;
		default:
			return _syntax(prog);
		}
	}
	argc -= optind;
	argv += optind;
        if (argc < 1) {
                return _syntax(prog);
        }
        server = *argv; argv++; argc--;

        mnt_path = "/tmp/A";
        snprintf(filename, sizeof(filename), "%s/%s", mnt_path, "testfile1.tmp");

	test_openlog("/tmp/testlog.log");
	test_begin("STATS");

        if (dvs_umount_all() < 0)
                goto done;

	dvs_mkdir_p(mnt_path);

	dvs_mount("/tmp", mnt_path, server, NULL);
	if (! stats_file_path(stats_path, sizeof(stats_path), mnt_path)) {
		test_err("mount path '%s' not found\n", mnt_path);
		goto done;
	}

	_test_create_count(stats_path, filename);

        if (_test_write_read("write/read", stats_path, filename, _write, _read, 1, 1))
                goto done;
        if (_test_write_read("write/read", stats_path, filename, _writev, _readv, 0, 1))
                goto done;

        if (_test_pwrite_pread("pwrite/pread", stats_path, filename, _pwrite, _pread, 1, 1))
                goto done;
        if (_test_pwrite_pread("pwritev/preadv", stats_path, filename, _pwritev, _preadv, 0, 1))
                goto done;
        if (_test_pwrite_pread("aio_write/aio_read", stats_path, filename, _aio_pwrite, _aio_pread, 1, 1))
                goto done;

        if (dvs_umount_all() < 0)
                goto done;

        dvs_mount("/tmp", mnt_path, server, "cache", NULL);
	if (! stats_file_path(stats_path, sizeof(stats_path), mnt_path)) {
		test_err("mount path '%s' not found\n", mnt_path);
		goto done;
	}

        _test_create_count(stats_path, filename);

        if (_test_write_read("write/read", stats_path, filename, _write, _read, 1, 1))
                goto done;
        if (_test_write_read("write/read", stats_path, filename, _writev, _readv, 0, 1))
                goto done;

        if (_test_pwrite_pread("pwrite/pread", stats_path, filename, _pwrite, _pread, 1, 1))
                goto done;
        if (_test_pwrite_pread("pwritev/preadv", stats_path, filename, _pwritev, _preadv, 0, 1))
                goto done;
        if (_test_pwrite_pread("aio_write/aio_read", stats_path, filename, _aio_pwrite, _aio_pread, 1, 1))
                goto done;

#if 0
	dvs_umount_all();
	dvs_mount("/tmp", mnt_path, server, "cache", NULL);
	_test_mmap_write(stats_path, filename);
	_test_cache_write(stats_path, filename);
#endif
        if (dvs_umount_all() < 0)
                goto done;

done:
	test_complete();
	return 0;
}
