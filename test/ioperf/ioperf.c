/*
 * ioperf - basic I/O data and metadata benchmark
 *
 * Copyright 2010-2012, 2016-2017 Cray Inc. All Rights Reserved.
 *
 * This file is part of Cray Data Virtualization Service (DVS).
 *
 * DVS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * DVS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License,
 * version 2, along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 *
 * ioperf is a simple benchmark that can perform read, write, open/close,
 * and create/unlink operations.  It can be compiled with or without MPI,
 * for use on Cray compute and service nodes respectively.
 *
 * Options:
 *   -p path_prefix: An optional path prefix to be prepended to the
 *     directory_prefix (if specified) and file.  path_prefix may be modified
 *     as described in the description of the -m option.
 *
 *   -m num_mountpoints: An optional number of mount points targeting
 *     individual servers.  If a path_prefix was specified via the -p option,
 *     num_mountpoints further modifies the path_prefix by appending the
 *     result of (MPI rank / num_mountpoints) to path_prefix.  This allows
 *     the user to simulate DVS cluster parallel mode when projecting ram
 *     file systems to compute nodes.
 *
 *     For example, if a compute node would typically have a single
 *     cluster parallel mount point for a clustered file system:
 *        /fs /fs dvs path=/fs,nodename=c0-0c0s6n3:c0-0c0s6n0,maxnodes=1,...
 *
 *     ...the user could instead define multiple serial mode mount points for
 *     each server and use ram file systems instead of a clustered file
 *     system.  This cuts out the performance penalty of the underlying
 *     file system and backend storage and allows the user to more accurately
 *     measure DVS performance only:
 *        /tmp /ramtest0 dvs path=/ramtest0,nodename=c0-0c0s6n3,...
 *        /tmp /ramtest1 dvs path=/ramtest1,nodename=c0-0c0s6n0,...
 *
 *     In this specific example, the user would specify '-m 2' on the ioperf
 *     command line, and thus MPI rank 1 would perform the operations to
 *     /ramtest0 (server c0-0c0s6n3), MPI rank 2 would perform the operations
 *     to /ramtest1 (server c0-0c0s6n0), MPI rank 3 would perform the
 *     operations to /ramtest0 (server c0-0c0s6n3), etc.
 *
 *     This simulates cluster parallel mode while avoiding problems that can
 *     occur when DVS potentially tries to route create and open operations to
 *     different servers based on directory and inode hash results.  This is
 *     not an issue when running with a clustered file system, however multiple
 *     distinct ram file systems have no knowledge of objects created on other
 *     ram file systems.
 *
 *   -d directory_prefix: An optional directory prefix to be prepended to the
 *     file.  directory_prefix may be modified as described in the description
 *     of the -u option.
 *
 *   -f file: The file name to perform the operations with.  This is a
 *     required option (unlike -p, -m, and -d).  file may be modified as
 *     described in the description of the -u option.
 *
 *   -b blksize: The data block size to transfer for each iteration of read
 *     and write operations.
 *
 *   -o offset: An initial offset for I/O.  Enables the -big option.
 *
 *   -s stride: A stride for I/O.  Enables the -big option.
 *
 *   -i iters: The number of iterations to execute for each operation
 *     specified.
 *
 *   -big: Specify whether the files used by read and write operations
 *     should grow to potentially large sizes by adhering to normal file
 *     offset behavior or not.  By default, big mode is off which means
 *     read and writes will always occur at offset 0 of the file.  This is
 *     useful when running ioperf with a ram file system with limited
 *     storage as opposed to a large cluster file system.
 *
 *   -u: Use unique file names.  If compiled with MPI support, the file name
 *     (-f option) will have the Cray node ID and process id (pid) appended
 *     to it (file.nid.pid) and the directory prefix (-d option) will have the
 *     MPI rank appended to it (directory.rank).  If compiled without MPI
 *     support, the file name (-f option) will have the process id (pid)
 *     appended to it (file.pid).
 *
 *   -v: Include verbose output (statistics from all MPI ranks).
 *
 *   -noclean: Do not remove output files.
 *
 *   -init: initialize the file outside of the timing loop.
 *
 *   -read: Perform file read operations.
 *
 *   -write: Perform file write operations.
 *
 *   -opcl: Perform file open and close operations.
 *
 *   -crrm: Perform file create and unlink operations.
 *
 *   -statfs: Perform file system statistic operations.
 *
 *   -nofdatasync: Do not flush data from buffered cache to disk drives.
 */

#define IOPERF_VERSION "1.5"
#define _GNU_SOURCE /* See feature_test_macros(7) */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

/*
 * MPI support only present when WITH_MPI is defined
 */
#ifdef WITH_MPI
#include <mpi.h>
#endif

#define ARG_BIG 0x01
#define ARG_NOCLEAN 0x02
#define ARG_CRRM 0x04
#define ARG_OPCL 0x08
#define ARG_READ 0x10
#define ARG_WRITE 0x20
#define ARG_STATFS 0x40
#define ARG_INIT 0x80
#define ARG_FDATASYNC 0x100

int iter;
int big;
int blksize;
int offset = 0;
int stride = 0;
int cleanup = 1;
int init_file = 0;
int fdata_sync = 1;
int verbose = 0;
int mpi_rank = 0; /* mpi world rank */
int mpi_size = 1; /* mpi world size */

struct option args[] = {
	{ "big", no_argument, NULL, ARG_BIG },
	{ "noclean", no_argument, NULL, ARG_NOCLEAN },
	{ "init", no_argument, NULL, ARG_INIT },
	{ "crrm", no_argument, NULL, ARG_CRRM },
	{ "opcl", no_argument, NULL, ARG_OPCL },
	{ "statfs", no_argument, NULL, ARG_STATFS },
	{ "read", no_argument, NULL, ARG_READ },
	{ "write", no_argument, NULL, ARG_WRITE },
	{ "nofdatasync", no_argument, NULL, ARG_FDATASYNC },
};

void usage(void)
{
	printf("usage: ioperf [-p path_prefix] [-m num_mountpoints] "
	       "[-d directory_prefix] [-o offset] [-s stride] -f file -b blksize -i iters "
	       "[-big] [-u] [-v] [-noclean] [-init] [-read] [-write] [-nofdatasync]"
	       "[-opcl] [-crrm] [-statfs]\n");
}

void perrorx(char *string)
{
	perror(string);
	exit(1);
}

void barrier(void)
{
#if defined(MPI_VERSION)
	MPI_Barrier(MPI_COMM_WORLD);
#endif
}

int start_timer(struct timeval *time_start)
{
	return gettimeofday(time_start, NULL);
}

void stop_timer(struct timeval *time_stop, int ret_start)
{
	int ret_stop;

	ret_stop = gettimeofday(time_stop, NULL);
	if (ret_start || ret_stop)
		perrorx("timing error");
}

void calc_timings(struct timeval *time_start, struct timeval *time_stop, int i,
		  double *total)
{
	struct timeval time_diff;
	double time;

	timersub(time_stop, time_start, &time_diff);
	time = (((double)time_diff.tv_sec * (double)1000000) +
		(double)time_diff.tv_usec);
	if (i == 0)
		*total = 0;
	*total += time;
}

#if defined(MPI_VERSION)
void print_summary(const char *name, double elapsed, double count,
		   const char *units)
{
	double *tlist;

	if (mpi_rank == 0) {
		tlist = (double *)malloc(mpi_size * sizeof(double));
		if (tlist == NULL)
			perrorx("malloc error");
	}

	MPI_Gather(&elapsed, 1, MPI_DOUBLE, tlist, 1, MPI_DOUBLE, 0,
		   MPI_COMM_WORLD);

	if (mpi_rank == 0) {
		double min_time = elapsed, max_time = elapsed;
		double avg_time, time_sum = 0, count_sum = 0;
		int min_rank = 0, max_rank = 0, i;

		for (i = 0; i < mpi_size; i++) {
			if (verbose) {
				printf("rank %5d: %s: %3.3f seconds  "
				       "%5.0f %s/sec\n",
				       i, name, tlist[i], count / tlist[i],
				       units);
			}
			if (tlist[i] < min_time) {
				min_time = tlist[i];
				min_rank = i;
			}
			if (tlist[i] > max_time) {
				max_time = tlist[i];
				max_rank = i;
			}
			time_sum += tlist[i];
			count_sum += (count / tlist[i]);
		}
		avg_time = time_sum / mpi_size;
		free(tlist);
		printf("%s  min  rank %5d  %3.3f seconds  %5.0f %s/sec\n", name,
		       min_rank, min_time, count / min_time, units);
		printf("%s  max  rank %5d  %3.3f seconds  %5.0f %s/sec\n", name,
		       max_rank, max_time, count / max_time, units);
		printf("%s  avg              %3.3f seconds  %5.0f %s/sec\n",
		       name, avg_time, count / avg_time, units);
		printf("%s  total            %3.3f seconds  %5.0f %s/sec\n\n",
		       name, max_time, count_sum, units);
	}
}
#endif

void print_timing(const char *name, double time, double count,
		  const char *units)
{
#if defined(MPI_VERSION)
	print_summary(name, time, count, units);
#else
	printf("pid %8d: %6s: %3.3f seconds  %5.0f %s/sec\n", getpid(), name,
	       time, count / time, units);
#endif
}

void do_crrm(char *file)
{
	struct timeval time_start, time_stop;
	double total_create = 0.0, total_unlink = 0.0;
	int i, fd, timer_ret, ret;

	(void)unlink(file);

	barrier();
	for (i = 0; i < iter; i++) {
		timer_ret = start_timer(&time_start);
		fd = creat(file, 0666);
		stop_timer(&time_stop, timer_ret);
		if (fd == -1)
			perrorx("create error");

		close(fd);

		calc_timings(&time_start, &time_stop, i, &total_create);

		timer_ret = start_timer(&time_start);
		ret = unlink(file);
		stop_timer(&time_stop, timer_ret);
		if (ret == -1)
			perrorx("unlink error");

		calc_timings(&time_start, &time_stop, i, &total_unlink);
	}
	barrier();

	if (!cleanup)
		(void)creat(file, 0666);

	print_timing("create", total_create / 1000000, (double)iter, "creates");
	print_timing("unlink", total_unlink / 1000000, (double)iter, "unlinks");
}

void do_opcl(char *file)
{
	struct timeval time_start, time_stop;
	double total_open = 0.0, total_close = 0.0;
	int i, fd, timer_ret, ret;

	fd = open(file, O_CREAT | O_RDWR, 0666);
	if (fd == -1)
		perrorx("open error");
	close(fd);

	barrier();
	for (i = 0; i < iter; i++) {
		timer_ret = start_timer(&time_start);
		fd = open(file, O_CREAT | O_RDWR, 0666);
		stop_timer(&time_stop, timer_ret);
		if (fd == -1)
			perrorx("open error");

		calc_timings(&time_start, &time_stop, i, &total_open);

		timer_ret = start_timer(&time_start);
		ret = close(fd);
		stop_timer(&time_stop, timer_ret);
		if (ret == -1)
			perrorx("close error");

		calc_timings(&time_start, &time_stop, i, &total_close);
	}
	barrier();

	if (cleanup)
		unlink(file);

	print_timing("open", total_open / 1000000, (double)iter, "opens");
	print_timing("close", total_close / 1000000, (double)iter, "closes");
}

void do_statfs(char *file)
{
	struct timeval time_start, time_stop;
	double total_statfs = 0.0;
	int i, fd, timer_ret, ret;
	struct statfs buf;

	fd = open(file, O_CREAT | O_RDWR, 0666);
	if (fd == -1)
		perrorx("open error");
	close(fd);

	barrier();
	for (i = 0; i < iter; i++) {
		timer_ret = start_timer(&time_start);
		ret = statfs(file, &buf);
		stop_timer(&time_stop, timer_ret);
		if (ret == -1)
			perrorx("statfs error");

		calc_timings(&time_start, &time_stop, i, &total_statfs);
	}
	barrier();

	print_timing("statfs", total_statfs / 1000000, (double)iter, "statfs");
}

void do_read_write(char *file, char *buf, int type)
{
	struct timeval time_start, time_stop;
	double total;
	int i, fd, timer_ret;
	off_t off;
	ssize_t size;

	/*
	 * Wait since there could be unlinks still going on from the previous
	 * time this routine was called (called for read them write)
	 */
	barrier();

	fd = open(file, O_CREAT | O_RDWR, 0666);
	if (fd == -1)
		perrorx("open error");

	/* initialize the file */
	if (init_file) {
		off = lseek(fd, offset, SEEK_SET);
		if (off == -1)
			perrorx("lseek error");
		if (!big) {
			size = write(fd, buf, blksize);
			if (size == -1)
				perrorx("write error");
		} else {
			for (i = 0; i < iter; i++) {
				if (stride && i) {
					off = lseek(fd, stride, SEEK_CUR);
					if (off == -1)
						perrorx("lseek error");
				}
				size = write(fd, buf, blksize);
				if (size == -1)
					perrorx("write error");
			}
		}
	}
	off = lseek(fd, offset, SEEK_SET);
	if (off == -1)
		perrorx("lseek error");

	barrier();

	/*
	 * Flush data from buffered cache to disk devices if data sync is
	 * enabled.
	 */
	if (fdata_sync) {
		if (fdatasync(fd) < 0)
			perrorx("fdatasync error");
	}

	timer_ret = start_timer(&time_start);
	for (i = 0; i < iter; i++) {
		if (!big) {
			off = lseek(fd, 0, SEEK_SET);
			if (off == -1)
				perrorx("lseek error");
		}

		if (stride && i) {
			off = lseek(fd, stride, SEEK_CUR);
			if (off == -1)
				perrorx("lseek error");
		}
		if (type == ARG_READ)
			size = read(fd, buf, blksize);
		else
			size = write(fd, buf, blksize);
		if (size == -1)
			perrorx("write error");
	}
	stop_timer(&time_stop, timer_ret);
	barrier();
	calc_timings(&time_start, &time_stop, 0, &total);

	close(fd);
	if (cleanup)
		unlink(file);

	print_timing((type == ARG_READ) ? "read" : "write", total / 1000000,
		     ((double)blksize * (double)iter) / (double)(1024 * 1024),
		     "MB");
}

int main(int argc, char *argv[])
{
	int i, c, ret, mounts = 0, unique = 0, arg = 0;
	char *path = NULL, *dir = NULL, *file = NULL, *buf = NULL, *tmp,
	     *dir_path = NULL;
	struct timeval tim;
	struct timezone tz;

#if defined(MPI_VERSION)
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &mpi_size);
#endif
	while ((c = getopt_long_only(argc, argv, "p:d:f:b:i:m:o:s:uv", args,
				     NULL)) != -1) {
		switch (c) {
		case 'p':
			path = optarg;
			break;
		case 'd':
			dir = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'b':
			blksize = atoi(optarg);
			break;
		case 'i':
			iter = atoi(optarg);
			break;
		case 'm':
			mounts = atoi(optarg);
			break;
		case 'o':
			offset = atoi(optarg);
			big = 1;
			break;
		case 's':
			stride = atoi(optarg);
			big = 1;
			break;
		case 'u':
			unique = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case ARG_BIG:
			big = 1;
			break;
		case ARG_NOCLEAN:
			cleanup = 0;
			break;
		case ARG_INIT:
			init_file = 1;
			break;
		case ARG_READ:
			arg |= ARG_READ;
			break;
		case ARG_WRITE:
			arg |= ARG_WRITE;
			break;
		case ARG_FDATASYNC:
			fdata_sync = 0;
			break;
		case ARG_OPCL:
			arg |= ARG_OPCL;
			break;
		case ARG_CRRM:
			arg |= ARG_CRRM;
			break;
		case ARG_STATFS:
			arg |= ARG_STATFS;
			break;
		}
	}
	if (file == NULL || iter <= 0 || !arg || mounts < 0 ||
	    ((arg & (ARG_READ | ARG_WRITE)) && (blksize <= 0))) {
		usage();
		exit(1);
	}

	if (!(arg &
	      (ARG_CRRM | ARG_OPCL | ARG_READ | ARG_WRITE | ARG_STATFS))) {
		arg |= (ARG_CRRM | ARG_OPCL | ARG_READ | ARG_WRITE |
			ARG_STATFS);
	}

	if (arg & (ARG_READ | ARG_WRITE)) {
		ret = posix_memalign((void **)&buf, getpagesize(), blksize);
		if (ret)
			perrorx("posix_memalign error");
		memset(buf, 'E', blksize);
	}

	if (stride) {
		stride -= blksize; /* the amount to skip after you write a block
				    */
	}

	if (unique) {
#if defined(MPI_VERSION)
		FILE *f;
		char *nid, line[128];
		f = fopen("/proc/cray_xt/nid", "r");
		if (f == NULL)
			perrorx("fopen error");
		if (fgets(line, sizeof(line), f) == NULL)
			perrorx("fgets error");
		nid = strtok(line, "\n");
		if (nid == NULL)
			perrorx("strtok error");
		if (asprintf(&file, "%s.%s.%d", file, nid, getpid()) < 0)
			perrorx("asprintf error");
#else
		if (asprintf(&file, "%s.%d", file, getpid()) < 0)
			perrorx("asprintf error");
#endif
	}

	if (dir != NULL) {
#if defined(MPI_VERSION)
		if (unique) {
			if (asprintf(&dir, "%s.%d", dir, mpi_rank) < 0)
				perrorx("asprintf error");
		}
#endif
		if (asprintf(&file, "%s/%s", dir, file) < 0)
			perrorx("asprintf error");
	}

	if (path != NULL) {
		ret = asprintf(&file, "%s%d/%s", path,
			       mounts ? (mpi_rank % mounts) : 0, file);
		if (ret < 0)
			perrorx("asprintf error");
	}
	if ((dir != NULL) && (path != NULL)) {
		ret = asprintf(&dir_path, "%s%d/%s", path,
			       mounts ? (mpi_rank % mounts) : 0, dir);
		if (ret < 0)
			perrorx("asprintf error");
	}
	/* create dir */
	(void)mkdir(dirname(dir_path), 0755);

	if (asprintf(&tmp, "%s", file) < 0)
		perrorx("asprintf error");

	/* Create a file */
	(void)mkdir(dirname(tmp), 0755);

	if (mpi_rank == 0) {
		gettimeofday(&tim, &tz);
		printf("%s", ctime(&tim.tv_sec));
		printf("command: version %s ", IOPERF_VERSION);
		for (i = 0; i < argc; i++) {
			printf("%s ", argv[i]);
		}
		printf("\n");
#if defined(MPI_VERSION)
		printf("rank %d using file: %s\n", mpi_rank, file);
#else
		printf("pid %d using file: %s\n", getpid(), file);
#endif
	}

	if (arg & ARG_CRRM)
		do_crrm(file);

	if (arg & ARG_OPCL)
		do_opcl(file);

	if (arg & ARG_STATFS)
		do_statfs(file);

	if (arg & ARG_READ)
		do_read_write(file, buf, ARG_READ);

	if (arg & ARG_WRITE)
		do_read_write(file, buf, ARG_WRITE);

#if defined(MPI_VERSION)
	MPI_Finalize();
#endif
	return 0;
}
