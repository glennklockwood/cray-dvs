/*
 * Copyright 2018 Cray Inc. All Rights Reserved.
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
 *
 *
 * This is a userspace daemon to supply user threads to the DVS server
 * thread pools. The threads do ioctl calls into the /dev/dvs device file.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/dvs_dev_ioctl.h"

#define PROXY_THREAD_NAME "DVS-USER-IPC_msg"
#define THREAD_REAP_ALARM_TIMEOUT 5

int daemonize = 1;
int verbose = 0;
char *nameptr = NULL;
int namelen = 0;

/*
 * Overwrites argv[0] with the desired program name
 */
void setprogname(char *fmt, ...)
{
	va_list args;

	/* Make sure the entire name is NULLed out */
	memset(nameptr, 0, namelen);

	va_start(args, fmt);
	vsnprintf(nameptr, namelen, fmt, args);
	va_end(args);
}

void err(char *fmt, ...)
{
	char buff[64] = "";
	char new_fmt[64] = "";
	va_list args;
	FILE *file;

	snprintf(new_fmt, sizeof(new_fmt), "dvs_thread_generator: %s\n", fmt);

	va_start(args, fmt);
	vsnprintf(buff, sizeof(buff), new_fmt, args);
	va_end(args);

	/* If this fails...who can we even tell? */
	file = stdout;
	if (daemonize) {
		if ((file = fopen("/dev/kmsg", "w")) == NULL)
			return;
	}

	fprintf(file, "%s", buff);

	if (file != stdout)
		fclose(file);
}

void set_oom_unkillable(void)
{
	ssize_t bytes_written;
	int oom_fd = -1;
	char oom_file[64] = "";
	char *value = "-1000";

	snprintf(oom_file, sizeof(oom_file), "/proc/%d/oom_score_adj",
		 getpid());
	if ((oom_fd = open(oom_file, O_RDWR)) < 0) {
		err("Could not open oom_score_adj file: %s", strerror(errno));
		return;
	}

	if ((bytes_written = write(oom_fd, value, strlen(value))) <
	    strlen(value)) {
		err("Could not write to oom_score_adj file");
	}
	close(oom_fd);
}

/*
 * This handler is only meant to interrupt ioctl
 */
void alarm_handler(int signum)
{
	return;
}

void do_daemonize(void)
{
	int ret;
	pid_t child;
	FILE *stream;

	if (!daemonize)
		return;

	child = fork();
	if (child)
		exit(0);

	child = fork();
	if (child)
		exit(0);

	set_oom_unkillable();
	setsid();

	if ((ret = chdir("/")) < 0) {
		fprintf(stderr, "Could not chdir to /: %s\n", strerror(errno));
	}
	umask(0);

	if ((stream = freopen("/dev/zero", "r", stdin)) == NULL) {
		fprintf(stderr, "Could not freopen stdin!\n");
	}

	if ((stream = freopen("/dev/null", "w", stdout)) == NULL) {
		fprintf(stderr, "Could not freopen stdout!\n");
	}

	if ((stream = freopen("/dev/null", "w", stderr)) == NULL) {
		fprintf(stderr, "Could not freopen stderr!\n");
	}
}

/*
 * Do an unblocked wait for all child processes
 */
void wait_for_children(void)
{
	pid_t pid;
	int status;

	do {
		pid = waitpid(-1, &status, WNOHANG);
	} while (pid > 0);
}

void fork_child_thread(int dev_fd, int pool_id, char *poolname)
{
	pid_t child;
	int i;

	for (i = 0; i < 10; i++) {
		child = fork();

		/* If the fork didn't work, wait a bit and try again */
		if (child < 0) {
			usleep(4000);
			continue;
		}

		if (child > 0)
			return;

		break;
	}

	if (child < 0) {
		err("fork failed!!!: %s", strerror(errno));
		return;
	}

	/* Only the child process will get to this point */
	setprogname(poolname);
	/* Send a thread through the ioctl to be drafted into service */
	ioctl(dev_fd, DVS_DEV_IOCTL_THREAD_TRAP, &pool_id);
	exit(0);
}

/*
 * Watch a specific pool for the go-ahead to create a thread
 */
void watch_pool(int dev_fd, int pool_id, char *poolname)
{
	int ret;
	struct sigaction sig;

	do_daemonize();

	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = alarm_handler;
	if (sigaction(SIGALRM, &sig, 0) < 0) {
		err("Could not set alarm handler: %s", strerror(errno));
	}

	err("Watching pool %s (id %d)", poolname, pool_id);

	while (1) {
		/*
		 * How long we may be in this ioctl is non-deterministic. Set
		 * an alarm so that any child threads that have exited while we
		 * were stuck on the ioctl can be properly waited for.
		 */
		alarm(THREAD_REAP_ALARM_TIMEOUT);
		/* This ioctl will return when it's time to send a thread */
		ret = ioctl(dev_fd, DVS_DEV_IOCTL_WAIT_ON_THREAD_CREATE,
			    &pool_id);
		if (ret) {
			if (errno != EINTR) {
				err("thread create ioctl failed: %s",
				    strerror(errno));
				exit(0);
			}
		} else {
			fork_child_thread(dev_fd, pool_id, poolname);
		}
		/* Reap any previous children that have exited */
		wait_for_children();
	}
}

void start_all_pools(int dev_fd)
{
	pid_t child;
	int i;
	int ret;
	int num_pools = 0;
	char poolname[64];

	if ((ret = ioctl(dev_fd, DVS_DEV_IOCTL_GET_NUM_INSTANCES, &num_pools)) <
	    0) {
		printf("Could not get number of instances: %s\n",
		       strerror(errno));
		exit(1);
	}

	for (i = 0; i < num_pools; i++) {
		child = fork();
		if (child == 0) {
			snprintf(poolname, sizeof(poolname), "%d", i);
			watch_pool(dev_fd, i, poolname);
		}
	}

	exit(0);
}

void usage(void)
{
	printf("dvs_thread_generator usage:\n"
	       "The dvs_thread_generator binary creates threads for the dvsipc\n"
	       "kernel module to use as server proxy threads.\n"
	       "Options:\n"
	       "--help            This help\n"
	       "--verbose         Output more information\n"
	       "--nodaemon        Do not daemonize\n"
	       "--file [filename] Send created threads to a device file other than\n"
	       "                      /dev/dvs\n");
}

int main(int argc, char *argv[])
{
	int c, dev_fd;
	int pool_id = -1;
	int moved_fd = 16;
	char poolbuff[64] = "";
	char *poolname = NULL;
	char *device_filename = "/dev/dvsipc";

	while (1) {
		static struct option long_options[] = {
			{ "help", no_argument, 0, 'h' },
			{ "verbose", no_argument, 0, 'v' },
			{ "nodaemon", no_argument, 0, 'D' },
			{ "pool", required_argument, 0, 'p' },
			{ "number", required_argument, 0, 'n' },
			{ "file", required_argument, 0, 'f' },
			{ 0, 0, 0, 0 }
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "hvDp:n:f:", long_options,
				&option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'D':
			daemonize = 0;
			break;
		case 'f':
			device_filename = optarg;
			break;
		case 'n':
			pool_id = atoi(optarg);
			break;
		case 'p':
			poolname = optarg;
			break;
		default:
			abort();
		}
	}

	nameptr = argv[0];
	namelen = strlen(argv[0]);

	/* Keep attempting to open the device file until it's finally created */
	while (1) {
		dev_fd = open(device_filename, O_RDWR);
		if (dev_fd >= 0)
			break;
		usleep(10000);
	}

	/*
	 * We don't want the system accidentally using our device as one of
	 * stdin, stdout, or stderr
	 */
	if (dev_fd <= STDERR_FILENO) {
		dup2(dev_fd, moved_fd);
		close(dev_fd);
		dev_fd = moved_fd;
	}

	/* If we were given a specific instance/thread pool, only watch that */
	if (pool_id >= 0) {
		if (poolname == NULL) {
			snprintf(poolbuff, sizeof(poolbuff), "%d", pool_id);
			poolname = poolbuff;
		}
		watch_pool(dev_fd, pool_id, poolname);
		exit(0);
	}

	/* Watch every instance and thread pool */
	start_all_pools(dev_fd);

	return 0;
}
