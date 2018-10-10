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

#ifndef COMMON_H
#define COMMON_H

#define	TEST_LOG_NONE	0
#define	TEST_LOG_INFO	1
#define	TEST_LOG_DEBUG	2
#define	TEST_LOG_MAX	2

char *stats_file_path(char *path, int siz, const char *mnt_path);
int   stats_write(const char *path, const char *options);
int   stats_read(const char *path);
const char *stats_getval(const char *key);

int dvs_mkdir_p(const char *dirpath);
int dvs_umount_all(void);
int dvs_mount(const char *remote, const char *local, const char *host, ...);

int  test_openlog(const char *logpath);
void test_closelog(void);
void test_set_suite_name(const char *name);
void test_set_fail_count(int count);
int  test_set_color(int enable);
int  test_set_verbose(int verbose);
void test_verboser(void);
void test_quieter(void);
void test_debug(const char *fmt, ...);
void test_info(const char *fmt, ...);
void test_log(const char *fmt, ...);
void test_err(const char *fmt, ...);
void test_begin(const char *name);
int  test_complete(void);
void test_suite_begin(const char *name);
int  test_suite_complete(void);
int  selftest_common(void);

#endif

