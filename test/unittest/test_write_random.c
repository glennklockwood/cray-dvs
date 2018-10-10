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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int
main(int argc, char **argv)
{
	char *prog = basename(*argv);
	char *name;
	int fn;
	off_t off;
	ssize_t len;
	unsigned char *buf;
	int i, n, m;

	argc--; argv++;
	if (argc < 1) {
		fprintf(stderr, "Usage: %s filename\n", prog);
		return 1;
	}
	name = argv[0];
	n = (argc > 1) ? atoi(argv[1]) : 1;
	m = (argc > 2) ? atoi(argv[2]) : 25;
	buf = malloc(m);
	printf("%s: read %d bytes, %d times\n", name, m, n);

#if 0
	if ((fn = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		perror(prog);
		return 1;
	}
	if ((off = lseek(fn, 10, SEEK_SET)) == (off_t)-1) {
		perror(prog);
		return 1;
	}
	memset(buf, 0xa5, m);
	if ((len = write(fn, buf, 10)) < 0) {
		perror(prog);
		return 1;
	}
	close(fn);
#endif
	if ((fn = open(name, O_RDONLY)) < 0) {
		perror(prog);
		return 1;
	}
	for (i=0; i<n; i++) {
		if ((off = lseek(fn, 0, SEEK_SET)) == (off_t)-1) {
			perror(prog);
			return 1;
		}
		memset(buf, 0, m);
		if ((len = read(fn, buf, m)) < 0) {
			perror(prog);
			return 1;
		}
	}
	if (m > 256)
		m = 256;
	for (i = 0; i < m; i++) {
		if (i && !(i % 16)) {
			printf("\n");
		}
		printf(" %02x", buf[i]);
	}
	printf("\n");
	close(fn);
	return 0;
}
