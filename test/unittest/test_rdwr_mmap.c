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
#include <sys/mman.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	char *prog = basename(*argv);
	char *name;
	int fn;
	off_t off;
	int mode = 0644;
	ssize_t siz;
	unsigned char *buf;
	struct stat sb;

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "Usage: %s filename [size [offset]]\n", prog);
		return 1;
	}
	name = argv[0];
	siz = (argc > 1) ? strtol(argv[1], NULL, 0) : -1;
	off = (argc > 2) ? strtol(argv[2], NULL, 0) : 0;
	printf("%s: mmap %ld bytes, offset %ld\n", name, siz, off);

	if ((fn = open(name, O_CREAT | O_RDWR, mode)) < 0) {
		perror(prog);
		return 1;
	}
	if (fstat(fn, &sb) < 0) {
		perror(prog);
		return 1;
	}
	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "%s: not a file\n", name);
		return 1;
	}
	if (siz < 0 || siz > sb.st_size) {
		siz = sb.st_size;
		printf("%s: file size %ld\n", name, siz);
	}
	if (siz == 0) {
		siz = 1024;
		printf("%s: file size %ld\n", name, siz);
	}
	buf = mmap(0, siz, PROT_READ | PROT_WRITE, MAP_SHARED, fn, off);
	if (buf == MAP_FAILED) {
		perror(prog);
		return 1;
	}
	close(fn);
	memset(buf, 0xcc, siz);
	if (munmap(buf, siz) < 0) {
		perror(prog);
		return 1;
	}
	return 0;
}
