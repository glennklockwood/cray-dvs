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
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static struct option longopts[] = {
	{"chunk",  required_argument, NULL, 'c'},
	{"flags",  required_argument, NULL, 'f'},
	{"gap",    required_argument, NULL, 'g'},
	{"mode",   required_argument, NULL, 'm'},
	{"number", required_argument, NULL, 'n'},
	{"offset", required_argument, NULL, 'o'},
	{"size",   required_argument, NULL, 's'},
	{"value",  required_argument, NULL, 'v'},
	{0,0,0,0}
};

static int
usage(const char *prog)
{
static	char *syntax =
	"Usage: %s [options] filename\n"
	"  --number=count   total number of files to auto-generate\n"
	"  --size=bytes     total size of file to write\n"
	"  --offset=bytes   starting offset\n"
	"  --chunk=bytes    individual write size\n"
	"  --gap=bytes      bytes to skip between writes\n"
	"  --value=byteval  integer value byte value to write\n"
	"  --mode=modeval   integer value for the file mode to create\n"
	"  --flags=flag,... list of rdonly,wronly,rdwr,creat,excl,trunc\n";
	fprintf(stderr, syntax, prog);
	return 1;
}

static int
_parseflags(char *options)
{
	int flags = 0;
	char *p = options;

	while (*p) {
		while (*p && *p != ',') p++;
		if (*p) *p++ = 0;
		if (!strcmp(options, "rdonly")) {
			flags |= O_RDONLY;
		} else if (!strcmp(options, "wronly")) {
			flags |= O_WRONLY;
		} else if (!strcmp(options, "rdwr")) {
			flags |= O_RDWR;
		} else if (!strcmp(options, "creat")) {
			flags |= O_CREAT;
		} else if (!strcmp(options, "excl")) {
			flags |= O_EXCL;
		} else if (!strcmp(options, "trunc")) {
			flags |= O_TRUNC;
		} else {
			fprintf(stderr, "Bad flags option '%s'\n", options);
		}
		options = p;
	}
	return flags;
}

int
main(int argc, char **argv)
{
	char *prog = basename(*argv);
	unsigned char *buf;
	size_t chunk  = 0;
	size_t gap    = 0;
	size_t size   = 1024;
	off_t  offset = 0;
	int number = 0;
	int bval = 0xa5;
	int mode = 0644;
	int flags = O_RDWR|O_CREAT|O_TRUNC;
	int index;
	int opt;

	while ((opt = getopt_long(argc, argv, "c:f:g:m:o:s:v:", longopts, NULL)) != -1) {
		switch (opt) {
		case 'c': chunk  = strtol(optarg, NULL, 0); break;
		case 'g': gap    = strtol(optarg, NULL, 0); break;
		case 'm': mode   = strtol(optarg, NULL, 0); break;
		case 'n': number = strtol(optarg, NULL, 0); break;
		case 'o': offset = strtol(optarg, NULL, 0); break;
		case 's': size   = strtol(optarg, NULL, 0); break;
		case 'v': bval   = strtol(optarg, NULL, 0); break;
		case 'f': flags  = _parseflags(optarg); break;
		default: return usage(prog);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		return usage(prog);
	}
	if (! chunk || chunk > size)
		chunk = size;

	index = 0;
	buf = malloc(chunk);
	while (index < number || argc > 0) {
		char filename[512];
		ssize_t len;
		int fn;

		if (index < number) {
			snprintf(filename, sizeof(filename), "%s.%d", *argv, index);
			if (++index >= number) {
				argc--; argv++;
			}
		} else {
			snprintf(filename, sizeof(filename), "%s", *argv);
			argc--; argv++;
		}
		if ((fn = open(filename, flags, mode)) < 0) {
			perror(prog);
			fprintf(stderr, "open(%s,0x%x) == %d, failed\n", filename, flags, fn);
			return 1;
		}
		memset(buf, bval, chunk);
		while (offset < size) {
			if ((len = pwrite(fn, buf, chunk, offset)) != chunk) {
				perror(prog);
				fprintf(stderr, "pwrite(%ld,%ld) == %ld, failed\n", chunk, offset, len);
				return 1;
			}
			offset += chunk + gap;
		}
		close(fn);
	}
	return 0;
}
