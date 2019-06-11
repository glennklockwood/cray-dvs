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

static struct option longopts[] = { { "chunk", required_argument, NULL, 'c' },
				    { "flags", required_argument, NULL, 'f' },
				    { "gap", required_argument, NULL, 'g' },
				    { "number", required_argument, NULL, 'n' },
				    { "offset", required_argument, NULL, 'o' },
				    { "pad", required_argument, NULL, 'p' },
				    { "ref", required_argument, NULL, 'r' },
				    { "size", required_argument, NULL, 's' },
				    { "value", required_argument, NULL, 'v' },
				    { 0, 0, 0, 0 } };

static int usage(const char *prog)
{
	static char *syntax =
		"Usage: %s [options] filename\n"
		"  --number=count   total number of files to auto-generate\n"
		"  --size=bytes     total size of file to read\n"
		"  --offset=bytes   starting offset\n"
		"  --chunk=bytes    individual read size\n"
		"  --gap=bytes      bytes to skip between reads\n"
		"  --value=byteval  integer byte value expected\n"
		"  --pad=byteval    integer byte value in gaps\n "
		"  --flags=flag,... list of rdonly,wronly,rdwr,creat,excl,trunc\n"
		"  --ref=filename   reference file\n";
	fprintf(stderr, syntax, prog);
	return 1;
}

static int _parseflags(char *options)
{
	int flags = 0;
	char *p = options;

	while (*p) {
		while (*p && *p != ',')
			p++;
		if (*p)
			*p++ = 0;
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

int main(int argc, char **argv)
{
	char *prog = basename(*argv);
	unsigned char *buf;
	unsigned char *rbuf;
	size_t chunk = 0;
	size_t gap = 0;
	size_t size = 1024;
	off_t offset = 0;
	char *rfile = NULL;
	int number = 0;
	int bval = 0xa5;
	int pval = 0x00;
	int flags = O_RDONLY;
	int pad = 0;
	int err = 0;
	int index;
	int opt;
	int rn = -1;

	while ((opt = getopt_long(argc, argv, "c:f:g:o:s:v:", longopts,
				  NULL)) != -1) {
		switch (opt) {
		case 'c':
			chunk = strtol(optarg, NULL, 0);
			break;
		case 'g':
			gap = strtol(optarg, NULL, 0);
			break;
		case 'n':
			number = strtol(optarg, NULL, 0);
			break;
		case 'o':
			offset = strtol(optarg, NULL, 0);
			break;
		case 'p':
			pval = strtol(optarg, NULL, 0);
			pad = 1;
			break;
		case 'r':
			rfile = optarg;
			pad = 1;
			break;
		case 's':
			size = strtol(optarg, NULL, 0);
			break;
		case 'v':
			bval = strtol(optarg, NULL, 0);
			break;
		case 'f':
			flags = _parseflags(optarg);
			break;
		default:
			return usage(prog);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		return usage(prog);
	}
	if (rfile) {
		if ((rn = open(rfile, O_RDONLY)) < 0) {
			perror(prog);
			fprintf(stderr, "open(%s) == %d, failed\n", rfile, rn);
			return 1;
		}
	}

	index = 0;
	while (index < number || argc > 0) {
		char filename[512];
		struct stat sb;
		size_t fsize;
		size_t fchunk;
		ssize_t req;
		ssize_t len;
		int fn;
		int i;

		if (index < number) {
			snprintf(filename, sizeof(filename), "%s.%d", *argv,
				 index);
			if (++index >= number) {
				argc--;
				argv++;
			}
		} else {
			snprintf(filename, sizeof(filename), "%s", *argv);
			argc--;
			argv++;
		}
		if ((fn = open(filename, flags)) < 0) {
			perror(prog);
			fprintf(stderr, "open(%s,0x%x) == %d, failed\n",
				filename, flags, fn);
			err++;
			continue;
		}
		if (fstat(fn, &sb) < 0) {
			perror(prog);
			fprintf(stderr, "fstat(%s) failed\n", filename);
			err++;
			continue;
		}
		fsize = (size < sb.st_size) ? size : sb.st_size;
		fchunk = (chunk && chunk <= fsize) ? chunk : fsize;
		req = (pad) ? fchunk + gap : fchunk;
		buf = malloc(req);
		rbuf = malloc(req);
		while (offset < fsize) {
			memset(buf, pval, req);
			memset(rbuf, pval, req);
			if (req > fsize - offset)
				req = fsize - offset;
			len = pread(fn, buf, req, offset);
			if (len < 0) {
				perror(prog);
				fprintf(stderr,
					"pread(%ld,%ld) == %ld, failed\n", req,
					offset, len);
				err++;
				break;
			}
			if (len < req) {
				fprintf(stderr,
					"pread(%ld,%ld) == %ld, unexpected short read\n",
					req, offset, len);
				err++;
				break;
			}
			if (rn >= 0) {
				ssize_t rlen;
				rlen = pread(rn, rbuf, req, offset);
				if (rlen < 0) {
					perror(prog);
					fprintf(stderr,
						"pread(%ld,%ld) REF == %ld, failed\n",
						req, offset, rlen);
					err++;
					break;
				}
				if (rlen < req) {
					fprintf(stderr,
						"pread(%ld,%ld) REF == %ld, short\n",
						req, offset, rlen);
					err++;
					break;
				}
				memset(rbuf, bval, fchunk);
			} else {
				memset(rbuf, bval, fchunk);
			}
			for (i = 0; i < req; i++) {
				if (buf[i] != rbuf[i]) {
					fprintf(stderr,
						"off=%ld, byt=%d, exp %02x, saw %02x\n",
						offset, i, rbuf[i], buf[i]);
					err++;
				}
			}
			offset += fchunk + gap;
		}
		free(rbuf);
		free(buf);
		close(fn);
	}
	if (rn >= 0)
		close(rn);
	return (err) ? 1 : 0;
}
