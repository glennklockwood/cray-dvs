#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define MAX_XATTRS_PER_FILE 32

#define OP_GET 0
#define OP_SET 1
#define OP_LIST 2
#define OP_RM 3
#define OP_COUNT 4

static long max_iterations = 0; /* Default is forever */
static int iterations = 0; /* How many have we done so far? */
static unsigned seed;
static char *dirname = "."; /* Default is pwd */
static int min_xattr_len = 0;
static int max_xattr_len = 4096;
static int quiet = 0;
static int num_files = 256;
static char list_buf[65536];
static char value_buf[65536];
static int verbose = 0;

struct xattr {
	char xa_name[128];
	char *xa_value;
	size_t xa_len;
};

struct file {
	char file_name[32];
	int fd;
	int num_xattrs;
	struct xattr xattrs[MAX_XATTRS_PER_FILE];
};

struct file *files;

static void sighandler(int signal)
{
	if (signal == SIGINT) {
		printf("Completed %d iterations without error.\n", iterations);
	}

	exit(0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-i iterations] [-s seed] [-m min_xattr_len]"
		"[-M max_xattr_len] [-d dirname] [-n numfiles] [-q] [-v]\n",
		prog);

	exit(1);
}

static int create_files(void)
{
	int i;

	for (i = 0; i < num_files; ++i) {
		int fd;

		snprintf(files[i].file_name, sizeof(files[i].file_name), "f.%d",
			 i);

		fd = open(files[i].file_name, O_CREAT | O_TRUNC, 0600);
		if (fd < 0) {
			perror("open");
			return errno;
		}

		files[i].fd = fd;
	}

	return 0;
}

static int check_xattrs(struct file *fp)
{
	ssize_t len;
	char *cp;
	char *end_cp;

	if (fp->num_xattrs == 0) {
		return 0;
	}

	/* Figure out the list size */
	len = flistxattr(fp->fd, list_buf, 0);
	if (len > sizeof(list_buf)) {
		fprintf(stderr, "Skipping check for '%s', len %ld > max\n",
			fp->file_name, len);
		return 0;
	}

	len = flistxattr(fp->fd, list_buf, len);
	if (len < 0) {
		fprintf(stderr, "LIST '%s': %s\n", fp->file_name,
			strerror(errno));
		return errno;
	}

	cp = list_buf;
	end_cp = list_buf + len;

	/*
	 * Walk through the list of xattrs for this file and make sure we
	 * know about each of them and that their values match what
	 * we're expecting.
	 *
	 * TODO: track which of the known xattrs we've seen to make sure
	 * our list is in sync with what's being reported about the file.
	 */
	while (cp < end_cp) {
		int i;
		int found = 0;
		size_t xa_len = strlen(cp);

		for (i = 0; i < MAX_XATTRS_PER_FILE; ++i) {
			struct xattr *xap = &fp->xattrs[i];

			if (strcmp(cp, xap->xa_name) == 0) {
				found = 1;

				len = fgetxattr(fp->fd, cp, value_buf,
						strlen(xap->xa_name));
				if (len < 0) {
					fprintf(stderr, "LIST '%s':'%s': %s\n",
						fp->file_name, xap->xa_name,
						strerror(errno));
					return errno;
				}

				if (len != xap->xa_len) {
					fprintf(stderr,
						"LIST/GET length mismatch "
						"for '%s':'%s'"
						" %ld != %ld\n",
						fp->file_name, xap->xa_name,
						xa_len, xap->xa_len);
					return EINVAL;
				}

				if (memcmp(xap->xa_value, value_buf,
					   xap->xa_len) != 0) {
					fprintf(stderr,
						"LIST value mismatch for "
						"'%s':'%s'\n",
						fp->file_name, xap->xa_name);
					return EINVAL;
				}
			}
		}

		if (!found) {
			fprintf(stderr,
				"LIST found unknown xattr '%s' on '%s'\n", cp,
				fp->file_name);
			return EINVAL;
		}

		cp += strlen(cp) + 1;
	}

	return 0;
}

static int stress_xattrs(void)
{
	int error;

	if (!quiet) {
		printf("seed %u, min_xattr_len %u, max_xattr_len %u\n", seed,
		       min_xattr_len, max_xattr_len);
	}

	srand(seed);

	error = create_files();
	if (error) {
		return error;
	}

	while (1) {
		int r = rand();
		int op = r % OP_COUNT;
		int which_xa;
		int fnum = r % num_files;
		struct file *fp = &files[fnum];
		struct xattr *xap;
		ssize_t xa_len;
		int new = 0;

		if (verbose) {
			printf("iter %d, op %d, fnum %d\n", iterations, op,
			       fnum);
		}

		switch (op) {
		case OP_GET:
			/*
			 * If this file has no xattrs, don't count a GET
			 * operation as an iteration.
			 */
			if (fp->num_xattrs == 0) {
				continue;
			}

			which_xa = r % fp->num_xattrs;
			xap = &fp->xattrs[which_xa];

			xa_len = fgetxattr(fp->fd, xap->xa_name, NULL, 0);
			if (xa_len < 0) {
				fprintf(stderr,
					"GET length for '%s':'%s': %s\n",
					fp->file_name, xap->xa_name,
					strerror(errno));
				return errno;
			}

			if (xa_len != xap->xa_len) {
				fprintf(stderr,
					"GET length mismatch for '%s':'%s'"
					" %ld != %ld\n",
					fp->file_name, xap->xa_name, xa_len,
					xap->xa_len);
				return EINVAL;
			}

			xa_len = fgetxattr(fp->fd, xap->xa_name, value_buf,
					   xa_len);

			if (xa_len < 0) {
				fprintf(stderr, "GET for '%s':'%s': %s\n",
					fp->file_name, xap->xa_name,
					strerror(errno));
				return errno;
			}

			if (memcmp(xap->xa_value, value_buf, xa_len) != 0) {
				fprintf(stderr, "miscompare for '%s':'%s'\n",
					fp->file_name, xap->xa_name);
				return -1;
			}

			break;

		case OP_SET:
			which_xa = r % MAX_XATTRS_PER_FILE;
			xap = &fp->xattrs[which_xa];

			if (xap->xa_name[0] == '\0') {
				snprintf(xap->xa_name, sizeof(xap->xa_name),
					 "user.%d", which_xa);
				new = 1;
			} else {
				free(xap->xa_value);
				new = 0;
			}

			xa_len = r % max_xattr_len;
			if (xa_len < min_xattr_len) {
				xa_len = min_xattr_len;
			}

			xap->xa_value = (char *)malloc(xa_len + 1);

			memset(xap->xa_value, 'a', xa_len);
			xap->xa_value[xa_len] = '\0';
			xap->xa_len = xa_len;

			if (fsetxattr(fp->fd, xap->xa_name, xap->xa_value,
				      xa_len, 0) < 0) {
				fprintf(stderr,
					"SET '%s':'%s' (attr len %u): %s\n",
					fp->file_name, xap->xa_name, xa_len,
					strerror(errno));
				return errno;
			}

			if (new) {
				++fp->num_xattrs;
			}

			break;

		case OP_LIST:
			error = check_xattrs(fp);
			break;

		case OP_RM:
			if (fp->num_xattrs == 0) {
				continue;
			}

			which_xa = r % MAX_XATTRS_PER_FILE;
			xap = &fp->xattrs[which_xa];

			if (xap->xa_name[0] == '\0') {
				continue;
			}

			if (fremovexattr(fp->fd, xap->xa_name) < 0) {
				fprintf(stderr, "REMOVE '%s':'%s': %s\n",
					fp->file_name, xap->xa_name,
					strerror(errno));
				return errno;
			}

			xap->xa_name[0] = '\0';

			free(xap->xa_value);
			xap->xa_value = NULL;
			xap->xa_len = 0;

			--fp->num_xattrs;

			break;
		}

		++iterations;

		if (max_iterations > 0 && iterations >= max_iterations) {
			printf("Completed %d iterations without error,\n",
			       iterations);
			break;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int c;
	int error;

	seed = time(NULL);

	while ((c = getopt(argc, argv, "d:hi:M:m:n:qs:v")) != -1) {
		switch (c) {
		case 'd':
			dirname = optarg;
			break;
		case 'i':
			max_iterations = strtol(optarg, NULL, 0);
			break;
		case 'M':
			max_xattr_len = strtol(optarg, NULL, 0);
			if (max_xattr_len < 0) {
				fprintf(stderr, "max_xattr_len must be >= 0\n");
				exit(1);
			}
			break;
		case 'm':
			min_xattr_len = strtol(optarg, NULL, 0);
			if (min_xattr_len < 0) {
				fprintf(stderr, "min_xattr_len must be >= 0\n");
				exit(1);
			}
			break;
		case 'n':
			num_files = strtol(optarg, NULL, 0);
			if (num_files <= 0) {
				fprintf(stderr, "num_files must be > 0\n");
				exit(1);
			}
			break;
		case 'q':
			quiet = atoi(optarg);
			break;
		case 's':
			seed = (unsigned)strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}

	argc -= optind;
	if (argc > 0) {
		usage(argv[0]);
	}

	files = (struct file *)calloc(num_files, sizeof(struct file));
	if (files == NULL) {
		perror("calloc files");
		exit(1);
	}

	if (chdir(dirname) < 0) {
		fprintf(stderr, "Directory '%s': %s\n", dirname,
			strerror(errno));
		exit(1);
	}

	if (min_xattr_len > max_xattr_len) {
		fprintf(stderr, "max_xattr_len must be >= min_xattr_len\n");
		exit(1);
	}

	signal(SIGINT, sighandler);

	error = stress_xattrs();

	exit(error);
}
