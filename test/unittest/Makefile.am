COMMON = common.c common.h

sbin_SCRIPTS = \
	test_common.sh \
	test_request_log.sh \
	regression_test.py

sbin_PROGRAMS = \
	test_common \
	test_stats \
	test_rdwr_mmap \
	test_read_file \
	test_read_mmap \
	test_spinlock_perf \
	test_write_file \
	test_write_mmap \
	test_write_random

test_common_SOURCES = test_common.c $(COMMON)
test_stats_SOURCES = test_stats.c $(COMMON)
test_rdwr_mmap_SOURCES = test_rdwr_mmap.c $(COMMON)
test_read_file_SOURCES = test_read_file.c $(COMMON)
test_read_mmap_SOURCES = test_read_mmap.c $(COMMON)
test_spinlock_perf_SOURCES = test_spinlock_perf.c $(COMMON)
test_write_file_SOURCES = test_write_file.c $(COMMON)
test_write_mmap_SOURCES = test_write_mmap.c $(COMMON)
test_write_random_SOURCES = test_write_random.c $(COMMON)
