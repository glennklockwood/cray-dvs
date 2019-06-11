# DVS KBUILD makefile
#
# Note, this is a gnu make makefile, bsd make will not work.
#
LNET_CFLAGS:=$(shell pkg-config cray-lnet --cflags || pkg-config lnet --cflags)
KREV:=$(shell uname -r)
MACH:=$(shell uname -m)
KDIR:=/lib/modules/$(KREV)/build
SSIMAP:=/etc/ssi-map
SSIMAPDEST:=/sys/kernel/debug/dvs/ssi-map
USER_PREFIX:=/usr/sbin

# Needed for lnet symbol definitions in the cray-lnet package
KBUILD_EXTRA_SYMBOLS?=/usr/share/symvers/$(MACH)/Module.symvers

# Just include lnet in EXTRA_CFLAGS
EXTRA_CFLAGS += ${LNET_CFLAGS}

# WITH_PREFIX controls where the userspace binary path is located.
#
# /usr/sbin is the default path.
ifndef WITH_PREFIX
WITH_PREFIX=/usr/sbin
endif

EXTRA_CFLAGS += -DWITH_PREFIX="\""$(WITH_PREFIX)"\""

# #Include <dvs/...> path
EXTRA_CFLAGS += -I$(PWD)/../include

EXTRA_CFLAGS += \
		-I${M}/../include \

# WITH_LEGACY_CRAY controls if we take cray modified kernel options
ifdef WITH_LEGACY_CRAY
ifdef NO_LEGACY_CRAY
$(error defining WITH_LEGACY_CRAY and NO_LEGACY_CRAY at once makes no logical sense)
endif
endif

ifdef WITH_LEGACY_CRAY
EXTRA_CFLAGS += -DWITH_LEGACY_CRAY
endif

ifdef NO_LEGACY_CRAY
EXTRA_CFLAGS += -DNO_LEGACY_CRAY
endif

# default to NO_LEGACY_CRAY
ifndef WITH_LEGACY_CRAY
ifndef NO_LEGACY_CRAY
EXTRA_CFLAGS += -DNO_LEGACY_CRAY -UWITH_LEGACY_CRAY
endif
endif

# WITH_DATAWARP controls if we compile with or without datawarp support
ifdef WITH_DATAWARP
ifdef NO_DATAWARP
$(error defining WITH_DATAWARP and NO_DATAWARP at once makes no logical sense)
endif
endif

ifdef WITH_DATAWARP
EXTRA_CFLAGS += -DWITH_DATAWARP
endif

ifdef NO_DATAWARP
EXTRA_CFLAGS += -DNO_DATAWARP
endif

# default to NO_DATAWARP
ifndef WITH_DATAWARP
ifndef NO_DATAWARP
EXTRA_CFLAGS += -UWITH_DATAWARP -DNO_DATAWARP
endif
endif

# WITH_REVISION controls the revision string that DVS is built with
#
# If not provided, we set it to "kbuild"
ifdef WITH_REVISION
EXTRA_CFLAGS += -DREVISION=$(WITH_REVISION)
else
EXTRA_CFLAGS += -DREVISION=\"kbuild\"
endif

# WITH_KATLAS controls if DVS is built with KATLAS memory debugging support
ifdef WITH_KATLAS
ifdef NO_KATLAS
$(error defining WITH_KATLAS and NO_KATLAS at once makes no logical sense)
endif
endif

ifdef WITH_KATLAS
EXTRA_CFLAGS += -DWITH_KATLAS
EXTRA_CFLAGS += $(shell pkg-config cray-katlas --cflags)
endif

ifdef NO_KATLAS
EXTRA_CFLAGS += -DNO_KATLAS
endif

ifndef SVNREV
EXTRA_CFLAGS += \
	-DSVNREV=\"zzz\"
endif

obj-m += dvsipc.o
obj-m += dvs.o
obj-m += dvsproc.o
obj-m += dvsipc_lnet.o

dvsipc-objs = dvsipc/ipc.o
dvsipc-objs += dvscommon/knodemap.o
dvsipc-objs += dvscommon/syscall.o
dvsipc-objs += dvsipc/dvsipc_hal/dvsipc.o
dvsipc-objs += dvsipc/dvsipc_hal/dvsipc_msg_queue.o
dvsipc-objs += dvsipc/dvsipc_hal/dvsipc_threads.o

dvsipc_lnet-objs := dvsipc/dvsipc_hal/dvsipc_lnet.o

dvs-objs = dvsof/dvs_sync.o
dvs-objs += dvscommon/dvscommon.o
dvs-objs += dvscommon/hash_table.o
dvs-objs += dvscommon/syscall.o
dvs-objs += dvsof/dvsofclient.o
dvs-objs += dvsof/dvsofserver.o
dvs-objs += dvsof/ioctl_desc.o
dvs-objs += dvspn/dvspnclient.o
dvs-objs += dvsutil/ssi_util_init.o

dvsproc-objs = dvsproc/dvs_log.o
dvsproc-objs += dvscommon/knodemap.o
dvsproc-objs += dvsproc/sys_setup.o
dvsproc-objs += dvsproc/ssi_proc.o
dvsproc-objs += dvsproc/ssi_sysctl.o
dvsproc-objs += dvsproc/dvsproc_stat.o
dvsproc-objs += dvsproc/dvsproc_test.o
dvsproc-objs += dvsproc/dvsproc_timing_stat.o

CFLAGS_dvsipc_lnet.o += ${CFLAGS}

# This include is wrong on many levels, but its due to this:
# /usr/include/lnet/lib-lnet.h:44:37: fatal error: libcfs/linux/linux-misc.h: No such file or directory
#  #include <libcfs/linux/linux-misc.h>
# libcfs/linux/linux-misc.h is in /usr/include by default, which is a bit incompatible
# with -nostdinc in general. I'm unsure why or how lustre is doing kernel module builds
# with -nostdinc and -I/usr/include, it makes no real sense to do both.
CFLAGS_dvsipc_lnet.o += -I/usr/include
CFLAGS_dvsipc_lnet.o += ${LNET_CFLAGS}

ifdef IPC_FLAGS
CFLAGS_dvsipc.o += ${IPC_FLAGS}
endif

# need to pick up fs/mount.h
CFLAGS_dvscommon.o += -I${srctree}
CFLAGS_dvsofclient.o += -I${srctree}
CFLAGS_dvsofserver.o += -I${srctree}
CFLAGS_ioctl_desc.o += -I${srctree}
CFLAGS_dvspnclient.o += -I${srctree}

CFLAGS_ssi_proc.o += -Wno-date-time
CFLAGS_dvsipc.o += -Wno-date-time

obj-m += dvs-objs

# Act as a "normal" makefile if someone runs make in this directory
all: ../userspace/dvs_thread_generator
	$(MAKE) -C $(KDIR) M=$(PWD) modules

.PHONY: patch
patch:
	for x in `find $(PWD)/../test -name "*.patch" -type f | grep -v 'no-' | sort` ; do \
	echo $$x; \
	patch -p1 -d $(PWD)/.. < $$x; \
	done

# Build the userspace binary outside of autoconf
../userspace/dvs_thread_generator:
	$(MAKE) -C ../userspace CFLAGS=-I$(PWD)/../include dvs_thread_generator

# Run the kernel kmod clean
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# The install target just runs the kmod modules_install target and installs
# the userspace binary into USER_PREFIX or /usr/sbin by default
.PHONY: install
install:  ../userspace/dvs_thread_generator
	install -m755 ../userspace/dvs_thread_generator $(USER_PREFIX)/dvs_thread_generator
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install KBUILD_MODPOST_FAIL_ON_WARNINGS=1

# Load/configure the built DVS
.PHONY: load
load:
	depmod -w -a -E $(PWD)/Module.symvers
	modprobe dvsproc
	cat $(SSIMAP) | tee $(SSIMAPDEST)
	modprobe dvs

# Unload DVS, if anything fails, then this target fails, user figures out what
# is broken.
#
# Note, rmmod -f may not work on kernels that don't have module force removal
# compiled in. As well as that just being dangerous to do on a system generally.
.PHONY: unload
unload:
	rmmod dvs
	sleep 3
	rmmod dvsipc
	sleep 3
	rmmod dvsipc_lnet
	sleep 3
	rmmod dvsproc

.PHONY: test
test:
	$(MAKE) -C ../test
