ifndef LNET_FLAGS
LNET_FLAGS=$(shell pkg-config cray-lnet --cflags)
endif

ifndef LNETVER
EXTRA_CFLAGS += \
        -DDVS_LNET_VERSION=27 \
	-DLNETVER=\"27\"
endif

ifdef WHITEBOX
GPL_LICENSE=1
EXTRA_CFLAGS += \
        -DWHITEBOX=1 \
        -DUSE_RCA=0
else
EXTRA_CFLAGS += \
        -DUSE_RCA=1
endif

ifndef SVNREV
EXTRA_CFLAGS += \
        -DSVNREV=\"zzz\"
endif

ifdef DVSPROC_TEST_ENABLE
EXTRA_CFLAGS += \
	-DDVSPROC_TEST_ENABLE=1
endif

ifdef GPL_LICENSE
EXTRA_CFLAGS += \
	-DDVS_LICENSE=\"GPL\"
else
EXTRA_CFLAGS += \
	-DDVS_LICENSE=\"Propietary\"
endif

obj-m+= dvsipc.o \
	dvs.o \
	dvsproc.o \
        dvsipc_lnet.o \

EXTRA_CFLAGS += \
	-I${M}/../include \

dvsipc-objs :=	\
	dvsipc/ipc.o \
	dvscommon/knodemap.o \
	dvscommon/syscall.o \
	dvsipc/dvsipc_hal/dvsipc.o \
	dvsipc/dvsipc_hal/dvsipc_msg_queue.o \
	dvsipc/dvsipc_hal/dvsipc_threads.o \

dvsipc_lnet-objs := \
	dvsipc/dvsipc_hal/dvsipc_lnet.o

dvs-objs :=	\
	dvsof/dvs_sync.o \
	dvscommon/dvscommon.o \
	dvscommon/hash_table.o \
	dvscommon/syscall.o \
	dvsof/dvsofclient.o \
	dvsof/dvsofserver.o \
        dvsof/ioctl_desc.o \
	dvspn/dvspnclient.o \
	dvsutil/ssi_util_init.o \

dvsproc-objs :=	\
	dvsproc/dvs_log.o \
	dvscommon/knodemap.o \
	dvsproc/ssi_proc.o \
	dvsproc/ssi_sysctl.o \
	dvsproc/dvsproc_stat.o \
	dvsproc/dvsproc_test.o \

CFLAGS_dvsipc_lnet.o += ${LNET_FLAGS}
CFLAGS_dvsipc.o += ${IPC_FLAGS}
# need to pick up fs/mount.h
CFLAGS_dvscommon.o += -I${srctree}
CFLAGS_dvsofserver.o += -I${srctree}
CFLAGS_ioctl_desc.o += -I${srctree}
