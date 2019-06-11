
/*
 * The purpose of this config.h file is to reduce the amount of #ifdef noise
 * elsewhere.
 *
 * Much like how git does things, platform specific defines/changes should
 * ideally go here.
 */

#ifndef DVSCONFIG_H
#define DVSCONFIG_H
#include <linux/version.h>
/* LUSTRE_* #defines should be caught by -I /usr/include/lustre/default/config.h
 */

#ifdef WITH_LEGACY_CRAY
#define LND_NAME "gni"
#else
#define LND_NAME "tcp"
#endif

#ifndef REVISION
#define REVISION "development"
#endif

#define STARTUP_VERSIONED_MSG(x)                                               \
	do {                                                                   \
		printk(x ": Revision: %s Built: %s @ %s against LNet %d%d\n",  \
		       REVISION, __DATE__, __TIME__, LUSTRE_MAJOR,             \
		       LUSTRE_MINOR);                                          \
	} while (0)

#define STARTUP_VERSIONED_MSG_SEQ(m, x)                                        \
	do {                                                                   \
		seq_printf(                                                    \
			m,                                                     \
			x ": Revision: %s Built: %s @ %s against LNet %d%d\n", \
			REVISION, __DATE__, __TIME__, LUSTRE_MAJOR,            \
			LUSTRE_MINOR);                                         \
	} while (0)

#define _RLIM_CUR INR_OPEN_CUR
#define _RLIM_MAX INR_OPEN_CUR

#endif /* DVSCONFIG_H */
