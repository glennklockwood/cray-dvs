/*
 * Unpublished Work © 2003 Unlimited Scale, Inc.  All rights reserved.
 * Unpublished Work © 2004 Cassatt Corporation    All rights reserved.
 * Copyright 2006-2016 Cray Inc. All Rights Reserved.
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

#ifndef USICONTEXT_H
#define USICONTEXT_H

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file usicontext.h"
#endif /* __KERNEL__ */

#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/sched/rt.h>

#include <dvs/dvs_config.h>

#include "common/kernel/kernel_interface.h"

/*
 * Define a jobid for placing messages in the correct input queue. Use
 * apid if available; use the uid if not. Set the high order bit to
 * avoid collisions between the two id types.
 */
#define CTX_JOBID_UID_MASK ((u64)0x1 << 63)
#define JOBID_APID(apid) ((apid))

#define JOBID_UID(uid) ((__kuid_val(uid)) | CTX_JOBID_UID_MASK)

/*
 * Context passed between client and server.  The following is a partial
 * list of what each entry is used for:
 *    tgid - the kernel uses current->tgid for file locking operations
 *
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
/* NGROUPS_SMALL has been removed with SLES 15 */
#define NGROUPS_SMALL 32
#endif
#define DVS_OTW_GROUPS (NGROUPS_SMALL * 4)

struct usicontext {
	kuid_t uid, euid, suid, fsuid;
	kgid_t gid, egid, sgid, fsgid;
	kgid_t groups[DVS_OTW_GROUPS];
	int ngroups;
	struct group_info *group_info;
	kernel_cap_t cap_effective, cap_inheritable, cap_permitted;
	unsigned securebits;
#ifndef WITH_LEGACY_CRAY
	u64 jobid;
#endif
#ifdef CONFIG_CRAY_ACCOUNTING
	u64 csa_apid;
#endif
#endif
	int umask;
	int node;
	int leader;
	sigset_t blocked;
	pid_t pgrp, session, tgid;
	struct rlimit rlim[RLIM_NLIMITS];
	long nice;
	const struct cred *cred;
};

#define CRED current->cred

/*
 * Capture (copy) context (client)
 */
static inline void capture_context(struct usicontext *ctx)
{
	ctx->uid = CRED->uid;
	ctx->euid = CRED->euid;
	ctx->suid = CRED->suid;
	ctx->fsuid = CRED->fsuid;
	ctx->gid = CRED->gid;
	ctx->egid = CRED->egid;
	ctx->sgid = CRED->sgid;
	ctx->fsgid = CRED->fsgid;

	get_group_info(CRED->group_info);
	ctx->ngroups = (CRED->group_info->ngroups > DVS_OTW_GROUPS) ?
			       DVS_OTW_GROUPS :
			       CRED->group_info->ngroups;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	memcpy(ctx->groups, CRED->group_info->blocks[0],
	       ctx->ngroups * sizeof(gid_t));
#else
	memcpy(ctx->groups, CRED->group_info->gid,
	       ctx->ngroups * sizeof(kgid_t));
#endif
	put_group_info(CRED->group_info);

	ctx->cap_effective = CRED->cap_effective;
	ctx->cap_inheritable = CRED->cap_inheritable;
	ctx->cap_permitted = CRED->cap_permitted;
	ctx->securebits = CRED->securebits;
#if defined(WITH_LEGACY_CRAY) && defined(CONFIG_CRAY_ACCOUNTING)
	ctx->csa_apid = current->csa_apid;
/* bug 823318 */
#ifdef RHEL_RELEASE_CODE
	ctx->jobid = JOBID_UID(CRED->uid);
#else
	ctx->jobid = (current->csa_apid ? JOBID_APID(current->csa_apid) :
					  JOBID_UID(CRED->uid));
#endif
#endif

	if (current->fs)
		ctx->umask = current->fs->umask;
	else
		ctx->umask = 0;
	ctx->leader = current->signal->leader;
	ctx->tgid = current->tgid;
	ctx->blocked = current->blocked;
	memcpy(ctx->rlim, current->signal->rlim, sizeof(current->signal->rlim));
	ctx->node = usi_node_addr;
	ctx->nice = kernel_get_task_nice(current);
}

/*
 * Set root context.
 */
static inline void set_root_context(struct usicontext *ctx)
{
	ctx->uid = GLOBAL_ROOT_UID;
	ctx->suid = GLOBAL_ROOT_UID;
	ctx->euid = GLOBAL_ROOT_UID;
	ctx->fsuid = GLOBAL_ROOT_UID;
	ctx->gid = GLOBAL_ROOT_GID;
	ctx->sgid = GLOBAL_ROOT_GID;
	ctx->egid = GLOBAL_ROOT_GID;
	ctx->fsgid = GLOBAL_ROOT_GID;

	ctx->umask = 0077;
	ctx->rlim[RLIMIT_CPU].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_CPU].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_FSIZE].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_DATA].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_DATA].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_STACK].rlim_cur = _STK_LIM;
	ctx->rlim[RLIMIT_STACK].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_CORE].rlim_cur = 0;
	ctx->rlim[RLIMIT_CORE].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_RSS].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_RSS].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_NPROC].rlim_cur = 0;
	ctx->rlim[RLIMIT_NPROC].rlim_max = 0;
	ctx->rlim[RLIMIT_NOFILE].rlim_cur = _RLIM_CUR;
	ctx->rlim[RLIMIT_NOFILE].rlim_max = _RLIM_MAX;
	ctx->rlim[RLIMIT_MEMLOCK].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_MEMLOCK].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_AS].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_AS].rlim_max = RLIM_INFINITY;
	ctx->rlim[RLIMIT_LOCKS].rlim_cur = RLIM_INFINITY;
	ctx->rlim[RLIMIT_LOCKS].rlim_max = RLIM_INFINITY;
	ctx->cap_effective = CAP_FULL_SET;
	ctx->cap_inheritable = CAP_FULL_SET;
	ctx->cap_permitted = CAP_FULL_SET;
}

/*
 * Save current context and then update current context with new
 */
static inline int push_context(struct usicontext *saved, struct usicontext *new)
{
	struct cred *newcred;
	struct group_info *newgroup;

	saved->uid = CRED->uid;
	saved->euid = CRED->euid;
	saved->suid = CRED->suid;
	saved->fsuid = CRED->fsuid;
	saved->gid = CRED->gid;
	saved->egid = CRED->egid;
	saved->sgid = CRED->sgid;
	saved->fsgid = CRED->fsgid;
	saved->group_info = CRED->group_info;
	saved->cap_effective = CRED->cap_effective;
	saved->cap_inheritable = CRED->cap_inheritable;
	saved->cap_permitted = CRED->cap_permitted;
	saved->securebits = CRED->securebits;
	saved->umask = current->fs->umask;
	saved->leader = current->signal->leader;
#if defined(WITH_LEGACY_CRAY) && defined(CONFIG_CRAY_ACCOUNTING)
	saved->csa_apid = current->csa_apid;
#endif
	saved->tgid = current->tgid;
	saved->blocked = current->blocked;
	memcpy(saved->rlim, current->signal->rlim,
	       sizeof(current->signal->rlim));
	saved->nice = kernel_get_task_nice(current);

	newcred = prepare_creds();
	if (!newcred) {
		return -ENOMEM;
	}

	newcred->uid = new->uid;
	newcred->euid = new->euid;
	newcred->suid = new->suid;
	newcred->fsuid = new->fsuid;
	newcred->gid = new->gid;
	newcred->egid = new->egid;
	newcred->sgid = new->sgid;
	newcred->fsgid = new->fsgid;

	newgroup = groups_alloc(new->ngroups);
	if (!newgroup) {
		abort_creds(newcred);
		return -ENOMEM;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	memcpy(newgroup->blocks[0], new->groups,
	       newgroup->ngroups * sizeof(gid_t));
#else
	memcpy(newgroup->gid, new->groups, newgroup->ngroups * sizeof(kgid_t));
#endif
	set_groups(newcred, newgroup);
	put_group_info(newgroup);

	newcred->cap_effective = new->cap_effective;
	newcred->cap_inheritable = new->cap_inheritable;
	newcred->cap_permitted = new->cap_permitted;
	newcred->securebits = new->securebits;

	saved->cred = override_creds(newcred);
	put_cred(newcred);
	current->fs->umask = new->umask;
	current->signal->leader = new->leader;
#if defined(WITH_LEGACY_CRAY) && defined(CONFIG_CRAY_ACCOUNTING)
	current->csa_apid = new->csa_apid;
#endif
	current->tgid = new->tgid;
	current->blocked = new->blocked;
	memcpy(current->signal->rlim, &new->rlim,
	       sizeof(current->signal->rlim));

	/*
	 * Increase RLIMIT_NOFILE.  We only want to enforce open file limits
	 * on clients, and don't want to trip over this limit when sharing
	 * init's file structures with other threads.
	 */
	if (current->signal->rlim[RLIMIT_NOFILE].rlim_max < 16384)
		current->signal->rlim[RLIMIT_NOFILE].rlim_max = 16384;
	if (current->signal->rlim[RLIMIT_NOFILE].rlim_cur < 16384)
		current->signal->rlim[RLIMIT_NOFILE].rlim_cur = 16384;
	kernel_set_task_nice(current, new->nice);

	return 0;
}

/*
 * Restore saved context
 */
static inline void pop_context(struct usicontext *saved)
{
	revert_creds(saved->cred);

	current->fs->umask = saved->umask;
	current->signal->leader = saved->leader;
#if defined(WITH_LEGACY_CRAY) && defined(CONFIG_CRAY_ACCOUNTING)
	current->csa_apid = saved->csa_apid;
#endif
	current->tgid = saved->tgid;
	current->blocked = saved->blocked;
	memcpy(current->signal->rlim, saved->rlim,
	       sizeof(current->signal->rlim));
	kernel_set_task_nice(current, saved->nice);
}
