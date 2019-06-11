/*
 * Unpublished work   Copyright 2004 Cassatt Corporation   All rights reserved.
 * Copyright 2006-2007, 2011 Cray Inc. All Rights Reserved.
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

/*
 * mod_interface.h - abstract away differences between the kernels
 *                   the USSL (aka SSI) modules support.
 */

#if !defined(MOD_INTERFACE_H)
#define MOD_INTERFACE_H

#ifndef __KERNEL__
/*
 * This header file not for userland!
 */
#error "Invalid inclusion of kernel-only header file kernel_interface.h"
#endif /* __KERNEL__ */

/*
 * Macros
 */

/*
 * Scheduling priorities
 */

/* get the nice value for a task */
#define kernel_get_task_nice(task) (current->static_prio - MAX_RT_PRIO - 20)
/* set the nice value for a task */
#define kernel_set_task_nice(task, new_nice) set_user_nice((task), new_nice)

/*
 * Signals
 */

/* get the signal lock */
#define kernel_get_signal_lock(task) ((task)->sighand->siglock)
/* determine if a specific signal is pending */
#define kernel_is_specific_signal_pending(task, signo)                         \
	(sigismember(&((task)->pending.signal), signo) ||                      \
	 sigismember(&((task)->signal->shared_pending.signal), signo))

#endif /* !defined(MOD_INTERFACE_H) */
