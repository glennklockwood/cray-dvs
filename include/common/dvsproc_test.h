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

#ifndef __DVSSYS_TEST_H__
#define __DVSSYS_TEST_H__

#ifdef __KERNEL__
#include <linux/proc_fs.h>

extern int dvsproc_test_init(struct proc_dir_entry *);
extern void dvsproc_test_exit(struct proc_dir_entry *);

#endif /* __KERNEL__ */

#endif /* __DVSSYS_TEST_H__ */
