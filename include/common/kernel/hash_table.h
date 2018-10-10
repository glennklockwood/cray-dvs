/*
 * Unpublished Work © 2004 Cassatt Corporation.  All rights reserved.
 * Copyright 2006-2007, 2009, 2011 Cray Inc. All Rights Reserved.
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

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/time.h>

typedef struct ht_bucket_s {
	int64_t			htb_key;
	char			*htb_string;
	struct timespec		htb_time;
	void			*htb_data;	/* mem not managed by us */
	struct ht_bucket_s	*htb_next_bucket;
	struct ht_bucket_s	*htb_prev_bucket;
} ht_bucket_t;

typedef struct ht_s {
	int32_t		ht_nbuckets;
	rwlock_t	ht_lock;
	ht_bucket_t	*ht_bucket[0];
} ht_t;

#define ht_hash(key, ht)	(((uint64_t)key) % ht->ht_nbuckets)

ht_t	*ht_init(int32_t nbuckets);
void	ht_delete(ht_t *ht, int8_t free_bucket_data_mem);
int8_t	ht_insert_data(ht_t *ht, int64_t key, char *string, void *data);
int8_t  ht_update_data(ht_t *ht, int64_t key, char *string);
void	*ht_delete_data(ht_t *ht, int64_t key);
void	*ht_find_data(ht_t *ht, int64_t key);

#endif /* HASH_TABLE_H */
