/*
 * Unpublished Work © 2004 Cassatt Corporation.  All rights reserved.
 * Copyright 2006-2009, 2011, 2016 Cray Inc. All Rights Reserved.
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

#include "common/kernel/hash_table.h"

#include <linux/slab.h>
#include "common/kernel/usiipc.h"

/*
 * ht_init - Create and initialize a new hash table.
 */
ht_t *ht_init(int32_t nbuckets)
{
	ht_t *new_ht = NULL;

	if (nbuckets <= 0) {
		printk(KERN_ERR "DVS: ht_init: invalid input: nbuckets=%d\n",
		       nbuckets);
		return NULL;
	}

	new_ht = (ht_t *)kmalloc_ssi(
		sizeof(ht_t) + (nbuckets * sizeof(ht_bucket_t *)), GFP_KERNEL);
	if (new_ht != NULL) {
		new_ht->ht_nbuckets = nbuckets;
		rwlock_init(&new_ht->ht_lock);
	} else {
		printk(KERN_ERR "DVS: ht_init: out of memory\n");
	}

	return new_ht;
}

/*
 * ht_delete - Delete a previously created hash table.  If free_bucket_data_mem
 *	       is set, the memory pointed to by htb_data in every bucket is
 *	       free'd.
 */
void ht_delete(ht_t *ht, int8_t free_bucket_data_mem)
{
	ht_bucket_t *htb_ptr = NULL, *free_htb_ptr = NULL;
	int i = 0;
	unsigned long flags = 0;

	if (ht == NULL) {
		printk(KERN_ERR "DVS: ht_delete: invalid input: ht=NULL\n");
		return;
	}

	write_lock_irqsave(&ht->ht_lock, flags);
	for (i = 0; i < ht->ht_nbuckets; i++) {
		htb_ptr = ht->ht_bucket[i];
		while (htb_ptr != NULL) {
			free_htb_ptr = htb_ptr;
			htb_ptr = htb_ptr->htb_next_bucket;

			if (free_bucket_data_mem)
				kfree_ssi(free_htb_ptr->htb_data);
			kfree_ssi(free_htb_ptr);
		}
	}

	write_unlock_irqrestore(&ht->ht_lock, flags);

	kfree_ssi(ht);
}

/*
 * ht_insert_data - Insert a new entry into the hash table.
 */
int8_t ht_insert_data(ht_t *ht, int64_t key, char *string, void *data)
{
	int ht_index = -1;
	ht_bucket_t *new_htb = NULL;
	unsigned long flags = 0;

	if (ht == NULL || data == NULL) {
		printk(KERN_ERR "DVS: ht_insert_data: invalid input: ht=0x%p "
				"key=0x%llx data=0x%p\n",
		       ht, key, data);
		return 0;
	}

	ht_index = ht_hash(key, ht);

	new_htb = (ht_bucket_t *)kmalloc_ssi(sizeof(ht_bucket_t), GFP_KERNEL);
	if (!new_htb)
		return 0;

	new_htb->htb_string = kmalloc_ssi(strlen(string) + 1, GFP_KERNEL);
	if (!new_htb->htb_string) {
		kfree_ssi(new_htb);
		return 0;
	}
	new_htb->htb_data = data;
	new_htb->htb_key = key;
	memcpy(new_htb->htb_string, string, strlen(string) + 1);
	new_htb->htb_prev_bucket = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	new_htb->htb_time = CURRENT_TIME;
#else
	getnstimeofday(&new_htb->htb_time);
#endif

	write_lock_irqsave(&ht->ht_lock, flags);
	if (ht->ht_bucket[ht_index] == NULL) {
		new_htb->htb_next_bucket = NULL;
		ht->ht_bucket[ht_index] = new_htb;
		write_unlock_irqrestore(&ht->ht_lock, flags);

		return 1;
	}

	ht->ht_bucket[ht_index]->htb_prev_bucket = new_htb;
	new_htb->htb_next_bucket = ht->ht_bucket[ht_index];
	ht->ht_bucket[ht_index] = new_htb;

	write_unlock_irqrestore(&ht->ht_lock, flags);

	return 1;
}

/*
 * ht_update_data - Locate an entry in the hash table and update it
 */
int8_t ht_update_data(ht_t *ht, int64_t key, char *string)
{
	char *old_htb_string;
	ht_bucket_t *htb_ptr = NULL;
	unsigned long flags = 0;

	if (ht == NULL) {
		printk(KERN_ERR "DVS: ht_update_data: invalid input: ht=0x%p "
				"key=0x%llx\n",
		       ht, key);
		return 0;
	}

	read_lock_irqsave(&ht->ht_lock, flags);

	htb_ptr = ht->ht_bucket[ht_hash(key, ht)];

	while (htb_ptr != NULL) {
		if (htb_ptr->htb_key == key) {
			read_unlock_irqrestore(&ht->ht_lock, flags);

			old_htb_string = htb_ptr->htb_string;
			htb_ptr->htb_string =
				kmalloc_ssi(strlen(string) + 1, GFP_KERNEL);
			if (!htb_ptr->htb_string) {
				htb_ptr->htb_string = old_htb_string;
				return 0;
			}
			kfree_ssi(old_htb_string);
			memcpy(htb_ptr->htb_string, string, strlen(string) + 1);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
			htb_ptr->htb_time = CURRENT_TIME;
#else
			getnstimeofday(&htb_ptr->htb_time);
#endif
			return 1;
		}
		htb_ptr = htb_ptr->htb_next_bucket;
	}

	read_unlock_irqrestore(&ht->ht_lock, flags);

	return 0;
}

/*
 * ht_delete_data - Delete an entry in the hash table and return it's data.
 */
void *ht_delete_data(ht_t *ht, int64_t key)
{
	ht_bucket_t *htb_ptr = NULL;
	void *data_ptr = NULL;
	unsigned long flags = 0;

	if (ht == NULL) {
		printk(KERN_ERR "DVS: ht_delete_data: invalid input: ht=0x%p "
				"key=0x%llx\n",
		       ht, key);
		return NULL;
	}

	write_lock_irqsave(&ht->ht_lock, flags);

	htb_ptr = ht->ht_bucket[ht_hash(key, ht)];
	while (htb_ptr != NULL) {
		if (htb_ptr->htb_key == key) {
			if (htb_ptr->htb_next_bucket != NULL)
				htb_ptr->htb_next_bucket->htb_prev_bucket =
					htb_ptr->htb_prev_bucket;
			if (htb_ptr->htb_prev_bucket != NULL)
				htb_ptr->htb_prev_bucket->htb_next_bucket =
					htb_ptr->htb_next_bucket;
			else
				ht->ht_bucket[ht_hash(key, ht)] =
					htb_ptr->htb_next_bucket;
			write_unlock_irqrestore(&ht->ht_lock, flags);
			data_ptr = htb_ptr->htb_data;
			kfree_ssi(htb_ptr->htb_string);
			kfree_ssi(htb_ptr);
			return data_ptr;
		}
		htb_ptr = htb_ptr->htb_next_bucket;
	}

	write_unlock_irqrestore(&ht->ht_lock, flags);

	return NULL;
}

/*
 * ht_find_data - Locate an entry in the hash table and return it's data.
 */
void *ht_find_data(ht_t *ht, int64_t key)
{
	ht_bucket_t *htb_ptr = NULL;
	unsigned long flags = 0;

	if (ht == NULL) {
		printk(KERN_ERR "DVS: ht_find_data: invalid input: ht=0x%p "
				"key=0x%llx\n",
		       ht, key);
		return NULL;
	}

	read_lock_irqsave(&ht->ht_lock, flags);

	htb_ptr = ht->ht_bucket[ht_hash(key, ht)];

	while (htb_ptr != NULL) {
		if (htb_ptr->htb_key == key) {
			read_unlock_irqrestore(&ht->ht_lock, flags);
			return htb_ptr->htb_data;
		}
		htb_ptr = htb_ptr->htb_next_bucket;
	}

	read_unlock_irqrestore(&ht->ht_lock, flags);

	return NULL;
}
