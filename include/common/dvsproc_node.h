/*
 * Copyright 2014-2015 Cray Inc. All Rights Reserved.
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
 *   NOTE: IF you change, add or remove anything from this file make sure that
 *         DVSNET-IF still works.  Modifiy DVSNET-IF as needed.
 *         include/dvsnet-if-ssiproc.h
 */

#ifndef DVSPROC_NODE_H
#define DVSPROC_NODE_H

typedef struct ssi_node_map {
	char			*name; /* node name */
	char			*tok;  /* interconnect token */
#ifdef __KERNEL__
	struct ssi_server_info	*server_info; /* server_info for servers only */
	spinlock_t		rr_lock; /* rr ref count lock */
#endif
} ssi_node_map_t;

#define SSIPROC_NODENAME_MAXLEN 256
#define SSIPROC_TOK_MAXLEN	256

#define SSI_NODE_NAME(node) (((node) >= 0 && (node) < ssiproc_max_nodes) ? \
				node_map[(node)].name : "bad node")

extern struct ssi_node_map *node_map;
extern int ssiproc_max_nodes;

/* node_map locking flags */
#define SSIPROC_LOCK_READ	0x0001
#define SSIPROC_LOCK_WRITE	0x0002

extern struct ssi_node_map *ssiproc_parse_mapfile(char *, unsigned long, int *);
extern int ssiproc_add_nodes(void);
extern int ssiproc_get_max_nodes(void);
extern int ssiproc_get_my_nodeid(void);
extern int ssiproc_lock_node_map(int);
extern int ssiproc_unlock_node_map(int);

extern uint64_t ipclower_str2phys(char *tok);
#endif
