/*
 * $Id: fnv_hash.h,v 1.1.1.1 2005/05/17 21:08:24 mjl Exp $
 *
 * Fowler / Noll / Vo Hash (FNV Hash)
 * http://www.isthe.com/chongo/tech/comp/fnv/
 *
 * This is an implementation of the algorithms posted above.
 * This file is placed in the public domain by Peter Wemm.
 *
 * Taken from:
 * $FreeBSD: src/sys/sys/fnv_hash.h,v 1.2 2001/03/20 02:10:18 peter Exp $
 */

/*
 * Copyright 2006-2007, 2009 Cray Inc. All Rights Reserved.
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

typedef uint32_t Fnv32_t;
#define FNV1_32_INIT ((Fnv32_t)33554467UL)
#define FNV_32_PRIME ((Fnv32_t)0x01000193UL)

static __inline Fnv32_t fnv_32_str(const char *str, Fnv32_t hval)
{
	const u_int8_t *s = (const u_int8_t *)str;
	Fnv32_t c;

	while ((c = *s++) != 0) {
		hval *= FNV_32_PRIME;
		hval ^= c;
	}
	return hval;
}
