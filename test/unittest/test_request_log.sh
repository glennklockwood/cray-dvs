#!/bin/bash
#
# Copyright 2016 Cray Inc. All Rights Reserved.
#
# This file is part of Cray Data Virtualization Service (DVS).
#
# DVS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DVS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

echo 1 >/proc/fs/dvs/request_log
for siz in 256 257; do
	echo $siz >/proc/fs/dvs/request_log_size_kb
	x=0
	y=1
	while [[ $x -ne $y ]]; do
		y=$x
		ls /tmp/A >/dev/null
		x=$(cat /proc/fs/dvs/request_log | wc -l)
	done
	cat /proc/fs/dvs/request_log |
		sed 's/^.*cmd=//' >tmp1
	ls /tmp/A >/dev/null
	cat /proc/fs/dvs/request_log |
		sed 's/^.*cmd=//' >tmp2
	if cmp tmp1 tmp2; then
		echo "Size $siz succeeded"
	else
		echo "Size $siz failed"
	fi
done
