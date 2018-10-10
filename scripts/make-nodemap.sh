#!/bin/bash
#
# Copyright 2007-2009 Cray Inc. All Rights Reserved.
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
# Create DVS node-map files for seastar interfaces
#
NODE_MAP_DIR=${NODE_MAP_DIR:-.}
IPC_INTERFACE=${IPC_INTERFACE:-ss}
HOSTS=${HOSTS:-/opt/xt-images/templates/default/etc/hosts}

mkdir -p ${NODE_MAP_DIR}

#
# Generate seastar ipc node-map first.
# 
# Format of the file is:
#  node_name physNID
#
xtcdr2proc -n | awk '{print $3,$1}' > ${NODE_MAP_DIR}/node-map.ss

#
# Link to the correct node-map file for the specified transport.
#
rm -f ${NODE_MAP_DIR}/node-map
ln -s ${NODE_MAP_DIR}/node-map.${IPC_INTERFACE} ${NODE_MAP_DIR}/node-map
