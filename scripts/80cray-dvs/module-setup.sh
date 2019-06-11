#!/bin/bash
# Copyright 2018 Cray Inc. All Rights Reserved.

# called by dracut
check() {
	return 0
}

# called by dracut
depends() {
	echo "cray-lnet"
	return 0
}

install() {
	rpm -ql $(rpm -qa | grep dvs | grep -v dvsnet) | grep -v '/man/' | \
		grep -v '/doc/' | grep -v ".txt" | grep -v '/example/' | \
		while read -r x ; do inst_simple "$x" ; done
}
