#!/bin/bash
# Copyright 2018 Cray Inc. All Rights Reserved.

# called by dracut
check() {
	return 0
}

# called by dracut
depends() {
	echo "cray-ansible-lnet"
	echo "cray-dvs"
	return 0
}

install() {
	# Ansible DVS modules
	find /etc/ansible/roles/dvs -type f | \
		while read -r x ; do inst_simple "$x" ; done

	# Ansible DVS config file
	inst_simple /etc/ansible/dvs.yaml
}
