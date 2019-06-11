#
# Copyright Cray Inc. All Rights Reserved
#

SUBDIRS = \
	include \
	scripts \
	userspace \
	test/unittest \
	test/ioperf \
	test/xattr/xattr_stress

if DOCS
SUBDIRS += man
endif

pkgconfig_DATA = cray-dvs.pc

sysconf_DATA = .version

.version:
	echo "#%Module" > $@
	echo "set ModulesVersion \"@MODULE_VERSION@\"" >> $@

install-data-local:
	$(INSTALL_DATA) -D $(srcdir)/module $(DESTDIR)@MODULE_PATH@
