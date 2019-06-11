#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

set -e
# This follows the advice from http://wiki.lustre.org/Compiling_Lustre#Establish_a_Build_Environment
#
# There is a chance its out of date or does too much, as it stands it takes
# forever to install the rpms and then build lustre.
zypper --gpg-auto-import-keys ref

kernel_rpm_version=$(rpm -q --queryformat '%{version}-%{release}\n' kernel-default)
zypper -n in kernel-source=${kernel_rpm_version} kernel-default-devel=${kernel_rpm_version} kernel-devel=${kernel_rpm_version} kernel-syms=${kernel_rpm_version}

# sles15 has createrepo_c, 12 createrepo (python)
zypper -n in createrepo_c || zypper -n in createrepo

zypper -n in asciidoc automake bc binutils-devel bison device-mapper-devel elfutils libelf-devel flex gcc gcc-c++ git glib2-tools glib2-devel hmaccalc libattr-devel libblkid-devel libselinux-devel libtool libuuid-devel lsscsi make mksh ncurses-devel net-tools numactl parted patchutils pciutils-devel perl pesign expect python-devel rpm-build sysstat systemd-devel tcl tcl-devel tk tk-devel wget xmlto zlib-devel libyaml-devel krb5-devel keyutils-devel net-snmp-devel

install -Ddm755 /src
cd /src
tar xvf /tmp/lustre.tar

patch -p1 < /tmp/make-lustre-great-again.patch

sh autogen.sh

./configure --disable-server --enable-client

make rpms -j $(grep -c processor /proc/cpuinfo)

install -Ddm775 /tmp/lustre

cp /src/*.rpm /tmp/lustre

cd /tmp/lustre

createrepo .
