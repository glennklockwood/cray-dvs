#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
set -e

iface=$1; shift
nodes=$1; shift

# Note, zypper al all kernel modules to prevent a situation where the kernel
# is upgraded but our kernel source is different.
#
# We need a better solution to upgrading the kernel and then rebooting...
#
# For now just build using the kernel version that kernel-default is using
#
echo 'allow_unsupported_modules 1' | tee -a /etc/modprobe.d/10-unsupported-modules.conf
zypper --gpg-auto-import-keys ref
zypper ar --no-gpgcheck https://download.opensuse.org/repositories/benchmark/openSUSE_Factory/ benchmark
zypper ar --no-gpgcheck https://download.opensuse.org/repositories/devel:/tools:/compiler/openSUSE_Factory/ compiler
zypper ar --no-gpgcheck http://srd-jenkins.us.cray.com/job/ci-dvs-lustre/job/feature%2Fshared%2Fshasta/lastSuccessfulBuild/artifact/sles12sp3 lustre
kernel_rpm_version=$(rpm -q --queryformat '%{version}-%{release}\n' kernel-default)
zypper -n in gcc make automake autoconf bc patch kernel-source=${kernel_rpm_version} kernel-default-devel=${kernel_rpm_version} kernel-syms=${kernel_rpm_version}
zypper -n in lustre-client lustre-client-devel
zypper -n in bonnie iozone
zypper -n al 'kernel*'
zypper -n up
echo "options lnet networks=tcp(${iface})" | tee /etc/modprobe.d/60-lnet.conf
echo 'options dvsproc ssiproc_max_nodes='"${nodes}" | tee /etc/modprobe.d/88-dvs.conf
modprobe ksocklnd
modprobe lnet
modprobe lustre
ln -s /usr/src/linux "/lib/modules/$(uname -r)/build"

# Install TAP:Harness::Archive so we can save the tap test output
curl -L https://cpanmin.us | perl - App::cpanminus
cpanm TAP::Harness::Archive
