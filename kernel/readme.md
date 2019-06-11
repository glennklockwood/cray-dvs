# Building DVS manually as a kernel module

## Intended Audience

This readme is tailored for a developer familiar with kernel and kernel module development. All information here is relevant to developing the kernel module itself. Setup of vm's, os installation, and other ancillary tasks are outside of the scope of this readme.

## Known Functional Operating Systems

As of the time of writing, only SLES 12 SP3, Linux kernel 4.4, is known to work. While DVS may function on other kernel revisions and platforms, this readme and setup presumes SLES 12 SP3 for all instructions.

### Build Prerequisites

To build DVS, obviously you will need the kernel source, a compiler, make, a devel lnet rpm, ostensibly cray-lnet, and a checkout of this repository.

Note: Stock lnet available from lustre will not allow you to build DVS. The devel rpms built are inadequate to allowing you to include the header files to build DVS against. Note however, that the cray-lustre development rpm package contains *no* changes for lnet compared to the community lustre lnet.

For SLES 12 SP3, you will need to install the following rpms with zypper:
- kernel-default-devel kernel-source kernel-syms [1]
- cray-lustre cray-lustre-devel

[1]: Note, you must install the exact same version as currently booted for the kernel-default rpm. Example:

```
kernel_rpm_version=$(rpm -q --queryformat '%{version}-%{release}\n' kernel-default)
zypper -n in kernel-source=${kernel_rpm_version} kernel-default-devel=${kernel_rpm_version} kernel-syms=${kernel_rpm_version}
```

### Minimal Configuration Prerequisites

Lnet will need to be configured to use tcp as the transport against the appropriate ethernet device. Example using *eth0* as the ethernet device:

```
# echo 'options lnet networks=tcp(eth0)' | tee /etc/modprobe.d/60-lnet.conf
```

To be able to modprobe dvs after build, you will need to specify the number of maximum nodes available to the dvs cluster you will be setting up/testing. For this readme, we will only ever use the local node, as such we will set this value to 1.

```
# echo 'options dvsproc ssiproc_max_nodes=1' | tee /etc/modprobe.d/88-dvs.conf
```

Lnet will need to be loaded as a kernel module for testing, note you may skip this if you don't intend to load the module at all. Note, you may need to add --allow-unsupported to load these kernel modules, or to set *allow_unsupported_modules* to *1* in */etc/modprobe.d/10-unsupported-modules.conf*

Example setting *allow_unsupported_modules* to *1* and manually modprobing the kernel modules:

```
# echo 'allow_unsupported_modules 1' | tee -a /etc/modprobe.d/10-unsupported-modules.conf
modprobe ksocklnd
modprobe lnet
modprobe lustre
```

### Building DVS

With all that out of the way, you're ready to actually build DVS.

In this directory simply type:

```
# make
```

And wait

To install built kernel modules, and a userspace helper binary to */usr/sbin* type:

```
# make install
```

### Loading DVS

Loading the DVS kernel module is somewhat unintutitive. First you need to load the dvsproc kernel module like so:

```
# modprobe dvsproc
```

Then you'll need to configure the */sys/kernel/debug/dvs/ssi-map* file. It is recommended to save this file to /etc so you can simply cat the file to the sys filesystem.

Example, note replace HOSTNAME with your hosts hostname, IP with its ipv4 address as appropriate:

```
# echo 'HOSTNAME IP@tcp' | tee /etc/ssi-map
```

Note also, that /etc/hosts will need to be properly setup for the node with HOSTNAME, example entry:

```
IP HOSTNAME.example.com EXAMPLE
```

If your host is setup correctly in dns that should also suffice, but to ensure hostname and ip lookups work correctly ensure that /etc/hosts is setup correctly to mimic A and C records for the host in question.

Now you're ready to load dvs:

```
# cat /etc/ssi-map | tee /sys/kernel/debug/dvs/ssi-map
modprobe dvs
```

If you were successful you will see output in dmesg similar to the following:

```
[  330.710956] dvs_thread_generator: Watching pool DVS-IPC_msg (id 0)
```

And you should see the following kernel modules:

```
# lsmod | grep dvs
dvs                   360448  0
dvsipc                110592  2 dvs
dvsipc_lnet            40960  1 dvsipc
dvsproc               114688  3 dvs,dvsipc,dvsipc_lnet
lnet                  557056  6 osc,lustre,obdclass,ptlrpc,ksocklnd,dvsipc_lnet
```
