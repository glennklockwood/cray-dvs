# DVS terraform+openstack automation

## Purpose

This automation is intended to show/allow for automating the creation of any number of sles vms, copying source to those vms, building the source, installing/loading the dvs kernel modules, and finally, doing basic mount testing and validation operations.

## Limitations

This setup has only been tested on SLES 12 SP3, and SLES 15 SP0. Other distributions *may* work, but will likely require changes.

# Usage

## Prerequisites

You *MUST* have terraform installed on your *$PATH*. Installing terraform is beyond the scope of this readme. Get terraform here:

https://www.terraform.io/downloads.html

You should also have an ssh key, preferably rsa, setup that you want to use for the vm. The default key file as used by this setup is ~/.ssh/id_rsa.cray_openstack

I recommend *not* putting a passphrase on the key, to generate the key you can do the following:

```
$ ssh-keygen -t rsa -b 4096 -C "Example ssh key" -f ~/.ssh/readme_example_rsa
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /Users/mtishmack/.ssh/readme_example_rsa.
Your public key has been saved in /Users/mtishmack/.ssh/readme_example_rsa.pub.
The key fingerprint is:
SHA256:2QMDwTFug2AGMfWUpBLpSOknwuuMvPWd43UZkhwQ4Hc Example ssh key
The key's randomart image is:
+---[RSA 4096]----+
|==*.o+*=.        |
|.B =oo.o.        |
|B . o.+.oE       |
|o* . ...o=o      |
|. +     S+o.     |
| .        ..o    |
|=  .     . o     |
|.+. . ..o .      |
| ..  ..+.        |
+----[SHA256]-----+
```

You will also need an openrc file, you may download one after logging into openstack by clicking on your user name and downloading the v3 openrc file.

Save this openrc file as $USER-openrc-v3.sh and source it:

```
$ . $USER-openrc-v3.sh
```

## Creating a vm in openstack via terraform

To create a vm simply type:

```
$ make up
```

To create multiple vm's simply run:

```
$ make up TF_VAR_nodes=N
```

To control what distribution should be built, *NOTE* only the strings sles12sp3 and sles15sp0 are valid run:

```
$ make up TF_VAR_distro=sles12sp3
$ make up TF_VAR_distro=sles15sp0
```


## Building source

Instead of installing git in the vm, we can simply rsync the current git checkout to the vm into */src*. This is automated, simply run:

```
$ make rsync
```

To rsync the current checkout to the vm.

## Building DVS

After rsyncing you can simply run:

```
$ make dvs
```

To build the source in the vm. If it exits fine it built successfully.

## Installing the DVS kernel modules

Once built, you will need to install the DVS kernel modules.

```
$ make install
```

## Loading the installed DVS kernel module

This will run depmod and other shenanigans and configure the vm to load/setup DVS on that node only by using */etc/ssi-map*.

```
$ make load
```

## Run tests on the built and loaded kernel module

Note, this clones fstest source from github so will require an active internet connection.

```
$ make test
```

## Remove the built vm instance

To cleanup and remove the instance and any associated components simply run:

```
$ make clean
```

## To ssh into built instance(s)

To make it a bit easier to ssh into the built openstack image, once you have built vm's you can run the following target:

```
$ make ssh_config
```

This will setup your ~/.ssh/config with entries for the vm's that have been built. This allows you to use ssh/scp/rsync at your convenience.

To remove any entries created by this setup run:

```
$ make clean_ssh_config
```

This will remove any entries added.

## If you have tmux installed

There is a provided script in this directory, *tmux.sh* that automates setting up sessions/panes/windows.

To use it simply run it like so (with switches to quick demonstrate that part):

```
$ ./tmux.sh --nodes=4 --flavor=highcpu.4
```
