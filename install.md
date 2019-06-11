# Installing DVS

## Prerequisites

You currently need to have lustre/lnet installed and setup for your specific operating system.

Right now only the cray-lnet package includes the correct config.h file necessary to allow DVS to build. Currently there is no difference in the cray-lnet package to the upstream package, the upstream lustre package simply does not allow outside packages to include its source without redefining kernel symbols.

TODO: Where are we providiing cray-lnet so that it is externally available?
TODO: Link to a bug on getting the upstream lustre package config fixed so we can just use upstream lustre.

Note, while DVS has historically used LNet versions back to 2.5, this source release has only been tested with LNet released with Lustre 2.11. Prior releases may work but have an unknown status.

### LNet Distribution/Version matrix

This might be better framed as Linux Kernel release instead of Distribution.

| Linux Distribution | LNet Version | Known working? |
|--------------------|:------------:|---------------:|
| SLES 12 SP3        | 2.11         | yes            |
| SLES 12 SP3        |<2.11         | perhaps        |
| Centos 7.5         | 2.11         | not yet tested |
| Centos 7.5         |<2.11         | not yet tested |

### LNet Module Configuration

While configuring LNet entirely is out of scope of this document, LNet must be setup and running and loaded prior to loading/using DVS.

At a minimum there should be a lnet network with the name of *tcp* setup against the ethernet device that DVS will be running on.

An example from SLES 12 SP3, note you may adapt this to your distribution of choice depending on where modprobe configuration files are located, this example uses *eth0* as the device:

```
# echo 'options lnet networks=tcp(eth0)' | tee /etc/modprobe.d/60-lnet.conf
```

### DVS Module Configuration

Note, currently DVS requires static initialization of the number of nodes that will be in use at module load time. This is done via the *ssiproc_max_nodes* module parameter. Similar to LNet you configure that as options to the dvsproc module.

```
# echo 'options dvsproc ssiproc_max_nodes=1' | tee /etc/modprobe.d/88-dvs.conf
```

This contrived example lists one node, note the default is 0 and DVS will not load correctly without being told the maximum size of the nodes expected to be in use.

### DVS Network Configuration for hostname/ipv4

Note DVS is very sensitive to a correctly setup network. It is highly recommended that you have /etc/hosts setup with hostname/ip entries. An example of a good setup:

```
$ cat /etc/hosts
1.2.3.4 fqdn.example.com fqdn othershortname
2.3.4.5 fqdn2.example.com fqdn2 othershortname2
```

This contrived example shows two hosts correctly configured in */etc/hosts* as fqdn.example.com, and fqdn2.example.com respectively. Any other layout may cause hostname to ip lookup to fail or behave wrong at runtime. Configuration of */etc/hosts* needs to be done by some configuration software and is outside of the full scope of this readme.

### DVS ssi-map

Much like */etc/hosts*, dvs uses an ssi-map file to handle knowing what ip address sends to which LNet port. Using the prior example above, lets save a static ssi-map to /etc for later use when loading the dvs module.

```
$ cat /etc/ssi-map
fqdn 1.2.3.4@tcp
fqdn2 2.3.4.5@tcp
```

### LNet rpms

For building, you will need the *cray-lustre-devel* and *cray-lustre* rpms. For running DVS, you only need *the cray-lustre* rpm.

TODO: Where can a user get these rpms outside of cray? Ideally this is a zypper/yum repo they can just add. OpenSUSE Build Service is an ideal option here.

Cray internal specific example for SLES 12 SP3 here as a placeholder for now.

```
zypper ar --no-gpgcheck http://download.buildservice.us.cray.com/cray-lustre:/Cray-master/SLE_12_SP3_SHASTA/ lustre
zypper -n in cray-lustre cray-lustre-devel
```

## LNet Module Loading

Lnet will need to be loaded as a kernel module prior to DVS being loaded. Depending on your Linux Distribution you may need to specify --allow-unsupported to load these kernel modules, or to set *allow_unsupported_modules* to *1* in */etc/modprobe.d/10-unsupported-modules.conf* (SLES 12 SP3 example, replace with your specific Linux distribution as appropriate).

Example setting *allow_unsupported_modules* to *1* and manually modprobing the prerequisite kernel modules:

```
# echo 'allow_unsupported_modules 1' | tee -a /etc/modprobe.d/10-unsupported-modules.conf
modprobe ksocklnd
modprobe lnet
modprobe lustre
```

## DVS Module Loading

To correctly load dvs, you first need to load a helper module, *dvsproc*

```
modprobe dvsproc
```

Then you will need to load the ssi-map into a proc file, as in this document we saved a file before as */etc/ssi-map* we'll use that.

```
cat /etc/ssi-map | tee /sys/kernel/debug/dvs/ssi-map
```

Now you can load the dvs kernel module:

```
modprobe dvs
```

And you're ready to start mounting dvs filesystems!
