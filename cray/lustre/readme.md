# Terraform setup to build cray lustre rpms

Note, this setup exists solely to make it easy to build lustre-client rpms for use by dvs for testing purposes.

The end result of a run from terraform is two directories:
- sles12sp3
- sles15sp0

Both should contain all of the rpms built via this process, and are setup to be used as zypper rpm repositories (aka: createrepo has been ran against them).

At the time of writing, only cray lustre source has been tested, but the intention is that upstream lustre could also be built in the same way as DVS only truly requires lnet to build.
