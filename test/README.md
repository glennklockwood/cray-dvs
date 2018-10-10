Adding Unit Tests to DVS
========================

## configure.ac (top level)

AC_CONFIG_FILES() contains a list of *.am targets to be converted by
automake into the target name. For instance, test/unittest/Makefile will
look for test/unittest/Makefile.am, and if found, will convert this into
test/unittest/Makefile. If you add any new Makefile.am files to the build
tree, you need to add them to this list, or the build will not work.

You may also want to add automake configure parameters to allow for
conditional builds based on autoconfig command-line options. See, for
instance, the code under the #MPI comment. This code converts

`autoreconf -i ./configure.ac --with-mpi=yes`

into

`export USE_MPI=1`

for use in the build environment.

## Makefile.am SUBDIRS (all levels)

Automake needs to be told which subdirectories to recurse into during the
build process, using the SUBDIRS macro.

Any Makefile.am can call out subdirectories. Every subdirectory needs to
be named in a SUBDIRS macro, somewhere. You can put them all in the
top-level Makefile.am, or you can use each intermediate Makefile.am (if
there is one) to list just the subdirectories below it.

## cray-dvs.spec (top level)

A new cray-dvs-test RPM package has been added, which installs test code
into:

/opt/cray/dvs/{version}/sbin/

To add new tests to this RPM, you must add individual files to the '%files
test' section.

WARNING: the list of files added here must exactly match the list of files
installed by the test Makefile.am. Omissions from one list or the other
will cause the build to fail.

## test/unittest/Makefile.am

To add new test code and compile it, add files to the sbin_SCRIPTS or
sbin_PROGRAMS macros. The sbin_PROGRAMS macros will also need source file
descriptions under a {testname}_SOURCES macro.

WARNING: the list of sbin_SCRIPTS and sbin_PROGRAMS macros must exactly
match the list of files added in the '%files test' section of the project
cray-dvs.spec file. Omission from one list or the other will cause the
build to fail.
