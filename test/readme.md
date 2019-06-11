# DVS Testing

# Table of Contents

* [Running tests](#running-tests)
* [Running fstest](#running-fstest)
* [Writing tests](#writing-tests)
* [Patching DVS](#patching-dvs)
* [Testing Caveats](#testing-caveats)
* [Running fstest](#running-fstest)

## Running Tests

DVS tests primarily utilize the sharness shell test framework to run. Upstream repo here https://github.com/chriscool/sharness

As such the tests are simply shell scripts that end in a *.t* suffix instead of .sh. To make running all of the tests via the perl prove test harness, a Makefile is present in this directory.

To run all of the fast tests, run:

```
make
```

or

```
make test
```

or

```
make test-fast
```

All three are equivalent.

We also run third party tooling via the same mechanism, however any test or tool that takes over ~10 minutes to run gets tagged into this category.

Currently we run iozone, and bonnie if present and the *test-long* target is called.

The *test-long* target is the same as *test-fast*, however it includes tests that can and probably will take a considerable amount of time to run. On the order of hours.

As such one must opt into testing them. To run these tests simply use the make *test-long* target like so:

```
make test-long
```

You may also completely ignore all of the above, and manually run the tests individually like so:

```
# /src/test/t1000-sys-fs-dvs-patches.t
ok 1 # skip We can cat /sys/fs/dvs/patches (missing HAS_PATCHES)
# passed all 1 test(s)
1..1
```

Note however you will need to ensure you provide a runnable environment for the test to run in. Tests should have predicates, that will attempt to gate them from running when they shouldn't. However they may not be perfect

## Writing Tests

Writing tests using sharness is rather straightforward. A minimal template you may copy from is located at [test_template.sh](test_template.sh)

Simply copy that file to a file named *tXYZN-description.t* and start writing your tests.

### Test framework philosophy/assumptions.

This test framework has been designed under some key assumptions. Note they aren't immutable assumptions, merely useful assumptions to getting work done quickly and getting tests running ASAP. But they do color how this test framework can be used at the time of writing.

Assumptions:
- The test framework/tests are responsible for mounting DVS mounts used for testing
- The test framework/tests are responsible for unmounting DVS mounts used for testing
- The tests should be able to be run in parallel
- The tests should *NOT* mount things twice or unmount filesystems in parallel that it controls
- The test framework controls the (by default */mnt/dvs*) directory it works in and is solely responsible for its setup/use
- The test framework controls the directory/mount (by default */mnt/lowerfs*) for the server
- Given an environment of N nodes, by default node 0 is the DVS server. If you want more than one DVS server, define the environment variable DVS_SERVER_COUNT=S, where S is the number of DVS servers. If S > N, then your test will run will be skipped.
- Given an environment of N nodes with S DVS servers, by default the last 2 nodes are DVS clients. If you want more or fewer DVS clients, define the environment variable DVS_CLIENT_COUNT=C, where C is the number of DVS clients. If C > N, then your test run will be skipped.
- Given an environment of N nodes, where the environment variable DVS_NODES_MAY_OVERLAP=false, and where the requested number of DVS servers is S and the requested number of DVS clients is C, then is (S + C) > N, then your test run will be skipped.
- To specify extra mount options to append to the DVS mount options string, define the environment variable DVS_MNTOPT_EXTRAS="name=val,name=val...", where name and val are supported DVS mount options and associated values. DO NOT include the path or nodename mount options, nor a comma "," prefix, as those are automatically generated.
- Tests control via calling *_run* or *run* where their tests run client node wise if that is a concern
- Tests control via calling *_run* or *run* where their tests run client node wise if that is a concern
- Tests are run as root
- Tests are only run on the first or only VM node
- ssh can be used passwordlessly as root across all nodes running tests

Before we describe how to write tests, lets step back first and describe what happens for testing. As DVS is essentially a network filesystem, we need to be able to run tests on multiple nodes that are each projecting a singular filesystem.

If you're testing on a single, node, you test and run on the same system. No shock there, not too many ways to test on a single node. But, that doesn't test much usefully.

When you have a DVS setup with N nodes, lets set N at 3 right now for simplicity, things get a bit more complicated. In this case, the first node will always be the DVS server node hosting data to the other 1..N nodes.

Of particular note, bonnie and iozone and fstest all differ slightly in how they run on different nodes. fstest as an example, only runs on the first client node. bonnie and iozone tests run on all nodes simultaneously.

It is up to the test creator to correctly determine how/when to run on client nodes.


### Why are the tests named tXYZN-description.t?

What is the reason for the naming convention? In a nutshell, we're following how the git project names tests. Sharness being the git test suite really means we're mostly just using their naming convention.

The tests end with .t so we can use wildcard *.t in makefiles, and easily separate out helper scripts/shell from test scripts.

The numbering is however something that has a method to the madness.

| Range     | Purpose                                                                 |
|-----------|:-----------------------------------------------------------------------:|
| 0-1000    | Very basic tests of the DVS modules, e.g. mod load/unload etc...        |
| 1001-2000 | Testing DVS while the kernel module is loaded, (no unloading expected)  |
| 2001-9000 | For future usage                                                        |
| 9001-9999 | Third party tests                                                       |

### Components Of A Good Test

Note, this is all generalities, all tests will require some thought and might need to deviate from anything put here. Use your own judgement.

But ideally a test:
- Should not fail if it is missing prerequisites, a failure should indicate test failure, not test failure due to lack of environmental setup
- Should define up front what it depends on
- Should be able to be run in parallel with other tests
- Should not depend on any prior tests, should be self contained
- Cleans up after itself
- Is able to run anywhere, be that VM, or an actual system
- Should be portable bourne shell, not dependent upon bash
- Should be run through shellcheck https://github.com/koalaman/shellcheck and ideally pass with no errors or warnings. Disabling checks just to remove warnings is discouraged.

Not all tests will fit into all these categories, an example of a test that cannot be done on a Cray XC is module unloading. As such we should be declaring that as a predicate that gates where a test will or can be expected to run.

Lets go over a quick example test for demonstration, not specific to DVS however:

```
#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

export test_description="Make sure true is true"
# shellcheck source=./sharness/sharness.sh
. "${DIR}/sharness/sharness.sh"
# shellcheck source=./lib.sh
. "${DIR}/lib.sh"

# Specify how many DVS servers & clients are required for this test, and
# whether overlapping of servers & clients is allowed when there are not enough
# nodes for clients and servers to remain independent.
# Defaults are: 1 DVS server, 2 DVS clients, nodes may NOT overlap.
# NOTE: DVS client nodes are the only nodes that are capable of running tests.
#       If a test is best-suited to run on only one node, it should run on the
#       last DVS client node. That test may use the function
#       last_dvs_client_node() to get the name of that last DVS client node.
DVS_SERVER_COUNT=1
DVS_CLIENT_NODE_COUNT=2
DVS_NODES_MAY_OVERLAP=false

# Setup automatically configures the DVS mount path and nodename mount options.
# If additional DVS mount options must be specified, use DVS_MNTOPT_EXTRAS
# to specify the extra DVS mount options to append.
DVS_MNTOPT_EXTRAS="attrcache_timeout=3,maxnodes=2"

# We need to call setup_sharness_test_prelude for a sharness test, or
# setup_shell_test_prelude for a shell test, if we depend upon DVS mounts
# being setup correctly for us. If there are not enough nodes to support
# the requested numbers and configuration of DVS servers and DVS clients,
# then those commands will output a message indicating that the test will be
# skipped due to not enough nodes, and will exit with a non-failure status.
setup_sharness_test_prelude

test_expect_success "return 0 = true" "
  return 0
"

cleanup "echo use this if needed to clean up after yourself"

# Similarly we need to call this function to cleanup correctly, but only if we needed DVS mounts
mount_put

test_done
```

Lets ignore the shebang lines, below those we define SRC/BASE/DIR so that we can load in both sharness and then our test library code in *lib.sh*. Next we also set *test_description* to a value which describes what the test is meant to accomplish. NOTE: test_description *MUST* be set prior to sourcing sharness and lib.sh!

Finally, we get to the test, in this case *test_expect_success*, which as the name implies, expects the shell we provide to evaluate to true. Finally we have a cleanup function which is responsible for any cleanup necessary that we may have setup in any prior tests. Lastly, we have test_done which is necessary for declaring that our test has finished correctly.

In the end we will see the following if we run this test script:

```
ok 1 - return 0 = true
# passed all 1 test(s)
1..1

```

### Adding a predicate to control when we run

Lets change that test_expect_success line to the following:

```
test_expect_success EXPENSIVE "return 0 = true" "
```

If we rerun the test we see the following:

```
ok 1 # skip return 0 = true (missing EXPENSIVE)
# passed all 1 test(s)
1..1

```

We can run this test by just adding --long-tests to the call to the test like so:

```
./test_script --long-tests
```

And we will now get the same situation as before.

### Setting our own predicates to determine if a test should run or not

While the EXPENSIVE predicate is great, and indeed it is what gates our "fast" tests from our "slow" tests, see the t9999* tests for examples. What if we have some way of determining on our own if we should have something run.

Lets have a look at one of the [lib.sh](lib.sh) functions, has_command():

```
has_command() {
  which $* > /dev/null 2>&1 && test_set_prereq "HAS_$*"
}
```

Now if we call this function in our script for some command, lets choose *make*, we can do the following:

```
has_command make

test_expect_success HAS_make "we have make present on PATH" "return 0"
```

And our test will only ever run when make is present. You can also call test_set_prereq manually to set a predicate. You can add multiple predicates by separating them via commas, like so:


```
test_expect_success HAS_foo,HAS_bar "we have foo and bar on PATH" "return 0"
```

For full details, have a look at the sharness source, it is rather small, at time of writing only 965 lines, most of which is comments: https://github.com/chriscool/sharness/blob/master/sharness.sh There are a lot of examples in the comments too. I won't go too deep into those things here.

## Patching DVS

In order to make it possible to patch DVS with changes that we don't normally want to be present in the source, we are following the linux kernel module of just applying patches on an ad-hoc basis.

To utilize this you simply need to provide a patch file in this directory. Commit the patch file into git and you can then use use *make patch* in the kernel directory to apply all patches to your current source.

An important part of this patch setup is that you include your patch in the list of patches applied from the t1000-sys-fs-dvs-patches.patch sysfs file.

Taking a minimal example, you need at least one hunk like so:

```
# cat t1001-sys-fs-dvs-patches-test.patch
diff --git a/kernel/dvsproc/sys_setup.c b/kernel/dvsproc/sys_setup.c
index 8beeebab..56ded205 100644
--- a/kernel/dvsproc/sys_setup.c
+++ b/kernel/dvsproc/sys_setup.c
@@ -73,6 +73,7 @@ EXPORT_SYMBOL(quiesce_barrier_rwsem);
 static const char patches[] = "\0"
                               /* PATCH START */
                               "t1000-sys-fs-dvs-patches.t\0"
+                              "t1001-sys-fs-dvs-patches-test.t\0"
                               /* PATCH END */
                               "\0";
```

Patches are expected to be applied in order, if any fail the patch will need to be updated.

PATCH START and PATCH END exist to help the patch command figure out where to apply the patch.

### Patch naming

Similar to our tests, patches should be named with a t, 4 leading digits, a dash, and then a description and then .patch. This is to ensure consistent ordering and to ensure patches are applied correctly and in a consistent manner.

Examples:
t1000-sys-fs-dvs-patches.patch
t1001-sys-fs-dvs-patches-test.patch

### Disabling a patch

To disable a patch, simply delete it. Its stored in git so removing it from your checkout will remove it from being patched. Or if you have changes to the patch, move the patch to have *no-* as the patch name. That is either of the following will work:

```
rm my_great.patch
mv my_great.patch no-my_great.patch
```

### Detecting if a patch is applied to DVS or not

Detecting if a patch is applied to DVS in a sharness test is trivial. Lets take a simple example:

t0000-readme.t
```
#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

export test_description="Is my patch applied or not?"
# shellcheck source=./sharness/sharness.sh
. "${DIR}/sharness/sharness.sh"
# shellcheck source=./lib.sh
. "${DIR}/lib.sh"

patched_test

test_expect_success HAVE_PATCH_"${BASE}" "${BASE} patch has been applied to running DVS" "
  return 0
"

test_expect_success NO_PATCH_"${BASE}" "${BASE} patch has not been applied to running DVS" "
  return 0
"

test_done
```

This example will run the first patch, if and only if there is an entry in */sys/fs/dvs/patches* with the same string as the test name. Conversely, it will run the second test only when that entry is not present in */sys/fs/dvs/patches* (or that file doesn't exist). Say we named this patch t0000-readme-patch.t, I would expect the patch file to look like so:
```
# cat t0000-readme.patch
diff --git a/kernel/dvsproc/sys_setup.c b/kernel/dvsproc/sys_setup.c
index 8beeebab..56ded205 100644
--- a/kernel/dvsproc/sys_setup.c
+++ b/kernel/dvsproc/sys_setup.c
@@ -74,6 +74,7 @@ EXPORT_SYMBOL(quiesce_barrier_rwsem);
 static const char patches[] = "\0"
                               /* PATCH START */
                               "t1000-sys-fs-dvs-patches.t\0"
                               "t1001-sys-fs-dvs-patches-test.t\0"
+                              "t0000-readme.t\0"
                               /* PATCH END */
                               "\0";
```

And running the test on a non patched box looks like what we would expect:

```
# ./t0000-readme.t
ok 1 # skip t0000-readme.t patch has been applied to running DVS (missing HAVE_PATCH_t0000-readme.t)
ok 2 - t0000-readme.t patch has not been applied to running DVS
# passed all 2 test(s)
1..2
```

Its up to you to write the test that is correct, this is just an example that takes advantage of both the positive assertion that a test patch is applied, and that it is not. Perhaps your test only runs if DVS has the patch applied or not.

Note, if you need to test for a specific patch string in */sys/fs/dvs/patches* lib.sh has a function *has_patch_x example* defined to let you easily set a predicate HAVE_PATCH_example and/or NO_PATCH_example. Its simply a grep for the text you pass it in */sys/fs/dvs/patches*, nothing special.

## Testing Caveats

TODO: I'm not entirely sure what all to write here.

## Running fstest

Our usage of fstest is a bit unique as it also outputs TAP text. As such fstest runs cannot be done from within our normal test suite.

To run fstest against a loaded DVS kernel module simply run:

```
make test-fstest
```
