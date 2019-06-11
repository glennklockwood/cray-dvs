#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}"; pwd)

test_description="Test that our patching mechanism works"
. ${DIR}/sharness/sharness.sh
. ${DIR}/lib.sh

has_patches

test_expect_success HAS_PATCHES "We can cat /sys/fs/dvs/patches" "
  cat /sys/fs/dvs/patches
"

test_done
