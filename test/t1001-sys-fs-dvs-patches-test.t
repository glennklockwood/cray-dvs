#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}"; pwd)

test_description="Test that our patching mechanism works"
. ${DIR}/sharness/sharness.sh
. ${DIR}/lib.sh

patched_test

test_expect_success HAS_PATCH_"${BASE}" "${BASE} patch is applied" "
  grep ${BASE} ${SYS_PATCHES}
"

test_expect_success NO_PATCH_"${BASE}" "${BASE} patch is not applied" "
  grep ${BASE} ${SYS_PATCHES} || return 0
"

test_done
