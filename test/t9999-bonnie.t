#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

test_description="Ensure bonnie runs on DVS"
# shellcheck source=./sharness/sharness.sh
. "${DIR}/sharness/sharness.sh"
# shellcheck source=./lib.sh
. "${DIR}/lib.sh"

setup_sharness_test_prelude
has_command bonnie

# Take the size of memory on the hosting server and double that for the bonnie
# test to make sure our results aren't bogus.
memoryx2=$(($(sys_memory)*2))

test_expect_success HAS_bonnie,EXPENSIVE "bonnie runs on ${SOURCE} fs" "
  run 'bonnie -d ${SOURCE} -s ${memoryx2}'
"

mount_put
test_done
