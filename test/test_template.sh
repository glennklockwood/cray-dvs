#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)
DVS_SERVER_COUNT=1
DVS_CLIENT_COUNT=2
DVS_NODES_MAY_OVERLAP=false
DVS_MNTOPT_EXTRAS="maxnodes=1"

export test_description="Replace this with a real description"
# shellcheck source=./sharness/sharness.sh
. "${DIR}/sharness/sharness.sh"
# shellcheck source=./lib.sh
. "${DIR}/lib.sh"

setup_shell_test_prelude

test_expect_success EXPENSIVE "return 0 = true" "
  return 0
"

cleanup "echo use this if needed to clean up after yourself"

test_done
