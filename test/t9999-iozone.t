#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

export test_description="Ensure iozone runs on DVS"
# shellcheck source=./sharness/sharness.sh
. "${DIR}/sharness/sharness.sh"
# shellcheck source=./lib.sh
. "${DIR}/lib.sh"

setup_sharness_test_prelude
has_command iozone

test_expect_success HAS_iozone,EXPENSIVE "iozone runs on lower fs ${LOWERFS}" "
  install -Ddm755 ${RESULTS}/${BASE}
  iozone -a -b ${RESULTS}/${BASE}/lowerfs-$(uname -n).xls
"

test_expect_success HAS_iozone,EXPENSIVE "iozone runs on ${SOURCE} fs" "
  install -Ddm755 ${RESULTS}/${BASE}
  run '(install -Ddm755 ${SOURCE}/\`uname -n\`; cd ${SOURCE}/\`uname -n\` && iozone -a -b ${SOURCE}/\`uname -n\`/source-\`uname -n\`.xls)'
"

mount_put
test_done
