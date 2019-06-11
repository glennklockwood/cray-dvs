#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

# shellcheck source=./lib.sh
. "${DIR}/lib.sh"

setup_shell_test_prelude

FSTESTDEST="${SOURCE}/fstest.git"
FSTESTRESULTS="${RESULTS}/${BASE}"
install -Ddm755 "${FSTESTRESULTS}"

# Download and configure the zfs on linux port of the open-source
# POSIX Filesystem Test Suite
git clone --depth 1 https://github.com/zfsonlinux/fstest.git "${FSTESTDEST}" || /bin/true
make "${FSTESTDEST}/fstest"
sed -i -e 's/ZFS/ext3/' "${FSTESTDEST}/tests/conf"

cd "${FSTESTRESULTS}" || exit 127

# Run fstest on the last DVS client node we find, this test suite doesn't lend itself well
# to running on multiple nodes at once.
_run "$(last_dvs_client_node)" "yes" "cd ${SOURCE} && prove -r ${FSTESTDEST} --timer --archive ${FSTESTDEST}/results.tar.gz --merge --state save"
rc=$?
results="${FSTESTDEST}/results.tar.gz"
[ -e "${results}" ] && mv "${results}"  "${FSTESTRESULTS}/results.tar.gz"

cleanup() {
  mount_put
}

trap cleanup EXIT

exit ${rc}
