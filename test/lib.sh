#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
#
# Shared library functions for use in DVS testing

# Constants that shouldn't be generally changed

# Where is the /sys patches file?
SYS_PATCHES="${SYS_PATCHES:-/sys/fs/dvs/patches}"

# Where is the ssi-map?
SYS_SSIMAP="${SYS_SSIMAP:-/sys/kernel/debug/dvs/ssi-map}"

# Where is our lower fs we are projecting?
LOWERFS=${LOWERFS:-/mnt/lowerfs}

# Where should all our test work happen?
PREFIX=${PREFIX:-/mnt/dvs}

# Where should test results end up in the end?
RESULTS=${RESULTS:-"${PREFIX}/results"}

# The source of where clients mount.
SOURCE=${SOURCE:-"${PREFIX}/source"}

# Where should timeline information go?
TIMELINE=${TIMELINE:-"${RESULTS}/timeline"}

# How many DVS servers are requested?
DVS_SERVER_COUNT=${DVS_SERVER_COUNT:-1}

# How many DVS run nodes are requested?
DVS_CLIENT_COUNT=${DVS_CLIENT_COUNT:-1}

# If needed, are DVS server/run nodes allowed to overlap?
DVS_NODES_MAY_OVERLAP=${DVS_NODES_MAY_OVERLAP:-true}

# What extra DVS mount options should be applied?
DVS_MNTOPT_EXTRAS=${DVS_MNTOPT_EXTRAS:-"none"}

dvs_total_nodes_count() {
  wc -l "${SYS_SSIMAP}" | awk '{print $1}'
}

# Return the number of nodes that make up the total span
have_enough_nodes() {
  if [ "${DVS_SERVER_COUNT}" -le 0 ]; then
     echo "0"
  fi
  if [ "${DVS_CLIENT_COUNT}" -le 0 ]; then
     echo "0"
  fi
  if [ "${DVS_NODES_MAY_OVERLAP}" = false ]; then
    max_overlap_count=0
  elif [ "${DVS_SERVER_COUNT}" -ge "${DVS_CLIENT_COUNT}" ]; then
    max_overlap_count=$DVS_CLIENT_COUNT
  else
    max_overlap_count=$DVS_SERVER_COUNT
  fi
  requested_nodes_count=$(("$DVS_SERVER_COUNT" + "$DVS_CLIENT_COUNT" - "$max_overlap_count"))
  total_nodes_count=$(dvs_total_nodes_count)
  if [ "${requested_nodes_count}" -gt "${total_nodes_count}" ]; then
    echo "0"
  else
    echo "${total_nodes_count}"
  fi
}

# Idempotent setup function, can be run in parallel with other tests.
setup_prelude() {
  install -Ddm755 "${PREFIX}" "${RESULTS}" "${SOURCE}"
}

# General prelude function for use by DVS tests that have mounts
do_setup_test_prelude() {
  setup_prelude
  export DEST="${PREFIX}/${BASE}"
  export DESTRESULTS="${RESULTS}/${BASE}"
  install -Ddm755 "${DEST}" "${DESTRESULTS}" "${LOWERFS}"
  mount_get "$(dvs_mount_nodes)"
}

setup_shell_test_prelude() {
  if [ "$(have_enough_nodes)" -eq 0 ]; then
    echo "Not enough nodes - skipping test $SRC"
    exit 0
  fi
  do_setup_test_prelude
}

setup_sharness_test_prelude() {
  if [ "$(have_enough_nodes)" -eq 0 ]; then
    # shellcheck disable=SC2034
    skip_all='Not enough nodes'
    test_done
  fi
  do_setup_test_prelude
}

# parses ${SYS_SSIMAP} to get node names for mount
#
# Output is a string of , joined node names.
dvs_mount_nodes() {
  awk '{print $2}' "${SYS_SSIMAP}" | tr '\n' ',' | sed -e 's/,$//g'
}

# Same as above, but reversed ordering
dvs_umount_nodes() {
  awk '{print $2}' "${SYS_SSIMAP}" | sed '1!G;h;$!d' | tr '\n' ',' | sed -e 's/,$//g'
}

# Return a comma-separated list of DVS client node namess. These nodes are the
# only nodes that are capable of running tests.
dvs_client_list() {
  nodes=$(awk '{print $2}' "${SYS_SSIMAP}" | tail -n "${DVS_CLIENT_COUNT}" | tr '\n' ',' | sed -e 's/,$//g')
  echo "${nodes}"
}

# Return a comma-separated list of DVS server node names.
dvs_server_list() {
  nodes=$(awk '{print $2}' "${SYS_SSIMAP}" | head -n "${DVS_SERVER_COUNT}" | tr '\n' ',' | sed -e 's/,$//g')
  echo "${nodes}"
}

# Return the name of last DVS client node. This is the node on which tests that
# run on only one node should run.
last_dvs_client_node() {
  node=$(awk '{print $2}' "${SYS_SSIMAP}" | tail -n 1)
  echo "${node}"
}

# Make it easier to get how much system memory is available.
sys_memory() {
  free -m | grep Mem | awk '{print $2}'
}

# Cheap functions to use for predicates that will help us know if we're on a VM.
#
# (ab)using the dmi interface for this, better ways to do this are sought.
product_name() {
  cat /sys/class/dmi/id/product_name
}

bios_vendor() {
  cat /sys/class/dmi/id/bios_vendor
}

# Are we in a virtualbox vm?
virtualbox() {
  if [ "$(product_name)" = "VirtualBox" ] && \
         [ "$(bios_vendor)" = "innotek GmbH" ]; then
    return 0
  fi
  return 1
}

# Are we in an openstack instance?
#
# Note, this is on Kilo on KVM, might need more vaidating.
openstack() {
  if [ "$(product_name)" = "OpenStack Nova" ] && \
         [ "$(bios_vendor)" = "SeaBIOS" ]; then
    return 0
  fi
  return 1
}

# Used by the is_vm function, might be useful elsewhere.
_is_vm() {
  if virtualbox || openstack ; then
    return 0
  fi
  return 1
}

# Note, positive assertion only, we only set the IS_VM predicate
# if we truly know the system we're on is a virtual machine or not.
is_vm() {
  _is_vm && test_set_prereq "IS_VM"
}

# Simple function to load any customizations that may be needed but only if
# present.
source_custom() {
  # shellcheck disable=SC1091
  [ -f "custom.sh" ] && . custom.sh
}

# Set sharness prereqs based on the existence of a command in PATH
#
# Predicate name becomes HAS_command when command is in PATH
has_command() {
  command -v "$*" > /dev/null 2>&1 && test_set_prereq "HAS_$*"
}

# Set sharness predicate IS_user when the current user == current user
is_user() {
  [ "$*" = "$(id -un)" ] && test_set_prereq "IS_$*"
}

# Set a prereq to denote that we're on a DVS that has been patched
has_patches() {
  [ -e "${SYS_PATCHES}" ] && test_set_prereq "HAS_PATCHES"
}

# Set a prereq to denote that we have a specific patch applied
has_patch_x() {
  if [ -e "${SYS_PATCHES}" ] && grep "$*" "${SYS_PATCHES}" > /dev/null 2>&1 ; then
    test_set_prereq "HAS_PATCH_$*"
  else
    test_set_prereq "NO_PATCH_$*"
  fi
}

patched_test() {
  has_patches
  has_patch_x "${BASE}"
}

# Basically just a way to run some command, the first arg is the list of where to run.
#
# run host1,host2 stuff
#
# TODO: TONS MORE CAN BE DONE HERE... just later not today.
#
# If you want to run something locally, just run it normally don't use this function.
#
# A note on this function, this function is setup to run all 1..N nodes iff nodes < 1
#
# That is, if one node is passed in, it will run there no matter what.
#
# If more than one node is passed in, it runs on all nodes *BUT* the first.
#
# The reason is so that you can pass in all nodes in the ssi-map delimited by ,'s
# and this runs all the commands on the remote nodes.
#
# The premise is that if there is one node, you run things locally. If there is more
# than one node, you run things there and not locally.

# This runs things *without* logging the output to files by default, run() does
_run() {
  hosts=${1:-"$(dvs_client_list)"}; shift
  #  logged=${1:-no}; shift
  logged=yes; shift
  PIDS=""

  i=0
  for host in $(echo "${hosts}" | tr ',' ' '); do
    hostdir="${TIMELINE}/${BASE}/${host}"

    if [ "${logged}" = "yes" ]; then
      install -Ddm755 "${hostdir}"
      printf "# %s $*\\n" "${host}" | tee -a "${TIMELINE}/run"
      ssh -q -ax -S none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${host}" "$@" 2>> "${hostdir}/stderr" >> "${hostdir}/stdout" &
    else
      ssh -q -ax -S none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${host}" "$@" &
    fi
    PIDS="${PIDS} $!"
    : $((i+=1))
  done

  # Wait loop, *very* simple for now.
  i=0
  for pid in ${PIDS}; do
    wait "${pid}"
    RC="${RC} $?"
    : $((i+=1))
  done

  # Return the worst case of what was run, first failure is the first to be returned
  i=0
  for status in ${RC}; do
    if [ "${status}" -ne 0 ]; then
      return "${status}"
    fi
  done
  return 0
}

run() {
  _run "$(dvs_client_list)" "yes" "$*"
}

# Given:
# the number of DVS servers, extra mount options, source, and destination
# echo a mount line for dvs
#
# Presumption is destination is the same everywhere.
mount_dvs_string() {
  dvs_server_count=$1; shift
  dvs_mntopt_extras=$1; shift
  source=$1; shift
  dest=$1; shift
  hosts="dvs"
  server_num=1
  while [ "${server_num}" -lt "${dvs_server_count}" ]
  do
    hosts="$hosts:dvs$server_num"
    server_num=$((server_num+1))
  done
  if [ "${dvs_mntopt_extras}" = "none" ]; then
    dvs_mntopt_extras=""
  else
    dvs_mntopt_extras=",${dvs_mntopt_extras}"
  fi
  echo mount -t dvs -o path="${dest}",nodename="${hosts}""${dvs_mntopt_extras}" "${source}" "${dest}"
}

# Internal used only by the next two functions
_lockfile="${TMPDIR:-/tmp}/dvs-mount-lock"
_lockfiledone="${_lockfile}.done"
_lockfilepiddir=${_lockfile}.pids

# mount_get is responsible for doing the dvs mount of /mnt/dvs on client nodes
# and recording all usage of that mount in tests.
#
# Strategy here is we flock on file descriptor 3 (good/bad idea? seems to work
# for now so who cares if there is a better way we can change it later)
#
# What happens: We create a lock file of fd 3, flock on that file so we can
# serialize any work done by sh scripts run in parallel, we look for a file that
# indicates some script has had client nodes mount the /mnt/dvs mounts for
# testing. If it has, followup scripts don't do anything despite locking and
# serializing the check to see if mounting has occurred. Finally, we create a
# file with our pid, $$ into a directory for use later to ensure we can
# correctly unmount dvs on all client/server nodes.
#
# Note on style in shell here, THIS IS SOME OF THE MOST AWFUL SHELL EVER
# WRITTEN. I'm not proud of it, but it works. Treat it like magic unless you
# understand it.
#
# DO NOT INSERT SPACES IN BETWEEN 3 and <, bash for some reason hates spaces
# around some valid posix shell. Bash is an annoying bourne shell, by that I
# mean it is insane what fiddly details it complains about that posix is fine
# with.
mount_get() {
  install -dm755 "${_lockfilepiddir}"
  : >> "${_lockfile}"
  {
    flock 3
    if [ ! -f "${_lockfiledone}" ]; then
      # Why shellcheck bitches about ${LOWERFS} not being quoted is beyond me,
      # the whole thing is quoted, it makes no sense.
      # shellcheck disable=SC2086
      _run "$(dvs_mount_nodes)" "yes" "install -Ddm755 ${SOURCE}; $(mount_dvs_string ${DVS_SERVER_COUNT} ${DVS_MNTOPT_EXTRAS} ${LOWERFS} ${SOURCE})"
      touch "${_lockfiledone}"
    fi
  } 3<"${_lockfile}"
  echo $$ > "${_lockfilepiddir}/$$"
}

# mount_put is responsible for doing unmounting ll of the client mounts mounted
# by mount_get
#
# We use the files setup by mount_get under /tmp/dvs-mount-lock.pids to know
# when we can do an unmount.
#
# Basically whomever manages to pull off an rmdir successfully does an unmount
# as they're the last script out the door to remove their pid file.
mount_put() {
  # This check is bogus here.
  # shellcheck disable=SC2164
  cd /
  # Unmount uses the same trick as mount_get to serialize or act as a mutex
  # between multiple processes to make sure the last one out unmounts.
  : >> "${_lockfile}"
  {
    flock 3
    rm "${_lockfilepiddir}/$$"
    sleep 1
    if ! rmdir "${_lockfilepiddir}" ; then
      printf "# mount_put() deferred\\n"
      return 0
    else
      printf "# mount_put() unmounting\\n"
      # rmdir worked! so remove the mount that mount_get setup
      _run "$(dvs_umount_nodes)" "yes" "umount ${SOURCE}"
      rm "${_lockfiledone}" || /bin/true
    fi
  } 3<"${_lockfile}"
}
