#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
# Description: A simple shell script to setup terraform for dvs in tmux
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)
set -e

usage()
{
  echo "tmux wrapper to start a DVS VM cluster"
  echo ""
  echo "Usage: ${BASE}"
  echo "  -h --help"
  echo "  --nodes=NODES"
  echo "  --flavor=NAME"
  echo "  --session=NAME"
  echo "  --distro=NAME"
  echo ""
}

# Note: we expect sane input, if you pass a letter where a number is needed well
# don't do that. TODO: bother with better input parsing? Meh.
# https://www.youtube.com/watch?v=q_GaltQHGXs
while [ "$1" != "" ]; do
  PARAM=$(echo "$1" | awk -F= '{print $1}')
  VALUE=$(echo "$1" | awk -F= '{print $2}')
  case $PARAM in
  -h | --help)
    usage
    exit
    ;;
  --session)
    session="$VALUE"
    ;;
  --nodes)
    nodes="$VALUE"
    ;;
  --flavor)
    flavor="$VALUE"
    ;;
  --distro)
    distro="$VALUE"
    ;;
  *)
    echo "ERROR: unknown parameter $PARAM"
    usage
    exit 1
    ;;
  esac
  shift
done

# exported variables are exported to make the entire session pickup settings on
# new pane creation
session=${session:-dvs}
FLAVOR=${flavor:-highcpu.4}
NODES=${nodes:-1}
DISTRO=${distro:-sles15sp0}
export FLAVOR
export NODES
export DISTRO

cd "${DIR}"

if ! tmux has-session -t "${session}"; then
  # First session pane is for doing work in the primary VM or whatever
  tmux new-session -d -s "${session}" -n dvs
  tmux send-keys -t "${session}:0" "ssh dvs"
  # Second split window in that session is for bringing things up running make
  # rsync to sync source/etc...
  # Also runs the ssh config targets after bringup so ssh is possible
  tmux split-window -v -t "${session}:0"
  tmux send-keys -t "${session}:0.1" "make init clean up TF_VAR_os_flavor=${FLAVOR} TF_VAR_nodes=${NODES} TF_VAR_distro=${DISTRO} && make ssh_config" C-m

  if [ "${NODES}" -gt 1 ]; then
    # First window ssh's to dvs
    tmux new-window -n dvs-N-nodes -t "${session}:1"
    tmux send-keys -t "${session}:1" "ssh dvs"
    idx=1
    # dvsN nodes (if any) in session 1
    while [ "${idx}" -lt "${NODES}" ]; do
      tmux split-window -v -t "${session}:"
      tmux send-keys -t "${session}:1.${idx}" "ssh dvs${idx}"
      idx=$(( idx + 1 ))
    done
  fi

  tmux select-window -t "${session}:0"
fi
tmux attach -t "${session}"
