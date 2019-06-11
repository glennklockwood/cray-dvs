#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
SRC="$0"
BASE=${SRC##*/}
DIR=$(cd "${SRC%$BASE}" && pwd || exit 126)

ips=$1; shift
prefix=${1:-"dvs"}; shift
domain=${1:-"example.com"}; shift
idx=0

# Here due to shift usage above, if theres nothing to shift that call fails.
set -e

# Basically, inputs are IP1,IP2,IP3 etc...
#
# This script sets up hostnames in /etc/hosts as follows:
# dvs = IP1
# dvs1 = IP2
# dvsn = IP(n+1)
#
# It then also sets up /etc/ssi-map with the same information essentially.

# We control /etc/ssi-map's horizontal and vertical.
cat /dev/null /etc/ssi-map || /bin/true

# We control /etc/hosts less...
cp /etc/hosts "/etc/hosts.orig.$(date +%s)"

for ip in $(echo "${ips}" | tr ',' ' '); do
  # index 0 is the "dvs" server not dvs0, dvs0 seems a silly name.
  if [ $((idx)) -eq 0 ]; then
    hostname=${prefix}
  else
    hostname="${prefix}${idx}"
  fi

  # Cheap, but it'll do, note we match on the host.domain.tld *NOT* on host
  sed -i -e "/.*${hostname}[.]${domain}.*/d" /etc/hosts
  echo "${ip} ${hostname}.${domain} ${hostname}" | tee -a /etc/hosts
  echo "${hostname} ${ip}@tcp" | tee -a /etc/ssi-map
  : $(( idx=idx+1 ))
done
