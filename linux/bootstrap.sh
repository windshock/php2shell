#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
created_policy=0
if [ ! -e /usr/sbin/policy-rc.d ]; then
  printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
  chmod +x /usr/sbin/policy-rc.d
  created_policy=1
fi
trap 'if [ "$created_policy" = 1 ]; then rm -f /usr/sbin/policy-rc.d; fi' EXIT
apt-get update
apt-get install -y --no-install-recommends build-essential clang libclang-rt-18-dev llvm gdb autoconf bison re2c pkg-config git ca-certificates curl nginx python3 libxml2-dev libsqlite3-dev
systemctl disable nginx.service || true
if ! id phplab >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash phplab
fi
install -d -o phplab -g phplab /home/phplab/php-lab
echo 'Bootstrap ready: use phplab for builds and services.'
