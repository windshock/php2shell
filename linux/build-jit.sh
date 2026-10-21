#!/usr/bin/env bash
# Build PHP 8.4.4 with opcache (runtime JIT available) for differential testing.
set -euo pipefail
base=/home/phplab/php-lab
source_dir="$base/sources/php-8.4.4"
build="$base/builds/8.4.4-jit"
prefix="$base/install/8.4.4-jit"
mkdir -p "$build" "$prefix" "$base/logs"
exec > >(tee "$base/logs/build-8.4.4-jit.log") 2>&1
test -z "$(git -C "$source_dir" status --porcelain)" || { echo 'source modified; refusing'; exit 1; }
rm -rf "$build"; mkdir -p "$build"; cd "$build"
CC=clang CXX=clang++ "$source_dir/configure" \
  --disable-all --enable-cli --enable-session --enable-opcache --without-pear \
  --prefix="$prefix" CFLAGS="-g3 -O2 -fno-omit-frame-pointer" \
  CXXFLAGS="-g3 -O2 -fno-omit-frame-pointer"
make -j2
make install
"$prefix/bin/php" -n -v
"$prefix/bin/php" -n -d zend_extension=opcache -d opcache.enable_cli=1 -r 'echo function_exists("opcache_get_status") ? "opcache ok\n" : "opcache missing\n";'
