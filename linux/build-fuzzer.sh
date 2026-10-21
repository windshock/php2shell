#!/usr/bin/env bash
# PHP official fuzzing SAPI build (libFuzzer + ASAN), separate from lab builds.
set -euo pipefail
base=/home/phplab/php-lab
source_dir="$base/sources/php-8.4.4"
build="$base/builds/8.4.4-fuzzer"
prefix="$base/install/8.4.4-fuzzer"
mkdir -p "$build" "$prefix" "$base/logs"
exec > >(tee "$base/logs/build-8.4.4-fuzzer.log") 2>&1
test -z "$(git -C "$source_dir" status --porcelain)" || { echo 'source modified; refusing'; exit 1; }
cd "$build"
rm -rf "$build"/*
CC=clang CXX=clang++ "$source_dir/configure" \
  --disable-all --enable-cli --enable-session --enable-fuzzer \
  --with-pic --enable-debug-assertions --enable-address-sanitizer \
  --prefix="$prefix" CFLAGS="-g3 -O1 -fno-omit-frame-pointer" \
  CXXFLAGS="-g3 -O1 -fno-omit-frame-pointer"
make -j2
ls -l sapi/fuzzer/php-fuzz-unserialize "$prefix/bin/php"
