#!/usr/bin/env bash
set -euo pipefail
version=${1:-8.4.4}
flavor=${2:-asan}
[[ "$version" =~ ^8\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected stable 8.x.y version'; exit 2; }
[[ "$flavor" = asan || "$flavor" = normal || "$flavor" = cov ]] || exit 2
base=/home/phplab/php-lab
source_dir="$base/sources/php-$version"
build="$base/builds/$version-$flavor"
prefix="$base/install/$version-$flavor"
mkdir -p "$base/sources" "$base/builds" "$base/install" "$base/logs"
exec > >(tee "$base/logs/build-$version-$flavor.log") 2>&1
if [ ! -d "$source_dir/.git" ]; then
  git clone --depth 1 --branch "php-$version" https://github.com/php/php-src.git "$source_dir"
fi
test -z "$(git -C "$source_dir" status --porcelain)" || { echo 'Source modified; refusing baseline build'; exit 1; }
commit=$(git -C "$source_dir" rev-parse HEAD)
if [ ! -f "$source_dir/configure" ]; then
  ( cd "$source_dir"; ./buildconf --force )
fi
mkdir -p "$build"
cd "$build"
flags=(-g3 -O2 -fno-omit-frame-pointer)
options=(--disable-all --enable-cli --enable-fpm --enable-session --without-pear --prefix="$prefix")
if [ "$flavor" = asan ] || [ "$flavor" = cov ]; then
  flags=(-g3 -O1 -fno-omit-frame-pointer)
  options+=(--enable-debug --enable-address-sanitizer)
  # cov: identical to asan plus SanitizerCoverage edge guards; with
  # ASAN_OPTIONS=coverage=1 each process writes <binary>.<pid>.sancov at
  # exit (Phase 5 v2 Stage 1c code-edge feedback).
  if [ "$flavor" = cov ]; then flags+=(-fsanitize-coverage=trace-pc-guard); fi
else
  options+=(--disable-debug)
fi
CC=clang CXX=clang++ CFLAGS="${flags[*]}" CXXFLAGS="${flags[*]}" "$source_dir/configure" "${options[@]}"
make -j2
make install
"$prefix/bin/php" -n -v
"$prefix/sbin/php-fpm" -n -v
python3 - "$version" "$flavor" "$commit" "$prefix" "${options[*]}" <<'PY'
import hashlib, json, pathlib, subprocess, sys
version, flavor, commit, prefix, configure = sys.argv[1:]
data = dict(version=version, flavor=flavor, source_commit=commit, prefix=prefix,
            configure=configure, compiler=subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
            kernel=subprocess.check_output(['uname', '-a'], text=True).strip())
data['binary_sha256'] = {name: hashlib.sha256(pathlib.Path(prefix, name).read_bytes()).hexdigest()
                         for name in ('bin/php', 'sbin/php-fpm')}
data['makefile_flags'] = [line for line in pathlib.Path('Makefile').read_text().splitlines()
                         if line.startswith(('CFLAGS =', 'CFLAGS_CLEAN =', 'LDFLAGS =', 'CONFIGURE_COMMAND ='))]
pathlib.Path(prefix, 'build-manifest.json').write_text(json.dumps(data, indent=2))
PY
