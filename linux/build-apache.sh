#!/usr/bin/env bash
# Build PHP 8.4.4 as an Apache module (mod_php, prefork) with ASAN.
# Pristine source is reused; a separate build tree and prefix keep the
# existing CLI/FPM builds untouched.
set -euo pipefail
version=${1:-8.4.4}
[[ "$version" =~ ^8\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected stable 8.x.y version'; exit 2; }
base=/home/phplab/php-lab
source_dir="$base/sources/php-$version"
build="$base/builds/$version-apache"
prefix="$base/install/$version-apache"
mkdir -p "$base/builds" "$base/install" "$base/logs"
exec > >(tee "$base/logs/build-$version-apache.log") 2>&1
[[ -d "$source_dir/.git" ]] || { echo "Missing source checkout: $source_dir"; exit 1; }
test -z "$(git -C "$source_dir" status --porcelain)" || { echo 'Source modified; refusing build'; exit 1; }
commit=$(git -C "$source_dir" rev-parse HEAD)
rm -rf "$build"
mkdir -p "$build"
cd "$build"
flags=(-g3 -O1 -fno-omit-frame-pointer)
"$source_dir/configure" \
  --disable-all --enable-cli --enable-session --without-pear \
  --with-apxs2=/usr/bin/apxs2 --enable-debug --enable-address-sanitizer \
  --prefix="$prefix" \
  CFLAGS="${flags[*]}" CXXFLAGS="${flags[*]}"
make -j2
make install
"$prefix/bin/php" -n -v
ls -l "$prefix/modules/libphp.so"
python3 - "$version" apache "$commit" "$prefix" <<'PY'
import hashlib, json, pathlib, subprocess, sys
version, flavor, commit, prefix = sys.argv[1:5]
data = dict(version=version, flavor=flavor, source_commit=commit, prefix=prefix,
            configure='--with-apxs2 --enable-debug --enable-address-sanitizer',
            compiler=subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
            kernel=subprocess.check_output(['uname', '-a'], text=True).strip())
data['binary_sha256'] = {name: hashlib.sha256(pathlib.Path(prefix, name).read_bytes()).hexdigest()
                         for name in ('bin/php', 'modules/libphp.so')}
data['makefile_flags'] = [line for line in pathlib.Path('Makefile').read_text().splitlines()
                          if line.startswith(('CFLAGS =', 'CFLAGS_CLEAN =', 'LDFLAGS ='))]
pathlib.Path(prefix, 'build-manifest.json').write_text(json.dumps(data, indent=2))
PY
