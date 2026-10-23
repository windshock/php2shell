<?php
// Derived reproducer (#4 H2.5): bugs_php_net_bug_php_id_78793.block00.txt
// verbatim loop over the php-src test file ext/exif/tests/bug77950.tiff
// (read from the official source tree, never written). The report saw the
// error under MemorySanitizer only, not under AddressSanitizer.
$f = '/home/phplab/php-lab/sources/php-8.4.27/ext/exif/tests/bug77950.tiff';
for ($i = 0; $i < 10; $i++) {
    fprintf(STDERR, "ITERATION $i:\n");
    @exif_read_data($f);
}
echo "done\n";
