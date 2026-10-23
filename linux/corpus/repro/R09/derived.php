<?php
// Derived reproducer (#4 H2.5): bugs_php_net_bug_php_id_76409.block00.txt
// verbatim - test.jpg is the single byte 0x2f ("Lw==" base64), and the
// report calls exif_read_data(file_get_contents("test.jpg")).
file_put_contents(__DIR__ . '/test.jpg', base64_decode('Lw=='));
@exif_read_data(file_get_contents(__DIR__ . '/test.jpg'));
echo "done\n";
