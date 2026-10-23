<?php
// Derived reproducer (#4 H2.5): the concise test input quoted verbatim in
// bugs_php_net_bug_php_id_74101.block01.txt, wrapped in unserialize().
var_dump(@unserialize('O:9:"Exception":799999999999999999999999999997:0i:0;a:0:{}i:2;i:0;i:0;R:2;'));
echo "done\n";
