<?php
// Deterministic serialization workload for JIT vs non-JIT differential testing.
$acc = [];
for ($i = 0; $i < 20000; $i++) {
    $value = ['a' => [1, 2, 3], 'b' => str_repeat('x', $i % 50), 'c' => (object) ['n' => $i]];
    $encoded = serialize($value);
    $decoded = unserialize($encoded);
    $acc[] = $decoded['c']->n;
}
session_start();
$_SESSION = ['first' => $acc[0], 'count' => count($acc)];
$session = session_encode();
$_SESSION = [];
session_decode($session);
echo hash('sha256', json_encode([$acc[0], $acc[19999], $_SESSION, strlen($session)])), "\n";
echo 'count=', count($acc), ' session_len=', strlen($session), "\n";
