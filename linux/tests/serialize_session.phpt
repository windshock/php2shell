--TEST--
Lab environment: session encode/decode and serialization roundtrip
--EXTENSIONS--
session
--INI--
session.use_cookies=0
session.cache_limiter=
--FILE--
<?php
session_start();
$_SESSION = ['lab' => ['n' => 7, 's' => 'test']];
$encoded = session_encode();
$_SESSION = [];
var_dump(session_decode($encoded));
var_dump($_SESSION['lab']['n']);
$value = ['a' => [1, 2], 'b' => 'ok'];
var_dump(unserialize(serialize($value)) === $value);
session_destroy();
?>
--EXPECT--
bool(true)
int(7)
bool(true)
