--TEST--
Harness calibration: deliberately distinguish release and debug builds, NOT a CVE
--FILE--
<?php echo PHP_DEBUG ? "debug\n" : "release\n"; ?>
--EXPECT--
debug
