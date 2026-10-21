--TEST--
Harness calibration: skipped tests must remain inconclusive
--SKIPIF--
<?php die('skip intentional harness control'); ?>
--FILE--
<?php echo "not executed\n"; ?>
--EXPECT--
not executed
