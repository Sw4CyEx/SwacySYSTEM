<?php

$descriptorspec = [
    0 => STDIN,
    1 => STDOUT,
    2 => STDERR
];

$process = proc_open('/bin/bash', $descriptorspec, $pipes);

if (is_resource($process)) {
    proc_close($process);
}
