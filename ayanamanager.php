<?php
session_start();
error_reporting(E_ALL & ~E_NOTICE);

// Configuration
define('FM_ROOT_PATH', $_SERVER['DOCUMENT_ROOT']);
define('FM_ROOT_URL', 'http://' . $_SERVER['HTTP_HOST']);
define('FM_SELF_URL', $_SERVER['PHP_SELF']);

// Security: Define allowed file extensions
$allowed_extensions = array('txt', 'php', 'html', 'css', 'js', 'json', 'xml', 'htaccess', 'log', 'md', 'sql');
$image_extensions = array('jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp');
$archive_extensions = array('zip', 'tar', 'gz', 'rar');

// Get current directory
$current_dir = isset($_GET['dir']) ? $_GET['dir'] : FM_ROOT_PATH;
$current_dir = realpath($current_dir);

// Security check: prevent directory traversal
if (!$current_dir || strpos($current_dir, FM_ROOT_PATH) !== 0) {
    $current_dir = FM_ROOT_PATH;
}

// Server Information Functions
function get_server_info() {
    global $current_dir;
    $info = array();
    
    // Basic PHP Info
    $info['php'] = array(
        'version' => PHP_VERSION,
        'sapi' => php_sapi_name(),
        'os' => PHP_OS,
        'architecture' => php_uname('m'),
        'server_software' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
        'document_root' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : 'Unknown',
        'max_execution_time' => ini_get('max_execution_time'),
        'memory_limit' => ini_get('memory_limit'),
        'post_max_size' => ini_get('post_max_size'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'max_file_uploads' => ini_get('max_file_uploads'),
        'date_timezone' => date_default_timezone_get(),
        'current_time' => date('Y-m-d H:i:s T')
    );
    
    // Extensions
    $info['extensions'] = array(
        'zip' => extension_loaded('zip'),
        'gd' => extension_loaded('gd'),
        'curl' => extension_loaded('curl'),
        'mbstring' => extension_loaded('mbstring'),
        'json' => extension_loaded('json'),
        'openssl' => extension_loaded('openssl'),
        'pdo' => extension_loaded('pdo'),
        'mysqli' => extension_loaded('mysqli'),
        'sqlite3' => extension_loaded('sqlite3'),
        'xml' => extension_loaded('xml'),
        'fileinfo' => extension_loaded('fileinfo'),
        'exif' => extension_loaded('exif'),
        'imagick' => extension_loaded('imagick')
    );
    
    // Disk Space
    $disk_path = $current_dir ? $current_dir : '.';
    $info['disk'] = array(
        'total_space' => disk_total_space($disk_path),
        'free_space' => disk_free_space($disk_path),
        'used_space' => disk_total_space($disk_path) - disk_free_space($disk_path)
    );
    
    // Memory Usage
    $info['memory'] = array(
        'current_usage' => memory_get_usage(true),
        'peak_usage' => memory_get_peak_usage(true),
        'limit' => ini_get('memory_limit')
    );
    
    // File System Capabilities
    $temp_dir = sys_get_temp_dir();
    $upload_tmp_dir = ini_get('upload_tmp_dir');
    if (empty($upload_tmp_dir)) {
        $upload_tmp_dir = $temp_dir;
    }
    
    $open_basedir = ini_get('open_basedir');
    if (empty($open_basedir)) {
        $open_basedir = 'Not set';
    }
    
    $info['filesystem'] = array(
        'current_dir_writable' => is_writable($current_dir ? $current_dir : '.'),
        'current_dir_readable' => is_readable($current_dir ? $current_dir : '.'),
        'temp_dir' => $temp_dir,
        'temp_dir_writable' => is_writable($temp_dir),
        'upload_tmp_dir' => $upload_tmp_dir,
        'open_basedir' => $open_basedir,
        'safe_mode' => (version_compare(PHP_VERSION, '5.4.0') < 0) ? ini_get('safe_mode') : 'Removed in PHP 5.4+'
    );
    
    // Security Settings
    $error_log = ini_get('error_log');
    if (empty($error_log)) {
        $error_log = 'Not set';
    }
    
    $info['security'] = array(
        'allow_url_fopen' => ini_get('allow_url_fopen'),
        'allow_url_include' => ini_get('allow_url_include'),
        'display_errors' => ini_get('display_errors'),
        'log_errors' => ini_get('log_errors'),
        'error_log' => $error_log,
        'expose_php' => ini_get('expose_php'),
        'register_globals' => (version_compare(PHP_VERSION, '5.4.0') < 0) ? ini_get('register_globals') : 'Removed in PHP 5.4+',
        'magic_quotes_gpc' => (version_compare(PHP_VERSION, '5.4.0') < 0) ? ini_get('magic_quotes_gpc') : 'Removed in PHP 5.4+'
    );
    
    // Server Environment
    $info['environment'] = array(
        'server_name' => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'Unknown',
        'server_port' => isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : 'Unknown',
        'https' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'request_method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'Unknown',
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown',
        'remote_addr' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown',
        'script_name' => isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : 'Unknown'
    );
    
    return $info;
}

function format_bytes($bytes, $precision = 2) {
    if ($bytes === false || $bytes === null) return 'Unknown';
    
    $units = array('B', 'KB', 'MB', 'GB', 'TB', 'PB');
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}

function parse_size($size) {
    $unit = preg_replace('/[^bkmgtpezy]/i', '', $size);
    $size = preg_replace('/[^0-9\.]/', '', $size);
    if ($unit) {
        return round($size * pow(1024, stripos('bkmgtpezy', $unit[0])));
    } else {
        return round($size);
    }
}

// Check if ZipArchive is available
function is_zip_available() {
    return class_exists('ZipArchive');
}

// Alternative zip function using system command
function create_zip_system($source, $destination) {
    if (!is_zip_available()) {
        // Try using system zip command
        $source = escapeshellarg($source);
        $destination = escapeshellarg($destination);
        $command = "cd " . escapeshellarg(dirname($source)) . " && zip -r $destination " . escapeshellarg(basename($source)) . " 2>&1";
        $output = array();
        $return_code = 0;
        exec($command, $output, $return_code);
        return $return_code === 0;
    }
    return false;
}

// Enhanced zip function with better error handling
function create_zip_archive($files, $zip_path, $base_path) {
    if (!is_zip_available()) {
        return array('success' => false, 'error' => 'ZipArchive extension is not available on this server');
    }
    
    $zip = new ZipArchive();
    $result = $zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    
    if ($result !== TRUE) {
        $error_messages = array(
            ZipArchive::ER_OK => 'No error',
            ZipArchive::ER_MULTIDISK => 'Multi-disk zip archives not supported',
            ZipArchive::ER_RENAME => 'Renaming temporary file failed',
            ZipArchive::ER_CLOSE => 'Closing zip archive failed',
            ZipArchive::ER_SEEK => 'Seek error',
            ZipArchive::ER_READ => 'Read error',
            ZipArchive::ER_WRITE => 'Write error',
            ZipArchive::ER_CRC => 'CRC error',
            ZipArchive::ER_ZIPCLOSED => 'Containing zip archive was closed',
            ZipArchive::ER_NOENT => 'No such file',
            ZipArchive::ER_EXISTS => 'File already exists',
            ZipArchive::ER_OPEN => 'Can not open file',
            ZipArchive::ER_TMPOPEN => 'Failure to create temporary file',
            ZipArchive::ER_ZLIB => 'Zlib error',
            ZipArchive::ER_MEMORY => 'Memory allocation failure',
            ZipArchive::ER_CHANGED => 'Entry has been changed',
            ZipArchive::ER_COMPNOTSUPP => 'Compression method not supported',
            ZipArchive::ER_EOF => 'Premature EOF',
            ZipArchive::ER_INVAL => 'Invalid argument',
            ZipArchive::ER_NOZIP => 'Not a zip archive',
            ZipArchive::ER_INTERNAL => 'Internal error',
            ZipArchive::ER_INCONS => 'Zip archive inconsistent',
            ZipArchive::ER_REMOVE => 'Can not remove file',
            ZipArchive::ER_DELETED => 'Entry has been deleted'
        );
        
        $error_msg = isset($error_messages[$result]) ? $error_messages[$result] : 'Unknown error';
        return array('success' => false, 'error' => "Cannot create zip file: $error_msg (Code: $result)");
    }
    
    $added_files = 0;
    
    foreach ($files as $file) {
        $file_path = $base_path . '/' . $file;
        
        if (!file_exists($file_path)) {
            continue;
        }
        
        if (is_dir($file_path)) {
            // Add directory recursively
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($file_path, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ($iterator as $item) {
                $item_path = $item->getRealPath();
                $relative_path = $file . '/' . substr($item_path, strlen($file_path) + 1);
                
                if ($item->isDir()) {
                    $zip->addEmptyDir($relative_path);
                } else {
                    if ($zip->addFile($item_path, $relative_path)) {
                        $added_files++;
                    }
                }
            }
        } else {
            // Add single file
            if ($zip->addFile($file_path, $file)) {
                $added_files++;
            }
        }
    }
    
    $close_result = $zip->close();
    
    if (!$close_result) {
        return array('success' => false, 'error' => 'Failed to close zip archive');
    }
    
    return array('success' => true, 'files_added' => $added_files);
}

// Handle AJAX requests
if (isset($_GET['ajax']) && $_GET['ajax'] == '1') {
    header('Content-Type: application/json');
    
    $action = isset($_POST['action']) ? $_POST['action'] : (isset($_GET['action']) ? $_GET['action'] : '');
    $response = array('success' => false, 'message' => '', 'progress' => 0);
    
    try {
        switch ($action) {
            case 'get_server_info':
                $server_info = get_server_info();
                $response['success'] = true;
                $response['data'] = $server_info;
                break;
                
            case 'check_zip_support':
                $response['success'] = true;
                $response['zip_available'] = is_zip_available();
                $response['message'] = is_zip_available() ? 'ZipArchive is available' : 'ZipArchive is not available';
                break;
                
            case 'bulk_delete_progress':
                $selected_files = isset($_POST['selected_files']) ? $_POST['selected_files'] : array();
                $total_files = count($selected_files);
                $deleted_count = 0;
                $errors = array();
                
                foreach ($selected_files as $index => $filename) {
                    if (file_exists($current_dir . '/' . $filename)) {
                        if (is_dir($current_dir . '/' . $filename)) {
                            if (rmdir($current_dir . '/' . $filename)) {
                                $deleted_count++;
                            } else {
                                $errors[] = "Failed to delete folder '$filename' (folder must be empty)";
                            }
                        } else {
                            if (unlink($current_dir . '/' . $filename)) {
                                $deleted_count++;
                            } else {
                                $errors[] = "Failed to delete file '$filename'";
                            }
                        }
                    }
                    
                    // Send progress update
                    $progress = (($index + 1) / $total_files) * 100;
                    if ($index < $total_files - 1) {
                        echo json_encode(array(
                            'success' => true,
                            'progress' => $progress,
                            'current_file' => $filename,
                            'completed' => $index + 1,
                            'total' => $total_files
                        )) . "\n";
                        flush();
                        usleep(100000); // Small delay to show progress
                    }
                }
                
                $response['success'] = true;
                $response['progress'] = 100;
                $response['message'] = "Successfully deleted $deleted_count item(s)";
                if (!empty($errors)) {
                    $response['errors'] = $errors;
                }
                break;
                
            case 'bulk_zip_progress':
                $selected_files = isset($_POST['selected_files']) ? $_POST['selected_files'] : array();
                $zip_name = isset($_POST['zip_name']) ? $_POST['zip_name'] : 'bulk_archive';
                $total_files = count($selected_files);
                
                if (empty($selected_files)) {
                    $response['message'] = 'No files selected';
                    break;
                }
                
                if (!is_zip_available()) {
                    $response['message'] = 'ZipArchive extension is not available on this server. Please contact your hosting provider.';
                    break;
                }
                
                $zip_path = $current_dir . '/' . $zip_name . '.zip';
                
                // Check if we can write to the directory
                if (!is_writable($current_dir)) {
                    $response['message'] = 'Cannot write to directory. Check permissions.';
                    break;
                }
                
                $result = create_zip_archive($selected_files, $zip_path, $current_dir);
                
                if ($result['success']) {
                    $response['success'] = true;
                    $response['progress'] = 100;
                    $response['message'] = "Created bulk archive: $zip_name.zip with " . $result['files_added'] . " file(s)";
                } else {
                    $response['message'] = $result['error'];
                }
                break;

            case 'upload_progress':
                // This would be used for real-time upload progress
                // For now, we'll simulate progress
                $response['success'] = true;
                $response['progress'] = 100;
                $response['message'] = 'Upload completed';
                break;
        }
    } catch (Exception $e) {
        $response['success'] = false;
        $response['message'] = 'Error: ' . $e->getMessage();
    }
    
    echo json_encode($response);
    exit;
}

// Handle regular form submissions
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && !isset($_GET['ajax'])) {
    $action = isset($_POST['action']) ? $_POST['action'] : '';
    
    try {
        switch ($action) {
            case 'create_file':
                $filename = isset($_POST['filename']) ? $_POST['filename'] : '';
                if ($filename && !file_exists($current_dir . '/' . $filename)) {
                    if (file_put_contents($current_dir . '/' . $filename, '')) {
                        $message = "File '$filename' created successfully!";
                    } else {
                        $error = "Failed to create file '$filename'";
                    }
                } else {
                    $error = "File already exists or invalid filename";
                }
                break;
                
            case 'create_folder':
                $foldername = isset($_POST['foldername']) ? $_POST['foldername'] : '';
                if ($foldername && !file_exists($current_dir . '/' . $foldername)) {
                    if (mkdir($current_dir . '/' . $foldername, 0755)) {
                        $message = "Folder '$foldername' created successfully!";
                    } else {
                        $error = "Failed to create folder '$foldername'";
                    }
                } else {
                    $error = "Folder already exists or invalid folder name";
                }
                break;
                
            case 'save_file':
                $filename = isset($_POST['filename']) ? $_POST['filename'] : '';
                $content = isset($_POST['content']) ? $_POST['content'] : '';
                if ($filename && file_exists($current_dir . '/' . $filename)) {
                    if (file_put_contents($current_dir . '/' . $filename, $content) !== false) {
                        $message = "File '$filename' saved successfully!";
                    } else {
                        $error = "Failed to save file '$filename'";
                    }
                }
                break;
                
            case 'rename':
                $old_name = isset($_POST['old_name']) ? $_POST['old_name'] : '';
                $new_name = isset($_POST['new_name']) ? $_POST['new_name'] : '';
                if ($old_name && $new_name && file_exists($current_dir . '/' . $old_name)) {
                    if (rename($current_dir . '/' . $old_name, $current_dir . '/' . $new_name)) {
                        $message = "Renamed '$old_name' to '$new_name' successfully!";
                    } else {
                        $error = "Failed to rename '$old_name'";
                    }
                }
                break;
                
            case 'delete':
                $filename = isset($_POST['filename']) ? $_POST['filename'] : '';
                if ($filename && file_exists($current_dir . '/' . $filename)) {
                    if (is_dir($current_dir . '/' . $filename)) {
                        if (rmdir($current_dir . '/' . $filename)) {
                            $message = "Folder '$filename' deleted successfully!";
                        } else {
                            $error = "Failed to delete folder '$filename' (folder must be empty)";
                        }
                    } else {
                        if (unlink($current_dir . '/' . $filename)) {
                            $message = "File '$filename' deleted successfully!";
                        } else {
                            $error = "Failed to delete file '$filename'";
                        }
                    }
                }
                break;
                
            case 'upload':
                $uploaded_files = array();
                $errors = array();
                
                // Handle multiple files upload
                if (isset($_FILES['upload_files']) && is_array($_FILES['upload_files']['name'])) {
                    $file_count = count($_FILES['upload_files']['name']);
                    
                    for ($i = 0; $i < $file_count; $i++) {
                        if ($_FILES['upload_files']['error'][$i] == 0) {
                            $filename = $_FILES['upload_files']['name'][$i];
                            $tmp_name = $_FILES['upload_files']['tmp_name'][$i];
                            $file_size = $_FILES['upload_files']['size'][$i];
                            
                            // Check file size
                            $max_size = parse_size(ini_get('upload_max_filesize'));
                            if ($file_size > $max_size) {
                                $errors[] = "File '$filename' is too large (" . format_bytes($file_size) . " > " . format_bytes($max_size) . ")";
                                continue;
                            }
                            
                            // Handle duplicate filenames
                            $target_path = $current_dir . '/' . $filename;
                            $original_filename = $filename;
                            $counter = 1;
                            
                            while (file_exists($target_path)) {
                                $file_info = pathinfo($original_filename);
                                $name = $file_info['filename'];
                                $ext = isset($file_info['extension']) ? '.' . $file_info['extension'] : '';
                                $filename = $name . '_' . $counter . $ext;
                                $target_path = $current_dir . '/' . $filename;
                                $counter++;
                            }
                            
                            if (move_uploaded_file($tmp_name, $target_path)) {
                                $uploaded_files[] = $filename;
                            } else {
                                $errors[] = "Failed to upload file '$filename'";
                            }
                        } else {
                            $filename = $_FILES['upload_files']['name'][$i];
                            $errors[] = "Upload error for file '$filename': Error code " . $_FILES['upload_files']['error'][$i];
                        }
                    }
                }
                // Handle single file upload (fallback)
                elseif (isset($_FILES['upload_files']) && $_FILES['upload_files']['error'] == 0) {
                    $filename = $_FILES['upload_files']['name'];
                    $tmp_name = $_FILES['upload_files']['tmp_name'];
                    $file_size = $_FILES['upload_files']['size'];
                    
                    $max_size = parse_size(ini_get('upload_max_filesize'));
                    if ($file_size <= $max_size) {
                        $target_path = $current_dir . '/' . $filename;
                        $original_filename = $filename;
                        $counter = 1;
                        
                        while (file_exists($target_path)) {
                            $file_info = pathinfo($original_filename);
                            $name = $file_info['filename'];
                            $ext = isset($file_info['extension']) ? '.' . $file_info['extension'] : '';
                            $filename = $name . '_' . $counter . $ext;
                            $target_path = $current_dir . '/' . $filename;
                            $counter++;
                        }
                        
                        if (move_uploaded_file($tmp_name, $target_path)) {
                            $uploaded_files[] = $filename;
                        } else {
                            $errors[] = "Failed to upload file '$filename'";
                        }
                    } else {
                        $errors[] = "File '$filename' is too large";
                    }
                } else {
                    $errors[] = "No files were uploaded or upload error occurred";
                }
                
                // Set response messages
                if (!empty($uploaded_files)) {
                    $message = "Successfully uploaded " . count($uploaded_files) . " file(s): " . implode(', ', $uploaded_files);
                }
                
                if (!empty($errors)) {
                    $error = implode('<br>', $errors);
                }
                
                if (empty($uploaded_files) && empty($errors)) {
                    $error = "No files were uploaded";
                }
                break;
                
            case 'zip':
                $filename = isset($_POST['filename']) ? $_POST['filename'] : '';
                if (!$filename || !file_exists($current_dir . '/' . $filename)) {
                    $error = "File or folder not found";
                    break;
                }
                
                if (!is_zip_available()) {
                    $error = "ZipArchive extension is not available on this server. Please contact your hosting provider.";
                    break;
                }
                
                if (!is_writable($current_dir)) {
                    $error = "Cannot write to directory. Check permissions.";
                    break;
                }
                
                $zip_path = $current_dir . '/' . $filename . '.zip';
                $result = create_zip_archive(array($filename), $zip_path, $current_dir);
                
                if ($result['success']) {
                    $message = "Created zip file: $filename.zip with " . $result['files_added'] . " file(s)";
                } else {
                    $error = $result['error'];
                }
                break;
                
            case 'unzip':
                $filename = isset($_POST['filename']) ? $_POST['filename'] : '';
                if ($filename && file_exists($current_dir . '/' . $filename) && pathinfo($filename, PATHINFO_EXTENSION) == 'zip') {
                    if (!is_zip_available()) {
                        $error = "ZipArchive extension is not available on this server";
                        break;
                    }
                    
                    $zip = new ZipArchive();
                    $result = $zip->open($current_dir . '/' . $filename);
                    
                    if ($result === TRUE) {
                        $extract_to = $current_dir . '/' . pathinfo($filename, PATHINFO_FILENAME);
                        if (!file_exists($extract_to)) {
                            mkdir($extract_to, 0755);
                        }
                        
                        if ($zip->extractTo($extract_to)) {
                            $zip->close();
                            $message = "Extracted zip file: $filename";
                        } else {
                            $zip->close();
                            $error = "Failed to extract zip file";
                        }
                    } else {
                        $error = "Failed to open zip file: $filename";
                    }
                } else {
                    $error = "Invalid zip file";
                }
                break;
        }
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
    }
}

// Handle file editing
$edit_file = '';
$edit_content = '';
if (isset($_GET['edit']) && file_exists($current_dir . '/' . $_GET['edit'])) {
    $edit_file = $_GET['edit'];
    $edit_content = file_get_contents($current_dir . '/' . $edit_file);
}

// Get directory contents
function get_directory_contents($dir) {
    $items = array();
    if (is_dir($dir) && $handle = opendir($dir)) {
        while (false !== ($entry = readdir($handle))) {
            if ($entry != "." && $entry != "..") {
                $items[] = $entry;
            }
        }
        closedir($handle);
    }
    sort($items);
    return $items;
}

// Format file size
function format_size($size) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    return round($size, 2) . ' ' . $units[$i];
}

// Get file permissions
function get_permissions($file) {
    $perms = fileperms($file);
    $info = '';
    
    // File type
    if (($perms & 0xC000) == 0xC000) $info = 's'; // Socket
    elseif (($perms & 0xA000) == 0xA000) $info = 'l'; // Symbolic Link
    elseif (($perms & 0x8000) == 0x8000) $info = '-'; // Regular
    elseif (($perms & 0x6000) == 0x6000) $info = 'b'; // Block special
    elseif (($perms & 0x4000) == 0x4000) $info = 'd'; // Directory
    elseif (($perms & 0x2000) == 0x2000) $info = 'c'; // Character special
    elseif (($perms & 0x1000) == 0x1000) $info = 'p'; // FIFO pipe
    else $info = 'u'; // Unknown
    
    // Owner
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x' ) : (($perms & 0x0800) ? 'S' : '-'));
    
    // Group
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x' ) : (($perms & 0x0400) ? 'S' : '-'));
    
    // World
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x' ) : (($perms & 0x0200) ? 'T' : '-'));
    
    return $info;
}

$items = get_directory_contents($current_dir);
$server_info = get_server_info();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ayana MINI</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 24px;
            margin-bottom: 10px;
        }
        
        .current-dir {
            background: rgba(255,255,255,0.2);
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            word-break: break-all;
        }
        
        .system-info {
            background: rgba(255,255,255,0.1);
            padding: 8px;
            border-radius: 5px;
            font-size: 12px;
            margin-top: 10px;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .system-info .info-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .server-info-panel {
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .server-info-header {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s;
        }
        
        .server-info-header:hover {
            background: linear-gradient(135deg, #218838, #1ea085);
        }
        
        .server-info-content {
            display: none;
            padding: 20px;
        }
        
        .server-info-content.show {
            display: block;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .info-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            border-left: 4px solid #007bff;
        }
        
        .info-section h4 {
            color: #495057;
            margin-bottom: 10px;
            font-size: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .info-table {
            width: 100%;
            font-size: 13px;
        }
        
        .info-table tr {
            border-bottom: 1px solid #dee2e6;
        }
        
        .info-table td {
            padding: 5px 0;
            vertical-align: top;
        }
        
        .info-table td:first-child {
            font-weight: 500;
            color: #495057;
            width: 40%;
        }
        
        .info-table td:last-child {
            color: #6c757d;
            font-family: monospace;
            font-size: 12px;
        }
        
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 5px;
        }
        
        .status-ok {
            background-color: #28a745;
        }
        
        .status-warning {
            background-color: #ffc107;
        }
        
        .status-error {
            background-color: #dc3545;
        }
        
        .progress-bar-mini {
            background: #e9ecef;
            border-radius: 3px;
            height: 6px;
            overflow: hidden;
            margin-top: 3px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            transition: width 0.3s ease;
        }
        
        .actions {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .action-group {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn:hover {
            background: #45a049;
        }
        
        .btn:disabled {
            background: #cccccc;
            cursor: not-allowed;
        }
        
        .btn-danger {
            background: #f44336;
        }
        
        .btn-danger:hover {
            background: #da190b;
        }
        
        .btn-warning {
            background: #ff9800;
        }
        
        .btn-warning:hover {
            background: #e68900;
        }
        
        .btn-info {
            background: #2196F3;
        }
        
        .btn-info:hover {
            background: #0b7dda;
        }
        
        input[type="text"], input[type="file"], textarea {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .file-list {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .file-item {
            display: flex;
            align-items: center;
            padding: 12px 20px;
            border-bottom: 1px solid #eee;
            transition: background 0.3s;
        }
        
        .file-item:hover {
            background: #f8f9fa;
        }
        
        .file-item:last-child {
            border-bottom: none;
        }
        
        .file-icon {
            width: 24px;
            height: 24px;
            margin-right: 12px;
            flex-shrink: 0;
        }
        
        .file-info {
            flex: 1;
            min-width: 0;
        }
        
        .file-name {
            font-weight: 500;
            margin-bottom: 4px;
            word-break: break-word;
        }
        
        .file-details {
            font-size: 12px;
            color: #666;
            font-family: monospace;
        }
        
        .file-actions {
            display: flex;
            gap: 5px;
            flex-shrink: 0;
        }
        
        .file-actions .btn {
            padding: 4px 8px;
            font-size: 12px;
        }
        
        .message {
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .editor {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .editor textarea {
            width: 100%;
            height: 400px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            resize: vertical;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 20px;
            border-radius: 10px;
            width: 90%;
            max-width: 500px;
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: black;
        }

        .bulk-actions {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: none;
        }

        .bulk-actions.show {
            display: block;
        }

        .bulk-actions h4 {
            margin-bottom: 10px;
            color: #856404;
        }

        .bulk-counter {
            font-weight: bold;
            color: #856404;
        }

        .select-all-container {
            background: white;
            padding: 15px 20px;
            border-bottom: 2px solid #eee;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .select-all-container input[type="checkbox"] {
            transform: scale(1.2);
        }

        .file-checkbox {
            margin-right: 12px;
            transform: scale(1.1);
        }

        .file-item.selected {
            background-color: #e3f2fd;
        }

        .bulk-zip-input {
            margin: 10px 0;
        }

        .bulk-zip-input input {
            width: 200px;
            margin-right: 10px;
        }

        /* Progress Bar Styles */
        .progress-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 2000;
            justify-content: center;
            align-items: center;
        }

        .progress-overlay.show {
            display: flex;
        }

        .progress-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            min-width: 400px;
            max-width: 90vw;
        }

        .progress-header {
            text-align: center;
            margin-bottom: 20px;
        }

        .progress-header h3 {
            color: #333;
            margin-bottom: 10px;
        }

        .progress-status {
            color: #666;
            font-size: 14px;
        }

        .progress-bar-container {
            background: #f0f0f0;
            border-radius: 10px;
            height: 20px;
            margin: 20px 0;
            overflow: hidden;
            position: relative;
        }

        .progress-bar {
            background: linear-gradient(90deg, #4CAF50, #45a049);
            height: 100%;
            width: 0%;
            transition: width 0.3s ease;
            border-radius: 10px;
            position: relative;
        }

        .progress-bar::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            background-image: linear-gradient(
                -45deg,
                rgba(255, 255, 255, .2) 25%,
                transparent 25%,
                transparent 50%,
                rgba(255, 255, 255, .2) 50%,
                rgba(255, 255, 255, .2) 75%,
                transparent 75%,
                transparent
            );
            background-size: 50px 50px;
            animation: move 2s linear infinite;
        }

        @keyframes move {
            0% {
                background-position: 0 0;
            }
            100% {
                background-position: 50px 50px;
            }
        }

        .progress-percentage {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: #333;
            font-weight: bold;
            font-size: 12px;
        }

        .progress-details {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #666;
            margin-top: 10px;
        }

        .current-operation {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
            color: #495057;
            border-left: 4px solid #007bff;
        }

        .progress-cancel {
            text-align: center;
            margin-top: 20px;
        }

        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .upload-progress {
            background: white;
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
            display: none;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .upload-progress.show {
            display: block;
        }
        
/* Upload Modal Enhancements */
.upload-modal-content {
    max-width: 600px;
    width: 95%;
}

.drag-drop-area {
    border: 3px dashed #007bff;
    border-radius: 10px;
    padding: 40px 20px;
    text-align: center;
    background: #f8f9fa;
    margin: 20px 0;
    transition: all 0.3s ease;
    cursor: pointer;
    position: relative;
}

.drag-drop-area:hover {
    border-color: #0056b3;
    background: #e3f2fd;
}

.drag-drop-area.drag-over {
    border-color: #28a745;
    background: #d4edda;
    transform: scale(1.02);
}

.drag-drop-content {
    pointer-events: none;
}

.upload-icon {
    font-size: 48px;
    margin-bottom: 15px;
    opacity: 0.7;
}

.drag-drop-area h4 {
    color: #495057;
    margin-bottom: 10px;
    font-size: 18px;
}

.drag-drop-area p {
    color: #6c757d;
    margin-bottom: 20px;
}

.selected-files-container {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
}

.selected-files-container h4 {
    color: #495057;
    margin-bottom: 15px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.selected-files-list {
    max-height: 200px;
    overflow-y: auto;
    margin-bottom: 15px;
}

.selected-file-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background: white;
    border-radius: 5px;
    margin-bottom: 5px;
    border: 1px solid #dee2e6;
}

.file-info-item {
    display: flex;
    align-items: center;
    gap: 10px;
    flex: 1;
}

.file-icon-small {
    font-size: 16px;
}

.file-details-small {
    display: flex;
    flex-direction: column;
}

.file-name-small {
    font-weight: 500;
    font-size: 14px;
    color: #495057;
}

.file-size-small {
    font-size: 12px;
    color: #6c757d;
}

.remove-file-btn {
    background: #dc3545;
    color: white;
    border: none;
    border-radius: 3px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 12px;
    transition: background 0.3s;
}

.remove-file-btn:hover {
    background: #c82333;
}

.upload-actions {
    display: flex;
    gap: 10px;
    justify-content: center;
}

.upload-progress-container {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
}

.upload-progress-container h4 {
    color: #495057;
    margin-bottom: 15px;
}

.overall-progress {
    margin-bottom: 20px;
}

.progress-info {
    text-align: center;
    margin-top: 10px;
    font-size: 14px;
    color: #6c757d;
}

.individual-progress {
    max-height: 150px;
    overflow-y: auto;
}

.file-progress-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #dee2e6;
}

.file-progress-item:last-child {
    border-bottom: none;
}

.file-progress-info {
    flex: 1;
    margin-right: 15px;
}

.file-progress-name {
    font-size: 13px;
    font-weight: 500;
    color: #495057;
}

.file-progress-status {
    font-size: 11px;
    color: #6c757d;
}

.file-progress-bar {
    width: 100px;
    height: 6px;
    background: #e9ecef;
    border-radius: 3px;
    overflow: hidden;
}

.file-progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #28a745, #20c997);
    width: 0%;
    transition: width 0.3s ease;
}

.file-status-icon {
    margin-left: 10px;
    font-size: 16px;
}

/* Drag and Drop States */
.drag-drop-area.drag-active {
    border-color: #28a745;
    background: #d4edda;
}

.drag-drop-area.drag-reject {
    border-color: #dc3545;
    background: #f8d7da;
}

/* Upload Statistics */
.upload-stats {
    display: flex;
    justify-content: space-around;
    background: white;
    padding: 15px;
    border-radius: 8px;
    margin: 15px 0;
    border: 1px solid #dee2e6;
}

.upload-stat {
    text-align: center;
}

.upload-stat-number {
    font-size: 20px;
    font-weight: bold;
    color: #007bff;
}

.upload-stat-label {
    font-size: 12px;
    color: #6c757d;
    margin-top: 5px;
}

@media (max-width: 768px) {
    .upload-modal-content {
        width: 98%;
        margin: 5% auto;
    }
    
    .drag-drop-area {
        padding: 30px 15px;
    }
    
    .upload-actions {
        flex-direction: column;
    }
    
    .selected-file-item {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    
    .file-progress-item {
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
    }
    
    .file-progress-bar {
        width: 100%;
    }
}
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .action-group {
                flex-direction: column;
            }
            
            .file-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .file-actions {
                width: 100%;
                justify-content: flex-start;
            }
            
            .modal-content {
                margin: 10% auto;
                width: 95%;
            }

            .bulk-actions {
                padding: 10px;
            }
            
            .bulk-zip-input {
                display: flex;
                flex-direction: column;
                gap: 10px;
            }
            
            .bulk-zip-input input {
                width: 100%;
                margin-right: 0;
            }

            .progress-container {
                min-width: 300px;
                padding: 20px;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .system-info {
                flex-direction: column;
                gap: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗂️ Ayana MINI</h1>
            <div class="current-dir">
                (<?php echo get_permissions($current_dir); ?>) <?php echo $current_dir; ?>
            </div>
            <div class="system-info">
                <div class="info-item">
                    <span class="status-indicator <?php echo is_zip_available() ? 'status-ok' : 'status-error'; ?>"></span>
                    ZipArchive: <?php echo is_zip_available() ? 'Available' : 'Not Available'; ?>
                </div>
                <div class="info-item">
                    <span class="status-indicator <?php echo is_writable($current_dir) ? 'status-ok' : 'status-error'; ?>"></span>
                    Writable: <?php echo is_writable($current_dir) ? 'Yes' : 'No'; ?>
                </div>
                <div class="info-item">
                    <span class="status-indicator status-ok"></span>
                    PHP: <?php echo PHP_VERSION; ?>
                </div>
                <div class="info-item">
                    <span class="status-indicator status-ok"></span>
                    Memory: <?php echo format_bytes($server_info['memory']['current_usage']); ?> / <?php echo $server_info['memory']['limit']; ?>
                </div>
            </div>
        </div>

        <!-- Server Information Panel -->
        <div class="server-info-panel">
            <div class="server-info-header" onclick="toggleServerInfo()">
                <div>
                    <strong>🖥️ Server Information & Capabilities</strong>
                    <small style="opacity: 0.8; margin-left: 10px;">Click to expand detailed system information</small>
                </div>
                <span id="serverInfoToggle">▼</span>
            </div>
            <div class="server-info-content" id="serverInfoContent">
                <div class="info-grid">
                    <!-- PHP Information -->
                    <div class="info-section">
                        <h4>🐘 PHP Information</h4>
                        <table class="info-table">
                            <tr><td>Version</td><td><?php echo $server_info['php']['version']; ?></td></tr>
                            <tr><td>SAPI</td><td><?php echo $server_info['php']['sapi']; ?></td></tr>
                            <tr><td>Operating System</td><td><?php echo $server_info['php']['os']; ?></td></tr>
                            <tr><td>Architecture</td><td><?php echo $server_info['php']['architecture']; ?></td></tr>
                            <tr><td>Server Software</td><td><?php echo $server_info['php']['server_software']; ?></td></tr>
                            <tr><td>Document Root</td><td><?php echo $server_info['php']['document_root']; ?></td></tr>
                            <tr><td>Current Time</td><td><?php echo $server_info['php']['current_time']; ?></td></tr>
                            <tr><td>Timezone</td><td><?php echo $server_info['php']['date_timezone']; ?></td></tr>
                        </table>
                    </div>

                    <!-- Memory & Limits -->
                    <div class="info-section">
                        <h4>💾 Memory & Limits</h4>
                        <table class="info-table">
                            <tr><td>Memory Limit</td><td><?php echo $server_info['php']['memory_limit']; ?></td></tr>
                            <tr>
                                <td>Current Usage</td>
                                <td>
                                    <?php echo format_bytes($server_info['memory']['current_usage']); ?>
                                    <div class="progress-bar-mini">
                                        <div class="progress-fill" style="width: <?php echo min(100, ($server_info['memory']['current_usage'] / parse_size($server_info['memory']['limit'])) * 100); ?>%"></div>
                                    </div>
                                </td>
                            </tr>
                            <tr><td>Peak Usage</td><td><?php echo format_bytes($server_info['memory']['peak_usage']); ?></td></tr>
                            <tr><td>Max Execution Time</td><td><?php echo $server_info['php']['max_execution_time']; ?>s</td></tr>
                            <tr><td>Post Max Size</td><td><?php echo $server_info['php']['post_max_size']; ?></td></tr>
                            <tr><td>Upload Max Filesize</td><td><?php echo $server_info['php']['upload_max_filesize']; ?></td></tr>
                            <tr><td>Max File Uploads</td><td><?php echo $server_info['php']['max_file_uploads']; ?></td></tr>
                        </table>
                    </div>

                    <!-- Disk Space -->
                    <div class="info-section">
                        <h4>💿 Disk Space</h4>
                        <table class="info-table">
                            <tr><td>Total Space</td><td><?php echo format_bytes($server_info['disk']['total_space']); ?></td></tr>
                            <tr><td>Free Space</td><td><?php echo format_bytes($server_info['disk']['free_space']); ?></td></tr>
                            <tr>
                                <td>Used Space</td>
                                <td>
                                    <?php echo format_bytes($server_info['disk']['used_space']); ?>
                                    <div class="progress-bar-mini">
                                        <div class="progress-fill" style="width: <?php echo ($server_info['disk']['used_space'] / $server_info['disk']['total_space']) * 100; ?>%"></div>
                                    </div>
                                </td>
                            </tr>
                        </table>
                    </div>

                    <!-- Extensions -->
                    <div class="info-section">
                        <h4>🔧 PHP Extensions</h4>
                        <table class="info-table">
                            <?php foreach ($server_info['extensions'] as $ext => $loaded): ?>
                            <tr>
                                <td><?php echo ucfirst($ext); ?></td>
                                <td>
                                    <span class="status-indicator <?php echo $loaded ? 'status-ok' : 'status-error'; ?>"></span>
                                    <?php echo $loaded ? 'Loaded' : 'Not Available'; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </table>
                    </div>

                    <!-- File System -->
                    <div class="info-section">
                        <h4>📁 File System</h4>
                        <table class="info-table">
                            <tr>
                                <td>Current Dir Writable</td>
                                <td>
                                    <span class="status-indicator <?php echo $server_info['filesystem']['current_dir_writable'] ? 'status-ok' : 'status-error'; ?>"></span>
                                    <?php echo $server_info['filesystem']['current_dir_writable'] ? 'Yes' : 'No'; ?>
                                </td>
                            </tr>
                            <tr>
                                <td>Current Dir Readable</td>
                                <td>
                                    <span class="status-indicator <?php echo $server_info['filesystem']['current_dir_readable'] ? 'status-ok' : 'status-error'; ?>"></span>
                                    <?php echo $server_info['filesystem']['current_dir_readable'] ? 'Yes' : 'No'; ?>
                                </td>
                            </tr>
                            <tr><td>Temp Directory</td><td><?php echo $server_info['filesystem']['temp_dir']; ?></td></tr>
                            <tr>
                                <td>Temp Dir Writable</td>
                                <td>
                                    <span class="status-indicator <?php echo $server_info['filesystem']['temp_dir_writable'] ? 'status-ok' : 'status-error'; ?>"></span>
                                    <?php echo $server_info['filesystem']['temp_dir_writable'] ? 'Yes' : 'No'; ?>
                                </td>
                            </tr>
                            <tr><td>Upload Tmp Dir</td><td><?php echo $server_info['filesystem']['upload_tmp_dir']; ?></td></tr>
                            <tr><td>Open Basedir</td><td><?php echo $server_info['filesystem']['open_basedir']; ?></td></tr>
                            <tr><td>Safe Mode</td><td><?php echo $server_info['filesystem']['safe_mode']; ?></td></tr>
                        </table>
                    </div>

                    <!-- Security Settings -->
                    <div class="info-section">
                        <h4>🔒 Security Settings</h4>
                        <table class="info-table">
                            <tr>
                                <td>Allow URL fopen</td>
                                <td>
                                    <span class="status-indicator <?php echo $server_info['security']['allow_url_fopen'] ? 'status-warning' : 'status-ok'; ?>"></span>
                                    <?php echo $server_info['security']['allow_url_fopen'] ? 'Enabled' : 'Disabled'; ?>
                                </td>
                            </tr>
                            <tr>
                                <td>Allow URL include</td>
                                <td>
                                    <span class="status-indicator <?php echo $server_info['security']['allow_url_include'] ? 'status-error' : 'status-ok'; ?>"></span>
                                    <?php echo $server_info['security']['allow_url_include'] ? 'Enabled' : 'Disabled'; ?>
                                </td>
                            </tr>
                            <tr><td>Display Errors</td><td><?php echo $server_info['security']['display_errors'] ? 'On' : 'Off'; ?></td></tr>
                            <tr><td>Log Errors</td><td><?php echo $server_info['security']['log_errors'] ? 'On' : 'Off'; ?></td></tr>
                            <tr><td>Error Log</td><td><?php echo $server_info['security']['error_log']; ?></td></tr>
                            <tr><td>Expose PHP</td><td><?php echo $server_info['security']['expose_php'] ? 'On' : 'Off'; ?></td></tr>
                        </table>
                    </div>

                    <!-- Server Environment -->
                    <div class="info-section">
                        <h4>🌐 Server Environment</h4>
                        <table class="info-table">
                            <tr><td>Server Name</td><td><?php echo $server_info['environment']['server_name']; ?></td></tr>
                            <tr><td>Server Port</td><td><?php echo $server_info['environment']['server_port']; ?></td></tr>
                            <tr>
                                <td>HTTPS</td>
                                <td>
                                    <span class="status-indicator <?php echo $server_info['environment']['https'] ? 'status-ok' : 'status-warning'; ?>"></span>
                                    <?php echo $server_info['environment']['https'] ? 'Enabled' : 'Disabled'; ?>
                                </td>
                            </tr>
                            <tr><td>Request Method</td><td><?php echo $server_info['environment']['request_method']; ?></td></tr>
                            <tr><td>Remote Address</td><td><?php echo $server_info['environment']['remote_addr']; ?></td></tr>
                            <tr><td>Script Name</td><td><?php echo $server_info['environment']['script_name']; ?></td></tr>
                        </table>
                    </div>

                    <!-- User Agent -->
                    <div class="info-section">
                        <h4>🖥️ Client Information</h4>
                        <table class="info-table">
                            <tr><td>User Agent</td><td style="word-break: break-all;"><?php echo htmlspecialchars($server_info['environment']['user_agent']); ?></td></tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="message success"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="message error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if (!is_zip_available()): ?>
            <div class="message error">
                <strong>⚠️ Warning:</strong> ZipArchive extension is not available on this server. 
                Zip/Unzip functionality will not work. Please contact your hosting provider to enable the ZipArchive extension.
            </div>
        <?php endif; ?>

        <?php if ($edit_file): ?>
            <div class="editor">
                <h3>Editing: <?php echo htmlspecialchars($edit_file); ?></h3>
                <form method="post">
                    <input type="hidden" name="action" value="save_file">
                    <input type="hidden" name="filename" value="<?php echo htmlspecialchars($edit_file); ?>">
                    <textarea name="content"><?php echo htmlspecialchars($edit_content); ?></textarea>
                    <div style="margin-top: 10px;">
                        <button type="submit" class="btn">💾 Save File</button>
                        <a href="<?php echo FM_SELF_URL; ?>?dir=<?php echo urlencode($current_dir); ?>" class="btn btn-warning">❌ Cancel</a>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <div class="actions">
            <div class="action-group">
                <button onclick="showModal('createFileModal')" class="btn">📄 New File</button>
                <button onclick="showModal('createFolderModal')" class="btn">📁 New Folder</button>
                <button onclick="showModal('uploadModal')" class="btn btn-info">⬆️ Upload</button>
                <?php if ($current_dir != FM_ROOT_PATH): ?>
                    <a href="<?php echo FM_SELF_URL; ?>?dir=<?php echo urlencode(dirname($current_dir)); ?>" class="btn btn-warning">⬅️ Back</a>
                <?php endif; ?>
            </div>
        </div>

        <div class="bulk-actions" id="bulkActions">
            <h4>Bulk Operations (<span class="bulk-counter" id="bulkCounter">0</span> selected)</h4>
            <div class="action-group">
                <button onclick="bulkDeleteWithProgress()" class="btn btn-danger" id="bulkDeleteBtn">🗑️ Delete Selected</button>
                <button onclick="showBulkZip()" class="btn" id="bulkZipBtn" <?php echo !is_zip_available() ? 'disabled title="ZipArchive not available"' : ''; ?>>🗜️ Zip Selected</button>
                <button onclick="clearSelection()" class="btn btn-warning">❌ Clear Selection</button>
            </div>
            <div class="bulk-zip-input" id="bulkZipInput" style="display: none;">
                <input type="text" id="zipName" placeholder="Enter zip filename" value="selected_files">
                <button onclick="bulkZipWithProgress()" class="btn" id="createZipBtn">Create Zip</button>
                <button onclick="hideBulkZip()" class="btn btn-warning">Cancel</button>
            </div>
        </div>

        <div class="file-list">
            <div class="select-all-container">
                <input type="checkbox" id="selectAll" onchange="toggleSelectAll()">
                <label for="selectAll"><strong>Select All</strong></label>
                <span style="margin-left: auto; color: #666; font-size: 14px;">
                    <?php echo count($items); ?> item(s) in this directory
                </span>
            </div>
            
            <?php foreach ($items as $item): ?>
                <?php
                $item_path = $current_dir . '/' . $item;
                $is_dir = is_dir($item_path);
                $size = $is_dir ? '-' : format_size(filesize($item_path));
                $modified = date('Y-m-d H:i:s', filemtime($item_path));
                $permissions = get_permissions($item_path);
                ?>
                <div class="file-item" data-filename="<?php echo htmlspecialchars($item); ?>">
                    <input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($item); ?>" onchange="updateBulkActions()">
                    <div class="file-icon">
                        <?php if ($is_dir): ?>
                            📁
                        <?php else: ?>
                            📄
                        <?php endif; ?>
                    </div>
                    <div class="file-info">
                        <div class="file-name">
                            <?php if ($is_dir): ?>
                                <a href="<?php echo FM_SELF_URL; ?>?dir=<?php echo urlencode($item_path); ?>" style="text-decoration: none; color: #333;">
                                    <?php echo htmlspecialchars($item); ?>
                                </a>
                            <?php else: ?>
                                <?php echo htmlspecialchars($item); ?>
                            <?php endif; ?>
                        </div>
                        <div class="file-details">
                            <?php echo $permissions; ?> | <?php echo $size; ?> | <?php echo $modified; ?>
                        </div>
                    </div>
                    <div class="file-actions">
                        <?php if (!$is_dir): ?>
                            <a href="<?php echo FM_SELF_URL; ?>?dir=<?php echo urlencode($current_dir); ?>&edit=<?php echo urlencode($item); ?>" class="btn btn-info">✏️ Edit</a>
                        <?php endif; ?>
                        <button onclick="renameItem('<?php echo htmlspecialchars($item); ?>')" class="btn btn-warning">🏷️ Rename</button>
                        <button onclick="zipItemWithProgress('<?php echo htmlspecialchars($item); ?>')" class="btn" <?php echo !is_zip_available() ? 'disabled title="ZipArchive not available"' : ''; ?>>🗜️ Zip</button>
                        <?php if (pathinfo($item, PATHINFO_EXTENSION) == 'zip'): ?>
                            <button onclick="unzipItem('<?php echo htmlspecialchars($item); ?>')" class="btn btn-info" <?php echo !is_zip_available() ? 'disabled title="ZipArchive not available"' : ''; ?>>📦 Unzip</button>
                        <?php endif; ?>
                        <button onclick="deleteItem('<?php echo htmlspecialchars($item); ?>')" class="btn btn-danger">🗑️ Delete</button>
                    </div>
                </div>
            <?php endforeach; ?>
            
            <?php if (empty($items)): ?>
                <div class="file-item">
                    <div style="text-align: center; width: 100%; color: #666;">
                        📂 This directory is empty
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Progress Overlay -->
    <div class="progress-overlay" id="progressOverlay">
        <div class="progress-container">
            <div class="progress-header">
                <h3 id="progressTitle">Processing...</h3>
                <div class="progress-status" id="progressStatus">Initializing...</div>
            </div>
            
            <div class="progress-bar-container">
                <div class="progress-bar" id="progressBar"></div>
                <div class="progress-percentage" id="progressPercentage">0%</div>
            </div>
            
            <div class="progress-details">
                <span id="progressCompleted">0</span>
                <span id="progressTotal">0</span>
            </div>
            
            <div class="current-operation" id="currentOperation">
                <div class="spinner"></div>
                <span id="currentFile">Preparing...</span>
            </div>
            
            <div class="progress-cancel">
                <button onclick="cancelOperation()" class="btn btn-danger" id="cancelBtn">Cancel Operation</button>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div id="createFileModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="hideModal('createFileModal')">&times;</span>
            <h3>Create New File</h3>
            <form method="post">
                <input type="hidden" name="action" value="create_file">
                <p><input type="text" name="filename" placeholder="Enter filename" required style="width: 100%;"></p>
                <p><button type="submit" class="btn">Create File</button></p>
            </form>
        </div>
    </div>

    <div id="createFolderModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="hideModal('createFolderModal')">&times;</span>
            <h3>Create New Folder</h3>
            <form method="post">
                <input type="hidden" name="action" value="create_folder">
                <p><input type="text" name="foldername" placeholder="Enter folder name" required style="width: 100%;"></p>
                <p><button type="submit" class="btn">Create Folder</button></p>
            </form>
        </div>
    </div>

    <div id="uploadModal" class="modal">
        <div class="modal-content upload-modal-content">
            <span class="close" onclick="hideModal('uploadModal')">&times;</span>
            <h3>Upload Files</h3>
            
            <!-- Drag & Drop Area -->
            <div class="drag-drop-area" id="dragDropArea">
                <div class="drag-drop-content">
                    <div class="upload-icon">📁</div>
                    <h4>Drag & Drop Files Here</h4>
                    <p>or click to browse files</p>
                    <button type="button" class="btn btn-info" onclick="document.getElementById('uploadFiles').click()">
                        📂 Browse Files
                    </button>
                </div>
            </div>
            
            <!-- File Input (Hidden) -->
            <input type="file" id="uploadFiles" multiple style="display: none;">
            
            <!-- Selected Files List -->
            <div class="selected-files-container" id="selectedFilesContainer" style="display: none;">
                <h4>Selected Files:</h4>
                <div class="selected-files-list" id="selectedFilesList"></div>
                <div class="upload-actions">
                    <button type="button" class="btn" onclick="startUpload()" id="startUploadBtn">
                        ⬆️ Upload Files
                    </button>
                    <button type="button" class="btn btn-warning" onclick="clearSelectedFiles()">
                        🗑️ Clear All
                    </button>
                </div>
            </div>
            
            <!-- Upload Progress -->
            <div class="upload-progress-container" id="uploadProgressContainer" style="display: none;">
                <h4>Upload Progress</h4>
                <div class="overall-progress">
                    <div class="progress-bar-container">
                        <div class="progress-bar" id="overallProgressBar"></div>
                        <div class="progress-percentage" id="overallProgressPercentage">0%</div>
                    </div>
                    <div class="progress-info">
                        <span id="uploadedCount">0</span> of <span id="totalCount">0</span> files uploaded
                    </div>
                </div>
                <div class="individual-progress" id="individualProgress"></div>
            </div>
        </div>
    </div>

    <div id="renameModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="hideModal('renameModal')">&times;</span>
            <h3>Rename Item</h3>
            <form method="post">
                <input type="hidden" name="action" value="rename">
                <input type="hidden" name="old_name" id="rename_old_name">
                <p><input type="text" name="new_name" id="rename_new_name" placeholder="Enter new name" required style="width: 100%;"></p>
                <p><button type="submit" class="btn">Rename</button></p>
            </form>
        </div>
    </div>

    <script>
        // Global variables - declare at the top to avoid initialization errors
        var selectedFiles = [];
        var uploadQueue = [];
        var currentUploadIndex = 0;
        var currentOperation = null;
        var operationCancelled = false;

        function toggleServerInfo() {
            const content = document.getElementById('serverInfoContent');
            const toggle = document.getElementById('serverInfoToggle');
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                toggle.textContent = '▼';
            } else {
                content.classList.add('show');
                toggle.textContent = '▲';
            }
        }

        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'block';
                if (modalId === 'uploadModal') {
                    // Reset the modal state
                    clearSelectedFiles();
                    const progressContainer = document.getElementById('uploadProgressContainer');
                    if (progressContainer) {
                        progressContainer.style.display = 'none';
                    }
                    const startBtn = document.getElementById('startUploadBtn');
                    if (startBtn) {
                        startBtn.disabled = false;
                    }
                    
                    // Initialize drag and drop after modal is shown
                    setTimeout(function() {
                        initializeDragDrop();
                        
                        // Add event listener for file input
                        const fileInput = document.getElementById('uploadFiles');
                        if (fileInput) {
                            fileInput.addEventListener('change', function(e) {
                                console.log('File input changed:', e.target.files.length, 'files');
                                handleMultipleFileSelect(e.target.files);
                            });
                        }
                    }, 100);
                }
            }
        }

        function hideModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
                if (modalId === 'uploadModal') {
                    clearSelectedFiles();
                    const progressContainer = document.getElementById('uploadProgressContainer');
                    if (progressContainer) {
                        progressContainer.style.display = 'none';
                    }
                    const startBtn = document.getElementById('startUploadBtn');
                    if (startBtn) {
                        startBtn.disabled = false;
                    }
                }
            }
        }

        function showProgress(title, status) {
            status = status || 'Initializing...';
            document.getElementById('progressTitle').textContent = title;
            document.getElementById('progressStatus').textContent = status;
            document.getElementById('progressBar').style.width = '0%';
            document.getElementById('progressPercentage').textContent = '0%';
            document.getElementById('progressCompleted').textContent = '0';
            document.getElementById('progressTotal').textContent = '0';
            document.getElementById('currentFile').textContent = 'Preparing...';
            document.getElementById('progressOverlay').classList.add('show');
            operationCancelled = false;
        }

        function hideProgress() {
            document.getElementById('progressOverlay').classList.remove('show');
            currentOperation = null;
        }

        function updateProgress(progress, currentFile, completed, total) {
            if (operationCancelled) return;
            
            document.getElementById('progressBar').style.width = progress + '%';
            document.getElementById('progressPercentage').textContent = Math.round(progress) + '%';
            
            if (currentFile) {
                document.getElementById('currentFile').textContent = currentFile;
            }
            
            if (total > 0) {
                document.getElementById('progressCompleted').textContent = completed;
                document.getElementById('progressTotal').textContent = total;
            }
        }

        function cancelOperation() {
            operationCancelled = true;
            if (currentOperation) {
                currentOperation.abort();
            }
            hideProgress();
            location.reload();
        }

        function renameItem(oldName) {
            document.getElementById('rename_old_name').value = oldName;
            document.getElementById('rename_new_name').value = oldName;
            showModal('renameModal');
        }

        function deleteItem(filename) {
            if (confirm('Are you sure you want to delete "' + filename + '"?')) {
                var form = document.createElement('form');
                form.method = 'post';
                form.innerHTML = '<input type="hidden" name="action" value="delete"><input type="hidden" name="filename" value="' + filename + '">';
                document.body.appendChild(form);
                form.submit();
            }
        }

        function zipItemWithProgress(filename) {
            <?php if (!is_zip_available()): ?>
                alert('ZipArchive extension is not available on this server. Please contact your hosting provider.');
                return;
            <?php endif; ?>
            
            if (confirm('Create zip archive for "' + filename + '"?')) {
                var form = document.createElement('form');
                form.method = 'post';
                form.innerHTML = '<input type="hidden" name="action" value="zip"><input type="hidden" name="filename" value="' + filename + '">';
                document.body.appendChild(form);
                form.submit();
            }
        }

        function unzipItem(filename) {
            <?php if (!is_zip_available()): ?>
                alert('ZipArchive extension is not available on this server. Please contact your hosting provider.');
                return;
            <?php endif; ?>
            
            if (confirm('Extract zip archive "' + filename + '"?')) {
                var form = document.createElement('form');
                form.method = 'post';
                form.innerHTML = '<input type="hidden" name="action" value="unzip"><input type="hidden" name="filename" value="' + filename + '">';
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Bulk operations functions
        function toggleSelectAll() {
            const selectAllCheckbox = document.getElementById('selectAll');
            const fileCheckboxes = document.querySelectorAll('.file-checkbox');
            
            fileCheckboxes.forEach(function(checkbox) {
                checkbox.checked = selectAllCheckbox.checked;
            });
            
            updateBulkActions();
        }

        function updateBulkActions() {
            const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
            const bulkActions = document.getElementById('bulkActions');
            const bulkCounter = document.getElementById('bulkCounter');
            const selectAllCheckbox = document.getElementById('selectAll');
            const allCheckboxes = document.querySelectorAll('.file-checkbox');
            
            // Update counter
            bulkCounter.textContent = selectedCheckboxes.length;
            
            // Show/hide bulk actions
            if (selectedCheckboxes.length > 0) {
                bulkActions.classList.add('show');
            } else {
                bulkActions.classList.remove('show');
                hideBulkZip();
            }
            
            // Update select all checkbox state
            if (selectedCheckboxes.length === 0) {
                selectAllCheckbox.indeterminate = false;
                selectAllCheckbox.checked = false;
            } else if (selectedCheckboxes.length === allCheckboxes.length) {
                selectAllCheckbox.indeterminate = false;
                selectAllCheckbox.checked = true;
            } else {
                selectAllCheckbox.indeterminate = true;
            }
            
            // Update file item styling
            document.querySelectorAll('.file-item').forEach(function(item) {
                const checkbox = item.querySelector('.file-checkbox');
                if (checkbox && checkbox.checked) {
                    item.classList.add('selected');
                } else {
                    item.classList.remove('selected');
                }
            });
        }

        function getSelectedFiles() {
            const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
            return Array.from(selectedCheckboxes).map(function(cb) { return cb.value; });
        }

        function bulkDeleteWithProgress() {
            const selectedFiles = getSelectedFiles();
            if (selectedFiles.length === 0) {
                alert('Please select files to delete');
                return;
            }
            
            if (confirm('Are you sure you want to delete ' + selectedFiles.length + ' selected item(s)?')) {
                showProgress('Deleting Files', 'Deleting ' + selectedFiles.length + ' item(s)...');
                
                const formData = new FormData();
                formData.append('action', 'bulk_delete_progress');
                selectedFiles.forEach(function(filename) {
                    formData.append('selected_files[]', filename);
                });
                
                currentOperation = fetch(window.location.href + '?ajax=1', {
                    method: 'POST',
                    body: formData
                });
                
                currentOperation
                    .then(function(response) { return response.json(); })
                    .then(function(data) {
                        if (data.success) {
                            updateProgress(100, 'Completed', selectedFiles.length, selectedFiles.length);
                            setTimeout(function() {
                                hideProgress();
                                location.reload();
                            }, 1000);
                        } else {
                            alert('Error: ' + data.message);
                            hideProgress();
                        }
                    })
                    .catch(function(error) {
                        if (!operationCancelled) {
                            console.error('Error:', error);
                            alert('An error occurred during the operation: ' + error.message);
                        }
                        hideProgress();
                    });
            }
        }

        function showBulkZip() {
            const selectedFiles = getSelectedFiles();
            if (selectedFiles.length === 0) {
                alert('Please select files to zip');
                return;
            }
            
            <?php if (!is_zip_available()): ?>
                alert('ZipArchive extension is not available on this server. Please contact your hosting provider.');
                return;
            <?php endif; ?>
            
            document.getElementById('bulkZipInput').style.display = 'block';
        }

        function hideBulkZip() {
            document.getElementById('bulkZipInput').style.display = 'none';
        }

        function bulkZipWithProgress() {
            const selectedFiles = getSelectedFiles();
            const zipName = document.getElementById('zipName').value.trim();
            
            if (selectedFiles.length === 0) {
                alert('Please select files to zip');
                return;
            }
            
            if (!zipName) {
                alert('Please enter a zip filename');
                return;
            }
            
            <?php if (!is_zip_available()): ?>
                alert('ZipArchive extension is not available on this server. Please contact your hosting provider.');
                return;
            <?php endif; ?>
            
            showProgress('Creating Bulk Archive', 'Creating ' + zipName + '.zip with ' + selectedFiles.length + ' item(s)...');
            
            const formData = new FormData();
            formData.append('action', 'bulk_zip_progress');
            formData.append('zip_name', zipName);
            selectedFiles.forEach(function(filename) {
                formData.append('selected_files[]', filename);
            });
            
            currentOperation = fetch(window.location.href + '?ajax=1', {
                method: 'POST',
                body: formData
            });
            
            currentOperation
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('HTTP error! status: ' + response.status);
                    }
                    return response.json();
                })
                .then(function(data) {
                    if (data.success) {
                        updateProgress(100, 'Archive created successfully', selectedFiles.length, selectedFiles.length);
                        setTimeout(function() {
                            hideProgress();
                            location.reload();
                        }, 1000);
                    } else {
                        alert('Error: ' + data.message);
                        hideProgress();
                    }
                })
                .catch(function(error) {
                    if (!operationCancelled) {
                        console.error('Error:', error);
                        alert('An error occurred during the operation: ' + error.message);
                    }
                    hideProgress();
                });
        }

        function clearSelection() {
            document.querySelectorAll('.file-checkbox').forEach(function(checkbox) {
                checkbox.checked = false;
            });
            document.getElementById('selectAll').checked = false;
            updateBulkActions();
        }

        // Drag and Drop Event Handlers
        function initializeDragDrop() {
            const dragDropArea = document.getElementById('dragDropArea');
            
            if (!dragDropArea) return;
            
            // Remove existing event listeners to prevent duplicates
            dragDropArea.replaceWith(dragDropArea.cloneNode(true));
            const newDragDropArea = document.getElementById('dragDropArea');
            
            // Prevent default drag behaviors
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(function(eventName) {
                newDragDropArea.addEventListener(eventName, preventDefaults, false);
                document.body.addEventListener(eventName, preventDefaults, false);
            });
            
            // Highlight drop area when item is dragged over it
            ['dragenter', 'dragover'].forEach(function(eventName) {
                newDragDropArea.addEventListener(eventName, highlight, false);
            });
            
            ['dragleave', 'drop'].forEach(function(eventName) {
                newDragDropArea.addEventListener(eventName, unhighlight, false);
            });
            
            // Handle dropped files
            newDragDropArea.addEventListener('drop', handleDrop, false);
            
            // Handle click to browse
            newDragDropArea.addEventListener('click', function(e) {
                e.preventDefault();
                document.getElementById('uploadFiles').click();
            });
        }

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        function highlight(e) {
            document.getElementById('dragDropArea').classList.add('drag-over');
        }

        function unhighlight(e) {
            document.getElementById('dragDropArea').classList.remove('drag-over');
        }

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleMultipleFileSelect(files);
        }

        function handleMultipleFileSelect(files) {
            console.log('Files selected:', files.length);
            
            if (!files || files.length === 0) {
                console.log('No files selected');
                return;
            }
            
            // Convert FileList to Array and add to selectedFiles
            const newFiles = Array.from(files);
            console.log('Processing files:', newFiles.map(function(f) { return f.name; }));
            
            // Check for duplicates and add unique files
            newFiles.forEach(function(file) {
                const isDuplicate = selectedFiles.some(function(existingFile) {
                    return existingFile.name === file.name && existingFile.size === file.size;
                });
                
                if (!isDuplicate) {
                    selectedFiles.push(file);
                }
            });
            
            console.log('Total selected files:', selectedFiles.length);
            updateSelectedFilesList();
            showSelectedFilesContainer();
        }

        function updateSelectedFilesList() {
            const container = document.getElementById('selectedFilesList');
            if (!container) return;
            
            container.innerHTML = '';
            
            selectedFiles.forEach(function(file, index) {
                const fileItem = document.createElement('div');
                fileItem.className = 'selected-file-item';
                fileItem.innerHTML = 
                    '<div class="file-info-item">' +
                        '<span class="file-icon-small">' + getFileIcon(file.name) + '</span>' +
                        '<div class="file-details-small">' +
                            '<div class="file-name-small">' + file.name + '</div>' +
                            '<div class="file-size-small">' + formatBytes(file.size) + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<button class="remove-file-btn" onclick="removeSelectedFile(' + index + ')">✕</button>';
                container.appendChild(fileItem);
            });
        }

        function getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'];
            const archiveExts = ['zip', 'rar', 'tar', 'gz', '7z'];
            const codeExts = ['php', 'js', 'html', 'css', 'json', 'xml'];
            
            if (imageExts.includes(ext)) return '🖼️';
            if (archiveExts.includes(ext)) return '📦';
            if (codeExts.includes(ext)) return '📝';
            return '📄';
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function removeSelectedFile(index) {
            selectedFiles.splice(index, 1);
            updateSelectedFilesList();
            
            if (selectedFiles.length === 0) {
                hideSelectedFilesContainer();
            }
        }

        function clearSelectedFiles() {
            selectedFiles = [];
            hideSelectedFilesContainer();
            const fileInput = document.getElementById('uploadFiles');
            if (fileInput) {
                fileInput.value = '';
            }
        }

        function showSelectedFilesContainer() {
            const container = document.getElementById('selectedFilesContainer');
            if (container) {
                container.style.display = 'block';
            }
        }

        function hideSelectedFilesContainer() {
            const container = document.getElementById('selectedFilesContainer');
            if (container) {
                container.style.display = 'none';
            }
        }

        function startUpload() {
            console.log('Starting upload for', selectedFiles.length, 'files');
            
            if (selectedFiles.length === 0) {
                alert('Please select files to upload');
                return;
            }
            
            // Show progress container
            const progressContainer = document.getElementById('uploadProgressContainer');
            if (progressContainer) {
                progressContainer.style.display = 'block';
            }
            
            const startBtn = document.getElementById('startUploadBtn');
            if (startBtn) {
                startBtn.disabled = true;
            }
            
            // Initialize progress
            uploadQueue = selectedFiles.slice(); // Create a copy
            currentUploadIndex = 0;
            
            document.getElementById('totalCount').textContent = uploadQueue.length;
            document.getElementById('uploadedCount').textContent = '0';
            
            // Create individual progress items
            createIndividualProgressItems();
            
            // Start uploading files
            uploadNextFile();
        }

        function createIndividualProgressItems() {
            const container = document.getElementById('individualProgress');
            if (!container) return;
            
            container.innerHTML = '';
            
            uploadQueue.forEach(function(file, index) {
                const progressItem = document.createElement('div');
                progressItem.className = 'file-progress-item';
                progressItem.id = 'progress-item-' + index;
                progressItem.innerHTML = 
                    '<div class="file-progress-info">' +
                        '<div class="file-progress-name">' + file.name + '</div>' +
                        '<div class="file-progress-status">Waiting...</div>' +
                    '</div>' +
                    '<div class="file-progress-bar">' +
                        '<div class="file-progress-fill" id="progress-fill-' + index + '"></div>' +
                    '</div>' +
                    '<div class="file-status-icon" id="status-icon-' + index + '">⏳</div>';
                container.appendChild(progressItem);
            });
        }

        function uploadNextFile() {
            if (currentUploadIndex >= uploadQueue.length) {
                // All files uploaded
                completeUpload();
                return;
            }
            
            const file = uploadQueue[currentUploadIndex];
            const formData = new FormData();
            
            console.log('Uploading file:', file.name);
            
            // Create proper FormData for PHP
            formData.append('action', 'upload');
            formData.append('upload_files[]', file);
            
            // Update status
            updateFileProgress(currentUploadIndex, 0, 'Uploading...');
            
            // Simulate upload progress
            let progress = 0;
            const progressInterval = setInterval(function() {
                progress += Math.random() * 20;
                if (progress > 90) progress = 90;
                updateFileProgress(currentUploadIndex, progress, 'Uploading...');
            }, 200);
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(function(response) {
                console.log('Upload response status:', response.status);
                return response.text();
            })
            .then(function(data) {
                console.log('Upload response:', data.substring(0, 200));
                clearInterval(progressInterval);
                updateFileProgress(currentUploadIndex, 100, 'Completed');
                const statusIcon = document.getElementById('status-icon-' + currentUploadIndex);
                if (statusIcon) {
                    statusIcon.textContent = '✅';
                }
                
                currentUploadIndex++;
                updateOverallProgress();
                
                // Upload next file after a short delay
                setTimeout(function() {
                    uploadNextFile();
                }, 300);
            })
            .catch(function(error) {
                console.error('Upload error:', error);
                clearInterval(progressInterval);
                updateFileProgress(currentUploadIndex, 0, 'Failed');
                const statusIcon = document.getElementById('status-icon-' + currentUploadIndex);
                if (statusIcon) {
                    statusIcon.textContent = '❌';
                }
                
                currentUploadIndex++;
                updateOverallProgress();
                
                // Continue with next file
                setTimeout(function() {
                    uploadNextFile();
                }, 300);
            });
        }

        function updateFileProgress(index, progress, status) {
            const progressFill = document.getElementById('progress-fill-' + index);
            const statusElement = document.querySelector('#progress-item-' + index + ' .file-progress-status');
            
            if (progressFill) {
                progressFill.style.width = progress + '%';
            }
            
            if (statusElement) {
                statusElement.textContent = status;
            }
        }

        function updateOverallProgress() {
            const completed = currentUploadIndex;
            const total = uploadQueue.length;
            const percentage = (completed / total) * 100;
            
            const progressBar = document.getElementById('overallProgressBar');
            const progressPercentage = document.getElementById('overallProgressPercentage');
            const uploadedCount = document.getElementById('uploadedCount');
            
            if (progressBar) {
                progressBar.style.width = percentage + '%';
            }
            if (progressPercentage) {
                progressPercentage.textContent = Math.round(percentage) + '%';
            }
            if (uploadedCount) {
                uploadedCount.textContent = completed;
            }
        }

        function completeUpload() {
            const progressBar = document.getElementById('overallProgressBar');
            const progressPercentage = document.getElementById('overallProgressPercentage');
            const uploadedCount = document.getElementById('uploadedCount');
            
            if (progressBar) {
                progressBar.style.width = '100%';
            }
            if (progressPercentage) {
                progressPercentage.textContent = '100%';
            }
            if (uploadedCount) {
                uploadedCount.textContent = uploadQueue.length;
            }
            
            // Show completion message
            setTimeout(function() {
                alert('Upload completed! ' + uploadQueue.length + ' file(s) uploaded successfully.');
                hideModal('uploadModal');
                location.reload();
            }, 1000);
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            var modals = document.getElementsByClassName('modal');
            for (var i = 0; i < modals.length; i++) {
                if (event.target == modals[i]) {
                    modals[i].style.display = 'none';
                }
            }
        }

        // Initialize bulk actions on page load
        document.addEventListener('DOMContentLoaded', function() {
            updateBulkActions();
        });
    </script>
</body>
</html>
