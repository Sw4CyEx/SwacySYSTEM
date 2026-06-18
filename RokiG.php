<?php
// RokiManager - File Manager
// Single File PHP Project

header('Content-Type: text/html; charset=utf-8');

$basePath = isset($_GET['path']) ? $_GET['path'] : '.';
$basePath = realpath($basePath) ?: '.';

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'delete') {
        $file = $_POST['file'] ?? '';
        $fullPath = $basePath . '/' . basename($file);
        
        if (file_exists($fullPath) && realpath($fullPath) !== false) {
            if (is_file($fullPath)) {
                unlink($fullPath);
                $_SESSION['message'] = "File deleted: " . basename($file);
            }
        }
        header("Location: ?path=" . urlencode($basePath));
        exit;
    }
    
    if ($action === 'zip') {
        $file = $_POST['file'] ?? '';
        $fullPath = $basePath . '/' . basename($file);
        
        if (file_exists($fullPath)) {
            $zipName = $basePath . '/' . basename($file) . '.zip';
            
            $zip = new ZipArchive();
            if ($zip->open($zipName, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
                if (is_dir($fullPath)) {
                    $files = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($fullPath),
                        RecursiveIteratorIterator::LEAVES_ONLY
                    );
                    foreach ($files as $file_path) {
                        if (!is_dir($file_path)) {
                            $arc_path = str_replace($basePath . '/', '', $file_path);
                            $zip->addFile($file_path, basename($file) . '/' . basename($file_path));
                        }
                    }
                } else {
                    $zip->addFile($fullPath, basename($file));
                }
                $zip->close();
                header("Location: ?path=" . urlencode($basePath));
                exit;
            }
        }
    }
    
    if ($action === 'unzip') {
        if (isset($_FILES['zipfile'])) {
            $zipfile = $_FILES['zipfile']['tmp_name'];
            $zip = new ZipArchive();
            
            if ($zip->open($zipfile) === true) {
                $zip->extractTo($basePath);
                $zip->close();
                $_SESSION['success'] = "File extracted successfully!";
            }
            unlink($zipfile);
            header("Location: ?path=" . urlencode($basePath));
            exit;
        }
    }
}

// Handle file download
if (isset($_GET['download'])) {
    $file = $_GET['download'];
    $fullPath = $basePath . '/' . basename($file);
    
    if (file_exists($fullPath) && is_file($fullPath)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($fullPath));
        readfile($fullPath);
        exit;
    }
}

$currentDir = scandir($basePath);
usort($currentDir, function($a, $b) {
    $aIsDir = is_dir($basePath . '/' . $a);
    $bIsDir = is_dir($basePath . '/' . $b);
    if ($aIsDir === $bIsDir) return strcasecmp($a, $b);
    return $bIsDir ? 1 : -1;
});
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RokiManager - File Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header p {
            opacity: 0.9;
            font-size: 0.9em;
        }
        
        .content {
            padding: 30px;
        }
        
        .path-bar {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9em;
            color: #555;
        }
        
        .upload-section {
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 2px dashed #667eea;
            transition: all 0.3s ease;
        }
        
        .upload-section.dragover {
            background: #e8f0ff;
            border-color: #5568d3;
            box-shadow: 0 0 20px rgba(102, 126, 234, 0.2);
        }
        
        .upload-section h3 {
            margin-bottom: 15px;
            color: #667eea;
            font-size: 1em;
        }
        
        .upload-form {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .file-input-wrapper {
            position: relative;
            flex: 1;
            min-width: 200px;
        }
        
        .file-input-wrapper input[type="file"] {
            position: absolute;
            opacity: 0;
            cursor: pointer;
        }
        
        .file-input-label {
            display: block;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            background: white;
            cursor: pointer;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .file-input-label:hover {
            background: #f0f0f0;
            border-color: #667eea;
        }
        
        .file-input-wrapper input[type="file"]:hover + .file-input-label,
        .file-input-wrapper input[type="file"]:focus + .file-input-label {
            background: #f0f0f0;
            border-color: #667eea;
        }
        
        .file-selected {
            color: #27ae60;
            font-weight: 500;
        }
        
        #uploadProgress {
            display: none;
            margin-top: 15px;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #ddd;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s ease;
        }
        
        .progress-text {
            font-size: 0.85em;
            color: #666;
            margin-top: 5px;
        }
        
        button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        button:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .file-list {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f5f5f5;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #ddd;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .file-icon {
            margin-right: 8px;
            font-size: 1.2em;
        }
        
        .file-name {
            display: flex;
            align-items: center;
        }
        
        .file-name a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
        
        .file-name a:hover {
            text-decoration: underline;
        }
        
        .size {
            color: #888;
            font-size: 0.9em;
        }
        
        .actions {
            display: flex;
            gap: 8px;
        }
        
        .btn-small {
            padding: 6px 12px;
            font-size: 0.85em;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
        }
        
        .btn-small:hover {
            background: #5568d3;
            transform: translateY(-1px);
        }
        
        .btn-small.danger {
            background: #e74c3c;
        }
        
        .btn-small.danger:hover {
            background: #c0392b;
        }
        
        .btn-small.success {
            background: #27ae60;
        }
        
        .btn-small.success:hover {
            background: #229954;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #999;
        }
        
        .empty-state p {
            font-size: 1.1em;
        }
        
        .message {
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            animation: slideIn 0.3s ease;
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
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .parent-dir {
            color: #667eea;
            font-weight: 600;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.5em;
            }
            
            .content {
                padding: 15px;
            }
            
            .upload-form {
                flex-direction: column;
            }
            
            input[type="file"] {
                min-width: auto;
            }
            
            table {
                font-size: 0.9em;
            }
            
            th, td {
                padding: 8px;
            }
            
            .actions {
                flex-direction: column;
            }
            
            .btn-small {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 RokiManager</h1>
            <p>Simple & Powerful File Manager</p>
        </div>
        
        <div class="content">
            <div class="path-bar">
                <strong>📍 Current Path:</strong> <?php echo htmlspecialchars($basePath); ?>
            </div>
            
            <div class="upload-section" id="uploadSection">
                <h3>⬆️ Upload & Extract ZIP File</h3>
                <p style="font-size: 0.9em; color: #666; margin-bottom: 15px;">Drag & drop a ZIP file here or click to select</p>
                <form method="POST" enctype="multipart/form-data" class="upload-form" id="uploadForm">
                    <div class="file-input-wrapper">
                        <input type="file" name="zipfile" id="zipfile" accept=".zip" required onchange="updateFileName(this)">
                        <label for="zipfile" class="file-input-label" id="fileLabel">
                            <span id="fileName">Choose ZIP file...</span>
                        </label>
                    </div>
                    <input type="hidden" name="action" value="unzip">
                    <button type="submit" id="uploadBtn">📦 Unzip Here</button>
                </form>
                <div id="uploadProgress">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="progress-text">Uploading: <span id="progressPercent">0</span>%</div>
                </div>
            </div>
            
            <?php if (isset($_SESSION['success'])): ?>
                <div class="message success">
                    ✅ <?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?>
                </div>
            <?php endif; ?>
            
            <div class="file-list">
                <table>
                    <thead>
                        <tr>
                            <th>📄 Name</th>
                            <th>📊 Type</th>
                            <th>📏 Size</th>
                            <th>⚙️ Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $hasFiles = false;
                        foreach ($currentDir as $file) {
                            if ($file === '.' || $file === '..' || $file === basename(__FILE__)) continue;
                            
                            $hasFiles = true;
                            $fullPath = $basePath . '/' . $file;
                            $isDir = is_dir($fullPath);
                            $fileSize = $isDir ? '-' : formatBytes(filesize($fullPath));
                            $type = $isDir ? '📁 Folder' : '📄 File';
                            $icon = $isDir ? '📁' : '📄';
                            
                            echo "<tr>";
                            echo "<td><div class='file-name'>";
                            echo "<span class='file-icon'>$icon</span>";
                            
                            if ($isDir) {
                                echo "<a href='?path=" . urlencode($fullPath) . "'>" . htmlspecialchars($file) . "</a>";
                            } else {
                                echo "<span>" . htmlspecialchars($file) . "</span>";
                            }
                            
                            echo "</div></td>";
                            echo "<td>$type</td>";
                            echo "<td><span class='size'>$fileSize</span></td>";
                            echo "<td><div class='actions'>";
                            
                            if (!$isDir) {
                                echo "<a href='?download=" . urlencode($file) . "&path=" . urlencode($basePath) . "' class='btn-small success'>⬇️ Download</a>";
                            }
                            
                            if ($isDir && strpos($fullPath, __DIR__) !== false) {
                                echo "<form method='POST' style='display:inline;'>";
                                echo "<input type='hidden' name='action' value='zip'>";
                                echo "<input type='hidden' name='file' value='" . htmlspecialchars($file) . "'>";
                                echo "<button type='submit' class='btn-small'>📦 Zip</button>";
                                echo "</form>";
                            }
                            
                            if ($file !== 'index.php' && strpos($fullPath, __DIR__) !== false) {
                                echo "<form method='POST' style='display:inline;' onsubmit=\"return confirm('Delete " . htmlspecialchars($file) . "?');\">";
                                echo "<input type='hidden' name='action' value='delete'>";
                                echo "<input type='hidden' name='file' value='" . htmlspecialchars($file) . "'>";
                                echo "<button type='submit' class='btn-small danger'>🗑️ Delete</button>";
                                echo "</form>";
                            }
                            
                            echo "</div></td>";
                            echo "</tr>";
                        }
                        
                        // Parent directory link
                        if ($basePath !== '.' && realpath($basePath) !== '/' && realpath($basePath) !== realpath(__DIR__)) {
                            $parent = dirname($basePath);
                            echo "<tr>";
                            echo "<td><div class='file-name'>";
                            echo "<span class='file-icon'>⬆️</span>";
                            echo "<a href='?path=" . urlencode($parent) . "' class='parent-dir'>.. (Parent Directory)</a>";
                            echo "</div></td>";
                            echo "<td>📁 Folder</td>";
                            echo "<td>-</td>";
                            echo "<td>-</td>";
                            echo "</tr>";
                        }
                        
                        if (!$hasFiles && ($basePath === '.' || realpath($basePath) === realpath(__DIR__))) {
                            echo "<tr><td colspan='4' style='text-align:center; color: #999; padding: 40px;'>Folder is empty</td></tr>";
                        }
                        ?>
                    </tbody>
                </table>
                
                <?php if (!$hasFiles && ($basePath === '.' || realpath($basePath) === realpath(__DIR__))): ?>
                    <div class="empty-state">
                        <p>📭 No files found in this directory</p>
                        <p style="font-size: 0.9em; margin-top: 10px;">Upload a ZIP file to get started!</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script>
        // Drag & Drop functionality
        const uploadSection = document.getElementById('uploadSection');
        const uploadForm = document.getElementById('uploadForm');
        const zipfile = document.getElementById('zipfile');
        const uploadBtn = document.getElementById('uploadBtn');
        const uploadProgress = document.getElementById('uploadProgress');
        const progressFill = document.getElementById('progressFill');
        const progressPercent = document.getElementById('progressPercent');
        
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadSection.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        // Highlight drop area when dragging over it
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadSection.addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadSection.addEventListener(eventName, unhighlight, false);
        });
        
        function highlight(e) {
            uploadSection.classList.add('dragover');
        }
        
        function unhighlight(e) {
            uploadSection.classList.remove('dragover');
        }
        
        // Handle dropped files
        uploadSection.addEventListener('drop', handleDrop, false);
        
        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            
            if (files.length > 0) {
                const file = files[0];
                
                // Validate file type
                if (!file.name.toLowerCase().endsWith('.zip')) {
                    alert('❌ Please drop a .zip file!');
                    return;
                }
                
                // Validate file size (max 100MB)
                if (file.size > 100 * 1024 * 1024) {
                    alert('❌ File is too large! Maximum size is 100MB');
                    return;
                }
                
                zipfile.files = files;
                updateFileName({value: file.name});
            }
        }
        
        // Update filename display
        function updateFileName(input) {
            const fileName = document.getElementById('fileName');
            if (input.files && input.files[0]) {
                const file = input.files[0];
                
                // Validate file size
                if (file.size > 100 * 1024 * 1024) {
                    fileName.textContent = '❌ File too large (max 100MB)';
                    fileName.classList.remove('file-selected');
                    uploadBtn.disabled = true;
                    return;
                }
                
                fileName.textContent = '✅ ' + file.name + ' (' + formatFileSize(file.size) + ')';
                fileName.classList.add('file-selected');
                uploadBtn.disabled = false;
            } else {
                fileName.textContent = 'Choose ZIP file...';
                fileName.classList.remove('file-selected');
                uploadBtn.disabled = false;
            }
        }
        
        // Format file size
        function formatFileSize(bytes) {
            const units = ['B', 'KB', 'MB'];
            let size = bytes;
            let unitIndex = 0;
            
            while (size >= 1024 && unitIndex < units.length - 1) {
                size /= 1024;
                unitIndex++;
            }
            
            return size.toFixed(2) + ' ' + units[unitIndex];
        }
        
        // Handle form submission with progress
        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!zipfile.files || zipfile.files.length === 0) {
                alert('❌ Please select a ZIP file');
                return;
            }
            
            const file = zipfile.files[0];
            
            // Final validation
            if (!file.name.toLowerCase().endsWith('.zip')) {
                alert('❌ Only .zip files are allowed');
                return;
            }
            
            if (file.size > 100 * 1024 * 1024) {
                alert('❌ File is too large! Maximum size is 100MB');
                return;
            }
            
            // Show progress
            uploadProgress.style.display = 'block';
            uploadBtn.disabled = true;
            
            const formData = new FormData();
            formData.append('zipfile', file);
            formData.append('action', 'unzip');
            
            const xhr = new XMLHttpRequest();
            
            // Track upload progress
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressFill.style.width = percentComplete + '%';
                    progressPercent.textContent = Math.round(percentComplete);
                }
            });
            
            // Handle completion
            xhr.addEventListener('load', function() {
                if (xhr.status === 200) {
                    window.location.reload();
                } else {
                    alert('❌ Upload failed!');
                    uploadBtn.disabled = false;
                    uploadProgress.style.display = 'none';
                }
            });
            
            // Handle errors
            xhr.addEventListener('error', function() {
                alert('❌ Upload error!');
                uploadBtn.disabled = false;
                uploadProgress.style.display = 'none';
            });
            
            xhr.open('POST', window.location.href);
            xhr.send(formData);
        });
    </script>
</body>
</html>

<?php
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision) . ' ' . $units[$pow];
}
?>
