<?php
// Signup Logic (signup.php)
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if ($password !== $confirm_password) {
        die('Passwords do not match.');
    }

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    
    $conn = new mysqli('localhost', 'root', '', 'user_auth');

    if ($conn->connect_error) {
        die('Connection failed: ' . $conn->connect_error);
    }

    $stmt = $conn->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    $stmt->bind_param('sss', $username, $email, $hashed_password);

    if ($stmt->execute()) {
        echo 'Signup successful! <a href="login.php">Login here</a>';
    } else {
        echo 'Error: ' . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>

