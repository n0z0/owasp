<?php
// --- KONFIGURASI DATABASE ---
$dbFile = 'database.sqlite';
try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL,
        display_name VARCHAR(100) -- Tambahkan kolom baru ini
    )");
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    if ($stmt->fetchColumn() == 0) {
        $pdo->exec("INSERT INTO users (username, password, role, display_name) VALUES 
            ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', 'Administrator'), 
            ('user1', '5f4dcc3b5aa765d61d8327deb882cf99', 'user', 'Asep Dinamo'),   
            ('user2', 'ee11cbb19052e40b07aac0ca060c23ee', 'user', 'Ujang Dongkrak');    
        ");
    }
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// --- LOGIKA APLIKASI ---
session_start();
 $action = $_GET['action'] ?? 'home';
 $message = '';

// --- ROUTING BERDASARKAN ACTION ---
switch ($action) {
    case 'profile':
        $userId = $_GET['id'] ?? 1;
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user) $message = "User not found.";
        break;

    case 'login':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = $_POST['username'];
            $password = $_POST['password'];
            
            // VULNERABLE: A03 - SQL Injection
            $sql = "SELECT * FROM users WHERE username = '$username' AND password = '" . md5($password) . "'";
            $stmt = $pdo->query($sql);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $_SESSION['user'] = $user;
                header('Location: ?action=home');
                exit;
            } else {
                $message = "Login failed!";
            }
        }
        break;

    case 'reset_password':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = $_POST['username'];
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $message = "Password reset link has been 'sent' to user '$username'. (This is a lie!)";
            } else {
                $message = "Username '$username' not found.";
            }
        }
        break;

    case 'debug':
        if (isset($_GET['mode']) && $_GET['mode'] === 'true') {
            phpinfo();
            exit;
        }
        break;

    case 'components':
        // Simulasi penggunaan library. Versi bisa diubah via URL.
        $library_version = $_GET['version'] ?? '1';
        $vulnerable_component = [
            'name' => 'theme-loader-library',
            'version' => 'v' . $library_version . '.0',
            'cve' => 'CVE-2023-54321: Local File Inclusion (LFI)'
        ];

        // Memuat library yang sesuai
        if ($library_version === '2') {
            include 'new_library_v2.php'; // Library yang aman
        } else {
            include 'old_library_v1.php'; // Library yang rentan
        }

        // Menangani submit form
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $selected_theme = $_POST['theme'];
            echo "<div class='vulnerable-box'>";
            load_theme($selected_theme); // Memanggil fungsi dari library
            echo "</div>";
        }

        break;

    case 'update_profile':
        // Ambil data user yang sedang login untuk ditampilkan di form
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user']['id']]);
        $profile_user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $userIdToUpdate = $_POST['user_id']; 
            $newRole = $_POST['role'];
            $stmt = $pdo->prepare("UPDATE users SET role = ? WHERE id = ?");
            $stmt->execute([$newRole, $userIdToUpdate]);
            $message = "Profile for user ID $userIdToUpdate updated to role '$newRole'.";
        }
        break;

    case 'logs':
        $logs = [];
        break;

        case 'fetch_url':
        $content = '';
        $error_message = '';

        if (isset($_GET['url']) && !empty($_GET['url'])) {
            $url = $_GET['url'];
            
            // Gunakan @ untuk menekan warning default dan tangkap error-nya
            $content = @file_get_contents($url);
            
            if ($content === false) {
                // Jika gagal, ambil pesan error terakhir
                $error = error_get_last();
                $error_message = "Gagal mengambil URL. Error: " . ($error['message'] ?? 'Izin akses ditolak (Permission Denied) atau file tidak ditemukan.');
            } elseif (empty($content)) {
                // Jika berhasil tapi isinya kosong
                $error_message = "URL berhasil diakses, tetapi file kosong atau tidak mengembalikan konten apapun.";
            }
        }
        break;

    case 'logout':
        session_destroy();
        header('Location: ?action=login');
        exit;

    case 'home':
    default:
        break;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>OWASP Top 10 Lab</title>
    <style>
        body { font-family: sans-serif; }
        nav { background: #333; padding: 1rem; }
        nav a { color: white; margin-right: 1rem; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .container { padding: 1rem; }
        .vulnerable-box { border: 1px solid #ccc; padding: 1rem; margin-top: 1rem; background-color: #f9f9f9; }
        .message { padding: 1rem; margin: 1rem 0; background: #eef; border: 1px solid #cce; }
        code { background: #eee; padding: 2px 5px; }
    </style>
</head>
<body>
    <nav>
        <a href="?action=home">Home</a>
        <a href="?action=login">Login</a>
        <a href="?action=profile&id=2">A01: Access Control</a>
        <a href="?action=reset_password">A04: Insecure Design</a>
        <a href="?action=debug">A05: Misconfiguration</a>
        <a href="?action=components">A06: Old Components</a>
        <a href="?action=update_profile">A08: Integrity Failures</a>
        <a href="?action=logs">A09: Logging Failures</a>
        <a href="?action=fetch_url">A10: SSRF</a>
        <?php if (isset($_SESSION['user'])): ?>
            <a href="?action=logout">Logout (<?= htmlspecialchars($_SESSION['user']['display_name']) ?>)</a>
        <?php endif; ?>
    </nav>
    <div class="container">
        <h1>OWASP Top 10 2021 Vulnerability Lab</h1>
        <?php if ($message): ?>
            <div class="message"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <?php switch ($action): case 'profile': ?>
            <h2>A01: Broken Access Control</h2>
            <p><strong>Cara Eksploitasi:</strong> Ubah <code>?id=</code> di URL untuk melihat data user lain. Coba <code>?id=2</code> atau <code>?id=3</code>.</p>
            <?php if ($user): ?>
                <div class="vulnerable-box">
                    <h3>Profile</h3>
                    <p><strong>ID:</strong> <?= $user['id'] ?></p>
                    <p><strong>Username:</strong> <?= htmlspecialchars($user['username']) ?></p>
                    <p><strong>Role:</strong> <?= htmlspecialchars($user['role']) ?></p>
                    <p><strong>Password Hash (A02):</strong> <code><?= htmlspecialchars($user['password']) ?></code> (Cari hash ini di Google!)</p>
                </div>
            <?php endif; ?>
        <?php break; case 'login': ?>
            <h2>Login (A03, A07, A02)</h2>
            <p><strong>Cara Eksploitasi A03 (SQL Injection):</strong> Login dengan username <code>' OR '1'='1' -- </code> (dengan spasi di akhir) dan password apa saja.</p>
            <p><strong>Cara Eksploitasi A07 (Brute Force):</strong> Tidak ada rate limiting. Gunakan tool seperti Burp Suite untuk menebak password.</p>
            <form method="post">
                <label>Username: <input type="text" name="username"></label><br><br>
                <label>Password: <input type="password" name="password"></label><br><br>
                <input type="submit" value="Login">
            </form>
        <?php break; case 'reset_password': ?>
            <h2>A04: Insecure Design</h2>
            <p><strong>Cara Eksploitasi:</strong> Coba masukkan username <code>admin</code>, lalu <code>user1</code>, lalu <code>asdfghjkl</code>. Anda bisa tahu mana username yang valid berdasarkan pesan yang muncul.</p>
            <form method="post">
                <label>Username to Reset: <input type="text" name="username"></label><br><br>
                <input type="submit" value="Reset Password">
            </form>
        <?php break; case 'debug': ?>
            <h2>A05: Security Misconfiguration</h2>
            <p><strong>Cara Eksploitasi:</strong> Akses <a href="?action=debug&mode=true">?action=debug&mode=true</a> untuk melihat <code>phpinfo()</code>.</p>
        <?php break; case 'components': ?>

        <h2>A06: Vulnerable and Outdated Components</h2>
        <p>Aplikasi ini menggunakan komponen berikut yang memiliki kerentanan serius:</p>
        <ul>
            <li><strong>Name:</strong> <?= htmlspecialchars($vulnerable_component['name']) ?></li>
            <li><strong>Version:</strong> <?= htmlspecialchars($vulnerable_component['version']) ?></li>
            <li><strong>CVE:</strong> <?= htmlspecialchars($vulnerable_component['cve']) ?></li>
        </ul>
        
        <hr>
        
        <h3>Theme Loader Simulator</h3>
        <p><strong>Cara Eksploitasi:</strong> Gunakan payload <code>../../secret.txt</code> untuk mencoba membaca file rahasia.</p>
        
        <form method="post">
            <label>Select Theme: <input type="text" name="theme" placeholder="e.g., blue.php, green.php, ../../secret.txt"></label>
            <input type="submit" value="Load Theme">
        </form>
        
        <p><a href="?action=components&version=2">Upgrade Library to v2.0 (Safe)</a> | <a href="?action=components&version=1">Downgrade to v1.0 (Vulnerable)</a></p>
        
  
        <?php break; case 'update_profile': ?>

            <h2>A08: Software and Data Integrity Failures</h2>
        <p><strong>Cara Eksploitasi:</strong> Form ini seharusnya hanya untuk mengubah "Display Name". Tapi karena kepercayaan pada hidden field, Anda bisa mengubah role user lain. Buka DevTools, ubah <code>user_id</code>, lalu submit.</p>
        
        <?php if (isset($profile_user)): ?>
            <form method="post">
                <input type="hidden" name="user_id" value="<?= $profile_user['id'] ?>">
                
                <label>Display Name: <input type="text" name="display_name" value="<?= htmlspecialchars($profile_user['display_name']) ?>"></label><br><br>
                
                <!-- Field ini seharusnya tidak ada di form user biasa, tapi ada di sini karena kerentanan -->
                <label>Role: 
                    <select name="role">
                        <option value="user" <?= $profile_user['role'] === 'user' ? 'selected' : '' ?>>User</option>
                        <option value="admin" <?= $profile_user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                    </select>
                </label><br><br>
                
                <input type="submit" value="Update Profile">
            </form>
            <?php endif; ?>
        <?php break; case 'logs': ?>
            <h2>A09: Security Logging and Monitoring Failures</h2>
            <p>Halaman ini seharusnya menampilkan log keamanan, tapi selalu kosong karena tidak ada logging yang diimplementasikan.</p>
            <pre><?= htmlspecialchars(implode("\n", $logs)) ?></pre>
        <?php break; case 'fetch_url': ?>

            <h2>A10: Server-Side Request Forgery (SSRF)</h2>
        <p><strong>Cara Eksploitasi:</strong> Coba masukkan URL internal server, misalnya <code>file:///C:/windows/win.ini</code> (di Windows).</p>
        
        <form method="get">
            <input type="hidden" name="action" value="fetch_url">
            <label>URL to Fetch: <input type="text" name="url" size="50" value="<?= htmlspecialchars($_GET['url'] ?? '') ?>"></label><br><br>
            <input type="submit" value="Fetch">
        </form>
        
        <?php if ($error_message): ?>
            <h3>Debug Information (Error Log):</h3>
            <div class="vulnerable-box" style="background-color: #ffdddd; border-color: #ff9999;">
                <p style="color: red;"><strong><?= htmlspecialchars($error_message) ?></strong></p>
            </div>
        <?php endif; ?>

        <?php if ($content): ?>
            <h3>Fetched Content:</h3>
            <div class="vulnerable-box">
                <pre><?= htmlspecialchars($content) ?></pre>
            </div>
        <?php endif; ?>

        <?php break; case 'home': default: ?>
            <h2>Selamat Datang di Lab OWASP Top 10!</h2>
            <p>Aplikasi ini sengaja dibuat rentan untuk tujuan pembelajaran. Gunakan menu di atas untuk menjelajahi setiap kerentanan.</p>
            <p>Untuk beberapa fitur, Anda perlu login terlebih dahulu.</p>
        <?php endswitch; ?>
    </div>
</body>
</html>