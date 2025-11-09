<?php
// new_library_v2.php
// Versi library yang sudah diperbaiki

function load_theme($theme_name) {
    // FIXED: Menggunakan whitelist untuk membatasi input yang diperbolehkan.
    $allowed_themes = ['blue', 'green', 'default'];

    if (in_array($theme_name, $allowed_themes)) {
        $theme_file = 'themes/' . $theme_name . '.php';
        include($theme_file);
    } else {
        // Jika input tidak valid, muat tema default yang aman.
        include('themes/default.php');
    }
}
?>