<?php
// old_library_v1.php
// Simulasi library lama yang memiliki kerentanan Local File Inclusion (LFI)

function load_theme($theme_name) {
    // VULNERABLE: Fungsi ini langsung menyertakan file tanpa validasi.
    // Penyerang bisa menggunakan '../' untuk mengakses file di luar folder 'themes'.
    $theme_file = 'themes/' . $theme_name;
    include($theme_file);
}
?>