<?php
error_reporting(1);
ini_set('display_errors', 1);

if (!isset($_POST['url'])) {
?>
<form method="POST" style="padding:20px;font-family:Arial">
    <h2>Auto Download & Extract (ZIP/TAR) – No Folder</h2>
    <input type="text" name="url" placeholder="https://domain.com/file.zip" style="width:400px;padding:8px" required>
    <br><br>
    <button type="submit" style="padding:8px 20px">Proses</button>
</form>
<?php
exit();
}

// =======================
// PROSES
// =======================
$url = trim($_POST['url']);
$filename = basename(parse_url($url, PHP_URL_PATH));
$dest = __DIR__ . '/';

echo "<pre>";
echo "Downloading: $filename...\n";

file_put_contents($filename, file_get_contents($url));

if (!file_exists($filename)) die("Gagal download file.\n");

$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));


// =======================
//  FIX ZIP – anti folder
// =======================
if ($ext == "zip") {
    $zip = new ZipArchive;
    if ($zip->open($filename) === TRUE) {

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $info = $zip->statIndex($i);
            $file = $info["name"];

            if (substr($file, -1) == "/") continue; // skip folder

            $target = $dest . basename($file);  // hancurkan struktur folder

            copy("zip://".$filename."#".$file, $target);
        }

        $zip->close();
        echo "ZIP diextract tanpa folder.\n";
    } else {
        echo "Gagal membuka ZIP.\n";
    }
}


// =======================
// TAR & TAR.GZ (aman)
// =======================
if ($ext == "tar" || $ext == "gz" || substr($filename, -7)=="tar.gz") {
    try {
        $phar = new PharData($filename);

        foreach (new RecursiveIteratorIterator($phar) as $file) {
            $local = $file->getPathName();
            $name = basename($local);
            copy($local, $dest . $name);
        }

        echo "TAR diextract tanpa folder.\n";
    } catch (Exception $e) {
        echo "Gagal extract TAR: ".$e->getMessage();
    }
}

echo "Selesai.\n</pre>";
?>
