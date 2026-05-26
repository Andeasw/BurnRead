<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Shanghai');

$BASE_DIR = __DIR__;
$HTML_DIR = $BASE_DIR . DIRECTORY_SEPARATOR . 'HTMLS';
$STATE_FILE = $HTML_DIR . DIRECTORY_SEPARATOR . '.htmls_state.json';

$COOLDOWN_DAYS = 60;
$RANDOM_DOWNLOAD_NAME = 'index.html';

$UPLOAD_TOKEN = '123';
$MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

$RECORD_IP = false;

if (!is_dir($HTML_DIR)) {
    mkdir($HTML_DIR, 0777, true);
}

function now_iso(): string {
    return date('Y-m-d H:i:s');
}

function h($s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function json_load(string $file): array {
    if (!is_file($file)) {
        return [
            'version' => 1,
            'created_at' => now_iso(),
            'updated_at' => now_iso(),
            'downloads_by_hash' => [],
            'history' => []
        ];
    }

    $raw = file_get_contents($file);
    $data = json_decode($raw ?: '', true);

    if (!is_array($data)) {
        $data = [];
    }

    $data['version'] = $data['version'] ?? 1;
    $data['created_at'] = $data['created_at'] ?? now_iso();
    $data['updated_at'] = $data['updated_at'] ?? now_iso();
    $data['downloads_by_hash'] = is_array($data['downloads_by_hash'] ?? null) ? $data['downloads_by_hash'] : [];
    $data['history'] = is_array($data['history'] ?? null) ? $data['history'] : [];

    return $data;
}

function json_save(string $file, array $data): void {
    $data['updated_at'] = now_iso();
    file_put_contents(
        $file,
        json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
        LOCK_EX
    );
}

function list_html_files(string $dir): array {
    $files = glob($dir . DIRECTORY_SEPARATOR . '*.html') ?: [];

    $files = array_values(array_filter($files, function ($file) {
        $name = basename($file);
        return is_file($file) && $name !== '' && $name[0] !== '.';
    }));

    natsort($files);
    return array_values($files);
}

function normalize_html_names(string $dir): void {
    $files = list_html_files($dir);

    if (!$files) {
        return;
    }

    $indexed = [];
    $others = [];

    foreach ($files as $file) {
        $name = basename($file);

        if (preg_match('/^index_(\d+)\.html$/i', $name, $m)) {
            $indexed[(int)$m[1]] = $file;
        } else {
            $others[] = $file;
        }
    }

    ksort($indexed);

    while ($indexed) {
        $nums = array_keys($indexed);
        $max = max($nums);
        $gap = null;

        for ($i = 1; $i <= $max; $i++) {
            if (!isset($indexed[$i])) {
                $gap = $i;
                break;
            }
        }

        if ($gap === null) {
            break;
        }

        $sourceNum = null;

        for ($i = $max; $i > $gap; $i--) {
            if (isset($indexed[$i])) {
                $sourceNum = $i;
                break;
            }
        }

        if ($sourceNum === null) {
            break;
        }

        $source = $indexed[$sourceNum];
        $target = $dir . DIRECTORY_SEPARATOR . 'index_' . $gap . '.html';
        $tmp = $dir . DIRECTORY_SEPARATOR . '__repair_' . uniqid('', true) . '.html';

        if (@rename($source, $tmp)) {
            @rename($tmp, $target);
            unset($indexed[$sourceNum]);
            $indexed[$gap] = $target;
            ksort($indexed);
        } else {
            break;
        }
    }

    if ($others) {
        usort($others, function ($a, $b) {
            return (filemtime($a) ?: 0) <=> (filemtime($b) ?: 0);
        });

        $used = [];

        foreach (list_html_files($dir) as $file) {
            if (preg_match('/^index_(\d+)\.html$/i', basename($file), $m)) {
                $used[(int)$m[1]] = true;
            }
        }

        foreach ($others as $file) {
            if (!is_file($file)) {
                continue;
            }

            $n = 1;
            while (isset($used[$n])) {
                $n++;
            }

            $target = $dir . DIRECTORY_SEPARATOR . 'index_' . $n . '.html';

            if (@rename($file, $target)) {
                $used[$n] = true;
            }
        }
    }
}

function file_num_from_request($value): ?int {
    $value = trim((string)$value);

    if ($value === '') {
        return null;
    }

    if (preg_match('/^\d+$/', $value)) {
        $n = (int)$value;
        return $n > 0 ? $n : null;
    }

    if (preg_match('/^index_(\d+)\.html$/i', $value, $m)) {
        $n = (int)$m[1];
        return $n > 0 ? $n : null;
    }

    return null;
}

function html_file_by_num(string $dir, int $num): ?string {
    $file = $dir . DIRECTORY_SEPARATOR . 'index_' . $num . '.html';
    return is_file($file) ? $file : null;
}

function file_hash(string $file): string {
    return hash_file('sha256', $file) ?: sha1($file);
}

function get_inventory(string $dir): array {
    $files = list_html_files($dir);
    $items = [];

    foreach ($files as $file) {
        if (!preg_match('/^index_(\d+)\.html$/i', basename($file), $m)) {
            continue;
        }

        $items[] = [
            'num' => (int)$m[1],
            'name' => basename($file),
            'path' => $file,
            'hash' => file_hash($file),
            'size' => filesize($file) ?: 0,
            'mtime' => filemtime($file) ?: 0
        ];
    }

    usort($items, fn($a, $b) => $a['num'] <=> $b['num']);

    return $items;
}

function cutoff_time(int $days): int {
    return time() - ($days * 86400);
}

function choose_random_file(array $items, array $state, int $cooldownDays): ?array {
    if (!$items) {
        return null;
    }

    $cutoff = cutoff_time($cooldownDays);
    $eligible = [];

    foreach ($items as $item) {
        $record = $state['downloads_by_hash'][$item['hash']] ?? null;
        $lastTs = is_array($record) && !empty($record['last_ts']) ? (int)$record['last_ts'] : 0;

        if ($lastTs <= 0 || $lastTs < $cutoff) {
            $eligible[] = $item;
        }
    }

    if (!$eligible) {
        $eligible = $items;
    }

    return $eligible[array_rand($eligible)];
}

function record_download(array &$state, array $item, string $type, bool $recordIp): void {
    $hash = $item['hash'];
    $ts = time();

    if (!isset($state['downloads_by_hash'][$hash]) || !is_array($state['downloads_by_hash'][$hash])) {
        $state['downloads_by_hash'][$hash] = [
            'hash' => $hash,
            'first_at' => now_iso(),
            'first_ts' => $ts,
            'last_at' => now_iso(),
            'last_ts' => $ts,
            'count' => 0,
            'names' => []
        ];
    }

    $state['downloads_by_hash'][$hash]['last_at'] = now_iso();
    $state['downloads_by_hash'][$hash]['last_ts'] = $ts;
    $state['downloads_by_hash'][$hash]['count'] = (int)($state['downloads_by_hash'][$hash]['count'] ?? 0) + 1;

    $names = $state['downloads_by_hash'][$hash]['names'] ?? [];

    if (!in_array($item['name'], $names, true)) {
        $names[] = $item['name'];
    }

    $state['downloads_by_hash'][$hash]['names'] = array_values($names);

    $row = [
        'time' => now_iso(),
        'ts' => $ts,
        'type' => $type,
        'num' => $item['num'],
        'name' => $item['name'],
        'hash' => $hash,
        'size' => $item['size']
    ];

    if ($recordIp) {
        $row['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
    }

    $state['history'][] = $row;

    if (count($state['history']) > 3000) {
        $state['history'] = array_slice($state['history'], -3000);
    }
}

function send_html_download(string $file, string $downloadName): void {
    if (!is_file($file)) {
        http_response_code(404);
        echo 'File not found';
        exit;
    }

    while (ob_get_level()) {
        ob_end_clean();
    }

    header('Content-Type: text/html; charset=UTF-8');
    header('Content-Length: ' . filesize($file));
    header('Content-Disposition: attachment; filename="' . addslashes($downloadName) . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    readfile($file);
    exit;
}

function send_raw_html(?string $file): void {
    if (!$file || !is_file($file)) {
        http_response_code(404);
        echo 'File not found';
        exit;
    }

    header('Content-Type: text/html; charset=UTF-8');
    readfile($file);
    exit;
}

function fmt_size(int $bytes): string {
    if ($bytes >= 1048576) {
        return round($bytes / 1048576, 2) . ' MB';
    }

    if ($bytes >= 1024) {
        return round($bytes / 1024, 1) . ' KB';
    }

    return $bytes . ' B';
}

function current_self_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') == 443);
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';

    $requestUri = $_SERVER['REQUEST_URI'] ?? ($_SERVER['SCRIPT_NAME'] ?? '/');
    $path = strtok($requestUri, '?');

    if ($path === false || $path === '') {
        $path = $_SERVER['SCRIPT_NAME'] ?? '/';
    }

    return $scheme . '://' . $host . $path;
}

function svg_favicon_data(): string {
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
        <defs>
            <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stop-color="#2563eb"/>
                <stop offset=".55" stop-color="#7c3aed"/>
                <stop offset="1" stop-color="#06b6d4"/>
            </linearGradient>
        </defs>
        <rect width="64" height="64" rx="16" fill="url(#g)"/>
        <path d="M18 16h22l8 8v24H18z" fill="rgba(255,255,255,.24)"/>
        <path d="M40 16v9h8" fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"/>
        <path d="M25 34l-6 6 6 6M39 34l6 6-6 6M34 32l-5 16" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>';

    return 'data:image/svg+xml;base64,' . base64_encode($svg);
}

function next_html_number(string $dir): int {
    $max = 0;

    foreach (list_html_files($dir) as $file) {
        if (preg_match('/^index_(\d+)\.html$/i', basename($file), $m)) {
            $max = max($max, (int)$m[1]);
        }
    }

    return $max + 1;
}

function upload_token_ok(string $token): bool {
    global $UPLOAD_TOKEN;

    if ($UPLOAD_TOKEN === '') {
        return true;
    }

    return hash_equals($UPLOAD_TOKEN, $token);
}

function normalize_uploaded_files(array $files): array {
    $result = [];

    if (!isset($files['name'])) {
        return $result;
    }

    if (!is_array($files['name'])) {
        return [$files];
    }

    foreach ($files['name'] as $i => $name) {
        $result[] = [
            'name' => $files['name'][$i] ?? '',
            'type' => $files['type'][$i] ?? '',
            'tmp_name' => $files['tmp_name'][$i] ?? '',
            'error' => $files['error'][$i] ?? UPLOAD_ERR_NO_FILE,
            'size' => $files['size'][$i] ?? 0
        ];
    }

    return $result;
}

function uploaded_file_is_html(array $file, string &$reason): bool {
    global $MAX_UPLOAD_BYTES;

    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        $reason = '上传失败';
        return false;
    }

    if (empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        $reason = '非法上传文件';
        return false;
    }

    $name = (string)($file['name'] ?? '');
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    if (!in_array($ext, ['html', 'htm'], true)) {
        $reason = '只允许 .html 或 .htm';
        return false;
    }

    $size = (int)($file['size'] ?? 0);

    if ($size <= 0) {
        $reason = '文件为空';
        return false;
    }

    if ($size > $MAX_UPLOAD_BYTES) {
        $reason = '文件过大，最大允许 ' . fmt_size($MAX_UPLOAD_BYTES);
        return false;
    }

    $content = file_get_contents($file['tmp_name']);

    if ($content === false || trim($content) === '') {
        $reason = '无法读取内容';
        return false;
    }

    if (strpos($content, "\0") !== false) {
        $reason = '包含二进制内容';
        return false;
    }

    if (preg_match('/<\?(php|=)?/i', $content)) {
        $reason = '不能包含 PHP 代码';
        return false;
    }

    $low = strtolower($content);

    if (strpos($low, '<html') === false && strpos($low, '<!doctype html') === false) {
        $reason = '缺少 html 或 doctype';
        return false;
    }

    if (strpos($low, '</html>') === false) {
        $reason = '缺少 </html>';
        return false;
    }

    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);

        if ($finfo) {
            $mime = finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);

            $allowed = [
                'text/html',
                'text/plain',
                'application/octet-stream',
                'application/xhtml+xml'
            ];

            if ($mime && !in_array($mime, $allowed, true)) {
                $reason = 'MIME 不允许：' . $mime;
                return false;
            }
        }
    }

    return true;
}

function uploaded_tmp_hash(array $file): string {
    return hash_file('sha256', $file['tmp_name']) ?: '';
}

function existing_hash_map(string $dir): array {
    $map = [];

    foreach (list_html_files($dir) as $file) {
        $hash = file_hash($file);

        if ($hash !== '') {
            $map[$hash] = basename($file);
        }
    }

    return $map;
}

function save_uploaded_html(array $file, string $dir, array &$knownHashes): array {
    normalize_html_names($dir);

    $original = (string)($file['name'] ?? 'upload.html');
    $hash = uploaded_tmp_hash($file);

    if ($hash !== '' && isset($knownHashes[$hash])) {
        return [
            'ok' => true,
            'skipped' => true,
            'message' => '重复跳过',
            'original' => $original,
            'name' => $knownHashes[$hash]
        ];
    }

    $num = next_html_number($dir);
    $targetName = 'index_' . $num . '.html';
    $target = $dir . DIRECTORY_SEPARATOR . $targetName;

    while (is_file($target)) {
        $num++;
        $targetName = 'index_' . $num . '.html';
        $target = $dir . DIRECTORY_SEPARATOR . $targetName;
    }

    if (!move_uploaded_file($file['tmp_name'], $target)) {
        return [
            'ok' => false,
            'skipped' => false,
            'message' => '保存失败',
            'original' => $original,
            'name' => ''
        ];
    }

    if ($hash !== '') {
        $knownHashes[$hash] = $targetName;
    }

    normalize_html_names($dir);

    return [
        'ok' => true,
        'skipped' => false,
        'message' => '上传成功',
        'original' => $original,
        'name' => $targetName
    ];
}

function save_uploaded_html_batch(array $files, string $dir): array {
    $uploaded = 0;
    $skipped = 0;
    $failed = 0;
    $messages = [];

    $knownHashes = existing_hash_map($dir);
    $batchHashes = [];

    foreach ($files as $file) {
        $original = (string)($file['name'] ?? 'unknown.html');

        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            continue;
        }

        $reason = '';

        if (!uploaded_file_is_html($file, $reason)) {
            $failed++;
            $messages[] = $original . '：' . $reason;
            continue;
        }

        $hash = uploaded_tmp_hash($file);

        if ($hash !== '' && isset($batchHashes[$hash])) {
            $skipped++;
            $messages[] = $original . '：本批次重复，已跳过';
            continue;
        }

        if ($hash !== '') {
            $batchHashes[$hash] = true;
        }

        $result = save_uploaded_html($file, $dir, $knownHashes);

        if (!$result['ok']) {
            $failed++;
            $messages[] = $original . '：' . $result['message'];
            continue;
        }

        if (!empty($result['skipped'])) {
            $skipped++;
            $messages[] = $original . '：重复已有文件 ' . $result['name'];
            continue;
        }

        $uploaded++;
        $messages[] = $original . ' → ' . $result['name'];
    }

    return [
        'uploaded' => $uploaded,
        'skipped' => $skipped,
        'failed' => $failed,
        'messages' => $messages
    ];
}

normalize_html_names($HTML_DIR);

$state = json_load($STATE_FILE);
$items = get_inventory($HTML_DIR);

if (array_key_exists('htmls', $_GET)) {
    $item = choose_random_file($items, $state, $COOLDOWN_DAYS);

    if (!$item) {
        http_response_code(404);
        echo 'No HTML files found in HTMLS folder';
        exit;
    }

    record_download($state, $item, 'random', $RECORD_IP);
    json_save($STATE_FILE, $state);
    send_html_download($item['path'], $RANDOM_DOWNLOAD_NAME);
}

if (isset($_GET['download'])) {
    $num = file_num_from_request($_GET['download']);

    if (!$num) {
        http_response_code(400);
        echo 'Bad file number';
        exit;
    }

    $file = html_file_by_num($HTML_DIR, $num);

    if (!$file) {
        http_response_code(404);
        echo 'File not found';
        exit;
    }

    foreach ($items as $item) {
        if ($item['num'] === $num) {
            record_download($state, $item, 'specified', $RECORD_IP);
            json_save($STATE_FILE, $state);
            break;
        }
    }

    send_html_download($file, 'index_' . $num . '.html');
}

if (isset($_GET['raw'])) {
    $num = file_num_from_request($_GET['raw']);

    if (!$num) {
        http_response_code(400);
        echo 'Bad file number';
        exit;
    }

    send_raw_html(html_file_by_num($HTML_DIR, $num));
}

$uploadMessage = '';
$uploadOk = false;
$uploadDetails = [];

if (isset($_GET['upload']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string)($_POST['token'] ?? $_GET['token'] ?? '');

    if (!upload_token_ok($token)) {
        $uploadMessage = '上传密钥错误';
    } elseif (empty($_FILES['html_file'])) {
        $uploadMessage = '请选择 HTML 文件';
    } else {
        $files = normalize_uploaded_files($_FILES['html_file']);
        $result = save_uploaded_html_batch($files, $HTML_DIR);

        $uploadOk = $result['uploaded'] > 0 && $result['failed'] === 0;

        $uploadMessage = '完成：成功 ' . $result['uploaded'] .
            '，跳过 ' . $result['skipped'] .
            '，失败 ' . $result['failed'];

        $uploadDetails = $result['messages'];

        normalize_html_names($HTML_DIR);
        $items = get_inventory($HTML_DIR);
    }
}

$total = count($items);
$cutoff = cutoff_time($COOLDOWN_DAYS);
$downloadedInWindow = 0;

foreach ($items as $item) {
    $record = $state['downloads_by_hash'][$item['hash']] ?? null;

    if (is_array($record) && !empty($record['last_ts']) && (int)$record['last_ts'] >= $cutoff) {
        $downloadedInWindow++;
    }
}

$availableInWindow = max(0, $total - $downloadedInWindow);
$history = array_reverse($state['history'] ?? []);
$recent = array_slice($history, 0, 30);

$firstNum = $total > 0 ? $items[0]['num'] : 0;

$selfUrl = current_self_url();
$apiRandom = $selfUrl . '?htmls';
$apiDownloadExample = $selfUrl . '?download=1';
$apiRawExample = $selfUrl . '?raw=1';
$apiUploadExample = $selfUrl . '?upload=1';
$favicon = svg_favicon_data();

?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTMLS 文件接口</title>
<link rel="icon" href="<?= h($favicon) ?>" type="image/svg+xml">
<link rel="shortcut icon" href="<?= h($favicon) ?>" type="image/svg+xml">
<meta name="theme-color" content="#2563eb">
<style>
:root {
    --bg1: #edf4ff;
    --bg2: #f7f0ff;
    --bg3: #eefdf7;
    --card: rgba(255, 255, 255, .82);
    --card-strong: rgba(255, 255, 255, .94);
    --text: #111827;
    --muted: #64748b;
    --muted2: #94a3b8;
    --line: rgba(148, 163, 184, .28);
    --line2: rgba(37, 99, 235, .16);
    --blue: #2563eb;
    --blue2: #1d4ed8;
    --cyan: #0891b2;
    --purple: #7c3aed;
    --green: #16a34a;
    --red: #dc2626;
    --radius: 14px;
    --shadow: 0 16px 42px rgba(15, 23, 42, .10);
    --shadow-soft: 0 10px 26px rgba(15, 23, 42, .07);
}

* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    height: 100%;
    overflow: hidden;
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
    background:
        radial-gradient(circle at 5% 5%, rgba(96, 165, 250, .34), transparent 30%),
        radial-gradient(circle at 92% 12%, rgba(168, 85, 247, .22), transparent 32%),
        radial-gradient(circle at 70% 90%, rgba(45, 212, 191, .22), transparent 34%),
        linear-gradient(135deg, var(--bg1), var(--bg2) 48%, var(--bg3));
}

body::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background:
        linear-gradient(90deg, rgba(255,255,255,.22) 1px, transparent 1px),
        linear-gradient(0deg, rgba(255,255,255,.22) 1px, transparent 1px);
    background-size: 42px 42px;
    mask-image: linear-gradient(to bottom, rgba(0,0,0,.45), transparent 72%);
    opacity: .45;
}

a {
    color: inherit;
    text-decoration: none;
}

button {
    font-family: inherit;
}

.app {
    position: relative;
    z-index: 1;
    height: 100vh;
    display: grid;
    grid-template-rows: auto auto auto 1fr;
    gap: 10px;
    padding: 10px;
    overflow: hidden;
}

.top {
    min-height: 56px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 8px 12px;
    box-shadow: var(--shadow);
    backdrop-filter: blur(18px);
}

.brand {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
}

.logo {
    width: 40px;
    height: 40px;
    flex: 0 0 auto;
    border-radius: 13px;
    display: grid;
    place-items: center;
    background:
        radial-gradient(circle at 30% 20%, rgba(255,255,255,.38), transparent 35%),
        linear-gradient(135deg, #2563eb, #7c3aed 58%, #06b6d4);
    box-shadow: 0 14px 28px rgba(37, 99, 235, .25);
}

.logo svg {
    width: 25px;
    height: 25px;
    display: block;
}

.title {
    min-width: 0;
}

.title h1 {
    margin: 0;
    font-size: 18px;
    line-height: 1.1;
    letter-spacing: -0.03em;
}

.title p {
    margin: 4px 0 0;
    color: var(--muted);
    font-size: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.top-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    justify-content: flex-end;
}

.btn,
.mini {
    border: 1px solid rgba(148, 163, 184, .32);
    background: rgba(255, 255, 255, .82);
    color: var(--text);
    border-radius: 999px;
    cursor: pointer;
    font-weight: 750;
    white-space: nowrap;
    transition: .18s ease;
}

.btn {
    height: 34px;
    padding: 0 13px;
    font-size: 13px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
}

.btn.primary {
    background: linear-gradient(135deg, var(--blue), var(--purple));
    border-color: transparent;
    color: #fff;
    box-shadow: 0 10px 22px rgba(37, 99, 235, .24);
}

.btn:hover,
.mini:hover {
    transform: translateY(-1px);
    background: #ffffff;
    border-color: rgba(37, 99, 235, .28);
}

.info {
    display: grid;
    grid-template-columns: 420px minmax(0, 1fr);
    gap: 10px;
    min-height: 96px;
    overflow: hidden;
}

.stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
    min-width: 0;
}

.stat {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 11px 10px;
    min-width: 0;
    box-shadow: var(--shadow-soft);
    backdrop-filter: blur(18px);
}

.stat b {
    display: block;
    font-size: 23px;
    line-height: 1;
    letter-spacing: -0.03em;
    background: linear-gradient(135deg, #0f172a, #2563eb);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.stat span {
    display: block;
    margin-top: 6px;
    color: var(--muted);
    font-size: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.apis {
    min-width: 0;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 8px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(245px, 1fr));
    gap: 8px;
    overflow: hidden;
    box-shadow: var(--shadow-soft);
    backdrop-filter: blur(18px);
}

.api {
    min-width: 0;
    border: 1px solid rgba(37, 99, 235, .13);
    border-radius: 12px;
    background:
        linear-gradient(135deg, rgba(239, 246, 255, .96), rgba(255, 255, 255, .88));
    padding: 8px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) 54px;
    gap: 8px;
    align-items: center;
}

.api > div {
    min-width: 0;
}

.api strong {
    display: block;
    font-size: 12px;
    margin-bottom: 5px;
    color: #1e293b;
}

.api code {
    display: block;
    width: 100%;
    max-width: 100%;
    color: #1e40af;
    background: rgba(219, 234, 254, .72);
    border: 1px solid rgba(147, 197, 253, .32);
    padding: 6px 8px;
    border-radius: 9px;
    font-size: 11px;
    line-height: 1.2;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.copy {
    width: 54px;
    min-width: 54px;
    height: 30px;
    padding: 0;
    font-size: 12px;
    justify-self: end;
}

.upload-panel {
    display: none;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 8px;
    box-shadow: var(--shadow);
    backdrop-filter: blur(18px);
}

.upload-panel.show {
    display: block;
}

.upload-form {
    display: grid;
    grid-template-columns: auto minmax(260px, 1fr) 190px auto minmax(180px, auto);
    gap: 8px;
    align-items: center;
}

.upload-title {
    font-size: 13px;
    font-weight: 800;
    white-space: nowrap;
}

.dropzone {
    min-height: 38px;
    border: 1px dashed rgba(37, 99, 235, .42);
    border-radius: 14px;
    background:
        linear-gradient(135deg, rgba(239, 246, 255, .95), rgba(240, 253, 250, .9));
    display: grid;
    align-content: center;
    gap: 2px;
    padding: 6px 12px;
    cursor: pointer;
    min-width: 0;
    transition: .18s ease;
}

.dropzone:hover,
.dropzone.drag {
    background:
        linear-gradient(135deg, rgba(219, 234, 254, .98), rgba(204, 251, 241, .92));
    border-color: var(--blue);
}

.dropzone input {
    display: none;
}

.drop-main {
    color: #1e3a8a;
    font-size: 13px;
    font-weight: 800;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.drop-sub {
    color: #64748b;
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.upload-token {
    height: 34px;
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 0 12px;
    background: rgba(255, 255, 255, .88);
    font-size: 13px;
    min-width: 0;
    outline: none;
}

.upload-token:focus {
    border-color: rgba(37, 99, 235, .48);
    box-shadow: 0 0 0 3px rgba(37, 99, 235, .10);
}

.upload-result {
    min-width: 0;
}

.upload-msg {
    font-size: 12px;
    font-weight: 800;
    white-space: nowrap;
}

.upload-msg.ok {
    color: var(--green);
}

.upload-msg.bad {
    color: var(--red);
}

.upload-details {
    margin-top: 3px;
    max-height: 48px;
    overflow: auto;
    color: var(--muted);
    font-size: 11px;
    line-height: 1.45;
}

.workspace {
    min-height: 0;
    display: grid;
    grid-template-columns: 390px minmax(0, 1fr);
    gap: 10px;
    overflow: hidden;
}

.left {
    min-height: 0;
    display: grid;
    grid-template-rows: minmax(0, 1.2fr) minmax(0, .8fr);
    gap: 10px;
    overflow: hidden;
}

.panel {
    min-height: 0;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    overflow: hidden;
    box-shadow: var(--shadow);
    display: grid;
    grid-template-rows: auto 1fr;
    backdrop-filter: blur(18px);
}

.panel-head {
    height: 40px;
    padding: 0 12px;
    border-bottom: 1px solid var(--line);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    background: rgba(255, 255, 255, .46);
}

.panel-head h2 {
    margin: 0;
    font-size: 14px;
    letter-spacing: -0.02em;
}

.small {
    color: var(--muted);
    font-size: 12px;
}

.scroll {
    min-height: 0;
    overflow: auto;
}

.scroll::-webkit-scrollbar,
.upload-details::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

.scroll::-webkit-scrollbar-thumb,
.upload-details::-webkit-scrollbar-thumb {
    background: rgba(100, 116, 139, .28);
    border-radius: 999px;
}

.scroll::-webkit-scrollbar-track,
.upload-details::-webkit-scrollbar-track {
    background: transparent;
}

.file {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 8px;
    padding: 9px 11px;
    border-bottom: 1px solid rgba(148, 163, 184, .20);
    align-items: center;
    transition: .16s ease;
}

.file:hover {
    background: rgba(239, 246, 255, .62);
}

.file.active {
    background:
        linear-gradient(90deg, rgba(219, 234, 254, .96), rgba(255,255,255,.72));
    box-shadow: inset 3px 0 0 var(--blue);
}

.file-title {
    font-size: 13px;
    font-weight: 800;
    line-height: 1.25;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.file-meta {
    margin-top: 3px;
    color: var(--muted);
    font-size: 11px;
    line-height: 1.4;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.file-actions {
    display: flex;
    gap: 5px;
    flex-shrink: 0;
}

.mini {
    height: 26px;
    padding: 0 8px;
    font-size: 11px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
}

.preview {
    min-height: 0;
}

.preview-head {
    height: 42px;
}

.preview-title {
    min-width: 0;
}

.preview-title h2 {
    margin: 0;
    font-size: 14px;
}

.preview-title div {
    margin-top: 2px;
    color: var(--muted);
    font-size: 11px;
    max-width: 50vw;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.preview-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
}

.iframe-box {
    min-height: 0;
    background: #fff;
}

iframe {
    width: 100%;
    height: 100%;
    display: block;
    border: 0;
    background: #fff;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    padding: 7px 9px;
    border-bottom: 1px solid rgba(148, 163, 184, .20);
    text-align: left;
    font-size: 11px;
    vertical-align: top;
}

th {
    color: var(--muted);
    background: rgba(248, 250, 252, .92);
    position: sticky;
    top: 0;
    z-index: 1;
}

td {
    color: #334155;
}

.empty {
    padding: 18px;
    color: var(--muted);
    font-size: 13px;
    text-align: center;
}

.toast {
    position: fixed;
    left: 50%;
    bottom: 16px;
    transform: translateX(-50%) translateY(14px);
    opacity: 0;
    pointer-events: none;
    background: #0f172a;
    color: #fff;
    padding: 9px 13px;
    border-radius: 999px;
    font-size: 13px;
    transition: .18s ease;
    z-index: 99;
    box-shadow: 0 12px 28px rgba(15, 23, 42, .25);
}

.toast.show {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
}

@media (max-width: 1360px) {
    .apis {
        grid-template-columns: repeat(2, minmax(260px, 1fr));
    }

    .info {
        min-height: 142px;
    }

    .upload-form {
        grid-template-columns: auto minmax(260px, 1fr) 160px auto;
    }

    .upload-result {
        grid-column: 1 / -1;
    }
}

@media (max-width: 1180px) {
    .info {
        grid-template-columns: 1fr;
        min-height: auto;
        max-height: none;
    }

    .workspace {
        grid-template-columns: 340px minmax(0, 1fr);
    }
}

@media (max-width: 900px) {
    html,
    body {
        overflow: auto;
        height: auto;
    }

    .app {
        height: auto;
        min-height: 100vh;
        overflow: visible;
    }

    .top {
        align-items: flex-start;
        flex-direction: column;
    }

    .top-actions {
        justify-content: flex-start;
    }

    .stats {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .apis {
        grid-template-columns: 1fr;
    }

    .api {
        grid-template-columns: minmax(0, 1fr) 54px;
    }

    .upload-form {
        grid-template-columns: 1fr;
    }

    .upload-title,
    .upload-msg {
        white-space: normal;
    }

    .drop-main,
    .drop-sub {
        white-space: normal;
    }

    .workspace {
        grid-template-columns: 1fr;
        overflow: visible;
    }

    .left {
        grid-template-rows: auto auto;
    }

    .panel {
        min-height: 260px;
    }

    .preview {
        height: 70vh;
    }

    .preview-title div {
        max-width: 80vw;
    }
}

@media (max-width: 560px) {
    .app {
        padding: 8px;
        gap: 8px;
    }

    .stats {
        grid-template-columns: 1fr;
    }

    .file {
        grid-template-columns: 1fr;
    }

    .file-actions {
        justify-content: flex-start;
    }

    .preview-head {
        height: auto;
        min-height: 76px;
        align-items: flex-start;
        flex-direction: column;
        padding: 8px 12px;
    }

    .preview-actions {
        flex-wrap: wrap;
    }

    .title p {
        white-space: normal;
    }
}
</style>
</head>
<body>

<div class="app">
    <header class="top">
        <div class="brand">
            <div class="logo" aria-hidden="true">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img">
                    <rect x="10" y="6" width="34" height="52" rx="7" fill="rgba(255,255,255,.24)"/>
                    <path d="M44 6 L54 16 V51 C54 55 51 58 47 58 H17 C13 58 10 55 10 51 V13 C10 9 13 6 17 6 H44Z" fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"/>
                    <path d="M44 7 V18 H54" fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"/>
                    <path d="M24 31 L17 38 L24 45" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M40 31 L47 38 L40 45" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M35 29 L29 47" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round"/>
                </svg>
            </div>
            <div class="title">
                <h1>HTMLS 文件接口</h1>
                <p>HTML 目录：HTMLS，随机下载文件名：index.html，当前路径：<?= h(parse_url($selfUrl, PHP_URL_PATH) ?: '/') ?></p>
            </div>
        </div>

        <div class="top-actions">
            <a class="btn primary" href="?htmls">随机下载 index.html</a>
            <button class="btn" type="button" onclick="toggleUpload()">批量上传</button>
            <?php if ($firstNum): ?>
                <button class="btn" type="button" onclick="selectFile(<?= (int)$firstNum ?>)">预览第一个</button>
            <?php endif; ?>
        </div>
    </header>

    <section class="info">
        <div class="stats">
            <div class="stat">
                <b><?= (int)$total ?></b>
                <span>文件总数</span>
            </div>
            <div class="stat">
                <b><?= (int)$downloadedInWindow ?></b>
                <span><?= (int)$COOLDOWN_DAYS ?> 天内已抽取</span>
            </div>
            <div class="stat">
                <b><?= (int)$availableInWindow ?></b>
                <span><?= (int)$COOLDOWN_DAYS ?> 天内优先可抽</span>
            </div>
            <div class="stat">
                <b><?= count($state['history'] ?? []) ?></b>
                <span>日志记录数</span>
            </div>
        </div>

        <div class="apis">
            <div class="api">
                <div>
                    <strong>随机下载接口</strong>
                    <code id="apiRandom"><?= h($apiRandom) ?></code>
                </div>
                <button class="btn copy" type="button" onclick="copyText('apiRandom')">复制</button>
            </div>

            <div class="api">
                <div>
                    <strong>指定下载接口</strong>
                    <code id="apiDownload"><?= h($apiDownloadExample) ?></code>
                </div>
                <button class="btn copy" type="button" onclick="copyText('apiDownload')">复制</button>
            </div>

            <div class="api">
                <div>
                    <strong>原始预览接口</strong>
                    <code id="apiRaw"><?= h($apiRawExample) ?></code>
                </div>
                <button class="btn copy" type="button" onclick="copyText('apiRaw')">复制</button>
            </div>

            <div class="api">
                <div>
                    <strong>批量上传接口</strong>
                    <code id="apiUpload"><?= h($apiUploadExample) ?></code>
                </div>
                <button class="btn copy" type="button" onclick="copyText('apiUpload')">复制</button>
            </div>
        </div>
    </section>

    <section class="upload-panel" id="uploadPanel">
        <form method="post" action="?upload=1" enctype="multipart/form-data" class="upload-form" id="uploadForm">
            <div class="upload-title">上传 HTML</div>

            <label class="dropzone" id="dropzone">
                <input id="htmlFileInput" type="file" name="html_file[]" accept=".html,.htm,text/html" multiple required>
                <span class="drop-main">拖动文件到这里，或点击多选</span>
                <span class="drop-sub" id="fileCountText">支持批量 .html / .htm，重复文件会自动跳过</span>
            </label>

            <input class="upload-token" type="password" name="token" placeholder="上传密钥" value="123" required>

            <button class="btn primary" type="submit">开始上传</button>

            <?php if ($uploadMessage !== ''): ?>
                <div class="upload-result">
                    <div class="upload-msg <?= $uploadOk ? 'ok' : 'bad' ?>">
                        <?= h($uploadMessage) ?>
                    </div>

                    <?php if (!empty($uploadDetails)): ?>
                        <div class="upload-details">
                            <?php foreach (array_slice($uploadDetails, 0, 20) as $line): ?>
                                <div><?= h($line) ?></div>
                            <?php endforeach; ?>

                            <?php if (count($uploadDetails) > 20): ?>
                                <div>还有 <?= count($uploadDetails) - 20 ?> 条未显示</div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </form>
    </section>

    <main class="workspace">
        <section class="left">
            <div class="panel">
                <div class="panel-head">
                    <h2>文件列表</h2>
                    <span class="small"><?= (int)$total ?> files</span>
                </div>

                <div class="scroll">
                    <?php if (!$items): ?>
                        <div class="empty">HTMLS 文件夹里暂无 .html 文件。</div>
                    <?php else: ?>
                        <?php foreach ($items as $item): ?>
                            <?php
                                $rec = $state['downloads_by_hash'][$item['hash']] ?? null;
                                $count = is_array($rec) ? (int)($rec['count'] ?? 0) : 0;
                                $last = is_array($rec) ? (string)($rec['last_at'] ?? '-') : '-';
                            ?>
                            <div class="file" data-num="<?= (int)$item['num'] ?>">
                                <div>
                                    <div class="file-title"><?= h($item['name']) ?></div>
                                    <div class="file-meta">
                                        <?= h(fmt_size((int)$item['size'])) ?>
                                        · 下载 <?= (int)$count ?> 次
                                        · <?= h($last) ?>
                                    </div>
                                </div>
                                <div class="file-actions">
                                    <button class="mini" type="button" onclick="selectFile(<?= (int)$item['num'] ?>)">预览</button>
                                    <a class="mini" href="?download=<?= (int)$item['num'] ?>">下载</a>
                                    <button class="mini" type="button" onclick="copyPlain(selfUrl + '?download=<?= (int)$item['num'] ?>')">复制</button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>

            <div class="panel">
                <div class="panel-head">
                    <h2>最近抽取日志</h2>
                    <span class="small"><?= count($recent) ?> rows</span>
                </div>

                <div class="scroll">
                    <?php if (!$recent): ?>
                        <div class="empty">暂无抽取记录。</div>
                    <?php else: ?>
                        <table>
                            <thead>
                            <tr>
                                <th>时间</th>
                                <th>类型</th>
                                <th>文件</th>
                                <th>大小</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($recent as $row): ?>
                                <tr>
                                    <td><?= h($row['time'] ?? '') ?></td>
                                    <td><?= h($row['type'] ?? '') ?></td>
                                    <td>
                                        <?php if (!empty($row['num'])): ?>
                                            <button class="mini" type="button" onclick="selectFile(<?= (int)$row['num'] ?>)">
                                                <?= h($row['name'] ?? '') ?>
                                            </button>
                                        <?php else: ?>
                                            <?= h($row['name'] ?? '') ?>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= h(fmt_size((int)($row['size'] ?? 0))) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </section>

        <section class="panel preview">
            <div class="panel-head preview-head">
                <div class="preview-title">
                    <h2 id="previewTitle">预览</h2>
                    <div id="previewSub">点击左侧文件即可切换预览，不刷新页面。</div>
                </div>

                <div class="preview-actions">
                    <a class="btn" id="openBtn" href="#" target="_blank">新窗口</a>
                    <a class="btn" id="downloadBtn" href="#">下载当前</a>
                    <button class="btn" type="button" id="copyCurrentBtn">复制当前</button>
                </div>
            </div>

            <div class="iframe-box">
                <?php if ($firstNum): ?>
                    <iframe id="previewFrame" src="?raw=<?= (int)$firstNum ?>"></iframe>
                <?php else: ?>
                    <div class="empty">暂无可预览文件。</div>
                <?php endif; ?>
            </div>
        </section>
    </main>
</div>

<div class="toast" id="toast">已复制</div>

<script>
const selfUrl = <?= json_encode($selfUrl, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
let currentNum = <?= (int)$firstNum ?>;

function showToast(text) {
    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.textContent = text || '已复制';
    toast.classList.add('show');

    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => {
        toast.classList.remove('show');
    }, 1300);
}

async function copyPlain(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('已复制');
    } catch (e) {
        const input = document.createElement('textarea');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        input.remove();
        showToast('已复制');
    }
}

function copyText(id) {
    const el = document.getElementById(id);
    if (!el) return;
    copyPlain(el.textContent.trim());
}

function toggleUpload() {
    const panel = document.getElementById('uploadPanel');
    if (!panel) return;
    panel.classList.toggle('show');
}

function selectFile(num) {
    currentNum = num;

    const rawUrl = '?raw=' + encodeURIComponent(num);
    const downloadUrl = '?download=' + encodeURIComponent(num);

    const frame = document.getElementById('previewFrame');
    const title = document.getElementById('previewTitle');
    const sub = document.getElementById('previewSub');
    const openBtn = document.getElementById('openBtn');
    const downloadBtn = document.getElementById('downloadBtn');

    if (frame) frame.src = rawUrl;
    if (title) title.textContent = '预览 index_' + num + '.html';
    if (sub) sub.textContent = selfUrl + '?raw=' + num;
    if (openBtn) openBtn.href = rawUrl;
    if (downloadBtn) downloadBtn.href = downloadUrl;

    document.querySelectorAll('.file').forEach(el => {
        el.classList.toggle('active', String(el.dataset.num) === String(num));
    });
}

const copyCurrentBtn = document.getElementById('copyCurrentBtn');

if (copyCurrentBtn) {
    copyCurrentBtn.addEventListener('click', () => {
        if (!currentNum) return;
        copyPlain(selfUrl + '?download=' + currentNum);
    });
}

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('htmlFileInput');
const fileCountText = document.getElementById('fileCountText');

function refreshFileCount() {
    if (!fileInput || !fileCountText) return;

    const files = Array.from(fileInput.files || []);

    if (!files.length) {
        fileCountText.textContent = '支持批量 .html / .htm，重复文件会自动跳过';
        return;
    }

    const htmlFiles = files.filter(file => /\.(html|htm)$/i.test(file.name));
    fileCountText.textContent = '已选择 ' + files.length + ' 个文件，其中 HTML 文件 ' + htmlFiles.length + ' 个';
}

if (fileInput) {
    fileInput.addEventListener('change', refreshFileCount);
}

if (dropzone && fileInput) {
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, event => {
            event.preventDefault();
            event.stopPropagation();
            dropzone.classList.add('drag');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, event => {
            event.preventDefault();
            event.stopPropagation();
            dropzone.classList.remove('drag');
        });
    });

    dropzone.addEventListener('drop', event => {
        const files = event.dataTransfer.files;
        if (!files || !files.length) return;

        fileInput.files = files;
        refreshFileCount();
    });
}

if (currentNum) {
    selectFile(currentNum);
}

<?php if ($uploadMessage !== ''): ?>
const uploadPanel = document.getElementById('uploadPanel');
if (uploadPanel) uploadPanel.classList.add('show');
<?php endif; ?>
</script>

</body>
</html>
