<?php
/**
 * Secure Burn-After-Reading System
 * By Prince 2025.12
 */

// --- 1. Init ---
function loadEnv($path) {
    if (!file_exists($path)) return [];
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $env = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($k, $v) = explode('=', $line, 2);
            $env[trim($k)] = trim(trim($v), '"\'');
        }
    }
    return $env;
}
$env = loadEnv(__DIR__ . '/.env');
if (empty($env['ENCRYPTION_KEY'])) die("Error: ENCRYPTION_KEY missing");

$githubUrl = "https://github.com/Andeasw/BurnRead";
$keyEnv = $env['ENCRYPTION_KEY'];
$domain = $env['SITE_DOMAIN'] ?? $_SERVER['HTTP_HOST'];
$maxReads = intval($env['MAX_READ_LIMIT'] ?? 10);
$uploadMaxMB = intval($env['UPLOAD_MAX_MB'] ?? 5);
$allowedExts = explode(',', $env['UPLOAD_TYPES'] ?? 'jpg,png,zip,txt');
$defaultExpiry = $env['MESSAGE_EXPIRY'] ?? '30:0:0:0';
list($md, $mh, $mm, $ms) = array_pad(explode(':', $defaultExpiry), 4, 0);
$maxSeconds = ($md * 86400) + ($mh * 3600) + ($mm * 60) + $ms;
$maxTimeStr = "{$md}d {$mh}h";

$langCode = $_GET['lang'] ?? $_COOKIE['site_lang'] ?? $env['DEFAULT_LANG'] ?? 'cn';
setcookie('site_lang', $langCode, time() + 86400 * 30, "/");

$i18n = [
    'cn' => [
        'title' => '阅后即焚', 'subtitle' => '安全加密 · 隐私保护',
        'desc' => '创建加密消息', 'nickname' => '昵称 (选填)',
        'note' => '标题 (选填)', 'pass_set' => '访问密码 (选填)',
        'pass_req' => '请输入访问密码', 'reads' => '阅读次数',
        'expiry' => '销毁时间', 'gen_btn' => '生成链接',
        'copy' => '复制', 'copied' => '已复制',
        'back' => '返回', 'edit' => '编辑', 'preview' => '预览',
        'placeholder' => '在此输入机密消息... (支持 Markdown)',
        'ready' => '链接已生成', 'ready_desc' => '有效阅读次数: %s',
        'msg_404' => '消息不存在或已销毁', 'msg_view' => '立即查看',
        'unlock' => '解锁', 'left' => '剩余: %s 次',
        'destroyed' => '已销毁', 'day' => '天', 'hour' => '时', 'min' => '分',
        'err_empty' => '内容为空', 'err_pass' => '密码错误',
        'sec_info' => '基础', 'sec_safe' => '安全',
        'upload_label' => '附件', 'upload_hint' => '最大 %sMB, 支持 %s',
        'download' => '下载附件', 'err_upload' => '文件不合法或过大',
        'max_limit' => '上限: %s', 'max_time' => '上限: %s',
        'file_ready' => '包含一个加密附件', 'select_file' => '点击选择文件...'
    ],
    'en' => [
        'title' => 'Burn Read', 'subtitle' => 'Secure & Private',
        'desc' => 'Create secure message', 'nickname' => 'Name (Opt)',
        'note' => 'Title (Opt)', 'pass_set' => 'Password (Opt)',
        'pass_req' => 'Password Required', 'reads' => 'Read Limit',
        'expiry' => 'Timer', 'gen_btn' => 'Generate',
        'copy' => 'Copy', 'copied' => 'Copied',
        'back' => 'Back', 'edit' => 'Edit', 'preview' => 'Preview',
        'placeholder' => 'Secret message... (Markdown)',
        'ready' => 'Link Ready', 'ready_desc' => 'Readable %s times',
        'msg_404' => 'Not found / Destroyed', 'msg_view' => 'View',
        'unlock' => 'Unlock', 'left' => '%s left',
        'destroyed' => 'Destroyed', 'day' => 'd', 'hour' => 'h', 'min' => 'm',
        'err_empty' => 'Empty content', 'err_pass' => 'Invalid Pass',
        'sec_info' => 'Info', 'sec_safe' => 'Security',
        'upload_label' => 'File', 'upload_hint' => 'Max %sMB, %s',
        'download' => 'Download File', 'err_upload' => 'Invalid File',
        'max_limit' => 'Max: %s', 'max_time' => 'Max: %s',
        'file_ready' => 'Contains encrypted file', 'select_file' => 'Click to select file...'
    ]
];
$L = $i18n[$langCode] ?? $i18n['cn'];

// --- 2. Crypto ---
function encrypt($data, $key) {
    global $keyEnv;
    $iv = random_bytes(16);
    $hashKey = hash_hmac('sha256', $key, $keyEnv, true);
    return base64_encode($iv . openssl_encrypt($data, 'aes-256-cbc', $hashKey, 0, $iv));
}
function decrypt($data, $key) {
    global $keyEnv;
    $data = base64_decode($data);
    if (strlen($data) < 16) return false;
    $iv = substr($data, 0, 16);
    $hashKey = hash_hmac('sha256', $key, $keyEnv, true);
    return openssl_decrypt(substr($data, 16), 'aes-256-cbc', $hashKey, 0, $iv);
}

// --- 3. Logic ---
$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
$isFile = isset($_GET['file'], $_GET['code']);

if ($isPost && !$isFile) {
    $content = $_POST['message'] ?? '';
    if (empty($content)) die($L['err_empty']);

    $encPaths = null; $encName = null;
    $randKey = bin2hex(random_bytes(16));

    if (!empty($_FILES['file']['name'])) {
        $f = $_FILES['file'];
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        if ($f['size'] > $uploadMaxMB * 1024 * 1024 || !in_array($ext, $allowedExts)) die($L['err_upload']);
        
        if (!is_dir('uploads')) mkdir('uploads', 0755, true);
        $encFileName = 'uploads/' . bin2hex(random_bytes(16)) . '.dat';
        file_put_contents($encFileName, encrypt(file_get_contents($f['tmp_name']), $randKey));
        $encPaths = $encFileName;
        $encName = encrypt($f['name'], $randKey);
    }

    $limit = min(max(intval($_POST['limit'] ?? 1), 1), $maxReads);
    $expS = (intval($_POST['d']??0)*86400) + (intval($_POST['h']??0)*3600) + (intval($_POST['m']??0)*60);
    if ($expS <= 0 || $expS > $maxSeconds) $expS = $maxSeconds;

    $verifyCode = bin2hex(random_bytes(4));
    $passHash = !empty($_POST['pass']) ? hash('sha256', $_POST['pass']) : null;

    $data = [
        'msg' => encrypt($content, $randKey),
        'name' => encrypt($_POST['name']??'', $randKey),
        'note' => encrypt($_POST['note']??'', $randKey),
        'file_path' => $encPaths, 'file_name' => $encName,
        'pass' => $passHash,
        'key_v' => encrypt($randKey, hash('sha256', $verifyCode)),
        'key_p' => $passHash ? encrypt($randKey, $passHash) : null,
        'code_h' => hash('sha256', $verifyCode),
        'time' => time(), 'exp' => $expS, 'reads' => $limit
    ];

    $fname = 'messages/' . bin2hex(random_bytes(8)) . '.json';
    if (!is_dir('messages')) mkdir('messages', 0755, true);
    file_put_contents($fname, json_encode($data));
    $link = $domain . "/?file=" . basename($fname) . "&code=" . $verifyCode;
    $successView = true;
}

if ($isFile) {
    $file = "messages/".basename($_GET['file']);
    $notFound = "<div class='glass p-8 rounded-2xl text-center max-w-sm mx-auto'><div class='text-4xl text-gray-400 mb-4'><i class='fas fa-wind'></i></div><div class='text-red-500 font-bold mb-6'>{$L['msg_404']}</div><a href='/' class='glass px-6 py-2 rounded-full text-blue-500 text-sm'>{$L['back']}</a></div>";
    
    if (!file_exists($file)) die($notFound);
    $data = json_decode(file_get_contents($file), true);
    if (time() - $data['time'] > $data['exp']) {
        if(!empty($data['file_path']) && file_exists($data['file_path'])) unlink($data['file_path']);
        unlink($file); die($notFound);
    }

    $passReq = !empty($data['pass']);
    $confirm = isset($_GET['confirm']);
    $showMsg = false; $err = '';

    if ($confirm) {
        $inHash = !empty($_POST['pass']) ? hash('sha256', $_POST['pass']) : null;
        $checkHash = $passReq ? $inHash : hash('sha256', $_GET['code']);
        
        if ($passReq && $inHash !== $data['pass']) { 
            $err = $L['err_pass']; 
        } else {
            $key = decrypt($passReq ? $data['key_p'] : $data['key_v'], $checkHash);
            if ($key) {
                $msg = decrypt($data['msg'], $key); 
                $name = decrypt($data['name'], $key);
                $note = decrypt($data['note'], $key);
                
                $downloadUrl = null; $fileName = null;
                if (!empty($data['file_path']) && file_exists($data['file_path'])) {
                    $fileName = decrypt($data['file_name'], $key);
                    $fileContent = decrypt(file_get_contents($data['file_path']), $key);
                    $b64 = base64_encode($fileContent);
                    $downloadUrl = "data:application/octet-stream;base64,$b64";
                }

                $data['reads']--;
                if ($data['reads'] <= 0) {
                    if(!empty($data['file_path']) && file_exists($data['file_path'])) unlink($data['file_path']);
                    unlink($file);
                } else file_put_contents($file, json_encode($data));
                
                $showMsg = true;
            } else $err = "Decryption Error";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?php echo $langCode; ?>" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $L['title']; ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { darkMode: 'class' }</script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"/>
    <?php if(!empty($env['SITE_ICON'])) echo '<link rel="icon" href="'.$env['SITE_ICON'].'">'; ?>
    <style>
        body { font-family: 'Inter', sans-serif; background: url('<?php echo $env['SITE_BACKGROUND']; ?>') no-repeat center center fixed; background-size: cover; }
        .glass { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.6); box-shadow: 0 4px 30px rgba(0, 0, 0, 0.05); }
        .dark .glass { background: rgba(20, 25, 40, 0.75); border: 1px solid rgba(255, 255, 255, 0.08); color: #e2e8f0; }
        .glass-input { background: rgba(255, 255, 255, 0.5); border: 1px solid rgba(255, 255, 255, 0.4); }
        .dark .glass-input { background: rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.1); color: white; }
        .glass-input:focus { background: rgba(255, 255, 255, 0.9); border-color: #3B82F6; }
        .markdown-body pre { background: rgba(0,0,0,0.05); padding: 0.8rem; border-radius: 0.5rem; overflow-x: auto; }
        .dark .markdown-body pre { background: rgba(0,0,0,0.4); }
        .markdown-body blockquote { border-left: 3px solid #60A5FA; padding-left: 0.8rem; color: #64748b; }
        .ctrl-btn { width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; border-radius: 4px; transition: 0.2s; }
        .ctrl-btn:hover { background: rgba(0,0,0,0.05); }
        .dark .ctrl-btn:hover { background: rgba(255,255,255,0.1); }
        /* Scrollbar */
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.2); border-radius: 2px; }
    </style>
</head>
<body class="min-h-screen flex flex-col text-gray-800 dark:text-gray-100">

<!-- Main -->
<div class="flex-grow flex items-center justify-center p-4">
    <div class="w-full max-w-5xl">

    <?php 
    function renderTools($L, $langCode) {
        $nextLang = $langCode==='cn'?'en':'cn';
        return "<div class='flex items-center gap-2 ml-3 pl-3 border-l border-gray-300 dark:border-gray-600 h-5'>
            <button type='button' onclick='toggleTheme()' class='ctrl-btn text-gray-500 dark:text-gray-400'><i class='fas fa-sun text-[10px] dark:hidden'></i><i class='fas fa-moon text-[10px] hidden dark:block'></i></button>
            <a href='?lang=$nextLang' class='ctrl-btn text-[9px] font-bold uppercase text-gray-500 dark:text-gray-400'>$nextLang</a></div>";
    }
    ?>

    <?php if (isset($successView)): ?>
        <div class="glass rounded-2xl p-8 max-w-md mx-auto text-center animate-fade-in">
            <div class="w-14 h-14 bg-gradient-to-tr from-green-400 to-green-600 text-white rounded-xl flex items-center justify-center mx-auto mb-4 text-2xl shadow-lg shadow-green-500/30"><i class="fas fa-check"></i></div>
            <h2 class="text-2xl font-bold mb-1"><?php echo $L['ready']; ?></h2>
            <p class="text-gray-500 text-xs mb-6"><?php echo sprintf($L['ready_desc'], $limit); ?></p>
            <div class="bg-white/50 dark:bg-black/30 border border-blue-200 dark:border-blue-800/50 rounded-lg p-3 mb-6 font-mono text-xs text-blue-600 dark:text-blue-400 break-all select-all shadow-inner"><?php echo $link; ?></div>
            <div class="flex gap-3 justify-center">
                <button onclick="copyLink('<?php echo $link; ?>')" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2.5 rounded-lg text-xs font-bold shadow-lg shadow-blue-500/20 transition-transform active:scale-95"><i class="fas fa-copy mr-1"></i><?php echo $L['copy']; ?></button>
                <a href="/" class="glass px-6 py-2.5 rounded-lg text-xs font-bold hover:bg-white/80 dark:hover:bg-white/10"><?php echo $L['back']; ?></a>
            </div>
        </div>

    <?php elseif ($isFile && $showMsg): ?>
        <div class="glass rounded-2xl w-full max-w-4xl h-[600px] flex flex-col relative overflow-hidden shadow-2xl mx-auto">
            <div class="px-6 py-4 border-b border-gray-200/50 dark:border-gray-700/50 flex justify-between items-center bg-white/30 dark:bg-black/10 backdrop-blur-sm z-10">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 text-white flex items-center justify-center shadow-lg shadow-blue-500/20"><i class="fas fa-user-secret"></i></div>
                    <div><div class="font-bold text-sm"><?php echo $name ?: 'Anonymous'; ?></div><?php if($note): ?><div class="text-[10px] text-gray-500 dark:text-gray-400"><?php echo htmlspecialchars($note); ?></div><?php endif; ?></div>
                </div>
                <div class="flex items-center gap-2">
                    <div class="px-2 py-1 rounded text-[10px] font-bold border border-emerald-500/20 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"><?php echo sprintf($L['left'], $data['reads']); ?></div>
                    <?php echo renderTools($L, $langCode); ?>
                </div>
            </div>

            <div class="flex-1 overflow-y-auto p-6 relative">
                <?php if($downloadUrl): ?>
                <div class="mb-6 p-3 rounded-xl bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-100 dark:border-blue-800 flex items-center justify-between shadow-sm animate-pulse">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-300 text-sm"><i class="fas fa-file-arrow-down"></i></div>
                        <div><div class="font-bold text-xs text-blue-900 dark:text-blue-200"><?php echo $L['file_ready']; ?></div><div class="text-[10px] text-blue-600 dark:text-blue-400 max-w-[150px] truncate"><?php echo htmlspecialchars($fileName); ?></div></div>
                    </div>
                    <a href="<?php echo $downloadUrl; ?>" download="<?php echo htmlspecialchars($fileName); ?>" class="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-[10px] font-bold rounded-lg shadow-lg shadow-blue-500/20 transition-all flex items-center gap-1"><i class="fas fa-download"></i> <?php echo $L['download']; ?></a>
                </div>
                <?php endif; ?>
                <div class="markdown-body text-sm leading-relaxed" id="content-view"></div>
                <textarea id="raw-content" class="hidden"><?php echo htmlspecialchars($msg); ?></textarea>
            </div>
        </div>
        <script>document.getElementById('content-view').innerHTML = marked.parse(document.getElementById('raw-content').value);</script>

    <?php elseif ($isFile && !$showMsg): ?>
        <div class="glass rounded-2xl p-10 max-w-sm mx-auto text-center relative shadow-xl">
            <div class="absolute top-4 right-4"><?php echo renderTools($L, $langCode); ?></div>
            <div class="mb-4 inline-block"><i class="fas <?php echo $passReq?'fa-lock':'fa-shield-halved'; ?> text-5xl bg-clip-text text-transparent bg-gradient-to-br from-blue-500 to-cyan-500 pb-1"></i></div>
            <h2 class="text-xl font-bold mb-1"><?php echo $passReq ? $L['pass_req'] : $L['msg_view']; ?></h2>
            <p class="text-xs text-gray-500 mb-6"><?php echo sprintf($L['left'], $data['reads']); ?></p>
            <?php if($err) echo "<div class='text-red-500 text-[10px] mb-4 bg-red-50 dark:bg-red-900/30 py-1.5 rounded font-medium'>$err</div>"; ?>
            <form method="post" action="?file=<?php echo $_GET['file']; ?>&code=<?php echo $_GET['code']; ?>&confirm=1">
                <?php if($passReq): ?>
                    <input type="password" name="pass" class="glass-input w-full px-4 py-2.5 rounded-xl mb-4 text-center outline-none text-base tracking-widest" placeholder="••••••" required autofocus>
                <?php endif; ?>
                <button class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white py-2.5 rounded-xl font-bold shadow-lg shadow-blue-500/25 transition-all"><?php echo $passReq ? $L['unlock'] : $L['msg_view']; ?></button>
            </form>
        </div>

    <?php else: ?>
        <!-- Create Screen -->
        <form method="post" enctype="multipart/form-data" class="grid grid-cols-1 lg:grid-cols-12 gap-4 w-full h-auto lg:h-[600px]">
            <!-- Settings -->
            <div class="lg:col-span-4 flex flex-col h-full">
                <div class="glass rounded-2xl p-5 h-full flex flex-col shadow-lg">
                    <div class="flex items-center gap-3 mb-5 shrink-0">
                        <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center text-white text-lg shadow-lg shadow-blue-500/30"><i class="fas fa-fire"></i></div>
                        <div><h1 class="font-bold text-lg leading-tight"><?php echo $L['title']; ?></h1><p class="text-[10px] text-gray-400"><?php echo $L['subtitle']; ?></p></div>
                    </div>
                    <div class="flex-1 overflow-y-auto pr-1 space-y-4 custom-scroll">
                        <div class="space-y-2">
                            <label class="text-[9px] font-bold text-gray-400 uppercase tracking-widest ml-1"><?php echo $L['sec_info']; ?></label>
                            <input type="text" name="name" class="glass-input w-full px-3 py-2 rounded-lg text-xs transition-all" placeholder="<?php echo $L['nickname']; ?>">
                            <input type="text" name="note" class="glass-input w-full px-3 py-2 rounded-lg text-xs transition-all" placeholder="<?php echo $L['note']; ?>">
                        </div>
                        <div class="space-y-3">
                            <label class="text-[9px] font-bold text-gray-400 uppercase tracking-widest ml-1"><?php echo $L['sec_safe']; ?></label>
                            <input type="password" name="pass" class="glass-input w-full px-3 py-2 rounded-lg text-xs transition-all" placeholder="<?php echo $L['pass_set']; ?>">
                            <div class="bg-white/30 dark:bg-black/10 rounded-lg p-2.5 border border-gray-100 dark:border-gray-700/50 space-y-2">
                                <div>
                                    <div class="flex justify-between text-[10px] mb-1 px-1 font-medium text-gray-600 dark:text-gray-300"><span><?php echo $L['reads']; ?></span><span class="text-blue-500 bg-blue-50 dark:bg-blue-900/30 px-1 rounded"><?php echo sprintf($L['max_limit'], $maxReads); ?></span></div>
                                    <div class="flex gap-2"><button type="button" onclick="adjLimit(-1)" class="w-7 h-7 rounded glass hover:bg-white dark:hover:bg-gray-700 text-gray-500 flex items-center justify-center">-</button><input type="number" id="limitInput" name="limit" value="1" readonly class="glass-input w-full text-center text-xs font-bold rounded bg-transparent"><button type="button" onclick="adjLimit(1)" class="w-7 h-7 rounded glass hover:bg-white dark:hover:bg-gray-700 text-gray-500 flex items-center justify-center">+</button></div>
                                </div>
                                <div>
                                    <div class="flex justify-between text-[10px] mb-1 px-1 font-medium text-gray-600 dark:text-gray-300"><span><?php echo $L['expiry']; ?></span><span class="text-gray-400"><?php echo sprintf($L['max_time'], $maxTimeStr); ?></span></div>
                                    <div class="grid grid-cols-3 gap-1.5"><?php foreach(['d'=>$L['day'],'h'=>$L['hour'],'m'=>$L['min']] as $k=>$v): ?><div class="relative"><input type="number" name="<?php echo $k; ?>" placeholder="0" class="glass-input w-full py-1.5 pl-1.5 pr-4 text-center text-[10px] rounded font-mono"><span class="absolute right-1.5 top-1.5 text-[9px] text-gray-400 pointer-events-none"><?php echo $v; ?></span></div><?php endforeach; ?></div>
                                </div>
                            </div>
                        </div>
                        <div class="pt-1">
                            <label class="text-[9px] font-bold text-gray-400 uppercase tracking-widest ml-1 mb-1 block"><?php echo $L['upload_label']; ?></label>
                            <!-- FIXED UPLOAD BUTTON -->
                            <div class="relative glass-input flex items-center gap-2 p-2 rounded-lg hover:bg-white/60 dark:hover:bg-black/40 transition-colors group">
                                <div class="bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 p-1.5 rounded group-hover:scale-110 transition-transform"><i class="fas fa-paperclip text-xs"></i></div>
                                <div id="fname" class="text-[10px] font-medium truncate opacity-70 flex-1"><?php echo $L['select_file']; ?></div>
                                <input type="file" name="file" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" onchange="document.getElementById('fname').innerText = this.files[0]?.name || '<?php echo $L['select_file']; ?>'">
                            </div>
                            <p class="text-[9px] text-gray-400 mt-1 ml-1"><?php echo sprintf($L['upload_hint'], $uploadMaxMB, implode(' ', $allowedExts)); ?></p>
                        </div>
                    </div>
                    <button class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white py-3 rounded-xl font-bold mt-3 shadow-lg shadow-blue-500/30 flex items-center justify-center gap-2 transition-all transform hover:-translate-y-0.5 text-sm shrink-0"><i class="fas fa-bolt"></i> <?php echo $L['gen_btn']; ?></button>
                </div>
            </div>

            <!-- Editor -->
            <div class="lg:col-span-8 h-full">
                <div class="glass rounded-2xl h-full flex flex-col p-1 relative overflow-hidden shadow-xl">
                    <div class="flex justify-between items-center px-4 py-2 border-b border-gray-200/50 dark:border-gray-700/50 bg-white/40 dark:bg-black/20 rounded-t-xl backdrop-blur-sm">
                        <div class="flex bg-gray-200/50 dark:bg-gray-700/50 rounded p-0.5">
                            <button type="button" onclick="tab('edit')" id="btn-edit" class="px-3 py-1 rounded text-[10px] bg-white dark:bg-gray-600 shadow-sm text-blue-600 dark:text-blue-300 font-bold transition-all"><?php echo $L['edit']; ?></button>
                            <button type="button" onclick="tab('prev')" id="btn-prev" class="px-3 py-1 rounded text-[10px] text-gray-500 dark:text-gray-400 hover:text-gray-700 transition-all"><?php echo $L['preview']; ?></button>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-[9px] font-bold text-gray-400 uppercase tracking-widest hidden sm:inline"><i class="fab fa-markdown mr-1"></i>Markdown</span>
                            <?php echo renderTools($L, $langCode); ?>
                        </div>
                    </div>
                    <div class="flex-1 relative group">
                        <textarea name="message" id="editor" class="absolute inset-0 w-full h-full bg-transparent p-5 outline-none resize-none text-gray-700 dark:text-gray-200 font-mono text-xs leading-relaxed" placeholder="<?php echo $L['placeholder']; ?>"></textarea>
                        <div id="preview" class="hidden absolute inset-0 w-full h-full bg-white/60 dark:bg-black/40 backdrop-blur-md p-5 overflow-y-auto markdown-body"></div>
                    </div>
                </div>
            </div>
        </form>
    <?php endif; ?>
    </div>
</div>

<!-- Footer -->
<footer class="py-4 text-center text-[10px] text-white/80 font-medium flex items-center justify-center gap-2 drop-shadow-md">
    <span>&copy; <?php echo date('Y'); ?> @Prince</span><span class="opacity-50">|</span>
    <a href="<?php echo $githubUrl; ?>" target="_blank" class="hover:scale-110 transition opacity-80 hover:opacity-100"><svg height="14" width="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg></a>
</footer>

<script>
    const maxR = <?php echo $maxReads; ?>;
    function adjLimit(d) { let v = parseInt(document.getElementById('limitInput').value) + d; document.getElementById('limitInput').value = Math.min(Math.max(v, 1), maxR); }
    function copyLink(txt) { navigator.clipboard.writeText(txt).then(() => alert('<?php echo $L['copied']; ?>')); }
    function toggleTheme() { const h = document.documentElement; h.classList.contains('dark') ? (h.classList.remove('dark'),localStorage.setItem('t','l')) : (h.classList.add('dark'),localStorage.setItem('t','d')); }
    if (localStorage.t === 'd' || (!('t' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) document.documentElement.classList.add('dark');
    function tab(t) {
        const ed=document.getElementById('editor'), pr=document.getElementById('preview'), be=document.getElementById('btn-edit'), bp=document.getElementById('btn-prev');
        const act='bg-white dark:bg-gray-600 shadow-sm text-blue-600 dark:text-blue-300 font-bold', inact='text-gray-500 dark:text-gray-400 hover:text-gray-700';
        if(t==='edit') { ed.classList.remove('hidden'); pr.classList.add('hidden'); be.className='px-3 py-1 rounded text-[10px] transition-all '+act; bp.className='px-3 py-1 rounded text-[10px] transition-all '+inact; }
        else { ed.classList.add('hidden'); pr.classList.remove('hidden'); pr.innerHTML=marked.parse(ed.value); bp.className='px-3 py-1 rounded text-[10px] transition-all '+act; be.className='px-3 py-1 rounded text-[10px] transition-all '+inact; }
    }
    document.getElementById('editor')?.addEventListener('keydown', function(e) { if (e.key == 'Tab') { e.preventDefault(); this.setRangeText("\t", this.selectionStart, this.selectionStart, "end"); } });
</script>
</body>
</html>