<?php
// ==========================================
// func.php - 核心逻辑配置 (MySQL版)
// ==========================================

// --- OAuth2 配置 ---
$CLIENT_ID = 'AMfmRA61Issgg0hONFPUf6NXDJPV5x9I';
$CLIENT_SECRET = 'R0zcaAU72LazaqoGv4gTrlMiFHsQNLgs';
$REDIRECT_URI = 'https://loli.000.moe/oauth_auto_login'; // 确保与LinuxDo后台一致
$AUTHORIZATION_ENDPOINT = 'https://connect.linux.do/oauth2/authorize';
$TOKEN_ENDPOINT = 'https://connect.linux.do/oauth2/token';
$USER_ENDPOINT = 'https://connect.linux.do/api/user';
$DOMIAN = 'linux.do'; 

// --- MySQL 数据库配置 ---
$DB_HOST = '127.0.0.1';   // 数据库地址 (如果是容器互联可能是 mysql 或 mariadb)
$DB_PORT = '3306';        // 端口
$DB_NAME = 'xboard';      // 数据库名 (请确认你的面板数据库名，可能是 v2board 或 xboard)
$DB_USER = 'root';        // 数据库用户名
$DB_PASS = 'Qaz369958';   // 数据库密码

// 核心 CURL 函数
function callbackFunc($code, $clientId, $clientSecret, $redirectUri) {
    global $TOKEN_ENDPOINT, $USER_ENDPOINT;
    $ch = curl_init($TOKEN_ENDPOINT);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'code' => $code,
        'redirect_uri' => $redirectUri,
        'grant_type' => 'authorization_code'
    ]));
  
    $tokenResponse = curl_exec($ch);
    curl_close($ch);
  
    $tokenData = json_decode($tokenResponse, true);
    if (!isset($tokenData['access_token'])) {
        return ['error' => 'access err', 'details' => $tokenData];
    }
  
    $ch = curl_init($USER_ENDPOINT);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $tokenData['access_token']
    ]);
  
    $userResponse = curl_exec($ch);
    curl_close($ch);
  
    return json_decode($userResponse, true);
}

// 跳转授权函数
function getoauth($sess){
    global $AUTHORIZATION_ENDPOINT, $CLIENT_ID, $REDIRECT_URI;
    $jump = $AUTHORIZATION_ENDPOINT . '?' . http_build_query([
        'client_id' => $CLIENT_ID,
        'redirect_uri' => $REDIRECT_URI,
        'response_type' => 'code',
        'state' => $sess
    ]);
    header('Location: ' . $jump, true, 302);
    exit();
}
    
// 回调处理函数 (等级限制 >= 2)
function ofmCallback($getCode){
    global $CLIENT_ID, $CLIENT_SECRET, $REDIRECT_URI;
    $userInfo = callbackFunc($getCode, $CLIENT_ID, $CLIENT_SECRET, $REDIRECT_URI);
  
    if (isset($userInfo['error'])) {
        exit('OAuth Error: ' . $userInfo['error']);
    } else {
        $username = $userInfo['username'];
        $trust_level = $userInfo['trust_level'];
        
        if ($trust_level < 2) {
            header('Content-Type: text/html; charset=utf-8');
            exit("<center><h1>等级不足</h1><p>本次内测仅限 LinuxDo 2级及以上用户参与。<br>你当前等级: {$trust_level}</p></center>");
        }
        return $username;
    }
}

function shengcpasswd($is_sess) {
    $bytes = random_bytes(16);
    if ($is_sess == true) {
        return substr(bin2hex($bytes), 0, 16);
    } else {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}

// 数据库操作函数 (MySQL版)
function getpasswd($user){
    global $DOMIAN, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS;
    $email = $user . '@' . $DOMIAN;
    
    try {
        // 连接 MySQL
        $dsn = "mysql:host={$DB_HOST};port={$DB_PORT};dbname={$DB_NAME};charset=utf8mb4";
        $pdo = new PDO($dsn, $DB_USER, $DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // 禁用模拟预处理，防止某些边缘情况下的注入
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

        // 1. 检查用户是否已存在
        $checkSql = "SELECT count(*) FROM v2_user WHERE email = :email";
        $checkStmt = $pdo->prepare($checkSql);
        $checkStmt->execute([':email' => $email]);
        
        if ($checkStmt->fetchColumn() > 0) {
            return 'exist'; // 返回已存在状态
        }

        // 2. 如果不存在，执行注册逻辑
        $passwd = shengcpasswd(false);
        $password = password_hash($passwd, PASSWORD_BCRYPT);
        
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        $uuid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
        
        $token = md5(uniqid(random_bytes(16), true));
        $now = time();

        $sql = "INSERT INTO v2_user (
            invite_user_id, telegram_id, email, password, password_algo, password_salt,
            balance, discount, commission_type, commission_rate, commission_balance,
            t, u, d, transfer_enable, banned, is_admin, last_login_at, is_staff,
            last_login_ip, uuid, group_id, plan_id, speed_limit, remind_expire,
            remind_traffic, token, expired_at, remarks, created_at, updated_at,
            device_limit, online_count, last_online_at, next_reset_at, last_reset_at,
            reset_count
        ) VALUES (
            NULL, NULL, :email, :password, NULL, NULL,
            0, NULL, 0, NULL, 0,
            0, 0, 0, 0, 0, 0, NULL, 0,
            NULL, :uuid, 1, 1, NULL, 1,
            1, :token, 0, NULL, :created_at, :updated_at,
            NULL, NULL, NULL, NULL, NULL,
            0
        )";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':email'      => $email,
            ':password'   => $password,
            ':uuid'       => $uuid,
            ':token'      => $token,
            ':created_at' => $now,
            ':updated_at' => $now
        ]);

        return $passwd;

    } catch (PDOException $e) {
        // 生产环境建议记录日志而不是直接输出错误，防止泄露敏感信息
        // 但为了方便你调试，暂时保留输出
        exit("Database Error: " . $e->getMessage());
    }
}
?>
