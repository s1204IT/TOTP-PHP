<?php

declare(strict_types=1);

function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    $c = require 'config.php';
    $pdo = new PDO($c['dsn'], $c['user'], $c['pass'], [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    // If table is not exists, create table.
    $pdo->exec('CREATE TABLE IF NOT EXISTS accounts (
        id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        issuer      VARCHAR(100) NOT NULL DEFAULT \'\',
        label       VARCHAR(190) NOT NULL,
        secret      VARCHAR(128) NOT NULL,
        digits      TINYINT UNSIGNED NOT NULL DEFAULT 6,
        period      SMALLINT UNSIGNED NOT NULL DEFAULT 30,
        algo        ENUM(\'SHA1\',\'SHA256\',\'SHA512\') NOT NULL DEFAULT \'SHA1\',
        sort_order  INT NOT NULL DEFAULT 0,
        created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    return $pdo;
}

// TOTP (RFC 6238 / RFC 4226)
function b32decode(string $s): string
{
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $buf = 0;
    $bits = 0;
    $out = '';
    foreach (str_split($s) as $ch) {
        $v = strpos($alpha, $ch);
        if ($v === false) throw new InvalidArgumentException('Invalid Base32');
        $buf = ($buf << 5) | $v;
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $out .= chr(($buf >> $bits) & 0xff);
            $buf &= (1 << $bits) - 1;
        }
    }
    return $out;
}

function totp_code(string $b32secret, int $digits, int $period, string $algo, int $time): string
{
    $counter = intdiv($time, $period);
    $hash = hash_hmac(strtolower($algo), pack('J', $counter), b32decode($b32secret), true);
    $o = ord($hash[strlen($hash) - 1]) & 0x0f;
    $n = ((ord($hash[$o]) & 0x7f) << 24) | (ord($hash[$o + 1]) << 16)
        | (ord($hash[$o + 2]) << 8) | ord($hash[$o + 3]);
    return str_pad((string)($n % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

function parse_otpauth(string $uri): array
{
    $u = parse_url(trim($uri));
    if (($u['scheme'] ?? '') === 'otpauth-migration') {
        throw new InvalidArgumentException('Do not support migration.');
    }
    if (($u['scheme'] ?? '') !== 'otpauth' || ($u['host'] ?? '') !== 'totp') {
        throw new InvalidArgumentException('Please start for "otpauth://totp/"');
    }
    parse_str($u['query'] ?? '', $q);
    $path = rawurldecode(ltrim($u['path'] ?? '', '/'));
    $issuer = (string)($q['issuer'] ?? '');
    $label = $path;
    if (str_contains($path, ':')) {
        [$i, $l] = explode(':', $path, 2);
        if ($issuer === '') $issuer = trim($i);
        $label = trim($l);
    }
    return [
        'issuer' => $issuer,
        'label' => $label,
        'secret' => (string)($q['secret'] ?? ''),
        'digits' => $q['digits'] ?? 6,
        'period' => $q['period'] ?? 30,
        'algo'   => $q['algorithm'] ?? 'SHA1',
    ];
}

function normalize_account(array $a): array
{
    $issuer = mb_substr(trim((string)($a['issuer'] ?? '')), 0, 100);
    $label  = mb_substr(trim((string)($a['label'] ?? '')), 0, 190);
    if ($issuer === '' && $label === '') throw new InvalidArgumentException('Enter service or account name');

    $secret = strtoupper(preg_replace('/[\s=-]+/', '', (string)($a['secret'] ?? '')));
    if (!preg_match('/^[A-Z2-7]{8,128}$/', $secret)) {
        throw new InvalidArgumentException('Please enter Base32 code');
    }
    $digits = (int)($a['digits'] ?? 6);
    $period = (int)($a['period'] ?? 30);
    $algo   = strtoupper((string)($a['algo'] ?? 'SHA1'));
    if ($digits < 6 || $digits > 8)    throw new InvalidArgumentException('Digits is 6~8');
    if ($period < 15 || $period > 120) throw new InvalidArgumentException('Period is 15~120sec');
    if (!in_array($algo, ['SHA1', 'SHA256', 'SHA512'], true)) throw new InvalidArgumentException('No such algolithm');

    return compact('issuer', 'label', 'secret', 'digits', 'period', 'algo');
}
