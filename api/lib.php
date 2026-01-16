<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function api_db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;

  if (STATS_DB_HOST === '' || STATS_DB_NAME === '' || STATS_DB_USER === '') {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'DB not configured'], JSON_UNESCAPED_UNICODE);
    exit;
  }

  $dsn = 'mysql:host=' . STATS_DB_HOST . ';dbname=' . STATS_DB_NAME . ';charset=' . STATS_DB_CHARSET;
  $pdo = new PDO($dsn, STATS_DB_USER, STATS_DB_PASS, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET SQL_MODE=''",
  ]);
  return $pdo;
}

function api_json($data, int $status = 200): void {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
  exit;
}

function api_bad_request(string $msg = 'bad request'): void {
  api_json(['error' => $msg], 400);
}

function api_not_found(): void {
  api_json(['error' => 'not found'], 404);
}

function api_limit(int $n): int {
  if ($n < 1) $n = 1;
  $max = (int)API_MAX_LIMIT;
  if ($n > $max) $n = $max;
  return $n;
}

function api_param_str(string $key, string $default = ''): string {
  $v = $_GET[$key] ?? $default;
  if (!is_string($v)) return $default;
  return trim($v);
}

function api_param_int(string $key, int $default = 0): int {
  $v = $_GET[$key] ?? null;
  if ($v === null) return $default;
  return (int)$v;
}

function api_iso8601_utc(?string $ts): ?string {
  if ($ts === null) return null;
  $t = strtotime($ts);
  return $t ? gmdate('c', $t) : null;
}

// Accept dashed UUID or 32-hex; returns 32-hex lowercase or null
function api_uuid_hex(?string $raw): ?string {
  if ($raw === null) return null;
  $hex = strtolower(preg_replace('/[^0-9a-f]/i', '', $raw));
  if (strlen($hex) !== 32) return null;
  return $hex;
}

function api_uuid_hex_to_bin(string $hex32): string {
  // returns 16-byte string
  return hex2bin($hex32) ?: "";
}

function api_uuid_bin_to_dashed(string $bin16): string {
  $hex = bin2hex($bin16);
  return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
}

function api_cache_headers(string $etag, int $maxAge, ?int $lastModifiedTs = null): void {
  header('Cache-Control: public, max-age=' . $maxAge);
  header('ETag: "' . $etag . '"');
  if ($lastModifiedTs !== null) {
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $lastModifiedTs) . ' GMT');
  }

  $inm = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));
  if ($inm !== '' && trim($inm, '"') === $etag) {
    http_response_code(304);
    exit;
  }
  $ims = (string)($_SERVER['HTTP_IF_MODIFIED_SINCE'] ?? '');
  if ($lastModifiedTs !== null && $ims !== '' && strtotime($ims) >= $lastModifiedTs) {
    http_response_code(304);
    exit;
  }
}

function api_active_run(PDO $pdo): array {
  $row = $pdo->query("SELECT s.active_run_id AS run_id, r.generated_at AS generated_at
                      FROM site_state s
                      LEFT JOIN import_run r ON r.id = s.active_run_id
                      WHERE s.id=1")->fetch();
  return [
    'run_id' => $row ? (int)($row['run_id'] ?? 0) : 0,
    'generated_at' => $row['generated_at'] ?? null,
  ];
}

// Cursor is base64url of "value:uuidhex" (value is int)
function api_encode_cursor(int $value, string $uuidHex32): string {
  $plain = $value . ':' . strtolower($uuidHex32);
  $b64 = rtrim(strtr(base64_encode($plain), '+/', '-_'), '=');
  return $b64;
}

function api_decode_cursor(string $cursor): ?array {
  $cursor = trim($cursor);
  if ($cursor === '') return null;
  $b64 = strtr($cursor, '-_', '+/');
  $pad = strlen($b64) % 4;
  if ($pad) $b64 .= str_repeat('=', 4 - $pad);
  $plain = base64_decode($b64, true);
  if ($plain === false) return null;
  $parts = explode(':', $plain, 2);
  if (count($parts) !== 2) return null;
  $val = (int)$parts[0];
  $uuidHex = api_uuid_hex($parts[1]);
  if ($uuidHex === null) return null;
  return ['value' => $val, 'uuid_hex' => $uuidHex];
}

