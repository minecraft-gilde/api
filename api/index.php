<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

// Preflight / OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  header('Allow: GET, OPTIONS');
  header('Cache-Control: no-store');
  exit;
}

$pdo = api_db();
$active = api_active_run($pdo);
$generatedISO = api_iso8601_utc($active['generated_at'] ?? null);

// Routing (path-based)
$path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?? '';
$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/api/index.php')), '/');
if ($base === '') $base = '/';
$route = trim(substr($path, strlen($base)), '/');
if ($route === '') $route = api_param_str('route', '');

// ===== Helpers =====
function respond_with_generated(array $payload, ?string $generatedISO): void {
  $payload['__generated'] = $generatedISO;
  api_json($payload);
}

function load_metric_defs(PDO $pdo): array {
  // divisor/decimals sind bei dir per Patch/Seed vorhanden.
  $rows = $pdo->query("SELECT id, label, category, unit, sort_order, enabled,
                              COALESCE(divisor, NULL) AS divisor,
                              COALESCE(decimals, NULL) AS decimals
                       FROM metric_def
                       WHERE enabled=1
                       ORDER BY sort_order ASC, id ASC")->fetchAll();
  $defs = [];
  foreach ($rows as $r) {
    $defs[$r['id']] = [
      'label' => $r['label'],
      'category' => $r['category'],
      'unit' => $r['unit'],
      'sort_order' => (int)$r['sort_order'],
      'divisor' => $r['divisor'] !== null ? (int)$r['divisor'] : null,
      'decimals' => $r['decimals'] !== null ? (int)$r['decimals'] : null,
    ];
  }
  return $defs;
}

function apply_divisor(int $raw, ?int $divisor): float|int {
  if ($divisor !== null && $divisor > 0) {
    return $raw / $divisor;
  }
  return $raw;
}

function fetch_players_by_hex(PDO $pdo, array $uuidHexList): array {
  // returns dashed_uuid => name
  $uuidHexList = array_values(array_unique(array_filter($uuidHexList)));
  if (empty($uuidHexList)) return [];

  $out = [];
  $chunkSize = 800;
  for ($i = 0; $i < count($uuidHexList); $i += $chunkSize) {
    $chunk = array_slice($uuidHexList, $i, $chunkSize);
    $ph = implode(',', array_fill(0, count($chunk), 'UNHEX(?)'));
    $stmt = $pdo->prepare("SELECT LOWER(HEX(uuid)) AS uuid_hex, name
                           FROM v_player_profile
                           WHERE uuid IN ($ph)");
    $stmt->execute($chunk);
    while ($r = $stmt->fetch()) {
      $hex = strtolower($r['uuid_hex']);
      $dash = substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
      $out[$dash] = $r['name'] ?? $dash;
    }
  }
  return $out;
}

// ===== Endpoints =====
try {
  if ($route === 'metrics') {
    // Meta für Frontend
    $defs = load_metric_defs($pdo);
    $etag = sha1('metrics:' . ($active['run_id'] ?? 0));
    api_cache_headers($etag, (int)API_CACHE_METRICS, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);

    respond_with_generated([
      'metrics' => $defs,
    ], $generatedISO);
  }

  if ($route === 'summary') {
    // Leichtgewichtige Übersicht (Server-KPIs + Spieleranzahl)
    // Beispiel: /api/summary?metrics=hours,distance,mob_kills,creeper
    $metricsRaw = api_param_str('metrics', '');
    $requested = array_values(array_unique(array_filter(array_map('trim', explode(',', $metricsRaw)))));
    if (empty($requested)) api_bad_request('metrics required');
    if (count($requested) > 12) api_bad_request('too many metrics');

    $defs = load_metric_defs($pdo);
    foreach ($requested as $m) {
      if (!isset($defs[$m])) api_bad_request('unknown metric');
    }

    $etag = sha1('summary:' . ($active['run_id'] ?? 0) . ':' . implode(',', $requested));
    api_cache_headers($etag, (int)API_CACHE_SUMMARY, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);

    // Player count (View ist bereits active-run-sicher)
    $row = $pdo->query("SELECT COUNT(*) AS c FROM v_player_profile")->fetch();
    $playerCount = (int)($row['c'] ?? 0);

    // Totals per requested metric
    $totals = array_fill_keys($requested, 0);
    $ph = implode(',', array_fill(0, count($requested), '?'));
    $stmt = $pdo->prepare("SELECT metric_id, SUM(value) AS total_raw
                           FROM v_metric_value
                           WHERE metric_id IN ($ph)
                           GROUP BY metric_id");
    $stmt->execute($requested);
    while ($r = $stmt->fetch()) {
      $id = (string)($r['metric_id'] ?? '');
      if ($id === '' || !isset($totals[$id])) continue;
      // SUM() kann als string zurückkommen – auf 64bit ist das ok
      $raw = (int)($r['total_raw'] ?? 0);
      $totals[$id] = apply_divisor($raw, $defs[$id]['divisor']);
    }

    respond_with_generated([
      'player_count' => $playerCount,
      'totals' => $totals,
    ], $generatedISO);
  }

  if ($route === 'leaderboards') {
    $limit = api_limit(api_param_int('limit', 50));
    $limitPlus = min($limit + 1, API_MAX_LIMIT + 1);

    $defs = load_metric_defs($pdo);
    if (empty($defs) || ($active['run_id'] ?? 0) === 0) {
      respond_with_generated(['__players' => new stdClass(), 'boards' => new stdClass(), 'cursors' => new stdClass()], $generatedISO);
    }

    $etag = sha1('boards:' . ($active['run_id'] ?? 0) . ':' . $limit);
    api_cache_headers($etag, (int)API_CACHE_LEADERBOARDS, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);

    // One query: Top (limit+1) per metric via window function
    $stmt = $pdo->prepare(
      "SELECT metric_id, uuid, value, rn
       FROM (
         SELECT mv.metric_id, mv.uuid, mv.value,
                ROW_NUMBER() OVER (PARTITION BY mv.metric_id ORDER BY mv.value DESC, mv.uuid ASC) AS rn
         FROM v_metric_value mv
         JOIN metric_def md ON md.id = mv.metric_id AND md.enabled=1
       ) t
       WHERE rn <= :lim
       ORDER BY metric_id ASC, rn ASC"
    );
    $stmt->bindValue(':lim', $limitPlus, PDO::PARAM_INT);
    $stmt->execute();

    $boards = [];
    $cursors = [];
    $needNamesHex = [];

    // track for cursor
    $countByMetric = [];
    $lastIncluded = [];

    while ($r = $stmt->fetch()) {
      $metric = (string)$r['metric_id'];
      if (!isset($defs[$metric])) continue;

      $rn = (int)$r['rn'];
      $rawVal = (int)$r['value'];
      $uuidBin = $r['uuid'];
      if (!is_string($uuidBin) || strlen($uuidBin) !== 16) continue;

      $uuidHex = strtolower(bin2hex($uuidBin));
      $uuidDash = substr($uuidHex, 0, 8) . '-' . substr($uuidHex, 8, 4) . '-' . substr($uuidHex, 12, 4) . '-' . substr($uuidHex, 16, 4) . '-' . substr($uuidHex, 20, 12);

      $countByMetric[$metric] = ($countByMetric[$metric] ?? 0) + 1;

      if ($rn <= $limit) {
        $boards[$metric] ??= [];
        $boards[$metric][] = [
          'uuid' => $uuidDash,
          'value' => apply_divisor($rawVal, $defs[$metric]['divisor']),
        ];
        $needNamesHex[] = $uuidHex;
        if ($rn === $limit) {
          $lastIncluded[$metric] = ['raw' => $rawVal, 'uuid_hex' => $uuidHex];
        }
      } else {
        // this metric has more than limit
        $cursors[$metric] = '...';
      }
    }

    // Fill cursors: only if we saw an extra row
    foreach (array_keys($defs) as $metricId) {
      if (isset($cursors[$metricId]) && isset($lastIncluded[$metricId])) {
        $cursors[$metricId] = api_encode_cursor((int)$lastIncluded[$metricId]['raw'], (string)$lastIncluded[$metricId]['uuid_hex']);
      } else {
        $cursors[$metricId] = null;
      }
      if (!isset($boards[$metricId])) {
        $boards[$metricId] = [];
      }
    }

    $players = fetch_players_by_hex($pdo, $needNamesHex);

    respond_with_generated([
      '__players' => $players,
      'boards' => $boards,
      'cursors' => $cursors,
    ], $generatedISO);
  }

  if ($route === 'leaderboard') {
    $metric = api_param_str('metric', '');
    if ($metric === '') api_bad_request('metric required');

    $limit = api_limit(api_param_int('limit', 200));
    $limitPlus = min($limit + 1, API_MAX_LIMIT + 1);
    $cursorRaw = api_param_str('cursor', '');
    $cursor = $cursorRaw !== '' ? api_decode_cursor($cursorRaw) : null;

    $defs = load_metric_defs($pdo);
    if (!isset($defs[$metric])) api_bad_request('unknown metric');

    $etag = sha1('board:' . ($active['run_id'] ?? 0) . ':' . $metric . ':' . $limit . ':' . $cursorRaw);
    api_cache_headers($etag, (int)API_CACHE_LEADERBOARDS, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);

    $sql = "SELECT uuid, value
            FROM v_metric_value
            WHERE metric_id = :metric";
    $params = [':metric' => $metric];

    if ($cursor) {
      $sql .= " AND (value < :v OR (value = :v AND uuid > UNHEX(:u)))";
      $params[':v'] = (int)$cursor['value'];
      $params[':u'] = (string)$cursor['uuid_hex'];
    }

    $sql .= " ORDER BY value DESC, uuid ASC LIMIT :lim";

    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':metric', $metric, PDO::PARAM_STR);
    if ($cursor) {
      $stmt->bindValue(':v', (int)$params[':v'], PDO::PARAM_INT);
      $stmt->bindValue(':u', (string)$params[':u'], PDO::PARAM_STR);
    }
    $stmt->bindValue(':lim', $limitPlus, PDO::PARAM_INT);
    $stmt->execute();

    $list = [];
    $needNamesHex = [];

    $rowNum = 0;
    $lastRaw = null;
    $lastUuidHex = null;
    $hasMore = false;

    while ($r = $stmt->fetch()) {
      $rowNum++;
      $uuidBin = $r['uuid'];
      if (!is_string($uuidBin) || strlen($uuidBin) !== 16) continue;
      $rawVal = (int)$r['value'];

      $uuidHex = strtolower(bin2hex($uuidBin));
      $uuidDash = substr($uuidHex, 0, 8) . '-' . substr($uuidHex, 8, 4) . '-' . substr($uuidHex, 12, 4) . '-' . substr($uuidHex, 16, 4) . '-' . substr($uuidHex, 20, 12);

      if ($rowNum <= $limit) {
        $list[] = ['uuid' => $uuidDash, 'value' => apply_divisor($rawVal, $defs[$metric]['divisor'])];
        $needNamesHex[] = $uuidHex;
        $lastRaw = $rawVal;
        $lastUuidHex = $uuidHex;
      } else {
        $hasMore = true;
        break;
      }
    }

    $nextCursor = null;
    if ($hasMore && $lastRaw !== null && $lastUuidHex !== null) {
      $nextCursor = api_encode_cursor((int)$lastRaw, (string)$lastUuidHex);
    }

    $players = fetch_players_by_hex($pdo, $needNamesHex);

    respond_with_generated([
      '__players' => $players,
      'boards' => [ $metric => $list ],
      'cursors' => [ $metric => $nextCursor ],
    ], $generatedISO);
  }

  if ($route === 'players') {
    $q = api_param_str('q', '');
    $q = mb_strtolower($q);
    if (strlen($q) < 2) {
      respond_with_generated(['items' => []], $generatedISO);
    }

    $limit = api_limit(min(api_param_int('limit', 8), (int)API_MAX_SEARCH));

    $stmt = $pdo->prepare("SELECT LOWER(HEX(uuid)) AS uuid_hex, name
                           FROM v_player_profile
                           WHERE name_lc LIKE CONCAT(:q, '%')
                           ORDER BY name_lc ASC, uuid ASC
                           LIMIT :lim");
    $stmt->bindValue(':q', $q, PDO::PARAM_STR);
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();

    $items = [];
    while ($r = $stmt->fetch()) {
      $hex = strtolower((string)$r['uuid_hex']);
      if (strlen($hex) !== 32) continue;
      $dash = substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
      $items[] = ['uuid' => $dash, 'name' => $r['name']];
    }

    $etag = sha1('players:' . ($active['run_id'] ?? 0) . ':' . $q . ':' . $limit);
    api_cache_headers($etag, 30, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);

    respond_with_generated(['items' => $items], $generatedISO);
  }

  if ($route === 'player') {
    $rawUuid = api_param_str('uuid', api_param_str('player', ''));
    $uuidHex = api_uuid_hex($rawUuid);
    if ($uuidHex === null) api_bad_request('invalid uuid');

    $etagBase = 'player:' . ($active['run_id'] ?? 0) . ':' . $uuidHex;

    // Look up profile + stats
    $stmt = $pdo->prepare("SELECT LOWER(HEX(p.uuid)) AS uuid_hex, p.name,
                                  ps.stats_gzip, ps.stats_sha1
                           FROM v_player_profile p
                           LEFT JOIN v_player_stats ps ON ps.uuid = p.uuid
                           WHERE p.uuid = UNHEX(:u)
                           LIMIT 1");
    $stmt->bindValue(':u', $uuidHex, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();

    if (!$row) {
      $etag = sha1($etagBase . ':nf');
      api_cache_headers($etag, (int)API_CACHE_PLAYER, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);
      respond_with_generated(['found' => false, 'uuid' => $rawUuid, 'name' => null, 'player' => null], $generatedISO);
    }

    $hex = strtolower((string)$row['uuid_hex']);
    $uuidDash = substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
    $sha1bin = $row['stats_sha1'] ?? null;
    $sha1hex = (is_string($sha1bin) && strlen($sha1bin) === 20) ? bin2hex($sha1bin) : '';

    $etag = sha1($etagBase . ':' . $sha1hex);
    api_cache_headers($etag, (int)API_CACHE_PLAYER, $active['generated_at'] ? strtotime((string)$active['generated_at']) : null);

    $statsGzip = $row['stats_gzip'] ?? null;
    $statsObj = null;

    if (is_string($statsGzip) && $statsGzip !== '') {
      $json = @gzdecode($statsGzip);
      if ($json === false) {
        // Falls der Host gzip nicht versteht (unwahrscheinlich) oder schon JSON ist
        $json = $statsGzip;
      }
      $decoded = json_decode($json, true);
      if (is_array($decoded)) {
        $statsObj = $decoded;
      } else {
        $statsObj = null;
      }
    }

    respond_with_generated([
      'found' => true,
      'uuid' => $uuidDash,
      'name' => $row['name'] ?? $uuidDash,
      'player' => $statsObj,
    ], $generatedISO);
  }



  if ($route === 'profile') {
    // Mojang sessionserver proxy (für Skins/Capes) + Cache
    $uuid = api_param_str('uuid', api_param_str('profile', ''));
    $uuid = preg_replace('/[^0-9a-f]/i', '', (string)$uuid);

    if (strlen($uuid) !== 32) {
      http_response_code(400);
      header('Content-Type: application/json; charset=utf-8');
      header('Cache-Control: no-store');
      echo json_encode(['error' => 'invalid uuid'], JSON_UNESCAPED_UNICODE);
      exit;
    }

    header('Content-Type: application/json; charset=utf-8');

    $cacheDir  = __DIR__ . '/cache';
    $cacheFile = $cacheDir . '/profile-' . $uuid . '.json';
    $lockFile  = $cacheDir . '/profile-' . $uuid . '.lock';

    $ttlFresh        = 6 * 3600; // 6h
    $ttlNegative     = 10 * 60;  // 10m
    $ttlStaleOnError = 30;       // 30s

    if (!is_dir($cacheDir) && !mkdir($cacheDir, 0775, true) && !is_dir($cacheDir)) {
      http_response_code(500);
      header('Cache-Control: no-store');
      echo json_encode(['error' => 'cannot create cache dir'], JSON_UNESCAPED_UNICODE);
      exit;
    }
    if (!is_writable($cacheDir)) {
      http_response_code(500);
      header('Cache-Control: no-store');
      echo json_encode(['error' => 'cache dir not writable'], JSON_UNESCAPED_UNICODE);
      exit;
    }

    $sendCached = function (int $maxAge) use ($cacheFile): void {
      if (!is_file($cacheFile)) {
        http_response_code(404);
        header('Cache-Control: no-store');
        echo '{}';
        return;
      }
      clearstatcache(true, $cacheFile);
      $mtime = filemtime($cacheFile) ?: time();
      $size  = filesize($cacheFile) ?: 0;
      $etag  = sha1($mtime . ':' . $size);
      api_cache_headers($etag, $maxAge, $mtime);
      readfile($cacheFile);
    };

    if (is_file($cacheFile) && (time() - (filemtime($cacheFile) ?: 0)) < $ttlFresh) {
      $sendCached($ttlFresh);
      exit;
    }

    $lockFp = @fopen($lockFile, 'c');
    if ($lockFp) {
      @flock($lockFp, LOCK_EX);
    }

    if (is_file($cacheFile) && (time() - (filemtime($cacheFile) ?: 0)) < $ttlFresh) {
      if ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); }
      $sendCached($ttlFresh);
      exit;
    }

    $url = "https://sessionserver.mojang.com/session/minecraft/profile/$uuid";
    $ctx = stream_context_create([
      'http' => [
        'timeout' => 3,
        'ignore_errors' => true,
        'header' => "Accept: application/json\r\nUser-Agent: minecraft-gilde.de api\r\n",
      ],
      'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
      ],
    ]);

    $body = @file_get_contents($url, false, $ctx);

    $status = 0;
    if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
      $status = (int)$m[1];
    }

    if ($status === 200 && is_string($body) && $body !== '') {
      json_decode($body, true);
      if (json_last_error() === JSON_ERROR_NONE) {
        $tmp = $cacheFile . '.' . bin2hex(random_bytes(6)) . '.tmp';
        file_put_contents($tmp, $body, LOCK_EX);
        rename($tmp, $cacheFile);
        if ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); }
        $sendCached($ttlFresh);
        exit;
      }
    }

    if (in_array($status, [204, 404], true)) {
      $tmp = $cacheFile . '.' . bin2hex(random_bytes(6)) . '.tmp';
      file_put_contents($tmp, '{}', LOCK_EX);
      rename($tmp, $cacheFile);
      if ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); }
      $sendCached($ttlNegative);
      exit;
    }

    // Fehler: stale cache falls vorhanden
    if (is_file($cacheFile)) {
      if ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); }
      $sendCached($ttlStaleOnError);
      exit;
    }

    if ($lockFp) { @flock($lockFp, LOCK_UN); @fclose($lockFp); }
    http_response_code(502);
    header('Cache-Control: no-store');
    echo json_encode(['error' => 'upstream error', 'status' => $status], JSON_UNESCAPED_UNICODE);
    exit;
  }

  // Unknown route
  api_not_found();

} catch (Throwable $e) {
  // Keine Details leaken
  api_json(['error' => 'server error'], 500);
}
