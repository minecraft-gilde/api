<?php
declare(strict_types=1);

// ===== API Konfiguration =====
// Trage hier die DB-Daten ein (MariaDB 10.11+)

define('STATS_DB_HOST', '');
define('STATS_DB_NAME', '');
define('STATS_DB_USER', '');
define('STATS_DB_PASS', '');
define('STATS_DB_CHARSET', 'utf8mb4');

// ===== Limits =====
// hartes Limit für alle Listen-Endpunkte

define('API_MAX_LIMIT', 100);

// Suchlimit (Autocomplete)

define('API_MAX_SEARCH', 25);

// Cache (Sekunden).

define('API_CACHE_LEADERBOARDS', 60);
define('API_CACHE_METRICS', 3600);
define('API_CACHE_PLAYER', 60);

// Kleine Übersichten / KPIs
define('API_CACHE_SUMMARY', 60);
