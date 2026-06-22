-- ============================================================
-- FiveM / RageMP / AltV Cheat Detection Database
-- Schema Version: 1.0
-- Compatible: SQLite 3 / PostgreSQL / MySQL
-- ============================================================

PRAGMA foreign_keys = ON;

-- Plattformen
CREATE TABLE IF NOT EXISTS platforms (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE,   -- 'fivem', 'ragamp', 'altv', 'common'
    display_name TEXT NOT NULL,
    description  TEXT
);

-- Bekannte Cheats / Cheat-Tools
CREATE TABLE IF NOT EXISTS cheats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    platform_id     INTEGER NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    aliases         TEXT,                       -- kommagetrennte alternative Namen
    cheat_type      TEXT    NOT NULL DEFAULT 'menu',  -- 'menu','injector','bypass','trainer','esp','dumper','script'
    paid            INTEGER NOT NULL DEFAULT 0, -- 0=free, 1=paid
    status          TEXT    NOT NULL DEFAULT 'active', -- 'active','inactive','detected','patched'
    confidence      TEXT    NOT NULL DEFAULT 'high',   -- 'confirmed','high','medium','low'
    description     TEXT,
    source_url      TEXT,                       -- Referenz / Report-Link
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Prozess-Namen (laufende .exe zugehörig zum Cheat)
CREATE TABLE IF NOT EXISTS process_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id    INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    process_name TEXT   NOT NULL,  -- z.B. "eulen.exe"
    description  TEXT
);

-- DLL / Modul-Namen (im Spielprozess injizierte Bibliotheken)
CREATE TABLE IF NOT EXISTS module_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id    INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    module_name TEXT    NOT NULL,  -- z.B. "eulen.dll"
    description TEXT
);

-- Fenster-Titel (CreateWindow / SetWindowText)
CREATE TABLE IF NOT EXISTS window_signatures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id     INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    window_title TEXT    NOT NULL,
    window_class TEXT,             -- interne WinAPI Klassenname
    is_overlay   INTEGER NOT NULL DEFAULT 0,
    description  TEXT
);

-- Mutex-Namen (verhindert Mehrfachinstanzen)
CREATE TABLE IF NOT EXISTS mutex_signatures (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id   INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    mutex_name TEXT    NOT NULL,
    description TEXT
);

-- Named Pipes (IPC zwischen Cheat-Komponenten)
CREATE TABLE IF NOT EXISTS pipe_signatures (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id  INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    pipe_name TEXT    NOT NULL,   -- z.B. "\\\\.\\pipe\\eulen"
    description TEXT
);

-- Allgemeine Strings (Speicher-Strings, Export-Namen, GUI-Texte)
CREATE TABLE IF NOT EXISTS string_signatures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id     INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    string_value TEXT    NOT NULL,
    string_type  TEXT    NOT NULL DEFAULT 'general',
    -- 'general' | 'export_name' | 'gui_label' | 'config_key' |
    -- 'class_name' | 'watermark' | 'debug_string' | 'network_agent'
    case_sensitive INTEGER NOT NULL DEFAULT 1,
    description  TEXT
);

-- Dateipfade (auf der Festplatte hinterlassene Dateien)
CREATE TABLE IF NOT EXISTS file_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id    INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    file_path   TEXT    NOT NULL,  -- %APPDATA%, %TEMP%, absolute Pfade
    file_type   TEXT    NOT NULL DEFAULT 'any',  -- 'exe','dll','config','log','any'
    description TEXT
);

-- Registry-Einträge
CREATE TABLE IF NOT EXISTS registry_signatures (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id       INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    registry_key   TEXT    NOT NULL,
    registry_value TEXT,
    description    TEXT
);

-- Netzwerk-IOCs (Domains / IPs für Auth, Updates, C2)
CREATE TABLE IF NOT EXISTS network_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id    INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    ioc_type    TEXT    NOT NULL DEFAULT 'domain',  -- 'domain','ip','url','user_agent'
    value       TEXT    NOT NULL,
    description TEXT
);

-- Speicher-Muster (Hex-Byte-Signaturen, ?? = Wildcard)
CREATE TABLE IF NOT EXISTS memory_patterns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cheat_id    INTEGER NOT NULL REFERENCES cheats(id) ON DELETE CASCADE,
    pattern     TEXT    NOT NULL,   -- z.B. "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    pattern_type TEXT   NOT NULL DEFAULT 'code',  -- 'code','data','string_ref'
    target_module TEXT,             -- in welchem Modul suchen
    description TEXT
);

-- ============================================================
-- Indizes für schnelle Suche
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_cheats_platform   ON cheats(platform_id);
CREATE INDEX IF NOT EXISTS idx_cheats_status     ON cheats(status);
CREATE INDEX IF NOT EXISTS idx_process_name      ON process_signatures(process_name);
CREATE INDEX IF NOT EXISTS idx_module_name       ON module_signatures(module_name);
CREATE INDEX IF NOT EXISTS idx_window_title      ON window_signatures(window_title);
CREATE INDEX IF NOT EXISTS idx_mutex_name        ON mutex_signatures(mutex_name);
CREATE INDEX IF NOT EXISTS idx_string_value      ON string_signatures(string_value);
CREATE INDEX IF NOT EXISTS idx_file_path         ON file_signatures(file_path);
CREATE INDEX IF NOT EXISTS idx_network_value     ON network_signatures(value);

-- ============================================================
-- Hilfssicht: Alle Signaturen flach (für schnellen Lookup)
-- ============================================================

CREATE VIEW IF NOT EXISTS v_all_signatures AS
    SELECT 'process'  AS sig_type, p.id, c.name AS cheat_name, pl.name AS platform,
           ps.process_name AS value, ps.description
    FROM process_signatures ps
    JOIN cheats c  ON c.id = ps.cheat_id
    JOIN platforms pl ON pl.id = c.platform_id
UNION ALL
    SELECT 'module', m.id, c.name, pl.name, ms.module_name, ms.description
    FROM module_signatures ms
    JOIN cheats c  ON c.id = ms.cheat_id
    JOIN platforms pl ON pl.id = c.platform_id
UNION ALL
    SELECT 'window', w.id, c.name, pl.name, ws.window_title, ws.description
    FROM window_signatures ws
    JOIN cheats c  ON c.id = ws.cheat_id
    JOIN platforms pl ON pl.id = c.platform_id
UNION ALL
    SELECT 'mutex', mu.id, c.name, pl.name, mus.mutex_name, mus.description
    FROM mutex_signatures mus
    JOIN cheats c  ON c.id = mus.cheat_id
    JOIN platforms pl ON pl.id = c.platform_id
UNION ALL
    SELECT 'string', s.id, c.name, pl.name, ss.string_value, ss.description
    FROM string_signatures ss
    JOIN cheats c  ON c.id = ss.cheat_id
    JOIN platforms pl ON pl.id = c.platform_id
UNION ALL
    SELECT 'network', n.id, c.name, pl.name, ns.value, ns.description
    FROM network_signatures ns
    JOIN cheats c  ON c.id = ns.cheat_id
    JOIN platforms pl ON pl.id = c.platform_id;
