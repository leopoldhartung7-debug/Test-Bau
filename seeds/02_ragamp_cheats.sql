-- ============================================================
-- Seed: RageMP Cheats (platform_id = 2)
-- ============================================================

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description, source_url) VALUES
  (30, 2, 'RageMP Cheat Suite',  'RPCS',                   'menu',     1, 'active',   'confirmed', 'Umfassendes Cheat-Menü für RageMP mit ESP und Aimbot',          NULL),
  (31, 2, 'Rage Bypass',         'ragebypass,rage-bypass', 'bypass',   0, 'active',   'confirmed', 'Bypass für RageMP Anti-Cheat-Maßnahmen',                        NULL),
  (32, 2, 'RageESP',             NULL,                     'esp',      0, 'active',   'confirmed', 'Standalone ESP für RageMP Spieler und Fahrzeuge',               NULL),
  (33, 2, 'RageAimbot',          NULL,                     'esp',      0, 'active',   'confirmed', 'Aimbot-Implementierung für RageMP',                             NULL),
  (34, 2, 'RageSpeed',           'RageSpeedHack',          'trainer',  0, 'active',   'high',      'Speedhack durch Speicher-Patches in RageMP',                    NULL),
  (35, 2, 'RageMP Resource Dumper', 'RMPDumper',           'dumper',   0, 'active',   'confirmed', 'Dumpt clientseitige RageMP Ressourcen/Skripte',                 NULL),
  (36, 2, 'Midnight RageMP',     'MidnightRage',           'menu',     1, 'active',   'high',      'Midnight-Variante speziell für RageMP',                         NULL),
  (37, 2, 'RageMP Noclip',       NULL,                     'trainer',  0, 'active',   'medium',    'Noclip/Flugmodus durch Physik-Manipulation',                    NULL),
  (38, 2, 'RPM Teleport',        'RageTeleport',           'trainer',  0, 'active',   'medium',    'Teleport-Hack für RageMP',                                      NULL);

-- -------------------------------------------------------
-- Prozesse
-- -------------------------------------------------------

INSERT OR IGNORE INTO process_signatures (cheat_id, process_name, description) VALUES
  (30, 'rmp_cheat.exe',         'RageMP Cheat Suite Prozess'),
  (31, 'rage_bypass.exe',       'Rage Bypass Prozess'),
  (32, 'rageesp.exe',           'RageESP Prozess'),
  (35, 'rmp_dumper.exe',        'RageMP Dumper Prozess'),
  (36, 'midnight_rage.exe',     'Midnight RageMP Variante');

-- -------------------------------------------------------
-- Module / DLLs
-- -------------------------------------------------------

INSERT OR IGNORE INTO module_signatures (cheat_id, module_name, description) VALUES
  (30, 'rmp_cheat.dll',        'RageMP Cheat Suite DLL'),
  (31, 'rage_bypass.dll',      'Rage Bypass DLL'),
  (32, 'rageesp.dll',          'RageESP injizierte DLL'),
  (33, 'rageaimbot.dll',       'RageAimbot DLL'),
  (34, 'ragespeed.dll',        'RageSpeed Hack DLL'),
  (36, 'midnight_rage.dll',    'Midnight RageMP DLL');

-- -------------------------------------------------------
-- Fenster-Titel & Klassen
-- -------------------------------------------------------

INSERT OR IGNORE INTO window_signatures (cheat_id, window_title, window_class, is_overlay, description) VALUES
  (30, 'RageMP Cheat Suite',    NULL,             0, 'Haupt-Fenster'),
  (30, 'RPCS',                  NULL,             1, 'RPCS Overlay'),
  (31, 'Rage Bypass',           'RageBypassWnd',  0, 'Bypass Launcher'),
  (32, 'RageESP',               NULL,             1, 'ESP Overlay in-game'),
  (35, 'RageMP Dumper',         NULL,             0, 'Dumper Fenster'),
  (36, 'Midnight RageMP',       NULL,             0, 'Midnight Rage Variante'),
  (36, 'MidnightRage',          NULL,             1, 'Midnight Rage Overlay');

-- -------------------------------------------------------
-- Mutex
-- -------------------------------------------------------

INSERT OR IGNORE INTO mutex_signatures (cheat_id, mutex_name, description) VALUES
  (30, 'RageMPCheatMutex',        'RageMP Cheat Suite Mutex'),
  (31, 'RageBypassMutex',         'Rage Bypass Mutex'),
  (32, 'RageESPMutex',            'RageESP Mutex'),
  (35, 'RageDumperMutex',         'RageMP Dumper Mutex'),
  (36, 'MidnightRageMutex',       'Midnight RageMP Mutex');

-- -------------------------------------------------------
-- Strings
-- -------------------------------------------------------

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  -- RageMP Cheat Suite
  (30, 'RageMP Cheat Suite',       'watermark',    1, 'Haupt-Wasserzeichen'),
  (30, 'RPCS v',                   'watermark',    1, 'Versions-Prefix'),
  (30, 'RPCS_Init',                'export_name',  1, 'DLL Init Export'),
  (30, 'ragemp_hook',              'general',      1, 'Hook-String'),
  -- Rage Bypass
  (31, 'Rage Bypass',              'watermark',    1, 'Bypass Wasserzeichen'),
  (31, 'ragemp_bypass',            'general',      1, 'Bypass Indikator'),
  (31, 'bypass_rage',              'general',      1, 'Alternativer Bypass String'),
  (31, 'rage_anticheat_patch',     'general',      1, 'Anti-Cheat Patch String'),
  -- RageESP
  (32, 'RageESP',                  'watermark',    1, 'ESP Wasserzeichen'),
  (32, 'ESP_DrawBoxes',            'export_name',  1, 'ESP Funktion Export'),
  (32, 'ESP_DrawNames',            'export_name',  1, 'ESP Funktion Export'),
  -- RageAimbot
  (33, 'RageAimbot',               'watermark',    1, 'Aimbot Wasserzeichen'),
  (33, 'SilentAim',                'gui_label',    1, 'Silent Aim Label'),
  (33, 'AimSmooth',                'config_key',   1, 'Aimbot Smoothing Konfig'),
  (33, 'FOV_Circle',               'config_key',   1, 'FOV Konfig'),
  -- RageSpeed
  (34, 'RageSpeed',                'watermark',    1, 'Speedhack Wasserzeichen'),
  (34, 'speed_multiplier',         'config_key',   1, 'Speed Multiplikator Konfig'),
  -- RageMP Dumper
  (35, 'RageMP Dumper',            'watermark',    1, 'Dumper Wasserzeichen'),
  (35, 'RMP_DUMP',                 'general',      1, 'Dump Indikator String'),
  (35, 'DumpClientScript',         'export_name',  1, 'Dump Funktion'),
  -- Midnight RageMP
  (36, 'Midnight RageMP',          'watermark',    1, 'Midnight Rage Wasserzeichen'),
  (36, 'MidnightRage',             'general',      1, 'Kurz-Name');

-- -------------------------------------------------------
-- RageMP spezifische Ziel-Prozesse (zum Injizieren)
-- -------------------------------------------------------

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  (31, 'ragemp.exe',             'general', 1, 'RageMP Ziel-Prozess für Injektion'),
  (31, 'rage_mp_sp.exe',         'general', 1, 'RageMP SP Variante Ziel-Prozess'),
  (31, 'RAGE Multiplayer',       'general', 1, 'RageMP Fenstertitel als Injektionsziel');

-- -------------------------------------------------------
-- Dateipfade
-- -------------------------------------------------------

INSERT OR IGNORE INTO file_signatures (cheat_id, file_path, file_type, description) VALUES
  (30, '%APPDATA%\\RMPCheat\\',        'any',    'RageMP Cheat Konfigurationsordner'),
  (31, '%TEMP%\\rage_bypass_',         'any',    'Rage Bypass temporäre Dateien'),
  (35, '%USERPROFILE%\\Desktop\\rmp_dump\\', 'any', 'RageMP Dump Output'),
  (35, '%TEMP%\\rmp_dump\\',           'any',    'RageMP Dump temporärer Ordner');

-- -------------------------------------------------------
-- Netzwerk-IOCs
-- -------------------------------------------------------

INSERT OR IGNORE INTO network_signatures (cheat_id, ioc_type, value, description) VALUES
  (30, 'domain', 'rmpcheat.net',           'RageMP Cheat Suite Domain'),
  (31, 'domain', 'ragebypass.xyz',         'Rage Bypass Domain'),
  (36, 'domain', 'midnight-rage.com',      'Midnight RageMP Domain');
