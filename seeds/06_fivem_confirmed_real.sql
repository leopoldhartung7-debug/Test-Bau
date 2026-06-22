-- ============================================================
-- Seed: Bestätigte FiveM Cheats (recherchiert)
-- Quellen: eulencheats.com | eulen.gg | ravenac.net
--          vag.gg HUNK-AC | forum.cfx.re | qlmshop.com
--          github.com/yowi0/FiveM-Menus | skript.gg
-- ============================================================
-- KATEGORIEN:
--   Lua Executor  → Eulen, RedEngine  (laufen als eigener Prozess)
--   Lua Mod Menu  → Brutan, Absolute, Cobra, Dopamine, Extrude,
--                   Fallout, Alien, Alokas, Exia  (Skripte im Executor)
--   External PvP  → TZX, HX Cheats, Skript.gg  (außerhalb Spielprozess)
--   Bypass/Tool   → NFIVE, CFX Dumper  (bereits in DB)
-- ============================================================

-- -------------------------------------------------------
-- CHEATS  (FiveM platform_id = 1)
-- -------------------------------------------------------

-- Lua Mod Menus (laufen IN Eulen / RedEngine)
INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description, source_url) VALUES
  (100, 1, 'Brutan',    'Brutan Menu,Brutan_v3', 'script', 0, 'active', 'confirmed',
   'Bekanntes FiveM Lua-Mod-Menü (wird in Eulen/RedEngine geladen). Erkannt von HUNK-AC, FiniAC.',
   'https://vag.gg/threads/hunk-ac-anti-eulen-anti-redengine-anti-executor-fivem-anticheat-2025.14371/'),

  (101, 1, 'Absolute',  'Absolute Menu,Absolute_v1', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü (Absolute_v1.lua). Erkannt von HUNK-AC und FiniAC als Lua-Menu.',
   'https://github.com/yowi0/FiveM-Menus'),

  (102, 1, 'Cobra',     'Cobra Menu,cobra-menu', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü (cobra-menu.lua). Teil der bekannten Lua-Menü-Sammlung.',
   'https://github.com/yowi0/FiveM-Menus'),

  (103, 1, 'Dopamine',  'd0pamine,Dopamine Menu', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü (d0pamine.lua / Dopamine.lua). GitHub-bestätigt.',
   'https://github.com/nertigel/d0pamine_lua'),

  (104, 1, 'Extrude',   'Extrude Menu', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü. Erkannt von HUNK-AC Anticheat.',
   'https://vag.gg/threads/hunk-ac-anti-eulen-anti-redengine-anti-executor-fivem-anticheat-2025.14371/'),

  (105, 1, 'Fallout',   'Fallout Menu', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü (Fallout.lua). GitHub-bestätigt, erkannt von HUNK-AC.',
   'https://github.com/yowi0/FiveM-Menus'),

  (106, 1, 'Alien',     'Alien Menu', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü. Erkannt von HUNK-AC Anticheat als Lua-Menü.',
   'https://vag.gg/threads/hunk-ac-anti-eulen-anti-redengine-anti-executor-fivem-anticheat-2025.14371/'),

  (107, 1, 'Alokas',    'Alokas Menu', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü. Erkannt von HUNK-AC Anticheat als Lua-Menü.',
   'https://vag.gg/threads/hunk-ac-anti-eulen-anti-redengine-anti-executor-fivem-anticheat-2025.14371/'),

  (108, 1, 'Exia',      'Exia Menu,Exia_v2', 'script', 0, 'active', 'confirmed',
   'FiveM Lua-Mod-Menü (Exia_v2.lua). GitHub-bestätigt.',
   'https://github.com/yowi0/FiveM-Menus'),

-- External PvP Cheats
  (110, 1, 'TZX',       'Project TZX,TZ Project,tzx-external', 'esp', 1, 'active', 'confirmed',
   'Externer FiveM PvP-Cheat (läuft außerhalb des Spielprozesses). Aimbot, ESP, Stream-Proof, Panic-Key.',
   'https://qlmshop.com/blog/best-fivem-pvp-cheat-2024/'),

  (111, 1, 'Skript',    'SKRIPT.gg,skript-gg', 'menu', 1, 'active', 'confirmed',
   'Universal-Cheat für FiveM / RageMP / AltV / GTA Online. Aimbot, ESP, Godmode, Fahrzeug-Optionen.',
   'https://skript.gg/products/gta'),

  (112, 1, 'HX Cheats', 'HXCheats,HX', 'esp', 1, 'active', 'confirmed',
   'Budget-PvP-Cheat für FiveM. Silent Aim, ESP, undetected auf den meisten Servern.',
   'https://qlmshop.com/blog/top-5-best-fivem-cheats-2024/');

-- -------------------------------------------------------
-- PROZESSE
-- -------------------------------------------------------

INSERT OR IGNORE INTO process_signatures (cheat_id, process_name, description) VALUES
  -- Lua Menus haben keinen eigenen Prozess, laufen in Eulen/RedEngine
  (110, 'tzx.exe',           'TZX Hauptprozess (external)'),
  (110, 'tzx_loader.exe',    'TZX Loader'),
  (110, 'tz_project.exe',    'TZ Project alternativer Prozessname'),
  (111, 'skript.exe',        'SKRIPT.gg Prozess'),
  (111, 'skript_loader.exe', 'SKRIPT.gg Loader'),
  (112, 'hxcheats.exe',      'HX Cheats Prozess'),
  (112, 'hx_loader.exe',     'HX Cheats Loader');

-- -------------------------------------------------------
-- MODULE / DLLs
-- -------------------------------------------------------

INSERT OR IGNORE INTO module_signatures (cheat_id, module_name, description) VALUES
  (110, 'tzx.dll',           'TZX injizierte DLL'),
  (111, 'skript.dll',        'SKRIPT.gg DLL'),
  (112, 'hxcheats.dll',      'HX Cheats DLL');

-- -------------------------------------------------------
-- FENSTER
-- -------------------------------------------------------

INSERT OR IGNORE INTO window_signatures (cheat_id, window_title, window_class, is_overlay, description) VALUES
  (110, 'TZX',               NULL, 0, 'TZX Hauptfenster'),
  (110, 'Project TZX',       NULL, 0, 'TZX alternatives Fenstertitel'),
  (110, 'TZX External',      NULL, 0, 'TZX External Bezeichnung'),
  (110, 'TZ Project',        NULL, 0, 'TZ Project Fenstertitel'),
  (111, 'SKRIPT',            NULL, 1, 'SKRIPT.gg Overlay'),
  (111, 'Skript.gg',         NULL, 0, 'SKRIPT.gg Fenster'),
  (112, 'HX Cheats',         NULL, 0, 'HX Cheats Fenster'),
  (112, 'HXCheats',          NULL, 1, 'HX Cheats Overlay');

-- -------------------------------------------------------
-- MUTEX
-- -------------------------------------------------------

INSERT OR IGNORE INTO mutex_signatures (cheat_id, mutex_name, description) VALUES
  (110, 'TZXMutex',          'TZX Single-Instance Mutex'),
  (110, 'Global\TZXSingle',  'TZX globaler Mutex'),
  (111, 'SkriptMutex',       'SKRIPT.gg Mutex'),
  (112, 'HXMutex',           'HX Cheats Mutex');

-- -------------------------------------------------------
-- STRINGS
-- -------------------------------------------------------

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES

  -- Brutan (Lua-Skript-interne Strings)
  (100, 'Brutan',            'watermark',    1, 'Brutan Menü-Name im Skript'),
  (100, 'Brutan Menu',       'watermark',    1, 'Brutan vollständiger Name'),
  (100, 'Brutan_v3',         'general',      1, 'Brutan Versions-String'),
  (100, 'BrutanLoaded',      'debug_string', 1, 'Brutan Lade-Bestätigung'),
  (100, 'brutan',            'general',      0, 'Brutan (lowercase, Lua-intern)'),

  -- Absolute
  (101, 'Absolute',          'watermark',    1, 'Absolute Menü-Name'),
  (101, 'Absolute Menu',     'watermark',    1, 'Absolute vollständiger Name'),
  (101, 'Absolute_v1',       'general',      1, 'Absolute Versions-String'),
  (101, 'AbsoluteMenu',      'general',      1, 'Absolute zusammengeschrieben'),
  (101, 'absolute',          'general',      0, 'Absolute (lowercase)'),

  -- Cobra
  (102, 'Cobra',             'watermark',    1, 'Cobra Menü-Name'),
  (102, 'Cobra Menu',        'watermark',    1, 'Cobra vollständiger Name'),
  (102, 'cobra-menu',        'general',      1, 'Cobra Dateiname-String'),
  (102, 'CobraMenu',         'general',      1, 'Cobra zusammengeschrieben'),
  (102, 'cobra',             'general',      0, 'Cobra (lowercase)'),

  -- Dopamine
  (103, 'Dopamine',          'watermark',    1, 'Dopamine Menü-Name'),
  (103, 'd0pamine',          'general',      1, 'Dopamine mit Null (0)'),
  (103, 'Dopamine Menu',     'watermark',    1, 'Dopamine vollständiger Name'),
  (103, 'dopamine',          'general',      0, 'Dopamine (lowercase)'),
  (103, 'd0p',               'general',      1, 'Dopamine Kurzform'),

  -- Extrude
  (104, 'Extrude',           'watermark',    1, 'Extrude Menü-Name'),
  (104, 'Extrude Menu',      'watermark',    1, 'Extrude vollständiger Name'),
  (104, 'extrude',           'general',      0, 'Extrude (lowercase)'),

  -- Fallout
  (105, 'Fallout',           'watermark',    1, 'Fallout Menü-Name'),
  (105, 'Fallout Menu',      'watermark',    1, 'Fallout vollständiger Name'),
  (105, 'FalloutMenu',       'general',      1, 'Fallout zusammengeschrieben'),
  (105, 'fallout',           'general',      0, 'Fallout (lowercase)'),

  -- Alien
  (106, 'Alien',             'watermark',    1, 'Alien Menü-Name'),
  (106, 'Alien Menu',        'watermark',    1, 'Alien vollständiger Name'),
  (106, 'alien',             'general',      0, 'Alien (lowercase)'),

  -- Alokas
  (107, 'Alokas',            'watermark',    1, 'Alokas Menü-Name'),
  (107, 'Alokas Menu',       'watermark',    1, 'Alokas vollständiger Name'),
  (107, 'alokas',            'general',      0, 'Alokas (lowercase)'),

  -- Exia
  (108, 'Exia',              'watermark',    1, 'Exia Menü-Name'),
  (108, 'Exia_v2',           'general',      1, 'Exia Versions-String'),
  (108, 'ExiaMenu',          'general',      1, 'Exia zusammengeschrieben'),
  (108, 'exia',              'general',      0, 'Exia (lowercase)'),

  -- TZX External
  (110, 'TZX',               'watermark',    1, 'TZX Wasserzeichen'),
  (110, 'Project TZX',       'watermark',    1, 'TZX vollständiger Name'),
  (110, 'TZ Project',        'watermark',    1, 'TZX alternatives Wasserzeichen'),
  (110, 'TZX v',             'watermark',    1, 'TZX Versions-Prefix'),
  (110, 'tzx-external',      'general',      1, 'TZX Bezeichnung als external'),
  (110, 'TZX_Init',          'export_name',  1, 'TZX DLL Init Export'),
  (110, 'TZX Aimbot',        'gui_label',    1, 'TZX Aimbot GUI-Label'),
  (110, 'TZX ESP',           'gui_label',    1, 'TZX ESP GUI-Label'),
  (110, 'PanicKey',          'config_key',   1, 'TZX Panic-Key Konfig'),
  (110, 'SilentAim',         'gui_label',    1, 'TZX Silent Aim Label'),
  (110, 'StreamProof',       'config_key',   1, 'TZX Stream-Proof Konfig'),

  -- SKRIPT.gg
  (111, 'SKRIPT',            'watermark',    1, 'SKRIPT.gg Wasserzeichen'),
  (111, 'skript.gg',         'network_agent',1, 'SKRIPT.gg Domain-String'),
  (111, 'Skript.gg',         'watermark',    1, 'SKRIPT.gg mit Punkt'),
  (111, 'SKRIPT v',          'watermark',    1, 'SKRIPT Versions-Prefix'),
  (111, 'SKRIPT_Init',       'export_name',  1, 'SKRIPT DLL Init Export'),
  (111, 'BoxESP',            'gui_label',    1, 'SKRIPT Box-ESP Label'),
  (111, 'SkeletonESP',       'gui_label',    1, 'SKRIPT Skelett-ESP Label'),
  (111, 'TrueGodmode',       'gui_label',    1, 'SKRIPT True Godmode Label'),
  (111, 'StreamProof',       'config_key',   1, 'SKRIPT Stream-Proof Konfig'),

  -- HX Cheats
  (112, 'HX Cheats',         'watermark',    1, 'HX Cheats Wasserzeichen'),
  (112, 'HXCheats',          'general',      1, 'HX Cheats zusammengeschrieben'),
  (112, 'HX v',              'watermark',    1, 'HX Versions-Prefix'),
  (112, 'HX_Init',           'export_name',  1, 'HX DLL Init Export'),
  (112, 'HX Aimbot',         'gui_label',    1, 'HX Aimbot Label'),
  (112, 'SilentAim',         'gui_label',    1, 'HX Silent Aim Label');

-- -------------------------------------------------------
-- NETZWERK
-- -------------------------------------------------------

INSERT OR IGNORE INTO network_signatures (cheat_id, ioc_type, value, description) VALUES
  (110, 'domain', 'tzx.gg',              'TZX Haupt-Domain'),
  (110, 'domain', 'auth.tzx.gg',         'TZX Auth-Server'),
  (110, 'domain', 'noblecheats.net',      'TZX Reseller-Domain'),
  (111, 'domain', 'skript.gg',            'SKRIPT.gg Haupt-Domain'),
  (111, 'domain', 'auth.skript.gg',       'SKRIPT.gg Auth-Server'),
  (112, 'domain', 'hxcheats.net',         'HX Cheats Domain');

-- -------------------------------------------------------
-- DATEIPFADE
-- -------------------------------------------------------

INSERT OR IGNORE INTO file_signatures (cheat_id, file_path, file_type, description) VALUES
  (110, '%APPDATA%\TZX\',               'any',    'TZX Konfigurationsordner'),
  (110, '%APPDATA%\TZX\config.json',    'config', 'TZX Konfigurationsdatei'),
  (110, '%TEMP%\tzx_*',                 'any',    'TZX temporäre Dateien'),
  (111, '%APPDATA%\Skript\',            'any',    'SKRIPT.gg Konfigurationsordner'),
  (112, '%APPDATA%\HXCheats\',          'any',    'HX Cheats Konfigurationsordner');
