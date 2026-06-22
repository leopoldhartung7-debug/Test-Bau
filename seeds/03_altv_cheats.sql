-- ============================================================
-- Seed: AltV Cheats (platform_id = 3)
-- ============================================================

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description, source_url) VALUES
  (50, 3, 'AltV Cheat Suite',    'ACS',                     'menu',    1, 'active',   'confirmed', 'Vollständiges Cheat-Menü für alt:V mit ESP, Aimbot und Teleport', NULL),
  (51, 3, 'AltV Bypass',         'altv_bypass,alt-bypass',  'bypass',  0, 'active',   'confirmed', 'Bypass-Tool für alt:V Integritätsprüfungen',                     NULL),
  (52, 3, 'AltV ESP',            'altvesp',                 'esp',     0, 'active',   'confirmed', 'Standalone ESP für alt:V',                                       NULL),
  (53, 3, 'AltV Resource Dumper','altvdumper,AltVDump',     'dumper',  0, 'active',   'confirmed', 'Dumpt clientseitige alt:V JavaScript-Ressourcen',                NULL),
  (54, 3, 'V8 Injector',         'altv_v8inject',           'script',  0, 'active',   'confirmed', 'Injiziert JS-Code in die alt:V V8-Runtime',                     NULL),
  (55, 3, 'AltV Noclip',         NULL,                      'trainer', 0, 'active',   'high',      'Noclip durch Physik-Manipulation in alt:V',                     NULL),
  (56, 3, 'AltV Speed Hack',     'AltVSpeed',               'trainer', 0, 'active',   'high',      'Speedhack für alt:V Clients',                                   NULL),
  (57, 3, 'AltV Teleport',       'AltVTP',                  'trainer', 0, 'active',   'high',      'Koordinaten-Teleport in alt:V',                                 NULL),
  (58, 3, 'AltV Aimbot',         NULL,                      'esp',     1, 'active',   'high',      'Aimbot/Silent-Aim für alt:V',                                   NULL),
  (59, 3, 'AltV God Mode',       'altgod',                  'trainer', 0, 'active',   'medium',    'Unverwundbarkeits-Hack für alt:V',                              NULL),
  (60, 3, 'CefSharp Injector',   'cef_inject',              'script',  0, 'active',   'medium',    'Injiziert Code in alt:Vs eingebetteten Chromium-Browser',       NULL);

-- -------------------------------------------------------
-- Prozesse
-- -------------------------------------------------------

INSERT OR IGNORE INTO process_signatures (cheat_id, process_name, description) VALUES
  (50, 'altv_cheat.exe',          'AltV Cheat Suite Prozess'),
  (51, 'altv_bypass.exe',         'AltV Bypass Prozess'),
  (52, 'altvesp.exe',             'AltV ESP Prozess'),
  (53, 'altv_dumper.exe',         'AltV Dumper Prozess'),
  (54, 'v8_injector.exe',         'V8 Injector Prozess'),
  (60, 'cef_injector.exe',        'CefSharp Injector Prozess');

-- -------------------------------------------------------
-- Module / DLLs
-- -------------------------------------------------------

INSERT OR IGNORE INTO module_signatures (cheat_id, module_name, description) VALUES
  (50, 'altv_cheat.dll',          'AltV Cheat Suite DLL'),
  (51, 'altv_bypass.dll',         'AltV Bypass DLL'),
  (52, 'altvesp.dll',             'AltV ESP DLL'),
  (53, 'altv_dumper.dll',         'AltV Dumper DLL'),
  (54, 'v8inject.dll',            'V8 Injector DLL'),
  (55, 'altv_noclip.dll',         'AltV Noclip DLL'),
  (56, 'altv_speed.dll',          'AltV Speed Hack DLL'),
  (58, 'altv_aimbot.dll',         'AltV Aimbot DLL'),
  (60, 'cef_hook.dll',            'CefSharp Hook DLL');

-- -------------------------------------------------------
-- Fenster-Titel & Klassen
-- -------------------------------------------------------

INSERT OR IGNORE INTO window_signatures (cheat_id, window_title, window_class, is_overlay, description) VALUES
  (50, 'AltV Cheat Suite',        'ACSWnd',         0, 'ACS Haupt-Fenster'),
  (50, 'ACS',                     NULL,             1, 'ACS In-Game Overlay'),
  (51, 'AltV Bypass',             'AltVBypassWnd',  0, 'Bypass Launcher-Fenster'),
  (52, 'AltV ESP',                NULL,             1, 'ESP Overlay'),
  (53, 'AltV Dumper',             NULL,             0, 'Dumper Fenster'),
  (54, 'V8 Injector',             NULL,             0, 'V8 Injector Fenster'),
  (60, 'CefSharp Injector',       NULL,             0, 'CEF Injector Fenster');

-- -------------------------------------------------------
-- Mutex
-- -------------------------------------------------------

INSERT OR IGNORE INTO mutex_signatures (cheat_id, mutex_name, description) VALUES
  (50, 'AltVCheatMutex',           'AltV Cheat Suite Mutex'),
  (51, 'AltVBypassMutex',          'AltV Bypass Mutex'),
  (52, 'AltVESPMutex',             'AltV ESP Mutex'),
  (53, 'AltVDumperMutex',          'AltV Dumper Mutex'),
  (54, 'V8InjectMutex',            'V8 Injector Mutex');

-- -------------------------------------------------------
-- Strings
-- -------------------------------------------------------

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  -- AltV Cheat Suite
  (50, 'AltV Cheat Suite',         'watermark',    1, 'Haupt-Wasserzeichen'),
  (50, 'ACS v',                    'watermark',    1, 'ACS Versions-Prefix'),
  (50, 'ACS_Init',                 'export_name',  1, 'ACS DLL Init Export'),
  (50, 'altv_hook',                'general',      1, 'AltV Hook Indikator'),
  -- AltV Bypass
  (51, 'AltV Bypass',              'watermark',    1, 'Bypass Wasserzeichen'),
  (51, 'altv_bypass',              'general',      1, 'Bypass Indikator'),
  (51, 'bypass_altv',              'general',      1, 'Alternativer Bypass String'),
  (51, 'altv_integrity_patch',     'general',      1, 'Integritätsprüfungs-Bypass'),
  (51, 'PatchIntegrityCheck',      'export_name',  1, 'Patch-Funktion Export'),
  -- AltV ESP
  (52, 'AltV ESP',                 'watermark',    1, 'ESP Wasserzeichen'),
  (52, 'altvesp',                  'general',      1, 'AltV ESP interner Name'),
  (52, 'DrawBoxESP',               'export_name',  1, 'ESP Box-Zeichenfunktion'),
  (52, 'DrawNameESP',              'export_name',  1, 'ESP Name-Zeichenfunktion'),
  (52, 'ESP_Enabled',              'config_key',   1, 'ESP Konfig-Schlüssel'),
  -- AltV Dumper
  (53, 'AltV Dumper',              'watermark',    1, 'Dumper Wasserzeichen'),
  (53, 'altv_dump',                'general',      1, 'Dump Indikator'),
  (53, 'DumpJS',                   'export_name',  1, 'JavaScript Dump Funktion'),
  (53, 'DumpResource',             'export_name',  1, 'Ressource Dump Funktion'),
  (53, 'ALTV_DUMP_',               'general',      1, 'Dump Datei Präfix'),
  -- V8 Injector
  (54, 'V8 Injector',              'watermark',    1, 'V8 Injector Wasserzeichen'),
  (54, 'v8inject',                 'general',      1, 'V8 Inject String'),
  (54, 'InjectJS',                 'export_name',  1, 'JavaScript Injektions-Export'),
  (54, 'eval(',                    'general',      1, 'JS eval() - häufig bei Injektion'),
  (54, 'alt.emit(',                'general',      1, 'AltV Event-Emission durch Exploit'),
  (54, 'alt.Player.local',         'general',      1, 'AltV lokales Spielerobjekt Exploit'),
  -- Noclip
  (55, 'AltV Noclip',              'watermark',    1, 'Noclip Wasserzeichen'),
  (55, 'noclip_enabled',           'config_key',   1, 'Noclip Konfig'),
  -- Speed Hack
  (56, 'AltV Speed',               'watermark',    1, 'Speed Hack Wasserzeichen'),
  (56, 'speed_multiplier',         'config_key',   1, 'Speed Multiplikator'),
  -- Aimbot
  (58, 'AltV Aimbot',              'watermark',    1, 'Aimbot Wasserzeichen'),
  (58, 'silent_aim',               'config_key',   1, 'Silent Aim Konfig'),
  (58, 'aim_fov',                  'config_key',   1, 'Aimbot FOV Konfig'),
  (58, 'aim_smooth',               'config_key',   1, 'Aimbot Smoothing Konfig'),
  -- God Mode
  (59, 'AltV God Mode',            'watermark',    1, 'God Mode Wasserzeichen'),
  (59, 'godmode_enabled',          'config_key',   1, 'Godmode Konfig'),
  -- CefSharp Injector
  (60, 'CefSharp Injector',        'watermark',    1, 'CEF Injector Wasserzeichen'),
  (60, 'cef_inject',               'general',      1, 'CEF Inject String'),
  (60, 'InjectCEF',                'export_name',  1, 'CEF Injektions-Export');

-- AltV spezifische Ziel-Prozesse
INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  (51, 'altv.exe',                'general', 1, 'AltV Ziel-Prozess für Injektion'),
  (51, 'alt-v.mp',                'general', 1, 'AltV Fenstertitel als Injektionsziel');

-- -------------------------------------------------------
-- Dateipfade
-- -------------------------------------------------------

INSERT OR IGNORE INTO file_signatures (cheat_id, file_path, file_type, description) VALUES
  (50, '%APPDATA%\\AltVCheat\\',        'any',    'AltV Cheat Konfigurationsordner'),
  (51, '%TEMP%\\altv_bypass_',          'any',    'AltV Bypass temporäre Dateien'),
  (53, '%USERPROFILE%\\Desktop\\altv_dump\\', 'any', 'AltV Dump Output auf Desktop'),
  (53, '%TEMP%\\altv_dump\\',           'any',    'AltV Dump temporärer Ordner'),
  (54, '%APPDATA%\\v8inject\\',         'any',    'V8 Injector Konfigurationsordner');

-- -------------------------------------------------------
-- Netzwerk-IOCs
-- -------------------------------------------------------

INSERT OR IGNORE INTO network_signatures (cheat_id, ioc_type, value, description) VALUES
  (50, 'domain', 'altv-cheat.net',          'AltV Cheat Suite Domain'),
  (51, 'domain', 'altv-bypass.xyz',         'AltV Bypass Domain'),
  (53, 'domain', 'altvdumper.net',          'AltV Dumper Domain'),
  (58, 'domain', 'altv-aimbot.com',         'AltV Aimbot Domain');
