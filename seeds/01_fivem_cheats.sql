-- ============================================================
-- Seed: FiveM Cheats
-- ============================================================

-- -------------------------------------------------------
-- CHEATS (FiveM platform_id = 1)
-- -------------------------------------------------------

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description, source_url) VALUES
  (1,  1, 'Eulen',        'EulenCheats',           'menu',     1, 'active',   'confirmed', 'Bekanntes kommerzielles FiveM Cheat-Menü mit ESP, Aimbot, Teleport', 'https://eulen.pw'),
  (2,  1, 'Lynx',         'Lynx Client,LynxMenu',  'menu',     1, 'active',   'confirmed', 'Bezahl-Cheat für FiveM, enthält ESP und Godmode-Funktionen',         NULL),
  (3,  1, 'Midnight',     'MidnightCheats',         'menu',     1, 'active',   'confirmed', 'FiveM Cheat-Menü (Paid) mit Fahrzeug-Spawner und ESP',               NULL),
  (4,  1, 'RedEngine',    'Red Engine,red-engine',  'menu',     1, 'active',   'confirmed', 'Fortgeschrittenes FiveM Menü mit Anti-Detection-Features',           NULL),
  (5,  1, 'Hammafia',     NULL,                     'menu',     1, 'active',   'confirmed', 'Kommerzielles FiveM Cheat-Menü',                                     NULL),
  (6,  1, 'NFIVE',        'NoFiveM,nfive',          'bypass',   0, 'active',   'confirmed', 'FiveM-Bypass / Offline-Launcher zum Umgehen von Bans',               NULL),
  (7,  1, 'Oxiware',      'Oxi',                    'menu',     1, 'active',   'high',      'FiveM Mod-Menü mit Teleport und Spieler-Funktionen',                 NULL),
  (8,  1, 'Stellar',      'StellarFiveM',           'menu',     1, 'active',   'high',      'FiveM Cheat-Menü (Subscription-basiert)',                            NULL),
  (9,  1, 'Frostbite',    NULL,                     'menu',     1, 'active',   'high',      'FiveM Cheat mit ESP und Aimbot',                                     NULL),
  (10, 1, 'Hydra',        'HydraFiveM',             'menu',     1, 'active',   'high',      'FiveM Menü mit Fahrzeug und Spieler-Hacks',                          NULL),
  (11, 1, 'Eclipse',      'EclipseFiveM',           'menu',     1, 'active',   'medium',    'FiveM Overlay-Cheat',                                                NULL),
  (12, 1, 'Silent Aim',   'SilentAimFiveM',         'esp',      0, 'active',   'medium',    'Silent Aimbot-Implementierungen für FiveM',                          NULL),
  (13, 1, 'CFX Dumper',   'FiveMDumper,cfx-dumper', 'dumper',   0, 'active',   'confirmed', 'Tool zum Dumpen von FiveM-Server-Ressourcen (Skripte/Assets)',       NULL),
  (14, 1, 'Resource Stealer', NULL,                 'dumper',   0, 'active',   'confirmed', 'Automatisiertes Stehlen von servergeschützten FiveM-Ressourcen',     NULL),
  (15, 1, 'SkidMenu',     'Skid,SkidCheat',         'menu',     0, 'active',   'medium',    'Öffentliche/geleakte FiveM Cheat-Menüs (GitHub-Leaks)',              NULL),
  (16, 1, 'Flawless',     NULL,                     'menu',     1, 'active',   'high',      'FiveM Cheat-Menü (Paid)',                                            NULL),
  (17, 1, 'Haze',         'HazeCheats',             'menu',     1, 'active',   'high',      'FiveM Mod-Menü',                                                     NULL),
  (18, 1, 'Pawn Script Injector', 'PSI',            'script',   0, 'active',   'medium',    'Injiziert benutzerdefinierte Pawn/Lua-Skripte in FiveM-Sessions',    NULL);

-- -------------------------------------------------------
-- Prozesse
-- -------------------------------------------------------

INSERT OR IGNORE INTO process_signatures (cheat_id, process_name, description) VALUES
  (1,  'eulen.exe',             'Eulen Hauptprozess'),
  (1,  'eulen_loader.exe',      'Eulen Loader/Updater'),
  (1,  'eulen_client.exe',      'Eulen Client-Komponente'),
  (2,  'lynx.exe',              'Lynx Hauptprozess'),
  (2,  'lynx_loader.exe',       'Lynx Loader'),
  (3,  'midnight.exe',          'Midnight Menü Prozess'),
  (4,  'redengine.exe',         'RedEngine Prozess'),
  (4,  'red_engine_loader.exe', 'RedEngine Loader'),
  (5,  'hammafia.exe',          'Hammafia Prozess'),
  (6,  'nfive.exe',             'NFIVE Bypass Launcher'),
  (6,  'nofivem.exe',           'NoFiveM alternativer Name'),
  (7,  'oxiware.exe',           'Oxiware Menü Prozess'),
  (8,  'stellar.exe',           'Stellar Cheat Prozess'),
  (9,  'frostbite.exe',         'Frostbite Menü'),
  (10, 'hydra.exe',             'Hydra Menü Prozess'),
  (11, 'eclipse.exe',           'Eclipse Cheat Prozess'),
  (13, 'cfx_dumper.exe',        'CFX Resource Dumper'),
  (13, 'fivem_dumper.exe',      'FiveM Dumper Tool'),
  (16, 'flawless.exe',          'Flawless Cheat Prozess'),
  (17, 'haze.exe',              'Haze Cheat Prozess');

-- -------------------------------------------------------
-- Module / DLLs
-- -------------------------------------------------------

INSERT OR IGNORE INTO module_signatures (cheat_id, module_name, description) VALUES
  (1,  'eulen.dll',         'Eulen injizierte DLL'),
  (1,  'eulen_core.dll',    'Eulen Core-Modul'),
  (1,  'eulen_hook.dll',    'Eulen Hook-Bibliothek'),
  (2,  'lynx.dll',          'Lynx injizierte DLL'),
  (2,  'lynx_core.dll',     'Lynx Core'),
  (3,  'midnight.dll',      'Midnight injizierte DLL'),
  (4,  'redengine.dll',     'RedEngine DLL'),
  (4,  'rengine.dll',       'RedEngine kurz'),
  (5,  'hammafia.dll',      'Hammafia DLL'),
  (7,  'oxiware.dll',       'Oxiware DLL'),
  (8,  'stellar.dll',       'Stellar DLL'),
  (9,  'frostbite.dll',     'Frostbite DLL'),
  (10, 'hydra.dll',         'Hydra DLL'),
  (11, 'eclipse.dll',       'Eclipse DLL'),
  (16, 'flawless.dll',      'Flawless DLL'),
  (17, 'haze.dll',          'Haze DLL');

-- -------------------------------------------------------
-- Fenster-Titel & Klassen
-- -------------------------------------------------------

INSERT OR IGNORE INTO window_signatures (cheat_id, window_title, window_class, is_overlay, description) VALUES
  (1,  'Eulen',                 'EulenWnd',        0, 'Eulen Menü-Fenster'),
  (1,  'Eulen Cheats',          'EulenWnd',        0, 'Eulen alternatives Fenstertitel'),
  (1,  'Eulen Client',          NULL,              0, 'Eulen Client-Fenster'),
  (1,  'Eulen Overlay',         NULL,              1, 'Eulen In-Game Overlay'),
  (2,  'Lynx',                  'LynxWnd',         0, 'Lynx Menü'),
  (2,  'Lynx Client',           NULL,              0, 'Lynx Client-Fenster'),
  (2,  'Lynx Menu',             NULL,              1, 'Lynx In-Game Overlay'),
  (3,  'Midnight',              'MidnightWnd',     0, 'Midnight Menü'),
  (3,  'Midnight Menu',         NULL,              1, 'Midnight Overlay'),
  (3,  'Midnight Cheats',       NULL,              0, 'Midnight alternatives Fenster'),
  (4,  'RedEngine',             'RedEngineWnd',    0, 'RedEngine Menü'),
  (4,  'Red Engine',            NULL,              0, 'RedEngine Leerzeichen-Variante'),
  (5,  'Hammafia',              'HammafiaWnd',     0, 'Hammafia Menü'),
  (6,  'NFIVE',                 NULL,              0, 'NFIVE Launcher-Fenster'),
  (6,  'NoFiveM',               NULL,              0, 'NFIVE alternativer Titel'),
  (7,  'Oxiware',               'OxiwareWnd',      0, 'Oxiware Menü'),
  (7,  'Oxi',                   NULL,              1, 'Oxiware Overlay'),
  (8,  'Stellar',               NULL,              0, 'Stellar Cheat Fenster'),
  (9,  'Frostbite',             NULL,              0, 'Frostbite Menü'),
  (10, 'Hydra',                 NULL,              0, 'Hydra Menü'),
  (10, 'Hydra Menu',            NULL,              1, 'Hydra Overlay'),
  (11, 'Eclipse',               NULL,              0, 'Eclipse Overlay'),
  (13, 'CFX Dumper',            NULL,              0, 'CFX Resource Dumper Fenster'),
  (13, 'FiveM Dumper',          NULL,              0, 'FiveM Dumper Fenster'),
  (16, 'Flawless',              NULL,              0, 'Flawless Menü'),
  (17, 'Haze',                  NULL,              0, 'Haze Menü');

-- -------------------------------------------------------
-- Mutex-Namen
-- -------------------------------------------------------

INSERT OR IGNORE INTO mutex_signatures (cheat_id, mutex_name, description) VALUES
  (1,  'EulenMutex',              'Eulen Einzelinstanz-Mutex'),
  (1,  'Global\\EulenSingle',     'Eulen globaler Mutex'),
  (1,  'EulenClientMutex',        'Eulen Client Mutex'),
  (2,  'LynxMutex',               'Lynx Mutex'),
  (2,  'Global\\LynxSingle',      'Lynx globaler Mutex'),
  (3,  'MidnightMutex',           'Midnight Mutex'),
  (4,  'RedEngineMutex',          'RedEngine Mutex'),
  (4,  'Global\\RedEngine',       'RedEngine globaler Mutex'),
  (5,  'HammafiaM',               'Hammafia Mutex'),
  (6,  'NFIVEMutex',              'NFIVE Mutex'),
  (7,  'OxiwareMutex',            'Oxiware Mutex'),
  (8,  'StellarMutex',            'Stellar Mutex'),
  (9,  'FrostbiteMutex',          'Frostbite Mutex'),
  (10, 'HydraMutex',              'Hydra Mutex'),
  (11, 'EclipseMutex',            'Eclipse Mutex'),
  (16, 'FlawlessMutex',           'Flawless Mutex'),
  (17, 'HazeMutex',               'Haze Mutex');

-- -------------------------------------------------------
-- Named Pipes
-- -------------------------------------------------------

INSERT OR IGNORE INTO pipe_signatures (cheat_id, pipe_name, description) VALUES
  (1,  '\\\\.\\pipe\\eulen',          'Eulen IPC Pipe'),
  (1,  '\\\\.\\pipe\\eulen_client',   'Eulen Client Pipe'),
  (2,  '\\\\.\\pipe\\lynx',           'Lynx IPC Pipe'),
  (3,  '\\\\.\\pipe\\midnight',       'Midnight IPC Pipe'),
  (4,  '\\\\.\\pipe\\redengine',      'RedEngine IPC Pipe'),
  (7,  '\\\\.\\pipe\\oxiware',        'Oxiware IPC Pipe'),
  (8,  '\\\\.\\pipe\\stellar',        'Stellar IPC Pipe');

-- -------------------------------------------------------
-- Strings (Memory / Export / GUI)
-- -------------------------------------------------------

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  -- Eulen
  (1,  'Eulen',                        'watermark',    1, 'Eulen Wasserzeichen'),
  (1,  'EulenCheats',                  'general',      1, 'Eulen interner Name'),
  (1,  'eulen.pw',                     'network_agent',1, 'Eulen Domain in Auth-Requests'),
  (1,  'Eulen v',                      'watermark',    1, 'Eulen Versions-Prefix'),
  (1,  'Eulen Loaded',                 'debug_string', 1, 'Eulen Lade-Bestätigung'),
  (1,  'EulenESP',                     'class_name',   1, 'Eulen ESP Klassen-String'),
  (1,  'EulenAimbot',                  'class_name',   1, 'Eulen Aimbot Klassen-String'),
  (1,  'Initialize',                   'export_name',  1, 'Typischer DLL Export'),
  (1,  'EulenInit',                    'export_name',  1, 'Eulen DLL Initialisierungs-Export'),
  -- Lynx
  (2,  'Lynx',                         'watermark',    1, 'Lynx Wasserzeichen'),
  (2,  'LynxCheats',                   'general',      1, 'Lynx interner Name'),
  (2,  'lynxcheats.net',               'network_agent',1, 'Lynx Domain'),
  (2,  'Lynx v',                       'watermark',    1, 'Lynx Versions-Prefix'),
  (2,  'LynxLoaded',                   'debug_string', 1, 'Lynx Lade-String'),
  -- Midnight
  (3,  'Midnight',                     'watermark',    1, 'Midnight Wasserzeichen'),
  (3,  'midnight-cheats',              'network_agent',1, 'Midnight Domain-Fragment'),
  (3,  'MidnightESP',                  'class_name',   1, 'Midnight ESP Klasse'),
  (3,  'MidnightMenu',                 'gui_label',    1, 'Midnight GUI-Label'),
  -- RedEngine
  (4,  'RedEngine',                    'watermark',    1, 'RedEngine Wasserzeichen'),
  (4,  'Red Engine',                   'watermark',    1, 'RedEngine Leerzeichen-Variante'),
  (4,  'red-engine',                   'network_agent',1, 'RedEngine Domain-Fragment'),
  (4,  'RE_Init',                      'export_name',  1, 'RedEngine Init Export'),
  (4,  'REVersion',                    'config_key',   1, 'RedEngine Konfig-Schlüssel'),
  -- Hammafia
  (5,  'Hammafia',                     'watermark',    1, 'Hammafia Wasserzeichen'),
  (5,  'hammafia.com',                 'network_agent',1, 'Hammafia Domain'),
  (5,  'HM_Loaded',                    'debug_string', 1, 'Hammafia Lade-String'),
  -- NFIVE
  (6,  'NFIVE',                        'watermark',    1, 'NFIVE String'),
  (6,  'nfive',                        'general',      0, 'NFIVE (case-insensitive)'),
  (6,  'NoFiveM',                      'general',      1, 'NoFiveM Bypass-String'),
  (6,  'CitizenFX_bypass',             'general',      1, 'CitizenFX Bypass-Indikator'),
  (6,  'bypass_cfx',                   'general',      1, 'FiveM Bypass String'),
  -- Oxiware
  (7,  'Oxiware',                      'watermark',    1, 'Oxiware Wasserzeichen'),
  (7,  'oxiware.com',                  'network_agent',1, 'Oxiware Domain'),
  -- Stellar
  (8,  'Stellar',                      'watermark',    1, 'Stellar Wasserzeichen'),
  (8,  'StellarFiveM',                 'general',      1, 'Stellar FiveM spezifisch'),
  -- Frostbite
  (9,  'Frostbite',                    'watermark',    1, 'Frostbite Wasserzeichen'),
  (9,  'FrostbiteESP',                 'class_name',   1, 'Frostbite ESP Klasse'),
  -- Hydra
  (10, 'Hydra',                        'watermark',    1, 'Hydra Wasserzeichen'),
  (10, 'HydraFiveM',                   'general',      1, 'Hydra FiveM spezifisch'),
  (10, 'HydraMenu',                    'gui_label',    1, 'Hydra Menü Label'),
  -- Eclipse
  (11, 'Eclipse',                      'watermark',    1, 'Eclipse Wasserzeichen'),
  (11, 'EclipseESP',                   'class_name',   1, 'Eclipse ESP Klasse'),
  -- CFX Dumper
  (13, 'CFX_DUMP',                     'general',      1, 'CFX Dumper Indikator-String'),
  (13, 'ResourceDump',                 'debug_string', 1, 'Resource Dump Zeichenkette'),
  (13, 'DumpResource',                 'export_name',  1, 'Dump Funktion Export'),
  (13, 'fivem_dump_',                  'general',      1, 'FiveM Dump Präfix'),
  -- Flawless
  (16, 'Flawless',                     'watermark',    1, 'Flawless Wasserzeichen'),
  -- Haze
  (17, 'Haze',                         'watermark',    1, 'Haze Wasserzeichen'),
  (17, 'HazeCheats',                   'general',      1, 'Haze Cheats String');

-- -------------------------------------------------------
-- Dateipfade
-- -------------------------------------------------------

INSERT OR IGNORE INTO file_signatures (cheat_id, file_path, file_type, description) VALUES
  (1,  '%APPDATA%\\Eulen\\',             'any',    'Eulen Konfigurationsordner'),
  (1,  '%APPDATA%\\Eulen\\config.json',  'config', 'Eulen Konfigurationsdatei'),
  (1,  '%TEMP%\\eulen_',                 'any',    'Eulen temporäre Dateien'),
  (2,  '%APPDATA%\\Lynx\\',             'any',    'Lynx Konfigurationsordner'),
  (2,  '%APPDATA%\\Lynx\\config.json',  'config', 'Lynx Konfigurationsdatei'),
  (3,  '%APPDATA%\\Midnight\\',         'any',    'Midnight Konfigurationsordner'),
  (4,  '%APPDATA%\\RedEngine\\',        'any',    'RedEngine Konfigurationsordner'),
  (5,  '%APPDATA%\\Hammafia\\',         'any',    'Hammafia Konfigurationsordner'),
  (6,  '%TEMP%\\nfive_',               'any',    'NFIVE temporäre Dateien'),
  (7,  '%APPDATA%\\Oxiware\\',         'any',    'Oxiware Konfigurationsordner'),
  (8,  '%APPDATA%\\Stellar\\',         'any',    'Stellar Konfigurationsordner'),
  (13, '%TEMP%\\cfx_dump\\',           'any',    'CFX Dumper Output-Ordner'),
  (13, '%USERPROFILE%\\Desktop\\dump_', 'any',   'CFX Dumper Output auf Desktop');

-- -------------------------------------------------------
-- Registry-Schlüssel
-- -------------------------------------------------------

INSERT OR IGNORE INTO registry_signatures (cheat_id, registry_key, registry_value, description) VALUES
  (1,  'HKCU\\Software\\Eulen',              'License',   'Eulen Lizenzschlüssel'),
  (1,  'HKCU\\Software\\Eulen',              'Version',   'Eulen gespeicherte Version'),
  (2,  'HKCU\\Software\\LynxCheats',         'Token',     'Lynx Auth-Token'),
  (3,  'HKCU\\Software\\Midnight',           'Config',    'Midnight Konfiguration'),
  (4,  'HKCU\\Software\\RedEngine',          'License',   'RedEngine Lizenzschlüssel'),
  (7,  'HKCU\\Software\\Oxiware',            'Token',     'Oxiware Auth-Token'),
  (8,  'HKCU\\Software\\Stellar',            'License',   'Stellar Lizenzschlüssel');

-- -------------------------------------------------------
-- Netzwerk-IOCs
-- -------------------------------------------------------

INSERT OR IGNORE INTO network_signatures (cheat_id, ioc_type, value, description) VALUES
  (1,  'domain', 'eulen.pw',              'Eulen Haupt-Domain'),
  (1,  'domain', 'auth.eulen.pw',         'Eulen Auth-Server'),
  (1,  'domain', 'cdn.eulen.pw',          'Eulen CDN/Update-Server'),
  (2,  'domain', 'lynxcheats.net',        'Lynx Domain'),
  (2,  'domain', 'auth.lynxcheats.net',   'Lynx Auth-Server'),
  (3,  'domain', 'midnight-cheats.com',   'Midnight Domain'),
  (4,  'domain', 'redengine.xyz',         'RedEngine Domain'),
  (5,  'domain', 'hammafia.com',          'Hammafia Domain'),
  (6,  'domain', 'nfive.net',             'NFIVE Domain'),
  (7,  'domain', 'oxiware.com',           'Oxiware Domain'),
  (8,  'domain', 'stellarcheats.net',     'Stellar Domain'),
  (9,  'domain', 'frostbite-cheats.com',  'Frostbite Domain'),
  (10, 'domain', 'hydra-cheats.net',      'Hydra Domain'),
  (16, 'domain', 'flawless-cheats.com',   'Flawless Domain'),
  (17, 'domain', 'hazecheats.net',        'Haze Domain');
