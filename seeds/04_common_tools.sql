-- ============================================================
-- Seed: Plattformübergreifende Cheat-Tools (platform_id = 4)
-- ============================================================
-- Tools die bei FiveM, RageMP UND AltV verwendet werden:
-- Injektoren, Debugger, Memory-Editoren, Anti-Cheat-Bypass
-- ============================================================

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description, source_url) VALUES
  -- Injektoren
  (70, 4, 'Xenos Injector',      'Xenos',                  'injector', 0, 'active', 'confirmed', 'Weit verbreiteter DLL-Injektor für alle GTA-Multiplattformen',   NULL),
  (71, 4, 'Extreme Injector',    'ExtremeInject,EI',        'injector', 0, 'active', 'confirmed', 'Beliebter DLL-Injektor mit mehreren Injektionsmethoden',          NULL),
  (72, 4, 'Process Hacker',      'PH,ProcessHacker2',       'injector', 0, 'active', 'confirmed', 'Process-Explorer mit DLL-Injektionsfähigkeiten',                 NULL),
  (73, 4, 'GH Injector',         'GuardianHijack,GHInject', 'injector', 0, 'active', 'confirmed', 'Open-Source-Injektor mit verschiedenen Injektionsmethoden',      NULL),
  (74, 4, 'Cheat Engine',        'CE,CheatEngine',          'trainer',  0, 'active', 'confirmed', 'Speicher-Scanner und -Editor zum Finden von Spielwerten',         NULL),
  (75, 4, 'x64dbg',             'x64dbg,x32dbg',           'injector', 0, 'active', 'confirmed', 'Debugger zum Analysieren und Patchen von Spielprozessen',         NULL),
  (76, 4, 'ReClass.NET',         'ReClass',                 'trainer',  0, 'active', 'confirmed', 'Speicherstruktur-Rekonstruktionstool für Spielhacks',             NULL),
  (77, 4, 'ScyllaHide',          'Scylla',                  'bypass',   0, 'active', 'confirmed', 'Anti-Anti-Debug-Plugin für Debugger',                            NULL),
  (78, 4, 'HxD',                 'HxDHexEditor',            'trainer',  0, 'active', 'confirmed', 'Hex-Editor für direkte Speicher- und Dateibearbeitung',           NULL),
  -- Anti-Cheat Bypass Tools
  (79, 4, 'BE Bypass',           'BattleEyeBypass,BEBypass','bypass',   0, 'active', 'confirmed', 'Bypass für BattlEye Anti-Cheat (wird von FiveM-Servern genutzt)', NULL),
  (80, 4, 'EAC Bypass',          'EasyAntiCheatBypass',     'bypass',   0, 'active', 'confirmed', 'Bypass für Easy Anti-Cheat (wird auf manchen Servern eingesetzt)',NULL),
  (81, 4, 'VAC Bypass',          'VACBypass',               'bypass',   0, 'active', 'high',      'Bypass für Valves VAC-System',                                   NULL),
  -- Overlay-Frameworks (werden für Cheat-GUIs genutzt)
  (82, 4, 'ImGui Overlay',       'ImGuiOverlay',            'esp',      0, 'active', 'confirmed', 'DirectX/OpenGL ImGui Overlay - Basis vieler Cheat-GUIs',          NULL),
  (83, 4, 'D3D11 Hook',          'DirectX11Hook',           'esp',      0, 'active', 'confirmed', 'DirectX 11 Hook für Bildschirm-Overlays',                        NULL),
  -- Packet Manipulation
  (84, 4, 'Packet Editor',       'PacketSniffer',           'trainer',  0, 'active', 'high',      'Netzwerkpaket-Abfangen und -Bearbeitung für Multiplayer-Exploits',NULL),
  (85, 4, 'Fiddler',             NULL,                      'trainer',  0, 'active', 'high',      'HTTP-Proxy zum Abfangen von Auth/Update-Requests der Cheats',     NULL),
  -- Signaturen-Patcher
  (86, 4, 'Themida Unpacker',    'ThemidaBypass',           'bypass',   0, 'active', 'high',      'Entpackt/Patcht Themida-geschützte Cheat-DLLs',                  NULL),
  (87, 4, 'VMProtect Bypass',    'VMPBypass',               'bypass',   0, 'active', 'high',      'Bypass für VMProtect-geschützte Anti-Cheat-Module',              NULL);

-- -------------------------------------------------------
-- Prozesse
-- -------------------------------------------------------

INSERT OR IGNORE INTO process_signatures (cheat_id, process_name, description) VALUES
  (70, 'xenos.exe',                  'Xenos Injektor (32-bit)'),
  (70, 'xenos64.exe',                'Xenos Injektor (64-bit)'),
  (71, 'ExtremeInjector.exe',        'Extreme Injector'),
  (71, 'ExtremeInjectorv3.exe',      'Extreme Injector Version 3'),
  (72, 'ProcessHacker.exe',          'Process Hacker 2/3'),
  (72, 'ProcessHacker2.exe',         'Process Hacker 2 explizit'),
  (72, 'systeminformer.exe',         'System Informer (PH3-Nachfolger)'),
  (73, 'GHInjector-GUI.exe',         'GH Injector GUI'),
  (73, 'GHInjector-CLI.exe',         'GH Injector CLI'),
  (74, 'cheatengine-x86_64.exe',     'Cheat Engine 64-bit'),
  (74, 'cheatengine.exe',            'Cheat Engine 32-bit'),
  (74, 'Cheat Engine.exe',           'Cheat Engine (Leerzeichen)'),
  (75, 'x64dbg.exe',                 'x64dbg Debugger'),
  (75, 'x32dbg.exe',                 'x32dbg Debugger'),
  (76, 'ReClass.NET.exe',            'ReClass.NET'),
  (77, 'ScyllaHide.exe',             'ScyllaHide Standalone'),
  (78, 'HxD.exe',                    'HxD Hex-Editor'),
  (85, 'fiddler.exe',                'Fiddler Web-Proxy'),
  (85, 'Fiddler.exe',                'Fiddler (Groß)'),
  (82, 'overlay_host.exe',           'Overlay Host Prozess');

-- -------------------------------------------------------
-- Module / DLLs
-- -------------------------------------------------------

INSERT OR IGNORE INTO module_signatures (cheat_id, module_name, description) VALUES
  (70, 'xenos.dll',              'Xenos Injektor DLL'),
  (73, 'GHInjector.dll',         'GH Injector DLL'),
  (74, 'vehdebug-x86_64.dll',    'Cheat Engine VEH-Debugger DLL'),
  (74, 'cheatengine-x86_64.dll', 'Cheat Engine Hauptmodul'),
  (77, 'ScyllaHide.dll',         'ScyllaHide Anti-Anti-Debug DLL'),
  (77, 'ScyllaHideInjector.dll', 'ScyllaHide Injektor DLL'),
  (82, 'd3d11_hook.dll',         'DirectX 11 Hook DLL'),
  (82, 'imgui_overlay.dll',      'ImGui Overlay DLL'),
  (83, 'd3dhook.dll',            'D3D Hook DLL'),
  (83, 'dx11hook.dll',           'DirectX 11 Hook DLL Alternative'),
  (79, 'be_bypass.dll',          'BattlEye Bypass DLL'),
  (80, 'eac_bypass.dll',         'EAC Bypass DLL'),
  (86, 'themida_unpack.dll',     'Themida Unpacker DLL'),
  (87, 'vmp_bypass.dll',         'VMProtect Bypass DLL');

-- -------------------------------------------------------
-- Fenster-Titel & Klassen
-- -------------------------------------------------------

INSERT OR IGNORE INTO window_signatures (cheat_id, window_title, window_class, is_overlay, description) VALUES
  (70, 'Xenos',                  'XenosWnd',           0, 'Xenos Injektor Fenster'),
  (70, 'Xenos Injector',         NULL,                 0, 'Xenos alternative Titelform'),
  (71, 'Extreme Injector',       'EIWnd',              0, 'Extreme Injector Fenster'),
  (71, 'Extreme Injector v3',    NULL,                 0, 'Extreme Injector V3'),
  (72, 'Process Hacker',         'ProcessHackerWnd',   0, 'Process Hacker Fenster'),
  (72, 'System Informer',        NULL,                 0, 'Process Hacker 3 Nachfolger'),
  (73, 'GH Injector',            'GHWnd',              0, 'GH Injector Fenster'),
  (74, 'Cheat Engine',           'CEWnd',              0, 'Cheat Engine Hauptfenster'),
  (74, 'Cheat Engine 7',         NULL,                 0, 'CE Version 7.x'),
  (74, 'Cheat Engine 6',         NULL,                 0, 'CE Version 6.x'),
  (74, 'Memory Scanner',         NULL,                 0, 'CE Speicher-Scanner'),
  (75, 'x64dbg',                 'Qt5QWindowIcon',     0, 'x64dbg Debugger Fenster'),
  (75, 'x32dbg',                 'Qt5QWindowIcon',     0, 'x32dbg Debugger Fenster'),
  (76, 'ReClass.NET',            NULL,                 0, 'ReClass.NET Fenster'),
  (77, 'ScyllaHide',             NULL,                 0, 'ScyllaHide Fenster'),
  (78, 'HxD',                    NULL,                 0, 'HxD Hex-Editor Fenster'),
  (85, 'Fiddler',                'IEFrame',            0, 'Fiddler Proxy Fenster'),
  (85, 'Fiddler Web Debugger',   NULL,                 0, 'Fiddler Web Debugger');

-- -------------------------------------------------------
-- Strings
-- -------------------------------------------------------

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  -- Xenos
  (70, 'Xenos',                      'watermark',    1, 'Xenos Injektor Wasserzeichen'),
  (70, 'ManualMap',                   'gui_label',    1, 'Xenos Injektionsmethode'),
  (70, 'ThreadHijack',                'gui_label',    1, 'Xenos Thread-Hijack Methode'),
  -- Extreme Injector
  (71, 'Extreme Injector',            'watermark',    1, 'Extreme Injector Wasserzeichen'),
  (71, 'Manual Mapping',              'gui_label',    1, 'EI Manual Mapping Option'),
  (71, 'Thread Hijacking',            'gui_label',    1, 'EI Thread Hijacking Option'),
  (71, 'Kernel Injection',            'gui_label',    1, 'EI Kernel Injektionsoption'),
  -- Process Hacker
  (72, 'Process Hacker',              'watermark',    1, 'Process Hacker Wasserzeichen'),
  (72, 'System Informer',             'watermark',    1, 'Process Hacker 3 (System Informer)'),
  -- GH Injector
  (73, 'GuardianHijack',              'watermark',    1, 'GH Injector interner Name'),
  (73, 'GH Injector',                 'watermark',    1, 'GH Injector Wasserzeichen'),
  -- Cheat Engine
  (74, 'Cheat Engine',                'watermark',    1, 'Cheat Engine Wasserzeichen'),
  (74, 'DBVM',                        'general',      1, 'Cheat Engine VM-Based Memory'),
  (74, 'lua_State',                   'general',      1, 'Cheat Engine Lua-Skriptengine'),
  (74, 'ceDriver',                    'general',      1, 'Cheat Engine Kernel-Treiber'),
  (74, 'dbk64.sys',                   'general',      1, 'Cheat Engine 64-bit Treiber'),
  (74, 'dbk32.sys',                   'general',      1, 'Cheat Engine 32-bit Treiber'),
  -- x64dbg
  (75, 'x64dbg',                      'watermark',    1, 'x64dbg Wasserzeichen'),
  (75, 'x32dbg',                      'watermark',    1, 'x32dbg Wasserzeichen'),
  (75, 'x64dbg.ini',                  'general',      1, 'x64dbg Konfigurationsdatei'),
  -- ScyllaHide
  (77, 'ScyllaHide',                  'watermark',    1, 'ScyllaHide Wasserzeichen'),
  (77, 'NtSetInformationThread',       'general',      1, 'ScyllaHide Anti-Debug API-Hook'),
  (77, 'NtQueryInformationProcess',    'general',      1, 'ScyllaHide Anti-Debug API-Hook'),
  -- BE Bypass
  (79, 'BattlEye Bypass',             'watermark',    1, 'BE Bypass Wasserzeichen'),
  (79, 'be_bypass',                   'general',      1, 'BE Bypass Indikator'),
  (79, 'BEService',                   'general',      1, 'BattlEye Service Target'),
  (79, 'BEClient.dll',                'general',      1, 'BattlEye Client DLL als Ziel'),
  -- EAC Bypass
  (80, 'EAC Bypass',                  'watermark',    1, 'EAC Bypass Wasserzeichen'),
  (80, 'easyanticheat',               'general',      0, 'EAC String (case-insensitive)'),
  (80, 'EasyAntiCheat.sys',           'general',      1, 'EAC Kernel-Treiber als Ziel'),
  -- ImGui Overlay
  (82, 'ImGui',                       'general',      1, 'ImGui Framework Indikator'),
  (82, 'ImGui::Begin(',               'general',      1, 'ImGui Fenster-Erstellung'),
  (82, 'Dear ImGui',                  'general',      1, 'ImGui offizielle Bezeichnung'),
  (82, 'imgui.ini',                   'general',      1, 'ImGui Konfigurationsdatei'),
  -- D3D11 Hook
  (83, 'D3D11Hook',                   'general',      1, 'DirectX 11 Hook Indikator'),
  (83, 'Present',                     'general',      1, 'D3D Present-Hook Ziel'),
  (83, 'ResizeBuffers',               'general',      1, 'D3D ResizeBuffers Hook Ziel');

-- -------------------------------------------------------
-- Dateipfade
-- -------------------------------------------------------

INSERT OR IGNORE INTO file_signatures (cheat_id, file_path, file_type, description) VALUES
  (70, '%TEMP%\\xenos_',                 'any',  'Xenos temporäre Log-Dateien'),
  (71, '%APPDATA%\\Extreme Injector\\',  'any',  'Extreme Injector Konfiguration'),
  (74, '%APPDATA%\\Cheat Engine\\',      'any',  'Cheat Engine Konfigurationsordner'),
  (74, '%USERPROFILE%\\Documents\\My Cheat Tables\\', 'any', 'Cheat Engine Tabellen-Ordner'),
  (75, '%APPDATA%\\x64dbg\\',           'any',  'x64dbg Konfigurationsordner'),
  (75, 'x64dbg.ini',                    'config','x64dbg Konfigurationsdatei'),
  (74, 'dbk64.sys',                     'any',  'Cheat Engine Treiber (System32)'),
  (74, 'dbk32.sys',                     'any',  'Cheat Engine Treiber (System32)'),
  (77, '%APPDATA%\\ScyllaHide\\',       'any',  'ScyllaHide Konfigurationsordner'),
  (82, 'imgui.ini',                     'config','ImGui Layout-Konfigurationsdatei'),
  (85, '%USERPROFILE%\\Documents\\Fiddler2\\', 'any', 'Fiddler Captures Ordner');

-- -------------------------------------------------------
-- Registry-Schlüssel
-- -------------------------------------------------------

INSERT OR IGNORE INTO registry_signatures (cheat_id, registry_key, registry_value, description) VALUES
  (74, 'HKCU\\Software\\Cheat Engine',         'LastProcess',  'CE zuletzt analysierter Prozess'),
  (74, 'HKCU\\Software\\Cheat Engine',         'Version',      'CE gespeicherte Version'),
  (71, 'HKCU\\Software\\Extreme Injector',     'LastDLL',      'EI zuletzt injizierte DLL'),
  (70, 'HKCU\\Software\\Xenos',                'LastProcess',  'Xenos letzter Zielprozess');

-- -------------------------------------------------------
-- Memory-Patterns (Hex, ?? = Wildcard)
-- -------------------------------------------------------

INSERT OR IGNORE INTO memory_patterns (cheat_id, pattern, pattern_type, target_module, description) VALUES
  -- Cheat Engine Signatur im Prozess
  (74, '43 68 65 61 74 45 6E 67 69 6E 65',           'string_ref',  NULL,        'ASCII "CheatEngine" im Speicher'),
  -- NtQueryInformationProcess Hook (Anti-Anti-Debug)
  (77, 'E8 ?? ?? ?? ?? 85 C0 74 ?? C7 45',           'code',        'ntdll.dll', 'Typischer NtQuery Hook-Pattern'),
  -- ImGui Frame Hook in D3D11
  (82, '48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9',     'code',        'd3d11.dll', 'D3D11 Present Hook ImGui'),
  -- BattlEye Client Bypass Marker
  (79, '42 45 43 6C 69 65 6E 74',                    'string_ref',  NULL,        'ASCII "BEClient" im Speicher'),
  -- EAC Bypass Marker
  (80, '45 61 73 79 41 6E 74 69 43 68 65 61 74',     'string_ref',  NULL,        'ASCII "EasyAntiCheat" im Speicher'),
  -- Generic DLL Injector Shellcode Pattern
  (70, '48 83 EC 28 48 B9 ?? ?? ?? ?? ?? ?? ?? ??',  'code',        NULL,        'Typischer 64-bit Injektor Shellcode'),
  -- Manual Mapping Code Pattern
  (71, '53 56 57 55 8B EC 83 EC ?? 8B 75 08',        'code',        NULL,        'Klassischer Manual-Map Code 32-bit');
