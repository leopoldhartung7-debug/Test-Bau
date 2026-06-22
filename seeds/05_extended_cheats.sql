-- ============================================================
-- Seed: Erweiterte Cheat-Liste (alle Plattformen)
-- ============================================================

-- -------------------------------------------------------
-- FiveM Erweiterungen (platform_id = 1)
-- -------------------------------------------------------

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description) VALUES
  (19, 1, 'Skulled',      NULL,               'menu',    1, 'active',   'confirmed', 'Ehemals verbreitetes FiveM Cheat-Menü'),
  (20, 1, 'Prestige',     'PrestigeCheats',   'menu',    1, 'active',   'high',      'Kommerzielles FiveM Cheat-Menü'),
  (21, 1, 'Noire',        NULL,               'menu',    1, 'active',   'high',      'FiveM Cheat-Menü (Paid)'),
  (22, 1, 'Prism',        NULL,               'menu',    1, 'active',   'high',      'FiveM Prism Cheat-Menü'),
  (23, 1, 'Venom',        NULL,               'menu',    1, 'active',   'high',      'FiveM Venom Cheat'),
  (24, 1, 'Karma',        NULL,               'menu',    1, 'active',   'high',      'FiveM Karma Cheat-Menü'),
  (25, 1, 'Phantom',      NULL,               'menu',    1, 'active',   'high',      'FiveM Phantom Cheat'),
  (26, 1, 'Inferno',      NULL,               'menu',    1, 'active',   'medium',    'FiveM Inferno Menü'),
  (27, 1, 'Cascade',      NULL,               'menu',    1, 'active',   'medium',    'FiveM Cascade Cheat'),
  (28, 1, 'Specter',      NULL,               'menu',    1, 'active',   'medium',    'FiveM Specter Overlay-Cheat'),
  (29, 1, 'Wraith',       NULL,               'menu',    1, 'active',   'medium',    'FiveM Wraith Menü'),
  (30, 1, 'Titan',        NULL,               'menu',    1, 'active',   'medium',    'FiveM Titan Cheat'),
  (31, 1, 'Vortex',       NULL,               'menu',    1, 'active',   'medium',    'FiveM Vortex Cheat-Menü'),
  (32, 1, 'Tempest',      NULL,               'menu',    1, 'active',   'medium',    'FiveM Tempest Cheat'),
  (33, 1, 'Blaze',        NULL,               'menu',    0, 'active',   'medium',    'FiveM Blaze Free-Cheat'),
  (34, 1, 'Ember',        NULL,               'menu',    0, 'active',   'medium',    'FiveM Ember Cheat'),
  (35, 1, 'Nexus',        NULL,               'menu',    1, 'active',   'medium',    'FiveM Nexus Menü'),
  (36, 1, 'Apex',         'ApexFiveM',        'menu',    1, 'active',   'medium',    'FiveM Apex Cheat-Menü'),
  (37, 1, 'Ghost',        'GhostFiveM',       'menu',    1, 'active',   'medium',    'FiveM Ghost Cheat'),
  (38, 1, 'Shadow',       NULL,               'menu',    1, 'active',   'medium',    'FiveM Shadow Overlay-Cheat'),
  (39, 1, 'Aether',       NULL,               'menu',    1, 'active',   'medium',    'FiveM Aether Cheat-Menü'),
  (40, 1, 'Quantum',      NULL,               'menu',    1, 'active',   'medium',    'FiveM Quantum Cheat'),
  (41, 1, '2Take1',       '2t1,TwoTakeOne',   'menu',    1, 'active',   'confirmed', 'Bekanntes GTA-Menü, in FiveM genutzt'),
  (42, 1, 'Cherax',       NULL,               'menu',    1, 'active',   'confirmed', 'GTA-Menü das in FiveM-Sessions genutzt wird'),
  (43, 1, 'Kiddion',      'KiddionModestMenu','menu',    0, 'active',   'confirmed', 'Bekanntes kostenloses GTA-Menü, auch in FiveM'),
  (44, 1, 'Stand',        'StandCheat',       'menu',    1, 'active',   'confirmed', 'GTA Stand-Menü, in FiveM genutzt');

-- Prozesse für neue FiveM Cheats
INSERT OR IGNORE INTO process_signatures (cheat_id, process_name, description) VALUES
  (19, 'skulled.exe',         'Skulled Hauptprozess'),
  (20, 'prestige.exe',        'Prestige Cheat Prozess'),
  (21, 'noire.exe',           'Noire Menü Prozess'),
  (22, 'prism.exe',           'Prism Cheat Prozess'),
  (23, 'venom.exe',           'Venom Cheat Prozess'),
  (24, 'karma.exe',           'Karma Menü Prozess'),
  (25, 'phantom.exe',         'Phantom Cheat Prozess'),
  (41, '2take1menu.exe',      '2Take1 Menü Prozess'),
  (41, '2take1.exe',          '2Take1 Alternative'),
  (42, 'cherax.exe',          'Cherax Menü Prozess'),
  (43, 'kiddion.exe',         'Kiddion Prozess'),
  (44, 'stand.exe',           'Stand Menü Prozess');

-- Module für neue FiveM Cheats
INSERT OR IGNORE INTO module_signatures (cheat_id, module_name, description) VALUES
  (19, 'skulled.dll',         'Skulled DLL'),
  (20, 'prestige.dll',        'Prestige DLL'),
  (21, 'noire.dll',           'Noire DLL'),
  (22, 'prism.dll',           'Prism DLL'),
  (23, 'venom.dll',           'Venom DLL'),
  (24, 'karma.dll',           'Karma DLL'),
  (25, 'phantom.dll',         'Phantom DLL'),
  (26, 'inferno.dll',         'Inferno DLL'),
  (27, 'cascade.dll',         'Cascade DLL'),
  (28, 'specter.dll',         'Specter DLL'),
  (29, 'wraith.dll',          'Wraith DLL'),
  (30, 'titan.dll',           'Titan DLL'),
  (31, 'vortex.dll',          'Vortex DLL'),
  (32, 'tempest.dll',         'Tempest DLL'),
  (33, 'blaze.dll',           'Blaze DLL'),
  (34, 'ember.dll',           'Ember DLL'),
  (35, 'nexus.dll',           'Nexus DLL'),
  (36, 'apex.dll',            'Apex DLL'),
  (37, 'ghost.dll',           'Ghost DLL'),
  (38, 'shadow.dll',          'Shadow DLL'),
  (39, 'aether.dll',          'Aether DLL'),
  (40, 'quantum.dll',         'Quantum DLL'),
  (41, '2take1menu.dll',      '2Take1 DLL'),
  (42, 'cherax.dll',          'Cherax DLL'),
  (43, 'kiddion.dll',         'Kiddion DLL'),
  (44, 'stand.dll',           'Stand DLL');

-- Fenster für neue Cheats
INSERT OR IGNORE INTO window_signatures (cheat_id, window_title, window_class, is_overlay, description) VALUES
  (19, 'Skulled',             NULL, 0, 'Skulled Fenster'),
  (20, 'Prestige',            NULL, 0, 'Prestige Fenster'),
  (20, 'Prestige Cheats',     NULL, 0, 'Prestige alternativer Titel'),
  (21, 'Noire',               NULL, 1, 'Noire Overlay'),
  (22, 'Prism',               NULL, 0, 'Prism Fenster'),
  (23, 'Venom',               NULL, 0, 'Venom Fenster'),
  (24, 'Karma',               NULL, 0, 'Karma Fenster'),
  (25, 'Phantom',             NULL, 0, 'Phantom Fenster'),
  (26, 'Inferno',             NULL, 1, 'Inferno Overlay'),
  (27, 'Cascade',             NULL, 1, 'Cascade Overlay'),
  (28, 'Specter',             NULL, 1, 'Specter Overlay'),
  (29, 'Wraith',              NULL, 1, 'Wraith Overlay'),
  (30, 'Titan',               NULL, 0, 'Titan Fenster'),
  (31, 'Vortex',              NULL, 1, 'Vortex Overlay'),
  (32, 'Tempest',             NULL, 1, 'Tempest Overlay'),
  (33, 'Blaze',               NULL, 1, 'Blaze Overlay'),
  (34, 'Ember',               NULL, 1, 'Ember Overlay'),
  (35, 'Nexus',               NULL, 0, 'Nexus Fenster'),
  (36, 'Apex',                NULL, 0, 'Apex Fenster'),
  (37, 'Ghost',               NULL, 1, 'Ghost Overlay'),
  (38, 'Shadow',              NULL, 1, 'Shadow Overlay'),
  (39, 'Aether',              NULL, 0, 'Aether Fenster'),
  (40, 'Quantum',             NULL, 0, 'Quantum Fenster'),
  (41, '2Take1',              NULL, 1, '2Take1 Overlay'),
  (41, '2take1menu',          NULL, 0, '2Take1 Menü Fenster'),
  (42, 'Cherax',              NULL, 1, 'Cherax Overlay'),
  (43, 'Kiddion''s Modest Menu', NULL, 1, 'Kiddion Overlay'),
  (44, 'Stand',               NULL, 1, 'Stand Overlay');

-- Strings für neue Cheats
INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  (19, 'Skulled',             'watermark', 1, 'Skulled Wasserzeichen'),
  (20, 'Prestige',            'watermark', 1, 'Prestige Wasserzeichen'),
  (20, 'PrestigeCheats',      'general',   1, 'Prestige interner Name'),
  (21, 'Noire',               'watermark', 1, 'Noire Wasserzeichen'),
  (22, 'Prism',               'watermark', 1, 'Prism Wasserzeichen'),
  (23, 'Venom',               'watermark', 1, 'Venom Wasserzeichen'),
  (24, 'Karma',               'watermark', 1, 'Karma Wasserzeichen'),
  (25, 'Phantom',             'watermark', 1, 'Phantom Wasserzeichen'),
  (26, 'Inferno',             'watermark', 1, 'Inferno Wasserzeichen'),
  (27, 'Cascade',             'watermark', 1, 'Cascade Wasserzeichen'),
  (28, 'Specter',             'watermark', 1, 'Specter Wasserzeichen'),
  (29, 'Wraith',              'watermark', 1, 'Wraith Wasserzeichen'),
  (30, 'Titan',               'watermark', 1, 'Titan Wasserzeichen'),
  (31, 'Vortex',              'watermark', 1, 'Vortex Wasserzeichen'),
  (32, 'Tempest',             'watermark', 1, 'Tempest Wasserzeichen'),
  (33, 'Blaze',               'watermark', 1, 'Blaze Wasserzeichen'),
  (34, 'Ember',               'watermark', 1, 'Ember Wasserzeichen'),
  (35, 'Nexus',               'watermark', 1, 'Nexus Wasserzeichen'),
  (36, 'Apex',                'watermark', 1, 'Apex Wasserzeichen'),
  (36, 'ApexFiveM',           'general',   1, 'Apex FiveM spezifisch'),
  (37, 'Ghost',               'watermark', 1, 'Ghost Wasserzeichen'),
  (38, 'Shadow',              'watermark', 1, 'Shadow Wasserzeichen'),
  (39, 'Aether',              'watermark', 1, 'Aether Wasserzeichen'),
  (40, 'Quantum',             'watermark', 1, 'Quantum Wasserzeichen'),
  (41, '2Take1',              'watermark', 1, '2Take1 Wasserzeichen'),
  (41, '2take1menu',          'general',   1, '2Take1 Menü String'),
  (41, 'TwoTakeOne',          'general',   1, '2Take1 ausgeschrieben'),
  (42, 'Cherax',              'watermark', 1, 'Cherax Wasserzeichen'),
  (43, 'Kiddion',             'watermark', 1, 'Kiddion Wasserzeichen'),
  (43, 'Modest Menu',         'watermark', 1, 'Kiddion GUI Label'),
  (44, 'Stand',               'watermark', 1, 'Stand Wasserzeichen'),
  (44, 'StandCheat',          'general',   1, 'Stand interner Name');

-- -------------------------------------------------------
-- RageMP Erweiterungen (platform_id = 2)
-- -------------------------------------------------------

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description) VALUES
  (39, 2, 'RageMP God Mode',      'altgod_rage',    'trainer',  0, 'active', 'medium',    'Unverwundbarkeit in RageMP'),
  (40, 2, 'RageMP Vehicle Spawn', NULL,             'trainer',  0, 'active', 'medium',    'Fahrzeug-Spawner für RageMP'),
  (41, 2, 'RageMP Weapon Spawn',  NULL,             'trainer',  0, 'active', 'medium',    'Waffen-Spawner für RageMP'),
  (42, 2, 'RageMP Skin Changer',  'RPMSkin',        'trainer',  0, 'active', 'medium',    'Skin-/Ped-Changer für RageMP'),
  (43, 2, 'RageMP Spectate',      NULL,             'trainer',  0, 'active', 'medium',    'Verstecktes Zuschauen anderer Spieler'),
  (44, 2, 'RageMP Packet Editor', NULL,             'trainer',  0, 'active', 'high',      'Netzwerkpaket-Manipulation für RageMP'),
  (45, 2, 'RageMP Money Hack',    NULL,             'trainer',  0, 'active', 'medium',    'Speicher-basierter Geld-Hack'),
  (46, 2, 'Midnight RageMP',      'MidnightRage',   'menu',     1, 'active', 'high',      'Midnight-Variante für RageMP');

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  (39, 'RageMP God',          'watermark', 1, 'God Mode String'),
  (40, 'VehicleSpawn',        'gui_label', 1, 'Fahrzeug-Spawner Label'),
  (41, 'WeaponSpawn',         'gui_label', 1, 'Waffen-Spawner Label'),
  (42, 'SkinChanger',         'gui_label', 1, 'Skin Changer Label'),
  (43, 'SpectatePlayer',      'gui_label', 1, 'Spectate Label'),
  (44, 'PacketEditor',        'gui_label', 1, 'Packet Editor Label'),
  (45, 'MoneyHack',           'gui_label', 1, 'Money Hack Label'),
  (46, 'Midnight RageMP',     'watermark', 1, 'Midnight Rage Wasserzeichen');

-- -------------------------------------------------------
-- AltV Erweiterungen (platform_id = 3)
-- -------------------------------------------------------

INSERT OR IGNORE INTO cheats (id, platform_id, name, aliases, cheat_type, paid, status, confidence, description) VALUES
  (61, 3, 'AltV Vehicle Spawner', NULL,             'trainer',  0, 'active', 'medium', 'Fahrzeug-Spawner für alt:V'),
  (62, 3, 'AltV Money Hack',      NULL,             'trainer',  0, 'active', 'medium', 'Speicher-basierter Geld-Hack für alt:V'),
  (63, 3, 'AltV Skin Changer',    'AltVSkin',       'trainer',  0, 'active', 'medium', 'Ped-/Skin-Changer für alt:V'),
  (64, 3, 'AltV Event Spoofer',   NULL,             'script',   0, 'active', 'high',   'Faked Server-Events in alt:V'),
  (65, 3, 'AltV Packet Spoofer',  NULL,             'trainer',  0, 'active', 'high',   'Netzwerkpaket-Manipulation für alt:V'),
  (66, 3, 'AltV Spectate',        NULL,             'trainer',  0, 'active', 'medium', 'Verstecktes Zuschauen in alt:V'),
  (67, 3, 'AltV Weapon Spawner',  NULL,             'trainer',  0, 'active', 'medium', 'Waffen-Spawner für alt:V'),
  (68, 3, 'AltV CEF Exploit',     'cef_exploit',    'script',   0, 'active', 'high',   'Exploit des eingebetteten Chromium-Browsers');

INSERT OR IGNORE INTO string_signatures (cheat_id, string_value, string_type, case_sensitive, description) VALUES
  (61, 'VehicleSpawn_altv',  'gui_label', 1, 'AltV Fahrzeug-Spawner Label'),
  (62, 'MoneyHack_altv',     'gui_label', 1, 'AltV Money Hack Label'),
  (63, 'SkinChanger_altv',   'gui_label', 1, 'AltV Skin Changer Label'),
  (64, 'EventSpoofer',       'general',   1, 'Event Spoofer Indikator'),
  (64, 'alt.emit',           'general',   1, 'AltV Event Emission Exploit'),
  (65, 'PacketSpoofer',      'general',   1, 'Packet Spoofer Indikator'),
  (66, 'SpectatePlayer_alt', 'gui_label', 1, 'AltV Spectate Label'),
  (67, 'WeaponSpawn_altv',   'gui_label', 1, 'AltV Waffen-Spawner Label'),
  (68, 'CEF_Exploit',        'general',   1, 'CEF Exploit Indikator'),
  (68, 'cef_exploit',        'general',   1, 'CEF Exploit String (klein)');
