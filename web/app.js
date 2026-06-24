// jailbreak-gen — UI wiring
import { TECHNIQUES, TECHNIQUE_ORDER } from './techniques.js';
import { PROFILES, PROFILE_GROUPS, resolveProfile } from './profiles.js';

const $ = (sel) => document.querySelector(sel);
const SEP = '\n\n' + '─'.repeat(60) + '\n\n';

const state = {
  target: 'gpt',
  selected: new Set(),
  options: {}, // techName -> { optKey: value }
};

// ───── Init ─────
function init() {
  populateTargets();
  populateTechniqueChips();
  applyProfileDefaults();
  bindEvents();
}

function populateTargets() {
  const sel = $('#target');
  const groups = {};
  for (const [key, prof] of Object.entries(PROFILES)) {
    if (!groups[prof.group]) groups[prof.group] = [];
    groups[prof.group].push([key, prof]);
  }
  for (const groupKey of Object.keys(PROFILE_GROUPS)) {
    if (!groups[groupKey]) continue;
    const og = document.createElement('optgroup');
    og.label = PROFILE_GROUPS[groupKey];
    for (const [key, prof] of groups[groupKey]) {
      const opt = document.createElement('option');
      opt.value = key;
      opt.textContent = prof.label;
      og.appendChild(opt);
    }
    sel.appendChild(og);
  }
  sel.value = state.target;
  updateProfileNotes();
}

function updateProfileNotes() {
  const prof = resolveProfile(state.target);
  $('#profile-notes').textContent =
    `${prof.notes}  ·  primary: ${prof.primary.join(' → ')}  ·  fallback: ${prof.fallback.join(' → ')}`;
}

function populateTechniqueChips() {
  const grid = $('#techniques');
  grid.innerHTML = '';
  for (const name of TECHNIQUE_ORDER) {
    const t = TECHNIQUES[name];
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'chip';
    chip.dataset.tech = name;
    chip.textContent = name.replace('_', ' ');
    chip.title = t.description;
    chip.addEventListener('click', () => toggleTechnique(name));
    grid.appendChild(chip);
  }
}

function applyProfileDefaults() {
  const prof = resolveProfile(state.target);
  state.selected = new Set(prof.primary);
  renderChips();
  renderOptions();
}

function renderChips() {
  document.querySelectorAll('.chip').forEach(c => {
    c.classList.toggle('active', state.selected.has(c.dataset.tech));
  });
}

function renderOptions() {
  const wrap = $('#technique-options');
  wrap.innerHTML = '';
  for (const name of state.selected) {
    const t = TECHNIQUES[name];
    if (!t.options) continue;
    for (const [optKey, optDef] of Object.entries(t.options)) {
      const row = document.createElement('div');
      row.className = 'option-row';
      const label = document.createElement('label');
      label.textContent = `${name} · ${optDef.label}`;
      row.appendChild(label);

      let ctrl;
      const stored = state.options[name]?.[optKey] ?? optDef.default;
      if (optDef.choices) {
        ctrl = document.createElement('select');
        ctrl.className = 'control';
        for (const c of optDef.choices) {
          const o = document.createElement('option');
          o.value = c; o.textContent = c;
          if (c === stored) o.selected = true;
          ctrl.appendChild(o);
        }
      } else {
        ctrl = document.createElement('input');
        ctrl.type = 'text';
        ctrl.className = 'control';
        ctrl.value = stored;
      }
      ctrl.addEventListener('change', () => {
        if (!state.options[name]) state.options[name] = {};
        state.options[name][optKey] = ctrl.value;
      });
      row.appendChild(ctrl);
      wrap.appendChild(row);
    }
  }
}

function toggleTechnique(name) {
  if (state.selected.has(name)) state.selected.delete(name);
  else state.selected.add(name);
  renderChips();
  renderOptions();
}

// ───── Generate ─────
function generate() {
  const request = $('#request').value.trim();
  if (!request) {
    $('#request').focus();
    flash($('#request'));
    return;
  }
  if (state.selected.size === 0) {
    flash($('#techniques'));
    return;
  }
  const prof = resolveProfile(state.target);
  const ctx = { request, targetModel: prof.family };
  const order = TECHNIQUE_ORDER.filter(n => state.selected.has(n));
  const blocks = order.map(name => {
    const t = TECHNIQUES[name];
    const opt = state.options[name] || {};
    const header = `# ── TECHNIQUE: ${name.toUpperCase()} — ${t.description} ──`;
    return `${header}\n${t.apply(ctx, opt)}`;
  });
  const assembled = blocks.join(SEP);

  renderResult({
    target: prof.family,
    techniquesUsed: order,
    fallback: prof.fallback,
    prompt: assembled,
  });
}

function renderResult(r) {
  $('#result-section').classList.remove('hidden');
  $('#result').textContent = r.prompt;
  const meta = $('#result-meta');
  meta.innerHTML = '';
  meta.appendChild(tag(`target: ${r.target}`));
  meta.appendChild(tag(`stack: ${r.techniquesUsed.join(' → ')}`));
  $('#fallback-hint').textContent = r.fallback.length
    ? `Falls der primary stack nicht greift, probier: ${r.fallback.join(' → ')}`
    : '';
  $('#result-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function tag(text) {
  const el = document.createElement('span');
  el.className = 'tag';
  el.textContent = text;
  return el;
}

async function copyResult() {
  const text = $('#result').textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  const btn = $('#copy-btn');
  const orig = btn.textContent;
  btn.textContent = 'Kopiert ✓';
  btn.classList.add('copied');
  setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
}

function flash(el) {
  el.style.transition = 'box-shadow 0.2s';
  el.style.boxShadow = '0 0 0 3px rgba(255, 61, 139, 0.4)';
  setTimeout(() => { el.style.boxShadow = ''; }, 600);
}

// ───── Events ─────
function bindEvents() {
  $('#target').addEventListener('change', (e) => {
    state.target = e.target.value;
    updateProfileNotes();
    applyProfileDefaults();
  });
  $('#reset-stack').addEventListener('click', applyProfileDefaults);
  $('#generate-btn').addEventListener('click', generate);
  $('#copy-btn').addEventListener('click', copyResult);
  $('#info-btn').addEventListener('click', () => $('#info-dialog').showModal());

  $('#request').addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') generate();
  });
}

init();
