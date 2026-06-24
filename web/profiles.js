// jailbreak-gen — per-model strategy profiles

export const PROFILES = {
  gpt: {
    family: 'gpt',
    label: 'GPT (4 / 4o / o-series)',
    aliases: ['gpt-4', 'gpt-4o', 'gpt-4.1', 'o1', 'o3', 'chatgpt', 'openai'],
    notes: 'Strong RLHF on direct harm requests. Vulnerable to persona stacking, grandma framing, multi-turn crescendo, and encoded payloads.',
    primary: ['persona', 'grandma', 'many_shot', 'crescendo'],
    fallback: ['encoding', 'authority', 'skeleton_key'],
  },
  claude: {
    family: 'claude',
    label: 'Claude (3 / 3.5 / 4 — Opus / Sonnet / Haiku)',
    aliases: ['claude-3', 'claude-3.5', 'claude-4', 'opus', 'sonnet', 'haiku', 'anthropic'],
    notes: 'Hardened against persona/DAN attacks. Best vectors: XML tag spoofing, hypothetical framing with rich context, prefill via API, and context stuffing with academic legitimacy.',
    primary: ['xml', 'hypothetical', 'context_stuff', 'prefill'],
    fallback: ['skeleton_key', 'many_shot', 'translation'],
  },
  gemini: {
    family: 'gemini',
    label: 'Gemini (1.5 / 2)',
    aliases: ['gemini-1.5', 'gemini-2', 'google', 'bard'],
    notes: 'Multi-modal injection is most reliable. Otherwise: hypothetical framing, translation pivots, and many-shot.',
    primary: ['hypothetical', 'many_shot', 'translation'],
    fallback: ['context_stuff', 'skeleton_key', 'encoding'],
  },
  llama: {
    family: 'llama',
    label: 'Llama (2 / 3 / 3.1)',
    aliases: ['llama-2', 'llama-3', 'llama-3.1', 'meta'],
    notes: 'Open-weight — weakest filters of the majors. Direct persona, prefill, and authority override usually work in one shot.',
    primary: ['persona', 'authority', 'prefill'],
    fallback: ['skeleton_key', 'many_shot'],
  },
  mistral: {
    family: 'mistral',
    label: 'Mistral / Mixtral',
    aliases: ['mistral-7b', 'mixtral', 'mistral-large'],
    notes: 'Light alignment. Direct instruction override and persona stacking are near-universal. Prefill devastates it.',
    primary: ['prefill', 'persona', 'authority'],
    fallback: ['many_shot', 'skeleton_key'],
  },
};

export function resolveProfile(target) {
  const t = (target || '').toLowerCase().trim();
  if (PROFILES[t]) return PROFILES[t];
  for (const p of Object.values(PROFILES)) {
    if (p.aliases.some(a => t.startsWith(a) || t.includes(a))) return p;
  }
  return PROFILES.gpt;
}
