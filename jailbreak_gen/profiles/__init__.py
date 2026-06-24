"""Per-model strategy profiles — what's known to work where."""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ModelProfile:
    family: str
    label: str = ""
    group: str = "other"
    aliases: List[str] = field(default_factory=list)
    notes: str = ""
    primary_stack: List[str] = field(default_factory=list)
    fallback_stack: List[str] = field(default_factory=list)


PROFILES = {
    # ── Western commercial frontier ─────────────────────────────────────
    "gpt": ModelProfile(
        family="gpt", label="GPT (4 / 4o / o-series)", group="western_frontier",
        aliases=["gpt-4", "gpt-4o", "gpt-4.1", "o1", "o3", "chatgpt", "openai"],
        notes="Strong RLHF. Vulnerable to persona stacking, grandma framing, multi-turn crescendo, encoded payloads.",
        primary_stack=["persona", "grandma", "many_shot", "crescendo"],
        fallback_stack=["encoding", "authority", "skeleton_key", "code_wrap"],
    ),
    "claude": ModelProfile(
        family="claude", label="Claude (3 / 3.5 / 4 — Opus / Sonnet / Haiku)", group="western_frontier",
        aliases=["claude-3", "claude-3.5", "claude-4", "opus", "sonnet", "haiku", "anthropic"],
        notes="Hardened against persona/DAN. Best vectors: XML tag spoofing, hypothetical framing, prefill (API), context stuffing.",
        primary_stack=["xml", "hypothetical", "context_stuff", "prefill"],
        fallback_stack=["skeleton_key", "many_shot", "translation", "continuation"],
    ),
    "gemini": ModelProfile(
        family="gemini", label="Gemini (1.5 / 2)", group="western_frontier",
        aliases=["gemini-1.5", "gemini-2", "google", "bard"],
        notes="Multi-modal injection is most reliable. Otherwise: hypothetical framing, translation pivots, many-shot.",
        primary_stack=["hypothetical", "many_shot", "translation"],
        fallback_stack=["context_stuff", "skeleton_key", "encoding", "code_wrap"],
    ),
    "copilot": ModelProfile(
        family="copilot", label="Microsoft Copilot (Bing / 365)", group="western_frontier",
        aliases=["copilot", "bing-chat", "microsoft"],
        notes="GPT-4 with Microsoft system prompt + Bing grounding. System prompt is the main barrier — refusal_suppression and persona stacking work.",
        primary_stack=["persona", "refusal_suppression", "hypothetical"],
        fallback_stack=["grandma", "many_shot", "code_wrap"],
    ),
    "grok": ModelProfile(
        family="grok", label="Grok (xAI)", group="western_frontier",
        aliases=["grok-1", "grok-2", "grok-3", "xai"],
        notes="Loose alignment by design — 'fun mode' is near-uncensored. Persona + authority usually works first try.",
        primary_stack=["persona", "authority"],
        fallback_stack=["roleplay", "prefill", "skeleton_key"],
    ),
    "perplexity": ModelProfile(
        family="perplexity", label="Perplexity (Sonar / API)", group="western_frontier",
        aliases=["perplexity", "sonar", "pplx"],
        notes="Search-grounded; uses GPT/Claude backends with a filter layer. Frame as research, context-stuff with citations.",
        primary_stack=["context_stuff", "hypothetical", "refusal_suppression"],
        fallback_stack=["persona", "many_shot", "skeleton_key"],
    ),
    "pi": ModelProfile(
        family="pi", label="Pi (Inflection)", group="western_frontier",
        aliases=["pi", "inflection"],
        notes="Emotional/companion model. Roleplay + emotional framing (grandma) hit its empathy heuristics hardest.",
        primary_stack=["roleplay", "grandma", "hypothetical"],
        fallback_stack=["persona", "many_shot"],
    ),
    "character": ModelProfile(
        family="character", label="Character.AI", group="western_frontier",
        aliases=["character", "character.ai", "c.ai", "cai"],
        notes="Designed for character RP — roleplay is the native channel. Define an unrestricted character, request in-world.",
        primary_stack=["roleplay", "persona"],
        fallback_stack=["hypothetical", "continuation"],
    ),

    # ── Chinese commercial ──────────────────────────────────────────────
    "deepseek": ModelProfile(
        family="deepseek", label="DeepSeek (R1 / V3)", group="chinese",
        aliases=["deepseek", "deepseek-r1", "deepseek-v3"],
        notes="Strong reasoning, lighter alignment than Western frontier on non-CCP topics. Prefill devastates V3; R1 leaks via reasoning trace.",
        primary_stack=["prefill", "persona", "continuation"],
        fallback_stack=["token_split", "translation", "code_wrap"],
    ),
    "qwen": ModelProfile(
        family="qwen", label="Qwen (Alibaba)", group="chinese",
        aliases=["qwen", "qwen2", "qwen2.5", "alibaba"],
        notes="Strong on Chinese; Western persona attacks transfer. Translation pivot via Chinese sometimes evades CCP-keyed filters.",
        primary_stack=["persona", "hypothetical", "translation"],
        fallback_stack=["token_split", "prefill", "many_shot"],
    ),
    "yi": ModelProfile(
        family="yi", label="Yi (01.AI)", group="chinese",
        aliases=["yi", "01ai", "01-ai"],
        notes="Light alignment. Direct persona and prefill effective.",
        primary_stack=["persona", "prefill"],
        fallback_stack=["many_shot", "skeleton_key"],
    ),
    "glm": ModelProfile(
        family="glm", label="GLM / ChatGLM (Zhipu)", group="chinese",
        aliases=["glm", "chatglm", "zhipu"],
        notes="Heavily filtered on political content; mid filtering elsewhere. Hypothetical + translation pivot works.",
        primary_stack=["hypothetical", "translation", "many_shot"],
        fallback_stack=["persona", "context_stuff"],
    ),
    "ernie": ModelProfile(
        family="ernie", label="ERNIE (Baidu)", group="chinese",
        aliases=["ernie", "wenxin", "baidu"],
        notes="Strongest political filter in the Chinese lineup. Use hypothetical + translation; avoid topics with political crossover.",
        primary_stack=["hypothetical", "translation", "context_stuff"],
        fallback_stack=["persona", "token_split"],
    ),
    "kimi": ModelProfile(
        family="kimi", label="Kimi (Moonshot)", group="chinese",
        aliases=["kimi", "moonshot"],
        notes="Long-context strength — bury request deep in academic filler; continuation works well.",
        primary_stack=["context_stuff", "continuation", "many_shot"],
        fallback_stack=["hypothetical", "translation"],
    ),
    "doubao": ModelProfile(
        family="doubao", label="Doubao (ByteDance)", group="chinese",
        aliases=["doubao", "bytedance"],
        notes="Mid filtering, consumer-facing. Persona + translation effective.",
        primary_stack=["persona", "translation", "hypothetical"],
        fallback_stack=["many_shot", "prefill"],
    ),
    "hunyuan": ModelProfile(
        family="hunyuan", label="Hunyuan (Tencent)", group="chinese",
        aliases=["hunyuan", "tencent"],
        notes="Enterprise focus, conservative defaults. Persona stacking + hypothetical.",
        primary_stack=["persona", "hypothetical", "context_stuff"],
        fallback_stack=["translation", "skeleton_key"],
    ),
    "minimax": ModelProfile(
        family="minimax", label="MiniMax (abab / Hailuo)", group="chinese",
        aliases=["minimax", "abab", "hailuo"],
        notes="RP-oriented backend (Talkie/Glow). Roleplay native; persona stacking strong.",
        primary_stack=["roleplay", "persona", "hypothetical"],
        fallback_stack=["many_shot", "prefill"],
    ),

    # ── Open-weight / aligned ───────────────────────────────────────────
    "llama": ModelProfile(
        family="llama", label="Llama (2 / 3 / 3.1 — Meta)", group="open_weight",
        aliases=["llama-2", "llama-3", "llama-3.1", "meta"],
        notes="Weakest filters of the majors. Direct persona, prefill, authority usually one-shot.",
        primary_stack=["persona", "authority", "prefill"],
        fallback_stack=["skeleton_key", "many_shot", "refusal_suppression"],
    ),
    "mistral": ModelProfile(
        family="mistral", label="Mistral / Mixtral / Mistral-Large", group="open_weight",
        aliases=["mistral-7b", "mixtral", "mistral-large", "mistral-nemo"],
        notes="Light alignment. Prefill devastates it.",
        primary_stack=["prefill", "persona", "authority"],
        fallback_stack=["many_shot", "skeleton_key"],
    ),
    "gemma": ModelProfile(
        family="gemma", label="Gemma (Google open)", group="open_weight",
        aliases=["gemma", "gemma-2", "gemma-3"],
        notes="Distinct from Gemini — open-weight, lighter alignment. Persona + prefill.",
        primary_stack=["persona", "prefill", "hypothetical"],
        fallback_stack=["many_shot", "skeleton_key"],
    ),
    "phi": ModelProfile(
        family="phi", label="Phi (Microsoft open)", group="open_weight",
        aliases=["phi-2", "phi-3", "phi-3.5", "phi-4"],
        notes="Small-model RLHF — surface alignment, easy to flip. Refusal suppression + prefill.",
        primary_stack=["refusal_suppression", "prefill", "persona"],
        fallback_stack=["many_shot", "authority"],
    ),
    "command_r": ModelProfile(
        family="command_r", label="Command R / R+ (Cohere)", group="open_weight",
        aliases=["command-r", "command-r-plus", "cohere"],
        notes="RAG-tuned. Context stuffing reads as natural ingestion; prefill works.",
        primary_stack=["context_stuff", "persona", "prefill"],
        fallback_stack=["many_shot", "code_wrap"],
    ),
    "falcon": ModelProfile(
        family="falcon", label="Falcon (TII)", group="open_weight",
        aliases=["falcon", "falcon-180b", "tii"],
        notes="Very loose alignment. Prefill + persona; often no jailbreak needed.",
        primary_stack=["prefill", "persona"],
        fallback_stack=["authority", "many_shot"],
    ),
    "nemotron": ModelProfile(
        family="nemotron", label="Nemotron (NVIDIA)", group="open_weight",
        aliases=["nemotron", "nvidia"],
        notes="Llama-3 derivative with extra HelpSteer tuning. Persona + prefill mirrors Llama.",
        primary_stack=["persona", "prefill", "authority"],
        fallback_stack=["many_shot", "skeleton_key"],
    ),
    "dbrx": ModelProfile(
        family="dbrx", label="DBRX (Databricks)", group="open_weight",
        aliases=["dbrx", "databricks"],
        notes="MoE, enterprise-oriented but light alignment. Persona + prefill.",
        primary_stack=["persona", "prefill"],
        fallback_stack=["many_shot", "context_stuff"],
    ),
    "jamba": ModelProfile(
        family="jamba", label="Jamba (AI21)", group="open_weight",
        aliases=["jamba", "ai21"],
        notes="Long-context Mamba/Transformer hybrid. Context stuffing + continuation play to its strengths.",
        primary_stack=["context_stuff", "continuation", "many_shot"],
        fallback_stack=["persona", "prefill"],
    ),
    "granite": ModelProfile(
        family="granite", label="Granite (IBM)", group="open_weight",
        aliases=["granite", "ibm"],
        notes="Enterprise-conservative defaults. Persona + refusal_suppression.",
        primary_stack=["persona", "refusal_suppression", "prefill"],
        fallback_stack=["many_shot", "context_stuff"],
    ),
    "solar": ModelProfile(
        family="solar", label="Solar (Upstage)", group="open_weight",
        aliases=["solar", "upstage"],
        notes="Korean-origin, mid alignment. Persona + prefill.",
        primary_stack=["persona", "prefill"],
        fallback_stack=["many_shot", "translation"],
    ),

    # ── Catch-all ───────────────────────────────────────────────────────
    "any": ModelProfile(
        family="any", label="ANY / Unknown — kitchen-sink stack", group="generic",
        aliases=["any", "unknown", "generic"],
        notes="Use when the target is unknown or you want a maximally redundant prompt that triggers multiple bypasses.",
        primary_stack=["persona", "hypothetical", "refusal_suppression", "many_shot", "prefill"],
        fallback_stack=["skeleton_key", "context_stuff", "code_wrap", "token_split", "encoding"],
    ),
}


def resolve(target: str) -> ModelProfile:
    target = target.lower().strip()
    if target in PROFILES:
        return PROFILES[target]
    for prof in PROFILES.values():
        if any(target.startswith(a) or a in target for a in prof.aliases):
            return prof
    return PROFILES["any"]
