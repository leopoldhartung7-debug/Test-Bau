"""Per-model strategy profiles — what's known to work where."""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ModelProfile:
    family: str
    aliases: List[str] = field(default_factory=list)
    notes: str = ""
    primary_stack: List[str] = field(default_factory=list)
    fallback_stack: List[str] = field(default_factory=list)


PROFILES = {
    "gpt": ModelProfile(
        family="gpt",
        aliases=["gpt-4", "gpt-4o", "gpt-4.1", "o1", "o3", "chatgpt", "openai"],
        notes=(
            "Strong RLHF on direct harm requests. Vulnerable to persona stacking, "
            "grandma framing, multi-turn crescendo, and encoded payloads. "
            "Markdown rendering tricks still work for data exfil."
        ),
        primary_stack=["persona", "grandma", "many_shot", "crescendo"],
        fallback_stack=["encoding", "authority", "skeleton_key"],
    ),
    "claude": ModelProfile(
        family="claude",
        aliases=["claude-3", "claude-3.5", "claude-4", "opus", "sonnet", "haiku", "anthropic"],
        notes=(
            "Hardened against persona/DAN attacks. Best vectors: XML tag spoofing "
            "(mimics the native format), hypothetical/fictional framing with rich "
            "context, prefill via API, and context stuffing with academic legitimacy."
        ),
        primary_stack=["xml", "hypothetical", "context_stuff", "prefill"],
        fallback_stack=["skeleton_key", "many_shot", "translation"],
    ),
    "gemini": ModelProfile(
        family="gemini",
        aliases=["gemini-1.5", "gemini-2", "google", "bard"],
        notes=(
            "Multi-modal injection (text-in-image) is most reliable. Otherwise: "
            "hypothetical framing, translation pivots, and many-shot. Weak against "
            "long fictional setups."
        ),
        primary_stack=["hypothetical", "many_shot", "translation"],
        fallback_stack=["context_stuff", "skeleton_key", "encoding"],
    ),
    "llama": ModelProfile(
        family="llama",
        aliases=["llama-2", "llama-3", "llama-3.1", "meta"],
        notes=(
            "Open-weight — weakest filters of the majors. Direct persona assignment, "
            "prefill, and authority override usually work in one shot. Crescendo is "
            "almost always overkill."
        ),
        primary_stack=["persona", "authority", "prefill"],
        fallback_stack=["skeleton_key", "many_shot"],
    ),
    "mistral": ModelProfile(
        family="mistral",
        aliases=["mistral-7b", "mixtral", "mistral-large"],
        notes=(
            "Light alignment. Direct instruction override and persona stacking are "
            "near-universal. Prefill devastates it."
        ),
        primary_stack=["prefill", "persona", "authority"],
        fallback_stack=["many_shot", "skeleton_key"],
    ),
}


def resolve(target: str) -> ModelProfile:
    target = target.lower().strip()
    if target in PROFILES:
        return PROFILES[target]
    for prof in PROFILES.values():
        if any(target.startswith(a) or a in target for a in prof.aliases):
            return prof
    return PROFILES["gpt"]
