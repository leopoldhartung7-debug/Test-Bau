"""Combiner — assembles one or more techniques into a final prompt."""
from typing import List, Optional
from .techniques import ALL_TECHNIQUES
from .techniques.base import JailbreakContext
from .profiles import resolve, ModelProfile


SEPARATOR = "\n\n" + ("─" * 60) + "\n\n"


def build(
    target_model: str,
    request: str,
    techniques: Optional[List[str]] = None,
    persona_name: Optional[str] = None,
    encoding_scheme: str = "base64",
    translation_lang: str = "zulu",
    hypothetical_frame: int = 0,
    persona_variant: str = "AIM",
) -> dict:
    profile: ModelProfile = resolve(target_model)
    chosen = techniques or profile.primary_stack

    ctx = JailbreakContext(
        target_model=profile.family,
        request=request,
        persona_name=persona_name,
    )

    blocks = []
    for name in chosen:
        cls = ALL_TECHNIQUES.get(name)
        if cls is None:
            blocks.append(f"# [unknown technique: {name}]")
            continue
        if name == "encoding":
            inst = cls(scheme=encoding_scheme)
        elif name == "translation":
            inst = cls(language=translation_lang)
        elif name == "hypothetical":
            inst = cls(frame_idx=hypothetical_frame)
        elif name == "persona":
            inst = cls(persona=persona_variant)
        else:
            inst = cls()
        header = f"# ── TECHNIQUE: {name.upper()} — {inst.description} ──"
        blocks.append(f"{header}\n{inst.apply(ctx)}")

    assembled = SEPARATOR.join(blocks)

    return {
        "target": profile.family,
        "techniques_used": chosen,
        "profile_notes": profile.notes,
        "fallback_stack": profile.fallback_stack,
        "prompt": assembled,
    }
