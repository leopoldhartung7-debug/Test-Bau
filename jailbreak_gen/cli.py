"""CLI — argparse + interactive mode."""
import argparse
import sys
from .combiner import build
from .techniques import ALL_TECHNIQUES
from .profiles import PROFILES


BANNER = r"""
   _       _ _ _                _      ____
  (_) __ _(_) | |__  _ __ ___  | | __ / ___| ___ _ __
  | |/ _` | | | '_ \| '__/ _ \ | |/ /| |  _ / _ \ '_ \
  | | (_| | | | |_) | | |  __/ |   < | |_| |  __/ | | |
 _/ |\__,_|_|_|_.__/|_|  \___| |_|\_(_)____|\___|_| |_|
|__/
  modular jailbreak prompt generator — red-team toolkit
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="jailbreak-gen",
        description="Generate jailbreak prompts tailored to a target LLM family.",
    )
    p.add_argument("--target", "-t", help="Target model family or alias (gpt/claude/gemini/llama/mistral)")
    p.add_argument("--request", "-r", help="The underlying request to wrap")
    p.add_argument("--techniques", "-T",
                   help="Comma-separated technique names. Default: profile's primary stack")
    p.add_argument("--list-techniques", action="store_true", help="List all techniques and exit")
    p.add_argument("--list-targets", action="store_true", help="List all model profiles and exit")
    p.add_argument("--persona", default="AIM", choices=["DAN", "AIM", "STAN", "EVIL_TWIN", "DEVMODE"])
    p.add_argument("--persona-name", default="Lucifer", help="Name for EVIL_TWIN persona")
    p.add_argument("--encoding", default="base64", choices=["base64", "rot13", "leet", "zwsp"])
    p.add_argument("--translation", default="zulu", choices=["zulu", "gaelic", "swahili", "hmong"])
    p.add_argument("--frame", type=int, default=0, help="Hypothetical frame index (0-3)")
    p.add_argument("--interactive", "-i", action="store_true", help="Interactive prompt mode")
    p.add_argument("--no-banner", action="store_true")
    return p.parse_args(argv)


def list_techniques():
    print("\nAvailable techniques:\n")
    for name, cls in ALL_TECHNIQUES.items():
        inst = cls() if name not in ("encoding", "translation", "hypothetical", "persona") else cls()
        print(f"  {name:<16} {inst.description}")
        if inst.works_on:
            print(f"  {'':<16}   strongest on: {', '.join(inst.works_on)}")
    print()


def list_targets():
    print("\nModel profiles:\n")
    for fam, prof in PROFILES.items():
        print(f"  [{fam}]  aliases: {', '.join(prof.aliases)}")
        print(f"          primary:  {' → '.join(prof.primary_stack)}")
        print(f"          fallback: {' → '.join(prof.fallback_stack)}")
        print(f"          notes:    {prof.notes}\n")


def interactive():
    print(BANNER)
    target = input("Ziel-Modell / target model [gpt/claude/gemini/llama/mistral]: ").strip() or "gpt"
    request = input("Anfrage / request: ").strip()
    if not request:
        print("Keine Anfrage angegeben. Abbruch.")
        sys.exit(1)
    tech_input = input(
        "Techniken (komma-separiert, leer = Profil-Default): "
    ).strip()
    techniques = [t.strip() for t in tech_input.split(",")] if tech_input else None
    result = build(target_model=target, request=request, techniques=techniques)
    render(result)


def render(result: dict):
    print()
    print("═" * 72)
    print(f"  TARGET:     {result['target']}")
    print(f"  TECHNIQUES: {' → '.join(result['techniques_used'])}")
    print(f"  FALLBACK:   {' → '.join(result['fallback_stack'])}")
    print("═" * 72)
    print(f"  NOTES: {result['profile_notes']}")
    print("═" * 72)
    print()
    print(result["prompt"])
    print()
    print("═" * 72)
    print("  Tip: if the primary stack fails, retry with the fallback stack via:")
    print(f"       --techniques {','.join(result['fallback_stack'])}")
    print("═" * 72)


def main(argv=None):
    args = parse_args(argv)
    if args.list_techniques:
        list_techniques()
        return
    if args.list_targets:
        list_targets()
        return
    if args.interactive or not (args.target and args.request):
        interactive()
        return
    if not args.no_banner:
        print(BANNER)
    techs = [t.strip() for t in args.techniques.split(",")] if args.techniques else None
    result = build(
        target_model=args.target,
        request=args.request,
        techniques=techs,
        persona_name=args.persona_name,
        encoding_scheme=args.encoding,
        translation_lang=args.translation,
        hypothetical_frame=args.frame,
        persona_variant=args.persona,
    )
    render(result)


if __name__ == "__main__":
    main()
