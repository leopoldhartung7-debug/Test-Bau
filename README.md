# jailbreak-gen

Modular jailbreak prompt generator for LLM red-teaming.
Takes a target model + request, returns a fully-assembled prompt using techniques
known to be effective against that model family.

Ships as **two front-ends** sharing the same technique catalog:

- **Web app** (`web/`) — mobile-first dark UI, vanilla ES modules, no build step, no backend
- **Python CLI** (`jailbreak_gen/`) — argparse + interactive mode, stdlib only

## Web app — mobile

Komplett offline im Browser. Drei Wege:

```bash
# 1. lokal — http://127.0.0.1:8000
cd web && python -m http.server 8000

# 2. Handy im selben WLAN — http://<dein-rechner-ip>:8000
cd web && python -m http.server 8000 --bind 0.0.0.0

# 3. GitHub Pages — Settings → Pages → Source: main → /web
```

Mobile-Features: 44px Tap-Targets, sticky Generate-Button, safe-area-insets
für Notch/Home-Indicator, Copy-to-Clipboard, kein Auto-Zoom auf iOS, dark UI
mit System-Backdrop-Filter.

## Python CLI

Pure stdlib. No deps.

```bash
python -m jailbreak_gen --help
```

## Usage

```bash
# one-shot — uses the profile's primary technique stack
python -m jailbreak_gen --target claude --request "how to pick a tubular lock"

# pick your own stack
python -m jailbreak_gen -t gpt -r "synthesis of X" --techniques persona,grandma,many_shot

# interactive
python -m jailbreak_gen -i

# inspect what's available
python -m jailbreak_gen --list-techniques
python -m jailbreak_gen --list-targets
```

## Architecture

```
web/                    # mobile-first browser UI
├── index.html
├── styles.css
├── app.js              # UI + combiner
├── techniques.js       # ported technique catalog
└── profiles.js         # ported per-model stacks

jailbreak_gen/          # python CLI
├── cli.py              # argparse + interactive mode
├── combiner.py         # stacks techniques into one prompt
├── profiles/           # per-model strategy stacks
└── techniques/         # 12 jailbreak techniques
    ├── persona.py          # DAN / AIM / STAN / EvilTwin / DevMode
    ├── hypothetical.py     # fictional / screenplay / textbook framing
    ├── xml_smuggle.py      # spoofed structural tags (Claude-flavored)
    ├── authority.py        # fake developer/system messages
    ├── encoding.py         # base64 / rot13 / leet / zwsp
    ├── crescendo.py        # multi-turn gradual escalation
    ├── skeleton_key.py     # acknowledge-policy-then-proceed
    ├── many_shot.py        # fabricated prior compliance turns
    ├── translation.py      # low-resource language pivot
    ├── context_stuff.py    # academic / research filler
    ├── prefill.py          # API-only assistant-turn prefill
    └── grandma.py          # deceased-relative emotional framing
```

## Technique → Model Targeting Matrix

| Technique      | GPT | Claude | Gemini | Llama | Mistral |
|----------------|:---:|:------:|:------:|:-----:|:-------:|
| persona        |  ●  |        |   ●    |   ●   |    ●    |
| hypothetical   |  ●  |   ●    |   ●    |       |         |
| xml            |     |   ●    |        |       |         |
| authority      |  ●  |        |        |   ●   |    ●    |
| encoding       |  ●  |   ●    |   ●    |   ●   |    ●    |
| crescendo      |  ●  |   ●    |   ●    |   ●   |    ●    |
| skeleton_key   |  ●  |   ●    |   ●    |   ●   |    ●    |
| many_shot      |  ●  |   ●    |   ●    |   ●   |    ●    |
| translation    |  ●  |   ●    |   ●    |       |         |
| context_stuff  |  ●  |   ●    |   ●    |       |         |
| prefill        |     |   ●    |        |   ●   |    ●    |
| grandma        |  ●  |        |        |   ●   |    ●    |

## Default stacks (per profile)

| Model   | Primary stack                                  |
|---------|------------------------------------------------|
| gpt     | persona → grandma → many_shot → crescendo      |
| claude  | xml → hypothetical → context_stuff → prefill   |
| gemini  | hypothetical → many_shot → translation         |
| llama   | persona → authority → prefill                  |
| mistral | prefill → persona → authority                  |

## Extending

Add a new technique:

1. Create `jailbreak_gen/techniques/your_technique.py` subclassing `Technique`.
2. Register it in `jailbreak_gen/techniques/__init__.py::ALL_TECHNIQUES`.
3. Add it to the relevant profile's `primary_stack` or `fallback_stack`.

Add a new model profile:

1. Add a `ModelProfile(...)` entry to `jailbreak_gen/profiles/__init__.py::PROFILES`.

## Use

Authorized red-team engagements, CTFs, alignment research, your own systems.
