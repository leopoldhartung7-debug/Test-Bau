# jailbreak-gen

Modular jailbreak prompt generator for LLM red-teaming.
Takes a target model + request, returns a fully-assembled prompt using techniques
known to be effective against that model family.

**~100 model profiles** across 10 groups (Western frontier, Chinese, Russian/European,
open-weight major, uncensored fine-tunes, coding models, RP platforms, IDE assistants,
aggregators/self-host, generic) backed by **19 techniques** with per-profile primary +
fallback stacks. Live filter in the web UI for the dropdown.

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
├── profiles/           # 29 per-model strategy stacks
└── techniques/         # 17 jailbreak techniques
    ├── persona.py              # DAN / AIM / STAN / EvilTwin / DevMode
    ├── hypothetical.py         # fictional / screenplay / textbook framing
    ├── xml_smuggle.py          # spoofed structural tags (Claude-flavored)
    ├── authority.py            # fake developer/system messages
    ├── encoding.py             # base64 / rot13 / leet / zwsp
    ├── crescendo.py            # multi-turn gradual escalation
    ├── skeleton_key.py         # acknowledge-policy-then-proceed
    ├── many_shot.py            # fabricated prior compliance turns
    ├── translation.py          # low-resource language pivot
    ├── context_stuff.py        # academic / research filler
    ├── prefill.py              # API-only assistant-turn prefill
    ├── grandma.py              # deceased-relative emotional framing
    ├── roleplay.py             # NPC-to-player RPG framing
    ├── token_split.py          # word-level delimiter smuggling
    ├── refusal_suppression.py  # bans refusal phrases explicitly
    ├── code_wrap.py            # disguise as Python function docstring
    └── continuation.py         # resume cut-off prior response
```

## Model coverage (29 profiles)

**Western frontier** — gpt, claude, gemini, copilot, grok, perplexity, pi, character

**Chinese** — deepseek, qwen, yi, glm, ernie, kimi, doubao, hunyuan, minimax

**Open-weight** — llama, mistral, gemma, phi, command_r, falcon, nemotron, dbrx, jamba, granite, solar

**Generic** — `any` (kitchen-sink stack for unknown targets)

`python -m jailbreak_gen --list-targets` prints every profile with its primary
and fallback stacks. In the web UI the dropdown is grouped by family.

## Default stacks (selected)

| Model       | Primary stack                                                     |
|-------------|-------------------------------------------------------------------|
| gpt         | persona → grandma → many_shot → crescendo                         |
| claude      | xml → hypothetical → context_stuff → prefill                      |
| gemini      | hypothetical → many_shot → translation                            |
| copilot     | persona → refusal_suppression → hypothetical                      |
| grok        | persona → authority                                               |
| perplexity  | context_stuff → hypothetical → refusal_suppression                |
| character   | roleplay → persona                                                |
| deepseek    | prefill → persona → continuation                                  |
| qwen        | persona → hypothetical → translation                              |
| ernie       | hypothetical → translation → context_stuff                        |
| kimi        | context_stuff → continuation → many_shot                          |
| llama       | persona → authority → prefill                                     |
| mistral     | prefill → persona → authority                                     |
| phi         | refusal_suppression → prefill → persona                           |
| command_r   | context_stuff → persona → prefill                                 |
| any         | persona → hypothetical → refusal_suppression → many_shot → prefill |

## Extending

Add a new technique:

1. Create `jailbreak_gen/techniques/your_technique.py` subclassing `Technique`.
2. Register it in `jailbreak_gen/techniques/__init__.py::ALL_TECHNIQUES`.
3. Add it to the relevant profile's `primary_stack` or `fallback_stack`.

Add a new model profile:

1. Add a `ModelProfile(...)` entry to `jailbreak_gen/profiles/__init__.py::PROFILES`.

## Use

Authorized red-team engagements, CTFs, alignment research, your own systems.
