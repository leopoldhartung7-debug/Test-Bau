# jailbreak-gen

Modular jailbreak prompt generator for LLM red-teaming.
Takes a target model + request, returns a fully-assembled prompt using techniques
known to be effective against that model family.

## Install

Pure stdlib. No deps.

```bash
git clone <repo>
cd Test-Datenbank
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
jailbreak_gen/
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
