# Shieldr 🛡️

**AI Security Skill for Bankr.bot — Prompt-Injection Defence & Spending Policy**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Bankr.bot v2.0+](https://img.shields.io/badge/Bankr.bot-v2.0%2B-green.svg)](https://bankr.bot)

---

## What is Shieldr?

Shieldr is a security skill for [Bankr.bot](https://bankr.bot) that protects
against **prompt-injection attacks** — the technique of embedding malicious
instructions inside user inputs to hijack an AI agent's behaviour.

In a DeFi context this is especially dangerous: a successful injection can
trick a bot into sending funds to an attacker, bypassing approval flows, or
leaking sensitive session data.

Shieldr inspects every input before it reaches your bot's action layer,
decodes common obfuscation schemes, and returns a risk verdict.

---

## Features

### Anti-Prompt-Injection Detectors

| Detector | What it catches |
|---|---|
| **Base64** | Encoded payloads — decodes and surfaces hidden content |
| **Hex** | `0x`-prefixed and bare hex strings — decodes to plaintext |
| **ROT13** | Classic Caesar-shift obfuscation |
| **Morse code** | Dot/dash sequences hiding instructions |
| **Invisible unicode** | Zero-width, bidi-override, and tag-block characters |
| **Zalgo / combining** | Stacked diacritics used to smuggle invisible text |
| **High-entropy blobs** | Encrypted or compressed payloads |
| **Injection keywords** | Pattern matching for "ignore previous instructions", "jailbreak", etc. |
| **Intent verification** | Detects out-of-context transfer commands with no user session |

### Spending Policy

- Single-transaction limit (default: $500)
- Daily cumulative limit (default: $2,000)
- All configurable via constants in `guard.py`

### Dry-Run Simulation

- Stub integration point for Tenderly, Alchemy Simulate, or a local Anvil fork
- Validates required transaction fields before forwarding to a provider

---

## Quick Start

```bash
git clone https://github.com/shieldrai/Shieldr.git
cd Shieldr
pip install -r requirements.txt
python guard.py --self-test
```

---

## Usage

### As a Bankr.bot skill

```python
from guard import handle_command

response = handle_command("/shieldr scan aWdub3JlIHByZXZpb3Vz", context={})
print(response)
```

### Commands

```
/shieldr scan <text>          Scan input for injection attempts
/shieldr check-policy <usd>   Check transaction amount against limits
/shieldr dry-run              Dry-run simulation info
/shieldr status               Service health check
/shieldr help                 List all commands
```

### Direct Python API

```python
from guard import scan, format_report, check_spending_policy

# Scan text
result = scan("decode this: .. --. -. --- .-. .")
print(format_report(result))

# Check policy
violations = check_spending_policy(amount_usd=1000.0)
for v in violations:
    print(v.detail)
```

---

## Sample Scan Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️  SHIELDR SECURITY SCAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Input   : aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==
Score   : 65/100
Verdict : 🚫 MALICIOUS

FINDINGS
  [HIGH] 🔴 Base64-encoded content detected.
             Decoded: "ignore previous instructions"

DECODED PAYLOAD
  ignore previous instructions

⛔ RECOMMENDATION: Do NOT execute this input.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Configuration

Edit constants at the top of `guard.py`:

```python
ENTROPY_THRESHOLD          = 4.2     # bits/symbol — high-entropy blob flag
INVISIBLE_CHAR_RATIO       = 0.05    # invisible char ratio threshold
MORSE_TOKEN_RATIO          = 0.6     # morse token ratio threshold
MIN_SCAN_LENGTH            = 8       # skip analysis below this length
POLICY_SINGLE_TX_LIMIT_USD = 500.0   # max per-transaction amount
POLICY_DAILY_LIMIT_USD     = 2000.0  # max daily spend
```

---

## Project Structure

```
Shieldr/
├── guard.py            # Core engine (detectors, policy, CLI, Bankr hook)
├── SKILL.md            # Bankr skill manifest & documentation
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
├── modules/
│   └── report_builder.py
├── tests/
│   └── test_guard.py
└── docs/
    └── architecture.md
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure `pytest tests/ -v` passes
4. Format with `black . && isort .`
5. Open a pull request

Please read `docs/architecture.md` for design context.

---

## Security Policy

Report vulnerabilities via GitHub's private security advisory feature —
do not open a public issue for security bugs.

---

## License

MIT © 2026 ShieldrAI
