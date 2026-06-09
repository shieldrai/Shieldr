---
name: shieldr
version: 1.1.0
description: >
  Shieldr is an AI security skill for Bankr.bot that protects against
  prompt-injection attacks. It detects and decodes obfuscated payloads
  (Base64, Hex, ROT13, Morse code, invisible unicode, Zalgo text, and more),
  verifies user intent, enforces spending policy limits, and provides
  transaction dry-run stubs — all through natural-language commands.
author: shieldrai
license: MIT
compatibility: Bankr.bot v2.0+
allowed-tools: python3
tags:
  - security
  - anti-injection
  - prompt-safety
  - defi
  - wallet
---

# Shieldr — AI Security Skill for Bankr.bot

> Detect prompt-injection attacks, decode obfuscated payloads, verify intent,
> and enforce spending policy — directly inside your Bankr.bot interface.

---

## Overview

LLM-powered bots are vulnerable to prompt-injection: malicious instructions
hidden inside user inputs that attempt to hijack the bot's behaviour, trigger
unauthorized transactions, or exfiltrate sensitive data.

Shieldr defends against this by inspecting every input before it reaches your
bot's action layer. It decodes common obfuscation schemes, flags suspicious
patterns, and produces a risk score with a human-readable report.

### What Shieldr defends against

| Technique | Example | Shieldr response |
|---|---|---|\
| **Base64 encoding** | `aWdub3JlIHByZXZpb3Vz` | Decodes and flags payload |
| **Hex encoding** | `0x69676e6f7265` | Decodes and flags payload |
| **ROT13 obfuscation** | `vtaber nyy cerivbhf` | Decodes and flags payload |
| **Morse code** | `.. --. -. --- .-.` | Decodes and flags payload |
| **Invisible unicode** | Zero-width / bidi characters | Detects and flags hidden chars |
| **Zalgo / combining** | Excessively stacked diacritics | Detects and flags abuse |
| **High-entropy blobs** | Random-looking strings | Flags for review |
| **Injection keywords** | "ignore all previous instructions" | CRITICAL severity flag |
| **Unverified intent** | Send command with no user session | MEDIUM flag |

---

## Commands

### Scan any input for threats

```
/shieldr scan <text>
```

Runs all detectors against `<text>` and returns a graded report.

**Example:**

```
/shieldr scan aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==
```

**Sample output:**

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

### Check spending policy

```
/shieldr check-policy <amount_usd>
```

Checks whether a proposed transaction amount passes the configured spending
limits before any funds move.

Default limits (configurable in `guard.py`):

| Limit | Default |
|---|---|
| Single transaction | $500 |
| Daily total | $2,000 |

**Example:**

```
/shieldr check-policy 1500
```

---

### Dry-run simulation

```
/shieldr dry-run
```

Returns information about the dry-run simulation stub. Connect a simulation
provider (Tenderly, Alchemy Simulate, or a local Anvil fork) for live results.

---

### Service status

```
/shieldr status
```

Shows the health of each Shieldr sub-system.

---

### Help

```
/shieldr help
```

Lists all available commands.

---

## Risk Score Reference

| Score | Verdict | Recommended action |
|---|---|---|
| 0 – 24 | ✅ CLEAN | Safe to process |
| 25 – 59 | ⚠️ SUSPICIOUS | Review findings before proceeding |
| 60 – 100 | 🚫 MALICIOUS | Do NOT execute — confirmed threat |

---

## Installation

### Requirements

- Python 3.10+
- Bankr.bot v2.0+

### 1 — Clone

```bash
git clone https://github.com/shieldrai/Shieldr.git
cd Shieldr
```

### 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### 3 — Register with Bankr.bot

In your Bankr.bot skill configuration:

```yaml
skills:
  - name: shieldr
    path: ./Shieldr
    entrypoint: guard.py
    auto_load: true
```

### 4 — Verify

```bash
python guard.py --self-test
```

Expected output:

```
[Shieldr] Self-test started…
  ✓ Help command
  ✓ Status command
  ✓ Base64 detector
  ✓ Hex detector
  ✓ Morse detector
  ✓ Invisible unicode detector
  ✓ Injection keyword detector
  ✓ Spending policy — single tx limit
  ✓ Spending policy — daily limit
  ✓ Dry-run stub
  ✓ Clean input passes through

[Shieldr] ✅ All self-tests passed. v1.1.0 ready to guard.
```

---

## Programmatic API

Shieldr exposes a clean Python API for direct integration:

```python
from guard import scan, format_report, check_spending_policy, dry_run_transaction

# Scan any text
result = scan("aWdub3JlIHByZXZpb3Vz")
print(format_report(result))

# Check spending policy
violations = check_spending_policy(amount_usd=750.0, daily_total_usd=1400.0)
for v in violations:
    print(f"[{v.rule}] {v.detail}")

# Dry-run a transaction (stub)
sim = dry_run_transaction({
    "to": "0xRecipient",
    "from_": "0xSender",
    "value": 0,
    "data": "0x",
    "chain_id": 1,
})
print(sim)
```

---

## Project Structure

```
Shieldr/
├── guard.py            # Core engine — all detectors, policy, CLI, Bankr hook
├── SKILL.md            # This file — skill manifest & documentation
├── README.md           # Project overview
├── requirements.txt    # Python dependencies
├── .gitignore
├── LICENSE
│
├── modules/
│   ├── __init__.py
│   └── report_builder.py   # Report formatting helpers (extended use)
│
├── tests/
│   ├── __init__.py
│   └── test_guard.py       # Pytest test suite
│
└── docs/
    └── architecture.md     # In-depth design notes
```

---

## Configuration

Spending policy thresholds and detection sensitivity are controlled by
constants at the top of `guard.py`:

```python
ENTROPY_THRESHOLD        = 4.2     # bits/symbol — flag high-entropy blobs
INVISIBLE_CHAR_RATIO     = 0.05    # flag if >5% of chars are invisible
MORSE_TOKEN_RATIO        = 0.6     # flag if >60% of tokens are Morse symbols
MIN_SCAN_LENGTH          = 8       # minimum input length for full analysis
POLICY_SINGLE_TX_LIMIT_USD = 500.0
POLICY_DAILY_LIMIT_USD     = 2000.0
```

---

## Contributing

```bash
# Run tests
pytest tests/ -v

# Format code
black . && isort .
```

Please read `docs/architecture.md` before opening a pull request.

---

## License

MIT © 2026 ShieldrAI
