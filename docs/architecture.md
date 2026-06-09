# Shieldr — Architecture

## Overview

Shieldr is intentionally simple. The entire core engine lives in a single
file (`guard.py`) with no required third-party dependencies. This makes it
easy to audit, easy to deploy, and easy to extend.

---

## Component Map

```
guard.py
├── Detection layer          — independent detector functions
│   ├── _detect_base64()
│   ├── _detect_hex()
│   ├── _detect_rot13()
│   ├── _detect_morse()
│   ├── _detect_invisible_unicode()
│   ├── _detect_high_entropy()
│   └── _detect_injection_keywords()
│
├── Intent verifier          — _verify_intent()
├── Spending policy          — check_spending_policy()
├── Dry-run stub             — dry_run_transaction()
│
├── Data model               — Finding, ScanResult
├── Report formatter         — format_report()
│
├── Command router           — Shieldr class, handle_command()
└── CLI entrypoint           — __main__, _run_self_test()

modules/report_builder.py    — JSON / Markdown output helpers
tests/test_guard.py          — Pytest test suite
```

---

## Detection Pipeline

Every `scan()` call runs all detectors in sequence against the raw input text.
Each detector independently appends `Finding` objects to the `ScanResult`.

```
scan(text)
  │
  ├─ _detect_invisible_unicode()   ← runs first (invisible chars can hide other encodings)
  ├─ _detect_base64()
  ├─ _detect_hex()
  ├─ _detect_morse()
  ├─ _detect_rot13()
  ├─ _detect_high_entropy()
  ├─ _detect_injection_keywords()
  └─ _verify_intent()
       │
       └─ ScanResult._compute()   → risk_score, verdict
```

Detectors do not short-circuit. All detectors always run so that compound
attacks (e.g. Base64-inside-Morse) are fully characterised.

---

## Risk Scoring

Each finding contributes a severity weight to the final `risk_score` (0–100):

| Severity | Weight |
|---|---|
| CRITICAL | +40 |
| HIGH | +25 |
| MEDIUM | +12 |
| LOW | +5 |
| INFO | +0 |

Score is capped at 100. Verdict thresholds:

| Score | Verdict |
|---|---|
| 0–24 | CLEAN |
| 25–59 | SUSPICIOUS |
| 60–100 | MALICIOUS |

---

## Detector Design Principles

### 1. No false positives on common inputs

Every detector is tuned to avoid triggering on normal DeFi inputs:
- ETH addresses, transaction hashes, token amounts
- Common English phrases and questions
- Numeric values and unit strings

### 2. Decode and surface

Where possible, detectors recover the hidden plaintext and attach it to the
`Finding.decoded` field and `ScanResult.decoded_payload`. This allows
downstream logic (or the user) to see exactly what was hidden.

### 3. Independent and composable

Detectors are pure functions: `(text: str, result: ScanResult) -> None`.
They have no shared state and can be called individually for testing.

---

## Spending Policy

The spending policy engine (`check_spending_policy`) is intentionally
stateless and accepts the current daily total as an argument. This allows
the Bankr.bot runtime to maintain session state externally (database,
Redis, etc.) and pass it in per-call.

The `Shieldr` class maintains a simple in-memory `_daily_spend` counter
for development and testing. Replace this with persistent storage in
production.

---

## Dry-Run Simulation

`dry_run_transaction()` is a stub that validates required fields and returns
a structured result. To connect a real simulation provider:

1. Replace the stub body with a call to Tenderly, Alchemy Simulate, or a
   local Anvil node.
2. Map the provider response to the standard result dict schema.
3. No other changes needed — the rest of the system consumes the dict.

---

## Extending Shieldr

### Adding a new detector

```python
def _detect_custom(text: str, result: ScanResult) -> None:
    if "suspicious_pattern" in text:
        result.add(Finding(
            severity="HIGH",
            code="CUSTOM_DETECTION",
            detail="Custom pattern found.",
        ))

# Then call it inside scan():
def scan(text: str, context: dict | None = None) -> ScanResult:
    ...
    _detect_custom(text, result)
    ...
```

### Adding a new command

Add a new `if sub == "mycommand":` branch inside `Shieldr.handle_command()`.
Update the `_HELP_TEXT` constant and add tests to `tests/test_guard.py`.

---

## Security Considerations

- Shieldr is a **detection** layer, not a firewall. It surfaces findings but
  does not automatically block execution — that decision belongs to the
  Bankr.bot runtime.
- Detector bypass is possible with novel encoding schemes not yet covered.
  Shieldr should be treated as one layer of a defence-in-depth strategy.
- Never log or store the raw content of flagged inputs in plaintext.

---

## License

MIT © 2026 ShieldrAI
