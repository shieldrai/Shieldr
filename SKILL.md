---
name: shieldr
version: 1.0.0
description: >
  Shieldr is an advanced AI-powered security skill for Bankr.bot that monitors,
  analyzes, and defends against on-chain threats in real time. It provides
  wallet risk scoring, transaction simulation, phishing detection, rug-pull
  screening, honeypot analysis, and smart contract auditing — all accessible
  directly through natural-language commands in your Bankr bot interface.
author: shieldrai
license: MIT
compatibility: Bankr.bot v2.0+
allowed-tools: python3 curl jq
tags:
  - security
  - defi
  - risk
  - audit
  - on-chain
  - wallet-guard
  - phishing
  - honeypot
---

# Shieldr — Advanced AI Security Skill for Bankr.bot

> Real-time on-chain threat detection, wallet risk scoring, smart contract
> auditing, and phishing defence — powered by AI and delivered through
> natural-language commands.

---

## Overview

Shieldr integrates directly with Bankr.bot to give every user an AI security
co-pilot. Whether you are about to sign a suspicious transaction, interact with
an unknown contract, or evaluate a new token, Shieldr runs a comprehensive
battery of checks and surfaces a human-readable risk report in seconds.

Shieldr is built around five core pillars:

| Pillar | What it does |
|---|---|
| **WalletGuard** | Scores wallet addresses for exposure to exploits, drainers, and blacklists |
| **TxShield** | Simulates transactions before execution and flags dangerous state changes |
| **ContractAudit** | Static-analyses deployed smart contracts for known vulnerability patterns |
| **TokenRadar** | Detects honeypots, rug-pull mechanics, and ownership concentration |
| **PhishNet** | Identifies phishing URLs, spoofed dApps, and malicious signatures |

---

## Features

### 🛡️ WalletGuard
- Risk score (0–100) for any EVM wallet address
- Checks against major sanction lists (OFAC, Chainalysis, TRM Labs)
- Detects interaction history with known exploit contracts
- Flags wallets linked to mixer services (Tornado Cash etc.)
- Shows wallet age, activity patterns, and anomaly indicators

### ⚡ TxShield (Transaction Simulation)
- Dry-runs any raw transaction before signing
- Previews exact token in/out, approvals granted, and ETH balance changes
- Detects unlimited-approval traps and re-entrancy patterns
- Warns on unusual gas limits that suggest evasion tactics
- Supports EIP-712 signed-message pre-flight checks

### 🔍 ContractAudit
- Scans deployed bytecode for 30+ known vulnerability patterns
- Checks proxy upgrade paths and admin key centralisation
- Detects selfdestruct, delegatecall, and arbitrary-send risks
- Reports contract age, verification status, and deployer history
- Provides an overall contract safety grade (A – F)

### 🚨 TokenRadar
- Honeypot simulation: attempts both buy and sell on a fork
- Ownership and mint authority checks
- Liquidity lock verification (Team Finance, Unicrypt, etc.)
- Detects hidden fee functions, blacklist modifiers, and pause mechanisms
- Top-holder concentration analysis (whale risk)

### 🎣 PhishNet
- URL reputation check against 10+ threat-intel feeds
- DOM-level spoofing detection for popular dApps
- Signature-request analysis (permit, approve, setApprovalForAll)
- Alerts for off-chain signed messages that drain assets
- Real-time community-flagged address database

---

## Supported Commands

All commands are invoked through Bankr.bot's natural-language interface.
Examples are shown in their canonical form; you can also phrase them
conversationally.

### Wallet Checks

```
/shieldr wallet <address>
```
Returns a full WalletGuard risk report for the given address.

```
/shieldr wallet <address> --brief
```
Returns a one-line risk summary (score + top flag).

### Transaction Simulation

```
/shieldr tx <raw_hex_or_tx_hash>
```
Simulates an unsigned transaction and returns a detailed pre-flight report.

```
/shieldr approve <token_address> <spender_address> [amount]
```
Analyses a specific ERC-20 approval before you sign it.

### Contract Audit

```
/shieldr audit <contract_address>
```
Runs a full static audit of a deployed contract and returns a graded report.

```
/shieldr audit <contract_address> --fast
```
Quick scan: returns only critical and high-severity findings.

### Token Safety

```
/shieldr token <token_address>
```
Runs TokenRadar: honeypot test, liquidity check, ownership analysis.

```
/shieldr token <token_address> --chain <chain_id>
```
Same as above, targeting a specific chain (default: Ethereum mainnet).

### Phishing & URL Checks

```
/shieldr url <url>
```
Checks a URL against PhishNet threat-intel feeds.

```
/shieldr sig <hex_signature>
```
Decodes and analyses an EIP-712 or raw hex signature for risk.

### Utility

```
/shieldr status
```
Returns the current health status of all Shieldr sub-services.

```
/shieldr help
```
Lists all available commands with short descriptions.

```
/shieldr set chain <chain_id>
```
Sets the default chain for the current session (default: `1` = Ethereum).

```
/shieldr alerts on|off
```
Toggles proactive threat alerts for your connected wallets.

---

## Supported Chains

| Chain | Chain ID | Status |
|---|---|---|
| Ethereum Mainnet | 1 | ✅ Full support |
| BNB Smart Chain | 56 | ✅ Full support |
| Polygon | 137 | ✅ Full support |
| Arbitrum One | 42161 | ✅ Full support |
| Optimism | 10 | ✅ Full support |
| Base | 8453 | ✅ Full support |
| Avalanche C-Chain | 43114 | 🔶 Beta |
| Fantom | 250 | 🔶 Beta |
| zkSync Era | 324 | 🔶 Beta |

---

## Installation

### Prerequisites

- Python 3.10+
- A running Bankr.bot instance (v2.0 or later)
- An RPC endpoint (Infura, Alchemy, or self-hosted)
- Optional: TRM Labs / Chainalysis API key for enhanced sanctions screening

### 1 — Clone the skill

```bash
git clone https://github.com/shieldrai/Shieldr.git
cd Shieldr
```

### 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### 3 — Configure environment

Copy the example config and fill in your values:

```bash
cp config/settings.example.yaml config/settings.yaml
```

Key fields in `config/settings.yaml`:

```yaml
rpc:
  ethereum: "https://mainnet.infura.io/v3/YOUR_KEY"
  bsc:      "https://bsc-dataseed.binance.org/"
  polygon:  "https://polygon-rpc.com/"

threat_intel:
  trm_labs_key:      ""        # optional — enables sanctions screening
  chainalysis_key:   ""        # optional — enables enhanced risk scoring
  gopluslabs_key:    ""        # optional — free tier available

simulation:
  tenderly_key:      ""        # optional — enables advanced tx simulation
  tenderly_account:  ""
  tenderly_project:  ""

alerts:
  enabled: true
  cooldown_seconds: 300        # minimum gap between repeat alerts
```

### 4 — Register with Bankr.bot

In your Bankr.bot configuration, add Shieldr as a skill:

```yaml
skills:
  - name: shieldr
    path: ./Shieldr
    entrypoint: guard.py
    auto_load: true
```

### 5 — Verify the installation

```bash
python guard.py --self-test
```

Expected output:

```
[Shieldr] Self-test started…
  ✓ Config loaded
  ✓ RPC connections (4/4 chains reachable)
  ✓ Threat-intel feeds (2/3 active — TRM Labs key missing, using fallback)
  ✓ Simulation engine ready
  ✓ PhishNet feeds updated (15 min ago)
[Shieldr] All systems operational. Ready to guard.
```

---

## Risk Score Reference

Shieldr produces a numeric risk score (0–100) for wallets, tokens, and
contracts. The score maps to the following grades and recommended actions:

| Score | Grade | Label | Recommended Action |
|---|---|---|---|
| 0 – 15 | A | ✅ Safe | Proceed normally |
| 16 – 35 | B | 🟢 Low Risk | Proceed with awareness |
| 36 – 55 | C | 🟡 Moderate Risk | Review flagged items |
| 56 – 75 | D | 🟠 High Risk | Exercise caution |
| 76 – 90 | E | 🔴 Very High Risk | Strongly advised against |
| 91 – 100 | F | 🚨 Critical | Do NOT interact |

---

## Output Format

Every Shieldr report follows a consistent structure so it can be parsed
programmatically or read as plain text:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️  SHIELDR REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target  : 0xAbC…1234  (Wallet)
Chain   : Ethereum Mainnet
Checked : 2025-07-14 10:32 UTC

RISK SCORE   : 72 / 100  (D — High Risk)

FINDINGS
  [HIGH]   Previously interacted with known drainer (0xDead…)
  [HIGH]   Address flagged by 2 threat-intel providers
  [MEDIUM] 94% of activity in last 30 days is MEV-related
  [LOW]    Wallet age < 14 days

RECOMMENDATION
  ⚠️  Do not send assets to this address without further verification.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Architecture

```
Shieldr/
├── guard.py              # Main entrypoint — command router & Bankr.bot hook
├── SKILL.md              # This file — skill manifest & documentation
├── requirements.txt      # Python dependencies
├── .gitignore
│
├── config/
│   ├── settings.example.yaml   # Template configuration
│   ├── settings.yaml           # Your local config (git-ignored)
│   └── chains.yaml             # Chain RPC & explorer definitions
│
├── modules/
│   ├── wallet_guard.py         # WalletGuard — address risk scoring
│   ├── tx_shield.py            # TxShield — transaction simulation
│   ├── contract_audit.py       # ContractAudit — bytecode analysis
│   ├── token_radar.py          # TokenRadar — honeypot & rug-pull detection
│   ├── phish_net.py            # PhishNet — URL & signature threat-intel
│   ├── risk_engine.py          # Central scoring aggregator
│   ├── report_builder.py       # Formats findings into readable reports
│   └── chain_client.py         # RPC abstraction layer (web3.py wrapper)
│
├── tests/
│   ├── test_wallet_guard.py
│   ├── test_tx_shield.py
│   ├── test_contract_audit.py
│   ├── test_token_radar.py
│   └── test_phish_net.py
│
├── docs/
│   ├── architecture.md         # In-depth system design
│   ├── api_reference.md        # Programmatic API for developers
│   └── threat_model.md        # Threat categories & detection methodology
│
└── assets/
    └── banner.txt              # ASCII art banner shown on startup
```

---

## Environment Variables

All secrets are loaded from environment variables (never hardcoded):

| Variable | Required | Description |
|---|---|---|
| `SHIELDR_RPC_ETH` | ✅ | Ethereum RPC endpoint |
| `SHIELDR_RPC_BSC` | — | BNB Smart Chain RPC |
| `SHIELDR_RPC_POLYGON` | — | Polygon RPC |
| `SHIELDR_RPC_BASE` | — | Base RPC |
| `SHIELDR_TRM_API_KEY` | — | TRM Labs API key |
| `SHIELDR_CHAINALYSIS_KEY` | — | Chainalysis API key |
| `SHIELDR_GOPLUSLABS_KEY` | — | GoPlus Labs API key |
| `SHIELDR_TENDERLY_KEY` | — | Tenderly simulation key |
| `SHIELDR_TENDERLY_ACCOUNT` | — | Tenderly account slug |
| `SHIELDR_TENDERLY_PROJECT` | — | Tenderly project slug |
| `SHIELDR_LOG_LEVEL` | — | `DEBUG` / `INFO` / `WARNING` (default: `INFO`) |
| `SHIELDR_ALERT_WEBHOOK` | — | Webhook URL for proactive alert delivery |

---

## Contributing

Contributions are welcome. Please read `docs/architecture.md` before opening
a pull request, and ensure all tests pass:

```bash
pytest tests/ -v
```

Code style: **Black** + **isort**. Run formatters before committing:

```bash
black . && isort .
```

---

## Security Policy

If you discover a vulnerability in Shieldr itself, please report it
responsibly via GitHub's private security advisory feature rather than
opening a public issue.

---

## License

MIT © 2025 ShieldrAI
