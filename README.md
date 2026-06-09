# 🛡️ Shieldr

**Advanced AI Security Skill for [Bankr.bot](https://bankr.bot)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Bankr Skill](https://img.shields.io/badge/Bankr-Skill-green.svg)](https://bankr.bot/skills)
[![Status: Beta](https://img.shields.io/badge/Status-Beta-orange.svg)]()

Shieldr is a production-grade security skill for Bankr.bot that gives every
user an AI-powered security co-pilot. It monitors, analyses, and defends
against on-chain threats in real time — all accessible through simple
natural-language commands inside your Bankr bot.

---

## ✨ Highlights

- 🛡️ **WalletGuard** — Risk-score any EVM wallet (0–100) with sanction-list checks
- ⚡ **TxShield** — Simulate transactions before signing; catch drains and traps
- 🔍 **ContractAudit** — Static-scan deployed contracts for 30+ vulnerability patterns
- 🚨 **TokenRadar** — Honeypot simulation, liquidity lock checks, rug-pull detection
- 🎣 **PhishNet** — URL & signature threat-intel against 10+ live feeds

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/shieldrai/Shieldr.git
cd Shieldr

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp config/settings.example.yaml config/settings.yaml
# → edit config/settings.yaml and add your RPC endpoints

# 4. Self-test
python guard.py --self-test
```

Then register Shieldr in your Bankr.bot config:

```yaml
skills:
  - name: shieldr
    path: ./Shieldr
    entrypoint: guard.py
    auto_load: true
```

---

## 💬 Example Commands

```
/shieldr wallet 0xAbC…1234
/shieldr token  0xdAC17F958D2ee523a2206206994597C13D831ec7
/shieldr audit  0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
/shieldr tx     0xraw_hex_or_pending_tx_hash
/shieldr url    https://uniswap-airdrop.xyz
/shieldr sig    0x1901…
/shieldr help
```

---

## 📋 Supported Chains

| Chain | Status |
|---|---|
| Ethereum Mainnet | ✅ Full |
| BNB Smart Chain | ✅ Full |
| Polygon | ✅ Full |
| Arbitrum One | ✅ Full |
| Optimism | ✅ Full |
| Base | ✅ Full |
| Avalanche, Fantom, zkSync | 🔶 Beta |

---

## 🏗️ Project Structure

```
Shieldr/
├── guard.py                    # Entrypoint — command router & Bankr.bot hook
├── SKILL.md                    # Skill manifest & full documentation
├── requirements.txt
├── .gitignore
├── config/
│   ├── settings.example.yaml   # Config template
│   └── chains.yaml             # Chain definitions
├── modules/
│   ├── wallet_guard.py         # Address risk scoring
│   ├── tx_shield.py            # Transaction simulation
│   ├── contract_audit.py       # Bytecode analysis
│   ├── token_radar.py          # Honeypot & rug-pull detection
│   ├── phish_net.py            # URL & signature threat intel
│   ├── risk_engine.py          # Central scoring aggregator
│   ├── report_builder.py       # Report formatter
│   └── chain_client.py         # RPC abstraction layer
├── tests/                      # Pytest test suite
└── docs/                       # Architecture & API reference
```

---

## ⚙️ Configuration

All secrets are loaded from **environment variables** — never hardcoded.

| Variable | Description |
|---|---|
| `SHIELDR_RPC_ETH` | Ethereum RPC (required) |
| `SHIELDR_RPC_BSC` | BNB Smart Chain RPC |
| `SHIELDR_RPC_POLYGON` | Polygon RPC |
| `SHIELDR_TRM_API_KEY` | TRM Labs (sanctions screening) |
| `SHIELDR_CHAINALYSIS_KEY` | Chainalysis (risk scoring) |
| `SHIELDR_GOPLUSLABS_KEY` | GoPlus Labs (token safety) |
| `SHIELDR_TENDERLY_KEY` | Tenderly (tx simulation) |
| `SHIELDR_ALERT_WEBHOOK` | Webhook for proactive alerts |

See `config/settings.example.yaml` for the full list.

---

## 🔒 Risk Score Reference

| Score | Grade | Label |
|---|---|---|
| 0–15 | A | ✅ Safe |
| 16–35 | B | 🟢 Low Risk |
| 36–55 | C | 🟡 Moderate Risk |
| 56–75 | D | 🟠 High Risk |
| 76–90 | E | 🔴 Very High Risk |
| 91–100 | F | 🚨 Critical — Do NOT interact |

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Code style (Black + isort):

```bash
black . && isort .
```

---

## 📖 Documentation

- [Architecture Overview](docs/architecture.md)
- [API Reference](docs/api_reference.md)
- [Threat Model](docs/threat_model.md)
- [Full Skill Manifest](SKILL.md)

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Commit your changes (`git commit -m 'feat: add your feature'`)
4. Push and open a Pull Request

Please read [docs/architecture.md](docs/architecture.md) before submitting.
All PRs must pass `pytest` and style checks.

---

## 🔐 Security Policy

Please report vulnerabilities via **GitHub's private security advisory**
feature — not public issues. We aim to respond within 48 hours.

---

## 📄 License

MIT © 2026 ShieldrAI
