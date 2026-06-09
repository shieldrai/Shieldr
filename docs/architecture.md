# Shieldr — Architecture Overview

## System Design

Shieldr is designed as a modular, async-first Python skill for Bankr.bot.
The system is decomposed into five independent security modules, each
responsible for a single security domain, plus three shared infrastructure
modules.

```
Bankr.bot Runtime
       │
       ▼  handle_command(command, context)
   guard.py  ──────────────────────────────────────
       │                                           │
       │  (command router)                         │
       │                                           │
   ┌───▼──────────────────────────────────────┐   │
   │            Security Modules              │   │
   │                                          │   │
   │  WalletGuard   ─► risk findings          │   │
   │  TxShield      ─► tx risk findings       │   │
   │  ContractAudit ─► audit findings         │   │
   │  TokenRadar    ─► token risk findings    │   │
   │  PhishNet      ─► url / sig findings     │   │
   └───────────────┬──────────────────────────┘   │
                   │                               │
                   ▼                               │
              RiskEngine  (score aggregator)       │
                   │                               │
                   ▼                               │
            ReportBuilder  (output formatter)      │
                   │                               │
                   ▼                               │
            ChainClient  (RPC abstraction)  ───────┘
                   │
                   ▼
         Ethereum / BSC / Polygon / …
```

## Module Responsibilities

### guard.py (Entrypoint)
- Parses raw command strings from Bankr.bot
- Routes commands to the appropriate module via a dispatch table
- Catches all exceptions and returns user-friendly error messages
- Exposes a module-level `handle_command()` for Bankr.bot integration
- Maintains a lazy singleton of the `Shieldr` class

### WalletGuard
- Queries TRM Labs, Chainalysis, and GoPlus for wallet risk data
- Checks on-chain transaction history for exploit/drainer interactions
- Calculates a weighted aggregate risk score (0–100)
- Runs all sub-checks concurrently using `asyncio.gather()`

### TxShield
- Routes simulation to Tenderly API if configured, else local Anvil fork
- Parses the EVM call trace for:
  - Token transfer events (ERC-20 Transfer logs)
  - Approval events (ERC-20 Approval, ERC-721 ApprovalForAll)
  - Re-entrant call patterns
- Handles both raw hex transactions and pending tx hashes

### ContractAudit
- Fetches deployed bytecode via `eth_getCode`
- Extracts 4-byte function selectors and matches against known dangerous selectors
- Detects EIP-1967 and EIP-897 proxy patterns
- Enriches findings with verified source data when available

### TokenRadar
- Primary honeypot detection via GoPlus Labs `/token/security` endpoint
- Secondary confirmation via Tenderly fork simulation (buy + sell)
- Liquidity lock status from Unicrypt, Team Finance, and PinkLock contracts
- Top-holder data from block explorer API

### PhishNet
- Concurrent queries to PhishTank, URLhaus, and CryptoScamDB
- Local typosquatting detection using Levenshtein distance
- Homograph attack detection via Unicode category analysis
- EIP-712 signature decoder for permit and setApprovalForAll risk checks

### RiskEngine
- Provides a single `compute(findings)` method used by all modules
- Applies configurable severity weights to produce a 0–100 score
- Maps scores to grades (A–F) using threshold table

### ReportBuilder
- Single class responsible for all user-facing output
- Enforces consistent report format across all command types
- Supports `brief` mode for compact one-line summaries

### ChainClient
- Wraps web3.py with per-chain connection pooling
- Automatic retry with exponential back-off via `tenacity`
- Lazy connection initialisation (connects on first use per chain)
- Utility methods for address validation and checksumming

## Data Flow — Wallet Check Example

```
User: "/shieldr wallet 0xAbC…"
          │
          ▼
    guard.py._parse_command()
          │
          ▼
    guard.py._handle_wallet(["0xAbC…"], context)
          │
          ▼
    WalletGuard.score("0xAbC…", chain_id=1)
          │
          ├─► _check_sanctions()          ─┐
          ├─► _check_exploit_interactions() ├─ asyncio.gather()
          ├─► _check_mixer_usage()         ─┤
          ├─► _check_wallet_age()          ─┤
          └─► _check_counterparty_risk()   ─┘
                    │
                    ▼
          WalletGuard._aggregate_score(findings)
                    │
                    ▼
          WalletRiskResult(score=72, grade="D", …)
                    │
                    ▼
          ReportBuilder.build_wallet_report(result)
                    │
                    ▼
          "━━━━━━━━━━━━━━━━━
           🛡️  SHIELDR REPORT
           …"
                    │
                    ▼
          Bankr.bot delivers to user
```

## Concurrency Model

All I/O-bound operations (RPC calls, API requests) are implemented as
`async def` coroutines. Within each module, independent checks run
concurrently via `asyncio.gather()` to minimise latency.

Bankr.bot must call Shieldr from an async context or use
`asyncio.run(handle_command(...))` if calling synchronously.

## Configuration Hierarchy

```
Environment Variables  (highest priority)
         │
         ▼
config/settings.yaml   (local overrides)
         │
         ▼
Built-in defaults      (lowest priority)
```

## Error Handling

- All exceptions within command handlers are caught in `guard.py`
- Sub-module errors are logged and surfaced as user-friendly messages
- RPC failures fall back to alternative endpoints when configured
- Missing API keys gracefully degrade to available fallback data sources

## Caching

Risk results are cached in-memory using `cachetools.TTLCache`:
- Wallet scores: 5 minutes
- Token analysis: 10 minutes
- Contract audits: 1 hour
- URL checks: 3 minutes

Cache TTLs are configurable in `config/settings.yaml`.
