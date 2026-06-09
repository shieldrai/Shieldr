# Shieldr — Programmatic API Reference

Developers can integrate Shieldr directly into Python code by importing the
modules rather than going through the command interface.

## guard.py — Top-Level API

```python
from guard import handle_command

# Call from anywhere
response: str = handle_command("/shieldr wallet 0xAbC…", context={})
```

### `handle_command(command, context=None) -> str`
Module-level entry point. Creates a `Shieldr` singleton on first call.

| Parameter | Type | Description |
|---|---|---|
| `command` | `str` | Full command string |
| `context` | `dict \| None` | Optional Bankr.bot session context |

---

## WalletGuard

```python
from modules.wallet_guard import WalletGuard
guard  = WalletGuard(chain_client, settings)
result = await guard.score("0xAbC…", chain_id=1)
```

### `await score(address, chain_id=1) -> WalletRiskResult`

| Field | Type | Description |
|---|---|---|
| `result.address` | `str` | Input address |
| `result.score` | `int` | 0–100 risk score |
| `result.grade` | `str` | A–F grade |
| `result.label` | `str` | Human-readable label |
| `result.findings` | `list[WalletFinding]` | Individual findings |
| `result.is_safe` | `bool` | True if score ≤ 15 |

---

## TxShield

```python
from modules.tx_shield import TxShield
shield = TxShield(chain_client, settings)
result = await shield.simulate(raw_tx_hex, chain_id=1)
```

### `await simulate(tx, chain_id=1) -> TxSimResult`
### `await analyse_approval(token, spender, amount=None, chain_id=1) -> TxSimResult`

---

## ContractAudit

```python
from modules.contract_audit import ContractAudit
auditor = ContractAudit(chain_client, settings)
result  = await auditor.scan("0xContract…", chain_id=1, fast=False)
```

### `await scan(address, chain_id=1, fast=False) -> AuditResult`

| Field | Type | Description |
|---|---|---|
| `result.grade` | `str` | A–F safety grade |
| `result.score` | `int` | 0–100 risk score |
| `result.findings` | `list[AuditFinding]` | Sorted findings |
| `result.critical_count` | `int` | Count of CRITICAL findings |

---

## TokenRadar

```python
from modules.token_radar import TokenRadar
radar  = TokenRadar(chain_client, settings)
result = await radar.analyse("0xToken…", chain_id=1)
```

### `await analyse(token_address, chain_id=1) -> TokenRadarResult`

| Field | Type | Description |
|---|---|---|
| `result.honeypot` | `HoneypotResult \| None` | Honeypot test result |
| `result.liquidity` | `list[LiquidityInfo]` | Pool & lock details |
| `result.concentration` | `HolderConcentration \| None` | Top holder data |

---

## PhishNet

```python
from modules.phish_net import PhishNet
net    = PhishNet(settings)
url_r  = await net.check_url("https://uniswap-airdrop.xyz")
sig_r  = await net.check_signature("0x1901…")
```

### `await check_url(url) -> UrlThreatResult`
### `await check_signature(hex_sig) -> SignatureRiskResult`

---

## RiskEngine

```python
from modules.risk_engine import RiskEngine
engine        = RiskEngine(settings)
score, grade, label = engine.compute(findings)
```

### `compute(findings) -> tuple[int, str, str]`
Returns `(score, grade, label)`.

---

## ReportBuilder

```python
from modules.report_builder import ReportBuilder
builder = ReportBuilder()
text    = builder.build_wallet_report(wallet_result, brief=False)
```

### Methods
- `build_wallet_report(result, brief=False) -> str`
- `build_tx_report(result) -> str`
- `build_approve_report(result) -> str`
- `build_audit_report(result) -> str`
- `build_token_report(result) -> str`
- `build_url_report(result) -> str`
- `build_sig_report(result) -> str`

---

## ChainClient

```python
from modules.chain_client import ChainClient
client   = ChainClient(settings)
bytecode = await client.get_bytecode("0xContract…", chain_id=1)
txs      = await client.get_transactions("0xWallet…", chain_id=1, limit=50)
```

### Key Methods
- `get_bytecode(address, chain_id) -> str`
- `get_balance(address, chain_id) -> int`
- `get_transactions(address, chain_id, limit) -> list[dict]`
- `get_first_tx_timestamp(address, chain_id) -> int | None`
- `get_approvals(address, chain_id) -> list[dict]`
- `call_contract(address, abi, fn, args, chain_id) -> Any`
- `health_check() -> dict[int, bool]`
- `is_valid_address(address) -> bool` (static)
- `checksum_address(address) -> str` (static)
