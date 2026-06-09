# Shieldr — Threat Model

## Threat Categories

### 1. Wallet Threats
| Threat | Severity | Detection Method |
|---|---|---|
| OFAC-sanctioned address | Critical | TRM Labs / Chainalysis API |
| Known exploit deployer | Critical | Curated on-chain database |
| Drainer contract interaction | Critical | Tx history analysis |
| Mixer service usage | High | Mixer address set lookup |
| New wallet (< 7 days) | Low | First-tx timestamp |
| High counterparty risk | Medium | Recursive risk propagation |

### 2. Transaction Threats
| Threat | Severity | Detection Method |
|---|---|---|
| Asset drain (ETH/token outflow) | Critical | Simulation state diff |
| Unlimited ERC-20 approval | High | Approval event parsing |
| setApprovalForAll (NFT) | High | Approval event parsing |
| Re-entrant call pattern | High | Call trace analysis |
| Gas limit anomaly | Medium | Gas ratio check |
| Suspicious EIP-712 permit | High | Signature decode + analysis |

### 3. Smart Contract Threats
| Threat | Severity | Detection Method |
|---|---|---|
| Unprotected mint function | Critical | Selector matching |
| Rug-pull withdrawal function | Critical | Selector matching |
| Upgradeable proxy (EOA admin) | High | EIP-1967 slot detection |
| Self-destruct present | High | Opcode scan |
| Tx.origin authentication | Medium | Opcode scan |
| Blacklist / whitelist modifier | Medium | Selector matching |
| Floating pragma | Low | Source analysis |

### 4. Token Threats
| Threat | Severity | Detection Method |
|---|---|---|
| Honeypot (sell disabled) | Critical | Fork simulation |
| Sell tax > 30% | High | Fork simulation |
| No locked liquidity | High | Lock platform contracts |
| Top 10 hold > 80% supply | High | Explorer holder API |
| Active unlimited mint | High | Selector + owner check |
| Liquidity < $10,000 | Medium | DEX subgraph query |

### 5. Phishing Threats
| Threat | Severity | Detection Method |
|---|---|---|
| URL in PhishTank database | Critical | Feed lookup |
| URL in CryptoScamDB | Critical | Feed lookup |
| Typosquatting a major dApp | High | Levenshtein distance |
| Homograph domain attack | High | Unicode category analysis |
| Permit with unlimited amount | High | EIP-712 decode |
| Domain age < 30 days | Medium | WHOIS lookup |

## Out of Scope (v1.0)

- MEV / sandwich attack detection (planned v1.1)
- Cross-chain bridge risk analysis (planned v1.2)
- Social engineering / off-chain scam detection
- Hardware wallet firmware verification
- Private key exposure detection
