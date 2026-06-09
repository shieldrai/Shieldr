"""
modules/ — Shieldr Security Module Package
===========================================
This package contains the five core security modules:

  - wallet_guard    WalletGuard  — address risk scoring
  - tx_shield       TxShield     — transaction simulation
  - contract_audit  ContractAudit — bytecode analysis
  - token_radar     TokenRadar   — honeypot & rug-pull detection
  - phish_net       PhishNet     — URL & signature threat intel

Supporting modules:
  - risk_engine     RiskEngine   — central scoring aggregator
  - report_builder  ReportBuilder — report formatting
  - chain_client    ChainClient  — RPC abstraction layer
"""
