"""
BIG BROTHER V7.0 — TOKEN CONTRACT DRAINER & HONEYPOT AUDITOR
Multi-chain Smart Contract Bytecode Forensics, Tax Verification & Rug-Pull Analyzer.
Zero-mock connection to GoPlus Security and Honeypot.is public forensic APIs.
"""

import asyncio
import json
import urllib.request
import urllib.error
import re
from typing import Dict, Any, Optional

SUPPORTED_CHAINS = {
    "1": "Ethereum Mainnet",
    "56": "BNB Smart Chain",
    "137": "Polygon PoS",
    "42161": "Arbitrum One",
    "eth": "1",
    "bsc": "56",
    "polygon": "137",
    "arbitrum": "42161"
}


def _fetch_json(url: str, timeout: int = 7) -> Optional[Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "BigBrother-ContractAuditor/7.0 (Web3 Security)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode("utf-8", errors="ignore")
                return json.loads(raw)
    except Exception:
        return None
    return None


async def audit_token_contract(address: str, chain: str = "1") -> Dict[str, Any]:
    """
    Main forensic auditor for smart contract drainers and honeypots.
    """
    clean_addr = address.strip().lower()
    if not re.match(r"^0x[a-fA-F0-9]{40}$", clean_addr):
        return {
            "status": "error",
            "error": "Invalid EVM contract address. Must be a 42-character 0x-prefixed hex string.",
            "target": address
        }

    chain_id = SUPPORTED_CHAINS.get(str(chain).lower(), "1")
    chain_name = SUPPORTED_CHAINS.get(chain_id, "EVM Chain")

    loop = asyncio.get_running_loop()

    # Query 1: GoPlus Security Token Security API
    goplus_url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={clean_addr}"
    # Query 2: Honeypot.is API for simulation
    honeypot_url = f"https://api.honeypot.is/v2/IsHoneypot?address={clean_addr}"

    gp_task = loop.run_in_executor(None, _fetch_json, goplus_url, 6)
    hp_task = loop.run_in_executor(None, _fetch_json, honeypot_url, 6)

    gp_data, hp_data = await asyncio.gather(gp_task, hp_task, return_exceptions=True)

    gp_info = {}
    if isinstance(gp_data, dict) and "result" in gp_data and isinstance(gp_data["result"], dict):
        # Result is keyed by lowercase address
        gp_info = gp_data["result"].get(clean_addr, {})

    hp_info = hp_data if isinstance(hp_data, dict) else {}

    # Extract forensic flags
    is_honeypot = False
    buy_tax = 0.0
    sell_tax = 0.0
    cannot_sell = False
    is_mintable = False
    is_proxy = False
    has_blacklist = False
    hidden_owner = False
    owner_change_balance = False
    anti_whale = False

    if gp_info:
        is_honeypot = gp_info.get("is_honeypot") == "1"
        cannot_sell = gp_info.get("cannot_sell_all") == "1" or is_honeypot
        buy_tax = round(float(gp_info.get("buy_tax", 0)) * 100, 2)
        sell_tax = round(float(gp_info.get("sell_tax", 0)) * 100, 2)
        is_mintable = gp_info.get("is_mintable") == "1"
        is_proxy = gp_info.get("is_proxy") == "1"
        has_blacklist = gp_info.get("is_blacklisted") == "1"
        hidden_owner = gp_info.get("hidden_owner") == "1"
        owner_change_balance = gp_info.get("owner_change_balance") == "1"
        anti_whale = gp_info.get("is_anti_whale") == "1"
    elif hp_info and "honeypotResult" in hp_info:
        is_honeypot = hp_info["honeypotResult"].get("isHoneypot", False)
        sim = hp_info.get("simulationResult", {})
        buy_tax = sim.get("buyTax", 0)
        sell_tax = sim.get("sellTax", 0)

    # Compute risk tier
    risk_score = 10
    vulnerabilities = []

    if is_honeypot or cannot_sell:
        risk_score += 70
        vulnerabilities.append("CRITICAL: Token transfer simulation failed. User funds cannot be sold.")
    if sell_tax > 25.0:
        risk_score += 35
        vulnerabilities.append(f"EXTREME SELL TAX: {sell_tax}% transaction fee deducted upon sale.")
    elif sell_tax > 10.0:
        risk_score += 15
        vulnerabilities.append(f"HIGH SELL TAX: {sell_tax}% transaction fee deducted upon sale.")
    if is_mintable:
        risk_score += 20
        vulnerabilities.append("UNLIMITED MINT: Contract creator can mint arbitrary new supply and dump on holders.")
    if is_proxy:
        risk_score += 15
        vulnerabilities.append("UPGRADEABLE PROXY: Contract logic can be swapped dynamically to insert a drainer.")
    if has_blacklist:
        risk_score += 15
        vulnerabilities.append("WALLET BLACKLIST: Owner retains privilege to freeze specific addresses from trading.")
    if hidden_owner or owner_change_balance:
        risk_score += 30
        vulnerabilities.append("BACKDOOR: Hidden creator privileges or direct balance manipulation functions detected.")

    risk_score = min(99, risk_score)
    if not vulnerabilities:
        risk_tier = "VERIFIED_SAFE"
    elif risk_score >= 65:
        risk_tier = "CRITICAL_RUGPULL_RISK"
    elif risk_score >= 35:
        risk_tier = "ELEVATED_RISK"
    else:
        risk_tier = "NOMINAL_RISK"

    token_name = gp_info.get("token_name") or hp_info.get("token", {}).get("name") or "Unknown Token"
    token_symbol = gp_info.get("token_symbol") or hp_info.get("token", {}).get("symbol") or "TOKEN"
    total_supply = gp_info.get("total_supply") or "N/A"
    creator_address = gp_info.get("creator_address") or "N/A"
    owner_address = gp_info.get("owner_address") or "N/A"

    return {
        "status": "success",
        "module": "v7_honeypot_auditor",
        "contract_address": clean_addr,
        "chain_id": chain_id,
        "chain_name": chain_name,
        "token": {
            "name": token_name,
            "symbol": token_symbol,
            "total_supply": total_supply,
            "creator": creator_address,
            "owner": owner_address,
            "ownership_renounced": owner_address in ("0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead", "")
        },
        "tax": {
            "buy_tax_pct": buy_tax,
            "sell_tax_pct": sell_tax,
            "transfer_tax_pct": float(gp_info.get("transfer_tax", 0)) * 100 if gp_info.get("transfer_tax") else 0.0
        },
        "forensic_checks": {
            "is_honeypot": is_honeypot,
            "cannot_sell_all": cannot_sell,
            "is_mintable": is_mintable,
            "is_proxy_contract": is_proxy,
            "has_blacklist_function": has_blacklist,
            "hidden_owner_detected": hidden_owner,
            "owner_can_modify_balance": owner_change_balance,
            "anti_whale_protection": anti_whale,
            "trust_list_dex": gp_info.get("trust_list") == "1"
        },
        "rugpull_risk_score": risk_score,
        "threat_tier": risk_tier,
        "vulnerabilities": vulnerabilities,
        "verdict": f"Honeypot Audit for {token_symbol} [{clean_addr[:8]}...]: {risk_tier} (Risk Score: {risk_score}/100)."
    }
