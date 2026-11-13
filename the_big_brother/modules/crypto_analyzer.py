"""
CRYPTO ANALYZER // VX HARDENED LEDGER LOOKUP

Upgraded with address-format auto-detection, multi-provider fallbacks
(Blockchair -> blockchain.info / Tronscan / Solana RPC), fiat valuation and
explicit provider provenance. Kept backwards-compatible with the legacy
result schema used by the dashboard.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import requests
except ImportError:
    requests = None

BLOCKCHAIR = "https://api.blockchair.com/{chain}/dashboards/address/{addr}?limit=10"
COINGECKO_IDS = {"BTC": "bitcoin", "ETH": "ethereum", "LTC": "litecoin", "TRX": "tron", "SOL": "solana", "DOGE": "dogecoin"}


def _get_json(url: str, timeout: int = 12) -> Optional[Dict[str, Any]]:
    if requests is not None:
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": "TheBigBrother-VX/1.0"})
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TheBigBrother-VX/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.getcode() == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        pass
    return None


def _post_json(url: str, payload: Dict[str, Any], timeout: int = 12) -> Optional[Dict[str, Any]]:
    body = json.dumps(payload).encode()
    if requests is not None:
        try:
            r = requests.post(url, data=body, timeout=timeout, headers={"Content-Type": "application/json", "User-Agent": "TheBigBrother-VX/1.0"})
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    try:
        req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": "TheBigBrother-VX/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.getcode() == 200:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        pass
    return None


def _detect_coin(address: str) -> str:
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
        return "ETH"
    if re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", address):
        return "TRX"
    if re.fullmatch(r"(bc1[02-9ac-hj-np-z]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})", address):
        return "BTC"
    if re.fullmatch(r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}", address):
        return "LTC"
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
        return "SOL"
    return "UNKNOWN"


def _price_usd(coin: str) -> Optional[float]:
    cid = COINGECKO_IDS.get(coin.upper())
    if not cid:
        return None
    data = _get_json(f"https://api.coingecko.com/api/v3/simple/price?ids={cid}&vs_currencies=usd", timeout=6)
    try:
        return float((data or {})[cid]["usd"])
    except Exception:
        return None


def _utc(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Unknown"


def _blank(address: str, coin: str) -> Dict[str, Any]:
    return {
        "coin": coin.upper(),
        "address": address,
        "balance": 0.0,
        "balance_usd": None,
        "total_received": 0.0,
        "total_sent": 0.0,
        "tx_count": 0,
        "last_seen": "Never",
        "recent_txs": [],
        "provider": "",
        "error": None,
        "address_valid": True,
    }


def _blockchair(address: str, coin: str) -> Optional[Dict[str, Any]]:
    chain = {"BTC": "bitcoin", "ETH": "ethereum", "LTC": "litecoin"}.get(coin)
    if not chain:
        return None
    data = _get_json(BLOCKCHAIR.format(chain=chain, addr=urllib.parse.quote(address)), timeout=14)
    if not isinstance(data, dict) or "data" not in data:
        return None
    row = (data.get("data") or {}).get(address) or {}
    addr = row.get("address") or {}
    txs = row.get("transactions") or []
    decimals = 18 if coin == "ETH" else 8
    unit = 10 ** decimals
    out = _blank(address, coin)
    out.update({
        "balance": float(addr.get("balance", 0) or 0) / unit,
        "total_received": float(addr.get("received", 0) or 0) / unit,
        "total_sent": float(addr.get("spent", 0) or 0) / unit,
        "tx_count": int(addr.get("transaction_count", 0) or 0),
        "provider": f"Blockchair {chain}",
    })
    if txs:
        times = [t.get("time") for t in txs if t.get("time")]
        if times:
            out["last_seen"] = _utc(max(times))
        for t in txs[:8]:
            out["recent_txs"].append({
                "hash": t.get("hash", ""),
                "time": t.get("time", ""),
                "result": float(t.get("balance_change", 0) or 0) / unit,
                "block": t.get("block_id"),
            })
    return out


def _btc_blockchain_info(address: str) -> Optional[Dict[str, Any]]:
    data = _get_json(f"https://blockchain.info/rawaddr/{urllib.parse.quote(address)}?limit=10", timeout=12)
    if not isinstance(data, dict):
        return None
    out = _blank(address, "BTC")
    out.update({
        "balance": float(data.get("final_balance", 0) or 0) / 1e8,
        "total_received": float(data.get("total_received", 0) or 0) / 1e8,
        "total_sent": float(data.get("total_sent", 0) or 0) / 1e8,
        "tx_count": int(data.get("n_tx", 0) or 0),
        "provider": "blockchain.info",
    })
    txs = data.get("txs") or []
    if txs:
        out["last_seen"] = _utc(txs[0].get("time"))
    for t in txs[:8]:
        out["recent_txs"].append({
            "hash": t.get("hash", ""),
            "time": _utc(t.get("time")),
            "result": float(t.get("result", 0) or 0) / 1e8,
        })
    return out


def _trx_tronscan(address: str) -> Optional[Dict[str, Any]]:
    data = _get_json(f"https://apilist.tronscanapi.com/api/accountv2?address={urllib.parse.quote(address)}", timeout=12)
    if not isinstance(data, dict):
        return None
    out = _blank(address, "TRX")
    out.update({
        "balance": float(data.get("balance", 0) or 0) / 1e6,
        "total_received": float(data.get("totalReceived", 0) or 0) / 1e6,
        "total_sent": float(data.get("totalSent", 0) or 0) / 1e6,
        "tx_count": int(data.get("transactions", 0) or 0),
        "provider": "Tronscan",
    })
    last = data.get("latest_operation_time")
    if last:
        out["last_seen"] = _utc(float(last) / 1000)
    return out


def _sol_rpc(address: str) -> Optional[Dict[str, Any]]:
    rpc = "https://api.mainnet-beta.solana.com"
    bal = _post_json(rpc, {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address]})
    if not isinstance(bal, dict) or "result" not in bal:
        return None
    sigs = _post_json(rpc, {"jsonrpc": "2.0", "id": 2, "method": "getSignaturesForAddress", "params": [address, {"limit": 10}]})
    out = _blank(address, "SOL")
    lamports = float((bal.get("result") or {}).get("value", 0) or 0)
    out.update({"balance": lamports / 1e9, "provider": "Solana JSON-RPC"})
    rows = (sigs or {}).get("result") or []
    out["tx_count"] = len(rows)
    if rows:
        out["last_seen"] = _utc(rows[0].get("blockTime"))
        for r in rows[:8]:
            out["recent_txs"].append({"hash": r.get("signature", ""), "time": _utc(r.get("blockTime")), "result": None})
    return out


def analyze_crypto(address: str, coin: str = "auto") -> Dict[str, Any]:
    address = (address or "").strip()
    coin = (coin or "auto").upper()
    if coin == "AUTO":
        coin = _detect_coin(address)
    if not address:
        return {"error": "Address is required", "coin": coin, "address": address}
    if coin == "UNKNOWN":
        return {"error": "Unrecognized address format. Specify BTC, ETH, LTC, TRX or SOL.", "coin": coin, "address": address}

    result: Optional[Dict[str, Any]] = None
    errors = []
    try:
        if coin in ("BTC", "ETH", "LTC"):
            result = _blockchair(address, coin)
            if result is None and coin == "BTC":
                result = _btc_blockchain_info(address)
        elif coin == "TRX":
            result = _trx_tronscan(address)
        elif coin == "SOL":
            result = _sol_rpc(address)
        else:
            errors.append(f"Unsupported coin {coin}")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    if result is None:
        return {
            "coin": coin,
            "address": address,
            "balance": 0.0,
            "total_received": 0.0,
            "tx_count": 0,
            "last_seen": "Unknown",
            "recent_txs": [],
            "error": "; ".join(errors) or "All upstream ledger providers failed or rate-limited.",
            "address_valid": True,
        }

    price = _price_usd(coin)
    if price is not None:
        result["balance_usd"] = round(result["balance"] * price, 2)
        result["price_usd"] = price
    result["tx_count"] = result.get("tx_count") or 0
    result["activity_level"] = (
        "DORMANT" if result["tx_count"] == 0 else
        "LOW" if result["tx_count"] < 10 else
        "MODERATE" if result["tx_count"] < 100 else "HIGH"
    )
    return result
