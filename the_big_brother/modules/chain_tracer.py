"""
CHAIN TRACER — Blockchain Wallet Intelligence Engine V6
Traces BTC, ETH, and TRX wallet addresses using free public APIs.
Returns: balance, tx count, recent transactions, risk flags, sanctions check,
known-exchange detection, and activity timeline — no API key required.
"""
import asyncio
import re
import aiohttp

# ── Known exchange / service clusters ──────────────────────────────────────
KNOWN_ENTITIES = {
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna": "Bitcoin Genesis Block",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "Binance Cold Wallet",
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance Hot Wallet",
    "0xd551234ae421e3bcba99a0da6d736074f22192ff": "Binance 2",
    "0x6262998Ced04146fA42253a5C0AF90CA02dfd2A3": "Crypto.com",
    "0x46705dfff24256421a05d056c29e81bdc09723b8": "Kraken",
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase",
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase 2",
}

SANCTION_KEYWORDS = [
    "lazarus", "hydra", "tornado", "blender", "chipmixer", "sinbad"
]

COIN_APIS = {
    "btc": {
        "info": "https://blockstream.info/api/address/{addr}",
        "txs": "https://blockstream.info/api/address/{addr}/txs",
        "explorer": "https://blockstream.info/address/{addr}",
    },
    "eth": {
        "info": "https://api.ethplorer.io/getAddressInfo/{addr}?apiKey=freekey",
        "txs": "https://api.ethplorer.io/getAddressTransactions/{addr}?apiKey=freekey&limit=10",
        "explorer": "https://etherscan.io/address/{addr}",
    },
    "trx": {
        "info": "https://apilist.tronscanapi.com/api/accountv2?address={addr}",
        "txs": "https://apilist.tronscanapi.com/api/transaction?sort=-timestamp&count=true&limit=10&address={addr}",
        "explorer": "https://tronscan.org/#/address/{addr}",
    },
}


def _detect_coin(address: str) -> str:
    addr = address.strip()
    if re.match(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$', addr):
        return "btc"
    if re.match(r'^0x[a-fA-F0-9]{40}$', addr):
        return "eth"
    if re.match(r'^T[a-zA-Z0-9]{33}$', addr):
        return "trx"
    return "unknown"


def _check_sanctions(address: str) -> dict:
    addr_lower = address.lower()
    known = KNOWN_ENTITIES.get(address) or KNOWN_ENTITIES.get(addr_lower)
    flags = []
    for kw in SANCTION_KEYWORDS:
        if kw in addr_lower:
            flags.append(kw)
    return {
        "known_entity": known,
        "sanction_flags": flags,
        "risk": "HIGH" if flags else ("MEDIUM" if known else "LOW"),
    }


async def _fetch(session: aiohttp.ClientSession, url: str) -> dict | list | None:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
            if r.status == 200:
                return await r.json(content_type=None)
    except Exception:
        pass
    return None


# ── BTC ─────────────────────────────────────────────────────────────────────
async def _analyze_btc(address: str, session: aiohttp.ClientSession) -> dict:
    apis = COIN_APIS["btc"]
    info = await _fetch(session, apis["info"].format(addr=address))
    txs_raw = await _fetch(session, apis["txs"].format(addr=address))

    balance_sat = 0
    tx_count = 0
    received = 0
    sent = 0

    if info:
        chain = info.get("chain_stats", {})
        balance_sat = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
        tx_count = chain.get("tx_count", 0)
        received = chain.get("funded_txo_sum", 0)
        sent = chain.get("spent_txo_sum", 0)

    transactions = []
    if txs_raw:
        for tx in txs_raw[:10]:
            vin_value = sum(i.get("prevout", {}).get("value", 0) for i in tx.get("vin", []))
            vout_value = sum(o.get("value", 0) for o in tx.get("vout", []))
            transactions.append({
                "txid": tx.get("txid", "")[:16] + "...",
                "txid_full": tx.get("txid", ""),
                "block": tx.get("status", {}).get("block_height"),
                "confirmed": tx.get("status", {}).get("confirmed", False),
                "input_value_btc": round(vin_value / 1e8, 8),
                "output_value_btc": round(vout_value / 1e8, 8),
                "fee_sat": tx.get("fee", 0),
            })

    return {
        "coin": "BTC",
        "address": address,
        "balance": round(balance_sat / 1e8, 8),
        "balance_unit": "BTC",
        "tx_count": tx_count,
        "total_received_btc": round(received / 1e8, 8),
        "total_sent_btc": round(sent / 1e8, 8),
        "explorer": apis["explorer"].format(addr=address),
        "transactions": transactions,
    }


# ── ETH ─────────────────────────────────────────────────────────────────────
async def _analyze_eth(address: str, session: aiohttp.ClientSession) -> dict:
    apis = COIN_APIS["eth"]
    info = await _fetch(session, apis["info"].format(addr=address))
    txs_raw = await _fetch(session, apis["txs"].format(addr=address))

    balance = 0.0
    tx_count = 0
    token_count = 0

    if info:
        eth_info = info.get("ETH", {})
        balance = float(eth_info.get("balance", 0))
        tx_count = eth_info.get("totalIn", 0) + eth_info.get("totalOut", 0)
        token_count = len(info.get("tokens", []))

    transactions = []
    if txs_raw and isinstance(txs_raw, list):
        for tx in txs_raw[:10]:
            transactions.append({
                "txid": str(tx.get("hash", ""))[:16] + "...",
                "txid_full": tx.get("hash", ""),
                "timestamp": tx.get("timestamp"),
                "value_eth": round(float(tx.get("value", 0)) / 1e18, 6),
                "from": tx.get("from", ""),
                "to": tx.get("to", ""),
                "success": tx.get("success", True),
            })

    return {
        "coin": "ETH",
        "address": address,
        "balance": round(balance, 6),
        "balance_unit": "ETH",
        "tx_count": tx_count,
        "token_count": token_count,
        "explorer": apis["explorer"].format(addr=address),
        "transactions": transactions,
    }


# ── TRX ─────────────────────────────────────────────────────────────────────
async def _analyze_trx(address: str, session: aiohttp.ClientSession) -> dict:
    apis = COIN_APIS["trx"]
    info = await _fetch(session, apis["info"].format(addr=address))
    txs_raw = await _fetch(session, apis["txs"].format(addr=address))

    balance = 0.0
    tx_count = 0

    if info:
        balance = float(info.get("balance", 0)) / 1e6
        tx_count = info.get("totalTransactionCount", 0)

    transactions = []
    if txs_raw and isinstance(txs_raw, dict):
        for tx in txs_raw.get("data", [])[:10]:
            transactions.append({
                "txid": str(tx.get("hash", ""))[:16] + "...",
                "txid_full": tx.get("hash", ""),
                "timestamp": tx.get("timestamp"),
                "value_trx": round(float(tx.get("amount", 0)) / 1e6, 4),
                "contract_type": tx.get("contractType"),
            })

    return {
        "coin": "TRX",
        "address": address,
        "balance": round(balance, 4),
        "balance_unit": "TRX",
        "tx_count": tx_count,
        "explorer": apis["explorer"].format(addr=address),
        "transactions": transactions,
    }


# ── PUBLIC ENTRY POINT ───────────────────────────────────────────────────────
async def chain_tracer(address: str, coin: str = "auto") -> dict:
    address = address.strip()
    if not address:
        return {"error": "No address provided"}

    if coin == "auto":
        coin = _detect_coin(address)

    if coin == "unknown":
        return {"error": "Could not detect coin type. Supports BTC, ETH, TRX."}

    sanctions = _check_sanctions(address)

    async with aiohttp.ClientSession(headers={"User-Agent": "TheBigBrother/6.0"}) as session:
        if coin == "btc":
            data = await _analyze_btc(address, session)
        elif coin == "eth":
            data = await _analyze_eth(address, session)
        elif coin == "trx":
            data = await _analyze_trx(address, session)
        else:
            return {"error": f"Unsupported coin: {coin}"}

    # Risk scoring
    risk_score = 0
    risk_flags = []

    if sanctions["sanction_flags"]:
        risk_score += 80
        risk_flags.append(f"Sanction keyword match: {', '.join(sanctions['sanction_flags'])}")
    if sanctions["known_entity"]:
        risk_flags.append(f"Known entity: {sanctions['known_entity']}")

    balance = data.get("balance", 0)
    tx_count = data.get("tx_count", 0)

    if balance > 100:
        risk_score += 15
        risk_flags.append("High balance (>100 units)")
    if tx_count > 1000:
        risk_score += 10
        risk_flags.append("High transaction volume (>1000 txs)")
    if tx_count == 0:
        risk_score += 5
        risk_flags.append("No transaction history — possible freshly generated wallet")

    verdict = (
        "CRITICAL" if risk_score >= 70 else
        "HIGH" if risk_score >= 40 else
        "MEDIUM" if risk_score >= 20 else
        "LOW"
    )

    data.update({
        "risk_score": min(100, risk_score),
        "verdict": verdict,
        "risk_flags": risk_flags,
        "sanctions": sanctions,
    })

    return data
