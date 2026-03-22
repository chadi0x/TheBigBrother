import requests
import datetime

def analyze_crypto(address: str, coin: str):
    """
    Analyzes a crypto address for balance and activity.
    Supports BTC, ETH, LTC, and TRX via free public APIs.
    """
    results = {
        "coin": coin.upper(),
        "address": address,
        "balance": 0,
        "total_received": 0,
        "tx_count": 0,
        "last_seen": "Never",
        "recent_txs": [],
        "error": None
    }
    
    try:
        if coin.lower() == "btc":
            url = f"https://blockchain.info/rawaddr/{address}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results["balance"] = data.get("final_balance", 0) / 100000000
                results["total_received"] = data.get("total_received", 0) / 100000000
                results["tx_count"] = data.get("n_tx", 0)
                
                txs = data.get("txs", [])
                if txs:
                    last_time = txs[0].get("time")
                    if last_time:
                        results["last_seen"] = datetime.datetime.fromtimestamp(last_time).strftime('%Y-%m-%d %H:%M:%S')
                    for t in txs[:5]:
                        results["recent_txs"].append({
                            "hash": t.get("hash"),
                            "time": datetime.datetime.fromtimestamp(t.get("time")).strftime('%Y-%m-%d %H:%M') if t.get("time") else "Unknown",
                            "result": t.get("result", 0) / 100000000
                        })
            else:
                 results["error"] = f"API returned {resp.status_code}"
                 
        elif coin.lower() == "eth":
            url = f"https://api.blockcypher.com/v1/eth/main/addrs/{address}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results["balance"] = data.get("balance", 0) / 10**18
                results["total_received"] = data.get("total_received", 0) / 10**18
                results["tx_count"] = data.get("n_tx", 0)
                
                txrefs = data.get("txrefs", [])
                if txrefs:
                    results["last_seen"] = txrefs[0].get("confirmed", "Check Explorer")[:19].replace("T", " ")
                    for t in txrefs[:5]:
                        results["recent_txs"].append({
                            "hash": t.get("tx_hash"),
                            "time": t.get("confirmed", "")[:16].replace("T", " "),
                            "result": t.get("value", 0) / 10**18
                        })
                else:
                    results["last_seen"] = "Check Explorer"
            else:
                 results["error"] = f"API returned {resp.status_code}"

        elif coin.lower() == "ltc":
            url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results["balance"] = data.get("balance", 0) / 10**8
                results["total_received"] = data.get("total_received", 0) / 10**8
                results["tx_count"] = data.get("n_tx", 0)
                
                txrefs = data.get("txrefs", [])
                if txrefs:
                    results["last_seen"] = txrefs[0].get("confirmed", "Check Explorer")[:19].replace("T", " ")
                    for t in txrefs[:5]:
                        results["recent_txs"].append({
                            "hash": t.get("tx_hash"),
                            "time": t.get("confirmed", "")[:16].replace("T", " "),
                            "result": t.get("value", 0) / 10**8
                        })
                else:
                    results["last_seen"] = "Check Explorer"
            else:
                 results["error"] = f"API returned {resp.status_code}"

        elif coin.lower() == "trx":
            url = f"https://apilist.tronscanapi.com/api/accountv2?address={address}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results["balance"] = data.get("balance", 0) / 1000000
                results["total_received"] = data.get("totalTransactionCount", 0) # Not exactly total received but useful
                results["tx_count"] = data.get("transactions", 0)
                
                last = data.get("latest_operation_time")
                if last:
                    results["last_seen"] = datetime.datetime.fromtimestamp(last/1000).strftime('%Y-%m-%d %H:%M:%S')
            else:
                 results["error"] = f"API returned {resp.status_code}"
    
    except Exception as e:
        results["error"] = str(e)
        
    return results
