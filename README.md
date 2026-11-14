<div align="center">

<br/>

<img width="2048" height="768" alt="The Big Brother VX_ Classified OSINT Command Center" src="https://github.com/user-attachments/assets/090a87c1-172f-4860-9b8c-e36b635ae2c3" />

<br/>

**Premium OSINT & Threat-Intelligence Console · 76 Engines · 24-Engine Keyless Arsenal · Unified Intelligence Result Surface**

[![Version](https://img.shields.io/badge/version-10.1.0--SOVEREIGN-E8C87A.svg?style=for-the-badge&logo=v&logoColor=white)](https://github.com/chadi0x/the-big-brother/releases)
[![License](https://img.shields.io/badge/license-MIT-5EEAD4.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-93C5FD.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-E8C87A.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/STATUS-OPERATIONAL-5EEAD4.svg?style=for-the-badge)](https://github.com/chadi0x/)

[`★ WHAT'S NEW`](#-whats-new-in-vx1-sovereign) · [`★ 24 NEW ENGINES`](#-the-vx-arsenal--24-new-engines) · [`★ RESULT SURFACE`](#-the-unified-intelligence-result-surface) · [`★ INSTALL`](#-installation) · [`★ PREMIUM`](#-premium-projects) · [`★ TELEGRAM`](https://t.me/hisoka0morow)

</div>

---
<a href="https://thebigbrother.cloud/">
  <img width="1584" height="672" alt="The Big Brother VX Sovereign" src="https://github.com/user-attachments/assets/26176b6c-ef32-473b-95f5-68b2d63e52fd">
</a>



> [!IMPORTANT]
> # 🚀 WANT TO USE THE BIG BROTHER WITHOUT INSTALLING ANYTHING?
>
> **You can access The Big Brother directly from your browser. No downloads, no installation, no local setup, and no configuration required.**
>
> <h2 align="center">⚡ <a href="https://thebigbrother.cloud/">LAUNCH THE BIG BROTHER ONLINE</a></h2>
>
>
> **Just open the website and start exploring.**
>
> ---

> [!IMPORTANT]
> ### ⚡ VX.1 IS A GROUND-UP REBRAND AND A 24-ENGINE EXPANSION
>
> The Big Brother has moved from the VX.0 **NEXUS** console to the **VX.1 SOVEREIGN** release:
>
> - **A completely new visual system** — obsidian surfaces, champagne/jade/ice accents, Sora + Manrope + IBM Plex Mono typography, refined navigation, and a full redesign of every card, form, badge, table and result deck.
> - **A brand-new VX Arsenal** with **24 keyless, production-grade engines** across DNS/CT, edge security, cloud exposure, token forensics, breach-aware password auditing, CVE/EPSS/KEV correlation, attack-surface scoring, origin unmasking, GraphQL and supply-chain auditing.
> - **A unified Intelligence Result Surface** — every new engine returns a structured envelope with a risk score, severity-ranked findings, extracted indicators and a navigable data model rendered as premium evidence cards.
> - **Hardened legacy engines** — SSL Sentinel, EXIF Analyzer, Dork Studio, Sky Radar and Crypto Analyzer were rebuilt with richer logic, safer fallbacks and no silent mock data.
---

## ⟦ OVERVIEW ⟧

**The Big Brother VX.1 (SOVEREIGN)** is a cyber-operations OSINT and threat-intelligence platform for Red Teams, SOC analysts, geolocation investigators, brand-protection teams and defensive researchers.

The platform now exposes **76 engines** (52 dual-engine tactical tools + 24 VX Arsenal engines) through three complementary surfaces:

1. **The legacy Dual-Engine Tactical Matrix** — 26 workspace tabs, each with a primary and companion engine.
2. **The VX Arsenal** — 24 brand-new keyless engines in a dynamic, filterable workspace.
3. **The Nexus Graph Canvas** — live relationship topology built from real scan payloads.

> **Indexed modules:** 60 (36 primary legacy modules + 24 VX engines). Companion engines are exposed through the dual-engine switcher and counted in the 76-engine total.

```text
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  76 TACTICAL ENGINES · 26 WORKSPACE TABS · 24 VX ENGINES · NEXUS CANVAS  │
   │  UNIFIED RESULT ENVELOPE · RISK GRADING · SEVERITY-RANKED FINDINGS       │
   │  ZERO API KEYS FOR THE VX ARSENAL · DOCKER-READY · PURE-PYTHON FALLBACKS │
   └──────────────────────────────────────────────────────────────────────────┘
```

---

## 🆕 WHAT'S NEW IN VX.1 (SOVEREIGN)

### 1. Full UI/UX Rebrand — "Obsidian Sovereign"
A structural and visual rebuild (`sovereign.css`) replaces the old three-column war-room with an Aurora command layout:

- **New palette:** obsidian black, electric mint, cyan, lime, amber and violet.
- **New typography:** Sora (display), Manrope (interface), IBM Plex Mono (telemetry).
- **New top bar:** brand, global search, live CPU/MEM/latency chips, inspector, audio and operator identity — no wrapping or misplaced elements.
- **New left rail:** clean expanded navigation and a proper icon-only collapsed mode with centered icons, active indicator and hover labels.
- **Permanent right rail removed:** threat, coverage, ledger, correlation and dossier export now live in a slide-over **Intelligence Inspector**.
- **New full-width dashboard:** bento-style command center with hero, engine mesh, live vitals, threat score, intel wire, markets, exploit/tech feeds and an operator launchpad.
- **Mobile-first navigation drawer** with scrim and keyboard/Escape support.
- **Rebuilt cards, forms, badges, tables, result decks and dialogs**, plus responsive layouts for 1600px, 1280px, 1024px, tablet and mobile widths.

### 2. The VX Arsenal — 24 New Keyless Engines
Every engine is available from a dynamic registry, so the UI builds its own forms, labels, source badges and run controls. No HTML edits are required to add a tool.

### 3. Unified Intelligence Result Surface
Every VX result is a structured envelope:

```json
{
  "status": "success",
  "tool": "dns_intel",
  "target": "example.com",
  "risk_score": 23,
  "risk_tier": "GUARDED",
  "grade": "B",
  "summary": "Human-readable executive summary.",
  "findings": [
    {"severity": "high", "title": "...", "detail": "...", "recommendation": "..."}
  ],
  "iocs": [{"type": "domain", "value": "example.com"}],
  "data": {"...": "structured evidence model"},
  "sources": ["Cloudflare DoH", "Google DoH"]
}
```

The renderer displays a **risk ring**, **letter grade**, **severity chips**, **finding cards**, **IOC tags**, **recursive data tables/cards** and a **raw JSON inspector** — with copy/export actions.

### 4. Legacy Result Decks Elevated
A `MutationObserver` wraps every existing `.result-deck` in the VX result toolbar, adds copy/collapse controls, and applies the premium result styling without touching the legacy render functions.

### 5. Hardened Legacy Logic
- **SSL Sentinel** — graded TLS posture, certificate chain, expiry window, SAN matching, forward secrecy, cipher/key analysis and recommendations.
- **EXIF Analyzer** — URL + uploaded bytes, GPS decimal conversion, camera fingerprint, software provenance, hashes, risk verdict.
- **Dork Studio** — expanded operator matrix across Google, GitHub, Shodan, Censys, FOFA, VirusTotal, Pastebin and LinkedIn with severity and rationale.
- **Sky Radar** — latitude-corrected bbox, airborne filtering, emergency squawk classification, military/VIP heuristics, distance/bearing and country stats.
- **Crypto Analyzer** — auto-detection across BTC/ETH/LTC/TRX/SOL, Blockchair multi-provider fallback, fiat valuation and explicit provenance.

---

## ⚡ THE VX ARSENAL — 24 NEW ENGINES

| # | Engine | Discipline | What It Does |
|:--|:---|:---|:---|
| **01** | **DNS Intelligence** | Network | Full A/AAAA/MX/NS/TXT/SOA/CAA/SRV matrix, SPF/DKIM/DMARC/MTA-STS/BIMI, DNSSEC signal, wildcard detection and provider attribution. |
| **02** | **Certificate Transparency** | Passive | Harvest every subdomain from CT logs, resolve live hosts, detect wildcard SANs, issuer distribution and stale attack surface. Falls back to OTX/HackerTarget passive DNS. |
| **03** | **Typosquat Radar** | Brand defense | Omission, repetition, transposition, keyboard, IDN homograph and TLD-swap permutations; resolves and fingerprints live lookalikes; excludes same-infrastructure defensive registrations. |
| **04** | **HTTP Security Audit** | Hardening | Header grading, CSP directive inspection, cookie flags, CORS, HSTS, TLS, HTTP→HTTPS redirect, server disclosure and technology fingerprinting. |
| **05** | **WAF & CDN Fingerprint** | Active probe | Cloudflare, Akamai, Imperva, F5, Sucuri, AWS, Azure, Fastly, DDoS-Guard, Vercel, Netlify and Bunny signatures, plus a harmless XSS canary to verify blocking. |
| **06** | **IP Intelligence** | Multi-source | Geo/ASN, RDAP registry, PTR, internet-exposed ports, CVEs, CPEs and hosting/proxy classification via Shodan InternetDB. |
| **07** | **Cloud Bucket Hunter** | Cloud exposure | Brand-derived candidate names tested against AWS S3, Google Cloud Storage and Azure Blob for public listings and private existence. |
| **08** | **Exposed Files Hunter** | Exposure | 50 high-signal paths (.git, .env, keys, SQL dumps, Spring actuators, source maps, backups) validated against content signatures to suppress soft-404 noise. |
| **09** | **Link Forensics** | Phishing defense | Shortener expansion, full redirect chain, punycode/@ tricks, raw-IP destinations, high-abuse TLDs, open-redirect parameters, tracking residue and sanitized URL. |
| **10** | **JWT Analyzer** | Token forensics | Header/claim decode, exp/nbf/lifetime audit, `alg=none`, `jku/x5u` key injection, PII/privilege claims and an HMAC dictionary attack for HS256/384/512. |
| **11** | **Pwned Password Audit** | Credential hygiene | Local entropy/pattern model + HIBP Pwned Passwords k-anonymity range lookup. The plaintext is never returned or logged. |
| **12** | **Gravatar Surface** | Identity | Resolve email-hash or username profiles, linked verified accounts, public phone numbers, location, biography and avatar artifacts. |
| **13** | **CVE Intelligence** | Threat intel | NVD/MITRE correlation with CISA KEV, known ransomware use and FIRST EPSS; accepts CVE IDs or vendor/product keywords. |
| **14** | **IOC Enrichment** | Threat intel | IP/domain/URL/email/hash enrichment with OTX pulses, malware families, adversaries, passive DNS, URLhaus records, geo and TLS context. |
| **15** | **VIN Provenance** | Vehicle OSINT | Check-digit validation, WMI country, NHTSA vPIC decode (make/model/trim/engine/plant/safety) and recall campaigns. |
| **16** | **Card BIN Intelligence** | Financial OSINT | Network/type/brand/prepaid, issuing bank, country, Luhn validation and local IIN prefix fallback. Only the first 8 digits are transmitted. |
| **17** | **Bluesky Intelligence** | Social surface | Handle/DID resolution, profile metrics, account age, follow ratio, posting rhythm, hashtags, links, labels and scam-language signals. |
| **18** | **Reddit Intelligence** | Social surface | Karma breakdown, account age, recent posts/comments, top subreddits/domains, UTC posting histogram, NSFW ratio and bot/spam signals. Arctic Shift fallback when Reddit blocks datacenter IPs. |
| **19** | **Discord Invite Intel** | Social surface | Server identity/age, member vs online counts, verification level, features, inviter, expiration, NSFW and scam-language signals. |
| **20** | **Telegram Intelligence** | Social surface | Public channel/group/profile resolution, subscriber/member counts, verification, recent posts, links, hashtags and scam signals. |
| **21** | **Attack Surface Scorecard** | Flagship | Runs six VX engines in parallel (DNS, CT, HTTP, WAF, exposed files, cloud buckets) and produces one weighted Attack Surface Index, letter grade, category breakdown, critical findings and quick wins. |
| **22** | **Origin IP Unmasker** | CDN bypass | Correlates current DNS, OTX passive DNS, HackerTarget, CT subdomains, MX and origin-style hostnames; validates candidates with Host-header probes and title/body/server fingerprint matching. |
| **23** | **GraphQL Inspector** | AppSec | Discovers GraphQL endpoints, runs introspection, inventories queries/mutations, flags sensitive and destructive fields, and tests batching, GET queries, GraphiQL and field-suggestion leaks. |
| **24** | **Supply Chain Auditor** | AppSec | Audits npm and PyPI packages for typosquatting, install-time scripts, deprecation, direct-URL dependencies, provenance gaps and suspicious setup.py execution primitives — including source-distribution inspection. |

> **All 24 engines are keyless.** Engines that depend on public feeds degrade gracefully and report upstream diagnostics instead of crashing.

### Flagship additions in VX.1

- **Attack Surface Scorecard** — the “one click, whole perimeter” engine. It orchestrates six engines, merges their findings, and gives an operator a single weighted index with category-level risk.
- **Origin IP Unmasker** — one of the most requested CDN-bypass workflows: historical DNS + CT + Host-header validation with evidence and confidence scores.
- **GraphQL Inspector** — aimed at bug-bounty and AppSec teams: schema inventory, sensitive fields, destructive mutations and batching/GET/GraphiQL checks.
- **Supply Chain Auditor** — npm/PyPI typosquat detection, install-script analysis and PyPI sdist execution-primitive inspection.


---

## 🧠 THE UNIFIED INTELLIGENCE RESULT SURFACE

The VX renderer is intentionally generic: any engine that returns the envelope contract gets the same premium output.

```text
   ┌──────────────────────────────────────────────────────────────────────┐
   │  RISK RING 64/100   JWT // HIGH // GRADE D // 29ms                  │
   │  Weak secret recovered · no expiry · PII embedded                   │
   ├──────────────────────────────────────────────────────────────────────┤
   │  SEVERITY-RANKED FINDINGS                                           │
   │  [CRITICAL] JWT signed with a weak secret                           │
   │             FIX // Rotate the signing key to a 256-bit secret       │
   │  [HIGH]     No expiration claim                                     │
   │  [MEDIUM]   PII embedded in token                                   │
   ├──────────────────────────────────────────────────────────────────────┤
   │  STRUCTURED INTELLIGENCE MODEL                                      │
   │  Header · Payload · Claims · Algorithm · Signature entropy          │
   ├──────────────────────────────────────────────────────────────────────┤
   │  EXTRACTED INDICATORS                                               │
   │  RAW ENVELOPE // COPY · EXPORT                                      │
   └──────────────────────────────────────────────────────────────────────┘
```

The same surface is applied to legacy results through a non-invasive enhancement layer, so existing tools immediately benefit from the new visual language.

---

## 🌐 NEXUS GRAPH CANVAS

The **Nexus Graph Canvas** (`#btn-mode-nexus`) provides interactive relationship network visualization powered by Cytoscape.js:

- **Selective tab capability** across relationship-centric modules.
- **Auto-revert logic** when navigating to a non-graph tab.
- **Zero-mock topology** built from real scan results cached via `window.recordModuleResult()`.
- **Force-directed (COSE), Concentric and Circle layouts.**

---

## 🚀 INSTALLATION

### ⟦ PROTOCOL A · Docker (Recommended) ⟧

```bash
# 1. Clone the repository
git clone https://github.com/chadi0x/TheBigBrother.git
cd TheBigBrother

# 2. Boot the stack
docker-compose up --build -d
```

> ▸ **Access Interface:** `http://localhost:8000`
> ▸ **Stop Stack:** `docker-compose down`
> ▸ **Live Logs:** `docker-compose logs -f`

### ⟦ PROTOCOL B · Bare-Metal Deployment ⟧

**Prerequisites:** Python `3.10+` · Node.js (optional)

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
playwright install chromium

# 3. Launch The Big Brother VX.1
uvicorn the_big_brother.gui.main:app --host 0.0.0.0 --port 8000 --reload
```

### ⟦ Protocol C · VX Arsenal only (optional) ⟧

The Arsenal is pure-stdlib first. If you only want the 24 new engines, import them directly:

```python
import asyncio
from the_big_brother.modules.arsenal import run_tool, get_registry

async def main():
    result = await run_tool("dns_intel", {"target": "example.com"})
    print(result["risk_score"], result["summary"])

asyncio.run(main())
```

---

## 🧪 QUICK API EXAMPLES

```bash
# Registry (tool metadata + dynamic form schema)
curl http://localhost:8000/api/arsenal/registry

# Run any VX engine
curl -X POST http://localhost:8000/api/arsenal/cert_transparency \
  -H 'Content-Type: application/json' \
  -d '{"target":"cloudflare.com"}'

# CVE correlation
curl -X POST http://localhost:8000/api/arsenal/cve_intel \
  -H 'Content-Type: application/json' \
  -d '{"target":"CVE-2024-3400"}'

# JWT audit (local only)
curl -X POST http://localhost:8000/api/arsenal/jwt_analyzer \
  -H 'Content-Type: application/json' \
  -d '{"target":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}'

# Flagship: one-click attack surface scorecard
curl -X POST http://localhost:8000/api/arsenal/attack_surface \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'

# GraphQL schema audit
curl -X POST http://localhost:8000/api/arsenal/graphql_inspector \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://countries.trevorblades.com/graphql"}'

# npm / PyPI supply-chain audit
curl -X POST http://localhost:8000/api/arsenal/supply_chain_audit \
  -H 'Content-Type: application/json' \
  -d '{"target":"loadsh"}'
```

The universal dispatcher also accepts Arsenal IDs:

```bash
curl -X POST http://localhost:8000/api/modules/ip_intel \
  -H 'Content-Type: application/json' \
  -d '{"target":"1.1.1.1"}'
```

---

## 📸 SCREENSHOTS

<div align="center">

### Command Center
<img width="1600" alt="VX Sovereign Command Center" src="docs/screenshots/command-center.png">

### VX Arsenal
<img width="1600" alt="VX Arsenal — 24 keyless engines" src="docs/screenshots/vx-arsenal.png">

### Attack Surface Scorecard
<img width="1600" alt="Attack Surface Scorecard with weighted index, findings and category data" src="docs/screenshots/attack-surface.png">

### Supply Chain Auditor
<img width="1600" alt="Supply Chain Auditor result with typosquat and install-script findings" src="docs/screenshots/supply-chain.png">

### Unified Intelligence Result Surface
<img width="1600" alt="VX result surface with risk ring, findings and structured data" src="docs/screenshots/result-surface.png">

</div>

---

## ◆ ARCHITECTURE & TECH STACK

```text
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                         FASTAPI ASYNC BACKEND                           │
  │   /api/dispatch/{module_id} · /api/scan · /api/arsenal/{tool_id}        │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
  ┌───────────────────────────────┐     ┌───────────────────────────────────┐
  │      52 LEGACY DUAL-ENGINES        │     │      24 VX ARSENAL ENGINES        │
  │  ChainTracer, SpiderCrawl...  │     │  DNS/CT, WAF, IP, JWT, CVE...    │
  └───────────────┬───────────────┘     └─────────────────┬─────────────────┘
                  │                                       │
                  └───────────────────┬───────────────────┘
                                      │
                                      ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │              SOVEREIGN FRONTEND (OBSIDIAN HUD)                          │
  │  sovereign.css · VX Arsenal registry · Unified Result Renderer          │
  │  Legacy result enhancement · Nexus Graph · Command Palette              │
  └─────────────────────────────────────────────────────────────────────────┘
```

| Layer | Technologies & Implementations |
|:---|:---|
| **Core Backend** | FastAPI · Python 3.10+ · AsyncIO orchestration · Uvicorn ASGI |
| **VX Arsenal** | Pure-stdlib transport (`urllib`), DoH, manual redirect chains, bounded payloads, graceful upstream diagnostics |
| **Forensic Engines** | `urllib`, `ssl`, `math`, `struct`, `wave`, `socket`, `hashlib`, Pillow, aiohttp |
| **Interface** | Semantic HTML5 · Sora/Manrope/IBM Plex Mono · Sovereign design tokens · Vanilla JS (ES6+) |
| **Visualization** | Cytoscape.js (topology) · Leaflet (maps/ADS-B) · Three.js (ambient WebGL) |
| **Web Crawling** | Playwright (headless Chromium) · Beautiful Soup 4 · DuckDuckGo API |
| **Deployment** | Docker · Multi-stage build · Docker Compose |

---

## 🔐 OPERATIONAL SAFETY

- The VX Arsenal is **read-only reconnaissance** unless a tool explicitly states otherwise (WAF probe sends a harmless XSS canary; exposed-files hunter performs GET probes).
- The password audit sends only the **first five characters of a SHA-1 hash** (HIBP k-anonymity) and never returns or logs plaintext.
- JWT analysis is **100% local**; tokens are not transmitted.
- BIN lookup transmits only the first 8 digits.
- Results are retained in memory only and are never written to a database by the console.
- You are responsible for authorization and lawful use.

---

## 🔥 PREMIUM PROJECTS

For specialized operations requiring private databases, custom satellite scrapers, and enterprise automation:

- 👁️ **TheBigBrother God-EYE Enterprise** · Private breach index · real-time SSN/DOB records · zero-key carrier lookups
- 🐦 **X GodMode** · Twitter/X algorithmic automation & sentiment engineering
- 🎵 **Amplifior** · Autonomous multi-channel social media automation
- 🎣 **Psychopath** · Conversational AI adversary emulation & red-team campaign framework
- 🛠️ **Custom Builds** · Tailored intelligence frameworks and military OSINT platforms on request

<div align="center">

**[▸ CONTACT ARCHITECT · Telegram @hisoka0morow](https://t.me/hisoka0morow)**

</div>

---

## ⚠️ DISCLAIMER

This software is strictly intended for **educational purposes, defensive cybersecurity audits, authorized threat intelligence, and lawful investigative research**. The author and contributors accept no liability and are not responsible for any misuse or damage caused by this program.

> **CLASSIFIED · AUTHORIZED OPERATORS ONLY**

---

## 📞 SUPPORT · COMMUNITY

- **Creator & Lead Architect** — `CHADI0X`
- **Official Cloud Portal** — [https://thebigbrother.cloud](https://thebigbrother.cloud)
- **Telegram Direct** — [@hisoka0morow](https://t.me/hisoka0morow)
- **GitHub** — [@chadi0x](https://github.com/chadi0x)

---

<div align="center">

```text
◆ ─────────────────────────────────────────────────── ◆
   "In the digital age, anonymity is a luxury.
    Information is the currency of power."
                              ── CHADI0X
◆ ─────────────────────────────────────────────────── ◆
```

**VX.1 (SOVEREIGN) · THE EYE THAT NEVER BLINKS · ◇**
*Engineered by CHADI0X · Tactical Cyber-Surveillance Grid*

</div>
