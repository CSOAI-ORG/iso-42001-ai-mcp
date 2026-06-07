<!-- mcp-name: io.github.CSOAI-ORG/iso-42001-ai-mcp -->
# Iso 42001 Ai MCP

> **⚖️ Built by [MEOK AI Labs](https://meok.ai) / [CSOAI](https://csoai.org).** Need this applied to _your_ system fast? Book a 30-min Founder Office Hour (£29) → **https://meok.ai/work** · Full governance platform → **https://meok.ai**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![PAYG enabled](https://img.shields.io/badge/PAYG-%C2%A30.05%2Fcall-7c3aed?logo=stripe&logoColor=white&labelColor=1a1a2e)](https://councilof.ai/payg)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-22c55e)](https://councilof.ai)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/iso_42001_ai_mcp/)

> ISO 42001 AI Management System compliance MCP — AIMS assessment, risk management, AI lifecycle go...

ISO 42001 AI Management System compliance MCP — AIMS assessment, risk management, AI lifecycle governance, certification readiness.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install iso_42001_ai_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install iso-42001-ai-mcp --client claude
```

## ⚡ Pay-per-call (PAYG) — no subscription

This MCP supports universal pay-per-call billing across the MEOK compliance fleet:

```bash
# One-time setup
export MEOK_PAYG_KEY="your_topup_token"

# Every tool call now deducts £0.05 from your balance.
# When balance hits zero, the tool returns a top-up URL.
# Works across all 7 MEOK compliance MCPs with the same token.
```

- **No subscription** — top up once, deduct per call.
- **£0.05/call default** (configurable via `MEOK_PAYG_RATE_GBP`).
- **USDC on Base L2 accepted** — set `MEOK_X402_RECEIVER` and pay via stablecoin.
- **Backward-compatible** — when `MEOK_PAYG_KEY` is unset, behaviour is unchanged.

**Get a token**: [councilof.ai/payg](https://councilof.ai/payg) (£10 / £50 / £200 top-up tiers).


## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/iso-42001-ai-mcp)
- [API Reference](https://api.meok.ai)
- [EU AI Act Compliance Guide](https://councilof.ai/compliance)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](https://cal.com/csoai/august-audit)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** $99/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** $499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/pricing) | [Contact Sales →](mailto:sales@csoai.org)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 300+ MCP servers for sovereign AI governance.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>


## Configuration

Add to your `claude_desktop_config.json` (Claude Desktop) or your MCP client config:

```json
{
  "mcpServers": {
    "iso-42001-ai-mcp": {
      "command": "uvx",
      "args": ["iso-42001-ai-mcp"]
    }
  }
}
```

Or: `pip install iso-42001-ai-mcp` then run the `iso-42001-ai-mcp` command (stdio transport).

## Examples

Once configured, ask your assistant, for example:
- "Use `audit_management_system` to …"
- "Use `assess_ai_risk` to …"
- "Use `generate_policy_template` to …"
