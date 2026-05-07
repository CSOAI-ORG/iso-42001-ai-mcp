<div align="center">

[![PyPI](https://img.shields.io/pypi/v/iso-42001-ai-mcp)](https://pypi.org/project/iso-42001-ai-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/iso-42001-ai-mcp)](https://pypi.org/project/iso-42001-ai-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/iso-42001-ai-mcp)](https://github.com/CSOAI-ORG/iso-42001-ai-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# ISO 42001 AI MCP

**AI Management System (AIMS) assessment, certification readiness, and EU AI Act crosswalk against ISO/IEC 42001:2023.**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

ISO 42001:2023 is the world's first certification standard specifically for AI management systems. It defines what an organisation must do to develop, deploy, and maintain AI responsibly. Certification bodies (BSI, TUV, SGS, Bureau Veritas) are now issuing ISO 42001 certificates, and enterprises are requesting it in procurement.

The standard has 39 Annex A controls and 9 management system clauses. Mapping these to your AI lifecycle, crosswalking to EU AI Act conformity assessment, and preparing for a Stage 1/Stage 2 audit typically costs 20-50K in consultancy fees. This MCP performs the full AIMS assessment, risk analysis, policy generation, Annex A control checks, EU AI Act crosswalk, and certification timeline planning from a single prompt.

## Install

```bash
pip install iso-42001-ai-mcp
```

## Tools

| Tool | ISO Reference | What it does |
|------|--------------|--------------|
| `audit_management_system` | Clauses 4-10 | Full AIMS audit against ISO 42001:2023 management clauses |
| `assess_ai_risk` | Clause 6.1 | AI-specific risk assessment with impact and likelihood scoring |
| `generate_policy_template` | Clause 5.2, Annex A | Generate AI policy aligned to management commitment requirements |
| `check_annex_controls` | Annex A (39 controls) | Control-by-control assessment of all Annex A objectives |
| `crosswalk_to_eu_ai_act` | Annex A + EU AI Act | Map ISO 42001 controls to EU AI Act conformity requirements |
| `create_certification_checklist` | Stage 1 / Stage 2 | Certification readiness checklist with timeline |
| `predict_risk_neural` | ML-assisted | Neural network risk prediction for AI systems |
| `quick_scan` | All clauses | Rapid AI system compliance overview |
| `certification_timeline` | Full lifecycle | Stage 1/Stage 2 audit timeline and milestones |

## Example

```
Prompt: "Assess our computer vision system for ISO 42001 certification
readiness. It processes facial images for building access control,
was trained on a proprietary dataset, and has no explainability layer."

Result: AIMS assessment with findings across Annex A controls: biometric
processing triggers A.6.2.4 (impact assessment), missing explainability
fails A.6.2.6 (transparency), proprietary dataset needs A.7.3 (data
management). EU AI Act crosswalk flags Annex III high-risk classification.
Certification timeline generated with 14-week remediation path.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — AIMS audit + quick scan |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

Every Pro/Enterprise audit produces a cryptographically signed certificate:

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
