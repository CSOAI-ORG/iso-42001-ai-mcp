# ISO/IEC 42001 AI Management System MCP Server

> **By [MEOK AI Labs](https://meok.ai)** — Sovereign AI tools for everyone.

The first MCP server implementing ISO/IEC 42001:2023 compliance assessment. Audit your AI management system against all clauses (4-10), evaluate Annex A controls, perform Annex B risk assessments, generate policy templates, check certification readiness, and crosswalk to EU AI Act articles.

Part of the **Compliance Trinity**: EU AI Act + NIST AI RMF + ISO 42001.

[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `audit_management_system` | Audit against ISO 42001 clauses 4-10 with gap analysis |
| `assess_ai_risk` | Annex B risk assessment with criteria, identification, analysis, evaluation |
| `generate_policy_template` | Generate AI policy documents per ISO 42001 requirements |
| `check_annex_controls` | Evaluate against all Annex A controls with Statement of Applicability |
| `crosswalk_to_eu_ai_act` | Map ISO 42001 clauses to EU AI Act articles (killer feature) |
| `create_certification_checklist` | ISO 42001 certification readiness checklist with pass/fail |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/iso-42001-ai-mcp.git
cd iso-42001-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "iso-42001-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/iso-42001-ai-mcp"
    }
  }
}
```

## The Crosswalk Advantage

No one else maps regulation-to-regulation as MCP tools. The `crosswalk_to_eu_ai_act` tool shows exactly where ISO 42001 conformity satisfies EU AI Act requirements:

- **Clause 6.1** maps to EU AI Act Articles 9(2), 9(5), 27
- **Clause 8.4** maps to EU AI Act Articles 27, 9(4)(a)
- **A.6.3** maps to EU AI Act Articles 9(2), 10, 13, 14, 15
- 25+ detailed mappings with alignment strength ratings

## Coverage

- **7 Management System Clauses** (4-10) with all subclauses
- **27 Annex A Controls** across 9 control sections
- **7 Annex B Risk Categories** with risk factors
- **25+ ISO-to-EU crosswalk mappings**
- **3 Policy template types** (comprehensive, brief, executive)
- **30-item certification readiness checklist**

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 10 assessments/day |
| Pro | $29/mo | Unlimited |

## Part of MEOK AI Labs

This is one of 255+ MCP servers by MEOK AI Labs. Browse all at [meok.ai](https://meok.ai) or [GitHub](https://github.com/CSOAI-ORG).

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | nicholas@meok.ai | United Kingdom
