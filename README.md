# ISO 42001 AI

> By [MEOK AI Labs](https://meok.ai) — ISO/IEC 42001:2023 AI Management System compliance assessment

## Installation

```bash
pip install iso-42001-ai-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `audit_management_system`
Audit against ISO 42001 clauses 4-10 with gap analysis.

**Parameters:**
- `organization_description` (str): Description of the AI management system
- `api_key` (str): API key

### `assess_ai_risk`
Annex B risk assessment with criteria, identification, analysis, and evaluation.

**Parameters:**
- `ai_system_description` (str): Description of the AI system
- `api_key` (str): API key

### `generate_policy_template`
Generate AI policy documents per ISO 42001 requirements.

**Parameters:**
- `policy_type` (str): Type of policy (comprehensive, brief, executive)
- `api_key` (str): API key

### `check_annex_controls`
Evaluate against all Annex A controls with Statement of Applicability.

**Parameters:**
- `organization_description` (str): Organization context
- `api_key` (str): API key

### `crosswalk_to_eu_ai_act`
Map ISO 42001 clauses to EU AI Act articles with alignment strength ratings.

**Parameters:**
- `clause_id` (str): ISO 42001 clause identifier
- `api_key` (str): API key

### `create_certification_checklist`
ISO 42001 certification readiness checklist with pass/fail assessment.

**Parameters:**
- `organization_description` (str): Organization context
- `api_key` (str): API key

## Authentication

Free tier: 10 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs

---

## 🏢 Enterprise & Pro Licensing

| Plan | Price | Link |
|------|-------|------|
| **Compliance Trinity** (EU AI Act + GDPR + ISO 42001) | £79/mo | [Subscribe](https://buy.stripe.com/eVq5kF2G0aEG3812Yg8k82i) |
| **Full Suite** (9 MCPs) | £999/mo | [Subscribe](https://buy.stripe.com/6oU14p0xS4giaAtbuM8k82q) |
| **Enterprise Assessment** | £5,000 | [Book Now](https://buy.stripe.com/00waEZ6Wg8wy7oh0Q88k82k) |

> The world's only ISO 42001 MCP server — by [MEOK AI Labs](https://meok.ai).

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | [csoai.org](https://csoai.org) | nicholas@meok.ai
