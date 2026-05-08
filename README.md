<div align="center">

# Iso 42001 Ai MCP

**MCP server for iso 42001 ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-iso-42001-ai-mcp)](https://pypi.org/project/meok-iso-42001-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Iso 42001 Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `audit_management_system` | Audit an AI management system against ISO/IEC 42001 clauses 4-10. |
| `assess_ai_risk` | Perform ISO 42001 Annex B risk assessment for AI systems. |
| `generate_policy_template` | Generate AI policy documents per ISO 42001 requirements. |
| `check_annex_controls` | Evaluate AI system against ISO 42001 Annex A controls. |
| `crosswalk_to_eu_ai_act` | Map ISO/IEC 42001 clauses and Annex A controls to EU AI Act articles. |
| `create_certification_checklist` | Generate ISO 42001 certification readiness checklist with pass/fail. |
| `predict_risk_neural` | Neural network-based risk prediction that improves from every compliance check. |
| `neural_insights` | Get aggregate learning insights from the neural compliance model. |
| `quick_scan` | One-line system description to instant ISO 42001 gap assessment. No API key need |
| `certification_timeline` | Returns ISO 42001 certification steps and typical timelines. No parameters neede |

## Installation

```bash
pip install meok-iso-42001-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "iso-42001-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_iso_42001_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 10 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
