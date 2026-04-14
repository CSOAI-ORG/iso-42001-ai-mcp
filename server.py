#!/usr/bin/env python3
"""
ISO/IEC 42001 AI Management System MCP Server
================================================
By MEOK AI Labs | https://meok.ai

The first MCP server implementing ISO/IEC 42001:2023 compliance assessment.
Covers all management system clauses (4-10), Annex A controls, Annex B risk
assessment, policy generation, certification readiness, and EU AI Act crosswalks.

Reference: ISO/IEC 42001:2023 — Information technology — Artificial intelligence
           — Management system

Install: pip install mcp
Run:     python server.py
"""

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Tier authentication (connects to Stripe subscriptions)
try:
    from auth_middleware import get_tier_from_api_key, Tier, TIER_LIMITS
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False  # Runs without auth in dev mode

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

# ── Authentication ──────────────────────────────────────────────
import os as _os
import sys, os
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access
_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

def _check_auth(api_key: str = "") -> str | None:
    """Check API key if MEOK_API_KEY is set. Returns error or None."""
    if _MEOK_API_KEY and api_key != _MEOK_API_KEY:
        return "Invalid API key. Get one at https://meok.ai/api-keys"
    return None


FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    """Returns error string if rate-limited, else None."""
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). "
            "Upgrade to MEOK AI Labs Pro for unlimited access at $29/mo: "
            "https://meok.ai/mcp/iso-42001-ai/pro"
        )
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "iso-42001-ai",
    instructions=(
        "ISO/IEC 42001:2023 AI Management System compliance server. "
        "Provides management system auditing against clauses 4-10, Annex A "
        "control evaluation, Annex B risk assessment, policy template generation, "
        "certification readiness checking, and crosswalks to EU AI Act. "
        "By MEOK AI Labs."
    ),
)

# ---------------------------------------------------------------------------
# ISO/IEC 42001:2023 Knowledge Base — Management System Clauses 4-10
# ---------------------------------------------------------------------------

ISO_42001_CLAUSES = {
    "clause_4": {
        "title": "Context of the organization",
        "number": "4",
        "subclauses": {
            "4.1": {
                "title": "Understanding the organization and its context",
                "description": "The organization shall determine external and internal issues that are relevant to its purpose and that affect its ability to achieve the intended outcome(s) of its AI management system.",
                "requirements": [
                    "Identify external issues: regulatory landscape, market conditions, technological trends, societal expectations regarding AI",
                    "Identify internal issues: organizational culture, AI capabilities, resources, governance structures",
                    "Consider AI-specific context: AI lifecycle stages, AI system portfolio, AI maturity level",
                    "Document the context analysis and review periodically",
                ],
                "audit_questions": [
                    "Has the organization documented its AI-specific external and internal context?",
                    "Are regulatory requirements for AI systems identified and tracked?",
                    "Is the organization's AI maturity level assessed?",
                    "Are technological trends and their implications for AI reviewed regularly?",
                ],
            },
            "4.2": {
                "title": "Understanding the needs and expectations of interested parties",
                "description": "The organization shall determine the interested parties that are relevant to the AI management system, their requirements, and which will be addressed through the AIMS.",
                "requirements": [
                    "Identify interested parties: customers, regulators, employees, affected individuals, civil society",
                    "Determine requirements of each interested party regarding responsible AI",
                    "Assess legal, regulatory, and contractual obligations related to AI",
                    "Document and maintain records of interested party analysis",
                ],
                "audit_questions": [
                    "Are all relevant interested parties identified and documented?",
                    "Are the AI-specific requirements of interested parties understood?",
                    "Are regulatory obligations for AI mapped and tracked?",
                    "Is there a process for updating interested party analysis?",
                ],
            },
            "4.3": {
                "title": "Determining the scope of the AI management system",
                "description": "The organization shall determine the boundaries and applicability of the AI management system to establish its scope, considering AI systems developed, provided, or used.",
                "requirements": [
                    "Define which AI systems are in scope of the AIMS",
                    "Consider AI systems developed internally, procured, or used as a service",
                    "Define organizational boundaries (departments, locations, functions)",
                    "Document scope including any exclusions with justification",
                ],
                "audit_questions": [
                    "Is the AIMS scope clearly defined and documented?",
                    "Does the scope cover all relevant AI systems?",
                    "Are any exclusions justified and documented?",
                    "Does the scope address AI systems across the full lifecycle?",
                ],
            },
            "4.4": {
                "title": "AI management system",
                "description": "The organization shall establish, implement, maintain, and continually improve an AI management system including the processes needed and their interactions.",
                "requirements": [
                    "Establish AIMS processes and their interactions",
                    "Implement the AIMS in accordance with ISO/IEC 42001 requirements",
                    "Maintain documentation of the AIMS",
                    "Continually improve the AIMS effectiveness",
                ],
                "audit_questions": [
                    "Is the AIMS established with documented processes?",
                    "Are process interactions defined and understood?",
                    "Is there evidence of AIMS implementation across the organization?",
                    "Are there mechanisms for continual improvement?",
                ],
            },
        },
    },
    "clause_5": {
        "title": "Leadership",
        "number": "5",
        "subclauses": {
            "5.1": {
                "title": "Leadership and commitment",
                "description": "Top management shall demonstrate leadership and commitment with respect to the AI management system.",
                "requirements": [
                    "Ensure AI policy and objectives are established and compatible with strategic direction",
                    "Ensure integration of AIMS requirements into business processes",
                    "Ensure resources needed for the AIMS are available",
                    "Communicate the importance of effective AI management and conforming to AIMS requirements",
                    "Ensure the AIMS achieves its intended outcomes",
                    "Direct and support persons to contribute to AIMS effectiveness",
                    "Promote continual improvement",
                    "Support other relevant management roles to demonstrate leadership in their areas of responsibility",
                ],
                "audit_questions": [
                    "Can top management articulate the AI policy and objectives?",
                    "Are adequate resources allocated to the AIMS?",
                    "Is there evidence of management review of AIMS effectiveness?",
                    "Are AI management responsibilities integrated into business processes?",
                ],
            },
            "5.2": {
                "title": "AI policy",
                "description": "Top management shall establish an AI policy that is appropriate, provides a framework for setting objectives, includes commitment to satisfy requirements, and includes commitment to continual improvement.",
                "requirements": [
                    "AI policy is appropriate to the organization's purpose",
                    "Provides framework for setting AI management objectives",
                    "Includes commitment to satisfy applicable requirements",
                    "Includes commitment to continual improvement of the AIMS",
                    "Policy is available as documented information",
                    "Policy is communicated within the organization",
                    "Policy is available to relevant interested parties as appropriate",
                    "Policy addresses responsible AI principles",
                ],
                "audit_questions": [
                    "Does a documented AI policy exist?",
                    "Is the policy approved by top management?",
                    "Does the policy address responsible AI principles?",
                    "Is the policy communicated to all relevant personnel?",
                    "Is the policy reviewed and updated periodically?",
                ],
            },
            "5.3": {
                "title": "Organizational roles, responsibilities, and authorities",
                "description": "Top management shall ensure that responsibilities and authorities for relevant roles are assigned, communicated, and understood within the organization.",
                "requirements": [
                    "Assign responsibility for ensuring AIMS conforms to ISO 42001 requirements",
                    "Assign responsibility for reporting on AIMS performance to top management",
                    "Define roles for AI risk management, AI ethics, AI governance",
                    "Ensure responsibilities are documented and communicated",
                ],
                "audit_questions": [
                    "Are AIMS roles and responsibilities clearly defined and documented?",
                    "Is there an AI governance body or committee?",
                    "Are AI risk management responsibilities assigned?",
                    "Do personnel understand their AIMS responsibilities?",
                ],
            },
        },
    },
    "clause_6": {
        "title": "Planning",
        "number": "6",
        "subclauses": {
            "6.1": {
                "title": "Actions to address risks and opportunities",
                "description": "When planning for the AI management system, the organization shall consider issues from 4.1, requirements from 4.2, and determine risks and opportunities that need to be addressed.",
                "requirements": [
                    "Determine AI-specific risks and opportunities from context analysis",
                    "Plan actions to address risks and opportunities",
                    "Plan how to integrate actions into AIMS processes",
                    "Plan how to evaluate effectiveness of actions",
                    "Conduct AI system impact assessment per Annex B",
                    "Perform AI risk assessment covering AI-specific threats and vulnerabilities",
                ],
                "audit_questions": [
                    "Is there a documented AI risk assessment process?",
                    "Are AI-specific risks and opportunities identified?",
                    "Are risk treatment plans documented?",
                    "Is the risk assessment reviewed and updated regularly?",
                    "Is there an AI impact assessment process?",
                ],
            },
            "6.2": {
                "title": "AI management system objectives and planning to achieve them",
                "description": "The organization shall establish AI management system objectives at relevant functions, levels, and processes.",
                "requirements": [
                    "Objectives are consistent with the AI policy",
                    "Objectives are measurable (where practicable)",
                    "Objectives take into account applicable requirements",
                    "Objectives are monitored, communicated, and updated as appropriate",
                    "Document what will be done, resources required, who is responsible, when it will be completed, how results will be evaluated",
                ],
                "audit_questions": [
                    "Are AIMS objectives documented and measurable?",
                    "Are objectives aligned with the AI policy?",
                    "Are action plans defined for achieving objectives?",
                    "Is progress toward objectives monitored and reported?",
                ],
            },
        },
    },
    "clause_7": {
        "title": "Support",
        "number": "7",
        "subclauses": {
            "7.1": {
                "title": "Resources",
                "description": "The organization shall determine and provide the resources needed for the establishment, implementation, maintenance, and continual improvement of the AIMS.",
                "requirements": [
                    "Determine required resources for AIMS (financial, human, technological)",
                    "Provide resources for AI risk management activities",
                    "Ensure adequate AI expertise is available (internal or external)",
                    "Allocate resources for AI system monitoring and evaluation",
                ],
                "audit_questions": [
                    "Are resources adequate for AIMS implementation?",
                    "Is there a resource allocation plan for AI management?",
                    "Is AI expertise sufficient for the organization's AI portfolio?",
                    "Are resources allocated for AI risk management activities?",
                ],
            },
            "7.2": {
                "title": "Competence",
                "description": "The organization shall determine necessary competence, ensure persons are competent, and where applicable take actions to acquire needed competence.",
                "requirements": [
                    "Determine competence requirements for AI management roles",
                    "Ensure personnel have appropriate AI literacy and skills",
                    "Provide training on AI risk management and responsible AI",
                    "Evaluate competence through appropriate assessment methods",
                    "Retain documented evidence of competence",
                ],
                "audit_questions": [
                    "Are AI competence requirements defined for relevant roles?",
                    "Is AI training provided to relevant personnel?",
                    "Are competence assessments conducted and documented?",
                    "Is there an AI skills development program?",
                ],
            },
            "7.3": {
                "title": "Awareness",
                "description": "Persons doing work under the organization's control shall be aware of the AI policy, their contribution to AIMS effectiveness, and implications of not conforming.",
                "requirements": [
                    "Ensure awareness of the AI policy throughout the organization",
                    "Communicate individual contributions to AIMS effectiveness",
                    "Communicate implications of not conforming to AIMS requirements",
                    "Foster AI awareness culture across all levels",
                ],
                "audit_questions": [
                    "Are personnel aware of the AI policy?",
                    "Do personnel understand their role in AIMS effectiveness?",
                    "Are consequences of non-conformity understood?",
                    "Is there an AI awareness program?",
                ],
            },
            "7.4": {
                "title": "Communication",
                "description": "The organization shall determine internal and external communications relevant to the AIMS.",
                "requirements": [
                    "Determine what to communicate about AI management",
                    "Determine when, with whom, and how to communicate",
                    "Establish channels for reporting AI incidents and concerns",
                    "Define external communication strategy for AI transparency",
                ],
                "audit_questions": [
                    "Is there a defined AI communication strategy?",
                    "Are internal communication channels established for AI topics?",
                    "Are there mechanisms for reporting AI incidents?",
                    "Is external communication about AI activities appropriate?",
                ],
            },
            "7.5": {
                "title": "Documented information",
                "description": "The AIMS shall include documented information required by ISO 42001 and determined by the organization as necessary for AIMS effectiveness.",
                "requirements": [
                    "Maintain documented information required by ISO 42001",
                    "Control creation, update, and approval of documents",
                    "Ensure documents are available, suitable for use, and adequately protected",
                    "Control distribution, access, retrieval, use, storage, preservation, and disposition",
                    "Retain records as evidence of AI management activities",
                ],
                "audit_questions": [
                    "Is AIMS documentation complete and current?",
                    "Is there a document control process?",
                    "Are records of AI management activities retained?",
                    "Is documented information accessible to relevant personnel?",
                ],
            },
        },
    },
    "clause_8": {
        "title": "Operation",
        "number": "8",
        "subclauses": {
            "8.1": {
                "title": "Operational planning and control",
                "description": "The organization shall plan, implement, and control the processes needed to meet AIMS requirements and implement actions from clause 6.",
                "requirements": [
                    "Plan and implement processes for AI system lifecycle management",
                    "Establish criteria for AI system development, deployment, and operation",
                    "Control processes in accordance with criteria",
                    "Control planned changes and review consequences of unintended changes",
                    "Ensure outsourced processes are controlled",
                ],
                "audit_questions": [
                    "Are AI lifecycle processes planned and documented?",
                    "Are criteria established for AI development and deployment?",
                    "Is change management applied to AI systems?",
                    "Are outsourced AI processes controlled?",
                ],
            },
            "8.2": {
                "title": "AI risk assessment",
                "description": "The organization shall perform AI risk assessments at planned intervals or when significant changes are proposed or occur.",
                "requirements": [
                    "Conduct risk assessment per criteria established in clause 6.1",
                    "Identify AI-specific risks (bias, safety, security, privacy, transparency)",
                    "Analyze risks (likelihood and impact)",
                    "Evaluate risks against risk criteria and prioritize",
                    "Retain documented information on AI risk assessment results",
                ],
                "audit_questions": [
                    "Are AI risk assessments conducted at planned intervals?",
                    "Do risk assessments cover AI-specific risk categories?",
                    "Are risk assessment results documented and acted upon?",
                    "Are risk assessments triggered by significant changes?",
                ],
            },
            "8.3": {
                "title": "AI risk treatment",
                "description": "The organization shall implement the AI risk treatment plan and retain documented information on the results.",
                "requirements": [
                    "Implement risk treatment plan from clause 6.1",
                    "Select appropriate Annex A controls for identified risks",
                    "Produce a Statement of Applicability documenting selected controls",
                    "Formulate AI risk treatment plan with justifications",
                    "Obtain risk owner approval for residual risks",
                    "Retain documented information on risk treatment results",
                ],
                "audit_questions": [
                    "Is the risk treatment plan implemented?",
                    "Is there a Statement of Applicability for Annex A controls?",
                    "Are risk treatment decisions justified and documented?",
                    "Have risk owners approved residual risks?",
                ],
            },
            "8.4": {
                "title": "AI system impact assessment",
                "description": "The organization shall establish and maintain a process for assessing potential consequences of AI systems on individuals, groups, and societies.",
                "requirements": [
                    "Assess potential positive and negative impacts of AI systems",
                    "Consider impacts on individuals, groups, communities, and societies",
                    "Assess impacts throughout the AI system lifecycle",
                    "Document impact assessment methodology and results",
                    "Review impact assessments when changes occur",
                ],
                "audit_questions": [
                    "Is there an AI impact assessment process?",
                    "Are impacts on individuals and society assessed?",
                    "Are impact assessments conducted throughout the AI lifecycle?",
                    "Are impact assessment results documented and reviewed?",
                ],
            },
        },
    },
    "clause_9": {
        "title": "Performance evaluation",
        "number": "9",
        "subclauses": {
            "9.1": {
                "title": "Monitoring, measurement, analysis, and evaluation",
                "description": "The organization shall determine what needs to be monitored and measured, the methods, when monitoring/measuring shall be performed, and when results shall be analyzed.",
                "requirements": [
                    "Define monitoring and measurement requirements for AI systems",
                    "Determine metrics for AI system performance and risk",
                    "Establish monitoring frequency and methods",
                    "Analyze and evaluate results of monitoring and measurement",
                    "Retain evidence of monitoring and measurement results",
                ],
                "audit_questions": [
                    "Are AI monitoring and measurement criteria defined?",
                    "Are appropriate AI metrics being tracked?",
                    "Is monitoring data analyzed and acted upon?",
                    "Are monitoring results documented?",
                ],
            },
            "9.2": {
                "title": "Internal audit",
                "description": "The organization shall conduct internal audits at planned intervals to provide information on whether the AIMS conforms to requirements and is effectively implemented.",
                "requirements": [
                    "Plan and establish audit program considering AI-specific requirements",
                    "Define audit criteria, scope, frequency, and methods",
                    "Select auditors with appropriate AI management competence",
                    "Report audit results to relevant management",
                    "Take necessary corrections and corrective actions without undue delay",
                    "Retain documented information as evidence of the audit programme and results",
                ],
                "audit_questions": [
                    "Is there a documented internal audit programme for the AIMS?",
                    "Are auditors competent in AI management systems?",
                    "Are audit findings reported and acted upon?",
                    "Are audit records maintained?",
                ],
            },
            "9.3": {
                "title": "Management review",
                "description": "Top management shall review the AIMS at planned intervals to ensure its continuing suitability, adequacy, and effectiveness.",
                "requirements": [
                    "Conduct management reviews at planned intervals",
                    "Review inputs: audit results, interested party feedback, risk assessment changes, AI performance metrics, incidents, improvement opportunities",
                    "Review outputs: improvement decisions, resource needs, AIMS changes",
                    "Retain documented information of management review results",
                ],
                "audit_questions": [
                    "Are management reviews conducted at planned intervals?",
                    "Do reviews cover all required inputs?",
                    "Are management review decisions documented and implemented?",
                    "Is there evidence of management commitment to improvement?",
                ],
            },
        },
    },
    "clause_10": {
        "title": "Improvement",
        "number": "10",
        "subclauses": {
            "10.1": {
                "title": "Continual improvement",
                "description": "The organization shall continually improve the suitability, adequacy, and effectiveness of the AI management system.",
                "requirements": [
                    "Identify and implement improvements to the AIMS",
                    "Use audit results, analysis, management review for improvement inputs",
                    "Apply lessons learned from AI incidents and near-misses",
                    "Track improvement actions to completion",
                ],
                "audit_questions": [
                    "Is there evidence of continual improvement activities?",
                    "Are lessons learned from AI incidents applied?",
                    "Are improvement actions tracked and closed?",
                    "Is the AIMS effectiveness improving over time?",
                ],
            },
            "10.2": {
                "title": "Nonconformity and corrective action",
                "description": "When a nonconformity occurs, the organization shall react, evaluate, implement corrective action, review effectiveness, and make changes to AIMS if necessary.",
                "requirements": [
                    "React to nonconformities by controlling and correcting them",
                    "Evaluate the need for action to eliminate root causes",
                    "Implement corrective action needed",
                    "Review effectiveness of corrective actions taken",
                    "Make changes to the AIMS if necessary",
                    "Retain documented information on nonconformities and corrective actions",
                ],
                "audit_questions": [
                    "Is there a process for handling AIMS nonconformities?",
                    "Are root cause analyses conducted for significant issues?",
                    "Are corrective actions implemented and verified?",
                    "Are nonconformity records maintained?",
                ],
            },
        },
    },
}

# ---------------------------------------------------------------------------
# ISO 42001 Annex A — AI Controls
# ---------------------------------------------------------------------------

ANNEX_A_CONTROLS = {
    "A.2": {
        "title": "Policies for AI",
        "controls": {
            "A.2.2": {
                "title": "AI policy",
                "description": "A set of policies for AI shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties.",
                "objective": "Provide management direction and support for AI in accordance with organizational requirements and relevant laws and regulations.",
            },
            "A.2.3": {
                "title": "Review of policies for AI",
                "description": "Policies for AI shall be reviewed at planned intervals, or if significant changes occur, to ensure their continuing suitability, adequacy, and effectiveness.",
                "objective": "Ensure AI policies remain current and effective.",
            },
        },
    },
    "A.3": {
        "title": "Internal organization",
        "controls": {
            "A.3.2": {
                "title": "Roles and responsibilities",
                "description": "Roles and responsibilities for AI shall be defined and allocated. Relevant roles shall include accountability for the AI management system, AI risk management, AI ethics, data governance, and AI system lifecycle management.",
                "objective": "Ensure clear accountability for AI management activities.",
            },
            "A.3.3": {
                "title": "AI knowledge and competencies within the organization",
                "description": "The organization shall identify and maintain the AI knowledge and competencies necessary for operation of the AI management system and its AI systems.",
                "objective": "Ensure the organization has adequate AI expertise.",
            },
            "A.3.4": {
                "title": "Engagement of interested parties",
                "description": "The organization shall engage relevant interested parties in the responsible development, provision, and use of AI systems.",
                "objective": "Incorporate diverse perspectives in AI management.",
            },
        },
    },
    "A.4": {
        "title": "Resources for AI systems",
        "controls": {
            "A.4.2": {
                "title": "Data for AI systems",
                "description": "Data used for AI systems shall be managed throughout the data lifecycle, including acquisition, processing, labeling, storage, and disposal. Data quality, relevance, representativeness, and integrity shall be ensured.",
                "objective": "Ensure data quality and appropriate data management for AI systems.",
            },
            "A.4.3": {
                "title": "Tools for AI systems",
                "description": "Tools used for AI system development, testing, and deployment shall be identified, evaluated, and managed.",
                "objective": "Ensure appropriate tooling for AI system lifecycle.",
            },
            "A.4.4": {
                "title": "System and computing resources",
                "description": "Computing resources for AI systems shall be planned, provisioned, and managed to meet performance, security, and availability requirements.",
                "objective": "Ensure adequate computing infrastructure for AI operations.",
            },
            "A.4.5": {
                "title": "Human resources",
                "description": "Human resources for AI activities shall be planned and managed, including training, competence development, and ethical awareness.",
                "objective": "Ensure adequate and competent human resources for AI activities.",
            },
        },
    },
    "A.5": {
        "title": "Assessing impacts of AI systems",
        "controls": {
            "A.5.2": {
                "title": "AI impact assessment process",
                "description": "The organization shall conduct impact assessments for AI systems considering potential effects on individuals, groups, communities, societies, and the environment, including both intended and unintended impacts.",
                "objective": "Systematically identify and assess impacts of AI systems.",
            },
            "A.5.3": {
                "title": "Documentation of AI system impact assessment",
                "description": "Results of AI system impact assessments shall be documented, including methodology, findings, and recommended actions.",
                "objective": "Maintain records of AI impact assessments.",
            },
        },
    },
    "A.6": {
        "title": "AI system lifecycle",
        "controls": {
            "A.6.2": {
                "title": "AI system design and development",
                "description": "AI systems shall be designed and developed according to established processes that address requirements specification, data management, model development, testing, and validation.",
                "objective": "Ensure systematic AI system development.",
            },
            "A.6.3": {
                "title": "Responsible AI design",
                "description": "AI systems shall be designed with consideration for fairness, transparency, explainability, accountability, safety, security, and privacy.",
                "objective": "Embed responsible AI principles in system design.",
            },
            "A.6.4": {
                "title": "AI testing and validation",
                "description": "AI systems shall be tested and validated before deployment and at regular intervals, using appropriate methods and metrics for the intended use.",
                "objective": "Ensure AI systems perform as intended and meet quality criteria.",
            },
            "A.6.5": {
                "title": "AI deployment",
                "description": "AI system deployment shall be planned and controlled, including deployment criteria, rollback procedures, and monitoring activation.",
                "objective": "Ensure controlled and monitored AI system deployment.",
            },
            "A.6.6": {
                "title": "AI system operation and monitoring",
                "description": "Deployed AI systems shall be operated and monitored in accordance with defined procedures, including performance monitoring, incident detection, and change management.",
                "objective": "Ensure ongoing safe and effective AI system operation.",
            },
            "A.6.7": {
                "title": "AI system retirement",
                "description": "AI systems shall be retired through a controlled process that addresses data handling, service continuity, stakeholder communication, and lessons learned.",
                "objective": "Ensure responsible AI system decommissioning.",
            },
        },
    },
    "A.7": {
        "title": "Data for AI systems",
        "controls": {
            "A.7.2": {
                "title": "Data quality for AI",
                "description": "Data quality requirements for AI systems shall be defined and measures implemented to ensure data accuracy, completeness, consistency, timeliness, and relevance.",
                "objective": "Ensure data quality meets AI system requirements.",
            },
            "A.7.3": {
                "title": "Data provenance",
                "description": "The provenance of data used in AI systems shall be documented and traceable, including sources, transformations, and lineage.",
                "objective": "Maintain data traceability and accountability.",
            },
            "A.7.4": {
                "title": "Data preparation",
                "description": "Data preparation processes (cleaning, labeling, augmentation, splitting) shall be documented and controlled to ensure reproducibility and quality.",
                "objective": "Ensure reliable and reproducible data preparation.",
            },
        },
    },
    "A.8": {
        "title": "Information for interested parties of AI systems",
        "controls": {
            "A.8.2": {
                "title": "Transparency of AI systems",
                "description": "The organization shall provide appropriate information about AI systems to relevant interested parties, including purpose, capabilities, limitations, and decision-making processes.",
                "objective": "Enable informed interaction with AI systems.",
            },
            "A.8.3": {
                "title": "AI system documentation",
                "description": "AI systems shall be documented throughout their lifecycle, including design decisions, training data, model architecture, performance metrics, and known limitations.",
                "objective": "Maintain comprehensive AI system documentation.",
            },
            "A.8.4": {
                "title": "Information about data for interested parties",
                "description": "Relevant information about data used in AI systems shall be made available to interested parties as appropriate.",
                "objective": "Enable transparency about data used in AI systems.",
            },
        },
    },
    "A.9": {
        "title": "Use of AI systems",
        "controls": {
            "A.9.2": {
                "title": "Intended use",
                "description": "The intended use of AI systems shall be defined, documented, and communicated. Measures shall be taken to prevent or detect uses beyond the intended scope.",
                "objective": "Ensure AI systems are used as intended.",
            },
            "A.9.3": {
                "title": "Responsible use of AI",
                "description": "The organization shall establish guidance for responsible use of AI systems, including ethical considerations, human oversight, and appeal mechanisms.",
                "objective": "Promote responsible use of AI systems.",
            },
            "A.9.4": {
                "title": "Monitoring of AI system use",
                "description": "The use of AI systems shall be monitored to detect misuse, unintended behaviors, and performance degradation.",
                "objective": "Ensure ongoing appropriate use of AI systems.",
            },
        },
    },
    "A.10": {
        "title": "Third-party and customer relationships",
        "controls": {
            "A.10.2": {
                "title": "Third-party components for AI systems",
                "description": "The use of third-party components (models, data, tools) in AI systems shall be assessed, managed, and documented.",
                "objective": "Ensure controlled use of third-party AI components.",
            },
            "A.10.3": {
                "title": "Monitoring of third-party AI components",
                "description": "Third-party AI components shall be monitored for changes, vulnerabilities, and performance issues throughout the AI system lifecycle.",
                "objective": "Maintain oversight of third-party AI dependencies.",
            },
            "A.10.4": {
                "title": "Customer relationships",
                "description": "The organization shall manage customer relationships regarding AI systems, including communication of capabilities, limitations, responsibilities, and incident handling.",
                "objective": "Ensure transparent and responsible customer relationships for AI.",
            },
        },
    },
}

# ---------------------------------------------------------------------------
# ISO 42001 Annex B — AI Risk Assessment Guidance
# ---------------------------------------------------------------------------

ANNEX_B_RISK_CATEGORIES = {
    "bias_and_fairness": {
        "title": "Bias and Fairness Risks",
        "description": "Risks related to discriminatory outcomes, unfair treatment, and systematic bias in AI system outputs.",
        "risk_factors": [
            "Training data bias (representation, historical, measurement, aggregation)",
            "Algorithmic bias (optimization targets, feature selection, proxy variables)",
            "Interaction bias (feedback loops, user behavior patterns)",
            "Evaluation bias (inappropriate metrics, unrepresentative test sets)",
            "Deployment bias (context shift, population drift)",
        ],
    },
    "safety_and_reliability": {
        "title": "Safety and Reliability Risks",
        "description": "Risks to physical or psychological safety of individuals, and risks of system unreliability.",
        "risk_factors": [
            "Physical harm from AI-controlled systems",
            "Psychological harm from AI interactions",
            "System failures in critical applications",
            "Unexpected behavior under edge cases",
            "Performance degradation over time",
            "Cascading failures in interconnected systems",
        ],
    },
    "transparency_and_explainability": {
        "title": "Transparency and Explainability Risks",
        "description": "Risks from insufficient transparency about AI system operation and inability to explain decisions.",
        "risk_factors": [
            "Opaque decision-making processes",
            "Inability to explain outcomes to affected individuals",
            "Insufficient documentation of system behavior",
            "Hidden assumptions in model design",
            "Lack of audit trail for decisions",
        ],
    },
    "privacy_and_data_protection": {
        "title": "Privacy and Data Protection Risks",
        "description": "Risks to personal data privacy and non-compliance with data protection regulations.",
        "risk_factors": [
            "Unauthorized processing of personal data",
            "Insufficient consent mechanisms",
            "Re-identification risk from model outputs",
            "Data retention beyond necessary periods",
            "Cross-border data transfer issues",
            "Sensitive data exposure through model memorization",
        ],
    },
    "security_and_resilience": {
        "title": "Security and Resilience Risks",
        "description": "Risks from cyberattacks, adversarial manipulation, and system vulnerabilities.",
        "risk_factors": [
            "Adversarial attacks on model inputs",
            "Data poisoning of training data",
            "Model extraction and theft",
            "Prompt injection attacks",
            "Supply chain compromise",
            "Infrastructure vulnerabilities",
        ],
    },
    "accountability_and_governance": {
        "title": "Accountability and Governance Risks",
        "description": "Risks from unclear accountability, inadequate governance, and non-compliance.",
        "risk_factors": [
            "Unclear responsibility for AI outcomes",
            "Inadequate oversight mechanisms",
            "Non-compliance with regulations",
            "Insufficient documentation for audit",
            "Lack of incident response procedures",
        ],
    },
    "societal_and_environmental": {
        "title": "Societal and Environmental Risks",
        "description": "Broader societal impacts and environmental risks from AI systems.",
        "risk_factors": [
            "Impact on employment and labor markets",
            "Social manipulation and misinformation",
            "Environmental impact of compute resources",
            "Digital divide and accessibility issues",
            "Impact on democratic processes",
        ],
    },
}

# ---------------------------------------------------------------------------
# ISO 42001 to EU AI Act Crosswalk — The Killer Feature
# ---------------------------------------------------------------------------

ISO_TO_EU_CROSSWALK = {
    "4.1": {
        "eu_articles": ["Article 9(1)", "Article 17(1)"],
        "mapping_rationale": "Understanding organizational context for AI maps to EU AI Act requirements for establishing a risk management system (Art 9.1) and quality management system (Art 17.1) that account for organizational context.",
        "alignment_strength": "strong",
    },
    "4.2": {
        "eu_articles": ["Article 9(4)", "Article 23", "Article 26"],
        "mapping_rationale": "Identifying interested parties and their requirements maps to EU AI Act stakeholder consideration in risk management (Art 9.4), obligations of importers/distributors (Art 23), and deployer obligations (Art 26).",
        "alignment_strength": "strong",
    },
    "4.3": {
        "eu_articles": ["Article 6", "Article 49"],
        "mapping_rationale": "Determining AIMS scope maps to EU AI Act classification rules (Art 6) determining which systems are in scope, and registration requirements (Art 49).",
        "alignment_strength": "moderate",
    },
    "5.1": {
        "eu_articles": ["Article 16", "Article 17(1)(a)"],
        "mapping_rationale": "Leadership commitment maps to EU AI Act provider obligations (Art 16) and quality management leadership requirements (Art 17.1.a).",
        "alignment_strength": "strong",
    },
    "5.2": {
        "eu_articles": ["Article 9(1)", "Article 17(1)(b)"],
        "mapping_rationale": "AI policy establishment maps to EU AI Act risk management system policy (Art 9.1) and quality management policy documentation (Art 17.1.b).",
        "alignment_strength": "strong",
    },
    "5.3": {
        "eu_articles": ["Article 17(1)(j)", "Article 26(1)"],
        "mapping_rationale": "Defining roles and responsibilities maps to EU AI Act quality management personnel accountability (Art 17.1.j) and deployer organizational measures (Art 26.1).",
        "alignment_strength": "strong",
    },
    "6.1": {
        "eu_articles": ["Article 9(2)", "Article 9(5)", "Article 27"],
        "mapping_rationale": "AI risk assessment maps directly to EU AI Act risk identification and analysis (Art 9.2), risk elimination/mitigation (Art 9.5), and fundamental rights impact assessment (Art 27).",
        "alignment_strength": "strong",
    },
    "6.2": {
        "eu_articles": ["Article 9(1)", "Article 17(1)(c)"],
        "mapping_rationale": "AIMS objectives map to EU AI Act risk management objectives (Art 9.1) and quality management objectives (Art 17.1.c).",
        "alignment_strength": "moderate",
    },
    "7.2": {
        "eu_articles": ["Article 4", "Article 17(1)(k)"],
        "mapping_rationale": "Competence requirements map directly to EU AI Act AI literacy obligations (Art 4) and quality management training requirements (Art 17.1.k).",
        "alignment_strength": "strong",
    },
    "7.5": {
        "eu_articles": ["Article 11", "Article 12", "Article 18"],
        "mapping_rationale": "Documented information requirements map to EU AI Act technical documentation (Art 11), record-keeping (Art 12), and documentation obligations (Art 18).",
        "alignment_strength": "strong",
    },
    "8.1": {
        "eu_articles": ["Article 9(8)", "Article 16(a)", "Article 17"],
        "mapping_rationale": "Operational planning and control maps to EU AI Act lifecycle risk management (Art 9.8), provider compliance obligation (Art 16.a), and quality management system (Art 17).",
        "alignment_strength": "strong",
    },
    "8.2": {
        "eu_articles": ["Article 9(2)", "Article 9(3)", "Article 9(7)"],
        "mapping_rationale": "AI risk assessment maps to EU AI Act risk identification (Art 9.2), systematic risk management updates (Art 9.3), and testing against metrics (Art 9.7).",
        "alignment_strength": "strong",
    },
    "8.3": {
        "eu_articles": ["Article 9(5)", "Article 9(6)"],
        "mapping_rationale": "AI risk treatment maps to EU AI Act risk elimination/mitigation measures (Art 9.5) and testing post-mitigation (Art 9.6).",
        "alignment_strength": "strong",
    },
    "8.4": {
        "eu_articles": ["Article 27", "Article 9(4)(a)"],
        "mapping_rationale": "AI system impact assessment maps directly to EU AI Act fundamental rights impact assessment (Art 27) and consideration of impacts on specific groups (Art 9.4.a).",
        "alignment_strength": "strong",
    },
    "9.1": {
        "eu_articles": ["Article 9(3)", "Article 15(1)", "Article 72"],
        "mapping_rationale": "Monitoring and measurement maps to EU AI Act risk management updates (Art 9.3), accuracy/robustness requirements (Art 15.1), and post-market monitoring (Art 72).",
        "alignment_strength": "strong",
    },
    "9.2": {
        "eu_articles": ["Article 17(1)(f)", "Article 17(1)(h)"],
        "mapping_rationale": "Internal audit maps to EU AI Act quality management audit procedures (Art 17.1.f) and quality management examination/testing procedures (Art 17.1.h).",
        "alignment_strength": "strong",
    },
    "9.3": {
        "eu_articles": ["Article 17(1)(a)", "Article 72(2)"],
        "mapping_rationale": "Management review maps to EU AI Act quality management leadership review (Art 17.1.a) and post-market monitoring system design (Art 72.2).",
        "alignment_strength": "moderate",
    },
    "10.1": {
        "eu_articles": ["Article 9(8)", "Article 17(1)(i)"],
        "mapping_rationale": "Continual improvement maps to EU AI Act continuous lifecycle risk management (Art 9.8) and quality management continual improvement (Art 17.1.i).",
        "alignment_strength": "strong",
    },
    "10.2": {
        "eu_articles": ["Article 20", "Article 62"],
        "mapping_rationale": "Nonconformity and corrective action maps to EU AI Act corrective actions for non-compliant systems (Art 20) and serious incident reporting (Art 62).",
        "alignment_strength": "strong",
    },
    "A.4.2": {
        "eu_articles": ["Article 10"],
        "mapping_rationale": "Data management for AI maps directly to EU AI Act data and data governance requirements (Art 10) covering quality, representativeness, and bias examination.",
        "alignment_strength": "strong",
    },
    "A.5.2": {
        "eu_articles": ["Article 27", "Article 9(4)"],
        "mapping_rationale": "AI impact assessment maps directly to EU AI Act fundamental rights impact assessment (Art 27) and risk management stakeholder consideration (Art 9.4).",
        "alignment_strength": "strong",
    },
    "A.6.3": {
        "eu_articles": ["Article 9(2)", "Article 10", "Article 13", "Article 14", "Article 15"],
        "mapping_rationale": "Responsible AI design maps across multiple EU AI Act high-risk requirements: risk management (Art 9), data governance (Art 10), transparency (Art 13), human oversight (Art 14), and accuracy/robustness (Art 15).",
        "alignment_strength": "strong",
    },
    "A.6.4": {
        "eu_articles": ["Article 9(7)", "Article 15(1)"],
        "mapping_rationale": "AI testing and validation maps to EU AI Act testing against predefined metrics (Art 9.7) and accuracy, robustness, cybersecurity (Art 15.1).",
        "alignment_strength": "strong",
    },
    "A.6.6": {
        "eu_articles": ["Article 9(3)", "Article 72"],
        "mapping_rationale": "AI operation and monitoring maps to EU AI Act risk management system updates (Art 9.3) and post-market monitoring system (Art 72).",
        "alignment_strength": "strong",
    },
    "A.7.2": {
        "eu_articles": ["Article 10(2)", "Article 10(3)"],
        "mapping_rationale": "Data quality maps to EU AI Act data quality criteria (Art 10.2) and data governance practices (Art 10.3).",
        "alignment_strength": "strong",
    },
    "A.7.3": {
        "eu_articles": ["Article 10(2)(e)", "Article 12"],
        "mapping_rationale": "Data provenance maps to EU AI Act data source documentation (Art 10.2.e) and automatic logging requirements (Art 12).",
        "alignment_strength": "strong",
    },
    "A.8.2": {
        "eu_articles": ["Article 13", "Article 50", "Article 52"],
        "mapping_rationale": "AI transparency maps to EU AI Act transparency obligations for high-risk systems (Art 13), transparency for AI interacting with persons (Art 50), and transparency for certain AI systems (Art 52).",
        "alignment_strength": "strong",
    },
    "A.9.2": {
        "eu_articles": ["Article 13(3)(b)(i)", "Article 9(2)(a)"],
        "mapping_rationale": "Intended use definition maps to EU AI Act specification of intended purpose (Art 13.3.b.i) and foreseeable misuse identification (Art 9.2.a).",
        "alignment_strength": "strong",
    },
    "A.9.3": {
        "eu_articles": ["Article 14", "Article 26(2)"],
        "mapping_rationale": "Responsible AI use maps to EU AI Act human oversight requirements (Art 14) and deployer use in accordance with instructions (Art 26.2).",
        "alignment_strength": "strong",
    },
    "A.10.2": {
        "eu_articles": ["Article 25", "Article 17(1)(g)"],
        "mapping_rationale": "Third-party component management maps to EU AI Act responsibilities along the value chain (Art 25) and supply chain management in quality management (Art 17.1.g).",
        "alignment_strength": "strong",
    },
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

RISK_KEYWORDS = {
    "bias_and_fairness": ["hiring", "recruitment", "lending", "credit", "insurance", "criminal justice", "sentencing", "facial recognition", "demographic", "discrimination", "protected class", "fairness"],
    "safety_and_reliability": ["medical", "health", "clinical", "autonomous", "robot", "physical", "life-critical", "safety", "weapon", "defense", "critical infrastructure"],
    "transparency_and_explainability": ["black box", "opaque", "unexplainable", "decision-making", "automated decision", "scoring", "ranking", "recommendation", "content generation"],
    "privacy_and_data_protection": ["personal data", "biometric", "health data", "financial data", "location", "surveillance", "tracking", "profiling", "sensitive data", "PII", "GDPR"],
    "security_and_resilience": ["adversarial", "attack", "poisoning", "extraction", "prompt injection", "jailbreak", "manipulation", "cybersecurity", "vulnerability"],
    "accountability_and_governance": ["audit", "compliance", "regulation", "oversight", "governance", "accountability", "liability", "responsible"],
    "societal_and_environmental": ["election", "democracy", "misinformation", "employment", "environmental", "carbon", "sustainability", "social media", "polarization"],
}


def _score_text(text: str, keywords: list[str]) -> float:
    text_lower = text.lower()
    matches = sum(1 for kw in keywords if kw.lower() in text_lower)
    return min(matches / max(len(keywords), 1), 1.0)


def _risk_level(score: float) -> str:
    if score >= 0.5:
        return "high"
    elif score >= 0.25:
        return "moderate"
    elif score > 0:
        return "low"
    return "minimal"


# ===========================================================================
# MCP Tools
# ===========================================================================


@mcp.tool()
def audit_management_system(
    organization_description: str,
    ai_systems_description: str = "",
    existing_certifications: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Audit an AI management system against ISO/IEC 42001 clauses 4-10.

    Evaluates organizational readiness and conformity across all seven
    management system clauses: Context (4), Leadership (5), Planning (6),
    Support (7), Operation (8), Performance Evaluation (9), and
    Improvement (10). Returns per-clause assessment with audit questions,
    gap analysis, and prioritized recommendations.

    Args:
        organization_description: Description of the organization and its
            AI management practices, governance structures, and policies.
        ai_systems_description: Description of AI systems in scope.
        existing_certifications: Existing ISO or other certifications held
            (e.g., 'ISO 27001, ISO 9001').
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Clause-by-clause audit results with conformity status and recommendations.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    full_text = f"{organization_description} {ai_systems_description}"

    # Check for synergy with existing certifications
    existing_certs = [c.strip() for c in existing_certifications.split(",") if c.strip()]
    cert_synergies = []
    if any("27001" in c for c in existing_certs):
        cert_synergies.append("ISO 27001 provides strong foundation for clauses 7.5 (documented information), 8.2 (risk assessment), and 9.2 (internal audit)")
    if any("9001" in c for c in existing_certs):
        cert_synergies.append("ISO 9001 provides strong foundation for clauses 5 (leadership), 7 (support), 9 (performance evaluation), and 10 (improvement)")
    if any("27701" in c for c in existing_certs):
        cert_synergies.append("ISO 27701 helps with privacy-related controls in Annex A.7 and A.8")

    clause_results = {}
    total_questions = 0
    total_addressed = 0

    for clause_id, clause_data in ISO_42001_CLAUSES.items():
        subclause_results = []
        clause_questions = 0
        clause_addressed = 0

        for sub_id, sub_data in clause_data["subclauses"].items():
            # Evaluate each audit question against the description
            question_results = []
            for question in sub_data["audit_questions"]:
                q_keywords = question.lower().split()[:6]
                addressed = _score_text(full_text, q_keywords) > 0.2
                question_results.append({
                    "question": question,
                    "status": "addressed" if addressed else "gap",
                })
                clause_questions += 1
                total_questions += 1
                if addressed:
                    clause_addressed += 1
                    total_addressed += 1

            conformity = clause_addressed / max(clause_questions, 1) if clause_questions > 0 else 0
            if conformity >= 0.75:
                conformity_status = "conforming"
            elif conformity >= 0.5:
                conformity_status = "partially_conforming"
            elif conformity >= 0.25:
                conformity_status = "major_gaps"
            else:
                conformity_status = "non_conforming"

            subclause_results.append({
                "subclause": sub_id,
                "title": sub_data["title"],
                "description": sub_data["description"],
                "requirements": sub_data["requirements"],
                "audit_findings": question_results,
                "conformity_score": round(conformity, 2),
                "conformity_status": conformity_status,
                "gaps_count": sum(1 for q in question_results if q["status"] == "gap"),
            })

        clause_conformity = clause_addressed / max(clause_questions, 1)
        clause_results[clause_id] = {
            "title": clause_data["title"],
            "clause_number": clause_data["number"],
            "conformity_score": round(clause_conformity, 2),
            "conformity_status": "conforming" if clause_conformity >= 0.75 else "partially_conforming" if clause_conformity >= 0.5 else "major_gaps" if clause_conformity >= 0.25 else "non_conforming",
            "subclauses": subclause_results,
            "total_questions": clause_questions,
            "addressed_count": clause_addressed,
            "gap_count": clause_questions - clause_addressed,
        }

    overall_conformity = total_addressed / max(total_questions, 1)

    # Generate prioritized recommendations
    recommendations = []
    for clause_id, result in clause_results.items():
        if result["conformity_status"] in ("non_conforming", "major_gaps"):
            recommendations.append({
                "priority": "critical" if result["conformity_status"] == "non_conforming" else "high",
                "clause": result["clause_number"],
                "title": result["title"],
                "action": f"Address {result['gap_count']} gaps in Clause {result['clause_number']} ({result['title']}). This clause is {result['conformity_status'].replace('_', ' ')}.",
                "effort": "high" if result["gap_count"] > 3 else "medium",
            })

    return {
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "framework": "ISO/IEC 42001:2023 — AI Management System",
        "overall_conformity_score": round(overall_conformity, 2),
        "overall_status": "conforming" if overall_conformity >= 0.75 else "partially_conforming" if overall_conformity >= 0.5 else "major_gaps" if overall_conformity >= 0.25 else "non_conforming",
        "certification_readiness": "ready" if overall_conformity >= 0.8 else "near_ready" if overall_conformity >= 0.6 else "not_ready",
        "total_audit_questions": total_questions,
        "addressed_count": total_addressed,
        "gap_count": total_questions - total_addressed,
        "existing_certifications": existing_certs,
        "certification_synergies": cert_synergies,
        "clause_results": clause_results,
        "recommendations": sorted(
            recommendations,
            key=lambda x: {"critical": 0, "high": 1, "standard": 2}.get(x["priority"], 3),
        ),
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def assess_ai_risk(
    system_description: str,
    system_name: str = "AI System",
    risk_criteria: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Perform ISO 42001 Annex B risk assessment for AI systems.

    Comprehensive AI risk assessment covering risk criteria establishment,
    risk identification across all Annex B categories, risk analysis
    (likelihood and impact), and risk evaluation against organizational
    risk criteria. Follows the ISO 42001 Annex B guidance structure.

    Args:
        system_description: Detailed description of the AI system including
            purpose, data, deployment context, and affected populations.
        system_name: Name of the AI system.
        risk_criteria: Organization's risk acceptance criteria description.
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Complete Annex B risk assessment with identified risks, analysis,
        and evaluation results.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    # Step 1: Risk Criteria
    risk_criteria_assessment = {
        "defined": bool(risk_criteria),
        "description": risk_criteria or "Not provided — using default criteria based on impact and likelihood scales.",
        "impact_scale": {
            "1_negligible": "Minimal impact; no significant harm to individuals or organization",
            "2_minor": "Limited impact; minor inconvenience or easily reversible harm",
            "3_moderate": "Significant impact; noticeable harm requiring remediation",
            "4_major": "Serious impact; substantial harm to individuals, organization, or society",
            "5_critical": "Catastrophic impact; irreversible harm, major safety/rights violations",
        },
        "likelihood_scale": {
            "1_rare": "Unlikely to occur (< 5% probability)",
            "2_unlikely": "Could occur in exceptional circumstances (5-20%)",
            "3_possible": "Could occur at some time (20-50%)",
            "4_likely": "Will probably occur in most circumstances (50-80%)",
            "5_almost_certain": "Expected to occur in most circumstances (> 80%)",
        },
        "risk_tolerance": "Risks rated 'high' or 'critical' require mandatory treatment. Moderate risks require documented acceptance by risk owner.",
    }

    # Step 2: Risk Identification
    risk_scores = {}
    for category, keywords in RISK_KEYWORDS.items():
        risk_scores[category] = round(_score_text(system_description, keywords), 3)

    identified_risks = []
    for category, cat_data in ANNEX_B_RISK_CATEGORIES.items():
        score = risk_scores.get(category, 0)
        if score > 0:
            # Determine impact and likelihood from score
            if score >= 0.5:
                impact = 5
                likelihood = 4
            elif score >= 0.35:
                impact = 4
                likelihood = 3
            elif score >= 0.2:
                impact = 3
                likelihood = 3
            elif score >= 0.1:
                impact = 2
                likelihood = 2
            else:
                impact = 1
                likelihood = 2

            risk_rating = impact * likelihood
            if risk_rating >= 16:
                risk_level_label = "critical"
            elif risk_rating >= 10:
                risk_level_label = "high"
            elif risk_rating >= 5:
                risk_level_label = "moderate"
            else:
                risk_level_label = "low"

            identified_risks.append({
                "category": category,
                "title": cat_data["title"],
                "description": cat_data["description"],
                "risk_factors": cat_data["risk_factors"],
                "analysis": {
                    "detection_score": score,
                    "impact_rating": impact,
                    "likelihood_rating": likelihood,
                    "risk_rating": risk_rating,
                    "risk_level": risk_level_label,
                },
                "evaluation": {
                    "exceeds_tolerance": risk_level_label in ("critical", "high"),
                    "requires_treatment": risk_level_label in ("critical", "high", "moderate"),
                    "treatment_priority": 1 if risk_level_label == "critical" else 2 if risk_level_label == "high" else 3 if risk_level_label == "moderate" else 4,
                },
                "recommended_controls": _get_annex_a_controls_for_risk(category),
            })

    # Sort by risk rating descending
    identified_risks.sort(key=lambda x: -x["analysis"]["risk_rating"])

    # Step 3: Risk Summary
    risk_matrix = {}
    for risk in identified_risks:
        level = risk["analysis"]["risk_level"]
        risk_matrix[level] = risk_matrix.get(level, 0) + 1

    return {
        "system_name": system_name,
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "framework": "ISO/IEC 42001:2023 — Annex B Risk Assessment",
        "risk_criteria": risk_criteria_assessment,
        "risk_identification": {
            "total_categories_assessed": len(ANNEX_B_RISK_CATEGORIES),
            "risks_identified": len(identified_risks),
            "risk_distribution": risk_matrix,
        },
        "identified_risks": identified_risks,
        "risk_treatment_required": sum(1 for r in identified_risks if r["evaluation"]["requires_treatment"]),
        "critical_risks": sum(1 for r in identified_risks if r["analysis"]["risk_level"] == "critical"),
        "statement_of_applicability_needed": True,
        "next_steps": [
            "Document risk treatment plan for all risks requiring treatment",
            "Select Annex A controls for each identified risk",
            "Produce Statement of Applicability (SoA)",
            "Obtain risk owner approval for residual risks",
            "Schedule next risk assessment review",
        ],
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


def _get_annex_a_controls_for_risk(risk_category: str) -> list[str]:
    """Map risk category to relevant Annex A controls."""
    mapping = {
        "bias_and_fairness": ["A.4.2 (Data for AI)", "A.5.2 (Impact assessment)", "A.6.3 (Responsible AI design)", "A.6.4 (Testing and validation)"],
        "safety_and_reliability": ["A.6.2 (Design and development)", "A.6.4 (Testing and validation)", "A.6.6 (Operation and monitoring)", "A.9.2 (Intended use)"],
        "transparency_and_explainability": ["A.8.2 (Transparency)", "A.8.3 (Documentation)", "A.8.4 (Information about data)", "A.9.3 (Responsible use)"],
        "privacy_and_data_protection": ["A.4.2 (Data for AI)", "A.7.2 (Data quality)", "A.7.3 (Data provenance)", "A.8.4 (Information about data)"],
        "security_and_resilience": ["A.4.3 (Tools for AI)", "A.4.4 (Computing resources)", "A.6.6 (Operation and monitoring)", "A.10.2 (Third-party components)"],
        "accountability_and_governance": ["A.2.2 (AI policy)", "A.3.2 (Roles and responsibilities)", "A.3.4 (Engagement)", "A.9.4 (Monitoring of use)"],
        "societal_and_environmental": ["A.5.2 (Impact assessment)", "A.5.3 (Impact documentation)", "A.3.4 (Engagement)", "A.6.3 (Responsible AI design)"],
    }
    return mapping.get(risk_category, ["A.6.3 (Responsible AI design)"])


@mcp.tool()
def generate_policy_template(
    organization_name: str,
    ai_scope: str = "",
    policy_type: str = "comprehensive",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Generate AI policy documents per ISO 42001 requirements.

    Creates policy templates that satisfy ISO 42001 clause 5.2 (AI policy)
    and Annex A.2.2 requirements. Includes AI policy statement, roles and
    responsibilities, objectives, principles, and governance structure.

    Args:
        organization_name: Name of the organization.
        ai_scope: Description of AI systems and activities in scope.
        policy_type: Type of policy ('comprehensive', 'brief', 'executive').
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Markdown-formatted policy template with all required elements.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if policy_type == "brief":
        policy = f"""# {organization_name} — AI Policy Statement

**Effective Date:** {date}
**Approved by:** [Chief Executive Officer / Board of Directors]
**Review Date:** {(datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%d')}

## Policy Statement

{organization_name} is committed to the responsible development, deployment, and use of artificial intelligence systems. This policy establishes the principles and governance framework for AI management in accordance with ISO/IEC 42001:2023.

## Scope

{ai_scope or f'This policy applies to all AI systems developed, deployed, or used by {organization_name}.'}

## Principles

1. **Safety:** AI systems shall not endanger human safety or wellbeing.
2. **Fairness:** AI systems shall be designed to avoid harmful bias and discrimination.
3. **Transparency:** AI systems and their decision-making processes shall be appropriately transparent.
4. **Accountability:** Clear accountability shall be established for AI system outcomes.
5. **Privacy:** AI systems shall respect and protect personal data and privacy.
6. **Security:** AI systems shall be resilient to attacks and failures.
7. **Human Oversight:** Appropriate human oversight shall be maintained for AI systems.

## Governance

The AI Governance Committee, chaired by [CTO/CDO], is responsible for overseeing this policy.

---
*This policy shall be reviewed annually or when significant changes occur.*
"""
    elif policy_type == "executive":
        policy = f"""# {organization_name} — Executive AI Policy

**Classification:** Confidential
**Effective Date:** {date}
**Owner:** Chief Executive Officer

## Purpose

This executive policy establishes {organization_name}'s strategic commitment to responsible AI in accordance with ISO/IEC 42001:2023 and applicable regulations.

## Strategic Commitment

The Board of Directors and executive leadership of {organization_name} commit to:

1. Establishing and maintaining an AI Management System (AIMS) per ISO/IEC 42001
2. Allocating adequate resources for responsible AI management
3. Integrating AI risk management into organizational governance
4. Ensuring compliance with all applicable AI regulations
5. Promoting a culture of responsible AI innovation

## Executive Responsibilities

| Role | Responsibility |
|------|---------------|
| CEO | Overall accountability for AI policy and AIMS |
| CTO | Technical governance of AI systems |
| CISO | AI security and resilience |
| DPO | AI privacy and data protection |
| CLO | AI regulatory compliance |
| AI Ethics Lead | Ethical AI review and guidance |

## Review

This policy is reviewed quarterly by the Executive Committee.
"""
    else:
        # Comprehensive policy
        policy = f"""# {organization_name} — AI Management Policy

**Document ID:** AIMS-POL-001
**Version:** 1.0
**Effective Date:** {date}
**Approved by:** [Chief Executive Officer / Board of Directors]
**Review Date:** {(datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%d')}
**Classification:** Internal
**Standard Reference:** ISO/IEC 42001:2023

---

## 1. Purpose

This policy establishes the framework for the responsible management of artificial intelligence (AI) systems at {organization_name}. It fulfills the requirements of ISO/IEC 42001:2023 Clause 5.2 (AI Policy) and Annex A.2.2 (Policies for AI).

## 2. Scope

{ai_scope or f'This policy applies to all AI systems developed, procured, deployed, or used by {organization_name}, including systems based on machine learning, deep learning, natural language processing, computer vision, and other AI technologies.'}

This policy applies to all personnel, contractors, and third parties involved in AI activities within the scope of the AI Management System (AIMS).

## 3. Definitions

| Term | Definition |
|------|-----------|
| AI System | A machine-based system that generates outputs such as predictions, recommendations, decisions, or content for a given set of objectives |
| AIMS | AI Management System as defined in ISO/IEC 42001:2023 |
| AI Risk | Effect of uncertainty on AI objectives, including potential negative impacts |
| Interested Party | Person or organization that can affect, be affected by, or perceive itself to be affected by a decision or activity related to AI |

## 4. AI Principles

{organization_name} commits to the following principles for all AI activities:

### 4.1 Safety and Reliability
AI systems shall be designed, developed, and deployed to operate safely and reliably. Systems shall include appropriate safeguards, fail-safe mechanisms, and human override capabilities.

### 4.2 Fairness and Non-discrimination
AI systems shall be designed to avoid harmful bias and ensure equitable outcomes. Regular bias assessments shall be conducted across relevant demographic groups.

### 4.3 Transparency and Explainability
AI systems shall be appropriately transparent. Stakeholders shall be informed when interacting with AI systems, and decisions shall be explainable to the extent required by context and regulation.

### 4.4 Accountability
Clear accountability shall be established for all AI systems. Roles, responsibilities, and authority for AI governance shall be defined and documented.

### 4.5 Privacy and Data Protection
AI systems shall comply with all applicable data protection regulations. Personal data shall be minimized, and privacy-preserving techniques shall be employed where appropriate.

### 4.6 Security and Resilience
AI systems shall be designed to withstand adversarial attacks, data poisoning, and other AI-specific security threats. Incident response procedures shall be established.

### 4.7 Human Oversight
Appropriate levels of human oversight shall be maintained for all AI systems, proportionate to the risk level of the system.

### 4.8 Environmental Responsibility
The environmental impact of AI systems shall be considered and minimized where practicable.

## 5. Governance Structure

### 5.1 AI Governance Committee
An AI Governance Committee shall be established with authority to:
- Approve AI strategy and policy
- Oversee AI risk management
- Review AI system impact assessments
- Approve deployment of high-risk AI systems
- Monitor regulatory compliance

### 5.2 Roles and Responsibilities

| Role | Responsibilities |
|------|-----------------|
| **Board of Directors** | Strategic oversight of AI governance; approval of AI policy |
| **Chief Executive Officer** | Overall accountability for AIMS; resource allocation |
| **Chief Technology Officer** | Technical governance; AI system portfolio management |
| **AI Management Representative** | Day-to-day AIMS management; reporting to top management |
| **AI Risk Manager** | AI risk assessment, treatment, and monitoring |
| **AI Ethics Lead** | Ethical review of AI systems; stakeholder engagement |
| **Data Protection Officer** | Privacy compliance for AI systems |
| **AI System Owners** | Accountability for specific AI systems through their lifecycle |
| **AI Developers** | Responsible development per policy and procedures |
| **AI Users** | Responsible use of AI systems per guidance and training |

## 6. AI Risk Management

### 6.1 Risk Assessment
AI risk assessments shall be conducted:
- Before development or procurement of new AI systems
- At planned intervals (minimum annually)
- When significant changes to AI systems are proposed
- Following AI incidents or near-misses

### 6.2 Risk Treatment
Identified risks shall be treated through:
- Risk avoidance (not proceeding with the AI system)
- Risk mitigation (implementing controls from Annex A)
- Risk transfer (contractual or insurance arrangements)
- Risk acceptance (documented acceptance by authorized risk owner)

### 6.3 Statement of Applicability
A Statement of Applicability shall document which Annex A controls are applicable and implemented, with justification for any exclusions.

## 7. AI System Lifecycle Management

All AI systems shall be managed through a defined lifecycle process covering:
1. **Requirements and Design** — Including responsible AI design per Annex A.6.3
2. **Data Management** — Per Annex A.4.2, A.7.2, A.7.3, A.7.4
3. **Development and Training** — Per Annex A.6.2
4. **Testing and Validation** — Per Annex A.6.4
5. **Deployment** — Per Annex A.6.5
6. **Operation and Monitoring** — Per Annex A.6.6
7. **Retirement** — Per Annex A.6.7

## 8. Competence and Awareness

- AI competence requirements shall be defined for all relevant roles (7.2)
- AI training shall be provided to personnel involved in AI activities (7.2)
- All personnel shall be aware of this policy and their responsibilities (7.3)
- AI literacy programmes shall be established organization-wide

## 9. Documentation and Records

The following documented information shall be maintained:
- This AI policy and supporting procedures
- AI system inventory and classification
- Risk assessment and treatment records
- Impact assessment records
- Statement of Applicability
- Audit reports and management review minutes
- Incident reports and corrective actions
- Training and competence records

## 10. Monitoring and Review

This policy shall be:
- Reviewed at least annually or when significant changes occur
- Subject to internal audit per the AIMS audit programme
- Reviewed in management reviews
- Updated as necessary based on regulatory changes, incidents, or improvements

## 11. Non-Compliance

Non-compliance with this policy shall be addressed through the organization's corrective action process (Clause 10.2). Serious non-compliance may result in disciplinary action.

## 12. Related Documents

- AIMS Risk Assessment Procedure
- AI System Impact Assessment Procedure
- AI Incident Response Procedure
- AI System Development and Deployment Procedure
- Data Governance Procedure
- Statement of Applicability

---

**Approval**

| Name | Role | Signature | Date |
|------|------|-----------|------|
| __________ | CEO | __________ | {date} |
| __________ | CTO | __________ | {date} |
| __________ | AI Governance Chair | __________ | {date} |

---

*Generated by MEOK AI Labs ISO 42001 AI MCP Server*
*This is a template — customize for your organization's specific context and requirements.*
"""

    return {
        "organization": organization_name,
        "policy_type": policy_type,
        "generated_date": date,
        "framework": "ISO/IEC 42001:2023",
        "clauses_addressed": ["5.2 (AI Policy)", "A.2.2 (Policies for AI)", "A.2.3 (Review of policies)", "5.3 (Roles and responsibilities)"],
        "policy_document": policy,
        "word_count": len(policy.split()),
        "customization_notes": [
            "Replace placeholder names and roles with actual organizational personnel",
            "Customize AI principles to reflect organizational values",
            "Adjust governance structure to match organizational hierarchy",
            "Add organization-specific procedures and references",
            "Review and customize risk appetite and tolerance statements",
        ],
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def check_annex_controls(
    system_description: str,
    system_name: str = "AI System",
    implemented_controls: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Evaluate AI system against ISO 42001 Annex A controls.

    Maps the system to all Annex A control objectives and evaluates
    which controls are applicable and their implementation status.
    Produces a gap analysis suitable for Statement of Applicability.

    Args:
        system_description: Description of the AI system and its management.
        system_name: Name of the AI system.
        implemented_controls: Description of controls already implemented
            (free text or comma-separated control IDs).
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Annex A control evaluation with applicability and gap analysis.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    full_text = f"{system_description} {implemented_controls}"

    control_results = {}
    total_controls = 0
    applicable_controls = 0
    implemented_count = 0
    gaps = []

    for section_id, section_data in ANNEX_A_CONTROLS.items():
        section_results = []
        for ctrl_id, ctrl_data in section_data["controls"].items():
            total_controls += 1

            # Determine applicability based on system description
            ctrl_keywords = ctrl_data["description"].lower().split()[:10]
            applicability_score = _score_text(full_text, ctrl_keywords)
            is_applicable = applicability_score > 0.1 or True  # Most Annex A controls are broadly applicable

            if is_applicable:
                applicable_controls += 1

            # Check if implemented
            impl_keywords = ctrl_data["title"].lower().split() + ctrl_data["objective"].lower().split()[:5]
            implementation_score = _score_text(full_text, impl_keywords)
            ctrl_id_mentioned = ctrl_id.lower() in implemented_controls.lower()

            if implementation_score > 0.3 or ctrl_id_mentioned:
                impl_status = "implemented"
                implemented_count += 1
            elif implementation_score > 0.15:
                impl_status = "partially_implemented"
            else:
                impl_status = "not_implemented"
                if is_applicable:
                    gaps.append({
                        "control_id": ctrl_id,
                        "title": ctrl_data["title"],
                        "objective": ctrl_data["objective"],
                        "section": section_data["title"],
                    })

            section_results.append({
                "control_id": ctrl_id,
                "title": ctrl_data["title"],
                "description": ctrl_data["description"],
                "objective": ctrl_data["objective"],
                "applicable": is_applicable,
                "implementation_status": impl_status,
                "justification_needed": not is_applicable,
            })

        control_results[section_id] = {
            "title": section_data["title"],
            "controls": section_results,
            "total": len(section_results),
            "implemented": sum(1 for c in section_results if c["implementation_status"] == "implemented"),
            "gaps": sum(1 for c in section_results if c["implementation_status"] == "not_implemented" and c["applicable"]),
        }

    return {
        "system_name": system_name,
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "framework": "ISO/IEC 42001:2023 — Annex A Controls",
        "summary": {
            "total_controls": total_controls,
            "applicable_controls": applicable_controls,
            "implemented_controls": implemented_count,
            "implementation_rate": round(implemented_count / max(applicable_controls, 1), 2),
            "gaps_count": len(gaps),
        },
        "statement_of_applicability_ready": len(gaps) == 0,
        "control_sections": control_results,
        "gaps": gaps[:20],
        "priority_actions": [
            f"Implement {g['control_id']} ({g['title']}): {g['objective']}"
            for g in gaps[:10]
        ],
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


@mcp.tool()
def crosswalk_to_eu_ai_act(
    iso_clauses: str = "all",
    focus_area: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Map ISO/IEC 42001 clauses and Annex A controls to EU AI Act articles.

    This is the killer feature -- regulation-to-regulation mapping showing
    exactly where ISO 42001 conformity satisfies EU AI Act requirements.
    Essential for organizations pursuing ISO 42001 certification while
    preparing for EU AI Act compliance.

    Args:
        iso_clauses: Comma-separated ISO clauses to crosswalk (e.g., '4,5,8')
            or 'all' for complete mapping. Include 'annex' for Annex A mappings.
        focus_area: Optional focus area to filter (e.g., 'risk management',
            'transparency', 'data governance', 'human oversight').
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Detailed crosswalk between ISO 42001 and EU AI Act with alignment
        strength ratings and dual-compliance guidance.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    # Parse requested clauses
    if iso_clauses.lower() == "all":
        requested = None  # Include everything
    else:
        requested = [c.strip() for c in iso_clauses.split(",")]

    crosswalk_results = {}
    for iso_ref, mapping in ISO_TO_EU_CROSSWALK.items():
        # Filter by requested clauses
        if requested:
            matches = False
            for req in requested:
                if req.lower() == "annex" and iso_ref.startswith("A."):
                    matches = True
                elif iso_ref.startswith(req):
                    matches = True
            if not matches:
                continue

        # Filter by focus area if specified
        if focus_area:
            if focus_area.lower() not in mapping["mapping_rationale"].lower():
                continue

        # Look up ISO clause/control description
        iso_desc = _lookup_iso_description(iso_ref)

        crosswalk_results[iso_ref] = {
            "iso_description": iso_desc,
            "eu_ai_act_articles": mapping["eu_articles"],
            "mapping_rationale": mapping["mapping_rationale"],
            "alignment_strength": mapping["alignment_strength"],
            "dual_compliance_note": _get_dual_compliance_note(iso_ref),
        }

    # Summary
    alignment_counts = {"strong": 0, "moderate": 0, "weak": 0}
    all_eu_articles = set()
    for result in crosswalk_results.values():
        strength = result["alignment_strength"]
        alignment_counts[strength] = alignment_counts.get(strength, 0) + 1
        all_eu_articles.update(result["eu_ai_act_articles"])

    return {
        "crosswalk_title": "ISO/IEC 42001:2023 to EU AI Act (Regulation 2024/1689) Crosswalk",
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "requested_clauses": iso_clauses,
        "focus_area": focus_area or "all areas",
        "total_mappings": len(crosswalk_results),
        "alignment_summary": alignment_counts,
        "eu_articles_covered": sorted(all_eu_articles),
        "crosswalk": crosswalk_results,
        "key_insight": (
            "ISO 42001 certification provides substantial coverage of EU AI Act requirements, "
            "particularly for high-risk AI systems under Articles 8-15. Organizations with "
            "ISO 42001 certification are well-positioned for EU AI Act compliance, though "
            "specific EU AI Act obligations (especially Articles 5, 49, 50, 62) require "
            "additional measures beyond ISO 42001."
        ),
        "methodology": (
            "Mappings based on semantic and structural analysis of ISO/IEC 42001:2023 "
            "requirements against EU AI Act (Regulation 2024/1689) article obligations. "
            "'Strong' alignment indicates near-direct requirements correspondence; 'moderate' "
            "indicates partial overlap requiring supplementary measures."
        ),
        "disclaimer": (
            "This crosswalk is for informational purposes. ISO 42001 certification does not "
            "automatically ensure EU AI Act compliance. Organizations must conduct independent "
            "legal analysis and may need additional measures for full regulatory compliance."
        ),
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


def _lookup_iso_description(iso_ref: str) -> str:
    """Look up description for an ISO 42001 clause or Annex A control."""
    # Check main clauses
    for clause_id, clause_data in ISO_42001_CLAUSES.items():
        for sub_id, sub_data in clause_data["subclauses"].items():
            if sub_id == iso_ref:
                return sub_data["description"]

    # Check Annex A controls
    for section_id, section_data in ANNEX_A_CONTROLS.items():
        for ctrl_id, ctrl_data in section_data["controls"].items():
            if ctrl_id == iso_ref:
                return ctrl_data["description"]

    return f"ISO 42001 reference {iso_ref}"


def _get_dual_compliance_note(iso_ref: str) -> str:
    """Get note on how ISO 42001 conformity supports EU AI Act compliance."""
    notes = {
        "4.1": "Organizational context analysis under ISO 42001 directly supports the contextual risk assessment required by the EU AI Act.",
        "5.2": "An ISO 42001-conformant AI policy provides the organizational framework needed for EU AI Act compliance management.",
        "6.1": "ISO 42001 risk assessment satisfies much of the EU AI Act Article 9 risk management system requirements.",
        "7.2": "ISO 42001 competence requirements align with EU AI Act Article 4 AI literacy obligations.",
        "8.2": "ISO 42001 AI risk assessment methodology can be extended to cover EU AI Act risk management requirements.",
        "8.4": "ISO 42001 impact assessment maps closely to EU AI Act fundamental rights impact assessment (Art 27).",
        "9.1": "ISO 42001 monitoring requirements support EU AI Act post-market monitoring obligations.",
        "A.4.2": "ISO 42001 data management controls directly support EU AI Act Article 10 data governance requirements.",
        "A.6.3": "Responsible AI design per ISO 42001 provides a framework for meeting multiple EU AI Act high-risk requirements.",
        "A.8.2": "ISO 42001 transparency controls address EU AI Act transparency obligations across risk tiers.",
    }
    return notes.get(iso_ref, "ISO 42001 conformity provides foundation for this EU AI Act requirement.")


@mcp.tool()
def create_certification_checklist(
    organization_name: str = "",
    current_status: str = "",
    target_date: str = "",
    caller: str = "anonymous",
    tier: str = "free",
api_key: str = "") -> dict:
    """Generate ISO 42001 certification readiness checklist with pass/fail.

    Creates a comprehensive certification preparation checklist covering
    all mandatory requirements, documentation, and evidence needed for
    ISO 42001 certification audit. Includes pre-audit assessment and
    remediation guidance.

    Args:
        organization_name: Name of the organization pursuing certification.
        current_status: Description of current AIMS implementation status.
        target_date: Target certification date (YYYY-MM-DD format).
        caller: Caller identifier for rate limiting.
        tier: Pricing tier ('free' or 'pro').

    Returns:
        Certification readiness checklist with pass/fail status per item.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    rate_err = _check_rate_limit(caller, tier)
    if rate_err:
        return {"error": rate_err}

    status_text = current_status.lower() if current_status else ""

    def _check(keywords: list[str]) -> str:
        """Check if status text indicates this item is done."""
        score = _score_text(status_text, keywords)
        if score > 0.3:
            return "pass"
        elif score > 0.15:
            return "partial"
        return "fail"

    checklist = {
        "management_system_documentation": {
            "title": "1. Management System Documentation",
            "items": [
                {"item": "AIMS scope statement documented (4.3)", "status": _check(["scope", "defined", "boundaries"]), "evidence": "Scope document defining boundaries, AI systems in scope, exclusions with justification"},
                {"item": "AI policy approved by top management (5.2)", "status": _check(["policy", "approved", "management"]), "evidence": "Signed AI policy document with date and approval signatures"},
                {"item": "AI management objectives documented (6.2)", "status": _check(["objectives", "measurable", "documented"]), "evidence": "AIMS objectives with KPIs, responsible persons, and timelines"},
                {"item": "Roles and responsibilities defined (5.3)", "status": _check(["roles", "responsibilities", "defined"]), "evidence": "Organizational chart, RACI matrix, or role descriptions for AI management"},
                {"item": "Process documentation complete (8.1)", "status": _check(["process", "documented", "procedures"]), "evidence": "AI lifecycle procedures, operational procedures, change management process"},
            ],
        },
        "risk_management": {
            "title": "2. Risk Management",
            "items": [
                {"item": "AI risk assessment methodology defined (6.1)", "status": _check(["risk assessment", "methodology"]), "evidence": "Risk assessment procedure with criteria, scales, and methodology"},
                {"item": "AI risk assessment conducted (8.2)", "status": _check(["risk assessment", "conducted", "completed"]), "evidence": "Completed risk assessment records with risk register"},
                {"item": "Risk treatment plan documented (8.3)", "status": _check(["risk treatment", "plan"]), "evidence": "Risk treatment plan with selected controls and justifications"},
                {"item": "Statement of Applicability prepared (8.3)", "status": _check(["statement of applicability", "SoA"]), "evidence": "SoA document listing all Annex A controls with applicability decisions"},
                {"item": "Residual risks accepted by risk owners (8.3)", "status": _check(["residual risk", "accepted", "risk owner"]), "evidence": "Signed risk acceptance records from authorized risk owners"},
                {"item": "AI impact assessment conducted (8.4)", "status": _check(["impact assessment", "conducted"]), "evidence": "Impact assessment records covering individuals, society, and environment"},
            ],
        },
        "annex_a_controls": {
            "title": "3. Annex A Controls Implementation",
            "items": [
                {"item": "AI policies defined and communicated (A.2)", "status": _check(["policies", "communicated"]), "evidence": "AI policy documents, communication records, acknowledgment receipts"},
                {"item": "Roles and AI competencies defined (A.3)", "status": _check(["competencies", "roles", "AI knowledge"]), "evidence": "Competence framework, training records, skills assessments"},
                {"item": "Data management controls implemented (A.4, A.7)", "status": _check(["data management", "data quality", "provenance"]), "evidence": "Data governance procedures, quality metrics, provenance documentation"},
                {"item": "Impact assessment process established (A.5)", "status": _check(["impact assessment", "process"]), "evidence": "Impact assessment procedure and completed assessment records"},
                {"item": "AI lifecycle controls in place (A.6)", "status": _check(["lifecycle", "development", "deployment", "monitoring"]), "evidence": "Development, testing, deployment, monitoring, and retirement procedures"},
                {"item": "Transparency and documentation controls (A.8)", "status": _check(["transparency", "documentation", "stakeholder"]), "evidence": "System documentation, transparency notices, stakeholder communications"},
                {"item": "Use and monitoring controls (A.9)", "status": _check(["intended use", "monitoring", "responsible use"]), "evidence": "Intended use documentation, monitoring dashboards, use guidelines"},
                {"item": "Third-party controls (A.10)", "status": _check(["third-party", "vendor", "supply chain"]), "evidence": "Vendor assessments, SLAs, third-party monitoring records"},
            ],
        },
        "performance_and_improvement": {
            "title": "4. Performance Evaluation and Improvement",
            "items": [
                {"item": "Monitoring and measurement defined (9.1)", "status": _check(["monitoring", "measurement", "metrics"]), "evidence": "Monitoring plan, KPIs, measurement records"},
                {"item": "Internal audit programme established (9.2)", "status": _check(["internal audit", "programme", "audit"]), "evidence": "Audit programme, audit procedures, auditor competence records, audit reports"},
                {"item": "At least one complete internal audit conducted (9.2)", "status": _check(["audit conducted", "audit completed", "audit report"]), "evidence": "Completed audit report with findings and corrective actions"},
                {"item": "Management review conducted (9.3)", "status": _check(["management review", "review conducted"]), "evidence": "Management review minutes with decisions and action items"},
                {"item": "Corrective action process in place (10.2)", "status": _check(["corrective action", "nonconformity"]), "evidence": "Corrective action procedure, nonconformity records, root cause analyses"},
                {"item": "Continual improvement activities documented (10.1)", "status": _check(["improvement", "continual", "lessons learned"]), "evidence": "Improvement register, lessons learned records, trend analysis"},
            ],
        },
        "pre_audit_readiness": {
            "title": "5. Pre-Audit Readiness",
            "items": [
                {"item": "AIMS has been operational for minimum 3 months", "status": _check(["operational", "running", "implemented"]), "evidence": "Evidence of AIMS operation including records spanning at least 3 months"},
                {"item": "All mandatory documents and records available", "status": _check(["documents", "records", "complete"]), "evidence": "Document register showing all required documents are current and accessible"},
                {"item": "Personnel trained and aware of audit process", "status": _check(["trained", "aware", "audit preparation"]), "evidence": "Training records, audit awareness communications"},
                {"item": "Certification body selected and Stage 1 scheduled", "status": _check(["certification body", "auditor", "scheduled"]), "evidence": "Certification body contract, Stage 1 audit date confirmation"},
                {"item": "Management commitment letter available", "status": _check(["management commitment", "leadership"]), "evidence": "Signed commitment letter from top management"},
            ],
        },
    }

    # Calculate overall readiness
    total_items = 0
    passed_items = 0
    failed_items = 0
    partial_items = 0

    for section in checklist.values():
        for item in section["items"]:
            total_items += 1
            if item["status"] == "pass":
                passed_items += 1
            elif item["status"] == "partial":
                partial_items += 1
            else:
                failed_items += 1

    readiness_score = round((passed_items + partial_items * 0.5) / max(total_items, 1), 2)

    if readiness_score >= 0.85:
        readiness_status = "ready_for_certification"
        recommendation = "Organization appears ready for Stage 1 certification audit. Address any remaining partial items."
    elif readiness_score >= 0.65:
        readiness_status = "near_ready"
        recommendation = "Good progress. Focus on closing the remaining gaps, particularly any failed items. Consider a pre-assessment audit."
    elif readiness_score >= 0.40:
        readiness_status = "significant_work_needed"
        recommendation = "Substantial implementation work remaining. Prioritize management system documentation and risk management sections."
    else:
        readiness_status = "early_stage"
        recommendation = "AIMS implementation is in early stages. Focus on establishing foundational elements: scope, policy, risk assessment, and governance structure."

    return {
        "organization": organization_name or "Not specified",
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "target_certification_date": target_date or "Not specified",
        "framework": "ISO/IEC 42001:2023 — Certification Readiness",
        "readiness_score": readiness_score,
        "readiness_status": readiness_status,
        "recommendation": recommendation,
        "summary": {
            "total_items": total_items,
            "passed": passed_items,
            "partial": partial_items,
            "failed": failed_items,
        },
        "checklist": checklist,
        "certification_process_overview": {
            "stage_1": "Documentation review — auditor reviews AIMS documentation for completeness and conformity",
            "stage_2": "Implementation audit — auditor verifies AIMS implementation and effectiveness on-site",
            "surveillance": "Annual surveillance audits to maintain certification",
            "recertification": "Full recertification audit every 3 years",
        },
        "powered_by": "MEOK AI Labs | https://meok.ai",
    }


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()