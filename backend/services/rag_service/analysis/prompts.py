import re
import json
import logging
from typing import Optional
from services.rag_service.analysis.risk_rubric import findings_for_prompt

logger = logging.getLogger(__name__)

CORPORATE_CLAUSES_LIBRARY: list[dict] = [
    {"id": "sla_uptime",             "name": "Service Level Agreement (SLA) & Uptime",      "category": "performance",  "keywords": ["SLA", "service level", "uptime", "availability", "99.9%", "downtime", "latency", "service credit", "MTTR", "response time"]},
    {"id": "data_protection_dpdp",   "name": "Data Protection & Privacy (DPDP / GDPR)",     "category": "privacy",      "keywords": ["data protection", "personal data", "DPDP Act", "data fiduciary", "data processor", "GDPR", "privacy", "consent", "PII", "data principal"]},
    {"id": "cybersecurity_certin",   "name": "Cybersecurity & Incident Reporting (CERT-In)", "category": "security",     "keywords": ["cybersecurity", "CERT-In", "incident", "breach", "security incident", "vulnerability", "log retention", "6 hours", "compromise"]},
    {"id": "ip_ownership_code",      "name": "Software IP & Work-For-Hire Assignment",      "category": "ip",           "keywords": ["intellectual property", "IP", "source code", "copyright", "patent", "work for hire", "invention assignment", "proprietary code", "repository"]},
    {"id": "software_license_scope",  "name": "Software License Scope & SaaS Restrictions",  "category": "ip",           "keywords": ["license", "licence", "grant", "sublicense", "EULA", "subscription", "named users", "concurrent users", "reverse engineering", "decompilation"]},
    {"id": "source_code_escrow",     "name": "Source Code Escrow & Repository Rights",      "category": "ip",           "keywords": ["escrow", "source code", "repository", "code deposit", "release condition", "github", "gitlab", "escrow agent"]},
    {"id": "open_source_governance",  "name": "Open Source Software (OSS) Governance",       "category": "ip",           "keywords": ["open source", "OSS", "GPL", "AGPL", "copyleft", "Apache", "MIT license", "third party software", "viral license"]},
    {"id": "confidentiality_nda",     "name": "Confidentiality & Trade Secrets (Source Code & APIs)", "category": "ip", "keywords": ["confidential", "non-disclosure", "NDA", "trade secret", "source code", "API key", "proprietary algorithm", "credentials"]},
    {"id": "limitation_liability_it", "name": "Limitation of Liability & Data Loss Caps",    "category": "liability",   "keywords": ["liability", "limit", "cap", "indirect damages", "consequential damages", "loss of data", "loss of profit", "maximum liability"]},
    {"id": "ip_indemnification",      "name": "IP Infringement & Data Breach Indemnification","category": "liability",  "keywords": ["indemnify", "indemnification", "hold harmless", "IP infringement", "third-party claim", "data breach liability", "patent claim"]},
    {"id": "cloud_hosting_dr",       "name": "Cloud Hosting, BCP & Disaster Recovery",      "category": "performance",  "keywords": ["cloud", "hosting", "AWS", "Azure", "GCP", "disaster recovery", "BCP", "backup", "RTO", "RPO", "failover", "data center"]},
    {"id": "it_audit_pentest",       "name": "IT Audit, Penetration Testing & Compliance",  "category": "compliance",   "keywords": ["audit", "right to audit", "security audit", "penetration testing", "vulnerability assessment", "SOC 2", "ISO 27001", "VAPT"]},
    {"id": "vendor_transition_exit",  "name": "Vendor Lock-in, De-provisioning & Exit Aid",  "category": "exit",         "keywords": ["transition", "exit assistance", "data migration", "de-provisioning", "vendor lock-in", "data return", "deletion of data"]},
    {"id": "it_moonlighting",        "name": "IT Moonlighting & Dual Employment Clause",    "category": "employment",   "keywords": ["moonlighting", "dual employment", "side project", "conflict of interest", "outside programming", "freelancing"]},
    {"id": "tech_non_solicitation",   "name": "Tech Talent Non-Solicitation",                 "category": "restriction",  "keywords": ["non-solicitation", "non solicitation", "poaching", "developers", "engineers", "hire away", "recruit"]},
    {"id": "termination_it_service", "name": "Termination & Suspension of Cloud/IT Services","category": "exit",        "keywords": ["terminate", "termination", "suspension", "service cut-off", "notice period", "material breach", "immediate termination"]},
    {"id": "uat_acceptance",         "name": "UAT Acceptance Criteria & Milestones",        "category": "performance",  "keywords": ["UAT", "acceptance criteria", "user acceptance testing", "milestone", "defect severity", "sign-off", "deliverable"]},
    {"id": "software_maintenance",   "name": "Software Maintenance, Bug Fixes & Patches",  "category": "performance",  "keywords": ["maintenance", "bug fix", "patch", "hotfix", "support tier", "error correction", "software update"]},
    {"id": "force_majeure_cyber",    "name": "Force Majeure & Cyber Warfare / Telecom Outage","category": "performance","keywords": ["force majeure", "cyber attack", "DDoS", "internet outage", "telecom disruption", "cloud provider outage"]},
    {"id": "governing_law_tech",     "name": "Governing Law & IT Dispute Arbitration",      "category": "dispute",      "keywords": ["governing law", "jurisdiction", "arbitration", "seat of arbitration", "courts of", "IT dispute"]},
    {"id": "payment_milestones",      "name": "Tech Milestones & SaaS Subscription Fees",     "category": "financial",    "keywords": ["payment", "invoice", "subscription fee", "milestone payment", "license fee", "overdue", "withholding"]},
    {"id": "penalty_delay",          "name": "Liquidated Damages / Delay Penalties",         "category": "financial",    "keywords": ["liquidated damages", "penalty", "delay penalty", "late delivery", "service credit"]},
    {"id": "it_asset_capitalization", "name": "IT Asset & Equipment Security Clause",        "category": "corporate",    "keywords": ["laptop", "company asset", "remote device", "asset return", "MDM", "device security"]},
    {"id": "anti_bribery_tech",      "name": "Anti-Corruption & Tech Vendor Procurement",    "category": "compliance",   "keywords": ["anti-bribery", "anti-corruption", "procurement", "kickback", "Prevention of Corruption Act", "FCPA"]},
    {"id": "change_of_control",      "name": "Change of Control & Assignment of Software",  "category": "corporate",    "keywords": ["change of control", "acquisition", "merger", "assignment", "transfer of agreement"]},
]

_CLAUSE_NAMES_LIST = "\n".join(
    f"  {i+1:02d}. {c['name']} [{c['category']}]"
    for i, c in enumerate(CORPORATE_CLAUSES_LIBRARY)
)

INDIAN_LAW_CONTEXT = """
INDIAN INFORMATION TECHNOLOGY & CORPORATE LEGAL FRAMEWORK (Apply where relevant):

1. INFORMATION TECHNOLOGY ACT, 2000 (with 2008 Amendments):
  • Sec 10A   – Validity of contracts formed through electronic means / digital signatures
  • Sec 43    – Penalty and compensation for damage to computer system / data extraction
  • Sec 43A   – Compensation for failure to protect Sensitive Personal Data / Information (SPDI)
  • Sec 65    – Tampering with computer source code documents (imprisonment up to 3 years)
  • Sec 66/66C– Computer-related offences, hacking, identity theft, unauthorized access
  • Sec 67/67A– Obscene/unlawful electronic transmission liability
  • Sec 69/69B– Power to issue directions for interception/monitoring of computer resources
  • Sec 72/72A– Penalty for breach of confidentiality, privacy, and unauthorized disclosure of personal info
  • Sec 79    – Safe Harbor & Intermediary Guidelines (due diligence required for tech platforms/cloud hosting)
  • IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021/2023

2. DIGITAL PERSONAL DATA PROTECTION ACT, 2023 (DPDP Act):
  • Data Fiduciary vs Data Processor obligations in software systems and enterprise IT architectures
  • Mandatory legitimate purpose, clear notice, and verifiable consent prior to processing digital personal data
  • Obligations of Significant Data Fiduciaries (SDF): Data Protection Officer (DPO), Independent Data Auditor, DPIA
  • Cross-border transfer of personal data restrictions and government notification requirements
  • Mandatory notification of personal data breaches to the Data Protection Board of India and affected data principals
  • Severe financial penalties up to ₹250 Crores for failure to take reasonable security safeguards to prevent data breaches

3. CERT-In CYBER SECURITY DIRECTIONS (2022 / Current):
  • Mandatory 6-hour reporting window to CERT-In for all designated cyber incidents (ransomware, data leaks, server breaches)
  • Mandatory retention of system logs, firewall logs, and user access records within Indian jurisdiction for 180 days
  • Mandatory NTP time synchronization with National Physical Laboratory (NPL) or NIC clock servers
  • Cloud and VPN service providers mandatory maintenance of customer identity and activity logs

4. SOFTWARE INTELLECTUAL PROPERTY & TRADE SECRETS:
  • Copyright Act 1957: Computer software programs recognized as "literary works" under Sec 2(o)
  • Work-for-hire doctrine (Sec 17): Employer/client owns software code developed by employees/contractors only with explicit written assignment
  • Patents Act 1970 (Sec 3(k)): Non-patentability of computer programs per se, unless tied to novel technical hardware interactions
  • Open Source Software (OSS) Legal Risks: Copyleft contamination (GPL, AGPL) requiring proprietary source code disclosure
  • Trade Secret Protection: Breach of confidence enforceable under Indian common law and Contract Act 1872

5. INDIAN CONTRACT ACT 1872 IN IT AGREEMENTS:
  • Master Services Agreements (MSA), Statements of Work (SOW), SaaS contracts, and Service Level Agreements (SLA)
  • Sec 27: Agreements in restraint of trade void (Post-employment non-competes for software developers are void in India; non-disclosure and non-solicitation during employment remain enforceable)
  • Sec 73 & 74: Damages for breach of tech contract; liquidated damages vs penalty stipulations (uptime credits)
  • Enforceability of limitation of liability and exclusion of consequential damages/data loss

6. COMPANIES ACT 2013 — CORPORATE IT & CYBER GOVERNANCE:
  • Sec 134(5): Directors' Responsibility Statement regarding adequacy and operating effectiveness of internal financial and IT controls
  • Sec 177: Audit Committee statutory mandate to review cybersecurity, IT infrastructure risks, and enterprise vulnerability
  • Sec 188: Related Party Transactions (RPT) in IT procurement, software licensing, and group company technology outsourcing
"""

_LEGAL_DOC_SIGNALS = [
    "agreement", "contract", "deed", "service level", "sla", "software",
    "saas", "license", "nda", "confidentiality", "intellectual property",
    "source code", "escrow", "dpdp", "data protection", "cybersecurity",
    "cert-in", "master services", "statement of work", "sow", "msa",
    "uptime", "hosting", "cloud", "aws", "azure", "gcp", "liability",
    "indemnity", "termination", "non-compete", "moonlighting", "acceptance",
    "uat", "bug", "patch", "vendor", "client", "developer", "engineer",
]


def _classify_document(text: str) -> str:
    """Quick keyword-based document type classifier for IT corporate legal documents."""
    lower = text[:3000].lower()
    hits = sum(1 for kw in _LEGAL_DOC_SIGNALS if kw in lower)
    if hits >= 4:
        return "corporate_legal"
    if hits >= 2:
        return "general_legal"
    return "non_legal"


_TITLE = re.compile(r"\s*\(?([A-Za-z][^.()\n]{3,110}?\b(?:agreement|contract|deed|licen[cs]e|addendum|memorandum of understanding))\b", re.IGNORECASE)


def _document_title(text: str) -> str:
    for line in text.splitlines()[:6]:
        m = _TITLE.match(line)
        if m and not m.group(1).lower().startswith(("this ", "the ")):
            title = m.group(1).strip()
            return title.title() if title.isupper() else title
    return ""


def _compliance_lines(risk_assessment: Optional[dict]) -> list[str]:
    if not risk_assessment:
        return []
    labels = {"COMPLIANT": "Addressed", "PARTIAL": "Partly addressed", "GAP": "Not addressed"}
    lines = []
    for c in risk_assessment.get("risk_checklist", []):
        if c["status"] not in labels:
            continue
        if c["status"] == "COMPLIANT" and c["finding"] != "adequately addressed":
            lines.append(f"No issue found: {c['title']}, {c['finding']} ({c['law']})")
        elif c["status"] == "COMPLIANT":
            lines.append(f"{labels[c['status']]}: {c['title']} ({c['law']})")
        else:
            lines.append(f"{labels[c['status']]}: {c['title']}, {c['finding']} ({c['law']})")
    return lines


def build_prompt(doc_full: str, local_context: str, law_context: str, doc_type: str, risk_assessment: Optional[dict] = None) -> str:
    title = _document_title(doc_full) or "Not stated"
    document_text = doc_full or local_context
    compliance_facts = "\n".join(f"- {line}" for line in _compliance_lines(risk_assessment)) or "(not available)"

    return f"""You are an Indian legal analyst. Read the contract below and report ONLY what it actually says.

STRICT RULES:
1. Use only facts written in the CONTRACT TEXT. Do not use outside knowledge about other contracts.
2. Never invent numbers, percentages, time limits, amounts, parties or clauses. Every number you write must appear in the contract.
3. Mention the clause number (for example "cl. 5" or "cl. 12D") for every clause and obligation.
4. If something is not in the contract, leave it out. Do not guess.
5. Cite a law only if it is named in the contract or in the RISK FINDINGS / COMPLIANCE FACTS below.
6. If the agreement is mutual, say that each party can act in each role. Do not assign fixed roles that the contract does not assign.
7. Keep exceptions and conditions (for example "except as the Purpose requires").
8. For each obligation, name the party exactly as the clause does (for example "the Recipient"). Never swap who must do what.

DOCUMENT TITLE: {title}

{'=' * 60}
CONTRACT TEXT:
{document_text}

{'=' * 60}
RELEVANT LAW EXTRACTS (use only if they match the contract):
{law_context or "(none)"}

{'=' * 60}
RISK FINDINGS (computed by rules from the full contract; do not change them):
{findings_for_prompt(risk_assessment) if risk_assessment else "(not available)"}

COMPLIANCE FACTS (computed by rules; do not contradict them):
{compliance_facts}

{'=' * 60}
TASKS:
1. "document_type": the type of this contract in a few words, based on its title and content.
2. "summary": 6-8 short sentences: what the contract is, the parties and their roles, the purpose, the term and how it ends, the most important duties, and the governing law and dispute forum.
3. "clauses": the 8-12 most important clauses, each "Clause name (cl. X): what this clause requires, with any time limit or amount". Skip definitions and boilerplate. A clause name alone is not enough; always say what it requires.
4. "obligations": 6-10 items, each "Party: duty, with the exact time limit if the contract gives one (cl. X)".
5. "critical_risks": one paragraph explaining the RISK FINDINGS above for this contract in plain words, using the law given with each finding. Keep the meaning of each finding exactly (if it says there is no cap, do not say liability is capped). Do not use codes. If there are none, say the rules found no significant risks.
6. "compliance": one paragraph explaining the COMPLIANCE FACTS above in plain words. Do not add other laws.

OUTPUT RULES:
- Output ONLY one valid JSON object, starting with {{ and ending with }}.
- No markdown, no code fences, no <think> tags.

JSON FORMAT:
{{
  "document_type": "",
  "summary": "",
  "clauses": [""],
  "obligations": [""],
  "critical_risks": "",
  "compliance": ""
}}"""


def _parse_response(raw: str, doc_type: str, risk_assessment: Optional[dict] = None, source_text: str = "") -> dict:
    result = _apply_risk(_parse_llm(raw, doc_type), risk_assessment)
    if source_text:
        result = _ground(result, source_text, risk_assessment)
    return result


_NUMBER_WORD = re.compile(r"\b[a-z]+(?:-[a-z]+)? \((\d+)\)")
_QUANTITY = re.compile(r"(\d+(?:\.\d+)?)\s*-?\s*(%|percent|hours?|hrs?|days?|business days|weeks?|months?|years?|crores?|lakhs?)(?![a-z])")
_SECTION = re.compile(r"\b(?:sec(?:tion)?s?\.?|s\.|ss\.|rule)\s*(\d+[a-z]?)", re.IGNORECASE)
_CONCEPTS = {
    "cloud": r"\bcloud\b", "saas": r"\bsaas\b", "uptime": r"\buptime\b|\bavailability\b",
    "sla": r"\bsla\b|service[- ]levels?", "hosting": r"\bhosting\b", "msa": r"master services agreement|\bmsa\b",
    "bug": r"\bp1\b|\bbugs?\b", "cert-in": r"cert-?\s?in", "non-compete": r"non-?compete",
    "escrow": r"\bescrow\b", "subscription": r"\bsubscription\b", "audit committee": r"audit committee",
    "related party": r"related party", "companies act": r"companies act", "work-for-hire": r"work[- ]for[- ]hire",
    "literary work": r"literary work", "dpia": r"\bdpia\b", "dpo": r"\bdpo\b|data protection officer",
    "milestone": r"\bmilestones?\b", "payment": r"\bpayments?\b|\binvoices?\b|\bfees?\b",
}


def _unit(u: str) -> str:
    u = u.lower()
    if u in ("%", "percent"):
        return "%"
    return u.rstrip("s").replace("business day", "day").replace("hr", "hour")


def _facts(text: str) -> tuple[set, set, set]:
    lower = _NUMBER_WORD.sub(r"\1", text.lower())
    quantities = {(n, _unit(u)) for n, u in _QUANTITY.findall(lower)}
    sections = {m.lower() for m in _SECTION.findall(lower)}
    concepts = {name for name, pattern in _CONCEPTS.items() if re.search(pattern, lower)}
    return quantities, sections, concepts


def _is_grounded(sentence: str, facts: tuple[set, set, set]) -> bool:
    quantities, sections, concepts = facts
    lower = _NUMBER_WORD.sub(r"\1", sentence.lower())
    if any((n, _unit(u)) not in quantities for n, u in _QUANTITY.findall(lower)):
        return False
    if any(s.lower() not in sections for s in _SECTION.findall(lower)):
        return False
    return all(name in concepts for name, pattern in _CONCEPTS.items() if re.search(pattern, lower))


def _keep_grounded(items: list[str], facts: tuple[set, set, set]) -> list[str]:
    return [i for i in items if _is_grounded(i, facts)]


def _keep_grounded_text(text: str, facts: tuple[set, set, set]) -> str:
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", (text or "").strip())
    return " ".join(s for s in sentences if s and _is_grounded(s, facts))


_CLAUSE_HEADING = re.compile(r"^(\d+[A-Z]?)\.\s+([A-Z][A-Za-z ,&/'\-]{2,70})$")
_BOILERPLATE = ("definition", "interpretation", "general", "counterpart", "notice", "entire agreement", "severab", "recital", "background")


def _clause_digest(text: str, limit: int = 15) -> list[str]:
    lines = [l.strip() for l in text.splitlines()]
    items = []
    for i, line in enumerate(lines):
        m = _CLAUSE_HEADING.match(line)
        if not m or len(m.group(2).split()) > 8 or any(b in m.group(2).lower() for b in _BOILERPLATE):
            continue
        body = next((l for l in lines[i + 1:i + 3] if l and not _CLAUSE_HEADING.match(l)), "")
        if not body:
            continue
        first = re.split(r"(?<=[.;])\s+(?=[A-Z0-9])", body)[0]
        first = re.sub(r"^\d+[A-Z]?(\.\d+)*\s+", "", first)
        if len(first) > 220:
            first = first[:220].rsplit(" ", 1)[0] + "…"
        name = m.group(2).title() if m.group(2).isupper() else m.group(2)
        items.append(f"{name} (cl. {m.group(1)}): {first}")
        if len(items) >= limit:
            break
    return items


_SUBCLAUSE = re.compile(r"^(\d+[A-Z]?(?:\.\d+)*)\.?\s+(.+)$")
_SHALL = re.compile(r"((?:the |each |either |neither )?[A-Z][A-Za-z'’ ]{1,40}?)\s+(?:shall|must|may not)\b")


def _clause_texts(text: str) -> dict:
    clauses, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        heading = _CLAUSE_HEADING.match(line)
        if heading:
            current = heading.group(1)
            clauses[current] = heading.group(2).lower()
            continue
        sub = _SUBCLAUSE.match(line)
        if sub and not heading:
            current = sub.group(1)
            line = sub.group(2)
        if current and line:
            clauses[current] = (clauses.get(current, "") + " " + line).strip()
    return clauses


def _subject(clause_text: str) -> str:
    m = _SHALL.search(clause_text)
    return m.group(1).split()[-1].lower() if m else ""


def _wrong_parties(items: list[str], clauses: dict) -> bool:
    checked = wrong = 0
    for item in items:
        num = re.search(r"cl\.\s*(\d+[A-Z]?(?:\.\d+)*)", item)
        if not num or ":" not in item:
            continue
        subject = _subject(clauses.get(num.group(1), ""))
        if not subject or subject in ("party", "parties"):
            continue
        checked += 1
        if subject not in item.split(":", 1)[0].lower():
            wrong += 1
    return checked > 0 and wrong * 2 >= checked


_STOP = {"shall", "must", "party", "parties", "agreement", "other", "which", "their", "under", "without", "within", "information", "confidential", "recipient", "discloser", "written", "notice", "after", "before", "where", "there", "these", "those", "about", "until"}


def _words(text: str) -> set:
    return {w for w in re.findall(r"[a-z]{4,}", text.lower()) if w not in _STOP}


def _fix_clause_numbers(items: list[str], clauses: dict) -> list[str]:
    if not clauses:
        return items
    fixed = []
    for item in items:
        m = re.search(r"cl\.\s*(\d+[A-Z]?(?:\.\d+)*)", item)
        if not m:
            fixed.append(item)
            continue
        words = _words(re.sub(r"cl\.\s*\S+", "", item))
        if len(words) < 2:
            fixed.append(item)
            continue
        score = lambda num: len(words & _words(" ".join(v for k, v in clauses.items() if k == num or k.startswith(num + ".")))) / len(words)
        cited = m.group(1)
        best = max(clauses, key=score)
        if score(best) >= 0.5 and score(best) >= score(cited) + 0.25 and not best.startswith(cited + "."):
            item = item[:m.start(1)] + best + item[m.end(1):]
        fixed.append(item)
    return fixed


def _party_in_text(item: str, text: str) -> bool:
    if ":" not in item:
        return True
    label = re.sub(r"\(.*?\)", "", item.split(":", 1)[0]).strip()
    words = [w for w in re.findall(r"[A-Za-z]{3,}", label) if w.lower() not in ("the", "and", "each", "both", "party", "parties")]
    return not words or any(w.lower() in text.lower() for w in words)


def _obligation_digest(text: str, limit: int = 14) -> list[str]:
    items = []
    for num, body in _clause_texts(text).items():
        sentence = next((s for s in re.split(r"(?<=[.;])\s+(?=[A-Z])", body) if re.search(r"\b(shall|must)\b", s)), "")
        if not sentence or re.search(r"\bmeans\b|shall have the meaning|\bincludes?\b", sentence):
            continue
        if len(sentence) > 220:
            sentence = sentence[:220].rsplit(" ", 1)[0] + "…"
        items.append(f"{sentence} (cl. {num})")
        if len(items) >= limit:
            break
    return items


def _names_only(items: list[str]) -> bool:
    if not items:
        return True
    short = sum(1 for i in items if len(i.split(":", 1)[-1].split()) < 5)
    return short >= len(items) / 2


def _ground(result: dict, source_text: str, risk_assessment: Optional[dict]) -> dict:
    doc_facts = _facts(source_text)
    findings = findings_for_prompt(risk_assessment) if risk_assessment else ""
    findings += " " + " ".join(l for l in _compliance_lines(risk_assessment) if not l.startswith("No issue found"))
    law_facts = _facts(findings)
    all_facts = tuple(a | b for a, b in zip(doc_facts, law_facts))

    title = _document_title(source_text)
    if title:
        result["document_type"] = title

    summary = _keep_grounded_text(result.get("summary", ""), doc_facts)
    result["summary"] = summary or (f"This document is a {title}." if title else result.get("summary", ""))
    clause_map = _clause_texts(source_text)
    result["clauses"] = _fix_clause_numbers(_keep_grounded(result.get("clauses", []), doc_facts), clause_map)
    if _names_only(result["clauses"]):
        result["clauses"] = _clause_digest(source_text) or result["clauses"]
    result["obligations"] = [o for o in _keep_grounded(result.get("obligations", []), doc_facts) if _party_in_text(o, source_text)]
    result["obligations"] = _fix_clause_numbers(result["obligations"], clause_map)
    if not result["obligations"] or _wrong_parties(result["obligations"], clause_map):
        result["obligations"] = _obligation_digest(source_text) or result["obligations"]
    result["critical_risks"] = re.sub(r"\b[RF]\d{1,2}\b:?\s*", "", result.get("critical_risks", ""))
    result["critical_risks"] = _keep_grounded_text(result.get("critical_risks", ""), all_facts)
    if re.search(r"no monetary cap|no upper limit|uncapped", findings):
        parts = re.split(r"(?<=[.;])\s+", result["critical_risks"])
        result["critical_risks"] = " ".join(p for p in parts if not re.search(r"(?<!un)\bcapped\b", p) or re.search(r"\b(no|not|un)\b", p))

    lines = _compliance_lines(risk_assessment)
    explanation = _keep_grounded_text(result.get("compliance", ""), all_facts)
    result["compliance"] = "\n".join(lines + ([explanation] if explanation else [])) if lines else explanation
    return result


def _apply_risk(result: dict, risk_assessment: Optional[dict]) -> dict:
    if not risk_assessment:
        return result
    result["risk_score"] = risk_assessment["risk_score"]
    result["risk_band"] = risk_assessment["risk_band"]
    result["risks"] = risk_assessment["risks"][:20]
    result["risk_checklist"] = risk_assessment["risk_checklist"]
    result["red_flags"] = risk_assessment["red_flags"]
    result["rubric_version"] = risk_assessment["rubric_version"]
    return result


def _parse_llm(raw: str, doc_type: str) -> dict:
    if not raw:
        return _fallback("LLM returned empty response")

    try:
        return _validate(json.loads(raw), doc_type)
    except (json.JSONDecodeError, ValueError):
        pass

    match = re.search(r"\{[\s\S]+\}", raw)
    if match:
        try:
            return _validate(json.loads(match.group()), doc_type)
        except (json.JSONDecodeError, ValueError):
            pass

    cleaned = _repair_json(raw)
    if cleaned:
        try:
            return _validate(json.loads(cleaned), doc_type)
        except (json.JSONDecodeError, ValueError):
            pass

    logger.warning("[PARSE] All JSON parsing failed — using regex extraction")
    return _extract_from_text(raw, doc_type)


def _repair_json(raw: str) -> Optional[str]:
    try:
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end == 0:
            return None

        candidate = raw[start:end]
        candidate = re.sub(r",\s*([\}\]])", r"\1", candidate)
        candidate = re.sub(r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', candidate)
        candidate = candidate.replace("'", '"')
        return candidate
    except Exception:
        return None


def _validate(data: dict, doc_type: str) -> dict:
    def to_list(v, limit: int) -> list[str]:
        if isinstance(v, list):
            return [str(x).strip() for x in v[:limit] if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip()]
        return []

    summary = str(data.get("summary", "")).strip()
    if len(summary.split()) < 20:
        summary = (
            f"{summary} "
            f"This document has been evaluated for Information Technology corporate legal compliance, "
            f"service level commitments, data protection, and IT operational risk under Indian commercial laws."
        ).strip()

    return {
        "document_type": str(data.get("document_type", _infer_doc_type_label(doc_type))).strip()[:100],
        "summary":       summary[:2000],
        "clauses":       to_list(data.get("clauses"),     12),
        "obligations":   to_list(data.get("obligations"),  10),
        "risks":         to_list(data.get("risks"),        8),
        "risk_score":    int(''.join(filter(str.isdigit, str(data.get("risk_score", "0")))) or 0),
        "critical_risks": str(data.get("critical_risks", "")).strip()[:1000],
        "compliance":    str(data.get("compliance", "")).strip()[:1000],
    }


def _extract_from_text(text: str, doc_type: str) -> dict:
    def after(label: str, max_chars: int = 800) -> str:
        m = re.search(
            rf'{label}\s*[:\-]?\s*(.+?)(?=\n\s*(?:clauses|obligations|risks|compliance|document_type|summary)\s*[:\-]|\Z)',
            text, re.IGNORECASE | re.DOTALL
        )
        return m.group(1).strip()[:max_chars] if m else ""

    def bullet_list(label: str, limit: int = 10) -> list[str]:
        m = re.search(
            rf'{label}\s*[:\-]?\s*([\s\S]+?)(?=\n\s*(?:clauses|obligations|risks|compliance|document_type|summary)\s*[:\-]|\Z)',
            text, re.IGNORECASE
        )
        if not m:
            return []
        block = m.group(1)
        items = re.findall(r'[-•*\d]+[.)]\s*(.+)', block)
        if not items:
            items = [line.strip() for line in block.split('\n') if line.strip() and len(line.strip()) > 10]
        return [i.strip() for i in items if i.strip()][:limit]

    return {
        "document_type": _infer_doc_type_label(doc_type),
        "summary":       after("summary", 1500) or text[:500],
        "clauses":       bullet_list("clauses", 10),
        "obligations":   bullet_list("obligations", 8),
        "risks":         bullet_list("risks", 6),
        "risk_score":    35,
        "critical_risks": after("critical_risks", 800),
        "compliance":    after("compliance", 800),
    }


def _infer_doc_type_label(doc_type: str) -> str:
    mapping = {
        "corporate_legal": "IT Master Services Agreement / Contract",
        "general_legal":   "IT Service & Compliance Document",
        "non_legal":       "General IT Document",
    }
    return mapping.get(doc_type, "IT Corporate Document")


def _fallback(reason: str) -> dict:
    return {
        "document_type": "IT Corporate Document",
        "summary":       f"IT Legal Analysis could not be completed: {reason}",
        "clauses":       [],
        "obligations":   [],
        "risks":         [],
        "risk_score":    0,
        "critical_risks": "",
        "compliance":    "",
        "error":         reason,
    }