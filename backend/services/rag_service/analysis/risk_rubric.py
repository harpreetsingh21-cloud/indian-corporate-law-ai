import re
from typing import Optional

RUBRIC_VERSION = "1.1"

STATUS_FACTOR = {"GAP": 1.0, "PARTIAL": 0.5, "COMPLIANT": 0.0}

_PERSONAL_DATA = r"personal data|personal information|customer data|user data|\bpii\b|data principal|data fiduciary|data processor|processing of (personal )?data|sensitive personal"
_IT_SYSTEMS = r"hosting|cloud|server|infrastructure|software|saas|platform|it services|system|network|cyber|incident"

RISK_CHECKLIST: list[dict] = [
    {
        "id": "R1",
        "title": "Reasonable security safeguards",
        "law": "DPDP Act 2023 s.8(5); DPDP Rules 2025 Rule 6; IT Act 2000 s.43A",
        "weight": 15,
        "applies_if": _PERSONAL_DATA,
        "strong": [
            r"(reasonable|appropriate|adequate|industry[- ]standard)\s+(technical and organi[sz]ational\s+)?(security\s+)?(safeguards|security measures|security practices|measures)",
            r"\bencrypt(ion|ed)\b",
            r"iso\s*/?\s*(iec\s*)?27001",
            r"access controls?",
        ],
        "weak": [r"\bsecurity\b.{0,60}\bdata\b", r"\bdata\b.{0,60}\bsecurity\b", r"\bsafeguard"],
        "gap_text": "no contractual duty to keep reasonable security safeguards for personal data",
        "partial_text": "security is mentioned but specific safeguards (encryption, access control, standards) are not defined",
    },
    {
        "id": "R2",
        "title": "Personal data breach notification",
        "law": "DPDP Act 2023 s.8(6); DPDP Rules 2025 Rule 7 (detailed report within 72 hours)",
        "weight": 12,
        "applies_if": _PERSONAL_DATA,
        "strong": [
            r"(breach|incident).{0,120}(notify|notification|inform|report|intimat).{0,80}\b(\d+|[a-z-]+ \(\d+\))\s*(hours|hrs|days|business days)\b",
            r"(notify|notification|inform|report|intimat).{0,80}\b(\d+|[a-z-]+ \(\d+\))\s*(hours|hrs|days|business days)\b.{0,120}(breach|incident)",
            r"(breach|incident).{0,120}(notify|notification|inform|report|intimat).{0,40}(without (undue )?delay|immediately|promptly)",
        ],
        "weak": [r"(breach|incident).{0,120}(notify|notification|inform|report|intimat)", r"(notify|notification|inform|report).{0,80}(breach|incident)"],
        "gap_text": "no obligation to notify a personal data breach",
        "partial_text": "breach notification is mentioned without a clear timeline",
    },
    {
        "id": "R3",
        "title": "CERT-In incident reporting and log retention",
        "law": "CERT-In Directions dated 28 April 2022 under IT Act 2000 s.70B(6) (6-hour reporting, 180-day logs)",
        "weight": 10,
        "applies_if": _IT_SYSTEMS,
        "strong": [
            r"cert-?\s?in.{0,200}\b(6|six)( \(6\))?\s*hours",
            r"\b(6|six)( \(6\))?\s*hours.{0,200}cert-?\s?in",
            r"logs?.{0,120}\b180\)?\s*days",
            r"\b180\)?\s*days.{0,80}logs?",
        ],
        "weak": [r"cert-?\s?in", r"(incident|security) report(ing)?", r"\blogs?\b.{0,40}(retain|retention|maintain|preserve)"],
        "gap_text": "no CERT-In reporting or log retention obligation",
        "partial_text": "incident reporting or logs are mentioned but the 6-hour CERT-In window or 180-day log retention is not specified",
    },
    {
        "id": "R4",
        "title": "Limitation of liability",
        "law": "Indian Contract Act 1872 ss.73-74",
        "weight": 10,
        "applies_if": None,
        "strong": [
            r"liability.{0,160}(shall not exceed|not exceed|limited to|capped at|cap of|maximum of|in excess of)",
            r"(aggregate|total|maximum|cumulative) liability",
        ],
        "weak": [r"limitation of liability", r"(indirect|consequential|special) (damages|loss)", r"\bliab(le|ility)\b"],
        "gap_text": "liability is not addressed, leaving exposure uncapped",
        "partial_text": "liability is mentioned but no monetary cap is set",
    },
    {
        "id": "R5",
        "title": "Confidentiality and non-disclosure",
        "law": "IT Act 2000 s.72A; Indian Contract Act 1872",
        "weight": 8,
        "applies_if": None,
        "strong": [
            r"confidential information.{0,250}(shall not|must not|will not|not to)\s+(disclose|use|reveal)",
            r"(keep|hold|maintain|treat).{0,40}(in )?(strict )?confiden(ce|tial)",
            r"non-?disclosure",
        ],
        "weak": [r"confidential"],
        "gap_text": "no confidentiality obligation",
        "partial_text": "confidentiality is mentioned but the duty not to disclose is not clearly stated",
    },
    {
        "id": "R6",
        "title": "Intellectual property ownership",
        "law": "Copyright Act 1957 ss.17-19 (ownership and written assignment)",
        "weight": 8,
        "applies_if": None,
        "strong": [
            r"(intellectual property|\bip\b|copyright|source code|deliverables|work product).{0,160}(shall (vest|belong|remain)|vests? (solely )?in|owned (solely |exclusively )?by|hereby assigns?|assignment of|sole (and exclusive )?property|exclusive property)",
            r"(shall (vest|belong|remain)|owned by|hereby assigns?|sole property).{0,160}(intellectual property|copyright|source code|deliverables|work product)",
        ],
        "weak": [r"intellectual property", r"copyright", r"\blicen[cs]e\b"],
        "gap_text": "ownership of intellectual property is not addressed",
        "partial_text": "intellectual property is mentioned but ownership or assignment is not clearly stated",
    },
    {
        "id": "R7",
        "title": "Data retention and deletion",
        "law": "DPDP Act 2023 s.8(7)",
        "weight": 7,
        "applies_if": _PERSONAL_DATA,
        "strong": [
            r"(delete|deletion|erase|erasure|destroy|destruction|return).{0,100}(data|personal data|confidential information|records).{0,120}(termination|expiry|expiration|within \d+|upon request|purpose)",
            r"(termination|expiry|expiration).{0,120}(delete|deletion|erase|destroy|return|hand ?over).{0,100}(data|confidential information|records)",
        ],
        "weak": [r"(retain|retention).{0,60}(data|records|information)", r"\b(delete|erase|destroy)\b"],
        "gap_text": "no rule for returning or deleting data after the purpose ends",
        "partial_text": "data retention is mentioned without a clear deletion or return trigger",
    },
    {
        "id": "R8",
        "title": "Cross-border data transfer",
        "law": "DPDP Act 2023 s.16",
        "weight": 6,
        "applies_if": _PERSONAL_DATA,
        "strong": [r"outside (of )?india", r"cross-?border", r"(stored|hosted|processed|located|reside) (only )?(with)?in india", r"data locali[sz]ation"],
        "weak": [r"transfer.{0,40}(data|personal data|information)", r"(other|foreign) countr"],
        "gap_text": "no terms on transferring or storing data outside India",
        "partial_text": "data transfer is mentioned without addressing transfers outside India",
    },
    {
        "id": "R9",
        "title": "Post-termination non-compete",
        "law": "Indian Contract Act 1872 s.27 (restraint of trade is void)",
        "weight": 10,
        "applies_if": None,
        "inverse": True,
        "strong": [
            r"(non-?compete|not (to )?(compete|engage)|restrain).{0,200}(after|following|post|subsequent to).{0,40}(termination|expiry|expiration|employment|cessation)",
            r"(after|following|post|subsequent to).{0,40}(termination|expiry|expiration|employment).{0,200}(non-?compete|not (to )?(compete|engage in)|competing business)",
            r"(years?|months?) thereafter.{0,200}(shall not|not to)[ ,]+(directly or indirectly[ ,]+)?(provide|engage|compete|carry on|work|render)",
        ],
        "weak": [r"non-?compete", r"shall not compete", r"competing business"],
        "gap_text": "contains a post-termination non-compete that is likely void and unenforceable",
        "partial_text": "contains a non-compete restriction whose scope should be checked",
        "ok_text": "no post-termination restraint of trade found",
    },
    {
        "id": "R10",
        "title": "Service levels with remedies",
        "law": "Indian Contract Act 1872 s.74 (liquidated damages and service credits)",
        "weight": 6,
        "applies_if": _IT_SYSTEMS,
        "strong": [
            r"\b\d{2}(\.\d+)?\s*%.{0,200}(service credit|credits?|penalt|liquidated damages|rebate|refund)",
            r"(service credit|credits?|penalt|liquidated damages|rebate).{0,200}\b\d{2}(\.\d+)?\s*%",
        ],
        "weak": [r"uptime", r"availability", r"service levels?", r"\bsla\b"],
        "gap_text": "no measurable service levels",
        "partial_text": "service levels are mentioned without a remedy (credits or damages) for failure",
    },
    {
        "id": "R11",
        "title": "Termination and exit",
        "law": "Indian Contract Act 1872 (termination rights; exit and transition)",
        "weight": 6,
        "applies_if": None,
        "strong": [
            r"terminat.{0,250}(transition|exit assistance|migration|return (of )?(all )?(the )?(client |customer )?(data|materials|confidential information)|hand ?over)",
            r"(transition|exit assistance|migration|hand ?over).{0,250}terminat",
        ],
        "weak": [r"terminat"],
        "gap_text": "no termination rights",
        "partial_text": "termination is covered but there is no exit, data return or transition support",
    },
    {
        "id": "R12",
        "title": "Governing law and dispute resolution",
        "law": "Arbitration and Conciliation Act 1996; Code of Civil Procedure 1908",
        "weight": 6,
        "applies_if": None,
        "all_of": [r"(governing law|governed by|construed in accordance with) .{0,60}law", r"(arbitrat|exclusive jurisdiction|courts? (at|of|in))"],
        "strong": [],
        "weak": [r"governing law|governed by", r"arbitrat|jurisdiction"],
        "gap_text": "no governing law or dispute resolution clause",
        "partial_text": "only one of governing law or dispute forum is specified",
    },
]


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.;!?])\s+|\n+", text)
    return [p.strip() for p in parts if p.strip()]


def _find(patterns: list[str], text: str) -> Optional[str]:
    lower = text.lower()
    for pattern in patterns:
        m = re.search(pattern, lower, re.DOTALL)
        if m:
            return _evidence(text, m.start(), m.end())
    return None


def _evidence(text: str, start: int, end: int) -> str:
    left = max(text.rfind("\n", 0, start), text.rfind(". ", 0, start) + 1) + 1
    right_candidates = [i for i in (text.find(". ", end), text.find("\n", end)) if i != -1]
    right = min(right_candidates) + 1 if right_candidates else len(text)
    snippet = " ".join(text[left:right].split())
    return snippet[:280] + ("…" if len(snippet) > 280 else "")


def _status(item: dict, text: str) -> tuple[str, str]:
    if item.get("all_of"):
        found = [_find([p], text) for p in item["all_of"]]
        if all(found):
            return "COMPLIANT", found[0]
        weak = _find(item["weak"], text)
        return ("PARTIAL", weak) if weak else ("GAP", "")

    strong = _find(item["strong"], text)
    weak = None if strong else _find(item["weak"], text)

    if item.get("inverse"):
        if strong:
            return "GAP", strong
        if weak:
            return "PARTIAL", weak
        return "COMPLIANT", ""

    if strong:
        return "COMPLIANT", strong
    if weak:
        return "PARTIAL", weak
    return "GAP", ""


SEVERITY_POINTS = {"Critical": 15, "High": 10, "Medium": 5, "Low": 3}

_PARTY = r"(vendor|service provider|supplier|contractor|licensor|developer|consultant|company|client|customer|licensee|employee)"

RED_FLAGS: list[dict] = [
    {
        "id": "F1",
        "title": "Unlimited liability",
        "severity": "Critical",
        "law": "Indian Contract Act 1872 ss.73-74",
        "patterns": [
            r"liability[^.]{0,80}(shall be|is|be|remain) unlimited",
            r"unlimited liability",
            r"(bear|liable|indemnify)[^.]{0,40}without (any )?(upper )?limit",
        ],
        "finding": "one party's liability has no upper limit, including indirect and consequential losses",
    },
    {
        "id": "F2",
        "title": "One-sided liability cap",
        "severity": "High",
        "law": "Indian Contract Act 1872 ss.73-74 (mutuality of risk allocation)",
        "all_of": [
            r"(the )?" + _PARTY + r"'?s? (aggregate |total |maximum )?liability[^.]{0,160}(shall not exceed|limited to|capped at)",
            r"liability[^.]{0,80}(shall be|is) unlimited|unlimited liability|without (any )?(upper )?limit",
        ],
        "finding": "liability is capped for one party while the other party's liability is unlimited",
    },
    {
        "id": "F3",
        "title": "Uncapped liquidated damages",
        "severity": "Critical",
        "law": "Indian Contract Act 1872 s.74 (only reasonable compensation is recoverable)",
        "patterns": [
            r"(liquidated damages|penalt(y|ies)|delay)[^.]{0,250}without (any )?(upper )?(limit|cap)",
            r"per (day|week|month)[^.]{0,120}(without (any )?(upper )?(limit|cap)|no (upper )?(limit|cap))",
        ],
        "finding": "delay damages keep accruing with no ceiling",
    },
    {
        "id": "F4",
        "title": "Damages payable without actual loss",
        "severity": "High",
        "law": "Indian Contract Act 1872 s.74; Kailash Nath Associates v. DDA (2015)",
        "patterns": [
            r"(irrespective|regardless) of whether[^.]{0,80}(suffered|incurred|sustained) any (actual )?loss",
            r"without (having |the need )?(to )?prov(e|ing) (any )?(actual )?(default or )?(loss|damage)",
            r"even if no (actual )?loss",
            r"without[^.]{0,40}(required|need)[^.]{0,40}to prove its loss",
        ],
        "finding": "fixed amounts are claimable even where no actual loss is shown, which courts may refuse to enforce",
    },
    {
        "id": "F5",
        "title": "Large fixed penalty per breach",
        "severity": "Medium",
        "law": "Indian Contract Act 1872 s.74",
        "patterns": [
            r"(liquidated damages|penalty|compensation) of[^.]{0,80}(crore)[^.]{0,60}per (instance|breach|event|occurrence|day)",
            r"(rs\.?|₹|inr)\s?[\d,]{8,}[^.]{0,80}per (instance|breach|event|occurrence)",
        ],
        "finding": "a fixed large amount is payable for each breach regardless of its seriousness",
    },
    {
        "id": "F6",
        "title": "Liability regardless of fault",
        "severity": "High",
        "law": "Indian Contract Act 1872 s.73 (compensation only for loss caused by the breach)",
        "patterns": [
            r"whether or not the " + _PARTY + r"[^.]{0,40}(was |is )?(at fault|negligent|responsible|in breach)",
            r"(irrespective|regardless) of (any )?(fault|negligence|cause|whether)[^.]{0,40}(fault|negligen)",
        ],
        "finding": "one party must pay for incidents even when it is not at fault",
    },
    {
        "id": "F7",
        "title": "Personal guarantee by directors",
        "severity": "High",
        "law": "Indian Contract Act 1872 ss.126-128 (contract of guarantee)",
        "patterns": [r"guarantors?[^.]{0,60}(jointly and severally,? )?(irrevocably and unconditionally )?guarantee", r"directors?[^.]{0,80}(personally )?guarantee", r"personal guarant"],
        "finding": "individual directors become personally liable for the company's obligations",
    },
    {
        "id": "F8",
        "title": "Waiver of statutory protections",
        "severity": "High",
        "law": "MSMED Act 2006 ss.15-16; Copyright Act 1957 s.19(4); Indian Contract Act 1872 ss.133-141",
        "patterns": [
            r"waives?[^.]{0,160}(micro, small and medium|msme|interest on (delayed|late) payment)",
            r"notwithstanding section 19\s?\(4\)",
            r"waive[^.]{0,80}rights available to sureties|sections? 133 to 141",
            r"waives? (all |any )?(statutory|legal) (rights|protections|remedies)",
        ],
        "finding": "a party gives up protections that Indian law grants it",
    },
    {
        "id": "F9",
        "title": "Unilateral appointment of arbitrator",
        "severity": "Critical",
        "law": "Arbitration and Conciliation Act 1996 s.12(5); Perkins Eastman v. HSCC (2019); CORE v. ECI-SPIC-SMO-MCML (2024)",
        "patterns": [
            r"arbitrat(or|ion)[^.]{0,80}appointed by (the )?(managing director|md|chairman|ceo|chief executive|director)[^.]{0,20}(of )?(the )?",
            r"arbitrator[^.]{0,40}(appointed|nominated) (solely |exclusively )?by (the )?" + _PARTY,
            r"(managing director|chairman|ceo)[^.]{0,60}(shall )?(appoint|nominate)[^.]{0,30}arbitrator",
        ],
        "finding": "one side alone picks the arbitrator, which the Supreme Court has held impermissible",
    },
    {
        "id": "F10",
        "title": "One-sided termination rights",
        "severity": "High",
        "law": "Indian Contract Act 1872 (mutuality; unconscionable terms)",
        "patterns": [
            r"shall not (have any|be entitled to|have the) right to terminate",
            r"no right to terminate",
            r"may not terminate (this agreement )?(for any reason|under any circumstances)",
        ],
        "finding": "one party can exit easily while the other party can never terminate",
    },
    {
        "id": "F11",
        "title": "Bank guarantee invocable without notice or proof",
        "severity": "High",
        "law": "Indian Contract Act 1872; unconditional bank guarantee practice",
        "patterns": [
            r"invoke[^.]{0,60}(bank|performance) guarantee[^.]{0,160}without (any )?(prior )?notice",
            r"(bank|performance) guarantee[^.]{0,160}without having to prove",
        ],
        "finding": "the security deposit can be encashed at any time without notice or proof of default",
    },
    {
        "id": "F12",
        "title": "Delayed or withheld payment",
        "severity": "Medium",
        "law": "MSMED Act 2006 s.15 (payment within 45 days to micro and small suppliers)",
        "patterns": [
            r"\(?\b(4[6-9]|[5-9]\d|\d{3})\)? days of (receipt of )?(a |the )?(valid )?invoice",
            r"may withhold[^.]{0,80}payment",
            r"set off any amount claimed",
        ],
        "finding": "payment can be delayed beyond 45 days, withheld or set off against disputed claims",
    },
    {
        "id": "F13",
        "title": "Unilateral control over scope and acceptance",
        "severity": "Medium",
        "law": "Indian Contract Act 1872 s.29 (uncertain terms)",
        "patterns": [
            r"reject any deliverable for any reason",
            r"acceptance criteria[^.]{0,80}(define|modify|supplement) at any time",
            r"no deemed acceptance",
            r"(sole|absolute) (and absolute )?discretion",
        ],
        "finding": "one party alone decides what is acceptable and can change the requirements at any time",
    },
    {
        "id": "F14",
        "title": "Transfer of pre-existing IP",
        "severity": "Medium",
        "law": "Copyright Act 1957 ss.18-19",
        "patterns": [r"assigns?[^.]{0,160}pre-?existing", r"pre-?existing[^.]{0,120}(shall vest|assigned|transferred)", r"background ip[^.]{0,80}(assign|vest)"],
        "finding": "the supplier loses ownership of tools and code it created before this contract",
    },
    {
        "id": "F15",
        "title": "Arbitration pre-deposit or one-sided costs",
        "severity": "High",
        "law": "ICOMM Tele Ltd. v. Punjab State Water Supply & Sewerage Board (2019)",
        "patterns": [
            r"deposit[^.]{0,80}(\d+\s?%|percent)[^.]{0,120}(pre-?condition|before)",
            r"bear all costs of (the )?arbitration[^.]{0,40}irrespective of the outcome",
        ],
        "finding": "a party must pay a deposit or all costs just to contest a claim",
    },
]


def _flag_status(flag: dict, text: str) -> tuple[Optional[str], int]:
    if flag.get("all_of"):
        found = [_find([p], text) for p in flag["all_of"]]
        return (found[0], 1) if all(found) else (None, 0)
    hits = [e for e in (_find([p], text) for p in flag["patterns"]) if e]
    unique = list(dict.fromkeys(hits))
    return (unique[0], len(unique)) if unique else (None, 0)


def _band(score: int) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


def _short(evidence: str, limit: int = 180) -> str:
    return evidence if len(evidence) <= limit else evidence[:limit].rsplit(" ", 1)[0] + "…"


def assess_risk(text: str) -> dict:
    text = text or ""
    lower = text.lower()
    checklist, findings = [], []
    for item in RISK_CHECKLIST:
        applies = not item["applies_if"] or re.search(item["applies_if"], lower) is not None
        if not applies:
            checklist.append({
                "id": item["id"], "title": item["title"], "law": item["law"], "weight": item["weight"],
                "status": "NOT_APPLICABLE", "evidence": "", "finding": "not applicable to this document", "points": 0,
            })
            continue
        status, evidence = _status(item, text)
        points = item["weight"] * STATUS_FACTOR[status]
        if status == "GAP":
            finding = item["gap_text"]
        elif status == "PARTIAL":
            finding = item["partial_text"]
        else:
            finding = item.get("ok_text", "adequately addressed")
        entry = {
            "id": item["id"], "title": item["title"], "law": item["law"], "weight": item["weight"],
            "status": status, "evidence": evidence, "finding": finding, "points": points,
        }
        checklist.append(entry)
        if status in ("GAP", "PARTIAL"):
            severity = "High" if item["weight"] >= 12 else "Medium" if item["weight"] >= 8 else "Low"
            findings.append({**entry, "severity": severity, "kind": "gap"})

    red_flags = []
    for flag in RED_FLAGS:
        evidence, count = _flag_status(flag, text)
        if not evidence:
            continue
        finding = flag["finding"] + (f" (found in {count} places)" if count > 1 else "")
        entry = {
            "id": flag["id"], "title": flag["title"], "law": flag["law"], "severity": flag["severity"],
            "status": "RED_FLAG", "evidence": evidence, "finding": finding,
            "points": SEVERITY_POINTS[flag["severity"]], "kind": "flag",
        }
        red_flags.append(entry)
        findings.append(entry)

    total = sum(f["points"] for f in findings)
    score = min(100, round(total))
    if any(f["severity"] == "Critical" for f in red_flags):
        score = max(score, 61)

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: (order[f["severity"]], -f["points"]))
    risks = []
    for f in findings:
        line = f"[{f['severity']}] {f['title']}: {f['finding']}."
        if f["evidence"]:
            line += f' Contract says: "{_short(f["evidence"])}"'
        line += f" Legal basis: {f['law']}."
        risks.append(line)

    return {
        "risk_score": score,
        "risk_band": _band(score),
        "risks": risks,
        "risk_checklist": checklist,
        "red_flags": red_flags,
        "rubric_version": RUBRIC_VERSION,
    }


def findings_for_prompt(assessment: dict) -> str:
    lines = [f"Rule-based risk score: {assessment['risk_score']}/100 ({assessment['risk_band']} risk)."]
    for f in assessment.get("red_flags", []):
        lines.append(f"- {f['id']} {f['title']} [RED FLAG, {f['severity']}]: {f['finding']} ({f['law']})")
    for c in assessment["risk_checklist"]:
        if c["status"] in ("GAP", "PARTIAL"):
            lines.append(f"- {c['id']} {c['title']} [{c['status']}]: {c['finding']} ({c['law']})")
    return "\n".join(lines)