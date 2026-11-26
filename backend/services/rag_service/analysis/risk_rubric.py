import re
from typing import Optional

RUBRIC_VERSION = "1.7"

STATUS_FACTOR = {"GAP": 1.0, "PARTIAL": 0.5, "COMPLIANT": 0.0}

_PERSONAL_DATA = r"personal data|personal information|customer data|user data|\bpii\b|data principal|data fiduciary|data processor|processing of (personal )?data|sensitive personal|\b(student|parent|patient|employee|candidate|applicant|subscriber|member)s? (and \w+ )?(data|records|details)\b|names?, (e-?mail|email|mobile|phone|contact|postal)"
_IT_SYSTEMS = r"hosting|cloud|server|infrastructure|software|saas|platform|it services|system|network|cyber|incident"
_NDA_TITLE = r"non-?disclosure agreement|confidentiality agreement|\bnda\b"

RISK_CHECKLIST: list[dict] = [
    {
        "id": "R1",
        "title": "Reasonable security safeguards",
        "law": "DPDP Act 2023 s.8(5); DPDP Rules 2025 Rule 6; IT Act 2000 s.43A",
        "weight": 15,
        "applies_if": _PERSONAL_DATA,
        "strong": [
            r"reasonable\s+(technical and organi[sz]ational\s+)?security\s+(safeguards|practices)",
            r"\bencrypt(ion|ed|s)?\b",
            r"iso\s*/?\s*(iec\s*)?27001",
            r"access controls?",
        ],
        "weak": [r"(reasonable|appropriate|adequate|industry[- ]standard)\s+(technical and organi[sz]ational\s+)?(security\s+)?(safeguards|security measures|security practices|measures)", r"\bsecurity\b.{0,60}\bdata\b", r"\bdata\b.{0,60}\bsecurity\b", r"\bsafeguard"],
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
            r"(breach|incident|unauthori[sz]ed (use|disclosure|access)).{0,160}(notify|notification|inform|report|intimat).{0,80}\b(\d+|[a-z-]+ \(\d+\))\s*(hours|hrs|days|business days)\b",
            r"(notify|notification|inform|report|intimat).{0,80}\b(\d+|[a-z-]+ \(\d+\))\s*(hours|hrs|days|business days)\b.{0,120}(breach|incident|unauthori[sz]ed (use|disclosure|access))",
            r"(notify|notification|inform|report|intimat).{0,120}(breach|incident).{0,120}\b(\d+|[a-z-]+ \(\d+\))\s*(hours|hrs|days|business days)\b",
        ],
        "weak": [r"(breach|incident).{0,120}(notify|notification|inform|report|intimat)", r"(notify|notification|inform|report).{0,80}(breach|incident)"],
        "gap_text": "no obligation to notify a personal data breach",
        "partial_text": "breach notification is mentioned without a clear timeline",
    },
    {
        "id": "R3",
        "title": "CERT-In incident reporting and log retention",
        "skip_for_nda": True,
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
        "issue_flags": ["F1", "F2"],
        "issue_text": "liability is capped for one party only, or one party's liability is unlimited",
        "weak": [r"no cap on.{0,40}liabilit", r"liabilit.{0,60}(is|shall be) (not limited|uncapped)", r"limitation of liability", r"(indirect|consequential|special) (damages|loss)", r"\bliab(le|ility)\b"],
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
            r"confidential information only (for|to)",
            r"disclose (it|such information|the same) only to",
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
            r"(intellectual property|\bip\b|copyright|source code|deliverables|work product).{0,160}(shall (vest|belong|remain)|vests? (solely )?in|owned (solely |exclusively )?by|hereby assigns?|assignment of|shall be (assigned|transferred)|sole (and exclusive )?property|exclusive property)",
            r"retains? all (rights|right, title and interest)",
            r"(shall (vest|belong|remain)|owned by|hereby assigns?|sole property).{0,160}(intellectual property|copyright|source code|deliverables|work product)",
            r"(confidential information|intellectual property|deliverables).{0,40}remains? the (sole |exclusive )?property of",
        ],
        "issue_flags": ["F14"],
        "issue_text": "the supplier's pre-existing tools or IP are transferred to the other party",
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
            r"(deletion|destruction) certificate|certif(y|ies|ication of) (the )?(deletion|destruction)",
        ],
        "issue": [
            r"(retained|kept|stored) for.{0,40}after (termination|expiry).{0,60}(may|will) (delete|erase|destroy)",
            r"may (delete|erase|destroy).{0,60}without (further |prior )?notice",
        ],
        "issue_text": "data may be deleted by one party shortly after termination without a proper return",
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
        "issue": [r"(may|can|will) (be )?(store|stored|process|processed|host|hosted|transfer|transferred|replicate|replicated)( and (store|stored|process|processed))?.{0,60}(in any country|anywhere|overseas|abroad)"],
        "issue_text": "data may be stored or processed in any country without safeguards",
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
        "skip_for_nda": True,
        "law": "Indian Contract Act 1872 s.74 (liquidated damages and service credits)",
        "weight": 6,
        "applies_if": _IT_SYSTEMS,
        "strong": [
            r"\b\d{2}(\.\d+)?\s*%.{0,200}(service credit|credits?|penalt|liquidated damages|rebate|refund)",
            r"(service credit|credits?|penalt|liquidated damages|rebate).{0,200}\b\d{2}(\.\d+)?\s*%",
        ],
        "issue": [r"(credits?|remed(y|ies)).{0,60}sole (and exclusive )?remedy", r"sole (and exclusive )?remedy.{0,60}(credits?|service levels?)"],
        "issue_text": "service credits are the only remedy for failure to meet service levels",
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
            r"terminat.{0,250}(transition|exit assistance|migration|return (or (securely )?(destroy|delete) )?(of )?(all )?(the )?(client |customer )?(data|materials|confidential information)|hand ?over)",
            r"(transition|exit assistance|migration|hand ?over).{0,250}terminat",
        ],
        "issue_flags": ["F10", "F16"],
        "issue_text": "only one party may terminate freely, or exit rights are unequal",
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


_IN_SENTENCE = r"(?:[^.\n]|\.(?=\S))"


def _within_sentence(pattern: str) -> str:
    pattern = re.sub(r"(?<!\\)\.\{", lambda m: _IN_SENTENCE + "{", pattern)
    return pattern.replace("[^.]{", _IN_SENTENCE + "{")


def _find(patterns: list[str], text: str) -> Optional[str]:
    lower = text.lower()
    for pattern in patterns:
        m = re.search(_within_sentence(pattern), lower)
        if m:
            return _evidence(text, m.start(), m.end())
    return None


def _evidence(text: str, start: int, end: int) -> str:
    newline = text.rfind("\n", 0, start)
    stop = text.rfind(". ", 0, start)
    left = max(newline + 1, stop + 2 if stop != -1 else 0)
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

RESIDUAL_RISK = 0

_PARTY = r"(vendor|service provider|provider|supplier|contractor|licensor|developer|consultant|company|client|customer|licensee|employee)"

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
            r"shall be liable for all (losses|damages|claims|costs)",
        ],
        "finding": "one party's liability has no upper limit, including indirect and consequential losses",
    },
    {
        "id": "F2",
        "title": "One-sided liability cap",
        "severity": "High",
        "law": "Indian Contract Act 1872 ss.73-74 (mutuality of risk allocation)",
        "all_of": [
            r"(the )?" + _PARTY + r"'?s? (aggregate |total |maximum )?liability[^.]{0,160}(shall not exceed|limited to|capped at)|(total|aggregate|maximum) liability of the " + _PARTY + r"[^.]{0,160}(shall not exceed|limited to|capped at)",
            r"liability[^.]{0,80}(shall be|is) unlimited|unlimited liability|without (any )?(upper )?limit|shall be liable for all (losses|damages|claims|costs)",
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
            r"without[^.]{0,60}(required|need|obliged|having) to prove[^.]{0,20}(actual )?(loss|damage)",
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
        "one_sided": "terminate",
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
        "title": "Long, withheld or set-off payments",
        "severity": "Medium",
        "law": "MSMED Act 2006 s.15 (payment within 45 days, if the supplier is a micro or small enterprise)",
        "patterns": [
            r"\(?\b(4[6-9]|[5-9]\d|\d{3})\)? days of (receipt of )?(a |the )?(valid )?invoice",
            r"may withhold[^.]{0,80}payment",
            r"set off any amount claimed",
        ],
        "finding": "payment terms favour the payer: longer than 45 days, or payments can be withheld or set off",
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
            r"(the )?" + _PARTY + r" shall bear (all |the )?(costs|expenses) of (the )?arbitration",
        ],
        "finding": "a party must pay a deposit or all costs just to contest a claim",
    },
    {
        "id": "F16",
        "title": "Unequal termination for convenience",
        "severity": "Medium",
        "law": "Indian Contract Act 1872 (mutuality of exit rights)",
        "all_of": [
            r"(client|customer|company|licensee) may terminate[^.]{0,80}for convenience",
            r"(service provider|vendor|supplier|contractor|licensor|developer) may terminate[^.]{0,80}for convenience only|(service provider|vendor|supplier|contractor)[^.]{0,40}(may not|shall not|cannot) terminate[^.]{0,40}for convenience",
        ],
        "one_sided": "convenience",
        "finding": "one party can leave for convenience much more easily, or much sooner, than the other",
    },
    {
        "id": "F17",
        "title": "Delayed or restricted deemed acceptance",
        "severity": "Medium",
        "law": "Indian Contract Act 1872 s.29 (uncertain terms); payment linked to acceptance",
        "patterns": [
            r"(deemed|treated as|considered) accepted only (when|if|after|upon)",
            r"deemed accept(ed|ance)[^.]{0,120}(live production|in production|commercial use)[^.]{0,60}(\d+|[a-z-]+ \(\d+\)) (consecutive )?days",
        ],
        "finding": "work counts as accepted only after a long period of live use, which delays milestone payments",
    },
    {
        "id": "F18",
        "title": "Free additional work",
        "severity": "Medium",
        "law": "Indian Contract Act 1872 s.2(d) (consideration); change control",
        "patterns": [
            r"implement[^.]{0,40}changes[^.]{0,160}(at no additional charge|without (any )?additional charge|free of charge)",
            r"person-?hours[^.]{0,80}(at no additional charge|free of charge|without (any )?additional charge)",
            r"implement[^.]{0,40}changes[^.]{0,80}without (any )?(increase|additional|extra) (in )?(fees|charges?|cost|price)",
        ],
        "finding": "the supplier must do extra change work without being paid for it",
    },
    {
        "id": "F19",
        "title": "One-sided right to assign",
        "severity": "Low",
        "law": "Indian Contract Act 1872 (assignment of contractual rights)",
        "patterns": [r"(the )?(client|customer|company|licensee) may assign[^.]{0,80}(on (written )?notice|without (the other party's )?consent)"],
        "one_sided": "assign",
        "finding": "only one party may transfer the contract without the other's consent",
    },
    {
        "id": "F20",
        "title": "Automatic renewal",
        "severity": "Low",
        "law": "Indian Contract Act 1872 (renewal terms)",
        "patterns": [r"automatically renew", r"(shall|will) (be )?automatically (renewed|extended)", r"renews? automatically", r"automatic renewal"],
        "finding": "the contract renews by itself unless notice is given in time",
    },
    {
        "id": "F21",
        "title": "One-sided costs",
        "severity": "Low",
        "law": "Indian Stamp Act 1899 / Delhi stamp rules (allocation of stamp duty)",
        "patterns": [r"stamp duty[^.]{0,80}borne (solely )?by the (service provider|vendor|supplier|contractor|licensor|developer)"],
        "finding": "one party alone pays costs, such as stamp duty, that are usually shared",
    },
    {
        "id": "F22",
        "title": "Short notice deadline to claim relief",
        "severity": "Low",
        "law": "Indian Contract Act 1872 s.28 (time limits on enforcing rights)",
        "patterns": [r"(not (be )?responsible|not liable|relieved)[^.]{0,160}provided (that )?it notifies[^.]{0,80}within (\d+|[a-z-]+ \(\d+\))"],
        "finding": "a party loses protection for delays it did not cause unless it gives notice within a short deadline",
    },
]


_ROLES = ["service provider", "provider", "vendor", "supplier", "contractor", "licensor", "developer", "consultant", "company", "client", "customer", "licensee"]
_MODAL = r"(may|can|shall be entitled to|shall have the right to|has the right to|is entitled to|reserves the right to)"
_DENY = r"(may not|shall not|cannot|will not|is not entitled to)"
_VERBS = {"terminate": r"terminat", "convenience": r"terminat", "assign": r"(assign|transfer|novate)"}
_FREE = r"for convenience|for any reason|at any time|without (any )?(cause|reason)|without assigning any reason"


def _roles(lower: str) -> list[str]:
    counts = {}
    for role in _ROLES:
        n = len(re.findall(r"\bthe " + role + r"\b", lower))
        if role == "provider":
            n -= len(re.findall(r"\bthe service provider\b", lower))
        if n >= 2:
            counts[role] = n
    return sorted(counts, key=counts.get, reverse=True)[:2]


def _one_sided(kind: str, text: str) -> Optional[str]:
    lower = text.lower()
    roles = _roles(lower)
    if len(roles) < 2:
        return None
    verb = _VERBS[kind]
    sentences = _sentences(lower)
    mutual = [s for s in sentences if re.search(r"\b(either|each|both|any) part(y|ies)\b[^.]{0,40}\b" + _MODAL + r"\b[^.]{0,20}\b" + verb, s) or re.search(verb + r"\w*[^.]{0,40}\bby (either|each|any) part", s)]
    if mutual and (kind != "convenience" or any(re.search(_FREE, s) for s in mutual)):
        return None
    rights = {}
    for role in roles:
        found = []
        for s in sentences:
            if not re.search(r"\b" + role + r"\b[^.]{0,40}\b" + _MODAL + r"\b[^.]{0,20}\b" + verb, s):
                continue
            if re.search(r"\b" + role + r"\b[^.]{0,40}\b" + _DENY + r"\b[^.]{0,20}\b" + verb, s):
                continue
            if kind == "assign" and re.search(r"\bwith (the )?(\w+'s )?(prior )?(written )?(consent|approval)|only with", s):
                continue
            found.append(s)
        rights[role] = found
    a, b = roles
    for strong, weak in ((a, b), (b, a)):
        if kind == "convenience":
            free = [s for s in rights[strong] if re.search(_FREE, s)]
            if free and rights[weak] and not any(re.search(_FREE, s) for s in rights[weak]):
                return _find([re.escape(free[0][:60])], text) or free[0]
        elif rights[strong] and not rights[weak]:
            return _find([re.escape(rights[strong][0][:60])], text) or rights[strong][0]
    return None


def _flag_status(flag: dict, text: str) -> tuple[Optional[str], int]:
    if flag.get("all_of"):
        found = [_find([p], text) for p in flag["all_of"]]
        if all(found):
            return found[0], 1
        hit = _one_sided(flag["one_sided"], text) if flag.get("one_sided") else None
        return (hit, 1) if hit else (None, 0)
    hits = [e for e in (_find([p], text) for p in flag["patterns"]) if e]
    if not hits and flag.get("one_sided"):
        hit = _one_sided(flag["one_sided"], text)
        hits = [hit] if hit else []
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
    is_nda = re.search(_NDA_TITLE, lower[:400]) is not None
    flagged = {flag["id"]: _flag_status(flag, text) for flag in RED_FLAGS}
    for item in RISK_CHECKLIST:
        applies = not item["applies_if"] or re.search(item["applies_if"], lower) is not None
        if is_nda and item.get("skip_for_nda"):
            applies = False
        if not applies:
            checklist.append({
                "id": item["id"], "title": item["title"], "law": item["law"], "weight": item["weight"],
                "status": "NOT_APPLICABLE", "evidence": "", "finding": "not applicable to this document", "points": 0,
            })
            continue
        status, evidence = _status(item, text)
        issue = None
        if status == "COMPLIANT" and not item.get("inverse"):
            issue = _find(item.get("issue", []), text) or next((flagged[f][0] for f in item.get("issue_flags", []) if flagged[f][0]), None)
            if issue:
                status, evidence = "PARTIAL", issue
        points = item["weight"] * STATUS_FACTOR[status]
        if status == "GAP":
            finding = item["gap_text"]
        elif issue:
            finding = item["issue_text"]
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
        evidence, count = flagged[flag["id"]]
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
    score = max(RESIDUAL_RISK, min(100, round(total)))
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
        lines.append(f"- {f['title']} [unfair clause, {f['severity']}]: {f['finding']} ({f['law']})")
    for c in assessment["risk_checklist"]:
        if c["status"] in ("GAP", "PARTIAL"):
            lines.append(f"- {c['title']} [{'missing' if c['status'] == 'GAP' else 'partly addressed'}]: {c['finding']} ({c['law']})")
    return "\n".join(lines)