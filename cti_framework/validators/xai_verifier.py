"""
Explainable AI (xAI) & Trust Verification Engine for CTI Framework.
Provides deterministic text matching, defang normalization, context assessment,
provenance hash tracking, claim grounding, and multi-factor trust scoring.
"""

import re
import ast
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

# RFC 5737 and private IP ranges
BENIGN_DNS_SERVERS = {
    "8.8.8.8", "8.8.4.4",          # Google Public DNS
    "1.1.1.1", "1.0.0.1",          # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",  # Quad9
    "208.67.222.222", "208.67.220.220" # OpenDNS
}

BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "cloudflare.com", "cisa.gov", "nist.gov", "virustotal.com",
    "abuse.ch", "example.com", "example.org", "test.com", "localhost"
}

MALICIOUS_KEYWORDS = [
    "c2", "command and control", "command-and-control", "beacon", "backdoor",
    "malware", "payload", "ransomware", "trojan", "infostealer", "stealer",
    "dropped", "exfiltration", "exploit", "compromised", "infected", "phishing",
    "threat actor", "botnet", "downloader", "cobalt strike", "rat", "reverse shell",
    "malicious", "attack", "attacker", "threat", "adversary", "exploit"
]

BENIGN_OR_EXAMPLE_KEYWORDS = [
    "example", "test", "testing", "documentation", "rfc 5737", "rfc 1918",
    "dummy", "placeholder", "public dns", "legitimate", "sample ip", "mock"
]


def calculate_sha256(text: str) -> str:
    """Calculate SHA-256 hash of a string."""
    if text is None:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_defanged(indicator: str) -> str:
    """
    Normalizes defanged IoCs to canonical format:
    hxxp:// -> http://
    1[.]1[.]1[.]1 -> 1.1.1.1
    example[.]com -> example.com
    """
    if not indicator:
        return ""
    val = indicator.strip()
    val = re.sub(r'hxxps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', val, flags=re.IGNORECASE)
    val = val.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("{.}", ".")
    val = val.replace("[:]", ":").replace("(:)", ":")
    val = val.replace("[at]", "@").replace("(@)", "@")
    return val


def is_rfc_example_or_private_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address is part of RFC 5737 (testnet), RFC 1918 (private),
    RFC 3330 (special/mock), or loopback.
    Returns (is_special, reason).
    """
    try:
        # Strip potential port
        clean_ip = ip_str.split(":")[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        
        # RFC 5737: 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
        testnet1 = ipaddress.ip_network("192.0.2.0/24")
        testnet2 = ipaddress.ip_network("198.51.100.0/24")
        testnet3 = ipaddress.ip_network("203.0.113.0/24")
        
        if ip_obj in testnet1 or ip_obj in testnet2 or ip_obj in testnet3:
            return True, "RFC 5737 Documentation / Testnet IP (Non-routable)"
            
        if ip_obj.is_private:
            return True, "RFC 1918 Private Network Address"
            
        if ip_obj.is_loopback:
            return True, "RFC 3330 Loopback Address (127.0.0.0/8)"
            
        if clean_ip in ("1.2.3.4", "0.0.0.0", "255.255.255.255"):
            return True, "Mock / Test Placeholder Address"
            
        return False, ""
    except ValueError:
        return False, ""


def find_indicator_in_text(indicator: str, raw_text: str) -> Tuple[str, int, int, str]:
    """
    Search for indicator in raw text with exact and normalized matching.
    Returns (match_status: 'exact_match'|'normalized_match'|'not_found',
             start_offset, end_offset, matched_string).
    """
    if not raw_text or not indicator:
        return "not_found", -1, -1, ""

    raw_lower = raw_text.lower()
    ind_lower = indicator.lower()

    # 1. Exact match (case-sensitive)
    pos = raw_text.find(indicator)
    if pos != -1:
        return "exact_match", pos, pos + len(indicator), indicator

    # 2. Case-insensitive exact match
    pos = raw_lower.find(ind_lower)
    if pos != -1:
        matched_str = raw_text[pos:pos + len(indicator)]
        return "exact_match", pos, pos + len(indicator), matched_str

    # 3. Normalized match: check defanged variants in text
    # e.g., indicator is 1.1.1.1, text contains 1[.]1[.]1[.]1
    defanged_patterns = [
        indicator.replace(".", "[.]"),
        indicator.replace(".", "(.)"),
        indicator.replace("http://", "hxxp://"),
        indicator.replace("https://", "hxxps://"),
    ]
    for pattern in defanged_patterns:
        pos = raw_text.find(pattern)
        if pos != -1:
            return "normalized_match", pos, pos + len(pattern), pattern
        pos = raw_lower.find(pattern.lower())
        if pos != -1:
            return "normalized_match", pos, pos + len(pattern), raw_text[pos:pos + len(pattern)]

    # 4. Normalized match: indicator was defanged, text contains clean
    clean_ind = normalize_defanged(indicator)
    if clean_ind != indicator:
        pos = raw_text.find(clean_ind)
        if pos != -1:
            return "normalized_match", pos, pos + len(clean_ind), clean_ind
        pos = raw_lower.find(clean_ind.lower())
        if pos != -1:
            return "normalized_match", pos, pos + len(clean_ind), raw_text[pos:pos + len(clean_ind)]

    return "not_found", -1, -1, ""


def extract_context_quote(raw_text: str, start_idx: int, end_idx: int, window_chars: int = 150) -> Tuple[str, str]:
    """
    Extracts a verbatim quote and context window strictly from raw text around offsets.
    Returns (exact_quote, context_window).
    """
    if not raw_text or start_idx < 0 or end_idx <= start_idx:
        return "", ""

    # Exact token quote
    exact_quote = raw_text[start_idx:end_idx]

    # Context window around the token
    left_bound = max(0, start_idx - window_chars)
    right_bound = min(len(raw_text), end_idx + window_chars)
    context_window = raw_text[left_bound:right_bound].strip()

    return exact_quote, context_window


def assess_indicator_maliciousness(indicator: str, indicator_type: str,
                                   context_window: str, source_match_status: str) -> Tuple[str, str, str]:
    """
    Evaluates whether the indicator in context is confirmed malicious,
    mentioned without confirmation, an example/benign entity, or insufficient evidence.
    Returns (maliciousness_status, context_assessment, notes).
    """
    if source_match_status == "not_found":
        return "insufficient_evidence", "Indicator not found in source text.", "AI Hallucination or regex extraction artifact."

    clean_val = normalize_defanged(indicator).lower()
    ctx_lower = context_window.lower()

    # Check 1: RFC 5737 / RFC 1918 / Private / Mock IPs
    if indicator_type.lower() == "ipv4":
        is_special, reason = is_rfc_example_or_private_ip(clean_val)
        if is_special:
            return "example_or_benign", f"Identified as {reason}.", f"IP belongs to test/private space ({clean_val}). Do not block."

    # Check 2: Known Public Benign DNS / Infrastructure
    if clean_val in BENIGN_DNS_SERVERS or clean_val in BENIGN_DOMAINS:
        for kw in MALICIOUS_KEYWORDS:
            if kw in ctx_lower:
                return "mentioned_not_confirmed", f"Legitimate infrastructure ({clean_val}) mentioned in threat context.", "Service likely abused or cited as reference. Not inherently malicious."
        return "example_or_benign", f"Known public benign service ({clean_val}).", "Benign infrastructure."

    # Check 3: Check for example / benign keywords near the indicator
    for kw in BENIGN_OR_EXAMPLE_KEYWORDS:
        if kw in ctx_lower:
            return "example_or_benign", f"Context explicitly indicates testing or sample data (found '{kw}').", "Not an active threat indicator."

    # Check 4: Check for malicious keywords in proximity
    matched_malicious_keywords = [kw for kw in MALICIOUS_KEYWORDS if kw in ctx_lower]
    if matched_malicious_keywords:
        kw_str = ", ".join(matched_malicious_keywords[:3])
        return "maliciousness_confirmed", f"Strong malicious context detected (associated with: {kw_str}).", "Source explicitly associates indicator with cyber threat activity."

    # Neutral mention without explicit malicious attribution
    return "mentioned_not_confirmed", "Indicator appears in text but without explicit malicious attribution.", "Context lacks conclusive threat evidence."


def compute_multi_factor_trust_score(source_match_status: str,
                                     maliciousness_status: str,
                                     external_verification_status: str = "unverified",
                                     published_date: Optional[str] = None) -> Tuple[float, str]:
    """
    Calculates multi-factor calibrated trust score (0.0 - 1.0).
    Components:
    - Match Score (weight 0.35)
    - Evidence Quality Score (weight 0.35)
    - Cross-check Score (weight 0.15)
    - Freshness Score (weight 0.15)
    Returns (score: 0.0 - 1.0, trust_status: 'verified'|'partially_verified'|'unverified'|'rejected')
    """
    # 1. Match score (0.35)
    if source_match_status == "exact_match":
        s_match = 1.0
    elif source_match_status == "normalized_match":
        s_match = 0.85
    else:
        # Not found in source -> strictly rejected
        return 0.0, "rejected"

    # 2. Evidence score (0.35)
    if maliciousness_status == "maliciousness_confirmed":
        s_evidence = 1.0
    elif maliciousness_status == "mentioned_not_confirmed":
        s_evidence = 0.40
    elif maliciousness_status == "insufficient_evidence":
        s_evidence = 0.20
    else:  # example_or_benign
        s_evidence = 0.05

    # 3. Cross check score (0.15)
    ext_lower = external_verification_status.lower()
    if "cisa" in ext_lower or "abuse_ch" in ext_lower or "vt_confirmed" in ext_lower:
        s_cross = 1.0
    elif ext_lower == "observed":
        s_cross = 0.6
    else:
        s_cross = 0.4

    # 4. Freshness score (0.15)
    s_fresh = 0.8  # default baseline
    if published_date:
        try:
            # parse date if possible
            pub_dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - pub_dt).days
            if age_days <= 7:
                s_fresh = 1.0
            elif age_days <= 30:
                s_fresh = 0.75
            elif age_days <= 90:
                s_fresh = 0.50
            else:
                s_fresh = 0.30
        except Exception:
            s_fresh = 0.7

    score = (0.35 * s_match) + (0.35 * s_evidence) + (0.15 * s_cross) + (0.15 * s_fresh)
    score = round(score, 3)

    # Determine structured trust status
    if s_match >= 0.85 and maliciousness_status == "maliciousness_confirmed":
        trust_status = "verified"
    elif s_match >= 0.85 and maliciousness_status in ("mentioned_not_confirmed", "example_or_benign", "insufficient_evidence"):
        trust_status = "partially_verified"
    else:
        trust_status = "rejected"

    return score, trust_status


class XAIVerifier:
    """Core xAI & Grounding Verifier Engine for CTI Framework."""

    def __init__(self, storage_manager=None):
        self.storage = storage_manager

    def verify_source_document(self, raw_content: str, source_url: str,
                               source_title: str = "", source_publisher: str = "",
                               published_at: Optional[str] = None, http_status: int = 200,
                               fetch_error: Optional[str] = None) -> Dict[str, Any]:
        """
        Validates data provenance for fetched source articles.
        Enforces content hashing and prevents fabricated source claims.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # Check HTTP status & reachability
        if http_status != 200 or fetch_error:
            status = "http_error" if (http_status and http_status != 200) else "unreachable"
            return {
                "source_url": source_url,
                "source_title": source_title,
                "source_publisher": source_publisher or "Unknown",
                "published_at": published_at,
                "fetched_at": now_iso,
                "http_status": http_status,
                "content_hash": "",
                "raw_content": "",
                "fetch_status": status,
                "fetch_error": fetch_error or f"HTTP status code {http_status}"
            }

        if not raw_content or not raw_content.strip():
            return {
                "source_url": source_url,
                "source_title": source_title,
                "source_publisher": source_publisher or "Unknown",
                "published_at": published_at,
                "fetched_at": now_iso,
                "http_status": 200,
                "content_hash": "",
                "raw_content": "",
                "fetch_status": "empty_content",
                "fetch_error": "Received 200 OK but source body is completely empty."
            }

        content_hash = calculate_sha256(raw_content)

        # Detect publisher if not provided
        if not source_publisher:
            url_lower = source_url.lower()
            if "thehackernews.com" in url_lower:
                source_publisher = "The Hacker News"
            elif "bleepingcomputer.com" in url_lower:
                source_publisher = "BleepingComputer"
            elif "cisa.gov" in url_lower:
                source_publisher = "CISA"
            elif "abuse.ch" in url_lower:
                source_publisher = "Abuse.ch"
            elif "mandiant.com" in url_lower:
                source_publisher = "Mandiant"
            else:
                source_publisher = "Generic Web Feed"

        return {
            "source_url": source_url,
            "source_title": source_title,
            "source_publisher": source_publisher,
            "published_at": published_at,
            "fetched_at": now_iso,
            "http_status": 200,
            "content_hash": content_hash,
            "raw_content": raw_content,
            "fetch_status": "success",
            "fetch_error": None
        }

    def verify_ioc(self, indicator: str, indicator_type: str, raw_content: str,
                   source_url: str = "", published_date: Optional[str] = None,
                   external_verification_status: str = "unverified") -> Dict[str, Any]:
        """
        Conducts deterministic grounding check, offset location, context evaluation,
        and multi-factor trust scoring for an indicator.
        """
        match_status, start_idx, end_idx, matched_str = find_indicator_in_text(indicator, raw_content)
        
        exact_quote, context_window = extract_context_quote(raw_content, start_idx, end_idx)
        
        mal_status, ctx_assess, notes = assess_indicator_maliciousness(
            indicator, indicator_type, context_window, match_status
        )

        trust_score, trust_status = compute_multi_factor_trust_score(
            source_match_status=match_status,
            maliciousness_status=mal_status,
            external_verification_status=external_verification_status,
            published_date=published_date
        )

        loc_str = f"offset: {start_idx}-{end_idx}" if start_idx >= 0 else "offset: not_found"

        # Downstream approval policy default
        approval_status = "pending_review"
        if trust_status == "rejected":
            approval_status = "rejected"
        elif trust_status == "verified" and match_status == "exact_match":
            # high confidence verified candidate ready for auto-approval if configured
            approval_status = "pending_review"

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "source_url": source_url,
            "evidence_quote": exact_quote,
            "evidence_location": loc_str,
            "char_offset_start": start_idx,
            "char_offset_end": end_idx,
            "source_match_status": match_status,
            "context_assessment": ctx_assess,
            "maliciousness_status": mal_status,
            "external_verification_status": external_verification_status,
            "verification_notes": notes,
            "trust_score": trust_score,
            "trust_status": trust_status,
            "approval_status": approval_status
        }

    def verify_claim(self, claim: str, claim_type: str, raw_content: str,
                     source_url: str = "") -> Dict[str, Any]:
        """
        Verifies MITRE ATT&CK techniques, CVEs, or Threat Actor claims against source text.
        Distinguishes behavioral grounding from superficial keyword matches.
        """
        if not raw_content or not raw_content.strip():
            return {
                "claim": claim,
                "claim_type": claim_type,
                "source_url": source_url,
                "evidence_quote": "",
                "evidence_location": "offset: -1",
                "reasoning_summary": "Empty source document. Cannot verify claim.",
                "verification_status": "insufficient_evidence",
                "uncertainties": "Source document is empty.",
                "supporting_references": [],
                "trust_score": 0.0
            }

        claim_lower = claim.lower()
        raw_lower = raw_content.lower()

        # MITRE Technique verification
        if claim_type == "mitre_attack":
            # Check for Technique ID (e.g., T1059, T1105)
            tid_match = re.search(r'T\d{4}(?:\.\d{3})?', claim, re.IGNORECASE)
            technique_id = tid_match.group(0).upper() if tid_match else ""
            
            id_in_text = technique_id and (technique_id.lower() in raw_lower)
            
            # Extract technique name keywords (e.g. Command and Scripting Interpreter)
            words = [w for w in re.split(r'\W+', claim_lower) if len(w) > 3 and w not in ("mitre", "attack", "technique")]
            matched_words = [w for w in words if w in raw_lower]
            
            # Check for behavioral description in article using word boundaries
            has_behavioral_evidence = False
            behavioral_keywords = [
                "execute", "executed", "executing", "executes",
                "injected", "injecting",
                "downloaded", "download", "downloading",
                "established", "establish", "abused", "abuse",
                "compromised", "compromise", "bypassed", "bypass",
                "exploit", "exploited", "exploiting",
                "dumped", "dumping", "spearphishing",
                "exfiltrated", "exfiltrate", "dropped"
            ]
            for act_word in behavioral_keywords:
                if re.search(rf'\b{act_word}\b', raw_lower):
                    has_behavioral_evidence = True
                    break

            if id_in_text and has_behavioral_evidence:
                pos = raw_lower.find(technique_id.lower())
                quote, _ = extract_context_quote(raw_content, pos, pos + len(technique_id))
                return {
                    "claim": claim,
                    "claim_type": claim_type,
                    "source_url": source_url,
                    "evidence_quote": quote,
                    "evidence_location": f"offset: {pos}-{pos + len(technique_id)}",
                    "reasoning_summary": f"Technique {technique_id} explicitly named with supporting behavioral context.",
                    "verification_status": "verified",
                    "uncertainties": "",
                    "supporting_references": [f"https://attack.mitre.org/techniques/{technique_id}/"],
                    "trust_score": 0.95
                }
            elif matched_words and has_behavioral_evidence:
                pos = raw_lower.find(matched_words[0])
                quote, _ = extract_context_quote(raw_content, pos, pos + len(matched_words[0]))
                return {
                    "claim": claim,
                    "claim_type": claim_type,
                    "source_url": source_url,
                    "evidence_quote": quote,
                    "evidence_location": f"offset: {pos}-{pos + len(matched_words[0])}",
                    "reasoning_summary": f"Behavioral patterns matched keywords: {', '.join(matched_words[:3])}.",
                    "verification_status": "verified",
                    "uncertainties": "Technique ID not explicitly cited; mapped via observed behavior.",
                    "supporting_references": [],
                    "trust_score": 0.75
                }
            elif matched_words and not has_behavioral_evidence:
                return {
                    "claim": claim,
                    "claim_type": claim_type,
                    "source_url": source_url,
                    "evidence_quote": "",
                    "evidence_location": "offset: -1",
                    "reasoning_summary": f"Single keyword match found ('{matched_words[0]}') without behavioral description of attack execution.",
                    "verification_status": "insufficient_evidence",
                    "uncertainties": "Superficial keyword mention only; insufficient proof of actual exploitation.",
                    "supporting_references": [],
                    "trust_score": 0.30
                }
            else:
                return {
                    "claim": claim,
                    "claim_type": claim_type,
                    "source_url": source_url,
                    "evidence_quote": "",
                    "evidence_location": "offset: not_found",
                    "reasoning_summary": "Neither technique ID nor attack behavior found in text.",
                    "verification_status": "rejected",
                    "uncertainties": "Claim appears to be an ungrounded inference.",
                    "supporting_references": [],
                    "trust_score": 0.0
                }

        # CVE Verification
        elif claim_type == "cve":
            cve_match = re.search(r'CVE-\d{4}-\d{4,7}', claim, re.IGNORECASE)
            cve_id = cve_match.group(0).upper() if cve_match else claim
            pos = raw_lower.find(cve_id.lower())
            if pos != -1:
                quote, _ = extract_context_quote(raw_content, pos, pos + len(cve_id))
                return {
                    "claim": claim,
                    "claim_type": claim_type,
                    "source_url": source_url,
                    "evidence_quote": quote,
                    "evidence_location": f"offset: {pos}-{pos + len(cve_id)}",
                    "reasoning_summary": f"Vulnerability {cve_id} confirmed in source text.",
                    "verification_status": "verified",
                    "uncertainties": "",
                    "supporting_references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                    "trust_score": 0.95
                }
            else:
                return {
                    "claim": claim,
                    "claim_type": claim_type,
                    "source_url": source_url,
                    "evidence_quote": "",
                    "evidence_location": "offset: not_found",
                    "reasoning_summary": f"Vulnerability {cve_id} does not appear in source text.",
                    "verification_status": "rejected",
                    "uncertainties": "CVE was not mentioned by publisher.",
                    "supporting_references": [],
                    "trust_score": 0.0
                }

        # Generic Claim
        words = [w for w in re.split(r'\W+', claim_lower) if len(w) > 3]
        matches = [w for w in words if w in raw_lower]
        ratio = len(matches) / max(1, len(words))
        if ratio >= 0.6:
            return {
                "claim": claim,
                "claim_type": claim_type,
                "source_url": source_url,
                "evidence_quote": f"Matched keywords: {', '.join(matches[:4])}",
                "evidence_location": "offset: text_body",
                "reasoning_summary": f"{int(ratio*100)}% of claim entities confirmed in article.",
                "verification_status": "verified",
                "uncertainties": "",
                "supporting_references": [],
                "trust_score": round(ratio, 2)
            }
        else:
            return {
                "claim": claim,
                "claim_type": claim_type,
                "source_url": source_url,
                "evidence_quote": "",
                "evidence_location": "offset: not_found",
                "reasoning_summary": "Insufficient textual correlation with source document.",
                "verification_status": "insufficient_evidence",
                "uncertainties": "Claim not substantiated by article.",
                "supporting_references": [],
                "trust_score": 0.2
            }

    def verify_skill(self, skill_name: str, skill_code: str,
                     source_reports: List[int], evidence_refs: List[int]) -> Dict[str, Any]:
        """
        Validates python skill code, AST syntax, and verifies evidence linkage.
        Enforces that skills must cite valid source reports and evidence refs.
        """
        # 1. AST Syntax Check
        try:
            ast.parse(skill_code)
        except SyntaxError as e:
            return {
                "skill_name": skill_name,
                "skill_version": "1.0.0",
                "source_reports": source_reports,
                "evidence_refs": evidence_refs,
                "verification_status": "rejected",
                "test_status": "syntax_error",
                "test_output": f"Python SyntaxError at line {e.lineno}: {e.msg}",
                "approval_status": "rejected"
            }

        # 2. Evidence Grounding Check (Must have source report & evidence refs)
        if not source_reports or not evidence_refs:
            return {
                "skill_name": skill_name,
                "skill_version": "1.0.0",
                "source_reports": source_reports,
                "evidence_refs": evidence_refs,
                "verification_status": "unverified",
                "test_status": "pending",
                "test_output": "Skill lacks source CTI report or evidence reference IDs.",
                "approval_status": "pending_review"
            }

        return {
            "skill_name": skill_name,
            "skill_version": "1.0.0",
            "source_reports": source_reports,
            "evidence_refs": evidence_refs,
            "verification_status": "verified",
            "test_status": "pending",
            "test_output": "Syntax and evidence linkage valid. Pending sandbox test.",
            "approval_status": "pending_review"
        }
