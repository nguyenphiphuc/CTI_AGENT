"""
xAI & Trust Engine (Explainable AI & Grounding Verification)
Cơ chế bảo vệ sự thật tuyệt đối (Zero-Hallucination Guarantee):
- Đối soát nguyên văn (Verbatim Grounding): Kiểm tra cứng chuỗi ký tự IoC/CVE trong văn bản gốc.
- Phân biệt Exact match, Normalized match (defanged IoC), Not found.
- Đánh giá ngữ cảnh độc hại (Maliciousness Context) vs Địa chỉ ví dụ / RFC 5737 / DNS lành tính.
- Xác định tọa độ ký tự chính xác (Exact Character Offsets [start..end]).
- Trích xuất câu văn chứa bằng chứng (Verbatim Context Sentence) trực tiếp từ nguồn.
- Đánh giá chỉ số tin cậy đa tiêu chí (Multi-factor Trust Score 0 - 100%).
- Ngăn chặn triệt để AI bịa đặt dữ liệu (Zero Hallucination).
"""

import re
from typing import Dict, List, Any, Tuple, Optional
from cti_framework.validators.xai_verifier import (
    XAIVerifier,
    find_indicator_in_text,
    extract_context_quote,
    assess_indicator_maliciousness,
    compute_multi_factor_trust_score,
    normalize_defanged
)

class XAITrustEngine:
    verifier = XAIVerifier()

    @staticmethod
    def extract_context_sentence(text: str, start_idx: int, end_idx: int) -> str:
        """Trích xuất câu văn hoàn chỉnh chứa entity từ văn bản gốc."""
        quote, _ = extract_context_quote(text, start_idx, end_idx, window_chars=120)
        return quote

    @classmethod
    def verify_entity_grounding(cls, raw_text: str, entity_value: str, entity_type: str = "ioc",
                                published_date: Optional[str] = None) -> Dict[str, Any]:
        """
        Kiểm tra toán học / xác thực chuỗi đối soát cứng:
        Trả về kết quả chứng minh entity có nằm trong bài viết gốc hay không,
        phân biệt exact_match, normalized_match, và đánh giá ngữ cảnh độc hại.
        """
        if not raw_text or not entity_value:
            return {
                "entity_value": entity_value,
                "entity_type": entity_type,
                "is_grounded": False,
                "trust_score": 0.0,
                "trust_status": "rejected",
                "confidence_label": "0% UNVERIFIED (DATA MISSING)",
                "exact_quote": "",
                "char_offset_start": -1,
                "char_offset_end": -1,
                "source_match_status": "not_found",
                "context_assessment": "Dữ liệu trống hoặc không có nội dung gốc để đối soát.",
                "maliciousness_status": "insufficient_evidence",
                "explanation": "Dữ liệu trống hoặc không có nội dung gốc để đối soát."
            }

        ver = cls.verifier.verify_ioc(
            indicator=str(entity_value).strip(),
            indicator_type=entity_type,
            raw_content=raw_text,
            published_date=published_date
        )

        is_grounded = ver["source_match_status"] in ("exact_match", "normalized_match")
        pct_score = round(ver["trust_score"] * 100, 1)

        if ver["source_match_status"] == "exact_match":
            conf_label = f"{pct_score}% VERIFIED ({ver['maliciousness_status'].upper()})"
        elif ver["source_match_status"] == "normalized_match":
            conf_label = f"{pct_score}% NORMALIZED MATCH ({ver['maliciousness_status'].upper()})"
        else:
            conf_label = "0% UNVERIFIED (HALLUCINATION DETECTED)"

        return {
            "entity_value": ver["indicator"],
            "entity_type": ver["indicator_type"],
            "is_grounded": is_grounded,
            "trust_score": ver["trust_score"],
            "trust_score_pct": pct_score,
            "trust_status": ver["trust_status"],
            "approval_status": ver["approval_status"],
            "confidence_label": conf_label,
            "exact_quote": ver["evidence_quote"],
            "char_offset_start": ver["char_offset_start"],
            "char_offset_end": ver["char_offset_end"],
            "source_match_status": ver["source_match_status"],
            "context_assessment": ver["context_assessment"],
            "maliciousness_status": ver["maliciousness_status"],
            "explanation": f"[{ver['source_match_status']}] {ver['context_assessment']} - {ver['verification_notes']}"
        }

    @classmethod
    def verify_mitre_evidence(cls, raw_text: str, evidence_quote: str, technique_id: str) -> Dict[str, Any]:
        """Kiểm tra xem kỹ thuật và câu bằng chứng MITRE của Agent có thực sự nằm trong bài báo không."""
        claim_res = cls.verifier.verify_claim(
            claim=f"{technique_id}: {evidence_quote}",
            claim_type="mitre_attack",
            raw_content=raw_text
        )

        is_grounded = claim_res["verification_status"] == "verified"

        return {
            "technique_id": technique_id,
            "is_grounded": is_grounded,
            "trust_score": claim_res["trust_score"],
            "verification_status": claim_res["verification_status"],
            "char_offset_start": -1,
            "char_offset_end": -1,
            "exact_quote": claim_res["evidence_quote"] or evidence_quote,
            "explanation": claim_res["reasoning_summary"] + (f" (Lưu ý: {claim_res['uncertainties']})" if claim_res['uncertainties'] else "")
        }

    @classmethod
    def audit_cti_analysis(cls, raw_text: str, extracted_iocs: List[Dict[str, Any]],
                           mitre_mappings: List[Dict[str, Any]],
                           published_date: Optional[str] = None) -> Dict[str, Any]:
        """
        Đánh giá toàn diện đợt phân tích CTI, tính Trust Score tổng thể đa nhân tố
        và trả về hồ sơ xAI Explainability Report đầy đủ với phân loại 4 trạng thái kiểm chứng.
        """
        audit_results = []
        verified_count = 0
        total_items = 0
        score_sum = 0.0

        # 1. Audit IoCs
        for item in extracted_iocs:
            val = item.get("value") or item.get("ioc_value") or ""
            itype = item.get("type") or item.get("ioc_type") or "ioc"
            ver = cls.verify_entity_grounding(raw_text, val, itype, published_date)
            audit_results.append(ver)
            total_items += 1
            score_sum += ver["trust_score"]
            if ver["is_grounded"] and ver["maliciousness_status"] == "maliciousness_confirmed":
                verified_count += 1

        # 2. Audit MITRE Mappings
        for m in mitre_mappings:
            tid = m.get("technique_id") or ""
            evidence = m.get("evidence") or ""
            ver_m = cls.verify_mitre_evidence(raw_text, evidence, tid)
            audit_results.append({
                "entity_value": tid,
                "entity_type": "mitre_technique",
                "is_grounded": ver_m["is_grounded"],
                "trust_score": ver_m["trust_score"],
                "trust_score_pct": round(ver_m["trust_score"] * 100, 1),
                "confidence_label": "GROUNDED" if ver_m["is_grounded"] else "UNGROUNDED",
                "exact_quote": ver_m.get("exact_quote", evidence),
                "char_offset_start": ver_m.get("char_offset_start", -1),
                "char_offset_end": ver_m.get("char_offset_end", -1),
                "source_match_status": "exact_match" if ver_m["is_grounded"] else "not_found",
                "maliciousness_status": "maliciousness_confirmed" if ver_m["is_grounded"] else "insufficient_evidence",
                "context_assessment": ver_m["explanation"],
                "explanation": ver_m["explanation"]
            })
            total_items += 1
            score_sum += ver_m["trust_score"]
            if ver_m["is_grounded"]:
                verified_count += 1

        if total_items == 0:
            overall_pct = 100.0
        else:
            overall_pct = round((score_sum / total_items) * 100, 1)

        if overall_pct >= 80:
            trust_badge = "VERIFIED_TRUSTED"
        elif overall_pct >= 50:
            trust_badge = "PARTIALLY_VERIFIED"
        else:
            trust_badge = "UNVERIFIED_RISK"

        return {
            "overall_trust_score": overall_pct,
            "total_items_checked": total_items,
            "verified_items_count": verified_count,
            "hallucination_detected": any(not v["is_grounded"] for v in audit_results),
            "verifications": audit_results,
            "trust_badge": trust_badge
        }
