from typing import Tuple, Optional
from .sigma_validator import validate_sigma_rule
from .yara_validator import validate_yara_rule
from .xai_verifier import XAIVerifier, normalize_defanged, find_indicator_in_text, is_rfc_example_or_private_ip

def validate_defense_rule(rule_type: str, content: str) -> Tuple[str, str]:
    """
    Validates rule based on its type ('sigma', 'yara', or other).
    Returns (status: 'valid' | 'invalid' | 'insufficient_evidence', error_message: str)
    """
    if "insufficient_evidence" in content.lower():
        return "invalid", "Không đủ bằng chứng kỹ thuật để tạo rule có ý nghĩa."

    rtype = rule_type.lower().strip()
    if rtype == "sigma":
        is_valid, err = validate_sigma_rule(content)
        return ("valid", "") if is_valid else ("invalid", err or "Lỗi cú pháp Sigma không xác định.")
    elif rtype == "yara":
        is_valid, err = validate_yara_rule(content)
        return ("valid", "") if is_valid else ("invalid", err or "Lỗi cú pháp YARA không xác định.")
    else:
        return "validation_pending", f"Chưa có bộ kiểm tra cú pháp tự động cho loại rule '{rule_type}'."
