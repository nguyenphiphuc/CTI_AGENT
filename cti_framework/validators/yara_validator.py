import re
from typing import Tuple, Optional

def validate_yara_rule(content: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a YARA rule syntax and structural integrity.
    Returns (is_valid: bool, error_message: Optional[str])
    """
    if not content or not content.strip():
        return False, "Nội dung YARA rule rỗng."

    # Strip markdown code blocks if any
    cleaned = content.strip()
    if cleaned.startswith("```yara") or cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    # Step 1: Check rule header
    rule_match = re.search(r'\brule\s+([a-zA-Z_][a-zA-Z0-9_]*)', cleaned)
    if not rule_match:
        return False, "Thiếu khai báo tên rule: 'rule <Tên_Rule>' hợp lệ (phải bắt đầu bằng chữ cái hoặc dấu gạch dưới)."

    rule_name = rule_match.group(1)

    # Step 2: Balanced braces
    open_braces = cleaned.count('{')
    close_braces = cleaned.count('}')
    if open_braces == 0 or open_braces != close_braces:
        return False, f"Lỗi dấu đóng mở ngoặc nhọn: tìm thấy {open_braces} dấu '{{' và {close_braces} dấu '}}'."

    # Step 3: Check condition section
    if not re.search(r'\bcondition\s*:', cleaned):
        return False, "Quy tắc YARA bắt buộc phải có phần 'condition:'."

    # Extract condition body
    condition_match = re.search(r'\bcondition\s*:\s*([^}]+)', cleaned)
    if not condition_match or not condition_match.group(1).strip():
        return False, "Phần 'condition:' trong YARA không được để trống."

    # Step 4: If strings section exists, validate string variables
    if re.search(r'\bstrings\s*:', cleaned):
        strings_match = re.search(r'\bstrings\s*:\s*(.*?)(?=\bcondition\s*:)', cleaned, re.DOTALL)
        if strings_match:
            strings_body = strings_match.group(1).strip()
            if strings_body:
                # Every non-comment line should start with $
                lines = [l.strip() for l in strings_body.splitlines() if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("/*")]
                for line in lines:
                    if not line.startswith("$"):
                        return False, f"Biến định danh chuỗi không hợp lệ trong phần strings: '{line}' (biến YARA phải bắt đầu bằng dấu '$')."

    return True, None
