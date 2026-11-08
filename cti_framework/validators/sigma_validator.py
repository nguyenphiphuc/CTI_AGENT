import yaml
from typing import Tuple, Optional

def validate_sigma_rule(content: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a Sigma Rule YAML content against Sigma standard specification.
    Returns (is_valid: bool, error_message: Optional[str])
    """
    if not content or not content.strip():
        return False, "Nội dung Sigma rule rỗng."

    # Step 1: Clean code block delimiters if model provided markdown
    cleaned = content.strip()
    if cleaned.startswith("```yaml") or cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    # Step 2: YAML Parsing
    try:
        data = yaml.safe_load(cleaned)
    except yaml.YAMLError as e:
        return False, f"Lỗi cú pháp YAML: {str(e)}"

    if not isinstance(data, dict):
        return False, "Cấu trúc Sigma không hợp lệ: Cần là định dạng dictionary (key-value)."

    # Step 3: Required Sigma Fields
    required_fields = ["title", "logsource", "detection"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return False, f"Thiếu trường bắt buộc trong quy chuẩn Sigma: {', '.join(missing)}"

    # Step 4: Validate logsource
    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        return False, "Trường 'logsource' phải là một dictionary chứa 'category', 'product', hoặc 'service'."

    # Step 5: Validate detection and condition
    detection = data.get("detection")
    if not isinstance(detection, dict):
        return False, "Trường 'detection' phải là một dictionary chứa các selection và 'condition'."

    if "condition" not in detection:
        return False, "Trường 'detection' bắt buộc phải có mục 'condition'."

    condition_val = str(detection.get("condition", "")).strip()
    if not condition_val:
        return False, "Điều kiện 'condition' trong detection không được để trống."

    return True, None
