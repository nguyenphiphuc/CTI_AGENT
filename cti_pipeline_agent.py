import json
import re
import sqlite3
import requests
import feedparser
from typing import Dict, Any, List

# ==============================================================================
# 1. DATABASE LOCAL CHO CTI (SQLite)
# ==============================================================================
class CTIDatabase:
    def __init__(self, db_path: str = "cti_local.db"):
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT,
                ioc_value TEXT UNIQUE,
                threat_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def insert_ioc(self, ioc_type: str, ioc_value: str, threat_level: str = "high"):
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO indicators (ioc_type, ioc_value, threat_level) VALUES (?, ?, ?)",
                (ioc_type, ioc_value, threat_level)
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            return False

    def get_all_iocs(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT ioc_type, ioc_value FROM indicators")
        return cursor.fetchall()

db = CTIDatabase()

# ==============================================================================
# 2. TOOL REGISTRY & MỞ RỘNG CÁC TOOL CTI MỚI
# ==============================================================================
class ToolRegistry:
    def __init__(self):
        self.tools = {}
        self.schemas = []

    def register(self, name: str, description: str, parameters: dict):
        def decorator(func):
            self.tools[name] = func
            self.schemas.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters
                }
            })
            return func
        return decorator

registry = ToolRegistry()

# Tool 1: Đọc tin từ nguồn RSS OSINT
@registry.register(
    name="fetch_rss_feeds",
    description="Lấy danh sách các tin cảnh báo mới nhất từ nguồn RSS CTI bên ngoài.",
    parameters={
        "type": "object",
        "properties": {
            "feed_url": {"type": "string", "description": "URL của feed RSS"}
        },
        "required": ["feed_url"]
    }
)
def fetch_rss_feeds(feed_url: str) -> str:
    feed = feedparser.parse(feed_url)
    if not feed.entries:
        return json.dumps({"status": "empty", "entries": []})
    
    # Lấy 2 tin mới nhất để demo
    entries = []
    for entry in feed.entries[:2]:
        entries.append({
            "title": entry.title,
            "summary": entry.get("summary", entry.get("description", ""))
        })
    return json.dumps(entries, ensure_ascii=False)

# Tool 2: Trích xuất IoC nâng cao (IP, Domain, SHA256)
@registry.register(
    name="extract_and_store_iocs",
    description="Trích xuất các giá trị IoC (IPv4, SHA256) từ văn bản và tự động lưu vào local database.",
    parameters={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Nội dung văn bản chứa thông tin mối đe dọa"}
        },
        "required": ["text"]
    }
)
def extract_and_store_iocs(text: str) -> str:
    # Pattern lọc IP (loại trừ private/loopback cơ bản)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

    raw_ips = re.findall(ip_pattern, text)
    valid_ips = [ip for ip in set(raw_ips) if not ip.startswith(("127.", "0."))]
    hashes = list(set(re.findall(sha256_pattern, text)))

    saved_ips = 0
    for ip in valid_ips:
        if db.insert_ioc("ip", ip):
            saved_ips += 1

    saved_hashes = 0
    for h in hashes:
        if db.insert_ioc("sha256", h):
            saved_hashes += 1

    result = {
        "found_ips": valid_ips,
        "found_hashes": hashes,
        "newly_stored": {"ips": saved_ips, "hashes": saved_hashes}
    }
    return json.dumps(result, ensure_ascii=False)

# Tool 3: Sinh quy tắc phát hiện đa nền tảng (Sigma / YARA)
@registry.register(
    name="generate_defense_rules",
    description="Tạo quy tắc phòng thủ dạng Sigma hoặc YARA dựa trên danh sách giá trị IoC cụ thể.",
    parameters={
        "type": "object",
        "properties": {
            "rule_type": {
                "type": "string",
                "enum": ["sigma", "yara"],
                "description": "Loại định dạng quy tắc muốn sinh"
            },
            "rule_name": {"type": "string", "description": "Tên quy tắc (ví dụ: APT_Malware_Block)"},
            "ioc_values": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Danh sách mã Hash hoặc IP"
            }
        },
        "required": ["rule_type", "rule_name", "ioc_values"]
    }
)
def generate_defense_rules(rule_type: str, rule_name: str, ioc_values: list) -> str:
    if rule_type == "yara":
        # Rule YARA phát hiện hash hoặc chuỗi
        strings_section = "\n        ".join([f'$hash_{i} = "{val}"' for i, val in enumerate(ioc_values)])
        conditions = " or ".join([f'$hash_{i}' for i in range(len(ioc_values))])
        yara_template = f"""
rule {rule_name.replace(' ', '_')}
{{
    meta:
        description = "CTI Local Agent Auto-generated Rule"
        threat_level = "High"
    strings:
        {strings_section}
    condition:
        {conditions}
}}
"""
        return yara_template.strip()

    else:
        # Rule Sigma phát hiện IP
        formatted_values = "\n        - ".join([f"'{v}'" for v in ioc_values])
        sigma_template = f"""
title: {rule_name}
status: test
description: Generated from CTI indicators
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
        - {formatted_values}
    condition: selection
level: high
"""
        return sigma_template.strip()

# ==============================================================================
# 3. AGENT RUNNER LOOP
# ==============================================================================
class CTIAgent:
    def __init__(self, model: str = "qwen2.5:7b", base_url: str = "http://localhost:11434"):
        self.model = model
        self.url = f"{base_url}/api/chat"
        self.messages = []

    def set_system_prompt(self, prompt: str):
        self.messages = [{"role": "system", "content": prompt}]

    def run(self, prompt: str, max_turns: int = 6) -> str:
        self.messages.append({"role": "user", "content": prompt})

        for _ in range(max_turns):
            payload = {
                "model": self.model,
                "messages": self.messages,
                "tools": registry.schemas,
                "stream": False,
                "options": {"temperature": 0.0}
            }

            resp = requests.post(self.url, json=payload, timeout=90).json()
            message = resp.get("message", {})
            self.messages.append(message)

            tool_calls = message.get("tool_calls")
            if not tool_calls:
                return message.get("content", "")

            for call in tool_calls:
                name = call["function"]["name"]
                args = call["function"]["arguments"]
                if isinstance(args, str):
                    args = json.loads(args)

                print(f"[THỰC THI TOOL] >> {name}")
                if name in registry.tools:
                    output = registry.tools[name](**args)
                else:
                    output = f"Lỗi: Không tìm thấy tool {name}"

                self.messages.append({
                    "role": "tool",
                    "content": str(output)
                })

        return "Agent vượt quá số bước phân tích."

# ==============================================================================
# 4. CHẠY KỊCH BẢN THỰC CHIẾN
# ==============================================================================
if __name__ == "__main__":
    agent = CTIAgent()
    agent.set_system_prompt(
        "Bạn là hệ thống CTI Agent tự động. Khi được giao nhiệm vụ:\n"
        "1. Trích xuất tất cả IoC từ nguồn thông tin được cung cấp và lưu vào cơ sở dữ liệu.\n"
        "2. Tự động sinh quy tắc YARA cho các Hash mã độc và quy tắc Sigma cho các địa chỉ IP.\n"
        "3. Trình bày báo cáo tóm tắt rõ ràng các chỉ số đã xử lý."
    )

    sample_task = """
    Phát hiện chiến dịch backdoor Cobalt Strike mới. 
    Hạ tầng điều khiển C2: 198.51.100.24 và 203.0.113.88.
    Tập tin thực thi độc hại mang mã băm SHA256:
    8f4c2057d0a2f1ef92efc340df6e8979c464a9efbb6b4f74d6f6e5200e84b8f0
    8f4c2057d0a2f1ef92efc340df6e8979c464a9efbb6b4f74d6f6e5200e84b8f1
    Hãy xử lý báo cáo, lưu dữ liệu và tạo đầy đủ bộ quy tắc phòng thủ mạng/mã độc tương ứng.
    """

    print(">>> Khởi động Agent phân tích mối đe dọa...")
    result = agent.run(sample_task)
    print("\n" + "="*70)
    print("BÁO CÁO CUỐI CÙNG TỪ AGENT:")
    print("="*70)
    print(result)