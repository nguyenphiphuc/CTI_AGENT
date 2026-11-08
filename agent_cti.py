import json
import re
import requests

# 1. TOOL REGISTRY
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

@registry.register(
    name="extract_iocs",
    description="Trích xuất địa chỉ IP và mã băm SHA256 từ nội dung báo cáo CTI.",
    parameters={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Văn bản báo cáo tình báo"}
        },
        "required": ["text"]
    }
)
def extract_iocs(text: str) -> str:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    ips = list(set(re.findall(ip_pattern, text)))
    hashes = list(set(re.findall(sha256_pattern, text)))
    
    result = {
        "ip_addresses": ips,
        "sha256_hashes": hashes,
        "count": len(ips) + len(hashes)
    }
    return json.dumps(result, ensure_ascii=False)

@registry.register(
    name="generate_sigma_rule",
    description="Tạo quy tắc Sigma định dạng YAML từ danh sách IP hoặc Hash.",
    parameters={
        "type": "object",
        "properties": {
            "rule_title": {"type": "string", "description": "Tên quy tắc phát hiện"},
            "target_type": {"type": "string", "enum": ["ip", "hash"], "description": "Loại định danh cần chặn"},
            "values": {"type": "array", "items": {"type": "string"}, "description": "Danh sách các giá trị IoC"}
        },
        "required": ["rule_title", "target_type", "values"]
    }
)
def generate_sigma_rule(rule_title: str, target_type: str, values: list) -> str:
    field = "DestinationIp" if target_type == "ip" else "Hashes"
    values_formatted = "\n        - ".join([f"'{v}'" for v in values])
    
    sigma = f"""
title: {rule_title}
status: experimental
description: Auto-generated detection rule from Local CTI Agent
logsource:
    category: network_connection
detection:
    selection:
        {field}:
        - {values_formatted}
    condition: selection
level: high
"""
    return sigma.strip()


# 2. AGENT ENGINE
class LocalAgent:
    def __init__(self, model: str = "qwen2.5:7b", base_url: str = "http://localhost:11434"):
        self.model = model
        self.api_url = f"{base_url}/api/chat"
        self.system_prompt = (
            "Bạn là trợ lý CTI Agent chạy hoàn toàn ở local. "
            "Khi người dùng chào hỏi, hãy trả lời bình thường. "
            "Khi người dùng đưa báo cáo hoặc IoC, hãy dùng tool để bóc tách và sinh rule Sigma."
        )
        self.messages = [{"role": "system", "content": self.system_prompt}]

    def execute(self, prompt: str, max_steps: int = 5) -> str:
        self.messages.append({"role": "user", "content": prompt})

        for _ in range(max_steps):
            payload = {
                "model": self.model,
                "messages": self.messages,
                "tools": registry.schemas,
                "stream": False,
                "options": {"temperature": 0.0}
            }

            try:
                res = requests.post(self.api_url, json=payload, timeout=120)
                res.raise_for_status()
                response_json = res.json()
            except Exception as e:
                return f"[Lỗi kết nối Ollama]: {e}"

            msg = response_json.get("message", {})
            self.messages.append(msg)

            tool_calls = msg.get("tool_calls")
            if not tool_calls:
                return msg.get("content", "")

            for tool_call in tool_calls:
                func_name = tool_call["function"]["name"]
                args = tool_call["function"]["arguments"]

                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}

                print(f"\n[ACTION] Agent gọi hàm: `{func_name}`")
                if func_name in registry.tools:
                    obs = registry.tools[func_name](**args)
                else:
                    obs = f"Lỗi: Không có hàm {func_name}"

                self.messages.append({
                    "role": "tool",
                    "content": str(obs)
                })

        return "Vượt quá số bước suy luận cho phép."


# 3. INTERACTIVE CHAT
if __name__ == "__main__":
    agent = LocalAgent(model="qwen2.5:7b")

    print("=" * 60)
    print("🤖 AGENT LOCAL ĐÃ KHỞI ĐỘNG (Gõ 'exit' để thoát)")
    print("=" * 60)

    while True:
        try:
            user_msg = input("\n[Bạn] > ").strip()
            if not user_msg:
                continue
            if user_msg.lower() in ["exit", "quit"]:
                print("Đã thoát Agent.")
                break

            print("[Agent đang xử lý...]")
            reply = agent.execute(user_msg)
            print(f"\n[Agent]:\n{reply}")

        except KeyboardInterrupt:
            print("\nĐã dừng chương trình.")
            break