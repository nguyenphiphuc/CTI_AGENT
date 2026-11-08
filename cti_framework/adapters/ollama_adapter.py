import requests
from typing import List, Dict, Any, Tuple
from adapters.base import BaseModelAdapter
from schemas.io_schemas import Message

class OllamaAdapter(BaseModelAdapter):
    def check_health(self) -> bool:
        try:
            res = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return res.status_code == 200
        except Exception:
            return False

    def generate(self, messages: List[Message], tools: List[Dict[str, Any]], options: Dict[str, Any]) -> Tuple[Message, str]:
        clean_options = {k: v for k, v in options.items() if k != "timeout"}
        clean_options.setdefault("num_ctx", 4096)
        clean_options.setdefault("num_predict", 1024)
        clean_options.setdefault("temperature", 0.1)

        payload = {
            "model": self.model_name,
            "messages": [m.dict(exclude_none=True) if hasattr(m, 'dict') else m.model_dump(exclude_none=True) for m in messages],
            "stream": False,
            "options": clean_options
        }
        if tools:
            payload["tools"] = tools

        try:
            res = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=options.get("timeout", 120))
            res.raise_for_status()
            data = res.json()
            msg_data = data.get("message", {})
            
            return Message(
                role=msg_data.get("role", "assistant"),
                content=msg_data.get("content", ""),
                tool_calls=msg_data.get("tool_calls")
            ), ""
            
        except requests.exceptions.RequestException as e:
            return Message(role="assistant", content=""), f"Connection error: {str(e)}"
