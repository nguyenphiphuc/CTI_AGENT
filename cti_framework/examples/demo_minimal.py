import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from adapters.ollama_adapter import OllamaAdapter
from core.tools import ToolRegistry
from core.agent import AgentEngine
from schemas.io_schemas import AgentConfig
from storage.sqlite_manager import StorageManager

registry = ToolRegistry()

@registry.register(
    name="get_current_time",
    description="Lấy thời gian hiện tại của hệ thống.",
    schema={
        "type": "object",
        "properties": {},
        "required": []
    }
)
def get_current_time():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

@registry.register(
    name="echo_uppercase",
    description="Chuyển một chuỗi thành chữ in hoa.",
    schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Văn bản cần in hoa"}
        },
        "required": ["text"]
    }
)
def echo_uppercase(text: str):
    return text.upper()

if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    adapter = OllamaAdapter(model_name="qwen2.5:7b", base_url="http://localhost:11434")
    
    if not adapter.check_health():
        print("Ollama is not reachable or model is not available.")
        sys.exit(1)
        
    storage = StorageManager("cti_framework.db")
    config = AgentConfig(model_name="qwen2.5:7b", max_steps=4)
    
    agent = AgentEngine(adapter=adapter, registry=registry, storage=storage, config=config)
    
    task = "Hãy cho tôi biết thời gian hiện tại, sau đó in hoa cụm từ 'hello world cti agent'."
    system_prompt = "Bạn là một AI Agent thông minh. Sử dụng công cụ để trả lời câu hỏi."
    
    print(f"Task: {task}")
    print("Running...")
    result = agent.run(task=task, system_prompt=system_prompt)
    print("\nResult:")
    print(result)
