from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union

class Message(BaseModel):
    role: str
    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None

class AgentConfig(BaseModel):
    model_name: str
    max_steps: int = 8
    temperature: float = 0.0
    timeout: int = 120
    cti_profile: str = "all"  # "web", "network", "endpoint", "all"
    artifact_focus: str = "all"  # "cve", "ipv4", "hash", "all"

class ExecutionTrace(BaseModel):
    step: int
    action_type: str # "model_inference", "tool_call", "error", "stop"
    content: Any
    timestamp: str
