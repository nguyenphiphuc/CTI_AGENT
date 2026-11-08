from typing import List, Dict, Any
from schemas.io_schemas import Message

class AgentState:
    def __init__(self, system_prompt: str):
        self.messages: List[Message] = [Message(role="system", content=system_prompt)]
        self.context: Dict[str, Any] = {}
        
    def add_message(self, message: Message):
        self.messages.append(message)
        
    def get_messages(self) -> List[Message]:
        return self.messages
