from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple
from schemas.io_schemas import Message

class BaseModelAdapter(ABC):
    def __init__(self, model_name: str, base_url: str):
        self.model_name = model_name
        self.base_url = base_url
        
    @abstractmethod
    def check_health(self) -> bool:
        pass
        
    @abstractmethod
    def generate(self, messages: List[Message], tools: List[Dict[str, Any]], options: Dict[str, Any]) -> Tuple[Message, str]:
        """
        Returns (Message, error_str)
        """
        pass
