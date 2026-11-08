"""
Base Agent Skill Framework
Lớp cơ sở cho toàn bộ các Skill được sinh động (Dynamically Synthesized) bởi CTI Agent
để chuyển giao sang cho Hunter / Defender Agent thực thi.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime

class BaseAgentSkill(ABC):
    def __init__(self, name: str, domain: str, description: str, target_threat: str):
        self.name = name
        self.domain = domain # "web", "network", "endpoint"
        self.description = description
        self.target_threat = target_threat # e.g. "CVE-2024-xxxx", "C2_Beaconing", "WebShell"
        self.created_at = datetime.now().isoformat()
        self.execution_count = 0

    @abstractmethod
    def execute(self, target_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Thực thi hành động phòng thủ / săn lùng thực tế."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "description": self.description,
            "target_threat": self.target_threat,
            "created_at": self.created_at,
            "execution_count": self.execution_count
        }
