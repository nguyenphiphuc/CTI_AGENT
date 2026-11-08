import inspect
from typing import Callable, Dict, Any, Optional

class BaseTool:
    def __init__(self, name: str, description: str, func: Callable, schema: Dict[str, Any], enabled: bool = True):
        self.name = name
        self.description = description
        self.func = func
        self.schema = schema
        self.enabled = enabled
        
    def execute(self, **kwargs) -> Any:
        if not self.enabled:
            return f"Error: Tool '{self.name}' is currently disabled by administrator."
        try:
            return self.func(**kwargs)
        except Exception as e:
            return f"Error executing {self.name}: {str(e)}"

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        
    def register(self, name: str, description: str, schema: Dict[str, Any]):
        def decorator(func: Callable):
            tool = BaseTool(name, description, func, schema, enabled=True)
            self._tools[name] = tool
            return func
        return decorator
        
    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def get_all_tools(self) -> Dict[str, BaseTool]:
        return self._tools
        
    def set_tool_enabled(self, name: str, enabled: bool) -> bool:
        if name in self._tools:
            self._tools[name].enabled = enabled
            return True
        return False

    def is_tool_enabled(self, name: str) -> bool:
        tool = self._tools.get(name)
        return tool.enabled if tool else False
        
    def get_all_schemas(self) -> list:
        schemas = []
        for name, tool in self._tools.items():
            if tool.enabled:
                schemas.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.schema
                    }
                })
        return schemas
