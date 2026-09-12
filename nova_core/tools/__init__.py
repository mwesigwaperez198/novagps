"""NOVA-CORE tool registry and base classes."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import time


@dataclass
class ToolResult:
    success: bool
    output: Any
    error: Optional[str] = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "output": self.output if isinstance(self.output, (str, int, float, bool, list, dict)) else str(self.output),
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
        }


class Tool(ABC):
    name: str = ""
    description: str = ""
    category: str = "general"

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        ...

    def _timed_execute(self, **kwargs) -> ToolResult:
        start = time.time()
        try:
            result = self.execute(**kwargs)
            result.duration_ms = (time.time() - start) * 1000
            return result
        except Exception as e:
            return ToolResult(
                success=False,
                output=None,
                error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def execute(self, name: str, **kwargs) -> ToolResult:
        tool = self._tools.get(name)
        if not tool:
            return ToolResult(success=False, output=None, error=f"Tool '{name}' not found")
        return tool._timed_execute(**kwargs)

    def list_tools(self) -> List[dict]:
        return [
            {"name": t.name, "description": t.description, "category": t.category}
            for t in self._tools.values()
        ]

    def list_by_category(self, category: str) -> List[dict]:
        return [
            {"name": t.name, "description": t.description}
            for t in self._tools.values()
            if t.category == category
        ]

    def get_schema(self) -> List[dict]:
        """Return tool schemas for LLM function calling."""
        schemas = []
        for tool in self._tools.values():
            schemas.append({
                "name": tool.name,
                "description": tool.description,
                "category": tool.category,
            })
        return schemas


_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
        _register_all_tools(_registry)
    return _registry


def _register_all_tools(registry: ToolRegistry):
    from .scanner import register_scanner_tools
    from .fuzzer import register_fuzzer_tools
    from .system import register_system_tools
    from .network import register_network_tools
    from .backend import register_backend_tools
    from .code_analysis import register_code_analysis_tools
    from .packet import register_packet_tools

    register_scanner_tools(registry)
    register_fuzzer_tools(registry)
    register_system_tools(registry)
    register_network_tools(registry)
    register_backend_tools(registry)
    register_code_analysis_tools(registry)
    register_packet_tools(registry)
