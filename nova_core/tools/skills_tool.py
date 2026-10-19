"""Skills as brain tools.

Bridges the LAU skill registry (nova_core.skills) into the tool layer so the
agent can reach for external security/OSINT tooling through the same reasoning
loop that drives port_scan, vuln_scan, and the rest — not a separate console.
"""

from __future__ import annotations

from ..tools import Tool, ToolRegistry, ToolResult


class SkillDispatch(Tool):
    name = "skill"
    description = (
        "Run a registered LAU skill against a target (phoneinfoga, nuclei, httpx, "
        "nmap, sqlmap, ffuf, theharvester, sherlock, yara, trufflehog, ...)."
    )
    category = "skills"

    def execute(self, key: str | None = None, target: str | None = None,
                args: list | None = None, **kwargs) -> ToolResult:
        from ..skills.adapters import SkillRefused, run_skill

        if not key:
            return ToolResult(success=False, output=None, error="no skill key supplied")
        try:
            result = run_skill(key, target=target, args=args)
        except SkillRefused as exc:
            return ToolResult(success=False, output=None, error=str(exc))

        status = result.get("status")
        if status == "ok":
            return ToolResult(success=True, output=result)
        return ToolResult(success=False, output=result, error=f"skill {key}: {status}")


class SkillCatalog(Tool):
    name = "skill_catalog"
    description = "List every registered LAU skill with availability and install hint."
    category = "skills"

    def execute(self, **kwargs) -> ToolResult:
        from ..skills.registry import list_skills

        items = list_skills()
        return ToolResult(
            success=True,
            output={
                "count": len(items),
                "ready_count": sum(1 for s in items if s["available"]),
                "skills": items,
            },
        )


def register_skill_tools(registry: ToolRegistry) -> None:
    registry.register(SkillDispatch())
    registry.register(SkillCatalog())
