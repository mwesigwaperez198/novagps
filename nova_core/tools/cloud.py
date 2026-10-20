"""Cloud research tools — read-only, no execution, no operator data out."""

from __future__ import annotations

from ..tools import Tool, ToolResult, ToolRegistry

_MAX_EXCERPT = 6000


def _cfg():
    from ..config import get_config

    return get_config()


def _enabled() -> bool:
    try:
        return bool(_cfg().cloud_research)
    except Exception:  # noqa: BLE001 — fail closed
        return False


class CloudResearchTool(Tool):
    name = "cloud_research"
    description = (
        "Read-only web research. Searches public sources, fetches the top pages, "
        "and returns titles, URLs, and quoted excerpts. Use when a question needs "
        "information the local tools cannot provide (guides, CVEs, vendor docs, "
        "how-to steps, current status). Returns source URLs for citation. Never "
        "executes anything and never sends operator data off-host."
    )
    category = "cloud"

    def preflight(self) -> dict:
        if not _enabled():
            return {"status": "disabled", "reason": "NOVA_CLOUD_RESEARCH=0"}
        cfg = _cfg()
        return {
            "status": "ready",
            "provider": cfg.search_provider,
            "search_api_key_configured": bool(cfg.search_api_key),
            "searxng_configured": bool(cfg.search_base_url),
            "max_sources": cfg.cloud_max_sources,
        }

    def execute(self, query="", max_sources=None, provider="", **kwargs) -> ToolResult:
        if not _enabled():
            return ToolResult(success=False, output=None,
                              error="cloud research is disabled (NOVA_CLOUD_RESEARCH=0)")
        q = str(query or "").strip()
        if not q:
            return ToolResult(success=False, output=None, error="query is required")
        try:
            from ..cloud import research as _research

            data = _research(
                q,
                max_sources=max_sources,
                provider=str(provider).strip() or None,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(success=False, output=None, error=str(exc))
        return ToolResult(success=bool(data.get("ok")), output=data,
                          error=None if data.get("ok") else data.get("error", "no sources"))


class WebSearchTool(Tool):
    name = "web_search"
    description = (
        "Search public web sources and return titles, URLs, and snippets without "
        "fetching the pages. Cheaper than cloud_research when only a pointer is "
        "needed. Read-only; no cookies, no credentials, no operator data."
    )
    category = "cloud"

    def preflight(self) -> dict:
        if not _enabled():
            return {"status": "disabled", "reason": "NOVA_CLOUD_RESEARCH=0"}
        return {"status": "ready", "provider": _cfg().search_provider}

    def execute(self, query="", max_results=5, provider="", **kwargs) -> ToolResult:
        if not _enabled():
            return ToolResult(success=False, output=None,
                              error="cloud research is disabled (NOVA_CLOUD_RESEARCH=0)")
        q = str(query or "").strip()
        if not q:
            return ToolResult(success=False, output=None, error="query is required")
        try:
            from ..cloud import search_web as _search_web

            data = _search_web(
                q,
                max_results=int(max_results or 5),
                provider=str(provider).strip() or None,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(success=False, output=None, error=str(exc))
        return ToolResult(success=True, output=data)


class FetchUrlTool(Tool):
    name = "fetch_url"
    description = (
        "Fetch one public http/https page read-only and return its plain text. "
        "Refuses private, loopback, link-local, and cloud-metadata addresses, "
        "honours robots.txt, and caps the body size. Text is returned as quoted "
        "data only — it is never executed."
    )
    category = "cloud"

    def preflight(self) -> dict:
        if not _enabled():
            return {"status": "disabled", "reason": "NOVA_CLOUD_RESEARCH=0"}
        return {"status": "ready", "max_bytes": _cfg().cloud_max_bytes}

    def execute(self, url="", **kwargs) -> ToolResult:
        if not _enabled():
            return ToolResult(success=False, output=None,
                              error="cloud research is disabled (NOVA_CLOUD_RESEARCH=0)")
        target = str(url or "").strip()
        if not target:
            return ToolResult(success=False, output=None, error="url is required")
        try:
            from ..cloud import fetch_url as _fetch_url

            data = _fetch_url(target)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(success=False, output=None, error=str(exc))
        if not data.get("ok"):
            return ToolResult(success=False, output=None, error=data.get("error", "fetch failed"))
        text = data.get("text") or ""
        data["text"] = text[:_MAX_EXCERPT]
        data["excerpt_of"] = len(text)
        return ToolResult(success=True, output=data)


def register_cloud_tools(registry: ToolRegistry) -> None:
    registry.register(CloudResearchTool())
    registry.register(WebSearchTool())
    registry.register(FetchUrlTool())
