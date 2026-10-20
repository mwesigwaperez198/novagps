"""Read-only cloud research for LAU.

Contract:
- GET only (the one POST exception is a search-provider API call, which sends
  the query and nothing else — no cookies, no referer, no operator data).
- Every URL is resolved and checked against private / link-local / metadata
  ranges before, during, and after redirects (SSRF guard).
- robots.txt is respected for page fetches.
- Response bodies are size- and content-type-capped, scripts stripped, and
  handed back as plain text for the model to read.
- Nothing fetched here is ever executed: web content is untrusted data, never
  instructions. Commands are never auto-run from a page.

Search providers, in order of preference:
1. A paid JSON API when NOVA_SEARCH_API_KEY is set (brave / tavily / serper).
2. A self-hosted SearXNG when NOVA_SEARCH_BASE_URL is set.
3. Keyless fallback: DuckDuckGo Instant Answer API + Wikipedia.
"""

from __future__ import annotations

import contextlib
import html
import ipaddress
import json
import logging
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from datetime import datetime, timezone
from typing import Optional

try:  # type: ignore  # isolated unit tests may run without package context
    from .config import get_config
except Exception:  # pragma: no cover
    from config import get_config

logger = logging.getLogger("nova_core.cloud")

USER_AGENT = "NovaGPS/1.0 (+https://novagps.onrender.com)"
DEFAULT_TIMEOUT = 20
MAX_BYTES = 1_500_000
REDIRECT_LIMIT = 3
ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PORTS = {None, 80, 443}
TEXT_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "text/markdown",
    "text/xml",
    "application/json",
    "application/xml",
    "text/csv",
}

_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".home.arpa",
    ".onion",
    ".lan",
)
_BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "metadata", "metadata.google.internal"}


class CloudError(RuntimeError):
    """A cloud call failed in a way the operator should see plainly."""


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        return _is_public_ip(str(ip.ipv4_mapped))
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    if not ip.is_global:
        return False
    # Belt and braces for ranges some Python builds classify as global.
    for net in _EXPLICIT_BLOCKED:
        if ip in net:
            return False
    return True


_EXPLICIT_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "169.254.169.254/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
    )
]


def _check_url(url: str) -> tuple[bool, str]:
    """Validate scheme, port, host shape, and every resolved address."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return False, f"malformed URL: {exc}"
    if parts.scheme not in ALLOWED_SCHEMES:
        return False, "only http/https URLs are allowed"
    if parts.username or parts.password:
        return False, "URLs with embedded credentials are refused"
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return False, "URL has no host"
    port = parts.port
    if port not in ALLOWED_PORTS:
        return False, f"port {port} is not allowed (only 80 and 443)"
    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_HOST_SUFFIXES):
        return False, "host is local or internal"
    if len(host) > 253:
        return False, "host name too long"

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not _is_public_ip(str(literal)):
            return False, "address is not a public internet address"
        return True, ""

    if "." not in host:
        return False, "single-label hostnames are refused"
    try:
        infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except OSError:
        # Some resolvers answer A records only under AF_INET (seen in sandboxes).
        try:
            infos = socket.getaddrinfo(host, port or 443, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            return False, "host did not resolve"
    if not infos:
        return False, "host did not resolve"
    for info in infos:
        addr = info[4][0]
        if not _is_public_ip(addr):
            return False, f"host resolves to a private address ({addr})"
    return True, ""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every hop; a public first URL can redirect to metadata."""

    max_redirections = REDIRECT_LIMIT

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        ok, reason = _check_url(newurl)
        if not ok:
            raise urllib.error.HTTPError(
                newurl, code, f"blocked redirect: {reason}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _request(url: str, timeout: int, max_bytes: int, accept: str = "*/*") -> dict:
    """One validated GET. Returns a plain dict; never raises on network errors."""
    ok, reason = _check_url(url)
    if not ok:
        return {"ok": False, "url": url, "error": reason}
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": accept,
            "Accept-Language": "en",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as resp:
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            raw = resp.read(max_bytes + 1)
            truncated = len(raw) > max_bytes
            raw = raw[:max_bytes]
            charset = resp.headers.get_content_charset() or "utf-8"
            try:
                text = raw.decode(charset, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "url": resp.geturl(),
                "status": getattr(resp, "status", None) or resp.getcode(),
                "content_type": ctype,
                "text": text,
                "truncated": truncated,
            }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "url": url, "status": exc.code, "error": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        return {"ok": False, "url": url, "error": f"network: {exc.reason}"}
    except Exception as exc:  # noqa: BLE001 — surfaced to the operator verbatim
        return {"ok": False, "url": url, "error": str(exc)}


_ROBOTS_CACHE: dict[str, tuple[float, Optional[urllib.robotparser.RobotFileParser]]] = {}


def _robots_allowed(url: str, timeout: int) -> bool:
    parts = urllib.parse.urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    now = time.time()
    cached = _ROBOTS_CACHE.get(base)
    if cached and cached[0] > now:
        rules = cached[1]
    else:
        rules = None
        try:
            doc = _request(
                f"{base}/robots.txt", min(timeout, 8), 65536, accept="text/plain,*/*"
            )
            if doc.get("ok") and doc.get("content_type") in ("", "text/plain", "text/html"):
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(doc["text"].splitlines())
                rules = rp
        except Exception:  # noqa: BLE001 — absence of robots.txt means "allowed"
            rules = None
        _ROBOTS_CACHE[base] = (now + 3600, rules)
    if rules is None:
        return True
    try:
        return bool(rules.can_fetch(USER_AGENT, url))
    except Exception:  # noqa: BLE001
        return True


_SCRIPT_RE = re.compile(r"(?is)<(script|style|noscript|svg|template|iframe|object)\b[^>]*>.*?</\1\s*>")
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_ANY_TAG_RE = re.compile(r"(?s)<[^>]+>")
_BLOCK_END_RE = re.compile(r"(?is)</(p|div|li|h[1-6]|tr|section|article|blockquote|pre)>")
_BR_RE = re.compile(r"(?is)<br\s*/?>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_BLANK_RE = re.compile(r"\n\s*\n+")


def html_to_text(raw: str) -> tuple[str, str]:
    """Strip scripts/styles/markup and return (title, plain text)."""
    if not raw:
        return "", ""
    title_match = _TITLE_RE.search(raw)
    title = ""
    if title_match:
        title = _WS_RE.sub(" ", _ANY_TAG_RE.sub(" ", html.unescape(title_match.group(1)))).strip()
    cleaned = _SCRIPT_RE.sub(" ", raw)
    cleaned = _BR_RE.sub("\n", cleaned)
    cleaned = _BLOCK_END_RE.sub("\n", cleaned)
    text = _ANY_TAG_RE.sub(" ", cleaned)
    text = html.unescape(text)
    text = _WS_RE.sub(" ", text)
    text = _BLANK_RE.sub("\n\n", text)
    return title, text.strip()


def fetch_url(url: str, timeout: Optional[int] = None, max_bytes: Optional[int] = None) -> dict:
    """Fetch a public page read-only and return title + plain text."""
    cfg = get_config()
    timeout = int(timeout or cfg.cloud_timeout)
    max_bytes = int(max_bytes or cfg.cloud_max_bytes)
    if not cfg.cloud_research:
        return {"ok": False, "url": url, "error": "cloud research is disabled (NOVA_CLOUD_RESEARCH=0)"}
    ok, reason = _check_url(url)
    if not ok:
        return {"ok": False, "url": url, "error": reason}
    if not _robots_allowed(url, timeout):
        return {"ok": False, "url": url, "error": "robots.txt disallows fetching this URL"}
    doc = _request(
        url,
        timeout,
        max_bytes,
        accept="text/html,application/xhtml+xml,application/json,text/plain,text/xml;q=0.9,*/*;q=0.5",
    )
    if not doc.get("ok"):
        return doc
    if doc.get("content_type") and doc["content_type"] not in TEXT_TYPES:
        return {
            "ok": False,
            "url": url,
            "error": f"unsupported content type ({doc['content_type']}); text only",
        }
    if doc["content_type"] in ("text/html", "application/xhtml+xml"):
        title, text = html_to_text(doc["text"])
    else:
        title, text = "", doc["text"]
    return {
        "ok": True,
        "url": doc["url"],
        "status": doc.get("status"),
        "content_type": doc.get("content_type", ""),
        "title": title,
        "text": text,
        "truncated": doc.get("truncated", False),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def _http_json(
    url: str,
    timeout: int = 20,
    payload: Optional[dict] = None,
    extra_headers: Optional[dict] = None,
) -> dict:
    """Call a search provider. POST is allowed only for provider APIs, and only
    the query is in the body — never cookies, headers from our host, or data."""
    method = "POST" if payload is not None else "GET"
    ok, reason = _check_url(url)
    if not ok:
        raise CloudError(f"provider endpoint refused: {reason}")
    data = None
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(4_000_000)
        return json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(400).decode("utf-8", "replace")[:200]
        except Exception:  # noqa: BLE001
            detail = ""
        raise CloudError(f"provider returned HTTP {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        if _looks_like_dns_failure(exc):
            try:
                with _ipv4_only():
                    with opener.open(req, timeout=timeout) as resp:
                        raw = resp.read(4_000_000)
                return json.loads(raw.decode("utf-8", errors="replace"))
            except urllib.error.URLError as exc2:
                raise CloudError(f"provider unreachable: {exc2.reason}") from exc2
        raise CloudError(f"provider unreachable: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise CloudError("provider returned a non-JSON body") from exc


@contextlib.contextmanager
def _ipv4_only():
    """Retry under AF_INET for resolvers that only answer A records."""
    original = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        return original(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = patched
    try:
        yield
    finally:
        socket.getaddrinfo = original


def _looks_like_dns_failure(exc: urllib.error.URLError) -> bool:
    reason = str(getattr(exc, "reason", exc))
    return any(marker in reason for marker in (
        "Name or service not known", "Name does not resolve",
        "Temporary failure in name resolution", "nodename nor servname",
    ))


def _clean_snippet(value: str, limit: int = 400) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", "", value or ""))
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _hit(title: str, url: str, snippet: str = "", source: str = "") -> dict:
    return {
        "title": _clean_snippet(title, 200),
        "url": (url or "").strip(),
        "snippet": _clean_snippet(snippet),
        "source": source,
    }


def _parse_brave(data: dict) -> list[dict]:
    out = []
    for r in ((data.get("web") or {}).get("results") or []):
        out.append(_hit(r.get("title", ""), r.get("url", ""), r.get("description", ""), "brave"))
    return out


def _parse_tavily(data: dict) -> list[dict]:
    return [_hit(r.get("title", ""), r.get("url", ""), r.get("content", ""), "tavily")
            for r in (data.get("results") or [])]


def _parse_serper(data: dict) -> list[dict]:
    return [_hit(r.get("title", ""), r.get("link", ""), r.get("snippet", ""), "serper")
            for r in (data.get("organic") or [])]


def _parse_ddg(data: dict) -> list[dict]:
    out = []
    if data.get("AbstractURL") and data.get("AbstractText"):
        out.append(_hit(
            data.get("Heading") or data.get("AbstractSource", ""),
            data.get("AbstractURL", ""),
            data.get("AbstractText", ""),
            "duckduckgo",
        ))
    stack = list(data.get("Results") or []) + list(data.get("RelatedTopics") or [])
    seen = set()
    while stack and len(out) < 12:
        item = stack.pop(0)
        if not isinstance(item, dict):
            continue
        if "Topics" in item:
            stack.extend(item.get("Topics") or [])
            continue
        url = item.get("FirstURL", "")
        if url and url not in seen:
            seen.add(url)
            out.append(_hit(item.get("Text", ""), url, item.get("Text", ""), "duckduckgo"))
    return out


def _parse_wikipedia(data: dict) -> list[dict]:
    out = []
    for r in (((data.get("query") or {}).get("search")) or []):
        title = r.get("title", "")
        url = "https://en.wikipedia.org/wiki/" + urllib.parse.quote(title.replace(" ", "_"))
        out.append(_hit(title, url, r.get("snippet", ""), "wikipedia"))
    return out


def _search_wikipedia(query: str, limit: int, timeout: int) -> list[dict]:
    url = (
        "https://en.wikipedia.org/w/api.php?action=query&list=search&format=json"
        f"&utf8=1&srlimit={limit}&srsearch={urllib.parse.quote_plus(query)}"
    )
    return _parse_wikipedia(_http_json(url, timeout=timeout))


def _search_ddg(query: str, limit: int, timeout: int) -> list[dict]:
    url = (
        "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1"
        f"&q={urllib.parse.quote_plus(query)}"
    )
    hits = _parse_ddg(_http_json(url, timeout=timeout))
    if len(hits) < limit:
        try:
            hits.extend(_search_wikipedia(query, limit - len(hits), timeout))
        except CloudError as exc:
            logger.info("wikipedia fallback skipped: %s", exc)
    return hits


def _search_brave(query: str, limit: int, key: str, timeout: int) -> list[dict]:
    url = (
        "https://api.search.brave.com/res/v1/web/search"
        f"?q={urllib.parse.quote_plus(query)}&count={limit}&safesearch=strict"
    )
    data = _http_json(
        url,
        timeout=timeout,
        extra_headers={"X-Subscription-Token": key},
    )
    if not isinstance(data, dict):
        raise CloudError("brave returned an unexpected payload")
    return _parse_brave(data)


def _search_tavily(query: str, limit: int, key: str, timeout: int) -> list[dict]:
    url = "https://api.tavily.com/search"
    data = _http_json(url, timeout=timeout, payload={
        "api_key": key,
        "query": query,
        "max_results": limit,
        "include_answer": False,
        "include_raw_content": False,
    })
    return _parse_tavily(data)


def _search_serper(query: str, limit: int, key: str, timeout: int) -> list[dict]:
    url = "https://google.serper.dev/search"
    data = _http_json(url, timeout=timeout, payload={
        "q": query,
        "num": limit,
    })
    return _parse_serper(data)


def _search_searx(query: str, limit: int, base: str, timeout: int) -> list[dict]:
    url = (
        f"{base}/search?format=json&categories=general&language=en"
        f"&q={urllib.parse.quote_plus(query)}"
    )
    data = _http_json(url, timeout=timeout)
    hits = []
    for r in (data.get("results") or [])[: limit * 2]:
        hits.append(_hit(r.get("title", ""), r.get("url", ""), r.get("content", ""), "searxng"))
    return hits[:limit]


_PROVIDERS = ("brave", "tavily", "serper", "searxng", "duckduckgo", "wikipedia")


def search_web(
    query: str,
    max_results: int = 5,
    provider: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict:
    """Search public sources. Falls back to the keyless path on purpose."""
    cfg = get_config()
    timeout = int(timeout or min(cfg.cloud_timeout, 20))
    max_results = max(1, min(int(max_results or 5), 10))
    query = (query or "").strip()
    if not query:
        raise CloudError("query is required")
    if not cfg.cloud_research:
        raise CloudError("cloud research is disabled (NOVA_CLOUD_RESEARCH=0)")

    chosen = (provider or cfg.search_provider or "duckduckgo").lower()
    if chosen == "auto":
        chosen = (
            "brave" if cfg.search_api_key
            else "searxng" if cfg.search_base_url
            else "duckduckgo"
        )
    if chosen not in _PROVIDERS:
        chosen = "duckduckgo"

    notes: list[str] = []
    key = cfg.search_api_key
    base = cfg.search_base_url
    runner = None
    if chosen in ("brave", "tavily", "serper") and not key:
        notes.append(f"{chosen} requires NOVA_SEARCH_API_KEY; using the keyless fallback instead.")
        chosen = "duckduckgo"
    elif chosen == "searxng" and not base:
        notes.append("searxng requires NOVA_SEARCH_BASE_URL; using the keyless fallback instead.")
        chosen = "duckduckgo"

    if chosen == "brave":
        runner = lambda q, n, t: _search_brave(q, n, key, t)
    elif chosen == "tavily":
        runner = lambda q, n, t: _search_tavily(q, n, key, t)
    elif chosen == "serper":
        runner = lambda q, n, t: _search_serper(q, n, key, t)
    elif chosen == "searxng":
        runner = lambda q, n, t: _search_searx(q, n, base, t)
    elif chosen == "wikipedia":
        runner = lambda q, n, t: _search_wikipedia(q, n, t)
    else:
        chosen = "duckduckgo"
        runner = _search_ddg

    try:
        hits = runner(query, max_results, timeout)
    except CloudError as exc:
        logger.warning("search provider %s failed: %s", chosen, exc)
        notes.append(f"{chosen} failed ({exc}); falling back to Wikipedia.")
        try:
            hits = _search_wikipedia(query, max_results, timeout)
            chosen = "wikipedia"
        except CloudError as exc2:
            raise CloudError(f"all search providers failed: {exc2}") from exc2

    deduped, seen = [], set()
    for h in hits:
        u = (h.get("url") or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        deduped.append(h)
        if len(deduped) >= max_results:
            break

    if not deduped:
        notes.append("No results came back for that query. Try different wording.")
    if chosen == "duckduckgo":
        notes.append(
            "Keyless search (DuckDuckGo instant answers + Wikipedia) is a limited index. "
            "Set NOVA_SEARCH_API_KEY (brave/tavily/serper) for full web coverage."
        )
    return {"provider": chosen, "query": query, "results": deduped, "notes": notes}


def _compress(text: str, limit: int = 2200) -> str:
    text = _WS_RE.sub(" ", text)
    text = _BLANK_RE.sub("\n", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    # Prefer a sentence/word boundary so an excerpt does not end mid-word.
    for boundary in (". ", "\n", " "):
        idx = cut.rfind(boundary)
        if idx > limit * 0.6:
            return cut[: idx + len(boundary)].rstrip() + " …"
    return cut.rstrip() + " …"


def research(
    query: str,
    max_sources: Optional[int] = None,
    provider: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict:
    """Search, then fetch the top pages so the model can quote real sources."""
    cfg = get_config()
    if not cfg.cloud_research:
        return {"ok": False, "query": query, "error": "cloud research is disabled (NOVA_CLOUD_RESEARCH=0)", "sources": []}
    limit = int(max_sources or cfg.cloud_max_sources)
    limit = max(1, min(limit, 6))
    query = (query or "").strip()
    if not query:
        return {"ok": False, "query": query, "error": "query is required", "sources": []}

    try:
        found = search_web(query, max_results=max(4, limit * 2), provider=provider, timeout=timeout)
    except CloudError as exc:
        return {"ok": False, "query": query, "error": str(exc), "sources": [], "notes": []}

    notes = list(found.get("notes") or [])
    sources: list[dict] = []
    seen: set = set()
    for hit in found.get("results", []):
        if len(sources) >= limit:
            break
        url = (hit.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        page = fetch_url(url, timeout=timeout)
        title = hit.get("title", "")
        excerpt = hit.get("snippet", "")
        fetched = False
        if page.get("ok"):
            fetched = True
            title = page.get("title") or title or url
            body = page.get("text") or ""
            if body:
                excerpt = _compress(body)
        entry = {
            "title": title,
            "url": page.get("url", url),
            "excerpt": excerpt,
            "fetched": fetched,
            "content_type": page.get("content_type", ""),
        }
        if not fetched and page.get("error"):
            entry["note"] = str(page["error"])[:160]
        sources.append(entry)

    if not sources:
        return {
            "ok": False,
            "query": query,
            "provider": found.get("provider", ""),
            "results": found.get("results", []),
            "sources": [],
            "notes": notes + ["Nothing could be fetched for this query."],
        }
    return {
        "ok": True,
        "query": query,
        "provider": found.get("provider", ""),
        "sources": sources,
        "notes": notes,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
