"""Cloud research: SSRF guard, HTML extraction, provider parsing, research flow."""

import types

import pytest

from nova_core import cloud


@pytest.fixture
def cloud_on(monkeypatch):
    """Let the cloud helpers run in tests (network is always monkeypatched)."""
    from nova_core import config as config_module

    config_module._config = None
    monkeypatch.setenv("NOVA_CLOUD_RESEARCH", "1")
    yield
    config_module._config = None


def _cfg_stub(**overrides):
    base = dict(
        cloud_research=True,
        cloud_max_sources=3,
        cloud_timeout=5,
        cloud_max_bytes=100000,
        search_provider="duckduckgo",
        search_api_key="",
        search_base_url="",
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


class TestSsrfGuard:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://metadata.google.internal/",
        "http://foo.internal/",
        "http://printer.local/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "http://user:pass@example.com/",
        "http://example.com:8080/",
        "http://intranet/",
    ])
    def test_blocked(self, url):
        ok, reason = cloud._check_url(url)
        assert not ok, f"{url} should be blocked"
        assert reason

    def test_public_ip_literal_allowed(self):
        ok, reason = cloud._check_url("https://1.1.1.1/")
        assert ok, reason

    def test_private_ip_classification(self):
        assert not cloud._is_public_ip("127.0.0.1")
        assert not cloud._is_public_ip("169.254.169.254")
        assert not cloud._is_public_ip("10.255.255.1")
        assert cloud._is_public_ip("8.8.8.8")

    def test_redirect_handler_revalidates(self, monkeypatch):
        handler = cloud._SafeRedirectHandler()

        class _Req:
            pass

        with pytest.raises(Exception):
            handler.redirect_request(
                _Req(), None, 302, "Found", {}, "http://169.254.169.254/"
            )


class TestHtmlExtraction:
    def test_strips_scripts_and_reads_title(self):
        raw = (
            "<html><head><title>Nuclei &amp; You</title>"
            "<style>body{color:red}</style></head>"
            "<body><script>alert('x')</script><h1>Install</h1>"
            "<p>Run apt-get install nuclei</p></body></html>"
        )
        title, text = cloud.html_to_text(raw)
        assert title == "Nuclei & You"
        assert "alert" not in text
        assert "color:red" not in text
        assert "Run apt-get install nuclei" in text

    def test_empty_input(self):
        assert cloud.html_to_text("") == ("", "")


class TestProviderParsers:
    def test_brave(self):
        data = {"web": {"results": [{"title": "T", "url": "https://a", "description": "d"}]}}
        hits = cloud._parse_brave(data)
        assert hits[0]["url"] == "https://a"
        assert hits[0]["source"] == "brave"

    def test_tavily(self):
        hits = cloud._parse_tavily({"results": [{"title": "T", "url": "https://b", "content": "c"}]})
        assert hits[0]["url"] == "https://b"

    def test_serper(self):
        hits = cloud._parse_serper({"organic": [{"title": "T", "link": "https://c", "snippet": "s"}]})
        assert hits[0]["url"] == "https://c"

    def test_duckduckgo_nested_topics(self):
        data = {
            "AbstractText": "About TCP",
            "AbstractURL": "https://example.com/tcp",
            "Heading": "TCP",
            "RelatedTopics": [
                {"Topics": [{"Text": "IPv6", "FirstURL": "https://example.com/ipv6"}]},
                {"Text": "UDP", "FirstURL": "https://example.com/udp"},
            ],
        }
        hits = cloud._parse_ddg(data)
        urls = {h["url"] for h in hits}
        assert "https://example.com/tcp" in urls
        assert "https://example.com/udp" in urls
        assert "https://example.com/ipv6" in urls

    def test_wikipedia_builds_url(self):
        hits = cloud._parse_wikipedia({"query": {"search": [{"title": "Nmap", "snippet": "scanner"}]}})
        assert hits[0]["url"] == "https://en.wikipedia.org/wiki/Nmap"


class TestResearchFlow:
    def test_research_combines_search_and_fetch(self, monkeypatch, cloud_on):
        from nova_core.tools import cloud as tool_cloud

        monkeypatch.setattr(tool_cloud, "_cfg", lambda: _cfg_stub())
        monkeypatch.setattr(cloud, "get_config", lambda: _cfg_stub())
        monkeypatch.setattr(cloud, "search_web", lambda *a, **k: {
            "provider": "duckduckgo",
            "query": "nmap",
            "results": [
                {"title": "Nmap Guide", "url": "https://a.example/1", "snippet": "s1", "source": "x"},
                {"title": "Nmap Docs", "url": "https://b.example/2", "snippet": "s2", "source": "x"},
            ],
            "notes": [],
        })
        monkeypatch.setattr(cloud, "fetch_url", lambda url, **k: {
            "ok": True, "url": url, "content_type": "text/html",
            "title": "Fetched", "text": "x" * 5000, "truncated": False,
        })
        data = cloud.research("nmap", max_sources=2)
        assert data["ok"]
        assert len(data["sources"]) == 2
        assert data["sources"][0]["fetched"] is True
        assert data["sources"][0]["excerpt"].endswith("…")

    def test_research_falls_back_to_snippets_when_fetch_fails(self, monkeypatch, cloud_on):
        monkeypatch.setattr(cloud, "get_config", lambda: _cfg_stub())
        monkeypatch.setattr(cloud, "search_web", lambda *a, **k: {
            "provider": "duckduckgo", "query": "x", "notes": [],
            "results": [{"title": "T", "url": "https://a.example", "snippet": "s", "source": "x"}],
        })
        monkeypatch.setattr(cloud, "fetch_url", lambda url, **k: {"ok": False, "url": url, "error": "HTTP 403"})
        data = cloud.research("x", max_sources=1)
        assert data["ok"]
        assert data["sources"][0]["fetched"] is False
        assert data["sources"][0]["excerpt"] == "s"

    def test_research_disabled_returns_error(self, monkeypatch):
        monkeypatch.setattr(cloud, "get_config", lambda: _cfg_stub(cloud_research=False))
        data = cloud.research("x")
        assert not data["ok"]
        assert "disabled" in data["error"]

    def test_search_falls_back_when_key_missing(self, monkeypatch, cloud_on):
        monkeypatch.setattr(cloud, "get_config", lambda: _cfg_stub(search_provider="brave", search_api_key=""))
        called = {}

        def fake_ddg(query, limit, timeout):
            called["ddg"] = True
            return [{"title": "T", "url": "https://a.example", "snippet": "s", "source": "ddg"}]

        monkeypatch.setattr(cloud, "_search_ddg", fake_ddg)
        data = cloud.search_web("anything", max_results=3)
        assert called.get("ddg")
        assert data["provider"] == "duckduckgo"
        assert any("requires NOVA_SEARCH_API_KEY" in n for n in data["notes"])
