"""Shared test settings.

Cloud research must never fire during the suite: it is a network call and it
would make every test slow and flaky. Tests that actually exercise the cloud
module re-enable it explicitly on the config instance.
"""

import pytest


@pytest.fixture(autouse=True)
def offline_cloud(monkeypatch):
    from nova_core import config as config_module

    previous = config_module._config
    config_module._config = None
    monkeypatch.setenv("NOVA_CLOUD_RESEARCH", "0")
    monkeypatch.delenv("NOVA_SEARCH_API_KEY", raising=False)
    yield
    config_module._config = previous
