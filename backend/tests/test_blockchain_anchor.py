import hashlib
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db import Base
import models
import blockchain_anchor


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, future=True)()


def test_genesis_hash_constant():
    assert blockchain_anchor.GENESIS_HASH == "0" * 64


def test_sha256_deterministic():
    h1 = blockchain_anchor._sha256("hello")
    h2 = blockchain_anchor._sha256("hello")
    assert h1 == h2
    assert len(h1) == 64


def test_anchor_consent_event_creates_record():
    session = _session()
    anchor = blockchain_anchor.anchor_consent_event(
        session, consent_id="c1", device_id="d1", action="capture",
        payload={"source": "manual", "scope": "tracking"},
    )
    assert anchor.record_id is not None
    assert anchor.previous_hash == blockchain_anchor.GENESIS_HASH
    assert anchor.chain_hash != blockchain_anchor.GENESIS_HASH
    assert anchor.action == "capture"


def test_chain_links_successively():
    session = _session()
    a1 = blockchain_anchor.anchor_consent_event(
        session, consent_id="c1", device_id="d1", action="capture",
        payload={"scope": "gps"},
    )
    a2 = blockchain_anchor.anchor_consent_event(
        session, consent_id="c2", device_id="d1", action="revoke",
        payload={"reason": "user asked"},
    )
    assert a2.previous_hash == a1.chain_hash
    assert a2.chain_hash != a1.chain_hash


def test_verify_chain_valid():
    session = _session()
    blockchain_anchor.anchor_consent_event(session, "c1", "d1", "capture", {"x": 1})
    blockchain_anchor.anchor_consent_event(session, "c2", "d1", "revoke", {"x": 2})
    result = blockchain_anchor.verify_chain(session)
    assert result["valid"] is True
    assert result["checked"] == 2
    assert result["broken_at"] is None


def test_verify_chain_empty():
    session = _session()
    result = blockchain_anchor.verify_chain(session)
    assert result["valid"] is True
    assert result["checked"] == 0


def test_get_consent_history():
    session = _session()
    blockchain_anchor.anchor_consent_event(session, "c1", "d1", "capture", {"scope": "gps"})
    blockchain_anchor.anchor_consent_event(session, "c2", "d1", "revoke", {"reason": "test"})
    history = blockchain_anchor.get_consent_history(session, "d1")
    assert len(history) == 2
    assert history[0]["action"] == "revoke"
    assert history[1]["action"] == "capture"


def test_get_consent_history_empty():
    session = _session()
    history = blockchain_anchor.get_consent_history(session, "nonexistent")
    assert history == []


def test_chain_hash_is_sha256():
    session = _session()
    anchor = blockchain_anchor.anchor_consent_event(session, "c1", "d1", "capture", {"x": 1})
    assert len(anchor.chain_hash) == 64
    assert all(c in "0123456789abcdef" for c in anchor.chain_hash)


def test_multiple_devices_isolated():
    session = _session()
    a1 = blockchain_anchor.anchor_consent_event(session, "c1", "dev-a", "capture", {"x": 1})
    a2 = blockchain_anchor.anchor_consent_event(session, "c2", "dev-b", "capture", {"x": 2})
    assert a1.previous_hash == blockchain_anchor.GENESIS_HASH
    assert a2.previous_hash == a1.chain_hash

    history_a = blockchain_anchor.get_consent_history(session, "dev-a")
    history_b = blockchain_anchor.get_consent_history(session, "dev-b")
    assert len(history_a) == 1
    assert len(history_b) == 1
