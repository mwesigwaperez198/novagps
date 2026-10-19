import hashlib

import pytest
from jose import jwt

from auth import Principal, get_current_principal, require_roles, ROLE_RANK
from config import get_settings


def test_dev_mode_returns_admin_principal():
    get_settings.cache_clear()
    try:
        from unittest.mock import patch
        with patch("auth.get_settings") as mock_settings:
            mock_settings.return_value.environment = "development"
            mock_settings.return_value.secret_key = "test"
            mock_settings.return_value.jwt_algorithm = "HS256"
            principal = get_current_principal(None)
            assert principal.role == "admin"
            assert "nova" in principal.subject
    finally:
        get_settings.cache_clear()


def test_missing_token_raises_401():
    from fastapi import HTTPException
    get_settings.cache_clear()
    try:
        from unittest.mock import patch
        with patch("auth.get_settings") as mock_settings:
            mock_settings.return_value.environment = "production"
            with pytest.raises(HTTPException) as exc_info:
                get_current_principal(None)
            assert exc_info.value.status_code == 401
    finally:
        get_settings.cache_clear()


def test_valid_jwt_decodes_principal():
    get_settings.cache_clear()
    try:
        secret = "test-secret-key-for-jwt"
        token = jwt.encode({"sub": "user@test.com", "role": "operator"}, secret, algorithm="HS256")
        from unittest.mock import patch
        with patch("auth.get_settings") as mock_settings:
            mock_settings.return_value.secret_key = secret
            mock_settings.return_value.jwt_algorithm = "HS256"
            mock_settings.return_value.environment = "production"
            principal = get_current_principal(token)
            assert principal.subject == "user@test.com"
            assert principal.role == "operator"
    finally:
        get_settings.cache_clear()


def test_invalid_jwt_raises_401():
    from fastapi import HTTPException
    get_settings.cache_clear()
    try:
        from unittest.mock import patch
        with patch("auth.get_settings") as mock_settings:
            mock_settings.return_value.secret_key = "correct-key"
            mock_settings.return_value.jwt_algorithm = "HS256"
            mock_settings.return_value.environment = "production"
            with pytest.raises(HTTPException) as exc_info:
                get_current_principal("garbage-token")
            assert exc_info.value.status_code == 401
    finally:
        get_settings.cache_clear()


def test_invalid_role_in_jwt_raises_403():
    from fastapi import HTTPException
    secret = "test-secret"
    token = jwt.encode({"sub": "hacker@test.com", "role": "superadmin"}, secret, algorithm="HS256")
    get_settings.cache_clear()
    try:
        from unittest.mock import patch
        with patch("auth.get_settings") as mock_settings:
            mock_settings.return_value.secret_key = secret
            mock_settings.return_value.jwt_algorithm = "HS256"
            mock_settings.return_value.environment = "production"
            with pytest.raises(HTTPException) as exc_info:
                get_current_principal(token)
            assert exc_info.value.status_code == 403
    finally:
        get_settings.cache_clear()


def test_require_roles_allows_matching_role():
    dep = require_roles("admin")
    principal = Principal(subject="a@b.com", role="admin")
    result = dep(principal)
    assert result.role == "admin"


def test_require_roles_operator_can_read_viewer():
    dep = require_roles("viewer")
    principal = Principal(subject="a@b.com", role="operator")
    result = dep(principal)
    assert result.role == "operator"


def test_require_roles_rejects_wrong_role():
    from fastapi import HTTPException
    dep = require_roles("admin")
    principal = Principal(subject="a@b.com", role="viewer")
    with pytest.raises(HTTPException) as exc_info:
        dep(principal)
    assert exc_info.value.status_code == 403


def test_role_rank_ordering():
    assert ROLE_RANK["viewer"] < ROLE_RANK["auditor"] < ROLE_RANK["operator"] < ROLE_RANK["admin"]


def test_owner_password_accepts_plural_alias(monkeypatch):
    from config import Settings

    monkeypatch.delenv("OWNER_PASSWORD", raising=False)
    monkeypatch.setenv("OWNERS_PASSWORD", "perez123!!")
    settings = Settings()
    assert settings.owner_password == "perez123!!"


def test_owner_password_prefers_canonical_name(monkeypatch):
    from config import Settings

    monkeypatch.setenv("OWNER_PASSWORD", "canonical")
    monkeypatch.setenv("OWNERS_PASSWORD", "plural")
    settings = Settings()
    assert settings.owner_password == "canonical"


class _EmptyQuery:
    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return None


class _EmptyDB:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def query(self, *args, **kwargs):
        return _EmptyQuery()


def test_broadcast_token_accepts_login_jwt(monkeypatch):
    import broadcast_auth
    import config

    secret = "broadcast-jwt-secret"

    class _Settings:
        environment = "production"
        secret_key = secret
        jwt_algorithm = "HS256"

    monkeypatch.setattr(config, "get_settings", lambda: _Settings())
    monkeypatch.setattr(broadcast_auth, "SessionLocal", lambda: _EmptyDB())

    owner = jwt.encode({"sub": "owner@test.com", "role": "admin"}, secret, algorithm="HS256")
    assert broadcast_auth.token_allowed(owner, "map") is True

    # Production must not accept anonymous listeners, and junk tokens fail closed.
    assert broadcast_auth.token_allowed(None, "map") is False
    assert broadcast_auth.token_allowed("not-a-jwt", "map") is False

    forged = jwt.encode({"sub": "x", "role": "admin"}, "wrong-secret", algorithm="HS256")
    assert broadcast_auth.token_allowed(forged, "map") is False


def test_broadcast_token_allows_dev_anonymous(monkeypatch):
    import broadcast_auth
    import config

    class _Settings:
        environment = "development"
        secret_key = "dev"
        jwt_algorithm = "HS256"

    monkeypatch.setattr(config, "get_settings", lambda: _Settings())
    assert broadcast_auth.token_allowed(None, "map") is True
