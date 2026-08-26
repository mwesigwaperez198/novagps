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
