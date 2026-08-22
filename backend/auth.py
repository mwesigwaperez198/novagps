from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from config import get_settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


ROLE_RANK = {"viewer": 10, "auditor": 20, "operator": 30, "admin": 40}


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str


def get_current_principal(token: str | None = Depends(oauth2_scheme)) -> Principal:
    settings = get_settings()
    if not token and settings.environment == "development":
        return Principal(subject="dev-admin@nova.local", role="admin")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    subject = payload.get("sub")
    role = payload.get("role", "viewer")
    if not subject or role not in ROLE_RANK:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid principal claims")
    return Principal(subject=subject, role=role)


def require_roles(*roles: str) -> Callable[[Principal], Principal]:
    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        allowed = set(roles)
        elevated_reader = principal.role == "operator" and "viewer" in allowed
        if principal.role != "admin" and principal.role not in allowed and not elevated_reader:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return principal

    return dependency
