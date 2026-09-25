"""
AegisSec - Authentication & Role-Based Access Control (RBAC)
JWT tokens, session verification, and role-based route protection.
"""

import time
import json
import base64
import hmac
import hashlib
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .db import db, hash_password
from .models import UserModel, RoleEnum

JWT_SECRET = "aegissec_jwt_super_secret_signing_key_2026"
JWT_ALGORITHM = "HS256"
security_bearer = HTTPBearer(auto_error=False)


def create_access_token(user_id: str, username: str, role: str, expires_in_seconds: int = 86400) -> str:
    """
    Generates an RFC 7519 compliant HMAC-SHA256 JSON Web Token.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": int(time.time()) + expires_in_seconds,
        "iat": int(time.time())
    }

    def b64_encode(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    header_b64 = b64_encode(header)
    payload_b64 = b64_encode(payload)
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), message, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token")

        header_b64, payload_b64, signature_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), message, hashlib.sha256).digest()
        
        # Pad signature if needed
        pad_len = 4 - (len(signature_b64) % 4)
        sig_to_verify = signature_b64 + ("=" * (pad_len % 4))
        actual_sig = base64.urlsafe_b64decode(sig_to_verify)

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Invalid signature")

        pad_len_p = 4 - (len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + ("=" * (pad_len_p % 4)))
        payload = json.loads(payload_bytes.decode("utf-8"))

        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")

        return payload
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> UserModel:
    if not credentials:
        # Fallback to demo default admin if no header provided during local dev testing
        user = db.get_user_by_username("admin")
        if user:
            return UserModel(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                role=RoleEnum(user["role"]),
                created_at=user["created_at"]
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_access_token(credentials.credentials)
    user = db.get_user_by_id(payload.get("sub"))
    if not user and payload.get("username"):
        user = db.get_user_by_username(payload.get("username"))
    if not user:
        if payload.get("username") and payload.get("role"):
            try:
                role_enum = RoleEnum(payload["role"])
            except Exception:
                role_enum = RoleEnum.DEVELOPER
            return UserModel(
                id=payload.get("sub") or f"u-{payload['username']}",
                username=payload["username"],
                email=payload.get("email") or f"{payload['username']}@cloudsec.internal",
                role=role_enum,
                created_at="2026-01-01T00:00:00"
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account not found")

    return UserModel(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=RoleEnum(user["role"]),
        created_at=user["created_at"]
    )


def require_roles(allowed_roles: List[str]):
    def role_checker(current_user: UserModel = Depends(get_current_user)) -> UserModel:
        if current_user.role.value not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Operation requires one of the following roles: {allowed_roles}. Current role: {current_user.role.value}"
            )
        return current_user
    return role_checker
