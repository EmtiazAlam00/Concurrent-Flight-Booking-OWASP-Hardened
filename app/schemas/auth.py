import uuid
from datetime import datetime
from typing import Annotated

from pydantic import EmailStr, Field, field_validator

from app.schemas.common import ResponseModel, StrictModel

#: Length beats composition rules. NIST SP 800-63B explicitly recommends
#: dropping mandatory character-class rules in favour of a longer minimum and
#: screening against known-breached passwords (the latter is documented future
#: work; see SECURITY.md).
Password = Annotated[str, Field(min_length=12, max_length=128)]


class RegisterRequest(StrictModel):
    email: EmailStr
    password: Password
    full_name: Annotated[str | None, Field(default=None, max_length=200)]

    @field_validator("password")
    @classmethod
    def not_obviously_weak(cls, v: str) -> str:
        lowered = v.lower()
        if lowered in {"password1234", "letmeinplease", "qwertyuiop12"}:
            raise ValueError("password is too common")
        return v


class LoginRequest(StrictModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]


class RefreshRequest(StrictModel):
    refresh_token: Annotated[str, Field(min_length=16, max_length=512)]


class TokenResponse(ResponseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - a scheme name, not a secret
    expires_in: int


class UserResponse(ResponseModel):
    id: uuid.UUID
    email: str
    full_name: str | None
    is_admin: bool
    created_at: datetime
