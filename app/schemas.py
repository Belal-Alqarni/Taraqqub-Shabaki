from typing import Literal

from pydantic import BaseModel, Field


class DeviceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    ip_address: str = Field(min_length=3, max_length=64)
    role: str = Field(default="server", max_length=40)
    vendor: str = Field(default="Unknown", max_length=80)
    location: str = Field(default="Main Site", max_length=80)


class IncidentQuestion(BaseModel):
    device_id: int | None = None
    symptom: str = Field(min_length=3, max_length=500)


class LoginRequest(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=8, max_length=200)


class UserCreate(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    role: Literal["viewer", "operator", "admin"] = "viewer"


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=8, max_length=200)
    new_password: str = Field(min_length=12, max_length=200)
