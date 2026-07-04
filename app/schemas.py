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


class SignupRequest(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    password: str = Field(min_length=12, max_length=200)
    workspace_name: str = Field(min_length=2, max_length=80)


class AgentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class AgentDeviceReport(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    ip_address: str = Field(min_length=3, max_length=64)
    role: str = Field(default="endpoint", max_length=40)
    vendor: str = Field(default="Unknown", max_length=80)
    status: Literal["online", "degraded", "down"] = "online"
    latency_ms: float = Field(default=0, ge=0, le=120000)
    packet_loss: float = Field(default=0, ge=0, le=100)
    cpu_usage: float = Field(default=0, ge=0, le=100)
    memory_usage: float = Field(default=0, ge=0, le=100)
    traffic_in_mbps: float = Field(default=0, ge=0)
    traffic_out_mbps: float = Field(default=0, ge=0)


class AgentReport(BaseModel):
    devices: list[AgentDeviceReport] = Field(min_length=1, max_length=256)
