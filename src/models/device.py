from enum import Enum
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class DeviceVendor(str, Enum):
    HUAWEI = "huawei"
    HP = "hp"
    UNKNOWN = "unknown"


class Device(BaseModel):
    ip: str
    hostname: Optional[str] = None
    model: Optional[str] = None
    vendor: DeviceVendor = DeviceVendor.UNKNOWN
    status: DeviceStatus = DeviceStatus.UNKNOWN
    credential_id: Optional[str] = None
    last_scan: Optional[datetime] = None
    last_config_collection: Optional[datetime] = None
    notes: Optional[str] = None

    class Config:
        use_enum_values = True


class DeviceCreate(BaseModel):
    ip: str
    hostname: Optional[str] = None
    vendor: Optional[DeviceVendor] = None
    credential_id: Optional[str] = None
    notes: Optional[str] = None


class BulkDeviceCreate(BaseModel):
    ips_text: str = Field(..., description="Comma, newline, space, or semicolon separated IPs")
    vendor: Optional[DeviceVendor] = None
    credential_id: Optional[str] = None
