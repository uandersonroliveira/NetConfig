from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import uuid


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class DeviceVendor(str, Enum):
    HUAWEI = "huawei"
    HP = "hp"
    ARUBA = "aruba"
    CISCO = "cisco"
    INTELBRAS = "intelbras"  # H3C/Comware platform
    UBIQUITI = "ubiquiti"    # Ubiquiti APs
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
    poe_status: Optional[Dict[str, Any]] = None  # PoE utilization data
    port_status: Optional[Dict[str, Any]] = None  # Port utilization data

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


class DeviceGroup(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    device_ips: List[str] = []
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    class Config:
        use_enum_values = True


class DeviceGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    device_ips: List[str] = []


class DeviceGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    device_ips: Optional[List[str]] = None
