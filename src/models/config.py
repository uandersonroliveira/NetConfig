from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class Credential(BaseModel):
    id: str
    username: str
    encrypted_password: str
    is_default: bool = False
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)


class CredentialCreate(BaseModel):
    username: str
    password: str
    is_default: bool = False
    description: Optional[str] = None


class CredentialResponse(BaseModel):
    id: str
    username: str
    is_default: bool
    description: Optional[str]
    created_at: datetime


class ConfigSnapshot(BaseModel):
    device_ip: str
    timestamp: datetime
    raw_config: str
    parsed_data: Optional[Dict[str, Any]] = None
    collection_duration: Optional[float] = None


class ParsedConfig(BaseModel):
    hostname: Optional[str] = None
    model: Optional[str] = None
    version: Optional[str] = None
    vlans: List[Dict[str, Any]] = []
    interfaces: List[Dict[str, Any]] = []
    mac_table: List[Dict[str, Any]] = []
    arp_table: List[Dict[str, Any]] = []
    users: List[Dict[str, Any]] = []
    acls: List[Dict[str, Any]] = []
    snmp_config: Optional[Dict[str, Any]] = None
    stp_config: Optional[Dict[str, Any]] = None


class ConfigComparison(BaseModel):
    device1_ip: str
    device2_ip: str
    device1_timestamp: datetime
    device2_timestamp: datetime
    differences: List[Dict[str, Any]]
    summary: Dict[str, int]
