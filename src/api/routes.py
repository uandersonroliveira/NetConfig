import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from ..models.device import Device, DeviceCreate, BulkDeviceCreate, DeviceVendor, DeviceStatus
from ..models.config import CredentialCreate, CredentialResponse, ConfigComparison
from ..storage.json_storage import JsonStorage
from ..core.scanner import Scanner
from ..core.connector import Connector
from ..core.collector import Collector
from ..core.analyzer import ConfigAnalyzer
from ..core.comparator import ConfigComparator
from ..core.mac_finder import MacFinder
from ..utils.ip_utils import parse_bulk_ips, expand_ip_input
from .websocket import manager

router = APIRouter(prefix="/api")
storage = JsonStorage()
scanner = Scanner()
connector = Connector()
collector = Collector(storage, connector)
analyzer = ConfigAnalyzer()
comparator = ConfigComparator()
mac_finder = MacFinder(storage, connector)
executor = ThreadPoolExecutor(max_workers=4)


# Request/Response Models
class ScanRequest(BaseModel):
    ip_range: str


class CollectRequest(BaseModel):
    device_ips: Optional[List[str]] = None
    credential_id: Optional[str] = None


class CompareRequest(BaseModel):
    device1_ip: str
    device2_ip: str
    timestamp1: Optional[datetime] = None
    timestamp2: Optional[datetime] = None


class MacSearchRequest(BaseModel):
    mac_address: str
    use_cache: bool = True


# Device endpoints
@router.get("/devices")
async def list_devices():
    """List all registered devices."""
    devices = storage.list_devices()
    return {"devices": [d.model_dump() for d in devices]}


@router.post("/devices")
async def add_device(device: DeviceCreate):
    """Add a single device."""
    existing = storage.get_device(device.ip)
    if existing:
        raise HTTPException(status_code=400, detail="Device already exists")

    new_device = Device(
        ip=device.ip,
        hostname=device.hostname,
        vendor=device.vendor or DeviceVendor.UNKNOWN,
        credential_id=device.credential_id,
        notes=device.notes
    )
    storage.save_device(new_device)
    return {"message": "Device added", "device": new_device.model_dump()}


@router.post("/devices/bulk")
async def add_devices_bulk(bulk: BulkDeviceCreate):
    """Add multiple devices from comma/newline separated text."""
    ips = parse_bulk_ips(bulk.ips_text)
    if not ips:
        raise HTTPException(status_code=400, detail="No valid IP addresses found")

    added = []
    skipped = []

    for ip in ips:
        existing = storage.get_device(ip)
        if existing:
            skipped.append(ip)
            continue

        new_device = Device(
            ip=ip,
            vendor=bulk.vendor or DeviceVendor.UNKNOWN,
            credential_id=bulk.credential_id
        )
        storage.save_device(new_device)
        added.append(ip)

    return {
        "message": f"Added {len(added)} devices, skipped {len(skipped)} existing",
        "added": added,
        "skipped": skipped
    }


@router.get("/devices/{ip}")
async def get_device(ip: str):
    """Get device by IP."""
    device = storage.get_device(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"device": device.model_dump()}


@router.put("/devices/{ip}")
async def update_device(ip: str, updates: DeviceCreate):
    """Update device information."""
    device = storage.get_device(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if updates.hostname:
        device.hostname = updates.hostname
    if updates.vendor:
        device.vendor = updates.vendor
    if updates.credential_id:
        device.credential_id = updates.credential_id
    if updates.notes:
        device.notes = updates.notes

    storage.save_device(device)
    return {"message": "Device updated", "device": device.model_dump()}


@router.delete("/devices/{ip}")
async def delete_device(ip: str):
    """Delete a device."""
    if storage.delete_device(ip):
        return {"message": "Device deleted"}
    raise HTTPException(status_code=404, detail="Device not found")


@router.post("/devices/bulk-delete")
async def bulk_delete_devices(request: BulkDeleteRequest):
    """Delete multiple devices at once."""
    if not request.device_ips:
        raise HTTPException(status_code=400, detail="No devices specified")

    deleted = []
    not_found = []

    for ip in request.device_ips:
        if storage.delete_device(ip):
            deleted.append(ip)
        else:
            not_found.append(ip)

    return {
        "message": f"Deleted {len(deleted)} devices",
        "deleted": deleted,
        "not_found": not_found
    }


# Device status check
class StatusCheckRequest(BaseModel):
    device_ips: Optional[List[str]] = None


class BulkDeleteRequest(BaseModel):
    device_ips: List[str]


@router.post("/devices/check-status")
async def check_devices_status(request: StatusCheckRequest, background_tasks: BackgroundTasks):
    """Check SSH connectivity status for devices."""

    if request.device_ips:
        devices = [storage.get_device(ip) for ip in request.device_ips]
        devices = [d for d in devices if d is not None]
    else:
        devices = storage.list_devices()

    if not devices:
        raise HTTPException(status_code=400, detail="No devices to check")

    device_ips = [d.ip for d in devices]

    def run_status_check():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        total = len(device_ips)
        online_count = 0
        offline_count = 0

        def progress_callback(current: int, total: int, ip: str, is_open: bool = None):
            loop.run_until_complete(manager.broadcast_progress(
                'status_check', current, total,
                f"Checking {ip}",
                success=True
            ))

        results = scanner.scan_with_details(','.join(device_ips), progress_callback)

        for ip, result in results.items():
            device = storage.get_device(ip)
            if device:
                if result.get('ssh_open'):
                    device.status = DeviceStatus.ONLINE
                    online_count += 1
                else:
                    device.status = DeviceStatus.OFFLINE
                    offline_count += 1
                storage.save_device(device)

        loop.run_until_complete(manager.broadcast_complete('status_check', {
            'total': total,
            'online': online_count,
            'offline': offline_count
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_status_check).result())
    return {"message": "Status check started", "devices_count": len(devices)}


# Scan endpoints
@router.post("/scan")
async def scan_network(request: ScanRequest, background_tasks: BackgroundTasks):
    """Scan IP range for devices with open SSH ports."""
    ip_range = request.ip_range

    def run_scan_sync():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        ips = expand_ip_input(ip_range)
        total = len(ips)
        found = []

        def progress_callback(current: int, total: int, ip: str, is_open: bool = None):
            loop.run_until_complete(manager.broadcast_progress(
                'scan', current, total,
                f"Scanning {ip}",
                success=True
            ))

        results = scanner.scan_with_details(ip_range, progress_callback)

        for ip, result in results.items():
            if result.get('ssh_open'):
                found.append(ip)
                existing = storage.get_device(ip)
                if not existing:
                    new_device = Device(ip=ip, status=DeviceStatus.ONLINE)
                    storage.save_device(new_device)

        loop.run_until_complete(manager.broadcast_complete('scan', {
            'total_scanned': total,
            'devices_found': len(found),
            'devices': found
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_scan_sync).result())
    return {"message": "Scan started", "ip_range": ip_range}


# Collection endpoints
@router.post("/collect")
async def collect_configs(request: CollectRequest, background_tasks: BackgroundTasks):
    """Collect configurations from devices."""

    if request.device_ips:
        devices = [storage.get_device(ip) for ip in request.device_ips]
        devices = [d for d in devices if d is not None]
    else:
        devices = storage.list_devices()

    if not devices:
        raise HTTPException(status_code=400, detail="No devices to collect from")

    cred = None
    if request.credential_id:
        cred = storage.get_credential(request.credential_id)
    else:
        cred = storage.get_default_credential()

    if not cred:
        raise HTTPException(status_code=400, detail="No credentials available. Please add credentials first.")

    password = storage.get_decrypted_password(cred.id)
    device_list = devices.copy()
    username = cred.username

    def run_collection_sync():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        total = len(device_list)
        success_count = 0
        fail_count = 0

        def progress_callback(current: int, total: int, ip: str, success: bool):
            loop.run_until_complete(manager.broadcast_progress(
                'collect', current, total,
                f"{'Collected' if success else 'Failed'}: {ip}",
                success=success
            ))

        results = collector.collect_devices(device_list, username, password, progress_callback)

        for result in results:
            if result.success:
                success_count += 1
            else:
                fail_count += 1

        loop.run_until_complete(manager.broadcast_complete('collect', {
            'total': total,
            'success': success_count,
            'failed': fail_count
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_collection_sync).result())
    return {"message": "Collection started", "devices_count": len(devices)}


# Config endpoints
@router.get("/configs/{ip}")
async def get_config_history(ip: str):
    """Get configuration history for a device."""
    history = storage.get_config_history(ip)
    return {
        "device_ip": ip,
        "configs": [
            {
                "timestamp": c.timestamp,
                "duration": c.collection_duration,
                "has_parsed_data": c.parsed_data is not None
            }
            for c in history
        ]
    }


@router.get("/configs/{ip}/latest")
async def get_latest_config(ip: str):
    """Get latest configuration for a device."""
    config = storage.get_latest_config(ip)
    if not config:
        raise HTTPException(status_code=404, detail="No configuration found")

    return {
        "device_ip": ip,
        "timestamp": config.timestamp,
        "raw_config": config.raw_config,
        "parsed_data": config.parsed_data
    }


@router.post("/compare")
async def compare_configs(request: CompareRequest):
    """Compare configurations between two devices or timestamps."""
    if request.timestamp1:
        config1 = storage.get_config_by_timestamp(request.device1_ip, request.timestamp1)
    else:
        config1 = storage.get_latest_config(request.device1_ip)

    if request.timestamp2:
        config2 = storage.get_config_by_timestamp(request.device2_ip, request.timestamp2)
    else:
        config2 = storage.get_latest_config(request.device2_ip)

    if not config1:
        raise HTTPException(status_code=404, detail=f"No config found for {request.device1_ip}")
    if not config2:
        raise HTTPException(status_code=404, detail=f"No config found for {request.device2_ip}")

    comparison = comparator.compare_configs(config1, config2)
    return {"comparison": comparison.model_dump()}


# MAC search endpoints
@router.get("/mac/{mac_address}")
async def search_mac(mac_address: str, use_cache: bool = True):
    """Search for a MAC address across all devices."""
    if use_cache:
        results = mac_finder.search_mac_from_cache(mac_address)
    else:
        results = mac_finder.search_mac(mac_address)

    return {
        "mac_address": mac_finder.normalize_mac(mac_address),
        "found": len(results) > 0,
        "results": [r.to_dict() for r in results]
    }


@router.post("/mac/search")
async def search_mac_live(request: MacSearchRequest, background_tasks: BackgroundTasks):
    """Search for a MAC address with live device queries."""
    if request.use_cache:
        results = mac_finder.search_mac_from_cache(request.mac_address)
        return {
            "mac_address": mac_finder.normalize_mac(request.mac_address),
            "found": len(results) > 0,
            "results": [r.to_dict() for r in results]
        }

    async def run_search():
        def progress_callback(current: int, total: int, ip: str):
            asyncio.create_task(manager.broadcast_progress(
                'mac_search', current, total, f"Searching {ip}"
            ))

        results = mac_finder.search_mac(request.mac_address, progress_callback)

        await manager.broadcast_complete('mac_search', {
            'mac_address': mac_finder.normalize_mac(request.mac_address),
            'found': len(results) > 0,
            'results': [r.to_dict() for r in results]
        })

    background_tasks.add_task(run_search)
    return {"message": "MAC search started"}


# Credential endpoints
@router.get("/credentials")
async def list_credentials():
    """List all credentials (passwords masked)."""
    credentials = storage.list_credentials()
    return {
        "credentials": [
            CredentialResponse(
                id=c.id,
                username=c.username,
                is_default=c.is_default,
                description=c.description,
                created_at=c.created_at
            ).model_dump()
            for c in credentials
        ]
    }


@router.post("/credentials")
async def add_credential(cred: CredentialCreate):
    """Add a new credential."""
    new_cred = storage.save_credential(
        cred.username, cred.password, cred.is_default, cred.description
    )
    return {
        "message": "Credential added",
        "credential": CredentialResponse(
            id=new_cred.id,
            username=new_cred.username,
            is_default=new_cred.is_default,
            description=new_cred.description,
            created_at=new_cred.created_at
        ).model_dump()
    }


@router.put("/credentials/{credential_id}/default")
async def set_default_credential(credential_id: str):
    """Set a credential as default."""
    if storage.set_default_credential(credential_id):
        return {"message": "Default credential updated"}
    raise HTTPException(status_code=404, detail="Credential not found")


@router.delete("/credentials/{credential_id}")
async def delete_credential(credential_id: str):
    """Delete a credential."""
    if storage.delete_credential(credential_id):
        return {"message": "Credential deleted"}
    raise HTTPException(status_code=404, detail="Credential not found")


# Stats endpoint
@router.get("/stats")
async def get_stats():
    """Get dashboard statistics."""
    devices = storage.list_devices()
    credentials = storage.list_credentials()

    online = sum(1 for d in devices if d.status == DeviceStatus.ONLINE)
    offline = sum(1 for d in devices if d.status == DeviceStatus.OFFLINE)
    unknown = sum(1 for d in devices if d.status == DeviceStatus.UNKNOWN)

    huawei = sum(1 for d in devices if d.vendor == DeviceVendor.HUAWEI)
    hp = sum(1 for d in devices if d.vendor == DeviceVendor.HP)

    return {
        "total_devices": len(devices),
        "status": {
            "online": online,
            "offline": offline,
            "unknown": unknown
        },
        "vendors": {
            "huawei": huawei,
            "hp": hp,
            "unknown": len(devices) - huawei - hp
        },
        "credentials_count": len(credentials),
        "has_default_credential": any(c.is_default for c in credentials)
    }
