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


class DiscoverRequest(BaseModel):
    device_ips: Optional[List[str]] = None
    credential_id: Optional[str] = None
    add_neighbors: bool = True


class CollectRequest(BaseModel):
    device_ips: Optional[List[str]] = None
    credential_id: Optional[str] = None


class CompareRequest(BaseModel):
    device1_ip: str
    device2_ip: str
    timestamp1: Optional[datetime] = None
    timestamp2: Optional[datetime] = None


class BatchCompareRequest(BaseModel):
    reference_ip: str
    target_ips: List[str]


class MacSearchRequest(BaseModel):
    mac_address: str
    use_cache: bool = True


# Request models for device operations
class StatusCheckRequest(BaseModel):
    device_ips: Optional[List[str]] = None


class LogCollectRequest(BaseModel):
    device_ips: List[str]
    credential_id: Optional[str] = None


class BulkDeleteRequest(BaseModel):
    device_ips: List[str]


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


# IMPORTANT: Specific paths must come BEFORE parameterized paths like /devices/{ip}
@router.post("/devices/bulk")
async def add_devices_bulk(bulk: BulkDeviceCreate):
    """
    Add multiple devices from comma/newline separated text.
    Supports IP ranges (192.168.1.1-10) and CIDR notation (192.168.1.0/24).
    """
    ips = expand_ip_input(bulk.ips_text)
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


# Parameterized device routes (must come AFTER specific paths)
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


@router.post("/discover")
async def discover_neighbors(request: DiscoverRequest, background_tasks: BackgroundTasks):
    """Discover network neighbors via LLDP/CDP from known devices."""

    if request.device_ips:
        devices = [storage.get_device(ip) for ip in request.device_ips]
        devices = [d for d in devices if d is not None and d.vendor != DeviceVendor.UNKNOWN]
    else:
        devices = [d for d in storage.list_devices() if d.vendor != DeviceVendor.UNKNOWN]

    if not devices:
        raise HTTPException(status_code=400, detail="No devices with known vendor to query")

    cred = None
    if request.credential_id:
        cred = storage.get_credential(request.credential_id)
    else:
        cred = storage.get_default_credential()

    if not cred:
        raise HTTPException(status_code=400, detail="No credentials available")

    password = storage.get_decrypted_password(cred.id)
    device_list = devices.copy()
    username = cred.username
    add_neighbors = request.add_neighbors

    def run_discovery_sync():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        total = len(device_list)
        all_neighbors = []
        new_devices = []

        for idx, device in enumerate(device_list, 1):
            loop.run_until_complete(manager.broadcast_progress(
                'discover', idx, total,
                f"Discovering neighbors on {device.ip}",
                success=True,
                extra={'device_ip': device.ip, 'status': 'in_progress'}
            ))

            try:
                result = connector.discover_neighbors(
                    device.ip, username, password, device.vendor
                )

                lldp_count = len(result.get('lldp_neighbors', []))
                cdp_count = len(result.get('cdp_neighbors', []))

                for neighbor in result.get('lldp_neighbors', []):
                    neighbor['source'] = 'lldp'
                    neighbor['source_device'] = device.ip
                    all_neighbors.append(neighbor)

                for neighbor in result.get('cdp_neighbors', []):
                    neighbor['source'] = 'cdp'
                    neighbor['source_device'] = device.ip
                    all_neighbors.append(neighbor)

                loop.run_until_complete(manager.broadcast_progress(
                    'discover', idx, total,
                    f"Found {lldp_count} LLDP, {cdp_count} CDP neighbors on {device.ip}",
                    success=True,
                    extra={'device_ip': device.ip, 'status': 'completed',
                           'lldp_count': lldp_count, 'cdp_count': cdp_count}
                ))
            except Exception as e:
                loop.run_until_complete(manager.broadcast_progress(
                    'discover', idx, total,
                    f"Failed to discover on {device.ip}: {str(e)}",
                    success=False,
                    extra={'device_ip': device.ip, 'status': 'failed', 'error': str(e)}
                ))

        # Add discovered neighbors as devices if requested
        if add_neighbors and all_neighbors:
            existing_ips = {d.ip for d in storage.list_devices()}
            for neighbor in all_neighbors:
                neighbor_name = neighbor.get('neighbor_device', '')
                if neighbor_name and neighbor_name not in existing_ips:
                    detected_vendor = connector.detect_vendor_from_neighbors(neighbor_name)
                    new_devices.append({
                        'name': neighbor_name,
                        'vendor': detected_vendor.value if detected_vendor else 'unknown',
                        'source': neighbor.get('source'),
                        'source_device': neighbor.get('source_device')
                    })

        loop.run_until_complete(manager.broadcast_complete('discover', {
            'total_devices_queried': total,
            'neighbors_found': len(all_neighbors),
            'neighbors': all_neighbors,
            'new_devices': new_devices
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_discovery_sync).result())
    return {"message": "Discovery started", "devices_count": len(devices)}


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


# Store collected logs in memory (per session)
collected_logs = {}


@router.post("/logs/collect")
async def collect_logs(request: LogCollectRequest, background_tasks: BackgroundTasks):
    """Collect logs from selected devices."""
    if not request.device_ips:
        raise HTTPException(status_code=400, detail="No devices selected")

    devices = [storage.get_device(ip) for ip in request.device_ips]
    devices = [d for d in devices if d is not None]

    if not devices:
        raise HTTPException(status_code=400, detail="No valid devices found")

    cred = None
    if request.credential_id:
        cred = storage.get_credential(request.credential_id)
    else:
        cred = storage.get_default_credential()

    if not cred:
        raise HTTPException(status_code=400, detail="No credentials available")

    password = storage.get_decrypted_password(cred.id)
    device_list = devices.copy()
    username = cred.username

    # Return device info for progress tracking
    device_info = [{'ip': d.ip, 'hostname': d.hostname or d.ip, 'vendor': d.vendor} for d in devices]

    def run_log_collection():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        total = len(device_list)
        results = []

        for idx, device in enumerate(device_list, 1):
            device_ip = device.ip
            hostname = device.hostname or device.ip

            # Broadcast progress - starting
            loop.run_until_complete(manager.broadcast_progress(
                'logs', idx, total, f"Collecting logs from {hostname}",
                extra={'device_ip': device_ip, 'status': 'collecting'}
            ))

            try:
                if device.vendor == 'unknown':
                    raise Exception("Unknown device vendor")

                driver = connector.create_connection(
                    device_ip, username, password, device.vendor
                )

                try:
                    logs = driver.get_logs()
                    collected_logs[device_ip] = {
                        'device_ip': device_ip,
                        'hostname': hostname,
                        'vendor': device.vendor,
                        'timestamp': datetime.now().isoformat(),
                        'logs': logs,
                        'success': True
                    }
                    results.append({
                        'device_ip': device_ip,
                        'hostname': hostname,
                        'success': True,
                        'log_size': len(logs)
                    })
                finally:
                    driver.disconnect()

                # Broadcast progress - success
                loop.run_until_complete(manager.broadcast_progress(
                    'logs', idx, total, f"Collected logs from {hostname}",
                    extra={'device_ip': device_ip, 'status': 'success'}
                ))

            except Exception as e:
                collected_logs[device_ip] = {
                    'device_ip': device_ip,
                    'hostname': hostname,
                    'vendor': device.vendor,
                    'timestamp': datetime.now().isoformat(),
                    'logs': None,
                    'success': False,
                    'error': str(e)
                }
                results.append({
                    'device_ip': device_ip,
                    'hostname': hostname,
                    'success': False,
                    'error': str(e)
                })

                # Broadcast progress - failed
                loop.run_until_complete(manager.broadcast_progress(
                    'logs', idx, total, f"Failed: {hostname}",
                    extra={'device_ip': device_ip, 'status': 'error'}
                ))

        # Broadcast completion
        success_count = sum(1 for r in results if r['success'])
        loop.run_until_complete(manager.broadcast_complete('logs', {
            'total': total,
            'success': success_count,
            'failed': total - success_count,
            'results': results
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_log_collection).result())
    return {"message": "Log collection started", "devices": device_info}


@router.get("/logs/{ip}")
async def get_device_logs(ip: str):
    """Get collected logs for a device."""
    if ip not in collected_logs:
        raise HTTPException(status_code=404, detail="Logs not found for this device")

    return collected_logs[ip]


@router.get("/logs")
async def list_collected_logs():
    """List all collected logs."""
    return {
        "logs": [
            {
                'device_ip': log['device_ip'],
                'hostname': log['hostname'],
                'vendor': log['vendor'],
                'timestamp': log['timestamp'],
                'success': log['success'],
                'log_size': len(log['logs']) if log['logs'] else 0
            }
            for log in collected_logs.values()
        ]
    }


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


# Store comparison reports in memory (could be persisted to JSON)
comparison_reports = []


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


@router.post("/compare/batch")
async def batch_compare_configs(request: BatchCompareRequest, background_tasks: BackgroundTasks):
    """Compare reference device configuration against multiple target devices."""
    global comparison_reports

    reference_config = storage.get_latest_config(request.reference_ip)
    if not reference_config:
        raise HTTPException(status_code=404, detail=f"No config found for reference device {request.reference_ip}")

    if not request.target_ips:
        raise HTTPException(status_code=400, detail="No target devices specified")

    reference_ip = request.reference_ip
    target_ips = request.target_ips.copy()

    def run_batch_compare():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        total = len(target_ips)
        results = []
        report_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        for i, target_ip in enumerate(target_ips):
            loop.run_until_complete(manager.broadcast_progress(
                'compare', i + 1, total,
                f"Comparing with {target_ip}",
                success=True
            ))

            target_config = storage.get_latest_config(target_ip)
            if not target_config:
                results.append({
                    'target_ip': target_ip,
                    'success': False,
                    'error': 'No configuration found'
                })
                continue

            try:
                comparison = comparator.compare_configs(reference_config, target_config)
                results.append({
                    'target_ip': target_ip,
                    'target_hostname': storage.get_device(target_ip).hostname if storage.get_device(target_ip) else target_ip,
                    'success': True,
                    'summary': comparison.summary,
                    'differences': comparison.differences[:50]  # Limit to first 50 diffs
                })
            except Exception as e:
                results.append({
                    'target_ip': target_ip,
                    'success': False,
                    'error': str(e)
                })

        # Store the report
        report = {
            'id': report_id,
            'timestamp': datetime.now().isoformat(),
            'reference_ip': reference_ip,
            'reference_hostname': storage.get_device(reference_ip).hostname if storage.get_device(reference_ip) else reference_ip,
            'total_targets': total,
            'successful': sum(1 for r in results if r.get('success')),
            'failed': sum(1 for r in results if not r.get('success')),
            'results': results
        }
        comparison_reports.insert(0, report)
        # Keep only last 20 reports
        if len(comparison_reports) > 20:
            comparison_reports.pop()

        loop.run_until_complete(manager.broadcast_complete('compare', {
            'report_id': report_id,
            'total': total,
            'successful': report['successful'],
            'failed': report['failed']
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_batch_compare).result())
    return {"message": "Batch comparison started", "target_count": len(target_ips)}


@router.get("/compare/reports")
async def get_comparison_reports():
    """Get list of comparison reports."""
    return {"reports": comparison_reports}


@router.get("/compare/reports/{report_id}")
async def get_comparison_report(report_id: str):
    """Get a specific comparison report by ID."""
    for report in comparison_reports:
        if report['id'] == report_id:
            return {"report": report}
    raise HTTPException(status_code=404, detail="Report not found")


# MAC search endpoints
@router.get("/mac/{mac_address}")
async def search_mac(mac_address: str, use_cache: bool = True):
    """
    Search for a MAC address across all devices.
    Supports wildcard patterns: * matches any sequence, ? matches single character.
    Examples: "00:11:22:*", "00:11:??:33:*", "0011*"
    """
    if use_cache:
        results = mac_finder.search_mac_from_cache(mac_address)
    else:
        results = mac_finder.search_mac(mac_address)

    # For wildcard searches, show the pattern; for exact, show normalized MAC
    is_wildcard = mac_finder.is_wildcard_pattern(mac_address)
    display_mac = mac_address if is_wildcard else (mac_finder.normalize_mac(mac_address) or mac_address)

    return {
        "mac_address": display_mac,
        "is_wildcard": is_wildcard,
        "found": len(results) > 0,
        "results": [r.to_dict() for r in results]
    }


@router.post("/mac/search")
async def search_mac_live(request: MacSearchRequest, background_tasks: BackgroundTasks):
    """Search for a MAC address with live device queries across all online devices."""
    mac_address = request.mac_address
    is_wildcard = mac_finder.is_wildcard_pattern(mac_address)
    display_mac = mac_address if is_wildcard else (mac_finder.normalize_mac(mac_address) or mac_address)

    # Get list of devices for initial response
    devices = storage.list_devices()
    device_list = [{'ip': d.ip, 'hostname': d.hostname or d.ip, 'vendor': d.vendor} for d in devices]

    def run_mac_search():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        device_statuses = {}

        def progress_callback(current: int, total: int, ip: str):
            # Update device status
            device_statuses[ip] = 'searching'
            loop.run_until_complete(manager.broadcast_progress(
                'mac_search', current, total, f"Searching {ip}",
                extra={'device_ip': ip, 'device_statuses': device_statuses.copy()}
            ))
            # Mark as complete after broadcast
            device_statuses[ip] = 'complete'

        results = mac_finder.search_mac(mac_address, progress_callback)

        loop.run_until_complete(manager.broadcast_complete('mac_search', {
            'mac_address': display_mac,
            'is_wildcard': is_wildcard,
            'found': len(results) > 0,
            'results': [r.to_dict() for r in results]
        }))
        loop.close()

    background_tasks.add_task(lambda: executor.submit(run_mac_search).result())
    return {"message": "MAC search started", "mac_address": display_mac, "devices": device_list}


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
