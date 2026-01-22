"""Discovery helper functions for neighbor discovery operations."""

import asyncio
from typing import List, Dict, Any, Optional, Callable
from ..models.device import Device, DeviceVendor, DeviceStatus
from ..storage.json_storage import JsonStorage


class DiscoveryHelper:
    """Helper class for device discovery operations."""

    def __init__(self, storage: JsonStorage, scanner, connector):
        self.storage = storage
        self.scanner = scanner
        self.connector = connector

    def scan_ip_range(
        self,
        ips: List[str],
        progress_callback: Optional[Callable] = None
    ) -> List[str]:
        """
        Scan a list of IPs for SSH connectivity.

        Args:
            ips: List of IP addresses to scan
            progress_callback: Optional callback(idx, total, ip, found_count)

        Returns:
            List of IPs with open SSH ports
        """
        found_ips = []

        for idx, ip in enumerate(ips, 1):
            if self.scanner.check_ssh_port(ip):
                found_ips.append(ip)

            if progress_callback and (idx % 10 == 0 or idx == len(ips)):
                progress_callback(idx, len(ips), ip, len(found_ips))

        return found_ips

    def detect_vendor_and_get_neighbors(
        self,
        ip: str,
        username: str,
        password: str,
        vendors_to_try: List[DeviceVendor] = None
    ) -> Dict[str, Any]:
        """
        Try to detect device vendor and get neighbors.

        Args:
            ip: Device IP address
            username: SSH username
            password: SSH password
            vendors_to_try: List of vendors to attempt (default: common vendors)

        Returns:
            Dict with 'vendor', 'lldp_neighbors', 'cdp_neighbors', 'success'
        """
        if vendors_to_try is None:
            vendors_to_try = [
                DeviceVendor.HUAWEI,
                DeviceVendor.HP,
                DeviceVendor.ARUBA,
                DeviceVendor.CISCO
            ]

        result = {
            'vendor': None,
            'lldp_neighbors': [],
            'cdp_neighbors': [],
            'success': False
        }

        for vendor in vendors_to_try:
            try:
                driver_class = self.connector.get_driver_class(vendor)
                driver = driver_class(ip, username, password, timeout=10)

                if driver.connect():
                    result['vendor'] = vendor
                    result['success'] = True

                    # Get neighbors while connected
                    try:
                        result['lldp_neighbors'] = driver.get_lldp_neighbors()
                    except Exception:
                        pass

                    try:
                        result['cdp_neighbors'] = driver.get_cdp_neighbors()
                    except Exception:
                        pass

                    driver.disconnect()
                    break

            except Exception:
                continue

        return result

    def process_neighbors(
        self,
        neighbors: List[Dict],
        source: str,
        source_device: str
    ) -> List[Dict]:
        """
        Add source metadata to neighbor entries.

        Args:
            neighbors: List of neighbor dicts
            source: Source protocol ('lldp' or 'cdp')
            source_device: IP of the device that reported neighbors

        Returns:
            List of neighbors with source metadata added
        """
        for neighbor in neighbors:
            neighbor['source'] = source
            neighbor['source_device'] = source_device
        return neighbors

    def identify_new_devices(
        self,
        neighbors: List[Dict],
        existing_ips: set
    ) -> List[Dict]:
        """
        Identify new devices from neighbor data.

        Args:
            neighbors: List of neighbor dicts with 'neighbor_device' field
            existing_ips: Set of IPs already in storage

        Returns:
            List of new device candidates
        """
        new_devices = []
        seen = set()

        for neighbor in neighbors:
            neighbor_name = neighbor.get('neighbor_device', '')
            if neighbor_name and neighbor_name not in existing_ips and neighbor_name not in seen:
                seen.add(neighbor_name)
                detected_vendor = self.connector.detect_vendor_from_neighbors(neighbor_name)
                new_devices.append({
                    'name': neighbor_name,
                    'vendor': detected_vendor.value if detected_vendor else 'unknown',
                    'source': neighbor.get('source'),
                    'source_device': neighbor.get('source_device')
                })

        return new_devices

    def save_discovered_device(
        self,
        ip: str,
        vendor: DeviceVendor,
        status: DeviceStatus = DeviceStatus.ONLINE
    ) -> bool:
        """
        Save a newly discovered device if it doesn't exist.

        Args:
            ip: Device IP address
            vendor: Detected vendor
            status: Device status (default: ONLINE)

        Returns:
            True if device was saved, False if already exists
        """
        existing = self.storage.get_device(ip)
        if not existing:
            new_device = Device(ip=ip, vendor=vendor, status=status)
            self.storage.save_device(new_device)
            return True
        return False


def create_discovery_result(
    devices_queried: int,
    neighbors: List[Dict],
    new_devices: List[Dict],
    extra: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Create a standardized discovery result dict.

    Args:
        devices_queried: Number of devices successfully queried
        neighbors: List of all discovered neighbors
        new_devices: List of identified new device candidates
        extra: Additional fields to include

    Returns:
        Standardized result dict
    """
    result = {
        'total_devices_queried': devices_queried,
        'neighbors_found': len(neighbors),
        'neighbors': neighbors,
        'new_devices': new_devices
    }

    if extra:
        result.update(extra)

    return result
