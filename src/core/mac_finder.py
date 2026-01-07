import re
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
from ..models.device import Device, DeviceVendor
from ..storage.json_storage import JsonStorage
from .connector import Connector


class MacSearchResult:
    """Result of a MAC address search."""

    def __init__(self, mac_address: str, device_ip: str, device_hostname: str,
                 interface: str, vlan: int, vendor: str):
        self.mac_address = mac_address
        self.device_ip = device_ip
        self.device_hostname = device_hostname
        self.interface = interface
        self.vlan = vlan
        self.vendor = vendor

    def to_dict(self) -> Dict[str, Any]:
        return {
            'mac_address': self.mac_address,
            'device_ip': self.device_ip,
            'device_hostname': self.device_hostname,
            'interface': self.interface,
            'vlan': self.vlan,
            'vendor': self.vendor
        }


class MacFinder:
    """Searches for MAC addresses across network devices."""

    def __init__(self, storage: JsonStorage, connector: Connector = None,
                 max_workers: int = 10):
        self.storage = storage
        self.connector = connector or Connector()
        self.max_workers = max_workers

    def normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to lowercase colon-separated format."""
        mac = mac.lower()
        mac = re.sub(r'[^0-9a-f]', '', mac)
        if len(mac) != 12:
            return ''
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    def search_mac(self, mac_address: str,
                   progress_callback: Optional[Callable[[int, int, str], None]] = None
                   ) -> List[MacSearchResult]:
        """
        Search for a MAC address across all devices.

        Args:
            mac_address: MAC address to search for (any format)
            progress_callback: Optional callback(current, total, device_ip)

        Returns:
            List of MacSearchResult where the MAC was found
        """
        normalized_mac = self.normalize_mac(mac_address)
        if not normalized_mac:
            return []

        devices = self.storage.list_devices()
        results = []
        total = len(devices)
        current = 0

        default_cred = self.storage.get_default_credential()

        def search_device(device: Device) -> Optional[MacSearchResult]:
            cred_id = device.credential_id or (default_cred.id if default_cred else None)
            if not cred_id:
                return None

            cred = self.storage.get_credential(cred_id)
            if not cred:
                return None

            password = self.storage.get_decrypted_password(cred_id)

            try:
                if device.vendor == DeviceVendor.UNKNOWN:
                    return None

                driver = self.connector.create_connection(
                    device.ip, cred.username, password, device.vendor
                )

                try:
                    mac_table = driver.get_mac_table()

                    for entry in mac_table:
                        if entry.get('mac_address') == normalized_mac:
                            return MacSearchResult(
                                mac_address=normalized_mac,
                                device_ip=device.ip,
                                device_hostname=device.hostname or device.ip,
                                interface=entry.get('interface', 'unknown'),
                                vlan=entry.get('vlan', 0),
                                vendor=device.vendor
                            )
                finally:
                    driver.disconnect()

            except Exception:
                pass

            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(search_device, device): device
                for device in devices
            }

            for future in concurrent.futures.as_completed(future_to_device):
                current += 1
                device = future_to_device[future]

                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception:
                    pass

                if progress_callback:
                    progress_callback(current, total, device.ip)

        return results

    def search_mac_from_cache(self, mac_address: str) -> List[MacSearchResult]:
        """
        Search for a MAC address using cached configuration data.
        Faster than live search but may not be up to date.
        """
        normalized_mac = self.normalize_mac(mac_address)
        if not normalized_mac:
            return []

        results = []
        devices = self.storage.list_devices()

        for device in devices:
            latest_config = self.storage.get_latest_config(device.ip)
            if not latest_config or not latest_config.parsed_data:
                continue

            mac_table = latest_config.parsed_data.get('mac_table', [])
            for entry in mac_table:
                if entry.get('mac_address') == normalized_mac:
                    results.append(MacSearchResult(
                        mac_address=normalized_mac,
                        device_ip=device.ip,
                        device_hostname=device.hostname or device.ip,
                        interface=entry.get('interface', 'unknown'),
                        vlan=entry.get('vlan', 0),
                        vendor=device.vendor
                    ))

        return results

    def get_all_macs_for_device(self, device_ip: str,
                                use_cache: bool = True) -> List[Dict[str, Any]]:
        """
        Get all MAC addresses for a specific device.

        Args:
            device_ip: Device IP address
            use_cache: If True, use cached data; if False, query live

        Returns:
            List of MAC table entries
        """
        if use_cache:
            config = self.storage.get_latest_config(device_ip)
            if config and config.parsed_data:
                return config.parsed_data.get('mac_table', [])
            return []

        device = self.storage.get_device(device_ip)
        if not device or device.vendor == DeviceVendor.UNKNOWN:
            return []

        cred_id = device.credential_id
        if not cred_id:
            default_cred = self.storage.get_default_credential()
            if default_cred:
                cred_id = default_cred.id

        if not cred_id:
            return []

        cred = self.storage.get_credential(cred_id)
        if not cred:
            return []

        password = self.storage.get_decrypted_password(cred_id)

        try:
            driver = self.connector.create_connection(
                device.ip, cred.username, password, device.vendor
            )
            try:
                return driver.get_mac_table()
            finally:
                driver.disconnect()
        except Exception:
            return []
