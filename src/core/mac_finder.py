import re
import fnmatch
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable, Tuple
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

    def is_wildcard_pattern(self, pattern: str) -> bool:
        """Check if the pattern contains wildcards."""
        return '*' in pattern or '?' in pattern

    def normalize_pattern(self, pattern: str) -> Tuple[str, bool]:
        """
        Normalize MAC address pattern, preserving wildcards.

        Returns:
            Tuple of (normalized_pattern, is_wildcard)
        """
        pattern = pattern.lower().strip()

        # Check for wildcards
        has_wildcard = self.is_wildcard_pattern(pattern)

        if not has_wildcard:
            # Regular MAC address - normalize normally
            normalized = self.normalize_mac(pattern)
            return (normalized, False) if normalized else ('', False)

        # Handle wildcard patterns
        # Remove common separators but preserve * and ?
        cleaned = ''
        for char in pattern:
            if char in '0123456789abcdef*?':
                cleaned += char
            # Skip separators like :, -, .

        # Convert to colon-separated format with wildcards
        # Handle partial patterns like "00:11:*" or "001122*"
        if ':' in pattern or '-' in pattern or '.' in pattern:
            # Already has separators - normalize them to colons
            parts = re.split(r'[:\-.]', pattern)
            normalized = ':'.join(p.lower() for p in parts if p)
        else:
            # No separators - try to split into pairs
            # But preserve wildcards
            if '*' in cleaned and len(cleaned) < 12:
                # Partial pattern like "0011*" - keep as is with wildcards
                normalized = cleaned
            else:
                # Try to split into pairs
                parts = []
                i = 0
                while i < len(cleaned):
                    if cleaned[i] == '*':
                        parts.append('*')
                        i += 1
                    elif cleaned[i] == '?':
                        if i + 1 < len(cleaned) and cleaned[i+1] == '?':
                            parts.append('??')
                            i += 2
                        else:
                            parts.append('?' + (cleaned[i+1] if i+1 < len(cleaned) else '?'))
                            i += 2
                    else:
                        parts.append(cleaned[i:i+2])
                        i += 2
                normalized = ':'.join(parts)

        return (normalized, True)

    def mac_matches_pattern(self, mac: str, pattern: str) -> bool:
        """
        Check if a MAC address matches a wildcard pattern.

        Supports:
            - * matches any sequence of characters
            - ? matches any single character
            - Partial patterns like "00:11:22:*" or "00:11:*"
        """
        # Normalize the MAC for comparison
        mac_normalized = self.normalize_mac(mac)
        if not mac_normalized:
            return False

        # Remove colons for easier matching
        mac_flat = mac_normalized.replace(':', '')
        pattern_flat = pattern.replace(':', '').replace('-', '').replace('.', '').lower()

        # Use fnmatch for wildcard matching
        return fnmatch.fnmatch(mac_flat, pattern_flat)

    def search_mac(self, mac_address: str,
                   progress_callback: Optional[Callable[[int, int, str], None]] = None
                   ) -> List[MacSearchResult]:
        """
        Search for a MAC address across all devices.
        Supports wildcard patterns with * and ?.

        Args:
            mac_address: MAC address or pattern to search for (any format)
                        Wildcards: * matches any sequence, ? matches single char
                        Examples: "00:11:22:*", "00:11:??:33:*", "0011*"
            progress_callback: Optional callback(current, total, device_ip)

        Returns:
            List of MacSearchResult where the MAC was found
        """
        pattern, is_wildcard = self.normalize_pattern(mac_address)

        if not is_wildcard:
            normalized_mac = self.normalize_mac(mac_address)
            if not normalized_mac:
                return []
            pattern = normalized_mac

        devices = self.storage.list_devices()
        results = []
        total = len(devices)
        current = 0

        default_cred = self.storage.get_default_credential()

        def search_device(device: Device) -> List[MacSearchResult]:
            device_results = []
            cred_id = device.credential_id or (default_cred.id if default_cred else None)
            if not cred_id:
                return device_results

            cred = self.storage.get_credential(cred_id)
            if not cred:
                return device_results

            password = self.storage.get_decrypted_password(cred_id)

            try:
                if device.vendor == DeviceVendor.UNKNOWN:
                    return device_results

                driver = self.connector.create_connection(
                    device.ip, cred.username, password, device.vendor
                )

                try:
                    mac_table = driver.get_mac_table()

                    for entry in mac_table:
                        entry_mac = entry.get('mac_address', '')
                        match = False

                        if is_wildcard:
                            match = self.mac_matches_pattern(entry_mac, pattern)
                        else:
                            normalized_entry = self.normalize_mac(entry_mac)
                            match = normalized_entry == pattern

                        if match:
                            device_results.append(MacSearchResult(
                                mac_address=self.normalize_mac(entry_mac) or entry_mac,
                                device_ip=device.ip,
                                device_hostname=device.hostname or device.ip,
                                interface=entry.get('interface', 'unknown'),
                                vlan=entry.get('vlan', 0),
                                vendor=device.vendor
                            ))
                finally:
                    driver.disconnect()

            except Exception:
                pass

            return device_results

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(search_device, device): device
                for device in devices
            }

            for future in concurrent.futures.as_completed(future_to_device):
                current += 1
                device = future_to_device[future]

                try:
                    device_results = future.result()
                    if device_results:
                        results.extend(device_results)
                except Exception:
                    pass

                if progress_callback:
                    progress_callback(current, total, device.ip)

        return results

    def search_mac_from_cache(self, mac_address: str) -> List[MacSearchResult]:
        """
        Search for a MAC address using cached configuration data.
        Supports wildcard patterns with * and ?.
        Faster than live search but may not be up to date.
        """
        pattern, is_wildcard = self.normalize_pattern(mac_address)

        if not is_wildcard:
            normalized_mac = self.normalize_mac(mac_address)
            if not normalized_mac:
                return []
            pattern = normalized_mac

        results = []
        devices = self.storage.list_devices()

        for device in devices:
            latest_config = self.storage.get_latest_config(device.ip)
            if not latest_config or not latest_config.parsed_data:
                continue

            mac_table = latest_config.parsed_data.get('mac_table', [])
            for entry in mac_table:
                entry_mac = entry.get('mac_address', '')
                match = False

                if is_wildcard:
                    match = self.mac_matches_pattern(entry_mac, pattern)
                else:
                    normalized_entry = self.normalize_mac(entry_mac)
                    match = normalized_entry == pattern

                if match:
                    results.append(MacSearchResult(
                        mac_address=self.normalize_mac(entry_mac) or entry_mac,
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
