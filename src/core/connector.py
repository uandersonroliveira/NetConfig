from typing import Optional, Type, List, Dict, Any
from ..drivers.base import BaseDriver
from ..drivers.huawei_s5720 import HuaweiS5720Driver
from ..drivers.hp_1900 import HP1900Driver
from ..drivers.aruba import ArubaDriver
from ..drivers.cisco_ios import CiscoIOSDriver
from ..models.device import DeviceVendor


class Connector:
    """Manages SSH connections to network devices using appropriate drivers."""

    DRIVERS = {
        DeviceVendor.HUAWEI: HuaweiS5720Driver,
        DeviceVendor.HP: HP1900Driver,
        DeviceVendor.ARUBA: ArubaDriver,
        DeviceVendor.CISCO: CiscoIOSDriver,
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def get_driver_class(self, vendor: DeviceVendor) -> Type[BaseDriver]:
        """Get the appropriate driver class for a vendor."""
        driver_class = self.DRIVERS.get(vendor)
        if not driver_class:
            raise ValueError(f"No driver available for vendor: {vendor}")
        return driver_class

    def create_connection(self, ip: str, username: str, password: str,
                          vendor: DeviceVendor) -> BaseDriver:
        """Create a connection to a device."""
        driver_class = self.get_driver_class(vendor)
        driver = driver_class(ip, username, password, self.timeout)
        driver.connect()
        return driver

    def detect_vendor(self, ip: str, username: str, password: str) -> Optional[DeviceVendor]:
        """
        Attempt to detect the vendor by trying different drivers.
        Returns the vendor if successful, None if unable to connect.
        """
        for vendor, driver_class in self.DRIVERS.items():
            try:
                driver = driver_class(ip, username, password, timeout=10)
                if driver.connect():
                    info = driver.get_device_info()
                    driver.disconnect()
                    return vendor
            except Exception:
                continue

        return None

    def test_connection(self, ip: str, username: str, password: str,
                        vendor: DeviceVendor) -> tuple[bool, Optional[str]]:
        """
        Test connection to a device.

        Returns:
            Tuple of (success, error_message)
        """
        try:
            driver = self.create_connection(ip, username, password, vendor)
            driver.disconnect()
            return True, None
        except ConnectionError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def discover_neighbors(self, ip: str, username: str, password: str,
                          vendor: DeviceVendor) -> Dict[str, Any]:
        """
        Discover neighbors via LLDP/CDP on a device.

        Returns:
            Dict with 'lldp_neighbors' and 'cdp_neighbors' lists
        """
        result = {
            'device_ip': ip,
            'lldp_neighbors': [],
            'cdp_neighbors': [],
            'error': None
        }

        try:
            driver = self.create_connection(ip, username, password, vendor)
            try:
                result['lldp_neighbors'] = driver.get_lldp_neighbors()
            except Exception:
                pass
            try:
                result['cdp_neighbors'] = driver.get_cdp_neighbors()
            except Exception:
                pass
            driver.disconnect()
        except Exception as e:
            result['error'] = str(e)

        return result

    def detect_vendor_from_neighbors(self, neighbor_name: str) -> Optional[DeviceVendor]:
        """
        Try to detect vendor from LLDP/CDP neighbor system name.
        """
        name_lower = neighbor_name.lower()

        if any(x in name_lower for x in ['huawei', 's5720', 's5700', 's6720', 'ce']):
            return DeviceVendor.HUAWEI
        elif any(x in name_lower for x in ['hp', '1900', 'comware', 'procurve']):
            return DeviceVendor.HP
        elif any(x in name_lower for x in ['aruba', 'iap', 'ap-']):
            return DeviceVendor.ARUBA
        elif any(x in name_lower for x in ['cisco', 'ios', 'isr', 'asr', 'csr', 'nexus', 'catalyst', 'c29', 'c35', 'c36', 'c38', 'c93']):
            return DeviceVendor.CISCO

        return DeviceVendor.UNKNOWN
