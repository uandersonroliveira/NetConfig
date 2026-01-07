import time
import concurrent.futures
from typing import List, Optional, Callable, Dict, Any
from datetime import datetime
from ..models.device import Device, DeviceStatus, DeviceVendor
from ..models.config import ConfigSnapshot
from ..storage.json_storage import JsonStorage
from .connector import Connector


class CollectionResult:
    """Result of a configuration collection attempt."""

    def __init__(self, device_ip: str, success: bool,
                 config: Optional[ConfigSnapshot] = None,
                 error: Optional[str] = None,
                 duration: float = 0):
        self.device_ip = device_ip
        self.success = success
        self.config = config
        self.error = error
        self.duration = duration


class Collector:
    """Collects configurations from network devices."""

    def __init__(self, storage: JsonStorage, connector: Connector = None,
                 max_workers: int = 10):
        self.storage = storage
        self.connector = connector or Connector()
        self.max_workers = max_workers

    def collect_device(self, device: Device, username: str, password: str
                      ) -> CollectionResult:
        """
        Collect configuration from a single device.

        Args:
            device: Device to collect from
            username: SSH username
            password: SSH password

        Returns:
            CollectionResult with config or error
        """
        start_time = time.time()

        try:
            if device.vendor == DeviceVendor.UNKNOWN:
                vendor = self.connector.detect_vendor(device.ip, username, password)
                if vendor:
                    device.vendor = vendor
                    self.storage.save_device(device)
                else:
                    return CollectionResult(
                        device.ip, False,
                        error="Could not detect device vendor",
                        duration=time.time() - start_time
                    )
            else:
                vendor = device.vendor

            driver = self.connector.create_connection(
                device.ip, username, password, vendor
            )

            try:
                config = driver.get_config()
                device_info = driver.get_device_info()

                parsed_data = {
                    'hostname': device_info.get('hostname'),
                    'model': device_info.get('model'),
                    'version': device_info.get('version'),
                    'vlans': driver.get_vlans(),
                    'interfaces': driver.get_interfaces(),
                    'mac_table': driver.get_mac_table(),
                    'arp_table': driver.get_arp_table(),
                }

                duration = time.time() - start_time

                snapshot = self.storage.save_config(
                    device.ip, config, parsed_data, duration
                )

                device.hostname = device_info.get('hostname') or device.hostname
                device.model = device_info.get('model') or device.model
                device.status = DeviceStatus.ONLINE
                device.last_config_collection = datetime.now()
                self.storage.save_device(device)

                return CollectionResult(device.ip, True, snapshot, duration=duration)

            finally:
                driver.disconnect()

        except ConnectionError as e:
            device.status = DeviceStatus.OFFLINE
            self.storage.save_device(device)
            return CollectionResult(
                device.ip, False,
                error=str(e),
                duration=time.time() - start_time
            )
        except Exception as e:
            return CollectionResult(
                device.ip, False,
                error=f"Collection error: {str(e)}",
                duration=time.time() - start_time
            )

    def collect_devices(self, devices: List[Device],
                        username: str, password: str,
                        progress_callback: Optional[Callable[[int, int, str, bool], None]] = None
                        ) -> List[CollectionResult]:
        """
        Collect configurations from multiple devices in parallel.

        Args:
            devices: List of devices to collect from
            username: SSH username
            password: SSH password
            progress_callback: Optional callback(current, total, ip, success)

        Returns:
            List of CollectionResults
        """
        results = []
        total = len(devices)
        current = 0

        def collect_one(device: Device) -> CollectionResult:
            return self.collect_device(device, username, password)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(collect_one, device): device
                for device in devices
            }

            for future in concurrent.futures.as_completed(future_to_device):
                current += 1
                device = future_to_device[future]

                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(CollectionResult(
                        device.ip, False, error=str(e)
                    ))

                if progress_callback:
                    progress_callback(
                        current, total, device.ip,
                        results[-1].success
                    )

        return results

    def collect_all(self, progress_callback: Optional[Callable[[int, int, str, bool], None]] = None
                   ) -> List[CollectionResult]:
        """
        Collect configurations from all registered devices using their assigned
        or default credentials.
        """
        devices = self.storage.list_devices()
        results = []
        total = len(devices)
        current = 0

        default_cred = self.storage.get_default_credential()

        def collect_one(device: Device) -> CollectionResult:
            cred_id = device.credential_id or (default_cred.id if default_cred else None)
            if not cred_id:
                return CollectionResult(
                    device.ip, False,
                    error="No credentials available"
                )

            cred = self.storage.get_credential(cred_id)
            if not cred:
                return CollectionResult(
                    device.ip, False,
                    error="Credential not found"
                )

            password = self.storage.get_decrypted_password(cred_id)
            return self.collect_device(device, cred.username, password)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(collect_one, device): device
                for device in devices
            }

            for future in concurrent.futures.as_completed(future_to_device):
                current += 1
                device = future_to_device[future]

                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(CollectionResult(
                        device.ip, False, error=str(e)
                    ))

                if progress_callback:
                    progress_callback(
                        current, total, device.ip,
                        results[-1].success
                    )

        return results
