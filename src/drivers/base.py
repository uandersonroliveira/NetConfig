from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List


class BaseDriver(ABC):
    """Abstract base class for network device drivers."""

    def __init__(self, ip: str, username: str, password: str, timeout: int = 30):
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.connection = None

    @abstractmethod
    def connect(self) -> bool:
        """Establish SSH connection to the device."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close the SSH connection."""
        pass

    @abstractmethod
    def get_config(self) -> str:
        """Retrieve the running configuration."""
        pass

    @abstractmethod
    def get_mac_table(self) -> List[Dict[str, Any]]:
        """Retrieve the MAC address table."""
        pass

    @abstractmethod
    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve interface status and configuration."""
        pass

    @abstractmethod
    def get_vlans(self) -> List[Dict[str, Any]]:
        """Retrieve VLAN configuration."""
        pass

    @abstractmethod
    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Retrieve ARP table."""
        pass

    @abstractmethod
    def get_device_info(self) -> Dict[str, Any]:
        """Retrieve device information (hostname, model, version)."""
        pass

    def send_command(self, command: str) -> str:
        """Send a command and return the output."""
        if self.connection:
            return self.connection.send_command(command)
        raise ConnectionError("Not connected to device")

    def is_connected(self) -> bool:
        """Check if connection is active."""
        return self.connection is not None and self.connection.is_alive()
