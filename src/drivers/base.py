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

    @abstractmethod
    def get_logs(self) -> str:
        """Retrieve device logs (syslog, event log, etc.)."""
        pass

    @abstractmethod
    def get_lldp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve LLDP neighbor information."""
        pass

    @abstractmethod
    def get_cdp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve CDP neighbor information (if supported)."""
        pass

    @abstractmethod
    def get_poe_status(self) -> Dict[str, Any]:
        """Get PoE status including budget, used, and per-port details.

        Returns:
            {
                'supported': bool,          # Device supports PoE
                'total_budget_watts': float, # Total PoE budget
                'used_watts': float,         # Currently used
                'utilization_percent': float, # Percentage used
                'ports': [                   # Per-port details
                    {
                        'interface': str,
                        'status': str,       # 'on', 'off', 'fault'
                        'power_watts': float,
                        'max_watts': float,
                        'device': str        # Connected device name
                    }
                ]
            }
        """
        pass

    @abstractmethod
    def get_port_utilization(self) -> Dict[str, Any]:
        """Get port utilization statistics.

        Returns:
            {
                'total_ports': int,
                'active_ports': int,      # Ports with link up
                'utilization_percent': float,
                'stack_members': [        # For stacked switches
                    {
                        'member_id': int,
                        'total_ports': int,
                        'active_ports': int
                    }
                ]
            }
        """
        pass

    def send_command(self, command: str) -> str:
        """Send a command and return the output."""
        if self.connection:
            return self.connection.send_command(command)
        raise ConnectionError("Not connected to device")

    def is_connected(self) -> bool:
        """Check if connection is active."""
        return self.connection is not None and self.connection.is_alive()
