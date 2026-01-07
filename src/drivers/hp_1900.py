import re
from typing import Dict, Any, List, Optional
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from .base import BaseDriver


class HP1900Driver(BaseDriver):
    """Driver for HP 1900 series switches (Comware platform)."""

    DEVICE_TYPE = "hp_comware"

    def connect(self) -> bool:
        """Establish SSH connection to the HP switch."""
        try:
            self.connection = ConnectHandler(
                device_type=self.DEVICE_TYPE,
                host=self.ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                conn_timeout=self.timeout,
            )
            return True
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            self.connection = None
            raise ConnectionError(f"Failed to connect to {self.ip}: {str(e)}")
        except Exception as e:
            self.connection = None
            raise ConnectionError(f"Connection error: {str(e)}")

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None

    def get_config(self) -> str:
        """Retrieve the running configuration."""
        return self.send_command("display current-configuration")

    def get_mac_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse the MAC address table."""
        output = self.send_command("display mac-address")
        return self._parse_mac_table(output)

    def _parse_mac_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse HP Comware MAC address table output."""
        mac_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(
                r'([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+'
                r'(\d+)\s+'
                r'(\S+)\s+'
                r'(\S+)',
                line.strip()
            )
            if match:
                mac_entries.append({
                    'mac_address': self._normalize_mac(match.group(1)),
                    'vlan': int(match.group(2)),
                    'interface': match.group(3),
                    'type': match.group(4)
                })

        return mac_entries

    def _normalize_mac(self, mac: str) -> str:
        """Convert HP MAC format (xxxx-xxxx-xxxx) to standard format (xx:xx:xx:xx:xx:xx)."""
        mac = mac.replace('-', '').lower()
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve and parse interface information."""
        output = self.send_command("display interface brief")
        return self._parse_interfaces(output)

    def _parse_interfaces(self, output: str) -> List[Dict[str, Any]]:
        """Parse HP Comware interface brief output."""
        interfaces = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(
                r'(\S+)\s+(UP|DOWN|ADM)\s+'
                r'(\S+)\s+'
                r'(\S*)',
                line.strip(),
                re.IGNORECASE
            )
            if match:
                status = match.group(2).upper()
                interfaces.append({
                    'interface': match.group(1),
                    'status': 'up' if status == 'UP' else 'down',
                    'protocol': match.group(3),
                    'description': match.group(4) if match.group(4) else None
                })

        return interfaces

    def get_vlans(self) -> List[Dict[str, Any]]:
        """Retrieve and parse VLAN configuration."""
        output = self.send_command("display vlan")
        return self._parse_vlans(output)

    def _parse_vlans(self, output: str) -> List[Dict[str, Any]]:
        """Parse HP Comware VLAN output."""
        vlans = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(r'^\s*(\d+)\s+(\S+)\s+', line)
            if match:
                vlans.append({
                    'vlan_id': int(match.group(1)),
                    'name': match.group(2),
                    'ports': []
                })

        return vlans

    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse ARP table."""
        output = self.send_command("display arp")
        return self._parse_arp_table(output)

    def _parse_arp_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse HP Comware ARP table output."""
        arp_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+'
                r'(\d+)\s+'
                r'(\S+)\s+'
                r'(\S+)',
                line.strip()
            )
            if match:
                arp_entries.append({
                    'ip_address': match.group(1),
                    'mac_address': self._normalize_mac(match.group(2)),
                    'vlan': int(match.group(3)),
                    'interface': match.group(4),
                    'type': match.group(5)
                })

        return arp_entries

    def get_device_info(self) -> Dict[str, Any]:
        """Retrieve device information."""
        config = self.get_config()
        version_output = self.send_command("display version")

        info = {
            'hostname': None,
            'model': None,
            'version': None,
            'vendor': 'hp'
        }

        hostname_match = re.search(r'sysname\s+(\S+)', config)
        if hostname_match:
            info['hostname'] = hostname_match.group(1)

        model_match = re.search(r'(1900\S*|JG\d+\S*)', version_output, re.IGNORECASE)
        if model_match:
            info['model'] = model_match.group(1)

        version_match = re.search(r'Version\s+([\d.]+)', version_output)
        if version_match:
            info['version'] = version_match.group(1)

        return info
