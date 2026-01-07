import re
from typing import Dict, Any, List, Optional
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from .base import BaseDriver


class HuaweiS5720Driver(BaseDriver):
    """Driver for Huawei S5720 series switches."""

    DEVICE_TYPE = "huawei"

    def connect(self) -> bool:
        """Establish SSH connection to the Huawei switch."""
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
        """Parse Huawei MAC address table output."""
        mac_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(
                r'([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+'
                r'(\d+)\s*/-\s+'
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
            else:
                match2 = re.match(
                    r'([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+'
                    r'(\d+)\s+'
                    r'(\S+)\s+'
                    r'(\S+)',
                    line.strip()
                )
                if match2:
                    mac_entries.append({
                        'mac_address': self._normalize_mac(match2.group(1)),
                        'vlan': int(match2.group(2)),
                        'interface': match2.group(3),
                        'type': match2.group(4)
                    })

        return mac_entries

    def _normalize_mac(self, mac: str) -> str:
        """Convert Huawei MAC format (xxxx-xxxx-xxxx) to standard format (xx:xx:xx:xx:xx:xx)."""
        mac = mac.replace('-', '').lower()
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve and parse interface information."""
        output = self.send_command("display interface brief")
        return self._parse_interfaces(output)

    def _parse_interfaces(self, output: str) -> List[Dict[str, Any]]:
        """Parse Huawei interface brief output."""
        interfaces = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(
                r'(\S+)\s+(\*?(?:up|down|administratively down))\s+'
                r'(\S+)\s+'
                r'(\S+)',
                line.strip(),
                re.IGNORECASE
            )
            if match:
                status = match.group(2).lower().replace('*', '')
                interfaces.append({
                    'interface': match.group(1),
                    'status': 'up' if 'up' in status else 'down',
                    'protocol': match.group(3),
                    'description': match.group(4) if match.group(4) != '--' else None
                })

        return interfaces

    def get_vlans(self) -> List[Dict[str, Any]]:
        """Retrieve and parse VLAN configuration."""
        output = self.send_command("display vlan")
        return self._parse_vlans(output)

    def _parse_vlans(self, output: str) -> List[Dict[str, Any]]:
        """Parse Huawei VLAN output."""
        vlans = []
        lines = output.strip().split('\n')
        current_vlan = None

        for line in lines:
            vlan_match = re.match(r'^(\d+)\s+(\S+)?\s*$', line.strip())
            if vlan_match:
                if current_vlan:
                    vlans.append(current_vlan)
                current_vlan = {
                    'vlan_id': int(vlan_match.group(1)),
                    'name': vlan_match.group(2) if vlan_match.group(2) else f'VLAN{vlan_match.group(1)}',
                    'ports': []
                }
            elif current_vlan and 'port' in line.lower():
                ports = re.findall(r'((?:Eth|GE|XGE)\S+)', line, re.IGNORECASE)
                current_vlan['ports'].extend(ports)

        if current_vlan:
            vlans.append(current_vlan)

        return vlans

    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse ARP table."""
        output = self.send_command("display arp")
        return self._parse_arp_table(output)

    def _parse_arp_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse Huawei ARP table output."""
        arp_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.match(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+'
                r'(\d+)\s*'
                r'(\S+)?\s*'
                r'(\S+)?',
                line.strip()
            )
            if match:
                arp_entries.append({
                    'ip_address': match.group(1),
                    'mac_address': self._normalize_mac(match.group(2)),
                    'vlan': int(match.group(3)) if match.group(3) else None,
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
            'vendor': 'huawei'
        }

        hostname_match = re.search(r'sysname\s+(\S+)', config)
        if hostname_match:
            info['hostname'] = hostname_match.group(1)

        model_match = re.search(r'(S5720\S*)', version_output)
        if model_match:
            info['model'] = model_match.group(1)

        version_match = re.search(r'VRP.*Version\s+([\d.]+)', version_output)
        if version_match:
            info['version'] = version_match.group(1)

        return info
