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

    def get_logs(self) -> str:
        """Retrieve device logs."""
        logs = []

        # Get logbuffer (system logs)
        try:
            logbuffer = self.send_command("display logbuffer")
            logs.append("=== LOG BUFFER ===\n" + logbuffer)
        except Exception:
            pass

        # Get diagnostic information
        try:
            diagnostic = self.send_command("display diagnostic-information")
            logs.append("\n=== DIAGNOSTIC INFO ===\n" + diagnostic)
        except Exception:
            pass

        # Get system health
        try:
            health = self.send_command("display device")
            logs.append("\n=== DEVICE STATUS ===\n" + health)
        except Exception:
            pass

        return "\n".join(logs) if logs else "No logs available"

    def get_lldp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve LLDP neighbor information."""
        neighbors = []
        try:
            output = self.send_command("display lldp neighbor-information")
            current_neighbor = {}

            for line in output.strip().split('\n'):
                line = line.strip()
                if 'LLDP neighbor-information' in line or (line.startswith('Port') and ':' not in line):
                    if current_neighbor and 'neighbor_device' in current_neighbor:
                        neighbors.append(current_neighbor)
                    current_neighbor = {}
                    # Extract local interface from "LLDP neighbor-information of port X"
                    port_match = re.search(r'port\s+(\S+)', line, re.IGNORECASE)
                    if port_match:
                        current_neighbor['local_interface'] = port_match.group(1)
                elif 'System name' in line:
                    current_neighbor['neighbor_device'] = line.split(':')[-1].strip()
                elif 'Port ID' in line:
                    current_neighbor['neighbor_interface'] = line.split(':')[-1].strip()
                elif 'System capabilities' in line:
                    current_neighbor['capabilities'] = line.split(':')[-1].strip()

            if current_neighbor and 'neighbor_device' in current_neighbor:
                neighbors.append(current_neighbor)
        except Exception:
            pass

        # Try brief version if detailed failed
        if not neighbors:
            try:
                output = self.send_command("display lldp neighbor-information brief")
                lines = output.strip().split('\n')

                for line in lines:
                    match = re.match(
                        r'(\S+)\s+(\S+)\s+(\S+)',
                        line.strip()
                    )
                    if match and not line.lower().startswith('local'):
                        neighbors.append({
                            'local_interface': match.group(1),
                            'neighbor_device': match.group(2),
                            'neighbor_interface': match.group(3),
                            'capabilities': None
                        })
            except Exception:
                pass

        return neighbors

    def get_cdp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve CDP neighbor information (HP Comware does not support CDP)."""
        return []

    def get_poe_status(self) -> Dict[str, Any]:
        """Get PoE status including budget, used, and per-port details."""
        result = {
            'supported': False,
            'total_budget_watts': 0,
            'used_watts': 0,
            'utilization_percent': 0,
            'ports': []
        }

        try:
            # Get PoE power summary
            power_output = self.send_command("display poe power")

            # Parse total budget and used power
            budget_match = re.search(r'Maximum\s+Power[:\s]+(\d+\.?\d*)\s*W', power_output, re.IGNORECASE)
            used_match = re.search(r'(?:Consuming|Used)\s+Power[:\s]+(\d+\.?\d*)\s*W', power_output, re.IGNORECASE)

            if budget_match:
                result['supported'] = True
                result['total_budget_watts'] = float(budget_match.group(1))
            if used_match:
                result['used_watts'] = float(used_match.group(1))

            if result['total_budget_watts'] > 0:
                result['utilization_percent'] = (result['used_watts'] / result['total_budget_watts']) * 100

            # Try to get per-port PoE status
            try:
                port_output = self.send_command("display poe interface")
                port_lines = port_output.strip().split('\n')

                for line in port_lines:
                    # Match interface PoE lines
                    match = re.match(
                        r'(GE|GigabitEthernet)\S*\s+(enabled|disabled|on|off)\s+.*?(\d+\.?\d*)?\s*W?',
                        line.strip(), re.IGNORECASE
                    )
                    if match:
                        port_info = {
                            'interface': match.group(1),
                            'status': 'on' if match.group(2).lower() in ['enabled', 'on'] else 'off',
                            'power_watts': float(match.group(3)) if match.group(3) else 0,
                            'max_watts': 15.4,
                            'device': ''
                        }
                        result['ports'].append(port_info)
            except Exception:
                pass

        except Exception:
            pass

        return result

    def get_port_utilization(self) -> Dict[str, Any]:
        """Get port utilization statistics."""
        result = {
            'total_ports': 0,
            'active_ports': 0,
            'utilization_percent': 0,
            'stack_members': []
        }

        try:
            output = self.send_command("display interface brief")
            lines = output.strip().split('\n')

            for line in lines:
                # Match interface status lines
                match = re.match(
                    r'(GigabitEthernet|GE|FastEthernet|FE|Ethernet)\S*\s+(UP|DOWN|ADM)',
                    line.strip(), re.IGNORECASE
                )
                if match:
                    result['total_ports'] += 1
                    if match.group(2).upper() == 'UP':
                        result['active_ports'] += 1

            if result['total_ports'] > 0:
                result['utilization_percent'] = (result['active_ports'] / result['total_ports']) * 100

            # Try to get device/stack information
            try:
                device_output = self.send_command("display device")
                for line in device_output.strip().split('\n'):
                    member_match = re.match(r'(?:Slot|Unit)\s*(\d+)', line, re.IGNORECASE)
                    if member_match:
                        result['stack_members'].append({
                            'member_id': int(member_match.group(1)),
                            'total_ports': 0,
                            'active_ports': 0
                        })
            except Exception:
                pass

        except Exception:
            pass

        return result
