import re
from typing import Dict, Any, List
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from .base import BaseDriver


class ArubaDriver(BaseDriver):
    """Driver for Aruba access points and controllers."""

    DEVICE_TYPE = "aruba_os"

    def connect(self) -> bool:
        """Establish SSH connection to the Aruba device."""
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
        return self.send_command("show running-config")

    def get_mac_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse the MAC address table from connected clients."""
        mac_entries = []

        # Try different commands for different Aruba platforms
        # show user-table for controllers
        try:
            output = self.send_command("show user-table")
            entries = self._parse_user_table(output)
            if entries:
                mac_entries.extend(entries)
        except Exception:
            pass

        # show clients for Instant APs
        if not mac_entries:
            try:
                output = self.send_command("show clients")
                entries = self._parse_clients(output)
                if entries:
                    mac_entries.extend(entries)
            except Exception:
                pass

        # show station-table for some platforms
        if not mac_entries:
            try:
                output = self.send_command("show station-table")
                entries = self._parse_station_table(output)
                if entries:
                    mac_entries.extend(entries)
            except Exception:
                pass

        return mac_entries

    def _parse_user_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse Aruba user-table output."""
        mac_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            # Match MAC address patterns in the line
            # Format: IP  MAC  Name  Role  Age(d:h:m)  Auth  ...
            match = re.search(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})',
                line
            )
            if match:
                mac_entries.append({
                    'mac_address': match.group(2).lower(),
                    'ip_address': match.group(1),
                    'vlan': 0,
                    'interface': 'wireless',
                    'type': 'dynamic'
                })

        return mac_entries

    def _parse_clients(self, output: str) -> List[Dict[str, Any]]:
        """Parse Aruba Instant AP clients output."""
        mac_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            # Look for MAC addresses in various formats
            match = re.search(
                r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})',
                line
            )
            if match:
                mac = match.group(1).lower()
                # Try to extract IP if present
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                ip_addr = ip_match.group(1) if ip_match else ''

                # Try to extract ESSID/SSID
                essid = ''
                essid_match = re.search(r'ESSID[:\s]+(\S+)', line, re.IGNORECASE)
                if essid_match:
                    essid = essid_match.group(1)

                mac_entries.append({
                    'mac_address': mac,
                    'ip_address': ip_addr,
                    'vlan': 0,
                    'interface': essid or 'wireless',
                    'type': 'dynamic'
                })

        return mac_entries

    def _parse_station_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse Aruba station-table output."""
        mac_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            match = re.search(
                r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})',
                line
            )
            if match:
                mac_entries.append({
                    'mac_address': match.group(1).lower(),
                    'vlan': 0,
                    'interface': 'wireless',
                    'type': 'dynamic'
                })

        return mac_entries

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve and parse interface information."""
        interfaces = []
        try:
            output = self.send_command("show interface")
            lines = output.strip().split('\n')

            for line in lines:
                match = re.match(r'^(\S+)\s+.*?(up|down)', line, re.IGNORECASE)
                if match:
                    interfaces.append({
                        'interface': match.group(1),
                        'status': match.group(2).lower(),
                        'protocol': 'up' if 'up' in match.group(2).lower() else 'down',
                        'description': None
                    })
        except Exception:
            pass

        return interfaces

    def get_vlans(self) -> List[Dict[str, Any]]:
        """Retrieve VLAN configuration."""
        vlans = []
        try:
            output = self.send_command("show vlan")
            lines = output.strip().split('\n')

            for line in lines:
                match = re.match(r'^\s*(\d+)\s+(\S+)?', line)
                if match and match.group(1).isdigit():
                    vlans.append({
                        'vlan_id': int(match.group(1)),
                        'name': match.group(2) if match.group(2) else f'VLAN{match.group(1)}',
                        'ports': []
                    })
        except Exception:
            pass

        return vlans

    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse ARP table."""
        arp_entries = []
        try:
            output = self.send_command("show arp")
            lines = output.strip().split('\n')

            for line in lines:
                match = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+'
                    r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})',
                    line
                )
                if match:
                    arp_entries.append({
                        'ip_address': match.group(1),
                        'mac_address': match.group(2).lower(),
                        'vlan': None,
                        'interface': None,
                        'type': 'dynamic'
                    })
        except Exception:
            pass

        return arp_entries

    def get_device_info(self) -> Dict[str, Any]:
        """Retrieve device information."""
        info = {
            'hostname': None,
            'model': None,
            'version': None,
            'vendor': 'aruba'
        }

        try:
            version_output = self.send_command("show version")

            # Extract hostname
            hostname_match = re.search(r'hostname[:\s]+(\S+)', version_output, re.IGNORECASE)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)

            # Extract model
            model_match = re.search(r'(AP-\S+|IAP-\S+|Aruba\s+\S+)', version_output, re.IGNORECASE)
            if model_match:
                info['model'] = model_match.group(1)

            # Extract version
            version_match = re.search(r'Version[:\s]+([\d.]+)', version_output)
            if version_match:
                info['version'] = version_match.group(1)
        except Exception:
            pass

        return info

    def get_logs(self) -> str:
        """Retrieve device logs."""
        logs = []

        # Get system log
        try:
            syslog = self.send_command("show log system")
            logs.append("=== SYSTEM LOG ===\n" + syslog)
        except Exception:
            pass

        # Get security log
        try:
            seclog = self.send_command("show log security")
            logs.append("\n=== SECURITY LOG ===\n" + seclog)
        except Exception:
            pass

        # Get AP debug log
        try:
            aplog = self.send_command("show ap debug log")
            logs.append("\n=== AP DEBUG LOG ===\n" + aplog)
        except Exception:
            pass

        # Get crash log if available
        try:
            crashlog = self.send_command("show crash-info")
            logs.append("\n=== CRASH INFO ===\n" + crashlog)
        except Exception:
            pass

        return "\n".join(logs) if logs else "No logs available"

    def get_lldp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve LLDP neighbor information."""
        neighbors = []
        try:
            output = self.send_command("show lldp neighbors")
            lines = output.strip().split('\n')

            for line in lines:
                # Skip header lines
                if not line.strip() or 'Local' in line or '---' in line:
                    continue

                # Try to parse tabular format: LocalPort  RemoteChassisId  RemotePort  RemoteSysName
                parts = line.split()
                if len(parts) >= 3:
                    neighbors.append({
                        'local_interface': parts[0],
                        'neighbor_device': parts[-1] if len(parts) >= 4 else parts[1],
                        'neighbor_interface': parts[2] if len(parts) >= 3 else parts[1],
                        'capabilities': None
                    })
        except Exception:
            pass

        # Try detailed version if brief failed
        if not neighbors:
            try:
                output = self.send_command("show lldp neighbors detail")
                current_neighbor = {}

                for line in output.strip().split('\n'):
                    line = line.strip()
                    if 'Local Port' in line:
                        if current_neighbor and 'neighbor_device' in current_neighbor:
                            neighbors.append(current_neighbor)
                        current_neighbor = {'local_interface': line.split(':')[-1].strip()}
                    elif 'System Name' in line or 'System name' in line:
                        current_neighbor['neighbor_device'] = line.split(':')[-1].strip()
                    elif 'Port ID' in line:
                        current_neighbor['neighbor_interface'] = line.split(':')[-1].strip()
                    elif 'Capabilities' in line:
                        current_neighbor['capabilities'] = line.split(':')[-1].strip()

                if current_neighbor and 'neighbor_device' in current_neighbor:
                    neighbors.append(current_neighbor)
            except Exception:
                pass

        return neighbors

    def get_cdp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve CDP neighbor information."""
        neighbors = []
        try:
            output = self.send_command("show cdp neighbors")
            lines = output.strip().split('\n')

            for line in lines:
                # Skip header lines
                if not line.strip() or 'Device' in line or '---' in line:
                    continue

                parts = line.split()
                if len(parts) >= 4:
                    neighbors.append({
                        'local_interface': parts[1] if len(parts) > 1 else '',
                        'neighbor_device': parts[0],
                        'neighbor_interface': parts[-1] if len(parts) >= 4 else '',
                        'capabilities': parts[2] if len(parts) >= 3 else None
                    })
        except Exception:
            pass

        return neighbors

    def get_poe_status(self) -> Dict[str, Any]:
        """Get PoE status. Aruba APs typically consume PoE, not provide it."""
        result = {
            'supported': False,
            'total_budget_watts': 0,
            'used_watts': 0,
            'utilization_percent': 0,
            'ports': [],
            'note': 'Access Point (consumes PoE)'
        }

        # Try to get power consumption info for controllers with PoE ports
        try:
            power_output = self.send_command("show power")

            # Some Aruba controllers may have PoE output
            budget_match = re.search(r'(?:Total|Maximum|Available)\s+Power[:\s]+(\d+\.?\d*)\s*W', power_output, re.IGNORECASE)
            used_match = re.search(r'(?:Used|Consumed)\s+Power[:\s]+(\d+\.?\d*)\s*W', power_output, re.IGNORECASE)

            if budget_match:
                result['supported'] = True
                result['total_budget_watts'] = float(budget_match.group(1))
            if used_match:
                result['used_watts'] = float(used_match.group(1))

            if result['total_budget_watts'] > 0:
                result['utilization_percent'] = (result['used_watts'] / result['total_budget_watts']) * 100
        except Exception:
            pass

        return result

    def get_port_utilization(self) -> Dict[str, Any]:
        """Get port utilization statistics."""
        result = {
            'total_ports': 0,
            'active_ports': 0,
            'utilization_percent': 0,
            'stack_members': [],
            'connected_clients': 0
        }

        try:
            # Get interface status
            output = self.send_command("show interface status")
            lines = output.strip().split('\n')

            for line in lines:
                # Match interface status lines
                match = re.match(
                    r'(\S+)\s+.*?(up|down)',
                    line.strip(), re.IGNORECASE
                )
                if match and not line.lower().startswith('port'):
                    result['total_ports'] += 1
                    if match.group(2).lower() == 'up':
                        result['active_ports'] += 1

            if result['total_ports'] > 0:
                result['utilization_percent'] = (result['active_ports'] / result['total_ports']) * 100
        except Exception:
            pass

        # Try to get connected clients count
        try:
            clients_output = self.send_command("show user-table count")
            count_match = re.search(r'(\d+)\s+(?:user|client)', clients_output, re.IGNORECASE)
            if count_match:
                result['connected_clients'] = int(count_match.group(1))
        except Exception:
            pass

        return result
