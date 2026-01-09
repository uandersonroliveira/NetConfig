import re
from typing import Dict, Any, List
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from .base import BaseDriver


class CiscoIOSDriver(BaseDriver):
    """Driver for Cisco IOS devices (routers and L3 switches)."""

    DEVICE_TYPE = "cisco_ios"

    def connect(self) -> bool:
        """Establish SSH connection to the Cisco device."""
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
        """Retrieve and parse the MAC address table."""
        mac_entries = []
        try:
            output = self.send_command("show mac address-table")
            mac_entries = self._parse_mac_table(output)
        except Exception:
            pass

        # Try alternative command for older IOS
        if not mac_entries:
            try:
                output = self.send_command("show mac-address-table")
                mac_entries = self._parse_mac_table(output)
            except Exception:
                pass

        return mac_entries

    def _parse_mac_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse Cisco MAC address table output."""
        mac_entries = []
        lines = output.strip().split('\n')

        for line in lines:
            # Format: vlan  mac_address  type  ports
            match = re.match(
                r'\s*(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'
                r'(\S+)\s+(\S+)',
                line.strip()
            )
            if match:
                mac_entries.append({
                    'mac_address': self._normalize_mac(match.group(2)),
                    'vlan': int(match.group(1)),
                    'interface': match.group(4),
                    'type': match.group(3)
                })

        return mac_entries

    def _normalize_mac(self, mac: str) -> str:
        """Convert Cisco MAC format (xxxx.xxxx.xxxx) to standard format (xx:xx:xx:xx:xx:xx)."""
        mac = mac.replace('.', '').lower()
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve and parse interface information."""
        interfaces = []
        try:
            output = self.send_command("show ip interface brief")
            lines = output.strip().split('\n')

            for line in lines:
                # Format: Interface  IP-Address  OK?  Method  Status  Protocol
                match = re.match(
                    r'(\S+)\s+(\d+\.\d+\.\d+\.\d+|unassigned)\s+\S+\s+\S+\s+'
                    r'(up|down|administratively down)\s+(up|down)',
                    line.strip(),
                    re.IGNORECASE
                )
                if match:
                    interfaces.append({
                        'interface': match.group(1),
                        'ip_address': match.group(2) if match.group(2) != 'unassigned' else None,
                        'status': 'up' if 'up' in match.group(3).lower() else 'down',
                        'protocol': match.group(4).lower(),
                        'description': None
                    })
        except Exception:
            pass

        return interfaces

    def get_vlans(self) -> List[Dict[str, Any]]:
        """Retrieve VLAN configuration."""
        vlans = []
        try:
            output = self.send_command("show vlan brief")
            lines = output.strip().split('\n')

            for line in lines:
                match = re.match(r'^(\d+)\s+(\S+)\s+(active|suspended)', line.strip(), re.IGNORECASE)
                if match:
                    vlans.append({
                        'vlan_id': int(match.group(1)),
                        'name': match.group(2),
                        'status': match.group(3),
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
                # Format: Protocol  Address  Age  Hardware Addr  Type  Interface
                match = re.match(
                    r'Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+|-)\s+'
                    r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'
                    r'(\S+)\s+(\S+)',
                    line.strip()
                )
                if match:
                    arp_entries.append({
                        'ip_address': match.group(1),
                        'mac_address': self._normalize_mac(match.group(3)),
                        'age': match.group(2),
                        'interface': match.group(5),
                        'type': match.group(4)
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
            'vendor': 'cisco',
            'device_type': 'router'
        }

        try:
            version_output = self.send_command("show version")

            # Extract hostname
            hostname_match = re.search(r'^(\S+)\s+uptime', version_output, re.MULTILINE)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)

            # Extract model
            model_match = re.search(r'[Cc]isco\s+(\S+)', version_output)
            if model_match:
                info['model'] = model_match.group(1)

            # Determine device type from model
            model = info['model'] or ''
            if any(x in model.upper() for x in ['ISR', 'ASR', 'CSR', '28', '29', '39', '43', '44']):
                info['device_type'] = 'router'
            elif any(x in model.upper() for x in ['WS-', 'C35', 'C36', 'C37', 'C38', 'C93', 'NEXUS']):
                info['device_type'] = 'switch'

            # Extract version
            version_match = re.search(r'Version\s+([\d.()A-Za-z]+)', version_output)
            if version_match:
                info['version'] = version_match.group(1)

        except Exception:
            pass

        return info

    def get_logs(self) -> str:
        """Retrieve device logs."""
        logs = []

        # Get logging buffer
        try:
            logbuffer = self.send_command("show logging")
            logs.append("=== LOGGING BUFFER ===\n" + logbuffer)
        except Exception:
            pass

        # Get recent events
        try:
            events = self.send_command("show logging last 100")
            logs.append("\n=== RECENT EVENTS ===\n" + events)
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
                if not line.strip() or 'Device ID' in line or '---' in line or 'Total' in line:
                    continue

                parts = line.split()
                if len(parts) >= 4:
                    neighbors.append({
                        'neighbor_device': parts[0],
                        'local_interface': parts[1],
                        'hold_time': parts[2] if parts[2].isdigit() else None,
                        'capabilities': parts[3] if len(parts) > 3 else None,
                        'neighbor_interface': parts[-1] if len(parts) > 4 else None
                    })
        except Exception:
            pass

        # Try detailed version
        if not neighbors:
            try:
                output = self.send_command("show lldp neighbors detail")
                current_neighbor = {}

                for line in output.strip().split('\n'):
                    line = line.strip()
                    if 'Local Intf' in line:
                        if current_neighbor and 'neighbor_device' in current_neighbor:
                            neighbors.append(current_neighbor)
                        current_neighbor = {'local_interface': line.split(':')[-1].strip()}
                    elif 'System Name' in line:
                        current_neighbor['neighbor_device'] = line.split(':')[-1].strip()
                    elif 'Port id' in line:
                        current_neighbor['neighbor_interface'] = line.split(':')[-1].strip()
                    elif 'System Capabilities' in line:
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
                if not line.strip() or 'Device ID' in line or '---' in line or 'Total' in line:
                    continue

                # CDP output can wrap, try to parse it
                parts = line.split()
                if len(parts) >= 2:
                    neighbors.append({
                        'neighbor_device': parts[0],
                        'local_interface': parts[1] + (parts[2] if len(parts) > 2 and parts[2][0].isdigit() else ''),
                        'capabilities': None,
                        'neighbor_interface': parts[-1] if len(parts) > 3 else None
                    })
        except Exception:
            pass

        # Try detailed version for more info
        if not neighbors:
            try:
                output = self.send_command("show cdp neighbors detail")
                current_neighbor = {}

                for line in output.strip().split('\n'):
                    line = line.strip()
                    if 'Device ID' in line:
                        if current_neighbor and 'neighbor_device' in current_neighbor:
                            neighbors.append(current_neighbor)
                        current_neighbor = {'neighbor_device': line.split(':')[-1].strip()}
                    elif 'IP address' in line:
                        current_neighbor['ip_address'] = line.split(':')[-1].strip()
                    elif 'Platform' in line:
                        current_neighbor['platform'] = line.split(':')[-1].split(',')[0].strip()
                    elif 'Interface' in line and 'Port ID' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            current_neighbor['local_interface'] = parts[0].split(':')[-1].strip()
                            current_neighbor['neighbor_interface'] = parts[1].split(':')[-1].strip()

                if current_neighbor and 'neighbor_device' in current_neighbor:
                    neighbors.append(current_neighbor)
            except Exception:
                pass

        return neighbors

    def get_routing_table(self) -> List[Dict[str, Any]]:
        """Retrieve routing table (L3 specific)."""
        routes = []
        try:
            output = self.send_command("show ip route")
            lines = output.strip().split('\n')

            for line in lines:
                # Match routes like: C 192.168.1.0/24 is directly connected, GigabitEthernet0/0
                # Or: S 10.0.0.0/8 [1/0] via 192.168.1.1
                match = re.match(
                    r'([CDOSBRNE\*\+]+)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+'
                    r'(?:is directly connected,\s+(\S+)|'
                    r'\[(\d+)/(\d+)\]\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s+(\S+))?)',
                    line.strip()
                )
                if match:
                    route = {
                        'protocol': match.group(1),
                        'network': match.group(2),
                    }
                    if match.group(3):  # Directly connected
                        route['interface'] = match.group(3)
                        route['type'] = 'connected'
                    else:  # Via next-hop
                        route['admin_distance'] = int(match.group(4))
                        route['metric'] = int(match.group(5))
                        route['next_hop'] = match.group(6)
                        route['interface'] = match.group(7)
                        route['type'] = 'static' if 'S' in match.group(1) else 'dynamic'
                    routes.append(route)
        except Exception:
            pass

        return routes

    def get_ospf_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve OSPF neighbor information (L3 specific)."""
        neighbors = []
        try:
            output = self.send_command("show ip ospf neighbor")
            lines = output.strip().split('\n')

            for line in lines:
                # Format: Neighbor ID  Pri  State  Dead Time  Address  Interface
                match = re.match(
                    r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)/\s*(\S+)\s+'
                    r'(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)',
                    line.strip()
                )
                if match:
                    neighbors.append({
                        'neighbor_id': match.group(1),
                        'priority': int(match.group(2)),
                        'state': match.group(3),
                        'dead_time': match.group(5),
                        'address': match.group(6),
                        'interface': match.group(7)
                    })
        except Exception:
            pass

        return neighbors

    def get_bgp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve BGP neighbor information (L3 specific)."""
        neighbors = []
        try:
            output = self.send_command("show ip bgp summary")
            lines = output.strip().split('\n')

            for line in lines:
                # Format: Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  ...  State/PfxRcd
                match = re.match(
                    r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+.*\s+(\S+)$',
                    line.strip()
                )
                if match:
                    neighbors.append({
                        'neighbor': match.group(1),
                        'version': int(match.group(2)),
                        'as': int(match.group(3)),
                        'msg_rcvd': int(match.group(4)),
                        'msg_sent': int(match.group(5)),
                        'state': match.group(6)
                    })
        except Exception:
            pass

        return neighbors

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
            # Get PoE power inline summary
            power_output = self.send_command("show power inline")

            # Parse module/chassis totals
            # Format: Available:370.0(w)  Used:45.6(w)  Remaining:324.4(w)
            available_match = re.search(r'Available[:\s]*(\d+\.?\d*)\s*\(?[wW]', power_output)
            used_match = re.search(r'Used[:\s]*(\d+\.?\d*)\s*\(?[wW]', power_output)

            if available_match:
                result['supported'] = True
                result['total_budget_watts'] = float(available_match.group(1))
            if used_match:
                result['used_watts'] = float(used_match.group(1))

            if result['total_budget_watts'] > 0:
                result['utilization_percent'] = (result['used_watts'] / result['total_budget_watts']) * 100

            # Parse per-port PoE status
            lines = power_output.strip().split('\n')
            for line in lines:
                # Format: Interface  Admin  Oper  Power  Device  Class  Max
                # Gi1/0/1   auto   on    6.4   IP Phone  2  15.4
                match = re.match(
                    r'(Gi|Fa|Te)\S+\s+(auto|off|on|static)\s+(on|off|faulty)\s+'
                    r'(\d+\.?\d*)\s+(\S.*?)?\s*(\d+)?\s*(\d+\.?\d*)?',
                    line.strip(), re.IGNORECASE
                )
                if match:
                    port_info = {
                        'interface': match.group(0).split()[0],
                        'status': match.group(3).lower(),
                        'power_watts': float(match.group(4)) if match.group(4) else 0,
                        'max_watts': float(match.group(7)) if match.group(7) else 15.4,
                        'device': match.group(5).strip() if match.group(5) else ''
                    }
                    result['ports'].append(port_info)

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
            output = self.send_command("show interfaces status")
            lines = output.strip().split('\n')

            for line in lines:
                # Match interface status lines
                # Format: Port  Name  Status  Vlan  Duplex  Speed  Type
                match = re.match(
                    r'(Gi|Fa|Te|Tw)\S+\s+\S*\s+(connected|notconnect|disabled|err-disabled)',
                    line.strip(), re.IGNORECASE
                )
                if match:
                    result['total_ports'] += 1
                    if match.group(2).lower() == 'connected':
                        result['active_ports'] += 1

            if result['total_ports'] > 0:
                result['utilization_percent'] = (result['active_ports'] / result['total_ports']) * 100

            # Try to get stack information
            try:
                stack_output = self.send_command("show switch")
                for line in stack_output.strip().split('\n'):
                    # Format: Switch#  Role  Mac Address  ...
                    member_match = re.match(r'\s*(\d+)\s+(Master|Member|Standby)', line, re.IGNORECASE)
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
