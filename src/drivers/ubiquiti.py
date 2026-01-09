import re
from typing import Dict, Any, List
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from .base import BaseDriver


class UbiquitiDriver(BaseDriver):
    """Driver for Ubiquiti Access Points (EdgeOS/Linux based)."""

    DEVICE_TYPE = "linux"

    def connect(self) -> bool:
        """Establish SSH connection to the Ubiquiti device."""
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
        config_parts = []

        # Try different configuration locations
        try:
            system_cfg = self.send_command("cat /tmp/system.cfg 2>/dev/null || cat /tmp/running.cfg 2>/dev/null || echo ''")
            if system_cfg.strip():
                config_parts.append("=== SYSTEM CONFIG ===\n" + system_cfg)
        except Exception:
            pass

        try:
            # Get wireless config if available
            wireless = self.send_command("cat /etc/persistent/cfg/wireless.cfg 2>/dev/null || echo ''")
            if wireless.strip():
                config_parts.append("\n=== WIRELESS CONFIG ===\n" + wireless)
        except Exception:
            pass

        try:
            # Try mca-cli for UniFi devices
            mca_config = self.send_command("mca-cli-op info 2>/dev/null || echo ''")
            if mca_config.strip():
                config_parts.append("\n=== MCA INFO ===\n" + mca_config)
        except Exception:
            pass

        return "\n".join(config_parts) if config_parts else "Configuration not available"

    def get_mac_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse the MAC address table (ARP/bridge fdb)."""
        mac_entries = []

        try:
            # Get bridge forwarding database
            fdb_output = self.send_command("bridge fdb show 2>/dev/null || brctl showmacs br0 2>/dev/null || echo ''")

            for line in fdb_output.strip().split('\n'):
                # Parse bridge fdb format: MAC dev interface ...
                match = re.match(
                    r'([0-9a-fA-F:]{17})\s+dev\s+(\S+)',
                    line.strip()
                )
                if match:
                    mac_entries.append({
                        'mac_address': match.group(1).lower(),
                        'vlan': 0,
                        'interface': match.group(2),
                        'type': 'dynamic'
                    })

                # Parse brctl format
                match2 = re.match(
                    r'(\d+)\s+([0-9a-fA-F:]{17})\s+(\S+)',
                    line.strip()
                )
                if match2:
                    mac_entries.append({
                        'mac_address': match2.group(2).lower(),
                        'vlan': 0,
                        'interface': 'br0',
                        'type': 'dynamic'
                    })
        except Exception:
            pass

        return mac_entries

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve and parse interface information."""
        interfaces = []

        try:
            output = self.send_command("ip link show")

            for line in output.strip().split('\n'):
                # Parse: 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
                match = re.match(
                    r'\d+:\s+(\S+):\s+<([^>]*)>',
                    line.strip()
                )
                if match:
                    iface_name = match.group(1).rstrip(':')
                    flags = match.group(2)
                    status = 'up' if 'UP' in flags else 'down'

                    interfaces.append({
                        'interface': iface_name,
                        'status': status,
                        'protocol': 'up' if 'LOWER_UP' in flags else 'down',
                        'description': None
                    })
        except Exception:
            pass

        return interfaces

    def get_vlans(self) -> List[Dict[str, Any]]:
        """Retrieve and parse VLAN configuration."""
        vlans = []

        try:
            output = self.send_command("cat /proc/net/vlan/config 2>/dev/null || echo ''")

            for line in output.strip().split('\n'):
                # Parse: vlan10 | 10 | eth0
                match = re.match(
                    r'(\S+)\s+\|\s+(\d+)\s+\|\s+(\S+)',
                    line.strip()
                )
                if match:
                    vlans.append({
                        'vlan_id': int(match.group(2)),
                        'name': match.group(1),
                        'ports': [match.group(3)]
                    })
        except Exception:
            pass

        return vlans

    def get_arp_table(self) -> List[Dict[str, Any]]:
        """Retrieve and parse ARP table."""
        arp_entries = []

        try:
            output = self.send_command("arp -n 2>/dev/null || cat /proc/net/arp")

            for line in output.strip().split('\n'):
                # Parse: IP HWtype HWaddress Flags Mask Iface
                match = re.match(
                    r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})\s+\S+\s+\S+\s+(\S+)',
                    line.strip()
                )
                if match:
                    arp_entries.append({
                        'ip_address': match.group(1),
                        'mac_address': match.group(2).lower(),
                        'vlan': 0,
                        'interface': match.group(3),
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
            'vendor': 'ubiquiti'
        }

        try:
            # Get hostname
            hostname = self.send_command("hostname 2>/dev/null || cat /proc/sys/kernel/hostname")
            if hostname.strip():
                info['hostname'] = hostname.strip()
        except Exception:
            pass

        try:
            # Try mca-cli for UniFi devices
            mca_info = self.send_command("mca-cli-op info 2>/dev/null || echo ''")
            if mca_info.strip():
                model_match = re.search(r'Model:\s*(.+)', mca_info)
                if model_match:
                    info['model'] = model_match.group(1).strip()

                version_match = re.search(r'Version:\s*(.+)', mca_info)
                if version_match:
                    info['version'] = version_match.group(1).strip()
        except Exception:
            pass

        # Fallback to system files
        if not info['model']:
            try:
                board = self.send_command("cat /etc/board.info 2>/dev/null || echo ''")
                model_match = re.search(r'board\.name=(\S+)', board)
                if model_match:
                    info['model'] = model_match.group(1)
            except Exception:
                pass

        if not info['version']:
            try:
                version = self.send_command("cat /etc/version 2>/dev/null || uname -r")
                if version.strip():
                    info['version'] = version.strip()
            except Exception:
                pass

        return info

    def get_logs(self) -> str:
        """Retrieve device logs."""
        logs = []

        try:
            # Get kernel messages
            dmesg = self.send_command("dmesg | tail -100 2>/dev/null || echo ''")
            if dmesg.strip():
                logs.append("=== KERNEL LOG ===\n" + dmesg)
        except Exception:
            pass

        try:
            # Get syslog
            syslog = self.send_command("cat /var/log/messages 2>/dev/null | tail -100 || echo ''")
            if syslog.strip():
                logs.append("\n=== SYSLOG ===\n" + syslog)
        except Exception:
            pass

        try:
            # Get wireless log if available
            wireless_log = self.send_command("cat /var/log/wevent 2>/dev/null | tail -50 || echo ''")
            if wireless_log.strip():
                logs.append("\n=== WIRELESS LOG ===\n" + wireless_log)
        except Exception:
            pass

        return "\n".join(logs) if logs else "No logs available"

    def get_lldp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve LLDP neighbor information."""
        neighbors = []

        try:
            # Try lldpcli if available
            output = self.send_command("lldpcli show neighbors 2>/dev/null || echo ''")

            if output.strip():
                current_neighbor = {}

                for line in output.strip().split('\n'):
                    line = line.strip()
                    if 'Interface:' in line:
                        if current_neighbor and 'neighbor_device' in current_neighbor:
                            neighbors.append(current_neighbor)
                        current_neighbor = {}
                        iface_match = re.search(r'Interface:\s*(\S+)', line)
                        if iface_match:
                            current_neighbor['local_interface'] = iface_match.group(1)
                    elif 'SysName:' in line:
                        name_match = re.search(r'SysName:\s*(.+)', line)
                        if name_match:
                            current_neighbor['neighbor_device'] = name_match.group(1).strip()
                    elif 'PortID:' in line:
                        port_match = re.search(r'PortID:\s*(.+)', line)
                        if port_match:
                            current_neighbor['neighbor_interface'] = port_match.group(1).strip()
                    elif 'Capability:' in line:
                        cap_match = re.search(r'Capability:\s*(.+)', line)
                        if cap_match:
                            current_neighbor['capabilities'] = cap_match.group(1).strip()

                if current_neighbor and 'neighbor_device' in current_neighbor:
                    neighbors.append(current_neighbor)
        except Exception:
            pass

        return neighbors

    def get_cdp_neighbors(self) -> List[Dict[str, Any]]:
        """Retrieve CDP neighbor information (Ubiquiti does not typically support CDP)."""
        return []

    def get_poe_status(self) -> Dict[str, Any]:
        """Get PoE status. Ubiquiti APs consume PoE, they don't provide it."""
        result = {
            'supported': False,
            'total_budget_watts': 0,
            'used_watts': 0,
            'utilization_percent': 0,
            'ports': [],
            'note': 'Device consumes PoE (does not provide PoE ports)'
        }

        # Try to get power consumption if available
        try:
            mca_status = self.send_command("mca-status 2>/dev/null || echo ''")
            if mca_status.strip():
                # Look for power consumption in mca-status
                power_match = re.search(r'(?:power|poe)[:\s]+(\d+\.?\d*)\s*(?:W|mW)', mca_status, re.IGNORECASE)
                if power_match:
                    power = float(power_match.group(1))
                    # Convert mW to W if needed
                    if power > 100:
                        power = power / 1000
                    result['used_watts'] = power
                    result['note'] = f'Device consuming {power:.1f}W via PoE'
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
            output = self.send_command("ip link show")

            for line in output.strip().split('\n'):
                # Count only physical interfaces (eth, wlan, ath)
                match = re.match(
                    r'\d+:\s+(eth\d+|wlan\d+|ath\d+):\s+<([^>]*)>',
                    line.strip()
                )
                if match:
                    result['total_ports'] += 1
                    flags = match.group(2)
                    if 'UP' in flags and 'LOWER_UP' in flags:
                        result['active_ports'] += 1

            if result['total_ports'] > 0:
                result['utilization_percent'] = (result['active_ports'] / result['total_ports']) * 100
        except Exception:
            pass

        # Get connected clients count for APs
        try:
            station_dump = self.send_command("iwinfo wlan0 assoclist 2>/dev/null | wc -l || echo '0'")
            clients = int(station_dump.strip()) if station_dump.strip().isdigit() else 0
            if clients > 0:
                result['connected_clients'] = clients
        except Exception:
            pass

        return result
