import re
from typing import Dict, Any, List, Optional
from ..models.config import ParsedConfig


class ConfigAnalyzer:
    """Analyzes and parses device configurations."""

    def analyze_config(self, raw_config: str, vendor: str = 'huawei') -> ParsedConfig:
        """
        Analyze a raw configuration and extract structured data.

        Args:
            raw_config: Raw configuration text
            vendor: Device vendor ('huawei' or 'hp')

        Returns:
            ParsedConfig with extracted data
        """
        parsed = ParsedConfig()

        parsed.hostname = self._extract_hostname(raw_config)
        parsed.vlans = self._extract_vlans(raw_config, vendor)
        parsed.interfaces = self._extract_interface_configs(raw_config, vendor)
        parsed.users = self._extract_users(raw_config, vendor)
        parsed.acls = self._extract_acls(raw_config, vendor)
        parsed.snmp_config = self._extract_snmp_config(raw_config)
        parsed.stp_config = self._extract_stp_config(raw_config, vendor)

        return parsed

    def _extract_hostname(self, config: str) -> Optional[str]:
        """Extract hostname from configuration."""
        match = re.search(r'sysname\s+(\S+)', config)
        if match:
            return match.group(1)
        return None

    def _extract_vlans(self, config: str, vendor: str) -> List[Dict[str, Any]]:
        """Extract VLAN configurations."""
        vlans = []

        vlan_pattern = r'vlan\s+(\d+)(?:\s+name\s+(\S+))?'
        for match in re.finditer(vlan_pattern, config, re.IGNORECASE):
            vlan_id = int(match.group(1))
            name = match.group(2) if match.group(2) else f'VLAN{vlan_id}'
            vlans.append({
                'vlan_id': vlan_id,
                'name': name
            })

        batch_pattern = r'vlan\s+batch\s+([\d\s]+)'
        for match in re.finditer(batch_pattern, config, re.IGNORECASE):
            vlan_ids = re.findall(r'\d+', match.group(1))
            for vid in vlan_ids:
                vid = int(vid)
                if not any(v['vlan_id'] == vid for v in vlans):
                    vlans.append({
                        'vlan_id': vid,
                        'name': f'VLAN{vid}'
                    })

        return sorted(vlans, key=lambda x: x['vlan_id'])

    def _extract_interface_configs(self, config: str, vendor: str) -> List[Dict[str, Any]]:
        """Extract interface configurations."""
        interfaces = []

        interface_blocks = re.split(r'\n(?=interface\s+)', config)

        for block in interface_blocks:
            if not block.strip().startswith('interface'):
                continue

            interface_match = re.match(r'interface\s+(\S+)', block)
            if not interface_match:
                continue

            iface = {
                'name': interface_match.group(1),
                'description': None,
                'vlan': None,
                'mode': None,
                'trunk_vlans': [],
                'shutdown': False,
                'speed': None,
                'duplex': None
            }

            desc_match = re.search(r'description\s+(.+?)(?:\n|$)', block)
            if desc_match:
                iface['description'] = desc_match.group(1).strip()

            if re.search(r'port\s+link-type\s+access', block, re.IGNORECASE):
                iface['mode'] = 'access'
                access_vlan = re.search(r'port\s+(?:default|access)\s+vlan\s+(\d+)', block, re.IGNORECASE)
                if access_vlan:
                    iface['vlan'] = int(access_vlan.group(1))

            elif re.search(r'port\s+link-type\s+trunk', block, re.IGNORECASE):
                iface['mode'] = 'trunk'
                trunk_allow = re.search(r'port\s+trunk\s+allow-pass\s+vlan\s+(.+?)(?:\n|$)', block, re.IGNORECASE)
                if trunk_allow:
                    vlan_str = trunk_allow.group(1).strip()
                    if vlan_str.lower() == 'all':
                        iface['trunk_vlans'] = ['all']
                    else:
                        iface['trunk_vlans'] = self._parse_vlan_list(vlan_str)

            if re.search(r'\bshutdown\b', block) and not re.search(r'undo\s+shutdown', block):
                iface['shutdown'] = True

            speed_match = re.search(r'speed\s+(\S+)', block)
            if speed_match:
                iface['speed'] = speed_match.group(1)

            duplex_match = re.search(r'duplex\s+(\S+)', block)
            if duplex_match:
                iface['duplex'] = duplex_match.group(1)

            interfaces.append(iface)

        return interfaces

    def _parse_vlan_list(self, vlan_str: str) -> List[int]:
        """Parse a VLAN list string (e.g., '1 10 to 20 100') into a list of VLAN IDs."""
        vlans = []
        parts = vlan_str.split()
        i = 0

        while i < len(parts):
            if parts[i].isdigit():
                if i + 2 < len(parts) and parts[i + 1].lower() == 'to':
                    start = int(parts[i])
                    end = int(parts[i + 2])
                    vlans.extend(range(start, end + 1))
                    i += 3
                else:
                    vlans.append(int(parts[i]))
                    i += 1
            else:
                i += 1

        return sorted(set(vlans))

    def _extract_users(self, config: str, vendor: str) -> List[Dict[str, Any]]:
        """Extract local user accounts."""
        users = []

        user_blocks = re.findall(
            r'local-user\s+(\S+).*?(?=\nlocal-user\s|\n#|\Z)',
            config, re.DOTALL
        )

        for block in re.finditer(r'local-user\s+(\S+)(.*?)(?=\nlocal-user\s|\n#|\Z)', config, re.DOTALL):
            username = block.group(1)
            user_config = block.group(2)

            user = {
                'username': username,
                'privilege': None,
                'service_type': []
            }

            priv_match = re.search(r'privilege\s+level\s+(\d+)', user_config)
            if priv_match:
                user['privilege'] = int(priv_match.group(1))

            service_match = re.search(r'service-type\s+(.+?)(?:\n|$)', user_config)
            if service_match:
                user['service_type'] = service_match.group(1).strip().split()

            users.append(user)

        return users

    def _extract_acls(self, config: str, vendor: str) -> List[Dict[str, Any]]:
        """Extract ACL configurations."""
        acls = []

        acl_blocks = re.finditer(
            r'acl\s+(?:number\s+)?(\d+)(?:\s+name\s+(\S+))?(.*?)(?=\nacl\s|\n#|\Z)',
            config, re.DOTALL | re.IGNORECASE
        )

        for match in acl_blocks:
            acl = {
                'number': int(match.group(1)),
                'name': match.group(2),
                'rules': []
            }

            rules = re.findall(r'rule\s+(\d+)\s+(.+?)(?:\n|$)', match.group(3))
            for rule_num, rule_content in rules:
                acl['rules'].append({
                    'number': int(rule_num),
                    'rule': rule_content.strip()
                })

            if acl['rules']:
                acls.append(acl)

        return acls

    def _extract_snmp_config(self, config: str) -> Optional[Dict[str, Any]]:
        """Extract SNMP configuration."""
        snmp = {
            'version': None,
            'communities': [],
            'contact': None,
            'location': None
        }

        if 'snmp-agent' not in config.lower():
            return None

        version_match = re.search(r'snmp-agent\s+sys-info\s+version\s+(\S+)', config, re.IGNORECASE)
        if version_match:
            snmp['version'] = version_match.group(1)

        community_matches = re.findall(
            r'snmp-agent\s+community\s+(\S+)\s+(\S+)',
            config, re.IGNORECASE
        )
        for perm, name in community_matches:
            snmp['communities'].append({
                'name': name,
                'permission': perm
            })

        contact_match = re.search(r'snmp-agent\s+sys-info\s+contact\s+(.+?)(?:\n|$)', config)
        if contact_match:
            snmp['contact'] = contact_match.group(1).strip()

        location_match = re.search(r'snmp-agent\s+sys-info\s+location\s+(.+?)(?:\n|$)', config)
        if location_match:
            snmp['location'] = location_match.group(1).strip()

        return snmp

    def _extract_stp_config(self, config: str, vendor: str) -> Optional[Dict[str, Any]]:
        """Extract STP configuration."""
        stp = {
            'mode': None,
            'priority': None,
            'enabled': True
        }

        if 'stp disable' in config.lower() or 'undo stp enable' in config.lower():
            stp['enabled'] = False
            return stp

        mode_match = re.search(r'stp\s+mode\s+(\S+)', config, re.IGNORECASE)
        if mode_match:
            stp['mode'] = mode_match.group(1).lower()

        priority_match = re.search(r'stp\s+priority\s+(\d+)', config, re.IGNORECASE)
        if priority_match:
            stp['priority'] = int(priority_match.group(1))

        return stp

    def get_config_summary(self, parsed: ParsedConfig) -> Dict[str, Any]:
        """Generate a summary of the configuration."""
        return {
            'hostname': parsed.hostname,
            'vlan_count': len(parsed.vlans),
            'interface_count': len(parsed.interfaces),
            'user_count': len(parsed.users),
            'acl_count': len(parsed.acls),
            'has_snmp': parsed.snmp_config is not None,
            'stp_enabled': parsed.stp_config.get('enabled', False) if parsed.stp_config else False
        }
