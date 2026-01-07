import difflib
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..models.config import ConfigSnapshot, ConfigComparison


class ConfigComparator:
    """Compares device configurations and identifies differences."""

    def compare_configs(self, config1: ConfigSnapshot, config2: ConfigSnapshot
                       ) -> ConfigComparison:
        """
        Compare two configuration snapshots.

        Args:
            config1: First configuration snapshot
            config2: Second configuration snapshot

        Returns:
            ConfigComparison with detailed differences
        """
        differences = []

        text_diff = self._diff_text(config1.raw_config, config2.raw_config)
        differences.extend(text_diff)

        if config1.parsed_data and config2.parsed_data:
            parsed_diff = self._diff_parsed(config1.parsed_data, config2.parsed_data)
            differences.extend(parsed_diff)

        summary = self._generate_summary(differences)

        return ConfigComparison(
            device1_ip=config1.device_ip,
            device2_ip=config2.device_ip,
            device1_timestamp=config1.timestamp,
            device2_timestamp=config2.timestamp,
            differences=differences,
            summary=summary
        )

    def _diff_text(self, text1: str, text2: str) -> List[Dict[str, Any]]:
        """Generate unified diff between two text configurations."""
        lines1 = text1.splitlines(keepends=True)
        lines2 = text2.splitlines(keepends=True)

        diff = difflib.unified_diff(
            lines1, lines2,
            fromfile='config1', tofile='config2',
            lineterm=''
        )

        diff_lines = []
        current_section = None

        for line in diff:
            if line.startswith('@@'):
                current_section = line.strip()
            elif line.startswith('-') and not line.startswith('---'):
                diff_lines.append({
                    'type': 'removed',
                    'content': line[1:].rstrip(),
                    'section': current_section
                })
            elif line.startswith('+') and not line.startswith('+++'):
                diff_lines.append({
                    'type': 'added',
                    'content': line[1:].rstrip(),
                    'section': current_section
                })

        return diff_lines

    def _diff_parsed(self, parsed1: Dict[str, Any], parsed2: Dict[str, Any]
                    ) -> List[Dict[str, Any]]:
        """Compare parsed configuration data."""
        differences = []

        differences.extend(self._compare_vlans(
            parsed1.get('vlans', []),
            parsed2.get('vlans', [])
        ))

        differences.extend(self._compare_interfaces(
            parsed1.get('interfaces', []),
            parsed2.get('interfaces', [])
        ))

        differences.extend(self._compare_users(
            parsed1.get('users', []),
            parsed2.get('users', [])
        ))

        return differences

    def _compare_vlans(self, vlans1: List[Dict], vlans2: List[Dict]
                      ) -> List[Dict[str, Any]]:
        """Compare VLAN configurations."""
        differences = []

        vlan_ids1 = {v['vlan_id'] for v in vlans1}
        vlan_ids2 = {v['vlan_id'] for v in vlans2}

        for vid in vlan_ids1 - vlan_ids2:
            vlan = next(v for v in vlans1 if v['vlan_id'] == vid)
            differences.append({
                'type': 'vlan_removed',
                'category': 'vlan',
                'vlan_id': vid,
                'name': vlan.get('name'),
                'source': 'config1'
            })

        for vid in vlan_ids2 - vlan_ids1:
            vlan = next(v for v in vlans2 if v['vlan_id'] == vid)
            differences.append({
                'type': 'vlan_added',
                'category': 'vlan',
                'vlan_id': vid,
                'name': vlan.get('name'),
                'source': 'config2'
            })

        return differences

    def _compare_interfaces(self, ifaces1: List[Dict], ifaces2: List[Dict]
                           ) -> List[Dict[str, Any]]:
        """Compare interface configurations."""
        differences = []

        iface_map1 = {i['name']: i for i in ifaces1}
        iface_map2 = {i['name']: i for i in ifaces2}

        all_ifaces = set(iface_map1.keys()) | set(iface_map2.keys())

        for iface_name in all_ifaces:
            if1 = iface_map1.get(iface_name)
            if2 = iface_map2.get(iface_name)

            if if1 and not if2:
                differences.append({
                    'type': 'interface_removed',
                    'category': 'interface',
                    'interface': iface_name,
                    'source': 'config1'
                })
            elif if2 and not if1:
                differences.append({
                    'type': 'interface_added',
                    'category': 'interface',
                    'interface': iface_name,
                    'source': 'config2'
                })
            elif if1 and if2:
                changes = []
                for key in ['vlan', 'mode', 'description', 'shutdown']:
                    if if1.get(key) != if2.get(key):
                        changes.append({
                            'field': key,
                            'old_value': if1.get(key),
                            'new_value': if2.get(key)
                        })

                if changes:
                    differences.append({
                        'type': 'interface_changed',
                        'category': 'interface',
                        'interface': iface_name,
                        'changes': changes
                    })

        return differences

    def _compare_users(self, users1: List[Dict], users2: List[Dict]
                      ) -> List[Dict[str, Any]]:
        """Compare user configurations."""
        differences = []

        user_map1 = {u['username']: u for u in users1}
        user_map2 = {u['username']: u for u in users2}

        all_users = set(user_map1.keys()) | set(user_map2.keys())

        for username in all_users:
            u1 = user_map1.get(username)
            u2 = user_map2.get(username)

            if u1 and not u2:
                differences.append({
                    'type': 'user_removed',
                    'category': 'user',
                    'username': username,
                    'source': 'config1'
                })
            elif u2 and not u1:
                differences.append({
                    'type': 'user_added',
                    'category': 'user',
                    'username': username,
                    'source': 'config2'
                })
            elif u1 and u2:
                if u1.get('privilege') != u2.get('privilege'):
                    differences.append({
                        'type': 'user_changed',
                        'category': 'user',
                        'username': username,
                        'field': 'privilege',
                        'old_value': u1.get('privilege'),
                        'new_value': u2.get('privilege')
                    })

        return differences

    def _generate_summary(self, differences: List[Dict[str, Any]]) -> Dict[str, int]:
        """Generate a summary of differences by category."""
        summary = {
            'total_changes': len(differences),
            'lines_added': 0,
            'lines_removed': 0,
            'vlans_changed': 0,
            'interfaces_changed': 0,
            'users_changed': 0
        }

        for diff in differences:
            diff_type = diff.get('type', '')
            category = diff.get('category', '')

            if diff_type == 'added':
                summary['lines_added'] += 1
            elif diff_type == 'removed':
                summary['lines_removed'] += 1
            elif category == 'vlan':
                summary['vlans_changed'] += 1
            elif category == 'interface':
                summary['interfaces_changed'] += 1
            elif category == 'user':
                summary['users_changed'] += 1

        return summary

    def get_diff_html(self, config1: ConfigSnapshot, config2: ConfigSnapshot) -> str:
        """Generate an HTML diff view."""
        lines1 = config1.raw_config.splitlines()
        lines2 = config2.raw_config.splitlines()

        differ = difflib.HtmlDiff()
        return differ.make_table(
            lines1, lines2,
            fromdesc=f'{config1.device_ip} ({config1.timestamp})',
            todesc=f'{config2.device_ip} ({config2.timestamp})',
            context=True
        )
