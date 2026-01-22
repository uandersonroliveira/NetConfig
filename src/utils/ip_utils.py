import re
import ipaddress
from typing import List, Set, Optional
from fastapi import HTTPException


def validate_ip(ip: str) -> bool:
    """Validate if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ip_strict(ip: str) -> str:
    """
    Validate and normalize an IP address.

    Raises HTTPException if invalid.
    Returns the normalized IP string.
    """
    if not ip:
        raise HTTPException(status_code=400, detail="IP address is required")

    ip = ip.strip()

    # Check for path traversal attempts
    dangerous_chars = ['..', '/', '\\', '%', '\x00', '\n', '\r']
    for char in dangerous_chars:
        if char in ip:
            raise HTTPException(status_code=400, detail="Invalid IP address format")

    try:
        # Parse and normalize the IP address
        parsed_ip = ipaddress.IPv4Address(ip)
        return str(parsed_ip)
    except (ipaddress.AddressValueError, ValueError):
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip[:50]}")


def sanitize_ip_for_path(ip: str) -> str:
    """
    Sanitize an IP address for use in file paths.

    Converts dots to underscores and validates the IP first.
    Returns a safe string that can be used in file paths.
    """
    # First validate it's a proper IP
    validated_ip = validate_ip_strict(ip)
    # Convert to safe path format (dots to underscores)
    return validated_ip.replace('.', '_')


def parse_bulk_ips(text: str) -> List[str]:
    """
    Parse a text containing multiple IP addresses.
    Accepts comma, newline, space, semicolon, or tab separated IPs.
    Returns a list of unique, valid IP addresses.
    """
    separators = r'[,;\s\t\n]+'
    parts = re.split(separators, text.strip())

    valid_ips: Set[str] = set()
    for part in parts:
        part = part.strip()
        if part and validate_ip(part):
            valid_ips.add(part)

    return sorted(valid_ips, key=lambda ip: [int(x) for x in ip.split('.')])


def parse_ip_range(range_str: str) -> List[str]:
    """
    Parse IP range notation and return list of IPs.
    Supports:
    - Single IP: 192.168.1.1
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.1-192.168.1.10
    - Last octet range: 192.168.1.1-10
    """
    range_str = range_str.strip()

    if validate_ip(range_str):
        return [range_str]

    if '/' in range_str:
        try:
            network = ipaddress.IPv4Network(range_str, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []

    if '-' in range_str:
        parts = range_str.split('-')
        if len(parts) == 2:
            start = parts[0].strip()
            end = parts[1].strip()

            if validate_ip(start):
                if validate_ip(end):
                    try:
                        start_ip = ipaddress.IPv4Address(start)
                        end_ip = ipaddress.IPv4Address(end)
                        if start_ip <= end_ip:
                            return [str(ipaddress.IPv4Address(i))
                                    for i in range(int(start_ip), int(end_ip) + 1)]
                    except ValueError:
                        return []
                else:
                    try:
                        end_octet = int(end)
                        start_parts = start.split('.')
                        start_octet = int(start_parts[3])
                        if 0 <= end_octet <= 255 and start_octet <= end_octet:
                            base = '.'.join(start_parts[:3])
                            return [f"{base}.{i}" for i in range(start_octet, end_octet + 1)]
                    except ValueError:
                        return []

    return []


def expand_ip_input(text: str) -> List[str]:
    """
    Expand IP input that may contain ranges, CIDR, or individual IPs.
    Handles mixed input with separators.
    """
    separators = r'[,;\n]+'
    parts = re.split(separators, text.strip())

    all_ips: Set[str] = set()
    for part in parts:
        part = part.strip()
        if not part:
            continue

        if ' ' in part and '-' not in part and '/' not in part:
            space_parts = part.split()
            for sp in space_parts:
                if validate_ip(sp.strip()):
                    all_ips.add(sp.strip())
        else:
            ips = parse_ip_range(part)
            all_ips.update(ips)

    return sorted(all_ips, key=lambda ip: [int(x) for x in ip.split('.')])
