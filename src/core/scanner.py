import socket
import concurrent.futures
from typing import List, Callable, Optional, Dict, Any
from ..utils.ip_utils import parse_ip_range, parse_bulk_ips, expand_ip_input


class Scanner:
    """Network scanner for discovering SSH-enabled devices."""

    def __init__(self, port: int = 22, timeout: float = 2.0, max_workers: int = 20):
        self.port = port
        self.timeout = timeout
        self.max_workers = max_workers

    def check_ssh_port(self, ip: str) -> bool:
        """Check if SSH port is open on the given IP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_range(self, ip_range: str,
                   progress_callback: Optional[Callable[[int, int, str], None]] = None
                   ) -> List[str]:
        """
        Scan an IP range for devices with open SSH ports.

        Args:
            ip_range: IP range string (CIDR, range notation, or single IP)
            progress_callback: Optional callback(current, total, ip) for progress updates

        Returns:
            List of IPs with open SSH ports
        """
        ips = expand_ip_input(ip_range)
        return self._scan_ips(ips, progress_callback)

    def scan_bulk_ips(self, ips_text: str,
                      progress_callback: Optional[Callable[[int, int, str], None]] = None
                      ) -> List[str]:
        """
        Scan multiple IPs provided as comma/newline separated text.

        Args:
            ips_text: Text containing IPs separated by comma, newline, space, or semicolon
            progress_callback: Optional callback for progress updates

        Returns:
            List of IPs with open SSH ports
        """
        ips = parse_bulk_ips(ips_text)
        return self._scan_ips(ips, progress_callback)

    def _scan_ips(self, ips: List[str],
                  progress_callback: Optional[Callable[[int, int, str], None]] = None
                  ) -> List[str]:
        """Internal method to scan a list of IPs."""
        if not ips:
            return []

        total = len(ips)
        found_devices = []
        current = 0

        def scan_one(ip: str) -> Optional[str]:
            if self.check_ssh_port(ip):
                return ip
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(scan_one, ip): ip for ip in ips}

            for future in concurrent.futures.as_completed(future_to_ip):
                current += 1
                ip = future_to_ip[future]

                try:
                    result = future.result()
                    if result:
                        found_devices.append(result)
                except Exception:
                    pass

                if progress_callback:
                    progress_callback(current, total, ip)

        return sorted(found_devices, key=lambda ip: [int(x) for x in ip.split('.')])

    def scan_with_details(self, ip_range: str,
                          progress_callback: Optional[Callable[[int, int, str, bool], None]] = None
                          ) -> Dict[str, Dict[str, Any]]:
        """
        Scan with detailed results including response time.

        Returns:
            Dict mapping IP to scan results
        """
        import time

        ips = expand_ip_input(ip_range)
        results = {}
        total = len(ips)
        current = 0

        def scan_one(ip: str) -> Dict[str, Any]:
            start_time = time.time()
            is_open = self.check_ssh_port(ip)
            elapsed = time.time() - start_time
            return {
                'ip': ip,
                'ssh_open': is_open,
                'response_time': round(elapsed * 1000, 2) if is_open else None
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(scan_one, ip): ip for ip in ips}

            for future in concurrent.futures.as_completed(future_to_ip):
                current += 1
                ip = future_to_ip[future]

                try:
                    result = future.result()
                    results[ip] = result
                    if progress_callback:
                        progress_callback(current, total, ip, result['ssh_open'])
                except Exception as e:
                    results[ip] = {'ip': ip, 'ssh_open': False, 'error': str(e)}
                    if progress_callback:
                        progress_callback(current, total, ip, False)

        return results
