"""LDAP/Active Directory client for authentication."""

from typing import Optional, Dict, List, Tuple
import ssl

from ..models.user import ADSettings


class LDAPClient:
    """Client for LDAP/Active Directory authentication."""

    def __init__(self, settings: ADSettings):
        self.settings = settings
        self._connection = None

    def _get_connection(self):
        """Get or create LDAP connection."""
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls

            server_uri = self.settings.server
            port = self.settings.port

            # Create TLS context if SSL is enabled
            tls = None
            if self.settings.use_ssl:
                tls = Tls(validate=ssl.CERT_NONE)  # For self-signed certs
                if port == 389:
                    port = 636  # Default LDAPS port

            server = Server(
                server_uri,
                port=port,
                use_ssl=self.settings.use_ssl,
                tls=tls,
                get_info=ALL
            )

            return server

        except ImportError:
            raise ImportError("ldap3 package is required for Active Directory integration. Install with: pip install ldap3")

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate a user against Active Directory.

        Returns user info dict if successful, None otherwise.
        """
        try:
            import ldap3
            from ldap3 import Connection, SIMPLE, NTLM

            server = self._get_connection()

            # Build user DN based on pattern
            # Supports patterns like:
            # - "{username}@domain.com" for UPN
            # - "DOMAIN\\{username}" for NT style
            # - "cn={username},ou=users,dc=example,dc=com" for DN style
            user_dn = self.settings.user_dn_pattern.format(username=username)

            # Try to bind with user credentials
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=False,
                raise_exceptions=False
            )

            if not conn.bind():
                return None

            # Try to get user info
            user_info = {
                "username": username,
                "email": None,
                "display_name": None,
                "groups": []
            }

            # Search for user to get additional info
            if self.settings.base_dn:
                search_filter = f"(sAMAccountName={username})"
                conn.search(
                    self.settings.base_dn,
                    search_filter,
                    attributes=['mail', 'displayName', 'memberOf']
                )

                if conn.entries:
                    entry = conn.entries[0]
                    if hasattr(entry, 'mail') and entry.mail.value:
                        user_info["email"] = str(entry.mail.value)
                    if hasattr(entry, 'displayName') and entry.displayName.value:
                        user_info["display_name"] = str(entry.displayName.value)
                    if hasattr(entry, 'memberOf') and entry.memberOf.values:
                        user_info["groups"] = [str(g) for g in entry.memberOf.values]

            conn.unbind()
            return user_info

        except ImportError:
            raise
        except Exception as e:
            print(f"LDAP authentication error: {e}")
            return None

    def get_user_groups(self, username: str) -> List[str]:
        """
        Get the groups a user belongs to.

        Returns list of group names (CN only, not full DN).
        """
        try:
            import ldap3
            from ldap3 import Connection, SIMPLE

            if not self.settings.bind_user or not self.settings.bind_password:
                return []

            server = self._get_connection()

            # Bind with service account
            conn = Connection(
                server,
                user=self.settings.bind_user,
                password=self.settings.bind_password,
                authentication=SIMPLE,
                auto_bind=True
            )

            # Search for user's groups
            search_filter = f"(sAMAccountName={username})"
            conn.search(
                self.settings.base_dn,
                search_filter,
                attributes=['memberOf']
            )

            groups = []
            if conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, 'memberOf') and entry.memberOf.values:
                    for group_dn in entry.memberOf.values:
                        # Extract CN from DN (e.g., "CN=GroupName,OU=Groups,DC=domain,DC=com")
                        group_str = str(group_dn)
                        if group_str.upper().startswith("CN="):
                            cn = group_str.split(",")[0][3:]  # Get value after "CN="
                            groups.append(cn)

            conn.unbind()
            return groups

        except ImportError:
            raise
        except Exception as e:
            print(f"LDAP get groups error: {e}")
            return []

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test the LDAP connection.

        Returns (success, message) tuple.
        """
        try:
            import ldap3
            from ldap3 import Connection, SIMPLE, ANONYMOUS

            server = self._get_connection()

            # If bind credentials are provided, use them
            if self.settings.bind_user and self.settings.bind_password:
                conn = Connection(
                    server,
                    user=self.settings.bind_user,
                    password=self.settings.bind_password,
                    authentication=SIMPLE,
                    auto_bind=False,
                    raise_exceptions=False
                )

                if conn.bind():
                    # Try to search base DN
                    if self.settings.base_dn:
                        conn.search(self.settings.base_dn, '(objectClass=*)', attributes=['objectClass'])
                        entry_count = len(conn.entries)
                        conn.unbind()
                        return True, f"Connection successful. Found {entry_count} entries in base DN."

                    conn.unbind()
                    return True, "Connection successful. Bind credentials verified."
                else:
                    return False, f"Bind failed: {conn.result.get('description', 'Unknown error')}"

            else:
                # Try anonymous bind just to test connectivity
                conn = Connection(
                    server,
                    authentication=ANONYMOUS,
                    auto_bind=False,
                    raise_exceptions=False
                )

                if conn.bind():
                    conn.unbind()
                    return True, "Connection successful (anonymous bind). Configure bind credentials for full functionality."

                # Even if anonymous bind fails, we can check if server is reachable
                return True, "Server is reachable. Anonymous bind not allowed - configure bind credentials."

        except ImportError:
            return False, "ldap3 package is not installed. Install with: pip install ldap3"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    def search_users(self, search_term: str, limit: int = 50) -> List[Dict]:
        """
        Search for users in Active Directory.

        Returns list of user info dicts.
        """
        try:
            import ldap3
            from ldap3 import Connection, SIMPLE

            if not self.settings.bind_user or not self.settings.bind_password:
                return []

            server = self._get_connection()

            conn = Connection(
                server,
                user=self.settings.bind_user,
                password=self.settings.bind_password,
                authentication=SIMPLE,
                auto_bind=True
            )

            # Search for users matching the term
            search_filter = f"(&(objectClass=user)(|(sAMAccountName=*{search_term}*)(displayName=*{search_term}*)(mail=*{search_term}*)))"
            conn.search(
                self.settings.base_dn,
                search_filter,
                attributes=['sAMAccountName', 'mail', 'displayName'],
                size_limit=limit
            )

            users = []
            for entry in conn.entries:
                user = {
                    "username": str(entry.sAMAccountName.value) if entry.sAMAccountName.value else "",
                    "email": str(entry.mail.value) if hasattr(entry, 'mail') and entry.mail.value else None,
                    "display_name": str(entry.displayName.value) if hasattr(entry, 'displayName') and entry.displayName.value else None
                }
                if user["username"]:
                    users.append(user)

            conn.unbind()
            return users

        except ImportError:
            raise
        except Exception as e:
            print(f"LDAP search error: {e}")
            return []
