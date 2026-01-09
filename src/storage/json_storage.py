import json
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from threading import Lock
from ..models.device import Device, DeviceStatus, DeviceVendor, DeviceGroup
from ..models.config import Credential, ConfigSnapshot
from ..models.user import User, AuthSettings, ADSettings
from ..utils.crypto import encrypt_password, decrypt_password


class JsonStorage:
    """JSON file-based storage for devices, credentials, and configurations."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.devices_file = self.data_dir / "devices.json"
        self.credentials_file = self.data_dir / "credentials.json"
        self.groups_file = self.data_dir / "device_groups.json"
        self.users_file = self.data_dir / "users.json"
        self.auth_settings_file = self.data_dir / "auth_settings.json"
        self.configs_dir = self.data_dir / "configs"
        self.configs_dir.mkdir(exist_ok=True)

        self._lock = Lock()
        self._init_files()

    def _init_files(self) -> None:
        """Initialize storage files if they don't exist."""
        if not self.devices_file.exists():
            self._write_json(self.devices_file, [])
        if not self.credentials_file.exists():
            self._write_json(self.credentials_file, [])
        if not self.groups_file.exists():
            self._write_json(self.groups_file, [])
        if not self.users_file.exists():
            self._write_json(self.users_file, [])
        if not self.auth_settings_file.exists():
            default_settings = AuthSettings().model_dump()
            self._write_json(self.auth_settings_file, default_settings)

    def _read_json(self, filepath: Path) -> Any:
        """Read JSON file with locking."""
        with self._lock:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []

    def _write_json(self, filepath: Path, data: Any) -> None:
        """Write JSON file with locking."""
        with self._lock:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)

    # Device operations
    def list_devices(self) -> List[Device]:
        """List all devices."""
        data = self._read_json(self.devices_file)
        return [Device(**d) for d in data]

    def get_device(self, ip: str) -> Optional[Device]:
        """Get a device by IP address."""
        devices = self.list_devices()
        for device in devices:
            if device.ip == ip:
                return device
        return None

    def save_device(self, device: Device) -> Device:
        """Save or update a device."""
        devices = self._read_json(self.devices_file)

        existing_idx = None
        for i, d in enumerate(devices):
            if d['ip'] == device.ip:
                existing_idx = i
                break

        device_dict = device.model_dump()
        if existing_idx is not None:
            devices[existing_idx] = device_dict
        else:
            devices.append(device_dict)

        self._write_json(self.devices_file, devices)
        return device

    def delete_device(self, ip: str) -> bool:
        """Delete a device by IP."""
        devices = self._read_json(self.devices_file)
        initial_len = len(devices)
        devices = [d for d in devices if d['ip'] != ip]

        if len(devices) < initial_len:
            self._write_json(self.devices_file, devices)
            return True
        return False

    def update_device_status(self, ip: str, status: DeviceStatus) -> None:
        """Update device status."""
        device = self.get_device(ip)
        if device:
            device.status = status
            self.save_device(device)

    # Credential operations
    def list_credentials(self) -> List[Credential]:
        """List all credentials."""
        data = self._read_json(self.credentials_file)
        return [Credential(**c) for c in data]

    def get_credential(self, credential_id: str) -> Optional[Credential]:
        """Get credential by ID."""
        credentials = self.list_credentials()
        for cred in credentials:
            if cred.id == credential_id:
                return cred
        return None

    def get_default_credential(self) -> Optional[Credential]:
        """Get the default credential."""
        credentials = self.list_credentials()
        for cred in credentials:
            if cred.is_default:
                return cred
        return None

    def save_credential(self, username: str, password: str,
                       is_default: bool = False, description: str = None) -> Credential:
        """Save a new credential."""
        credentials = self._read_json(self.credentials_file)

        if is_default:
            for cred in credentials:
                cred['is_default'] = False

        new_cred = Credential(
            id=str(uuid.uuid4()),
            username=username,
            encrypted_password=encrypt_password(password),
            is_default=is_default,
            description=description
        )

        credentials.append(new_cred.model_dump())
        self._write_json(self.credentials_file, credentials)
        return new_cred

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential by ID."""
        credentials = self._read_json(self.credentials_file)
        initial_len = len(credentials)
        credentials = [c for c in credentials if c['id'] != credential_id]

        if len(credentials) < initial_len:
            self._write_json(self.credentials_file, credentials)
            return True
        return False

    def set_default_credential(self, credential_id: str) -> bool:
        """Set a credential as default."""
        credentials = self._read_json(self.credentials_file)
        found = False

        for cred in credentials:
            if cred['id'] == credential_id:
                cred['is_default'] = True
                found = True
            else:
                cred['is_default'] = False

        if found:
            self._write_json(self.credentials_file, credentials)
        return found

    def get_decrypted_password(self, credential_id: str) -> Optional[str]:
        """Get decrypted password for a credential."""
        cred = self.get_credential(credential_id)
        if cred:
            return decrypt_password(cred.encrypted_password)
        return None

    # Configuration operations
    def save_config(self, device_ip: str, raw_config: str,
                   parsed_data: Dict[str, Any] = None,
                   duration: float = None) -> ConfigSnapshot:
        """Save a configuration snapshot."""
        device_dir = self.configs_dir / device_ip.replace('.', '_')
        device_dir.mkdir(exist_ok=True)

        timestamp = datetime.now()
        filename = timestamp.strftime("%Y%m%d_%H%M%S")

        config_file = device_dir / f"{filename}.txt"
        config_file.write_text(raw_config, encoding='utf-8')

        snapshot = ConfigSnapshot(
            device_ip=device_ip,
            timestamp=timestamp,
            raw_config=raw_config,
            parsed_data=parsed_data,
            collection_duration=duration
        )

        meta_file = device_dir / f"{filename}_meta.json"
        with open(meta_file, 'w', encoding='utf-8') as f:
            json.dump(snapshot.model_dump(), f, indent=2, default=str)

        return snapshot

    def get_config_history(self, device_ip: str) -> List[ConfigSnapshot]:
        """Get configuration history for a device."""
        device_dir = self.configs_dir / device_ip.replace('.', '_')
        if not device_dir.exists():
            return []

        snapshots = []
        for meta_file in sorted(device_dir.glob("*_meta.json"), reverse=True):
            try:
                with open(meta_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'timestamp' in data and isinstance(data['timestamp'], str):
                        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                    snapshots.append(ConfigSnapshot(**data))
            except Exception:
                continue

        return snapshots

    def get_latest_config(self, device_ip: str) -> Optional[ConfigSnapshot]:
        """Get the latest configuration for a device."""
        history = self.get_config_history(device_ip)
        return history[0] if history else None

    def get_config_by_timestamp(self, device_ip: str, timestamp: datetime) -> Optional[ConfigSnapshot]:
        """Get a specific configuration by timestamp."""
        device_dir = self.configs_dir / device_ip.replace('.', '_')
        filename = timestamp.strftime("%Y%m%d_%H%M%S")
        meta_file = device_dir / f"{filename}_meta.json"

        if meta_file.exists():
            with open(meta_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'timestamp' in data and isinstance(data['timestamp'], str):
                    data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                return ConfigSnapshot(**data)
        return None

    # Device Group operations
    def list_groups(self) -> List[DeviceGroup]:
        """List all device groups."""
        data = self._read_json(self.groups_file)
        groups = []
        for g in data:
            if 'created_at' in g and isinstance(g['created_at'], str):
                g['created_at'] = datetime.fromisoformat(g['created_at'])
            if 'updated_at' in g and isinstance(g['updated_at'], str):
                g['updated_at'] = datetime.fromisoformat(g['updated_at'])
            groups.append(DeviceGroup(**g))
        return groups

    def get_group(self, group_id: str) -> Optional[DeviceGroup]:
        """Get a device group by ID."""
        groups = self.list_groups()
        for group in groups:
            if group.id == group_id:
                return group
        return None

    def save_group(self, group: DeviceGroup) -> DeviceGroup:
        """Save or update a device group."""
        groups = self._read_json(self.groups_file)

        existing_idx = None
        for i, g in enumerate(groups):
            if g['id'] == group.id:
                existing_idx = i
                break

        group.updated_at = datetime.now()
        group_dict = group.model_dump()

        if existing_idx is not None:
            groups[existing_idx] = group_dict
        else:
            groups.append(group_dict)

        self._write_json(self.groups_file, groups)
        return group

    def delete_group(self, group_id: str) -> bool:
        """Delete a device group by ID."""
        groups = self._read_json(self.groups_file)
        initial_len = len(groups)
        groups = [g for g in groups if g['id'] != group_id]

        if len(groups) < initial_len:
            self._write_json(self.groups_file, groups)
            return True
        return False

    def get_groups_for_device(self, device_ip: str) -> List[DeviceGroup]:
        """Get all groups that contain a specific device."""
        groups = self.list_groups()
        return [g for g in groups if device_ip in g.device_ips]

    def add_devices_to_group(self, group_id: str, device_ips: List[str]) -> Optional[DeviceGroup]:
        """Add devices to a group."""
        group = self.get_group(group_id)
        if not group:
            return None

        for ip in device_ips:
            if ip not in group.device_ips:
                group.device_ips.append(ip)

        return self.save_group(group)

    def remove_devices_from_group(self, group_id: str, device_ips: List[str]) -> Optional[DeviceGroup]:
        """Remove devices from a group."""
        group = self.get_group(group_id)
        if not group:
            return None

        group.device_ips = [ip for ip in group.device_ips if ip not in device_ips]
        return self.save_group(group)

    # User operations
    def list_users(self) -> List[User]:
        """List all users."""
        data = self._read_json(self.users_file)
        users = []
        for u in data:
            if 'created_at' in u and isinstance(u['created_at'], str):
                u['created_at'] = datetime.fromisoformat(u['created_at'])
            if 'last_login' in u and isinstance(u['last_login'], str):
                u['last_login'] = datetime.fromisoformat(u['last_login'])
            users.append(User(**u))
        return users

    def get_user(self, user_id: str) -> Optional[User]:
        """Get a user by ID."""
        users = self.list_users()
        for user in users:
            if user.id == user_id:
                return user
        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get a user by username."""
        users = self.list_users()
        for user in users:
            if user.username.lower() == username.lower():
                return user
        return None

    def save_user(self, user: User) -> User:
        """Save or update a user."""
        users = self._read_json(self.users_file)

        existing_idx = None
        for i, u in enumerate(users):
            if u['id'] == user.id:
                existing_idx = i
                break

        user_dict = user.model_dump()

        if existing_idx is not None:
            users[existing_idx] = user_dict
        else:
            users.append(user_dict)

        self._write_json(self.users_file, users)
        return user

    def delete_user(self, user_id: str) -> bool:
        """Delete a user by ID."""
        users = self._read_json(self.users_file)
        initial_len = len(users)
        users = [u for u in users if u['id'] != user_id]

        if len(users) < initial_len:
            self._write_json(self.users_file, users)
            return True
        return False

    def count_admin_users(self) -> int:
        """Count the number of admin users."""
        users = self.list_users()
        return sum(1 for u in users if u.role == 'admin' and u.is_active)

    def update_user_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp."""
        user = self.get_user(user_id)
        if user:
            user.last_login = datetime.now()
            self.save_user(user)

    # Auth Settings operations
    def get_auth_settings(self) -> AuthSettings:
        """Get authentication settings."""
        data = self._read_json(self.auth_settings_file)
        if isinstance(data, list):
            # Handle case where file was initialized as empty list
            return AuthSettings()
        return AuthSettings(**data)

    def save_auth_settings(self, settings: AuthSettings) -> AuthSettings:
        """Save authentication settings."""
        # Encrypt AD bind password if present
        settings_dict = settings.model_dump()
        if settings.ad_settings.bind_password:
            settings_dict['ad_settings']['bind_password'] = encrypt_password(
                settings.ad_settings.bind_password
            )
        self._write_json(self.auth_settings_file, settings_dict)
        return settings

    def get_decrypted_ad_bind_password(self) -> Optional[str]:
        """Get decrypted AD bind password."""
        settings = self.get_auth_settings()
        if settings.ad_settings.bind_password:
            try:
                return decrypt_password(settings.ad_settings.bind_password)
            except Exception:
                return settings.ad_settings.bind_password
        return None
