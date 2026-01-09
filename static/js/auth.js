/**
 * Authentication Client for NetConfig
 * Handles login, logout, token management, and session handling
 */

const Auth = {
    token: null,
    user: null,
    refreshTimer: null,

    /**
     * Initialize authentication from stored token
     */
    init() {
        this.token = localStorage.getItem('netconfig-token');
        const userJson = localStorage.getItem('netconfig-user');
        if (userJson) {
            try {
                this.user = JSON.parse(userJson);
            } catch (e) {
                this.user = null;
            }
        }

        if (this.token) {
            this.scheduleTokenRefresh();
        }
    },

    /**
     * Check if authentication is required
     */
    async checkAuthRequired() {
        try {
            const response = await fetch('/api/auth/check');
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error checking auth status:', error);
            return { auth_required: true, has_users: false, ad_enabled: false };
        }
    },

    /**
     * Login with username and password
     */
    async login(username, password, useAD = false) {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
                use_ad: useAD
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Login failed');
        }

        const data = await response.json();
        this.token = data.token;
        this.user = data.user;

        localStorage.setItem('netconfig-token', this.token);
        localStorage.setItem('netconfig-user', JSON.stringify(this.user));

        this.scheduleTokenRefresh();

        return data;
    },

    /**
     * Logout and clear session
     */
    async logout() {
        try {
            if (this.token) {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        }

        this.clearSession();
        window.location.reload();
    },

    /**
     * Clear local session data
     */
    clearSession() {
        this.token = null;
        this.user = null;
        localStorage.removeItem('netconfig-token');
        localStorage.removeItem('netconfig-user');

        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
    },

    /**
     * Refresh the access token
     */
    async refreshToken() {
        if (!this.token) return false;

        try {
            const response = await fetch('/api/auth/refresh', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                this.clearSession();
                return false;
            }

            const data = await response.json();
            this.token = data.token;
            this.user = data.user;

            localStorage.setItem('netconfig-token', this.token);
            localStorage.setItem('netconfig-user', JSON.stringify(this.user));

            this.scheduleTokenRefresh();
            return true;
        } catch (error) {
            console.error('Token refresh error:', error);
            this.clearSession();
            return false;
        }
    },

    /**
     * Schedule token refresh before expiration
     */
    scheduleTokenRefresh() {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
        }

        // Refresh 5 minutes before expiration (assuming 8 hour default)
        const refreshInterval = (8 * 60 - 5) * 60 * 1000; // 7h55m in ms

        this.refreshTimer = setTimeout(() => {
            this.refreshToken();
        }, refreshInterval);
    },

    /**
     * Load current user from server
     */
    async loadUser() {
        if (!this.token) return null;

        try {
            const response = await fetch('/api/auth/me', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                this.clearSession();
                return null;
            }

            this.user = await response.json();
            localStorage.setItem('netconfig-user', JSON.stringify(this.user));
            return this.user;
        } catch (error) {
            console.error('Load user error:', error);
            this.clearSession();
            return null;
        }
    },

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.token && !!this.user;
    },

    /**
     * Check if current user is admin
     */
    isAdmin() {
        return this.user?.role === 'admin';
    },

    /**
     * Check if current user is read-only
     */
    isReadOnly() {
        return this.user?.role === 'readonly';
    },

    /**
     * Get the current auth token
     */
    getToken() {
        return this.token;
    },

    /**
     * Get current user
     */
    getUser() {
        return this.user;
    },

    /**
     * Check if user must change password
     */
    mustChangePassword() {
        return this.user?.must_change_password === true;
    },

    /**
     * Change password for current user
     */
    async changePassword(currentPassword, newPassword) {
        if (!this.user) throw new Error('Not authenticated');

        const response = await fetch(`/api/users/${this.user.id}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Password change failed');
        }

        // Update user to reflect password changed
        this.user.must_change_password = false;
        localStorage.setItem('netconfig-user', JSON.stringify(this.user));

        return await response.json();
    }
};

/**
 * User Management API
 */
const UserAPI = {
    /**
     * List all users (admin only)
     */
    async list() {
        const response = await fetch('/api/users', {
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to list users');
        }

        return await response.json();
    },

    /**
     * Create a new user (admin only)
     */
    async create(userData) {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Auth.getToken()}`
            },
            body: JSON.stringify(userData)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to create user');
        }

        return await response.json();
    },

    /**
     * Update a user (admin only)
     */
    async update(userId, updates) {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Auth.getToken()}`
            },
            body: JSON.stringify(updates)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to update user');
        }

        return await response.json();
    },

    /**
     * Delete a user (admin only)
     */
    async delete(userId) {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to delete user');
        }

        return await response.json();
    },

    /**
     * Toggle user active status (admin only)
     */
    async toggleActive(userId) {
        const response = await fetch(`/api/users/${userId}/toggle-active`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to toggle user status');
        }

        return await response.json();
    },

    /**
     * Change user password (admin or self)
     */
    async changePassword(userId, currentPassword, newPassword) {
        const response = await fetch(`/api/users/${userId}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Auth.getToken()}`
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to change password');
        }

        return await response.json();
    }
};

/**
 * Auth Settings API (admin only)
 */
const AuthSettingsAPI = {
    /**
     * Get authentication settings
     */
    async get() {
        const response = await fetch('/api/auth/settings', {
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to get auth settings');
        }

        return await response.json();
    },

    /**
     * Update authentication settings
     */
    async update(settings) {
        const response = await fetch('/api/auth/settings', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Auth.getToken()}`
            },
            body: JSON.stringify(settings)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to update auth settings');
        }

        return await response.json();
    },

    /**
     * Test Active Directory connection
     */
    async testAD(settings) {
        const response = await fetch('/api/auth/ad/test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Auth.getToken()}`
            },
            body: JSON.stringify(settings)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'AD test failed');
        }

        return await response.json();
    }
};

/**
 * Backup API (admin only)
 */
const BackupAPI = {
    /**
     * Get backup info
     */
    async getInfo() {
        const response = await fetch('/api/backup/list', {
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to get backup info');
        }

        return await response.json();
    },

    /**
     * Download config backup
     */
    async downloadConfig() {
        const response = await fetch('/api/backup/config', {
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to download config backup');
        }

        const blob = await response.blob();
        const filename = response.headers.get('Content-Disposition')
            ?.match(/filename=(.+)/)?.[1] || 'netconfig_config_backup.json';

        this._downloadBlob(blob, filename);
    },

    /**
     * Download full data backup
     */
    async downloadData() {
        const response = await fetch('/api/backup/data', {
            headers: {
                'Authorization': `Bearer ${Auth.getToken()}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to download data backup');
        }

        const blob = await response.blob();
        const filename = response.headers.get('Content-Disposition')
            ?.match(/filename=(.+)/)?.[1] || 'netconfig_full_backup.zip';

        this._downloadBlob(blob, filename);
    },

    /**
     * Helper to download blob as file
     */
    _downloadBlob(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }
};

// Export for use in other modules
window.Auth = Auth;
window.UserAPI = UserAPI;
window.AuthSettingsAPI = AuthSettingsAPI;
window.BackupAPI = BackupAPI;
