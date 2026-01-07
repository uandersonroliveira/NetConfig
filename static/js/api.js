// API Client for NetConfig
const API = {
    baseUrl: '/api',

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
            },
            ...options,
        };

        if (config.body && typeof config.body === 'object') {
            config.body = JSON.stringify(config.body);
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    // Device endpoints
    async getDevices() {
        return this.request('/devices');
    },

    async addDevice(device) {
        return this.request('/devices', {
            method: 'POST',
            body: device,
        });
    },

    async addDevicesBulk(ipsText, vendor = null, credentialId = null) {
        return this.request('/devices/bulk', {
            method: 'POST',
            body: {
                ips_text: ipsText,
                vendor: vendor,
                credential_id: credentialId,
            },
        });
    },

    async getDevice(ip) {
        return this.request(`/devices/${ip}`);
    },

    async updateDevice(ip, updates) {
        return this.request(`/devices/${ip}`, {
            method: 'PUT',
            body: updates,
        });
    },

    async deleteDevice(ip) {
        return this.request(`/devices/${ip}`, {
            method: 'DELETE',
        });
    },

    async bulkDeleteDevices(deviceIps) {
        return this.request('/devices/bulk-delete', {
            method: 'POST',
            body: {
                device_ips: deviceIps,
            },
        });
    },

    async checkDevicesStatus(deviceIps = null) {
        return this.request('/devices/check-status', {
            method: 'POST',
            body: {
                device_ips: deviceIps,
            },
        });
    },

    // Scan endpoints
    async startScan(ipRange) {
        return this.request('/scan', {
            method: 'POST',
            body: { ip_range: ipRange },
        });
    },

    // Collection endpoints
    async startCollection(deviceIps = null, credentialId = null) {
        return this.request('/collect', {
            method: 'POST',
            body: {
                device_ips: deviceIps,
                credential_id: credentialId,
            },
        });
    },

    // Config endpoints
    async getConfigHistory(ip) {
        return this.request(`/configs/${ip}`);
    },

    async getLatestConfig(ip) {
        return this.request(`/configs/${ip}/latest`);
    },

    async compareConfigs(device1Ip, device2Ip, timestamp1 = null, timestamp2 = null) {
        return this.request('/compare', {
            method: 'POST',
            body: {
                device1_ip: device1Ip,
                device2_ip: device2Ip,
                timestamp1: timestamp1,
                timestamp2: timestamp2,
            },
        });
    },

    // MAC search endpoints
    async searchMac(macAddress, useCache = true) {
        return this.request(`/mac/${encodeURIComponent(macAddress)}?use_cache=${useCache}`);
    },

    async searchMacLive(macAddress) {
        return this.request('/mac/search', {
            method: 'POST',
            body: {
                mac_address: macAddress,
                use_cache: false,
            },
        });
    },

    // Credential endpoints
    async getCredentials() {
        return this.request('/credentials');
    },

    async addCredential(username, password, isDefault = false, description = null) {
        return this.request('/credentials', {
            method: 'POST',
            body: {
                username,
                password,
                is_default: isDefault,
                description,
            },
        });
    },

    async setDefaultCredential(credentialId) {
        return this.request(`/credentials/${credentialId}/default`, {
            method: 'PUT',
        });
    },

    async deleteCredential(credentialId) {
        return this.request(`/credentials/${credentialId}`, {
            method: 'DELETE',
        });
    },

    // Stats endpoint
    async getStats() {
        return this.request('/stats');
    },
};

window.API = API;
