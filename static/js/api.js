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

    async addScannedDevices(devices) {
        return this.request('/scan/add-devices', {
            method: 'POST',
            body: { devices: devices },
        });
    },

    async startDiscovery(deviceIps = null, credentialId = null, addNeighbors = true, ipRange = null) {
        return this.request('/discover', {
            method: 'POST',
            body: {
                device_ips: deviceIps,
                ip_range: ipRange,
                credential_id: credentialId,
                add_neighbors: addNeighbors,
            },
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

    async batchCompare(referenceIp, targetIps) {
        return this.request('/compare/batch', {
            method: 'POST',
            body: {
                reference_ip: referenceIp,
                target_ips: targetIps,
            },
        });
    },

    async getComparisonReports() {
        return this.request('/compare/reports');
    },

    async getComparisonReport(reportId) {
        return this.request(`/compare/reports/${reportId}`);
    },

    // Log collection endpoints
    async collectLogs(deviceIps, credentialId = null) {
        return this.request('/logs/collect', {
            method: 'POST',
            body: {
                device_ips: deviceIps,
                credential_id: credentialId,
            },
        });
    },

    async getDeviceLogs(ip) {
        return this.request(`/logs/${ip}`);
    },

    async listCollectedLogs() {
        return this.request('/logs');
    },

    // MAC search endpoints
    async searchMac(macAddress, deviceIps = null, credentialId = null) {
        return this.request('/mac/search', {
            method: 'POST',
            body: {
                mac_address: macAddress,
                device_ips: deviceIps,
                credential_id: credentialId,
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

    // Device Group endpoints
    async getGroups() {
        return this.request('/groups');
    },

    async createGroup(name, description = null, color = null, deviceIps = []) {
        return this.request('/groups', {
            method: 'POST',
            body: {
                name,
                description,
                color,
                device_ips: deviceIps,
            },
        });
    },

    async getGroup(groupId) {
        return this.request(`/groups/${groupId}`);
    },

    async updateGroup(groupId, updates) {
        return this.request(`/groups/${groupId}`, {
            method: 'PUT',
            body: updates,
        });
    },

    async deleteGroup(groupId) {
        return this.request(`/groups/${groupId}`, {
            method: 'DELETE',
        });
    },

    async addDevicesToGroup(groupId, deviceIps) {
        return this.request(`/groups/${groupId}/devices`, {
            method: 'POST',
            body: { device_ips: deviceIps },
        });
    },

    async removeDevicesFromGroup(groupId, deviceIps) {
        return this.request(`/groups/${groupId}/devices`, {
            method: 'DELETE',
            body: { device_ips: deviceIps },
        });
    },

    async getDeviceGroups(deviceIp) {
        return this.request(`/devices/${deviceIp}/groups`);
    },
};

window.API = API;
