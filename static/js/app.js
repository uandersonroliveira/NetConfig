// Main application logic
document.addEventListener('DOMContentLoaded', () => {
    // Initialize WebSocket
    wsClient.connect();

    // State
    let currentPage = 'dashboard';
    let devices = [];
    let credentials = [];

    // DOM Elements
    const navLinks = document.querySelectorAll('.nav-menu a');
    const pageViews = document.querySelectorAll('.page-view');

    // Navigation
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            navigateTo(page);
        });
    });

    function navigateTo(page) {
        currentPage = page;

        navLinks.forEach(link => {
            link.classList.toggle('active', link.dataset.page === page);
        });

        pageViews.forEach(view => {
            view.classList.toggle('active', view.id === `page-${page}`);
        });

        loadPageData(page);
    }

    async function loadPageData(page) {
        switch (page) {
            case 'dashboard':
                await loadDashboard();
                break;
            case 'devices':
                await loadDevices();
                break;
            case 'credentials':
                await loadCredentials();
                break;
            case 'collect':
                await loadCredentials();
                await loadDevices();
                break;
            case 'compare':
                await loadDevices();
                updateCompareSelects();
                break;
        }
    }

    function updateCompareSelects() {
        const select1 = document.getElementById('compare-device1');
        const select2 = document.getElementById('compare-device2');
        if (select1 && select2) {
            const options = '<option value="">Select device...</option>' +
                devices.map(d => `<option value="${d.ip}">${d.hostname || d.ip}</option>`).join('');
            select1.innerHTML = options;
            select2.innerHTML = options;
        }
    }

    // Dashboard
    async function loadDashboard() {
        try {
            const stats = await API.getStats();
            document.getElementById('stat-total-devices').textContent = stats.total_devices;
            document.getElementById('stat-online').textContent = stats.status.online;
            document.getElementById('stat-offline').textContent = stats.status.offline;
            document.getElementById('stat-credentials').textContent = stats.credentials_count;
        } catch (error) {
            showToast('Failed to load dashboard stats', 'error');
        }
    }

    // Devices
    async function loadDevices() {
        try {
            const response = await API.getDevices();
            devices = response.devices;
            renderDevicesTable();
        } catch (error) {
            showToast('Failed to load devices', 'error');
        }
    }

    function renderDevicesTable() {
        const tbody = document.getElementById('devices-tbody');
        const selectAllCheckbox = document.getElementById('select-all-devices');

        if (selectAllCheckbox) {
            selectAllCheckbox.checked = false;
        }
        updateBulkDeleteButton();

        if (!devices.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <div class="empty-state-icon">&#128268;</div>
                        <p>No devices registered yet</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = devices.map(device => `
            <tr>
                <td>
                    <input type="checkbox" class="device-checkbox" value="${device.ip}" onchange="updateBulkDeleteButton()">
                </td>
                <td>${device.ip}</td>
                <td>${device.hostname || '-'}</td>
                <td><span class="badge badge-info">${device.vendor || 'unknown'}</span></td>
                <td>
                    <span class="badge ${getStatusBadgeClass(device.status)}">
                        ${device.status || 'unknown'}
                    </span>
                </td>
                <td>${device.model || '-'}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-secondary" onclick="viewDeviceConfig('${device.ip}')">
                            Config
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteDevice('${device.ip}')">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    function getStatusBadgeClass(status) {
        switch (status) {
            case 'online': return 'badge-success';
            case 'offline': return 'badge-danger';
            default: return 'badge-warning';
        }
    }

    // Credentials
    async function loadCredentials() {
        try {
            const response = await API.getCredentials();
            credentials = response.credentials;
            renderCredentialsTable();
            updateCredentialSelects();
        } catch (error) {
            showToast('Failed to load credentials', 'error');
        }
    }

    function renderCredentialsTable() {
        const tbody = document.getElementById('credentials-tbody');
        if (!credentials.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-state">
                        <div class="empty-state-icon">&#128274;</div>
                        <p>No credentials configured yet</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = credentials.map(cred => `
            <tr>
                <td>${cred.username}</td>
                <td>${cred.description || '-'}</td>
                <td>
                    ${cred.is_default ? '<span class="badge badge-success">Default</span>' : ''}
                </td>
                <td>${new Date(cred.created_at).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        ${!cred.is_default ? `
                            <button class="btn btn-sm btn-secondary" onclick="setDefaultCredential('${cred.id}')">
                                Set Default
                            </button>
                        ` : ''}
                        <button class="btn btn-sm btn-danger" onclick="deleteCredential('${cred.id}')">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    function updateCredentialSelects() {
        const selects = document.querySelectorAll('.credential-select');
        selects.forEach(select => {
            const currentValue = select.value;
            select.innerHTML = '<option value="">Use Default</option>' +
                credentials.map(c => `
                    <option value="${c.id}" ${c.is_default ? 'selected' : ''}>
                        ${c.username}${c.is_default ? ' (default)' : ''}
                    </option>
                `).join('');
            if (currentValue) select.value = currentValue;
        });
    }

    // Modal handling
    window.openModal = function(modalId) {
        document.getElementById(modalId).classList.add('active');
    };

    window.closeModal = function(modalId) {
        document.getElementById(modalId).classList.remove('active');
    };

    // Add device form
    document.getElementById('add-device-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const ipsText = formData.get('ips');
        const vendor = formData.get('vendor') || null;
        const credentialId = formData.get('credential_id') || null;

        try {
            const result = await API.addDevicesBulk(ipsText, vendor, credentialId);
            showToast(`Added ${result.added.length} devices`, 'success');
            closeModal('add-device-modal');
            e.target.reset();
            await loadDevices();
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    // Add credential form
    document.getElementById('add-credential-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        try {
            await API.addCredential(
                formData.get('username'),
                formData.get('password'),
                formData.get('is_default') === 'on',
                formData.get('description') || null
            );
            showToast('Credential added', 'success');
            closeModal('add-credential-modal');
            e.target.reset();
            await loadCredentials();
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    // Scan form
    document.getElementById('scan-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ipRange = document.getElementById('scan-ip-range').value;

        try {
            await API.startScan(ipRange);
            showToast('Scan started', 'info');
            showProgress('scan');
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    // Collect form
    document.getElementById('collect-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const selectedDevices = Array.from(document.querySelectorAll('.device-checkbox:checked'))
            .map(cb => cb.value);
        const credentialId = document.getElementById('collect-credential').value || null;

        try {
            await API.startCollection(
                selectedDevices.length ? selectedDevices : null,
                credentialId
            );
            showToast('Collection started', 'info');
            showProgress('collect');
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    // MAC search form
    document.getElementById('mac-search-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const macAddress = document.getElementById('mac-address').value;
        const useCache = document.getElementById('mac-use-cache').checked;

        try {
            const result = await API.searchMac(macAddress, useCache);
            renderMacResults(result);
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    function renderMacResults(result) {
        const container = document.getElementById('mac-results');
        if (!result.found) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>MAC address not found: ${result.mac_address}</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Switch</th>
                        <th>Port</th>
                        <th>VLAN</th>
                        <th>Vendor</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.results.map(r => `
                        <tr>
                            <td>${r.device_hostname} (${r.device_ip})</td>
                            <td>${r.interface}</td>
                            <td>${r.vlan}</td>
                            <td>${r.vendor}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    // Compare form
    document.getElementById('compare-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const device1 = document.getElementById('compare-device1').value;
        const device2 = document.getElementById('compare-device2').value;

        try {
            const result = await API.compareConfigs(device1, device2);
            renderCompareResults(result.comparison);
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    function renderCompareResults(comparison) {
        const container = document.getElementById('compare-results');
        const summary = comparison.summary;

        container.innerHTML = `
            <div class="card">
                <h4>Summary</h4>
                <p>Lines added: ${summary.lines_added} | Lines removed: ${summary.lines_removed}</p>
                <p>VLANs changed: ${summary.vlans_changed} | Interfaces changed: ${summary.interfaces_changed}</p>
            </div>
            <div class="diff-viewer">
                ${comparison.differences.map(diff => `
                    <div class="diff-line ${diff.type === 'added' ? 'diff-added' : ''}${diff.type === 'removed' ? 'diff-removed' : ''}">
                        ${diff.type === 'added' ? '+' : diff.type === 'removed' ? '-' : ' '} ${diff.content || JSON.stringify(diff)}
                    </div>
                `).join('')}
            </div>
        `;
    }

    // View device config
    window.viewDeviceConfig = async function(ip) {
        try {
            const config = await API.getLatestConfig(ip);
            document.getElementById('config-device-ip').textContent = ip;
            document.getElementById('config-viewer-content').textContent = config.raw_config;
            openModal('config-viewer-modal');
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Delete device
    window.deleteDevice = async function(ip) {
        if (!confirm(`Delete device ${ip}?`)) return;

        try {
            await API.deleteDevice(ip);
            showToast('Device deleted', 'success');
            await loadDevices();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Check device status
    window.checkDevicesStatus = async function() {
        try {
            await API.checkDevicesStatus();
            showToast('Status check started', 'info');
            showProgress('status_check');
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Collect all configs from devices page
    window.collectAllConfigs = async function() {
        try {
            const result = await API.startCollection(null, null);
            showToast('Collection started', 'info');
            showProgress('devices-collect');
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Toggle select all devices
    window.toggleSelectAll = function(checkbox) {
        const deviceCheckboxes = document.querySelectorAll('.device-checkbox');
        deviceCheckboxes.forEach(cb => {
            cb.checked = checkbox.checked;
        });
        updateBulkDeleteButton();
    };

    // Update bulk delete button visibility
    window.updateBulkDeleteButton = function() {
        const selectedCheckboxes = document.querySelectorAll('.device-checkbox:checked');
        const bulkDeleteBtn = document.getElementById('bulk-delete-btn');
        const selectedCount = document.getElementById('selected-count');

        if (bulkDeleteBtn && selectedCount) {
            const count = selectedCheckboxes.length;
            selectedCount.textContent = count;
            bulkDeleteBtn.style.display = count > 0 ? 'inline-flex' : 'none';
        }

        // Update select-all checkbox state
        const allCheckboxes = document.querySelectorAll('.device-checkbox');
        const selectAllCheckbox = document.getElementById('select-all-devices');
        if (selectAllCheckbox && allCheckboxes.length > 0) {
            selectAllCheckbox.checked = selectedCheckboxes.length === allCheckboxes.length;
            selectAllCheckbox.indeterminate = selectedCheckboxes.length > 0 && selectedCheckboxes.length < allCheckboxes.length;
        }
    };

    // Bulk delete devices
    window.bulkDeleteDevices = async function() {
        const selectedCheckboxes = document.querySelectorAll('.device-checkbox:checked');
        const selectedIps = Array.from(selectedCheckboxes).map(cb => cb.value);

        if (selectedIps.length === 0) {
            showToast('No devices selected', 'warning');
            return;
        }

        if (!confirm(`Delete ${selectedIps.length} device(s)?\n\n${selectedIps.join('\n')}`)) {
            return;
        }

        try {
            const result = await API.bulkDeleteDevices(selectedIps);
            showToast(`Deleted ${result.deleted.length} device(s)`, 'success');
            await loadDevices();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Set default credential
    window.setDefaultCredential = async function(id) {
        try {
            await API.setDefaultCredential(id);
            showToast('Default credential updated', 'success');
            await loadCredentials();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Delete credential
    window.deleteCredential = async function(id) {
        if (!confirm('Delete this credential?')) return;

        try {
            await API.deleteCredential(id);
            showToast('Credential deleted', 'success');
            await loadCredentials();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Progress handling
    function showProgress(taskType) {
        // Handle special cases
        if (taskType === 'devices-collect') {
            showProgressContainer('devices-collect-progress');
        } else {
            showProgressContainer(`${taskType}-progress`);
        }
    }

    function showProgressContainer(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.style.display = 'block';
            container.querySelector('.progress-bar-fill').style.width = '0%';
            container.querySelector('.progress-text span').textContent = 'Starting...';
        }
    }

    function hideProgress(taskType) {
        // Handle collect events on both pages
        if (taskType === 'collect') {
            hideProgressContainer('collect-progress');
            hideProgressContainer('devices-collect-progress');
        } else {
            hideProgressContainer(`${taskType}-progress`);
        }
    }

    function hideProgressContainer(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            setTimeout(() => {
                container.style.display = 'none';
            }, 2000);
        }
    }

    // WebSocket event handlers
    wsClient.on('progress', (data) => {
        // Handle collect events on both pages
        if (data.task_type === 'collect') {
            updateProgressContainer('collect-progress', data);
            updateProgressContainer('devices-collect-progress', data);
        } else {
            updateProgressContainer(`${data.task_type}-progress`, data);
        }
    });

    function updateProgressContainer(containerId, data) {
        const container = document.getElementById(containerId);
        if (container) {
            container.style.display = 'block';
            container.querySelector('.progress-bar-fill').style.width = `${data.percentage}%`;
            container.querySelector('.progress-text span').textContent = data.message;
        }
    }

    wsClient.on('complete', async (data) => {
        hideProgress(data.task_type);

        switch (data.task_type) {
            case 'scan':
                showToast(`Scan complete: ${data.results.devices_found} devices found`, 'success');
                await loadDevices();
                break;
            case 'collect':
                showToast(`Collection complete: ${data.results.success}/${data.results.total} successful`, 'success');
                await loadDevices();
                break;
            case 'status_check':
                showToast(`Status check complete: ${data.results.online} online, ${data.results.offline} offline`, 'success');
                await loadDevices();
                break;
            case 'mac_search':
                renderMacResults(data.results);
                break;
        }
    });

    wsClient.on('taskError', (data) => {
        hideProgress(data.task_type);
        showToast(data.error, 'error');
    });

    // Toast notifications
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 5000);
    }

    // Initial load
    navigateTo('dashboard');
});
