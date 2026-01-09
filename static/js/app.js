// Main application logic
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize i18n first
    await I18n.init();

    // Initialize authentication
    Auth.init();

    // State
    let currentPage = 'dashboard';
    let devices = [];
    let credentials = [];
    let lastComparisonReportId = null;
    let users = [];
    let authStatus = null;

    // Check auth and initialize app after all functions are defined
    async function initializeApp() {
        authStatus = await Auth.checkAuthRequired();

        if (authStatus.auth_required) {
            if (!Auth.isAuthenticated()) {
                showLoginPage(authStatus.ad_enabled);
                return;
            }

            // Check if password change is required
            if (Auth.mustChangePassword()) {
                showForcePasswordChangeModal();
                return;
            }
        }

        // Show app container if authenticated
        showAppContainer();

        // Initialize WebSocket
        wsClient.connect();

        // Navigate to dashboard
        navigateTo('dashboard');
    }

    // DOM Elements
    const navLinks = document.querySelectorAll('.nav-menu a[data-page]');
    const pageViews = document.querySelectorAll('.page-view');
    const submenuToggles = document.querySelectorAll('.nav-submenu-toggle');

    // Submenu toggle
    submenuToggles.forEach(toggle => {
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            const submenu = toggle.closest('.nav-submenu');
            submenu.classList.toggle('open');
        });
    });

    // Navigation
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            if (page) {
                navigateTo(page);
            }
        });
    });

    function navigateTo(page) {
        currentPage = page;

        // Update active states for nav links
        navLinks.forEach(link => {
            link.classList.toggle('active', link.dataset.page === page);
        });

        // Update submenu states
        document.querySelectorAll('.nav-submenu').forEach(submenu => {
            const hasActiveChild = submenu.querySelector(`a[data-page="${page}"]`);
            submenu.classList.toggle('has-active', !!hasActiveChild);
            if (hasActiveChild) {
                submenu.classList.add('open');
            }
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
                await loadCredentials();
                break;
            case 'devices':
                await loadDevices();
                await loadCredentials();
                break;
            case 'credentials':
                await loadCredentials();
                break;
            case 'collect':
                await loadCredentials();
                await loadDevices();
                initCollectPageDeviceList();
                break;
            case 'compare':
                await loadDevices();
                updateCompareReferenceSelect();
                break;
            case 'scan':
                await loadCredentials();
                break;
            case 'reports':
                await loadComparisonReports();
                break;
            case 'logs':
                await loadDevices();
                await loadCredentials();
                initLogsDeviceList();
                break;
            case 'mac-search':
                await loadDevices();
                await loadCredentials();
                initMacSearchDeviceList();
                break;
            case 'users':
                await loadUsers();
                break;
            case 'ad-settings':
                await loadADSettings();
                break;
            case 'backup':
                await loadBackupInfo();
                break;
        }
    }

    // ==================== AUTHENTICATION ====================

    function showLoginPage(adEnabled) {
        document.getElementById('login-page').style.display = 'flex';
        document.querySelector('.app-container').style.display = 'none';

        if (adEnabled) {
            document.getElementById('ad-login-option').style.display = 'block';
        }

        // Set up login form handler
        document.getElementById('login-form').addEventListener('submit', handleLogin);
    }

    function showAppContainer() {
        document.getElementById('login-page').style.display = 'none';
        document.querySelector('.app-container').style.display = 'flex';

        // Update user info in sidebar
        updateSidebarUserInfo();

        // Hide admin-only elements for non-admin users
        applyRoleBasedUI();
    }

    function updateSidebarUserInfo() {
        const user = Auth.getUser();
        if (user) {
            document.getElementById('sidebar-username').textContent = user.username;
            document.getElementById('sidebar-role').textContent = user.role;
            document.getElementById('sidebar-role').className = `user-role badge ${user.role === 'admin' ? 'badge-success' : 'badge-info'}`;
        }
    }

    function applyRoleBasedUI() {
        const isAdmin = Auth.isAdmin();

        // Hide admin-only elements
        document.querySelectorAll('[data-admin-only]').forEach(el => {
            el.style.display = isAdmin ? '' : 'none';
        });

        // Hide write buttons for read-only users
        if (Auth.isReadOnly()) {
            document.querySelectorAll('.btn-primary:not([data-always-show])').forEach(btn => {
                if (btn.closest('[data-admin-only]')) return;
                btn.style.display = 'none';
            });
        }
    }

    async function handleLogin(e) {
        e.preventDefault();

        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        const useAD = document.getElementById('login-use-ad')?.checked || false;
        const errorDiv = document.getElementById('login-error');
        const button = e.target.querySelector('button[type="submit"]');

        errorDiv.style.display = 'none';
        button.disabled = true;
        button.textContent = I18n.t('common.loggingIn') || 'Logging in...';

        try {
            await Auth.login(username, password, useAD);

            // Check if password change is required
            if (Auth.mustChangePassword()) {
                showForcePasswordChangeModal();
            } else {
                showAppContainer();
                wsClient.connect();
                navigateTo('dashboard');
            }
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
        } finally {
            button.disabled = false;
            button.textContent = I18n.t('login.loginButton') || 'Login';
        }
    }

    function showForcePasswordChangeModal() {
        document.getElementById('login-page').style.display = 'none';
        document.getElementById('force-password-change-modal').style.display = 'flex';

        document.getElementById('force-password-change-form').addEventListener('submit', handleForcePasswordChange);
    }

    async function handleForcePasswordChange(e) {
        e.preventDefault();

        const currentPassword = document.getElementById('force-current-password').value;
        const newPassword = document.getElementById('force-new-password').value;
        const confirmPassword = document.getElementById('force-confirm-password').value;
        const errorDiv = document.getElementById('force-password-error');
        const button = e.target.querySelector('button[type="submit"]');

        errorDiv.style.display = 'none';

        if (newPassword !== confirmPassword) {
            errorDiv.textContent = I18n.t('users.passwordMismatch') || 'Passwords do not match';
            errorDiv.style.display = 'block';
            return;
        }

        if (newPassword.length < 8) {
            errorDiv.textContent = I18n.t('users.passwordTooShort') || 'Password must be at least 8 characters';
            errorDiv.style.display = 'block';
            return;
        }

        button.disabled = true;
        button.textContent = I18n.t('common.changing') || 'Changing...';

        try {
            await Auth.changePassword(currentPassword, newPassword);
            document.getElementById('force-password-change-modal').style.display = 'none';
            showAppContainer();
            wsClient.connect();
            navigateTo('dashboard');
            showToast(I18n.t('toast.passwordChanged') || 'Password changed successfully', 'success');
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
        } finally {
            button.disabled = false;
            button.textContent = I18n.t('users.changePassword') || 'Change Password';
        }
    }

    // ==================== USERS MANAGEMENT ====================

    async function loadUsers() {
        if (!Auth.isAdmin()) return;

        try {
            users = await UserAPI.list();
            renderUsersTable();
        } catch (error) {
            showToast(I18n.t('toast.error.loadUsers') || 'Failed to load users', 'error');
        }
    }

    function renderUsersTable() {
        const tbody = document.getElementById('users-tbody');
        if (!tbody) return;

        if (!users || users.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <div class="empty-state-icon">&#128101;</div>
                        <p>No users found</p>
                    </td>
                </tr>
            `;
            return;
        }

        const currentUserId = Auth.getUser()?.id;

        tbody.innerHTML = users.map(user => `
            <tr data-user-id="${user.id}">
                <td>${escapeHtml(user.username)}</td>
                <td>
                    <span class="badge ${user.role === 'admin' ? 'badge-success' : 'badge-info'}">
                        ${user.role === 'admin' ? I18n.t('users.admin') || 'Admin' : I18n.t('users.readonly') || 'Read-only'}
                    </span>
                </td>
                <td>
                    <span class="badge ${user.auth_type === 'ad' ? 'badge-warning' : 'badge-info'}">
                        ${user.auth_type === 'ad' ? I18n.t('users.ad') || 'AD' : I18n.t('users.local') || 'Local'}
                    </span>
                </td>
                <td>${user.email || '-'}</td>
                <td>${user.last_login ? new Date(user.last_login).toLocaleString() : I18n.t('users.never') || 'Never'}</td>
                <td>
                    <span class="badge ${user.is_active ? 'badge-success' : 'badge-danger'}">
                        ${user.is_active ? I18n.t('users.active') || 'Active' : I18n.t('users.inactive') || 'Inactive'}
                    </span>
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-secondary" onclick="openEditUserModal('${user.id}')">
                            ${I18n.t('common.edit') || 'Edit'}
                        </button>
                        ${user.auth_type !== 'ad' ? `
                            <button class="btn btn-sm btn-secondary" onclick="openChangePasswordModal('${user.id}')">
                                ${I18n.t('users.changePassword') || 'Password'}
                            </button>
                        ` : ''}
                        ${user.id !== currentUserId ? `
                            <button class="btn btn-sm ${user.is_active ? 'btn-warning' : 'btn-success'}" onclick="toggleUserActive('${user.id}')">
                                ${user.is_active ? I18n.t('users.deactivate') || 'Deactivate' : I18n.t('users.activate') || 'Activate'}
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.id}')">
                                ${I18n.t('common.delete') || 'Delete'}
                            </button>
                        ` : ''}
                    </div>
                </td>
            </tr>
        `).join('');
    }

    // User form handlers
    document.getElementById('add-user-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const userData = {
            username: document.getElementById('user-username').value,
            password: document.getElementById('user-password').value,
            email: document.getElementById('user-email').value || null,
            role: document.getElementById('user-role').value
        };

        try {
            await UserAPI.create(userData);
            showToast(I18n.t('toast.userCreated') || 'User created successfully', 'success');
            closeModal('add-user-modal');
            e.target.reset();
            await loadUsers();
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    document.getElementById('edit-user-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const userId = document.getElementById('edit-user-id').value;
        const updates = {
            username: document.getElementById('edit-user-username').value,
            email: document.getElementById('edit-user-email').value || null,
            role: document.getElementById('edit-user-role').value
        };

        try {
            await UserAPI.update(userId, updates);
            showToast(I18n.t('toast.userUpdated') || 'User updated successfully', 'success');
            closeModal('edit-user-modal');
            await loadUsers();
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    document.getElementById('change-password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const userId = document.getElementById('change-password-user-id').value;
        const currentPassword = document.getElementById('change-current-password').value;
        const newPassword = document.getElementById('change-new-password').value;
        const confirmPassword = document.getElementById('change-confirm-password').value;

        if (newPassword !== confirmPassword) {
            showToast(I18n.t('users.passwordMismatch') || 'Passwords do not match', 'error');
            return;
        }

        try {
            await UserAPI.changePassword(userId, currentPassword || null, newPassword);
            showToast(I18n.t('toast.passwordChanged') || 'Password changed successfully', 'success');
            closeModal('change-password-modal');
            e.target.reset();
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    window.openEditUserModal = function(userId) {
        const user = users.find(u => u.id === userId);
        if (!user) return;

        document.getElementById('edit-user-id').value = user.id;
        document.getElementById('edit-user-username').value = user.username;
        document.getElementById('edit-user-email').value = user.email || '';
        document.getElementById('edit-user-role').value = user.role;

        openModal('edit-user-modal');
    };

    window.openChangePasswordModal = function(userId) {
        const user = users.find(u => u.id === userId);
        if (!user) return;

        document.getElementById('change-password-user-id').value = userId;
        document.getElementById('change-current-password').value = '';
        document.getElementById('change-new-password').value = '';
        document.getElementById('change-confirm-password').value = '';

        // Show current password field only if changing own password
        const currentPasswordGroup = document.getElementById('current-password-group');
        const currentUserId = Auth.getUser()?.id;
        currentPasswordGroup.style.display = (userId === currentUserId) ? 'block' : 'none';
        document.getElementById('change-current-password').required = (userId === currentUserId);

        openModal('change-password-modal');
    };

    window.toggleUserActive = async function(userId) {
        try {
            await UserAPI.toggleActive(userId);
            showToast(I18n.t('toast.userStatusChanged') || 'User status changed', 'success');
            await loadUsers();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    window.deleteUser = async function(userId) {
        if (!confirm(I18n.t('confirm.deleteUser') || 'Are you sure you want to delete this user?')) return;

        try {
            await UserAPI.delete(userId);
            showToast(I18n.t('toast.userDeleted') || 'User deleted', 'success');
            await loadUsers();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // ==================== AD SETTINGS ====================

    async function loadADSettings() {
        if (!Auth.isAdmin()) return;

        try {
            const settings = await AuthSettingsAPI.get();
            populateADSettingsForm(settings);
        } catch (error) {
            showToast(I18n.t('toast.error.loadADSettings') || 'Failed to load AD settings', 'error');
        }
    }

    function populateADSettingsForm(settings) {
        document.getElementById('ad-enabled').checked = settings.ad_enabled || false;
        document.getElementById('ad-settings-fields').style.display = settings.ad_enabled ? 'block' : 'none';

        if (settings.ad_settings) {
            const ad = settings.ad_settings;
            document.getElementById('ad-server').value = ad.server || '';
            document.getElementById('ad-port').value = ad.port || 389;
            document.getElementById('ad-use-ssl').checked = ad.use_ssl || false;
            document.getElementById('ad-base-dn').value = ad.base_dn || '';
            document.getElementById('ad-user-dn-pattern').value = ad.user_dn_pattern || '';
            document.getElementById('ad-admin-group').value = ad.admin_group || '';
            document.getElementById('ad-readonly-group').value = ad.readonly_group || '';
            document.getElementById('ad-bind-user').value = ad.bind_user || '';
            document.getElementById('ad-bind-password').value = ad.bind_password || '';
        }
    }

    // Toggle AD settings fields visibility
    document.getElementById('ad-enabled')?.addEventListener('change', function() {
        document.getElementById('ad-settings-fields').style.display = this.checked ? 'block' : 'none';
    });

    // AD settings form submission
    document.getElementById('ad-settings-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const settings = {
            ad_enabled: document.getElementById('ad-enabled').checked,
            ad_settings: {
                server: document.getElementById('ad-server').value,
                port: parseInt(document.getElementById('ad-port').value) || 389,
                use_ssl: document.getElementById('ad-use-ssl').checked,
                base_dn: document.getElementById('ad-base-dn').value,
                user_dn_pattern: document.getElementById('ad-user-dn-pattern').value,
                admin_group: document.getElementById('ad-admin-group').value,
                readonly_group: document.getElementById('ad-readonly-group').value,
                bind_user: document.getElementById('ad-bind-user').value,
                bind_password: document.getElementById('ad-bind-password').value
            }
        };

        try {
            await AuthSettingsAPI.update(settings);
            showToast(I18n.t('toast.adSettingsSaved') || 'AD settings saved', 'success');
        } catch (error) {
            showToast(error.message, 'error');
        }
    });

    window.testADConnection = async function() {
        const resultDiv = document.getElementById('ad-test-result');
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '<span class="spinner"></span> Testing connection...';
        resultDiv.className = '';

        const settings = {
            ad_settings: {
                server: document.getElementById('ad-server').value,
                port: parseInt(document.getElementById('ad-port').value) || 389,
                use_ssl: document.getElementById('ad-use-ssl').checked,
                base_dn: document.getElementById('ad-base-dn').value,
                user_dn_pattern: document.getElementById('ad-user-dn-pattern').value,
                bind_user: document.getElementById('ad-bind-user').value,
                bind_password: document.getElementById('ad-bind-password').value
            }
        };

        try {
            const result = await AuthSettingsAPI.testAD(settings);
            if (result.success) {
                resultDiv.innerHTML = `<span style="color: var(--success-color);">&#10003;</span> ${result.message}`;
            } else {
                resultDiv.innerHTML = `<span style="color: var(--danger-color);">&#10007;</span> ${result.message}`;
            }
        } catch (error) {
            resultDiv.innerHTML = `<span style="color: var(--danger-color);">&#10007;</span> ${error.message}`;
        }
    };

    // ==================== BACKUP ====================

    async function loadBackupInfo() {
        if (!Auth.isAdmin()) return;

        try {
            const info = await BackupAPI.getInfo();
            renderBackupInfo(info);
        } catch (error) {
            document.getElementById('backup-info').innerHTML = '<p class="empty-state">Failed to load backup information</p>';
        }
    }

    function renderBackupInfo(info) {
        const container = document.getElementById('backup-info');
        if (!container) return;

        let html = '<div class="table-container"><table><thead><tr><th>File</th><th>Size</th><th>Last Modified</th></tr></thead><tbody>';

        // Config files
        info.config_files.forEach(f => {
            html += `<tr><td>${f.name}</td><td>${formatFileSize(f.size)}</td><td>${new Date(f.modified).toLocaleString()}</td></tr>`;
        });

        // Data files
        info.data_files.forEach(f => {
            html += `<tr><td>${f.name}</td><td>${formatFileSize(f.size)}</td><td>${new Date(f.modified).toLocaleString()}</td></tr>`;
        });

        html += '</tbody></table></div>';

        if (info.device_configs_count !== undefined) {
            html += `<p style="margin-top: 1rem; color: var(--text-muted);">Device configurations: ${info.device_configs_count} file(s)</p>`;
        }

        container.innerHTML = html;
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function updateCompareReferenceSelect() {
        const select = document.getElementById('compare-reference');
        if (select) {
            const options = '<option value="">Select reference device...</option>' +
                devices.map(d => `<option value="${d.ip}">${d.hostname || d.ip} (${d.ip})</option>`).join('');
            select.innerHTML = options;

            // Add change listener
            select.onchange = function() {
                updateCompareTargetsList(this.value);
            };
        }
        // Reset targets list
        updateCompareTargetsList(null);
    }

    function updateCompareTargetsList(referenceIp) {
        const container = document.getElementById('compare-targets-list');
        const startBtn = document.getElementById('start-compare-btn');
        const countSpan = document.getElementById('compare-selected-count');

        if (!container) return;

        if (!referenceIp) {
            container.innerHTML = `<p class="empty-state" style="padding: 1rem;">${I18n.t('compare.selectReferenceFirst') || 'Select a reference device first'}</p>`;
            if (startBtn) startBtn.disabled = true;
            if (countSpan) countSpan.textContent = I18n.t('common.selected', { count: 0 }) || '0 selected';
            return;
        }

        const targetDevices = devices.filter(d => d.ip !== referenceIp);

        if (targetDevices.length === 0) {
            container.innerHTML = `<p class="empty-state" style="padding: 1rem;">${I18n.t('compare.noOtherDevices') || 'No other devices available for comparison'}</p>`;
            if (startBtn) startBtn.disabled = true;
            if (countSpan) countSpan.textContent = I18n.t('common.selected', { count: 0 }) || '0 selected';
            return;
        }

        container.innerHTML = targetDevices.map(d => `
            <div style="padding: 0.5rem; border-bottom: 1px solid var(--border-color);">
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input type="checkbox" class="compare-target-checkbox" value="${d.ip}" onchange="updateCompareSelectedCount()">
                    <span>${d.hostname || d.ip}</span>
                    <span style="color: var(--text-muted); font-size: 0.85em;">(${d.ip})</span>
                    <span class="badge ${getStatusBadgeClass(d.status)}" style="margin-left: auto;">${d.status || 'unknown'}</span>
                </label>
            </div>
        `).join('');

        updateCompareSelectedCount();
    }

    window.updateCompareSelectedCount = function() {
        const checkboxes = document.querySelectorAll('.compare-target-checkbox:checked');
        const countSpan = document.getElementById('compare-selected-count');
        const startBtn = document.getElementById('start-compare-btn');

        if (countSpan) countSpan.textContent = `${checkboxes.length} selected`;
        if (startBtn) startBtn.disabled = checkboxes.length === 0;
    };

    window.selectAllCompareTargets = function(selectAll) {
        const checkboxes = document.querySelectorAll('.compare-target-checkbox');
        checkboxes.forEach(cb => cb.checked = selectAll);
        updateCompareSelectedCount();
    };

    window.filterCompareTargets = function(searchTerm) {
        const items = document.querySelectorAll('#compare-targets-list .device-selection-item');
        const term = searchTerm.toLowerCase().trim();

        items.forEach(item => {
            const ip = item.querySelector('.device-selection-ip')?.textContent.toLowerCase() || '';
            const hostname = item.querySelector('.device-selection-hostname')?.textContent.toLowerCase() || '';
            const vendor = item.querySelector('.badge')?.textContent.toLowerCase() || '';

            const matches = term === '' || ip.includes(term) || hostname.includes(term) || vendor.includes(term);
            item.style.display = matches ? '' : 'none';
        });
    };

    window.selectFilteredCompareTargets = function() {
        const items = document.querySelectorAll('#compare-targets-list .device-selection-item');
        items.forEach(item => {
            if (item.style.display !== 'none') {
                const checkbox = item.querySelector('.compare-target-checkbox');
                if (checkbox) checkbox.checked = true;
            }
        });
        updateCompareSelectedCount();
    };

    window.startBatchComparison = async function() {
        const referenceIp = document.getElementById('compare-reference').value;
        const targetCheckboxes = document.querySelectorAll('.compare-target-checkbox:checked');
        const targetIps = Array.from(targetCheckboxes).map(cb => cb.value);
        const button = document.getElementById('start-compare-btn');

        if (!referenceIp) {
            showToast(I18n.t('toast.selectReferenceDevice'), 'warning');
            return;
        }

        if (targetIps.length === 0) {
            showToast(I18n.t('toast.selectTargetDevices'), 'warning');
            return;
        }

        setButtonLoading(button, true, I18n.t('common.comparing') || 'Comparing...');

        try {
            await API.batchCompare(referenceIp, targetIps);
            showToast(I18n.t('toast.comparisonStarted') || 'Comparison started', 'info');
            showProgress('compare');

            // Hide complete section while comparison runs
            const completeSection = document.getElementById('compare-complete');
            if (completeSection) completeSection.style.display = 'none';
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    };

    window.viewComparisonReport = function() {
        if (lastComparisonReportId) {
            // Navigate to reports page and show the specific report
            navigateTo('reports');
            setTimeout(() => viewReportDetails(lastComparisonReportId), 100);
        }
    };

    async function loadComparisonReports() {
        try {
            const response = await API.getComparisonReports();
            renderComparisonReportsList(response.reports);
        } catch (error) {
            showToast(I18n.t('toast.error.loadReports'), 'error');
        }
    }

    function renderComparisonReportsList(reports) {
        const container = document.getElementById('comparison-reports-list');
        if (!container) return;

        if (!reports || reports.length === 0) {
            container.innerHTML = '<p class="empty-state">No comparison reports yet. Run a comparison from the Compare page.</p>';
            return;
        }

        container.innerHTML = `
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Reference</th>
                            <th>Targets</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${reports.map(report => `
                            <tr>
                                <td>${new Date(report.timestamp).toLocaleString()}</td>
                                <td>${report.reference_ip}</td>
                                <td>${report.total_targets} device(s)</td>
                                <td>
                                    <button class="btn btn-sm btn-primary" onclick="viewReportDetails('${report.id}')">
                                        View Details
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    window.viewReportDetails = async function(reportId) {
        try {
            const response = await API.getComparisonReport(reportId);
            renderReportDetails(response.report);
        } catch (error) {
            showToast(I18n.t('reports.failedToLoadDetails') || 'Failed to load report details', 'error');
        }
    };

    function renderReportDetails(report) {
        const container = document.getElementById('comparison-reports-list');
        if (!container) return;

        const resultsHtml = report.results.map(r => {
            if (!r.success) {
                return `
                    <div class="card" style="margin-top: 1rem;">
                        <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <span class="card-title">${r.target_ip}</span>
                            <span class="badge badge-danger">${I18n.t('status.failed') || 'Failed'}</span>
                        </div>
                        <div style="padding: 0.75rem; color: var(--danger-color);">
                            ${r.error || I18n.t('common.unknownError') || 'Unknown error'}
                        </div>
                    </div>
                `;
            }

            const hasDifferences = r.summary && (r.summary.lines_added > 0 || r.summary.lines_removed > 0);

            return `
                <div class="card" style="margin-top: 1rem;">
                    <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="card-title">${r.target_hostname || r.target_ip}</span>
                        <span class="badge ${hasDifferences ? 'badge-warning' : 'badge-success'}">
                            ${hasDifferences ? I18n.t('common.differences', { count: r.summary.lines_added + r.summary.lines_removed }) || `${r.summary.lines_added + r.summary.lines_removed} differences` : I18n.t('common.identical') || 'Identical'}
                        </span>
                    </div>
                    ${hasDifferences && r.summary ? `
                        <div style="padding: 0.75rem;">
                            <p><strong>${I18n.t('compare.linesAdded') || 'Lines added:'}</strong> ${r.summary.lines_added} | <strong>${I18n.t('compare.linesRemoved') || 'Lines removed:'}</strong> ${r.summary.lines_removed}</p>
                            ${r.differences && r.differences.length > 0 ? `
                                <details style="margin-top: 0.5rem;">
                                    <summary style="cursor: pointer; color: var(--primary-color);">${I18n.t('compare.showDifferences') || 'Show differences'}</summary>
                                    <div class="diff-viewer" style="margin-top: 0.5rem; max-height: 300px; overflow-y: auto;">
                                        ${r.differences.map(diff => `
                                            <div class="diff-line ${diff.type === 'added' ? 'diff-added' : ''}${diff.type === 'removed' ? 'diff-removed' : ''}">
                                                ${diff.type === 'added' ? '+' : diff.type === 'removed' ? '-' : ' '} ${diff.content || diff.line || ''}
                                            </div>
                                        `).join('')}
                                    </div>
                                </details>
                            ` : ''}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');

        container.innerHTML = `
            <div style="margin-bottom: 1rem;">
                <button class="btn btn-secondary" onclick="loadComparisonReports()">
                    &larr; Back to Reports
                </button>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Comparison Report</span>
                </div>
                <div style="padding: 0.75rem;">
                    <p><strong>Reference Device:</strong> ${report.reference_hostname || report.reference_ip} (${report.reference_ip})</p>
                    <p><strong>Date:</strong> ${new Date(report.timestamp).toLocaleString()}</p>
                    <p><strong>Compared:</strong> ${report.successful} successful, ${report.failed} failed out of ${report.total_targets} device(s)</p>
                </div>
            </div>
            <h4 style="margin-top: 1rem;">Results</h4>
            ${resultsHtml}
        `;
    }

    // Make loadComparisonReports accessible globally
    window.loadComparisonReports = loadComparisonReports;

    // ==================== COLLECTION DEVICE PROGRESS ====================

    function initCollectDeviceProgress(deviceIps) {
        const container = document.getElementById('devices-collect-device-progress');
        const listContainer = document.getElementById('devices-collect-device-list');

        if (!container || !listContainer) return;

        listContainer.style.display = 'block';

        container.innerHTML = deviceIps.map(ip => {
            const device = devices.find(d => d.ip === ip);
            const hostname = device ? (device.hostname || ip) : ip;
            return `
                <div class="device-progress-item" data-device-ip="${ip}" style="display: flex; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                    <span class="device-ip" style="flex: 1;">${hostname} <span style="color: var(--text-muted);">(${ip})</span></span>
                    <span class="device-status status-pending">
                        <span class="spinner-small"></span> Pending...
                    </span>
                </div>
            `;
        }).join('');
    }

    function updateCollectDeviceStatus(deviceIp, status) {
        const container = document.getElementById('devices-collect-device-progress');
        if (!container) return;

        const deviceRow = container.querySelector(`[data-device-ip="${deviceIp}"]`);
        if (!deviceRow) return;

        const statusSpan = deviceRow.querySelector('.device-status');
        if (!statusSpan) return;

        if (status === 'in_progress') {
            statusSpan.innerHTML = '<span class="spinner-small"></span> Collecting...';
            statusSpan.className = 'device-status status-progress';
        } else if (status === 'completed') {
            statusSpan.innerHTML = '&#10004; Collected';
            statusSpan.className = 'device-status status-success';
        } else if (status === 'failed') {
            statusSpan.innerHTML = '&#10008; Failed';
            statusSpan.className = 'device-status status-error';
        }
    }

    function hideCollectDeviceProgress() {
        const listContainer = document.getElementById('devices-collect-device-list');
        if (listContainer) {
            setTimeout(() => {
                listContainer.style.display = 'none';
            }, 3000);
        }
    }

    // ==================== LOG COLLECTION ====================

    async function initLogsDeviceList() {
        const container = document.getElementById('logs-device-list');
        if (!container) return;

        // Populate group select
        await populateGroupSelect('logs-group');

        if (devices.length === 0) {
            container.innerHTML = '<p class="empty-state" style="padding: 1rem;">No devices available. Add devices first.</p>';
            return;
        }

        container.innerHTML = devices.map(d => `
            <div style="padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);" data-device-filter="${d.hostname || ''} ${d.ip} ${d.vendor || ''}">
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input type="checkbox" class="logs-device-checkbox" value="${d.ip}" onchange="updateLogsSelectedCount()">
                    <span style="flex: 1;">${d.hostname || d.ip}</span>
                    <span style="color: var(--text-muted); font-size: 0.85em;">${d.ip}</span>
                    <span class="badge ${getStatusBadgeClass(d.status)}" style="margin-left: 0.5rem;">${d.status || 'unknown'}</span>
                    <span class="badge badge-info" style="margin-left: 0.25rem;">${d.vendor}</span>
                </label>
            </div>
        `).join('');

        updateLogsSelectedCount();

        // Clear filter input
        const filterInput = document.getElementById('logs-filter');
        if (filterInput) filterInput.value = '';

        // Hide previous results
        const resultsContainer = document.getElementById('logs-results');
        if (resultsContainer) resultsContainer.style.display = 'none';
        const progressContainer = document.getElementById('logs-device-progress');
        if (progressContainer) progressContainer.style.display = 'none';
    }

    window.filterLogsDevices = function(filterText) {
        filterDeviceList('logs-device-list', filterText);
    };

    window.selectLogsGroup = function(groupId) {
        if (!groupId) return;
        selectDevicesByGroup('logs-group', 'logs-device-checkbox', updateLogsSelectedCount);
    };

    window.updateLogsSelectedCount = function() {
        const checkboxes = document.querySelectorAll('.logs-device-checkbox:checked');
        const countSpan = document.getElementById('logs-selected-count');
        if (countSpan) countSpan.textContent = `${checkboxes.length} selected`;
    };

    window.selectAllLogDevices = function(selectAll) {
        // Only affect visible (non-filtered) checkboxes
        const container = document.getElementById('logs-device-list');
        const items = container.querySelectorAll('[data-device-filter]');
        items.forEach(item => {
            if (item.style.display !== 'none') {
                const cb = item.querySelector('.logs-device-checkbox');
                if (cb) cb.checked = selectAll;
            }
        });
        // Reset group dropdown
        const groupSelect = document.getElementById('logs-group');
        if (groupSelect) groupSelect.value = '';
        updateLogsSelectedCount();
    };

    // Log collection form handler
    document.getElementById('logs-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const selectedCheckboxes = document.querySelectorAll('.logs-device-checkbox:checked');
        const deviceIps = Array.from(selectedCheckboxes).map(cb => cb.value);

        if (deviceIps.length === 0) {
            showToast(I18n.t('toast.selectAtLeastOneDevice'), 'warning');
            return;
        }

        const credentialId = document.getElementById('logs-credential').value || null;
        const button = document.getElementById('logs-collect-btn');

        // Hide previous results
        const resultsContainer = document.getElementById('logs-results');
        if (resultsContainer) resultsContainer.style.display = 'none';

        setButtonLoading(button, true, I18n.t('common.collecting') || 'Collecting...');

        try {
            const response = await API.collectLogs(deviceIps, credentialId);
            showToast(I18n.t('toast.logCollectionStarted'), 'info');
            showProgress('logs');

            // Initialize device progress list
            if (response.devices && response.devices.length > 0) {
                initLogsDeviceProgress(response.devices);
            }
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    });

    function initLogsDeviceProgress(deviceList) {
        const container = document.getElementById('logs-device-progress');
        const listContainer = document.getElementById('logs-device-status-list');

        if (!container || !listContainer) return;

        container.style.display = 'block';
        listContainer.innerHTML = deviceList.map(d => `
            <div class="logs-device-item" id="logs-device-${d.ip.replace(/\./g, '-')}"
                 style="display: flex; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                <span class="logs-device-status" style="width: 24px; text-align: center; margin-right: 0.5rem;">
                    <span style="color: var(--text-muted);">&#9679;</span>
                </span>
                <span style="flex: 1;">${d.hostname}</span>
                <span style="color: var(--text-muted); font-size: 0.85em;">${d.ip}</span>
                <span class="badge badge-info" style="margin-left: 0.5rem;">${d.vendor}</span>
            </div>
        `).join('');
    }

    function updateLogsDeviceStatus(ip, status) {
        const itemId = `logs-device-${ip.replace(/\./g, '-')}`;
        const item = document.getElementById(itemId);
        if (!item) return;

        const statusSpan = item.querySelector('.logs-device-status');
        if (!statusSpan) return;

        if (status === 'collecting') {
            statusSpan.innerHTML = '<span class="spinner" style="width: 14px; height: 14px;"></span>';
            item.style.backgroundColor = 'var(--bg-color)';
        } else if (status === 'success') {
            statusSpan.innerHTML = '<span style="color: var(--success-color);">&#10003;</span>';
            item.style.backgroundColor = '';
        } else if (status === 'error') {
            statusSpan.innerHTML = '<span style="color: var(--danger-color);">&#10007;</span>';
            item.style.backgroundColor = '';
        }
    }

    function renderLogsResults(results) {
        const container = document.getElementById('logs-results');
        const listContainer = document.getElementById('logs-results-list');

        if (!container || !listContainer) return;

        container.style.display = 'block';

        if (!results || results.length === 0) {
            listContainer.innerHTML = `<p class="empty-state">${I18n.t('logs.noLogs') || 'No logs collected'}</p>`;
            return;
        }

        listContainer.innerHTML = `
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>${I18n.t('logs.device') || 'Device'}</th>
                            <th>${I18n.t('devices.status') || 'Status'}</th>
                            <th>${I18n.t('logs.size') || 'Size'}</th>
                            <th>${I18n.t('common.actions') || 'Actions'}</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr>
                                <td>${r.hostname} (${r.device_ip})</td>
                                <td>
                                    <span class="badge ${r.success ? 'badge-success' : 'badge-danger'}">
                                        ${r.success ? I18n.t('logs.success') || 'Success' : I18n.t('logs.failed') || 'Failed'}
                                    </span>
                                </td>
                                <td>${r.success ? formatBytes(r.log_size) : (r.error || I18n.t('common.error') || 'Error')}</td>
                                <td>
                                    ${r.success ? `
                                        <button class="btn btn-sm btn-primary" onclick="viewDeviceLogs('${r.device_ip}')">
                                            ${I18n.t('logs.viewLogs') || 'View Logs'}
                                        </button>
                                    ` : ''}
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    window.viewDeviceLogs = async function(ip) {
        try {
            const response = await API.getDeviceLogs(ip);
            showLogsModal(response);
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    function showLogsModal(logData) {
        // Reuse config viewer modal for logs
        const modal = document.getElementById('config-viewer-modal');
        const titleSpan = document.getElementById('config-device-ip');
        const contentPre = document.getElementById('config-viewer-content');

        if (modal && titleSpan && contentPre) {
            titleSpan.textContent = `${logData.hostname} (${logData.device_ip}) - Logs`;
            contentPre.textContent = logData.logs || I18n.t('common.noLogsAvailable') || 'No logs available';
            openModal('config-viewer-modal');
        }
    }

    // ==================== GROUP SELECT & FILTER HELPERS ====================

    async function populateGroupSelect(selectId) {
        const select = document.getElementById(selectId);
        if (!select) return;

        try {
            const response = await API.getGroups();
            const groupList = response.groups || [];

            select.innerHTML = '<option value="">-- Select Group --</option>' +
                groupList.map(g => `<option value="${g.id}" data-devices='${JSON.stringify(g.device_ips)}'>${escapeHtml(g.name)} (${g.device_ips.length})</option>`).join('');
        } catch (error) {
            console.error('Failed to load groups:', error);
            select.innerHTML = '<option value="">-- No Groups --</option>';
        }
    }

    function selectDevicesByGroup(groupSelectId, checkboxClass, updateCountFn) {
        const select = document.getElementById(groupSelectId);
        if (!select) return;

        const selectedOption = select.options[select.selectedIndex];
        if (!selectedOption || !selectedOption.value) return;

        const deviceIps = JSON.parse(selectedOption.dataset.devices || '[]');
        const checkboxes = document.querySelectorAll(`.${checkboxClass}`);

        // Deselect all first, then select only group devices
        checkboxes.forEach(cb => {
            cb.checked = deviceIps.includes(cb.value);
        });

        if (updateCountFn) updateCountFn();
    }

    function filterDeviceList(containerId, filterText) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const items = container.querySelectorAll('[data-device-filter]');
        const search = filterText.toLowerCase().trim();

        items.forEach(item => {
            if (!search) {
                item.style.display = '';
                return;
            }

            const filterData = item.dataset.deviceFilter.toLowerCase();
            item.style.display = filterData.includes(search) ? '' : 'none';
        });
    }

    // ==================== CONFIGURATIONS COLLECTION PAGE ====================

    async function initCollectPageDeviceList() {
        const container = document.getElementById('collect-page-device-list');
        if (!container) return;

        // Populate group select
        await populateGroupSelect('collect-page-group');

        if (!devices || devices.length === 0) {
            container.innerHTML = '<p class="empty-state">No devices available. Add devices first.</p>';
            updateCollectPageSelectedCount();
            return;
        }

        container.innerHTML = devices.map(d => `
            <div style="padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);" data-device-filter="${d.hostname || ''} ${d.ip} ${d.vendor || ''}">
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input type="checkbox" class="collect-page-device-checkbox" value="${d.ip}" checked onchange="updateCollectPageSelectedCount()">
                    <span style="flex: 1;">${d.hostname || d.ip}</span>
                    <span style="color: var(--text-muted); font-size: 0.85em;">${d.ip}</span>
                    <span class="badge ${getStatusBadgeClass(d.status)}" style="margin-left: 0.5rem;">${d.status || 'unknown'}</span>
                    <span class="badge badge-info" style="margin-left: 0.25rem;">${d.vendor}</span>
                </label>
            </div>
        `).join('');

        updateCollectPageSelectedCount();

        // Clear filter input
        const filterInput = document.getElementById('collect-page-filter');
        if (filterInput) filterInput.value = '';

        // Hide progress containers
        const progressContainer = document.getElementById('collect-page-device-progress');
        if (progressContainer) progressContainer.style.display = 'none';
    }

    window.filterCollectPageDevices = function(filterText) {
        filterDeviceList('collect-page-device-list', filterText);
    };

    window.selectCollectPageGroup = function(groupId) {
        if (!groupId) return;
        selectDevicesByGroup('collect-page-group', 'collect-page-device-checkbox', updateCollectPageSelectedCount);
    };

    window.selectAllCollectPageDevices = function(selectAll) {
        // Only affect visible (non-filtered) checkboxes
        const container = document.getElementById('collect-page-device-list');
        const items = container.querySelectorAll('[data-device-filter]');
        items.forEach(item => {
            if (item.style.display !== 'none') {
                const cb = item.querySelector('.collect-page-device-checkbox');
                if (cb) cb.checked = selectAll;
            }
        });
        // Reset group dropdown
        const groupSelect = document.getElementById('collect-page-group');
        if (groupSelect) groupSelect.value = '';
        updateCollectPageSelectedCount();
    };

    window.updateCollectPageSelectedCount = function() {
        const checkboxes = document.querySelectorAll('.collect-page-device-checkbox:checked');
        const countSpan = document.getElementById('collect-page-selected-count');
        if (countSpan) countSpan.textContent = `${checkboxes.length} selected`;
    };

    window.startCollectFromPage = async function() {
        const credentialId = document.getElementById('collect-page-credential').value || null;
        const checkboxes = document.querySelectorAll('.collect-page-device-checkbox:checked');
        const deviceIps = Array.from(checkboxes).map(cb => cb.value);

        if (deviceIps.length === 0) {
            showToast(I18n.t('toast.selectAtLeastOneDevice'), 'warning');
            return;
        }

        const button = document.getElementById('collect-page-btn');
        setButtonLoading(button, true, I18n.t('common.collecting') || 'Collecting...');

        // Hide previous progress
        const progressContainer = document.getElementById('collect-page-device-progress');
        if (progressContainer) progressContainer.style.display = 'none';

        try {
            await API.startCollection(deviceIps, credentialId);
            showToast(I18n.t('toast.collectionStarted'), 'info');
            showProgress('collect');

            // Initialize device progress list
            initCollectPageDeviceProgress(deviceIps);
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    };

    function initCollectPageDeviceProgress(deviceIps) {
        const container = document.getElementById('collect-page-device-progress');
        const listContainer = document.getElementById('collect-page-device-status');

        if (!container || !listContainer) return;

        container.style.display = 'block';

        listContainer.innerHTML = deviceIps.map(ip => {
            const device = devices.find(d => d.ip === ip);
            const hostname = device ? (device.hostname || ip) : ip;
            const vendor = device ? device.vendor : 'unknown';
            return `
                <div class="collect-page-device-item" id="collect-page-device-${ip.replace(/\./g, '-')}"
                     style="display: flex; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                    <span class="collect-page-device-status" style="width: 24px; text-align: center; margin-right: 0.5rem;">
                        <span style="color: var(--text-muted);">&#9679;</span>
                    </span>
                    <span style="flex: 1;">${hostname}</span>
                    <span style="color: var(--text-muted); font-size: 0.85em;">${ip}</span>
                    <span class="badge badge-info" style="margin-left: 0.5rem;">${vendor}</span>
                </div>
            `;
        }).join('');
    }

    function updateCollectPageDeviceStatus(ip, status) {
        const itemId = `collect-page-device-${ip.replace(/\./g, '-')}`;
        const item = document.getElementById(itemId);
        if (!item) return;

        const statusSpan = item.querySelector('.collect-page-device-status');
        if (!statusSpan) return;

        if (status === 'in_progress') {
            statusSpan.innerHTML = '<span class="spinner" style="width: 14px; height: 14px;"></span>';
            item.style.backgroundColor = 'var(--bg-color)';
        } else if (status === 'completed') {
            statusSpan.innerHTML = '<span style="color: var(--success-color);">&#10003;</span>';
            item.style.backgroundColor = '';
        } else if (status === 'failed') {
            statusSpan.innerHTML = '<span style="color: var(--danger-color);">&#10007;</span>';
            item.style.backgroundColor = '';
        }
    }

    function hideCollectPageDeviceProgress() {
        const container = document.getElementById('collect-page-device-progress');
        if (container) {
            setTimeout(() => {
                container.style.display = 'none';
            }, 3000);
        }
    }

    // Button loading state helpers
    function setButtonLoading(button, loading, originalText = null) {
        if (!button) return;

        if (loading) {
            button.disabled = true;
            button.style.opacity = '0.6';
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = `<span class="spinner"></span> ${originalText || I18n.t('common.loading') || 'Loading...'}`;
        } else {
            button.disabled = false;
            button.style.opacity = '1';
            if (button.dataset.originalText) {
                button.innerHTML = button.dataset.originalText;
            }
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
            showToast(I18n.t('toast.error.loadDashboard'), 'error');
        }
    }

    // Devices
    async function loadDevices() {
        try {
            const response = await API.getDevices();
            devices = response.devices;
            renderDevicesTable();
        } catch (error) {
            showToast(I18n.t('toast.error.loadDevices'), 'error');
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
                        <p>${I18n.t('devices.noDevices') || 'No devices registered yet'}</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = devices.map(device => `
            <tr data-device-ip="${device.ip}" data-device-hostname="${device.hostname || ''}">
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
                        <button class="btn btn-sm btn-secondary" onclick="viewDeviceConfig('${device.ip}')" title="${I18n.t('common.view') || 'View'}">
                            ${I18n.t('common.config') || 'Config'}
                        </button>
                        <button class="btn btn-sm btn-primary" onclick="downloadDeviceConfig('${device.ip}')" title="${I18n.t('devices.downloadConfig') || 'Download'}">
                            &#8681;
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteDevice('${device.ip}')" title="${I18n.t('common.delete') || 'Delete'}">
                            &#128465;
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        // Initialize or refresh SelectionManager
        initDeviceSelection();
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
            showToast(I18n.t('toast.error.loadCredentials'), 'error');
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
                credentials.map(c => {
                    const desc = c.description ? ` - ${c.description}` : '';
                    const defaultTag = c.is_default ? ' (default)' : '';
                    return `
                        <option value="${c.id}" ${c.is_default ? 'selected' : ''}>
                            ${c.username}${desc}${defaultTag}
                        </option>
                    `;
                }).join('');
            if (currentValue) select.value = currentValue;
        });
    }

    // Modal handling
    window.openModal = async function(modalId) {
        // Ensure credentials are loaded for modals that need them
        if (modalId === 'add-device-modal' || modalId === 'add-credential-modal') {
            await loadCredentials();
        }
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
            showToast(I18n.t('toast.devicesAdded', { count: result.added.length }), 'success');
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
            showToast(I18n.t('toast.credentialAdded'), 'success');
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
        const button = document.getElementById('scan-btn');
        setButtonLoading(button, true, I18n.t('common.scanning') || 'Scanning...');

        // Hide previous results
        document.getElementById('scan-results').style.display = 'none';

        try {
            await API.startScan(ipRange);
            showToast(I18n.t('toast.scanStarted'), 'info');
            showProgress('scan');
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    });

    // Scan results handling
    function renderScanResults(devices) {
        const container = document.getElementById('scan-results');
        const tbody = document.getElementById('scan-results-tbody');

        if (!devices || devices.length === 0) {
            container.style.display = 'none';
            return;
        }

        tbody.innerHTML = devices.map(d => `
            <tr>
                <td>
                    <input type="checkbox" class="scan-device-checkbox"
                           data-ip="${d.ip}"
                           ${d.already_exists ? 'disabled' : 'checked'}
                           onchange="updateScanSelectedCount()">
                </td>
                <td>${d.ip}</td>
                <td>${d.response_time ? d.response_time + ' ms' : '-'}</td>
                <td>
                    <select class="form-control scan-vendor-select" data-ip="${d.ip}" ${d.already_exists ? 'disabled' : ''}>
                        <option value="">Auto-detect</option>
                        <option value="huawei">Huawei</option>
                        <option value="hp">HP</option>
                        <option value="aruba">Aruba</option>
                        <option value="cisco">Cisco (IOS)</option>
                    </select>
                </td>
                <td>
                    ${d.already_exists ?
                        '<span class="badge badge-warning">Already exists</span>' :
                        '<span class="badge badge-success">New</span>'}
                </td>
            </tr>
        `).join('');

        container.style.display = 'block';
        updateScanSelectedCount();
    }

    window.toggleScanSelectAll = function(checkbox) {
        const checkboxes = document.querySelectorAll('.scan-device-checkbox:not(:disabled)');
        checkboxes.forEach(cb => cb.checked = checkbox.checked);
        updateScanSelectedCount();
    };

    window.updateScanSelectedCount = function() {
        const checked = document.querySelectorAll('.scan-device-checkbox:checked').length;
        document.getElementById('scan-selected-count').textContent = checked;
        document.getElementById('add-scanned-devices-btn').disabled = checked === 0;
    };

    window.addSelectedScannedDevices = async function() {
        const checkboxes = document.querySelectorAll('.scan-device-checkbox:checked');
        const devices = [];

        checkboxes.forEach(cb => {
            const ip = cb.dataset.ip;
            const vendorSelect = document.querySelector(`.scan-vendor-select[data-ip="${ip}"]`);
            devices.push({
                ip: ip,
                vendor: vendorSelect ? vendorSelect.value : null
            });
        });

        if (devices.length === 0) {
            showToast(I18n.t('toast.noDevicesSelected'), 'warning');
            return;
        }

        const button = document.getElementById('add-scanned-devices-btn');
        setButtonLoading(button, true, I18n.t('common.adding') || 'Adding...');

        try {
            const result = await API.addScannedDevices(devices);
            showToast(I18n.t('toast.devicesAdded', { count: result.added.length }), 'success');
            document.getElementById('scan-results').style.display = 'none';
            await loadDevices();
        } catch (error) {
            showToast(error.message, 'error');
        } finally {
            setButtonLoading(button, false);
        }
    };

    window.clearScanResults = function() {
        document.getElementById('scan-results').style.display = 'none';
        document.getElementById('scan-results-tbody').innerHTML = '';
    };

    // Discovery form
    document.getElementById('discover-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const credentialId = document.getElementById('discover-credential').value || null;
        const ipRange = document.getElementById('discover-ip-range').value || null;
        const button = document.getElementById('discover-btn');
        setButtonLoading(button, true, I18n.t('common.discovering') || 'Discovering...');

        // Clear previous results
        document.getElementById('discover-results').style.display = 'none';
        document.getElementById('discover-results-tbody').innerHTML = '';
        document.getElementById('discover-device-list').style.display = 'none';

        try {
            await API.startDiscovery(null, credentialId, true, ipRange);
            showToast(I18n.t('toast.discoveryStarted'), 'info');
            showProgress('discover');
            initDiscoverDeviceProgress();
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    });

    // Initialize discover device progress list
    function initDiscoverDeviceProgress() {
        const container = document.getElementById('discover-device-progress');
        const listContainer = document.getElementById('discover-device-list');
        listContainer.style.display = 'block';
        container.innerHTML = '<p class="empty-state">Waiting for device information...</p>';
    }

    // Update discover device status
    function updateDiscoverDeviceStatus(deviceIp, status, message = '') {
        const container = document.getElementById('discover-device-progress');

        // Clear empty state message
        if (container.querySelector('.empty-state')) {
            container.innerHTML = '';
        }

        let deviceRow = container.querySelector(`[data-device-ip="${deviceIp}"]`);
        if (!deviceRow) {
            deviceRow = document.createElement('div');
            deviceRow.className = 'device-progress-item';
            deviceRow.setAttribute('data-device-ip', deviceIp);
            deviceRow.innerHTML = `
                <span class="device-ip">${deviceIp}</span>
                <span class="device-status"></span>
            `;
            container.appendChild(deviceRow);
        }

        const statusSpan = deviceRow.querySelector('.device-status');
        if (status === 'in_progress') {
            statusSpan.innerHTML = '<span class="spinner-small"></span> Discovering...';
            statusSpan.className = 'device-status status-progress';
        } else if (status === 'completed') {
            statusSpan.innerHTML = `&#10004; ${message || 'Done'}`;
            statusSpan.className = 'device-status status-success';
        } else if (status === 'failed') {
            statusSpan.innerHTML = `&#10008; ${message || 'Failed'}`;
            statusSpan.className = 'device-status status-error';
        }
    }

    // Render discovered neighbors
    function renderDiscoverResults(neighbors, newDevices) {
        const tbody = document.getElementById('discover-results-tbody');
        const resultsContainer = document.getElementById('discover-results');

        if (!neighbors || neighbors.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No neighbors discovered</td></tr>';
        } else {
            tbody.innerHTML = neighbors.map(n => `
                <tr>
                    <td>${n.neighbor_device || '-'}</td>
                    <td>${n.source_device || '-'}</td>
                    <td><span class="badge ${n.source === 'lldp' ? 'badge-primary' : 'badge-warning'}">${(n.source || '').toUpperCase()}</span></td>
                    <td>${n.local_interface || '-'}</td>
                    <td>${n.neighbor_interface || '-'}</td>
                    <td>${getVendorFromNeighborName(n.neighbor_device)}</td>
                </tr>
            `).join('');
        }
        resultsContainer.style.display = 'block';
    }

    // Detect vendor from neighbor name
    function getVendorFromNeighborName(name) {
        if (!name) return 'Unknown';
        const lower = name.toLowerCase();
        if (lower.includes('huawei') || lower.includes('s5720') || lower.includes('s5700')) return 'Huawei';
        if (lower.includes('hp') || lower.includes('1900') || lower.includes('comware')) return 'HP';
        if (lower.includes('aruba') || lower.includes('iap') || lower.includes('ap-')) return 'Aruba';
        if (lower.includes('cisco') || lower.includes('ios') || lower.includes('isr') ||
            lower.includes('asr') || lower.includes('nexus') || lower.includes('catalyst')) return 'Cisco';
        return 'Unknown';
    }

    // Collect form
    document.getElementById('collect-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const button = e.target.querySelector('button[type="submit"]');
        setButtonLoading(button, true, I18n.t('common.collecting') || 'Collecting...');

        const selectedDevices = Array.from(document.querySelectorAll('.device-checkbox:checked'))
            .map(cb => cb.value);
        const credentialId = document.getElementById('collect-credential').value || null;

        try {
            await API.startCollection(
                selectedDevices.length ? selectedDevices : null,
                credentialId
            );
            showToast(I18n.t('toast.collectionStarted') || 'Collection started', 'info');
            showProgress('collect');
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    });

    // MAC search state
    let macSearchDevices = [];

    // Initialize MAC search device selection list
    async function initMacSearchDeviceList() {
        const container = document.getElementById('mac-search-device-list');
        if (!container) return;

        // Populate group select
        await populateGroupSelect('mac-search-group');

        // Clear filter input
        const filterInput = document.getElementById('mac-search-filter');
        if (filterInput) filterInput.value = '';

        if (!devices || devices.length === 0) {
            container.innerHTML = '<p class="empty-state" style="padding: 0.5rem;">No devices available. Add devices first.</p>';
            updateMacSearchSelectedCount();
            return;
        }

        container.innerHTML = devices.map(d => `
            <div style="display: flex; align-items: center; padding: 0.25rem 0;" data-device-filter="${d.hostname || ''} ${d.ip} ${d.vendor || ''}">
                <input type="checkbox" class="mac-search-device-checkbox"
                       id="mac-device-${d.ip}" value="${d.ip}" checked
                       onchange="updateMacSearchSelectedCount()">
                <label for="mac-device-${d.ip}" style="margin-left: 0.5rem; flex: 1; cursor: pointer;">
                    ${d.hostname || d.ip}
                    <span style="color: var(--text-muted);">(${d.ip})</span>
                    <span class="badge ${d.status === 'online' ? 'badge-success' : d.status === 'offline' ? 'badge-danger' : 'badge-warning'}" style="margin-left: 0.5rem;">
                        ${d.status || 'unknown'}
                    </span>
                </label>
            </div>
        `).join('');

        updateMacSearchSelectedCount();
    }

    window.filterMacSearchDevices = function(filterText) {
        filterDeviceList('mac-search-device-list', filterText);
    };

    window.selectMacSearchGroup = function(groupId) {
        if (!groupId) return;
        selectDevicesByGroup('mac-search-group', 'mac-search-device-checkbox', updateMacSearchSelectedCount);
    };

    window.selectAllMacSearchDevices = function(select) {
        // Only affect visible (non-filtered) checkboxes
        const container = document.getElementById('mac-search-device-list');
        const items = container.querySelectorAll('[data-device-filter]');
        items.forEach(item => {
            if (item.style.display !== 'none') {
                const cb = item.querySelector('.mac-search-device-checkbox');
                if (cb) cb.checked = select;
            }
        });
        // Reset group dropdown
        const groupSelect = document.getElementById('mac-search-group');
        if (groupSelect) groupSelect.value = '';
        updateMacSearchSelectedCount();
    };

    window.updateMacSearchSelectedCount = function() {
        const checked = document.querySelectorAll('.mac-search-device-checkbox:checked').length;
        const countSpan = document.getElementById('mac-search-selected-count');
        if (countSpan) {
            countSpan.textContent = `${checked} selected`;
        }
    };

    // MAC search form
    document.getElementById('mac-search-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const macAddress = document.getElementById('mac-address').value;
        const credentialId = document.getElementById('mac-search-credential').value || null;
        const button = document.getElementById('mac-search-btn');

        // Get selected devices
        const checkboxes = document.querySelectorAll('.mac-search-device-checkbox:checked');
        const selectedDeviceIps = Array.from(checkboxes).map(cb => cb.value);

        if (selectedDeviceIps.length === 0) {
            showToast(I18n.t('toast.selectAtLeastOneDevice') || 'Please select at least one device', 'warning');
            return;
        }

        // Hide previous results
        const resultsContainer = document.getElementById('mac-results');
        if (resultsContainer) resultsContainer.style.display = 'none';

        // Hide device progress
        const deviceProgressContainer = document.getElementById('mac-device-progress');
        if (deviceProgressContainer) deviceProgressContainer.style.display = 'none';

        setButtonLoading(button, true, I18n.t('common.searching') || 'Searching...');

        try {
            const response = await API.searchMac(macAddress, selectedDeviceIps, credentialId);
            showToast(I18n.t('toast.macSearchStarted'), 'info');
            showProgress('mac_search');

            // Initialize device list with selected devices
            if (response.devices && response.devices.length > 0) {
                macSearchDevices = response.devices;
                initMacDeviceProgress(macSearchDevices);
            }
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
        }
    });

    function initMacDeviceProgress(devices) {
        const container = document.getElementById('mac-device-progress');
        const listContainer = document.getElementById('mac-device-list');

        if (!container || !listContainer) return;

        container.style.display = 'block';
        listContainer.innerHTML = devices.map(d => `
            <div class="mac-device-item" id="mac-device-${d.ip.replace(/\./g, '-')}"
                 style="display: flex; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                <span class="mac-device-status" style="width: 24px; text-align: center; margin-right: 0.5rem;">
                    <span style="color: var(--text-muted);">&#9679;</span>
                </span>
                <span style="flex: 1;">${d.hostname}</span>
                <span style="color: var(--text-muted); font-size: 0.85em;">${d.ip}</span>
                <span class="badge badge-info" style="margin-left: 0.5rem;">${d.vendor}</span>
            </div>
        `).join('');
    }

    function updateMacDeviceStatus(ip, status) {
        const itemId = `mac-device-${ip.replace(/\./g, '-')}`;
        const item = document.getElementById(itemId);
        if (!item) return;

        const statusSpan = item.querySelector('.mac-device-status');
        if (!statusSpan) return;

        if (status === 'searching') {
            statusSpan.innerHTML = '<span class="spinner" style="width: 14px; height: 14px;"></span>';
            item.style.backgroundColor = 'var(--bg-color)';
        } else if (status === 'complete') {
            statusSpan.innerHTML = '<span style="color: var(--success-color);">&#10003;</span>';
            item.style.backgroundColor = '';
        } else if (status === 'error') {
            statusSpan.innerHTML = '<span style="color: var(--danger-color);">&#10007;</span>';
            item.style.backgroundColor = '';
        }
    }

    function renderMacResults(result) {
        const container = document.getElementById('mac-results');
        const isWildcard = result.is_wildcard;

        // Show the results container
        container.style.display = 'block';

        if (!result.found) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>${isWildcard ? 'No MAC addresses matching pattern' : 'MAC address not found'}: ${result.mac_address}</p>
                </div>
            `;
            return;
        }

        const headerText = isWildcard
            ? `Found ${result.results.length} MAC address${result.results.length > 1 ? 'es' : ''} matching: ${result.mac_address}`
            : `Found MAC address: ${result.mac_address}`;

        container.innerHTML = `
            <div class="card-header" style="border-bottom: 1px solid var(--border-color); margin: -1.5rem -1.5rem 1rem -1.5rem; padding: 1rem 1.5rem;">
                <span class="card-title">${headerText}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>Switch</th>
                        <th>Port</th>
                        <th>VLAN</th>
                        <th>Vendor</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.results.map(r => `
                        <tr>
                            <td><code>${r.mac_address}</code></td>
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
        if (!confirm(I18n.t('confirm.deleteDevice', { ip }))) return;

        try {
            await API.deleteDevice(ip);
            showToast(I18n.t('toast.deviceDeleted'), 'success');
            await loadDevices();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Check device status
    window.checkDevicesStatus = async function() {
        const button = document.querySelector('button[onclick="checkDevicesStatus()"]');
        setButtonLoading(button, true, I18n.t('common.checking') || 'Checking...');

        try {
            await API.checkDevicesStatus();
            showToast(I18n.t('toast.statusCheckStarted'), 'info');
            showProgress('status_check');
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(button, false);
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

    // Update bulk delete and download button visibility
    window.updateBulkDeleteButton = function() {
        const selectedCheckboxes = document.querySelectorAll('.device-checkbox:checked');
        const bulkDeleteBtn = document.getElementById('bulk-delete-btn');
        const bulkDownloadBtn = document.getElementById('bulk-download-btn');
        const selectedCount = document.getElementById('selected-count');
        const downloadCount = document.getElementById('download-count');

        const count = selectedCheckboxes.length;

        if (bulkDeleteBtn && selectedCount) {
            selectedCount.textContent = count;
            bulkDeleteBtn.style.display = count > 0 ? 'inline-flex' : 'none';
        }

        if (bulkDownloadBtn && downloadCount) {
            downloadCount.textContent = count;
            bulkDownloadBtn.style.display = count > 0 ? 'inline-flex' : 'none';
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
            showToast(I18n.t('toast.noDevicesSelected') || 'No devices selected', 'warning');
            return;
        }

        if (!confirm(I18n.t('confirm.deleteDevices', { count: selectedIps.length }) + '\n\n' + selectedIps.join('\n'))) {
            return;
        }

        try {
            const result = await API.bulkDeleteDevices(selectedIps);
            showToast(I18n.t('toast.devicesDeleted', { count: result.deleted.length }), 'success');
            await loadDevices();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    window.bulkDownloadConfigs = async function() {
        const selectedCheckboxes = document.querySelectorAll('.device-checkbox:checked');
        const selectedIps = Array.from(selectedCheckboxes).map(cb => cb.value);

        if (selectedIps.length === 0) {
            showToast(I18n.t('toast.noDevicesSelected') || 'No devices selected', 'warning');
            return;
        }

        try {
            await API.downloadConfigsBulk(selectedIps);
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    window.downloadDeviceConfig = function(ip) {
        API.downloadConfig(ip);
    };

    // Set default credential
    window.setDefaultCredential = async function(id) {
        try {
            await API.setDefaultCredential(id);
            showToast(I18n.t('toast.defaultCredentialUpdated'), 'success');
            await loadCredentials();
        } catch (error) {
            showToast(error.message, 'error');
        }
    };

    // Delete credential
    window.deleteCredential = async function(id) {
        if (!confirm(I18n.t('confirm.deleteCredential'))) return;

        try {
            await API.deleteCredential(id);
            showToast(I18n.t('toast.credentialDeleted'), 'success');
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
            // Initialize device list on starting phase
            if (data.phase === 'starting' && data.device_ips) {
                initCollectDeviceProgress(data.device_ips);
            }
            // Update per-device status on both pages
            if (data.device_ip && data.status) {
                updateCollectDeviceStatus(data.device_ip, data.status);
                updateCollectPageDeviceStatus(data.device_ip, data.status);
            }
        } else if (data.task_type === 'mac_search') {
            updateProgressContainer('mac_search-progress', data);
            // Update per-device status
            if (data.device_ip) {
                updateMacDeviceStatus(data.device_ip, 'searching');
                // Mark as complete after a short delay
                setTimeout(() => updateMacDeviceStatus(data.device_ip, 'complete'), 500);
            }
        } else if (data.task_type === 'logs') {
            updateProgressContainer('logs-progress', data);
            // Update per-device status
            if (data.device_ip && data.status) {
                updateLogsDeviceStatus(data.device_ip, data.status);
            }
        } else if (data.task_type === 'discover') {
            updateProgressContainer('discover-progress', data);
            // Update per-device status
            if (data.device_ip && data.status) {
                const message = data.lldp_count !== undefined ?
                    `LLDP: ${data.lldp_count}, CDP: ${data.cdp_count}` : '';
                updateDiscoverDeviceStatus(data.device_ip, data.status, message);
            }
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
                const scanBtnComplete = document.getElementById('scan-btn');
                setButtonLoading(scanBtnComplete, false);
                showToast(I18n.t('toast.scanComplete', { count: data.results.devices_found }), 'success');
                renderScanResults(data.results.devices);
                break;
            case 'collect':
                showToast(I18n.t('toast.collectionComplete', { success: data.results.success, total: data.results.total }), 'success');
                // Reset buttons
                const collectPageBtn = document.getElementById('collect-page-btn');
                setButtonLoading(collectPageBtn, false);
                // Hide device progress after delay
                hideCollectDeviceProgress();
                hideCollectPageDeviceProgress();
                await loadDevices();
                break;
            case 'status_check':
                showToast(I18n.t('toast.statusCheckComplete', { online: data.results.online, offline: data.results.offline }), 'success');
                // Reset button
                const statusBtn = document.querySelector('button[onclick="checkDevicesStatus()"]');
                setButtonLoading(statusBtn, false);
                await loadDevices();
                break;
            case 'mac_search':
                const macSearchBtn = document.getElementById('mac-search-btn');
                setButtonLoading(macSearchBtn, false);
                // Hide device progress
                const deviceProgressContainer = document.getElementById('mac-device-progress');
                if (deviceProgressContainer) {
                    setTimeout(() => { deviceProgressContainer.style.display = 'none'; }, 1000);
                }
                const resultsCount = data.results.results ? data.results.results.length : 0;
                if (data.results.found) {
                    showToast(I18n.t('toast.macFound', { count: resultsCount }), 'success');
                } else {
                    showToast(I18n.t('toast.macNotFound'), 'warning');
                }
                renderMacResults(data.results);
                break;
            case 'compare':
                lastComparisonReportId = data.results.report_id;
                showToast(I18n.t('toast.comparisonComplete', { count: data.results.total }), 'success');
                // Reset button
                const compareBtn = document.getElementById('start-compare-btn');
                setButtonLoading(compareBtn, false);
                // Show complete section with view report button
                const completeSection = document.getElementById('compare-complete');
                const summaryText = document.getElementById('compare-complete-summary');
                if (completeSection) {
                    completeSection.style.display = 'block';
                    if (summaryText) {
                        summaryText.textContent = `Compared ${data.results.total} device(s) against reference`;
                    }
                }
                break;
            case 'logs':
                const logsBtn = document.getElementById('logs-collect-btn');
                setButtonLoading(logsBtn, false);
                showToast(I18n.t('toast.logCollectionComplete', { success: data.results.success, total: data.results.total }), 'success');
                // Render results
                renderLogsResults(data.results.results);
                break;
            case 'discover':
                const discoverBtn = document.getElementById('discover-btn');
                setButtonLoading(discoverBtn, false);
                const neighborsFound = data.results.neighbors_found || 0;
                showToast(I18n.t('toast.discoveryComplete', { count: neighborsFound }), 'success');
                // Render results
                renderDiscoverResults(data.results.neighbors, data.results.new_devices);
                break;
        }
    });

    wsClient.on('taskError', (data) => {
        hideProgress(data.task_type);
        showToast(data.error, 'error');

        // Reset buttons on error
        if (data.task_type === 'collect') {
            const collectPageBtn = document.getElementById('collect-page-btn');
            setButtonLoading(collectPageBtn, false);
        } else if (data.task_type === 'status_check') {
            const statusBtn = document.querySelector('button[onclick="checkDevicesStatus()"]');
            setButtonLoading(statusBtn, false);
        } else if (data.task_type === 'compare') {
            const compareBtn = document.getElementById('start-compare-btn');
            setButtonLoading(compareBtn, false);
        } else if (data.task_type === 'mac_search') {
            const macSearchBtn = document.getElementById('mac-search-btn');
            setButtonLoading(macSearchBtn, false);
        } else if (data.task_type === 'logs') {
            const logsBtn = document.getElementById('logs-collect-btn');
            setButtonLoading(logsBtn, false);
        } else if (data.task_type === 'discover') {
            const discoverBtn = document.getElementById('discover-btn');
            setButtonLoading(discoverBtn, false);
        } else if (data.task_type === 'scan') {
            const scanBtn = document.getElementById('scan-btn');
            setButtonLoading(scanBtn, false);
        }
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

    // =============================================
    // Device Selection and Context Menu
    // =============================================

    let deviceSelectionManager = null;
    let deviceContextMenu = null;

    function initDeviceSelection() {
        const tbody = document.getElementById('devices-tbody');
        if (!tbody) return;

        // Destroy existing manager if any
        if (deviceSelectionManager) {
            deviceSelectionManager.destroy();
        }

        deviceSelectionManager = new SelectionManager({
            container: tbody,
            itemSelector: 'tr[data-device-ip]',
            checkboxSelector: '.device-checkbox',
            onSelectionChange: (selectedValues, count) => {
                updateBulkDeleteButtonFromSelection(count);
            },
            enableMarquee: true,
            enableKeyboardNav: true
        });

        // Bind context menu to tbody
        tbody.addEventListener('contextmenu', handleDeviceContextMenu);
    }

    function handleDeviceContextMenu(e) {
        // Only handle if clicking on a device row
        const row = e.target.closest('tr[data-device-ip]');
        if (!row) return;

        e.preventDefault();

        // Get selected devices
        let selectedDevices = [];
        if (deviceSelectionManager) {
            selectedDevices = deviceSelectionManager.getSelectedValues();
        }

        // If right-clicked row is not in selection, select only that row
        const clickedIp = row.dataset.deviceIp;
        if (!selectedDevices.includes(clickedIp)) {
            if (deviceSelectionManager) {
                deviceSelectionManager.deselectAll();
                deviceSelectionManager.selectItem(row);
            }
            selectedDevices = [clickedIp];
        }

        // Show context menu
        if (deviceContextMenu && selectedDevices.length > 0) {
            deviceContextMenu.show(e.clientX, e.clientY, selectedDevices);
        }
    }

    function updateBulkDeleteButtonFromSelection(count) {
        const btn = document.getElementById('bulk-delete-btn');
        const downloadBtn = document.getElementById('bulk-download-btn');
        const countSpan = document.getElementById('selected-count');
        const downloadCountSpan = document.getElementById('download-count');
        if (btn && countSpan) {
            countSpan.textContent = count;
            btn.style.display = count > 0 ? 'inline-flex' : 'none';
        }
        if (downloadBtn && downloadCountSpan) {
            downloadCountSpan.textContent = count;
            downloadBtn.style.display = count > 0 ? 'inline-flex' : 'none';
        }
    }

    // Initialize context menu
    function initContextMenu() {
        deviceContextMenu = new ContextMenu({
            onAction: handleContextMenuAction
        });
    }

    async function handleContextMenuAction(action, data) {
        const devices = data.devices || [];
        const groupId = data.groupId;

        switch (action) {
            case 'add-to-new-group':
                // Open create group modal with devices pre-selected
                openCreateGroupModal(devices);
                break;

            case 'add-to-group':
                if (groupId && devices.length > 0) {
                    try {
                        await API.addDevicesToGroup(groupId, devices);
                        showToast(I18n.t('toast.devicesAddedToGroup', { count: devices.length }), 'success');
                    } catch (error) {
                        showToast(I18n.t('toast.error.addToGroup', { message: error.message }), 'error');
                    }
                }
                break;

            case 'remove-from-groups':
                if (devices.length > 0) {
                    try {
                        // Get all groups and remove devices from each
                        const response = await API.getGroups();
                        const groups = response.groups || [];
                        for (const group of groups) {
                            const toRemove = devices.filter(ip => group.device_ips.includes(ip));
                            if (toRemove.length > 0) {
                                await API.removeDevicesFromGroup(group.id, toRemove);
                            }
                        }
                        showToast(I18n.t('toast.devicesRemovedFromGroups', { count: devices.length }), 'success');
                        // Refresh groups if on groups tab
                        loadGroups();
                    } catch (error) {
                        showToast(I18n.t('toast.error.removeFromGroups', { message: error.message }), 'error');
                    }
                }
                break;
        }
    }

    // =============================================
    // Device Page Tabs
    // =============================================

    function initDevicePageTabs() {
        const tabsContainer = document.getElementById('devices-tabs');
        if (!tabsContainer) return;

        tabsContainer.addEventListener('click', (e) => {
            const btn = e.target.closest('.tab-btn');
            if (!btn) return;

            const tabId = btn.dataset.tab;

            // Update active states
            tabsContainer.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Show corresponding content
            const devicePage = document.getElementById('page-devices');
            devicePage.querySelectorAll('.tab-content').forEach(content => {
                content.classList.toggle('active', content.id === tabId);
            });

            // Load groups when switching to groups tab
            if (tabId === 'devices-groups-tab') {
                loadGroups();
            }
        });
    }

    // =============================================
    // Groups Management
    // =============================================

    let groups = [];

    async function loadGroups() {
        try {
            const response = await API.getGroups();
            groups = response.groups || [];
            renderGroupsList();
        } catch (error) {
            showToast(I18n.t('toast.error.loadGroups'), 'error');
        }
    }

    function renderGroupsList() {
        const container = document.getElementById('groups-list');
        if (!container) return;

        if (groups.length === 0) {
            container.innerHTML = `
                <div class="groups-empty">
                    <div class="groups-empty-icon">&#128193;</div>
                    <p>No groups created yet</p>
                    <button class="btn btn-primary" onclick="openCreateGroupModal()">Create Your First Group</button>
                </div>
            `;
            return;
        }

        container.innerHTML = groups.map(group => `
            <div class="group-card" data-group-id="${group.id}">
                <div class="group-card-header">
                    <span class="group-color-dot" style="background: ${group.color || '#6b7280'}"></span>
                    <h4 class="group-name">${escapeHtml(group.name)}</h4>
                    <div class="group-actions">
                        <button class="btn btn-sm btn-secondary" onclick="openEditGroupModal('${group.id}')">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteGroup('${group.id}')">Delete</button>
                    </div>
                </div>
                <p class="group-description">${escapeHtml(group.description) || I18n.t('groups.noDescription') || 'No description'}</p>
                <div class="group-stats">
                    <span class="badge badge-info">${group.device_count} device${group.device_count !== 1 ? 's' : ''}</span>
                </div>
                <div class="group-devices-preview">
                    ${group.device_ips.slice(0, 5).map(ip => `<span class="device-chip">${ip}</span>`).join('')}
                    ${group.device_ips.length > 5 ? `<span class="device-chip-more">+${group.device_ips.length - 5} more</span>` : ''}
                </div>
            </div>
        `).join('');
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    window.openCreateGroupModal = function(preSelectedDevices = []) {
        // Reset form
        document.getElementById('group-id').value = '';
        document.getElementById('group-name').value = '';
        document.getElementById('group-description').value = '';
        document.getElementById('group-color').value = '#3b82f6';
        document.getElementById('group-modal-title').textContent = I18n.t('groups.createGroup') || 'Create Group';
        document.getElementById('group-submit-btn').textContent = I18n.t('groups.createGroup') || 'Create Group';

        // Render device selection
        renderGroupDeviceSelection(preSelectedDevices);

        // Update color preview
        updateColorPreview();

        document.getElementById('group-modal').classList.add('active');
    };

    window.openEditGroupModal = async function(groupId) {
        try {
            const response = await API.getGroup(groupId);
            const group = response.group;

            document.getElementById('group-id').value = group.id;
            document.getElementById('group-name').value = group.name;
            document.getElementById('group-description').value = group.description || '';
            document.getElementById('group-color').value = group.color || '#3b82f6';
            document.getElementById('group-modal-title').textContent = I18n.t('groups.editGroup') || 'Edit Group';
            document.getElementById('group-submit-btn').textContent = I18n.t('groups.saveChanges') || 'Save Changes';

            // Render device selection with pre-selected devices
            renderGroupDeviceSelection(group.device_ips);

            // Update color preview
            updateColorPreview();

            document.getElementById('group-modal').classList.add('active');
        } catch (error) {
            showToast(I18n.t('toast.error.loadGroup', { message: error.message }) || 'Failed to load group: ' + error.message, 'error');
        }
    };

    function renderGroupDeviceSelection(selectedIps = []) {
        const container = document.getElementById('group-device-selection');
        const countSpan = document.getElementById('group-device-count');

        if (devices.length === 0) {
            container.innerHTML = `<p class="empty-state">${I18n.t('collect.noDevices') || 'No devices available'}</p>`;
            countSpan.textContent = I18n.t('common.selected', { count: 0 }) || '0 selected';
            return;
        }

        container.innerHTML = devices.map(device => {
            const isSelected = selectedIps.includes(device.ip);
            return `
                <div class="device-selection-item ${isSelected ? 'selected' : ''}" data-device-ip="${device.ip}">
                    <input type="checkbox" class="group-device-checkbox" value="${device.ip}" ${isSelected ? 'checked' : ''}>
                    <div class="device-selection-info">
                        <span class="device-selection-ip">${device.ip}</span>
                        <span class="device-selection-hostname">${device.hostname || ''}</span>
                    </div>
                    <span class="badge badge-info">${device.vendor || 'unknown'}</span>
                </div>
            `;
        }).join('');

        // Bind click handlers
        container.querySelectorAll('.device-selection-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (e.target.type === 'checkbox') return;
                const checkbox = item.querySelector('input[type="checkbox"]');
                checkbox.checked = !checkbox.checked;
                item.classList.toggle('selected', checkbox.checked);
                updateGroupDeviceCount();
            });
        });

        container.querySelectorAll('.group-device-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                e.target.closest('.device-selection-item').classList.toggle('selected', e.target.checked);
                updateGroupDeviceCount();
            });
        });

        updateGroupDeviceCount();
    }

    function updateGroupDeviceCount() {
        const count = document.querySelectorAll('.group-device-checkbox:checked').length;
        document.getElementById('group-device-count').textContent = `${count} selected`;
    }

    window.selectAllGroupDevices = function(selectAll) {
        document.querySelectorAll('.group-device-checkbox').forEach(checkbox => {
            checkbox.checked = selectAll;
            checkbox.closest('.device-selection-item').classList.toggle('selected', selectAll);
        });
        updateGroupDeviceCount();
    };

    function updateColorPreview() {
        const colorInput = document.getElementById('group-color');
        const preview = document.getElementById('color-preview');
        const color = colorInput.value;

        const colorNames = {
            '#3b82f6': I18n.t('groups.colors.blue') || 'Blue',
            '#22c55e': I18n.t('groups.colors.green') || 'Green',
            '#ef4444': I18n.t('groups.colors.red') || 'Red',
            '#f59e0b': I18n.t('groups.colors.amber') || 'Amber',
            '#8b5cf6': I18n.t('groups.colors.purple') || 'Purple',
            '#ec4899': I18n.t('groups.colors.pink') || 'Pink',
            '#06b6d4': I18n.t('groups.colors.cyan') || 'Cyan',
            '#6b7280': I18n.t('groups.colors.gray') || 'Gray'
        };

        preview.textContent = colorNames[color.toLowerCase()] || color;
    }

    // Color picker change handler
    document.getElementById('group-color')?.addEventListener('input', updateColorPreview);

    // Group form submission
    document.getElementById('group-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const groupId = document.getElementById('group-id').value;
        const name = document.getElementById('group-name').value.trim();
        const description = document.getElementById('group-description').value.trim();
        const color = document.getElementById('group-color').value;
        const selectedDevices = Array.from(document.querySelectorAll('.group-device-checkbox:checked'))
            .map(cb => cb.value);

        if (!name) {
            showToast(I18n.t('toast.enterGroupName'), 'error');
            return;
        }

        const submitBtn = document.getElementById('group-submit-btn');
        setButtonLoading(submitBtn, true);

        try {
            if (groupId) {
                // Update existing group
                await API.updateGroup(groupId, {
                    name,
                    description: description || null,
                    color,
                    device_ips: selectedDevices
                });
                showToast(I18n.t('toast.groupUpdated'), 'success');
            } else {
                // Create new group
                await API.createGroup(name, description || null, color, selectedDevices);
                showToast(I18n.t('toast.groupCreated'), 'success');
            }

            closeModal('group-modal');
            loadGroups();
        } catch (error) {
            showToast(I18n.t('toast.error.saveGroup', { message: error.message }), 'error');
        } finally {
            setButtonLoading(submitBtn, false);
        }
    });

    window.deleteGroup = async function(groupId) {
        if (!confirm(I18n.t('confirm.deleteGroup'))) {
            return;
        }

        try {
            await API.deleteGroup(groupId);
            showToast(I18n.t('toast.groupDeleted'), 'success');
            loadGroups();
        } catch (error) {
            showToast(I18n.t('toast.error.deleteGroup', { message: error.message }), 'error');
        }
    };

    // =============================================
    // Language Preferences
    // =============================================

    window.saveLanguagePreference = async function() {
        const locale = document.getElementById('language-select').value;
        const success = await I18n.setLocale(locale);
        if (success) {
            showToast(I18n.t('toast.languageSaved'), 'success');
        }
    };

    // Listen for locale changes to re-render dynamic content
    window.addEventListener('localeChanged', async () => {
        // Re-render device table if on devices page
        if (currentPage === 'devices') {
            renderDevicesTable();
            renderGroupsList();
        }
        // Re-render credentials table if on credentials page
        if (currentPage === 'credentials') {
            renderCredentialsTable();
        }
    });

    // =============================================
    // Initialization
    // =============================================

    // Initialize context menu
    initContextMenu();

    // Initialize device page tabs
    initDevicePageTabs();

    // Initial load - call initializeApp which handles auth check
    initializeApp();
});
