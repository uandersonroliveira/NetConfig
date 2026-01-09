/**
 * ContextMenu - Right-click context menu for device operations
 *
 * Usage:
 *   const menu = new ContextMenu({
 *     onAction: (action, data) => {
 *       // action: 'add-to-new-group', 'add-to-group', 'remove-from-groups'
 *       // data: { devices: [...], groupId: 'optional' }
 *     }
 *   });
 *
 *   // Show menu on right-click
 *   element.addEventListener('contextmenu', (e) => {
 *     e.preventDefault();
 *     menu.show(e.clientX, e.clientY, selectedDevices);
 *   });
 */
class ContextMenu {
    constructor(options = {}) {
        this.menuElement = null;
        this.currentTarget = [];
        this.groups = [];
        this.onAction = options.onAction || (() => {});

        this._createMenu();
        this._bindEvents();
    }

    _createMenu() {
        this.menuElement = document.createElement('div');
        this.menuElement.className = 'context-menu';
        this.menuElement.innerHTML = `
            <div class="context-menu-header">
                <span class="context-menu-count">0 devices selected</span>
            </div>
            <div class="context-menu-divider"></div>
            <div class="context-menu-section">
                <div class="context-menu-item" data-action="add-to-new-group">
                    <span class="context-menu-icon">+</span>
                    <span>Create New Group</span>
                </div>
            </div>
            <div class="context-menu-divider"></div>
            <div class="context-menu-section context-menu-groups">
                <div class="context-menu-label">Add to Group</div>
                <div class="context-menu-groups-list"></div>
            </div>
            <div class="context-menu-divider"></div>
            <div class="context-menu-section">
                <div class="context-menu-item context-menu-item-danger" data-action="remove-from-groups">
                    <span class="context-menu-icon">-</span>
                    <span>Remove from All Groups</span>
                </div>
            </div>
        `;
        document.body.appendChild(this.menuElement);
    }

    async show(x, y, selectedDevices) {
        if (!selectedDevices || selectedDevices.length === 0) {
            return;
        }

        this.currentTarget = selectedDevices;

        // Update selection count
        const countEl = this.menuElement.querySelector('.context-menu-count');
        countEl.textContent = `${selectedDevices.length} device${selectedDevices.length !== 1 ? 's' : ''} selected`;

        // Load and display groups
        await this._updateGroupsList();

        // Position menu
        this.menuElement.style.left = x + 'px';
        this.menuElement.style.top = y + 'px';
        this.menuElement.classList.add('active');

        // Adjust if off-screen
        requestAnimationFrame(() => {
            const rect = this.menuElement.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
                this.menuElement.style.left = (x - rect.width) + 'px';
            }
            if (rect.bottom > window.innerHeight) {
                this.menuElement.style.top = (y - rect.height) + 'px';
            }
        });
    }

    hide() {
        this.menuElement.classList.remove('active');
    }

    async _updateGroupsList() {
        const groupsListEl = this.menuElement.querySelector('.context-menu-groups-list');

        try {
            const response = await API.getGroups();
            this.groups = response.groups || [];

            if (this.groups.length === 0) {
                groupsListEl.innerHTML = `
                    <div class="context-menu-empty">No groups available</div>
                `;
            } else {
                groupsListEl.innerHTML = this.groups.map(g => `
                    <div class="context-menu-item" data-action="add-to-group" data-group-id="${g.id}">
                        <span class="context-menu-color" style="background: ${g.color || '#6b7280'}"></span>
                        <span>${this._escapeHtml(g.name)}</span>
                        <span class="context-menu-badge">${g.device_count}</span>
                    </div>
                `).join('');
            }
        } catch (error) {
            console.error('Failed to load groups:', error);
            groupsListEl.innerHTML = `
                <div class="context-menu-empty">Failed to load groups</div>
            `;
        }
    }

    _escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    _bindEvents() {
        // Close on click outside
        document.addEventListener('click', (e) => {
            if (!this.menuElement.contains(e.target)) {
                this.hide();
            }
        });

        // Close on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hide();
            }
        });

        // Handle menu item clicks
        this.menuElement.addEventListener('click', (e) => {
            const item = e.target.closest('.context-menu-item');
            if (!item) return;

            const action = item.dataset.action;
            const groupId = item.dataset.groupId;

            this.onAction(action, {
                devices: this.currentTarget,
                groupId: groupId
            });

            this.hide();
        });

        // Prevent default context menu on the context menu itself
        this.menuElement.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });
    }

    // Update available groups (can be called externally when groups change)
    async refreshGroups() {
        await this._updateGroupsList();
    }

    destroy() {
        if (this.menuElement) {
            this.menuElement.remove();
        }
    }
}

// Export to window for global access
window.ContextMenu = ContextMenu;
