/**
 * SelectionManager - Unified selection handling for device lists
 *
 * Supports:
 * - Checkbox selection
 * - Shift+Click range selection
 * - Ctrl+Click toggle selection
 * - Shift+Arrow keyboard navigation
 * - Click+Drag marquee selection
 *
 * Usage:
 *   const manager = new SelectionManager({
 *     container: document.getElementById('devices-tbody'),
 *     itemSelector: 'tr[data-device-ip]',
 *     checkboxSelector: '.device-checkbox',
 *     onSelectionChange: (selectedItems) => { ... },
 *     enableMarquee: true,
 *     enableKeyboardNav: true
 *   });
 */
class SelectionManager {
    constructor(options) {
        this.container = options.container;
        this.itemSelector = options.itemSelector || 'tr[data-device-ip]';
        this.checkboxSelector = options.checkboxSelector || '.device-checkbox';
        this.onSelectionChange = options.onSelectionChange || (() => {});
        this.enableMarquee = options.enableMarquee !== false;
        this.enableKeyboardNav = options.enableKeyboardNav !== false;

        this.selectedItems = new Set();
        this.lastSelectedIndex = -1;
        this.isMarqueeActive = false;
        this.marqueeStart = { x: 0, y: 0 };
        this.marqueeElement = null;
        this.focusedIndex = -1;

        this._boundHandlers = {};
        this._init();
    }

    _init() {
        this._bindCheckboxEvents();
        this._bindClickEvents();
        if (this.enableKeyboardNav) {
            this._bindKeyboardEvents();
        }
        if (this.enableMarquee) {
            this._initMarquee();
        }
    }

    // Get all selectable items
    _getItems() {
        return Array.from(this.container.querySelectorAll(this.itemSelector));
    }

    // Get value from item (device IP)
    _getItemValue(item) {
        return item.dataset.deviceIp || item.querySelector(this.checkboxSelector)?.value;
    }

    // Get checkbox for item
    _getCheckbox(item) {
        return item.querySelector(this.checkboxSelector);
    }

    // Selection methods
    getSelectedItems() {
        return Array.from(this.selectedItems);
    }

    getSelectedValues() {
        return this.getSelectedItems().map(item => this._getItemValue(item));
    }

    getSelectedCount() {
        return this.selectedItems.size;
    }

    selectItem(item) {
        if (!item) return;
        this.selectedItems.add(item);
        item.classList.add('selected');
        const checkbox = this._getCheckbox(item);
        if (checkbox) checkbox.checked = true;
    }

    deselectItem(item) {
        if (!item) return;
        this.selectedItems.delete(item);
        item.classList.remove('selected');
        const checkbox = this._getCheckbox(item);
        if (checkbox) checkbox.checked = false;
    }

    toggleItem(item) {
        if (this.selectedItems.has(item)) {
            this.deselectItem(item);
        } else {
            this.selectItem(item);
        }
    }

    selectAll() {
        const items = this._getItems();
        items.forEach(item => this.selectItem(item));
        this._notifyChange();
    }

    deselectAll() {
        const items = this._getItems();
        items.forEach(item => this.deselectItem(item));
        this.selectedItems.clear();
        this._notifyChange();
    }

    selectRange(startIndex, endIndex) {
        const items = this._getItems();
        const start = Math.min(startIndex, endIndex);
        const end = Math.max(startIndex, endIndex);

        for (let i = start; i <= end; i++) {
            if (items[i]) {
                this.selectItem(items[i]);
            }
        }
    }

    // Update selection state from checkboxes (for external changes)
    syncFromCheckboxes() {
        const items = this._getItems();
        this.selectedItems.clear();
        items.forEach(item => {
            const checkbox = this._getCheckbox(item);
            if (checkbox && checkbox.checked) {
                this.selectedItems.add(item);
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        });
        this._notifyChange();
    }

    // Event handlers
    _bindCheckboxEvents() {
        this._boundHandlers.checkboxChange = (e) => {
            if (!e.target.matches(this.checkboxSelector)) return;

            const item = e.target.closest(this.itemSelector);
            if (!item) return;

            if (e.target.checked) {
                this.selectItem(item);
            } else {
                this.deselectItem(item);
            }

            const items = this._getItems();
            this.lastSelectedIndex = items.indexOf(item);
            this._notifyChange();
        };

        this.container.addEventListener('change', this._boundHandlers.checkboxChange);
    }

    _bindClickEvents() {
        this._boundHandlers.click = (e) => {
            // Don't handle if clicking on checkbox directly
            if (e.target.matches(this.checkboxSelector)) return;
            // Don't handle if clicking on buttons or links
            if (e.target.matches('button, a, input, select')) return;

            const item = e.target.closest(this.itemSelector);
            if (!item) return;

            const items = this._getItems();
            const currentIndex = items.indexOf(item);

            if (e.shiftKey && this.lastSelectedIndex !== -1) {
                // Range selection
                if (!e.ctrlKey && !e.metaKey) {
                    this.deselectAll();
                }
                this.selectRange(this.lastSelectedIndex, currentIndex);
            } else if (e.ctrlKey || e.metaKey) {
                // Toggle single item
                this.toggleItem(item);
            } else {
                // Single select - only if clicking on the row itself
                this.deselectAll();
                this.selectItem(item);
            }

            this.lastSelectedIndex = currentIndex;
            this.focusedIndex = currentIndex;
            this._notifyChange();
        };

        this.container.addEventListener('click', this._boundHandlers.click);
    }

    _bindKeyboardEvents() {
        this.container.setAttribute('tabindex', '0');

        this._boundHandlers.keydown = (e) => {
            if (!['ArrowUp', 'ArrowDown', 'Space', 'Enter', 'a', 'A'].includes(e.key)) return;

            const items = this._getItems();
            if (items.length === 0) return;

            // Ctrl+A to select all
            if ((e.ctrlKey || e.metaKey) && (e.key === 'a' || e.key === 'A')) {
                e.preventDefault();
                this.selectAll();
                return;
            }

            // Arrow navigation
            if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                e.preventDefault();

                let newIndex = this.focusedIndex;
                if (e.key === 'ArrowDown') {
                    newIndex = Math.min(newIndex + 1, items.length - 1);
                } else {
                    newIndex = Math.max(newIndex - 1, 0);
                }

                if (newIndex < 0) newIndex = 0;

                if (e.shiftKey) {
                    // Extend selection
                    if (this.lastSelectedIndex === -1) {
                        this.lastSelectedIndex = this.focusedIndex >= 0 ? this.focusedIndex : 0;
                    }
                    this.selectRange(this.lastSelectedIndex, newIndex);
                } else {
                    // Move focus without selection change
                    this.deselectAll();
                    this.selectItem(items[newIndex]);
                    this.lastSelectedIndex = newIndex;
                }

                this.focusedIndex = newIndex;

                // Scroll item into view
                items[newIndex].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
                this._updateFocusIndicator(items, newIndex);
                this._notifyChange();
            }

            // Space/Enter to toggle selection
            if ((e.key === 'Space' || e.key === 'Enter') && this.focusedIndex >= 0) {
                e.preventDefault();
                const item = items[this.focusedIndex];
                this.toggleItem(item);
                this.lastSelectedIndex = this.focusedIndex;
                this._notifyChange();
            }
        };

        this.container.addEventListener('keydown', this._boundHandlers.keydown);
    }

    _updateFocusIndicator(items, focusedIndex) {
        items.forEach((item, idx) => {
            item.classList.toggle('focused', idx === focusedIndex);
        });
    }

    _initMarquee() {
        // Create marquee overlay element
        this.marqueeElement = document.createElement('div');
        this.marqueeElement.className = 'selection-marquee';
        document.body.appendChild(this.marqueeElement);

        this._boundHandlers.mousedown = (e) => {
            // Left click only
            if (e.button !== 0) return;
            // Don't start marquee on interactive elements
            if (e.target.matches('input, button, a, select, textarea')) return;
            // Only start if clicking on the container or an item
            if (!this.container.contains(e.target)) return;

            this._startMarquee(e);
        };

        this._boundHandlers.mousemove = (e) => {
            if (this.isMarqueeActive) {
                this._updateMarquee(e);
            }
        };

        this._boundHandlers.mouseup = (e) => {
            if (this.isMarqueeActive) {
                this._endMarquee(e);
            }
        };

        this.container.addEventListener('mousedown', this._boundHandlers.mousedown);
        document.addEventListener('mousemove', this._boundHandlers.mousemove);
        document.addEventListener('mouseup', this._boundHandlers.mouseup);
    }

    _startMarquee(e) {
        // Only start marquee if not clicking directly on an item
        const item = e.target.closest(this.itemSelector);
        if (item) return;

        this.isMarqueeActive = true;
        this.marqueeStart = { x: e.clientX, y: e.clientY };

        if (!e.ctrlKey && !e.metaKey && !e.shiftKey) {
            this.deselectAll();
        }

        this.marqueeElement.style.display = 'block';
        this.marqueeElement.style.left = e.clientX + 'px';
        this.marqueeElement.style.top = e.clientY + 'px';
        this.marqueeElement.style.width = '0px';
        this.marqueeElement.style.height = '0px';
    }

    _updateMarquee(e) {
        const x = Math.min(this.marqueeStart.x, e.clientX);
        const y = Math.min(this.marqueeStart.y, e.clientY);
        const width = Math.abs(e.clientX - this.marqueeStart.x);
        const height = Math.abs(e.clientY - this.marqueeStart.y);

        this.marqueeElement.style.left = x + 'px';
        this.marqueeElement.style.top = y + 'px';
        this.marqueeElement.style.width = width + 'px';
        this.marqueeElement.style.height = height + 'px';

        // Highlight items within marquee
        const marqueeRect = { left: x, top: y, right: x + width, bottom: y + height };
        const items = this._getItems();

        items.forEach(item => {
            const itemRect = item.getBoundingClientRect();
            const intersects = this._rectsIntersect(marqueeRect, itemRect);
            item.classList.toggle('selection-preview', intersects);
        });
    }

    _endMarquee(e) {
        this.isMarqueeActive = false;
        this.marqueeElement.style.display = 'none';

        // Select items within marquee
        const items = this._getItems();
        items.forEach(item => {
            if (item.classList.contains('selection-preview')) {
                this.selectItem(item);
                item.classList.remove('selection-preview');
            }
        });

        this._notifyChange();
    }

    _rectsIntersect(rect1, rect2) {
        return !(
            rect1.right < rect2.left ||
            rect1.left > rect2.right ||
            rect1.bottom < rect2.top ||
            rect1.top > rect2.bottom
        );
    }

    _notifyChange() {
        this.onSelectionChange(this.getSelectedValues(), this.getSelectedCount());
        this._updateSelectAllCheckbox();
    }

    _updateSelectAllCheckbox() {
        const selectAllCheckbox = this.container.closest('table')?.querySelector('thead input[type="checkbox"]');
        if (!selectAllCheckbox) return;

        const items = this._getItems();
        const selectedCount = this.getSelectedCount();

        if (selectedCount === 0) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = false;
        } else if (selectedCount === items.length) {
            selectAllCheckbox.checked = true;
            selectAllCheckbox.indeterminate = false;
        } else {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = true;
        }
    }

    // Cleanup
    destroy() {
        if (this._boundHandlers.checkboxChange) {
            this.container.removeEventListener('change', this._boundHandlers.checkboxChange);
        }
        if (this._boundHandlers.click) {
            this.container.removeEventListener('click', this._boundHandlers.click);
        }
        if (this._boundHandlers.keydown) {
            this.container.removeEventListener('keydown', this._boundHandlers.keydown);
        }
        if (this._boundHandlers.mousedown) {
            this.container.removeEventListener('mousedown', this._boundHandlers.mousedown);
        }
        if (this._boundHandlers.mousemove) {
            document.removeEventListener('mousemove', this._boundHandlers.mousemove);
        }
        if (this._boundHandlers.mouseup) {
            document.removeEventListener('mouseup', this._boundHandlers.mouseup);
        }
        if (this.marqueeElement) {
            this.marqueeElement.remove();
        }
    }

    // Re-initialize after table re-render
    refresh() {
        this.selectedItems.clear();
        this.lastSelectedIndex = -1;
        this.focusedIndex = -1;
    }
}

// Export to window for global access
window.SelectionManager = SelectionManager;
