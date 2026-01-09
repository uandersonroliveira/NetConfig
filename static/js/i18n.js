// Internationalization (i18n) Module for NetConfig
const I18n = {
    currentLocale: 'en-US',
    translations: {},
    supportedLocales: ['en-US', 'pt-BR'],
    defaultLocale: 'en-US',

    /**
     * Initialize i18n - load saved locale or detect from browser
     */
    async init() {
        // Check localStorage for saved preference
        const savedLocale = localStorage.getItem('netconfig-locale');

        if (savedLocale && this.supportedLocales.includes(savedLocale)) {
            this.currentLocale = savedLocale;
        } else {
            // Detect from browser
            const browserLang = navigator.language || navigator.userLanguage;

            // Check for exact match first
            if (this.supportedLocales.includes(browserLang)) {
                this.currentLocale = browserLang;
            } else {
                // Check for language prefix match (e.g., 'pt' matches 'pt-BR')
                const langPrefix = browserLang.split('-')[0];
                const match = this.supportedLocales.find(l => l.startsWith(langPrefix));
                if (match) {
                    this.currentLocale = match;
                } else {
                    this.currentLocale = this.defaultLocale;
                }
            }
        }

        await this.loadLocale(this.currentLocale);
        this.translatePage();
    },

    /**
     * Load translation file for a locale
     */
    async loadLocale(locale) {
        try {
            const response = await fetch(`/static/locales/${locale}.json`);
            if (!response.ok) {
                throw new Error(`Failed to load locale: ${locale}`);
            }
            this.translations = await response.json();
            this.currentLocale = locale;
        } catch (error) {
            console.error(`Failed to load locale ${locale}:`, error);
            // Fallback to default locale if not already
            if (locale !== this.defaultLocale) {
                console.log(`Falling back to ${this.defaultLocale}`);
                await this.loadLocale(this.defaultLocale);
            }
        }
    },

    /**
     * Get translation for a key with optional parameter interpolation
     * @param {string} key - Dot-notation key (e.g., 'nav.dashboard', 'toast.deviceDeleted')
     * @param {object} params - Optional parameters for interpolation (e.g., { count: 5 })
     * @returns {string} - Translated string or key if not found
     */
    t(key, params = {}) {
        // Navigate nested keys
        const keys = key.split('.');
        let value = this.translations;

        for (const k of keys) {
            if (value && typeof value === 'object' && k in value) {
                value = value[k];
            } else {
                // Key not found, return the key itself for debugging
                console.warn(`Translation missing: ${key}`);
                return key;
            }
        }

        if (typeof value !== 'string') {
            console.warn(`Translation key ${key} is not a string`);
            return key;
        }

        // Interpolate parameters {{param}}
        return value.replace(/\{\{(\w+)\}\}/g, (match, paramKey) => {
            return params.hasOwnProperty(paramKey) ? params[paramKey] : match;
        });
    },

    /**
     * Translate all elements with data-i18n attributes on the page
     */
    translatePage() {
        // Translate text content
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            el.textContent = this.t(key);
        });

        // Translate placeholders
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            el.placeholder = this.t(key);
        });

        // Translate title attributes
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.getAttribute('data-i18n-title');
            el.title = this.t(key);
        });

        // Update language selector if present
        const langSelect = document.getElementById('language-select');
        if (langSelect) {
            langSelect.value = this.currentLocale;
        }
    },

    /**
     * Change locale and persist preference
     */
    async setLocale(locale) {
        if (!this.supportedLocales.includes(locale)) {
            console.error(`Unsupported locale: ${locale}`);
            return false;
        }

        await this.loadLocale(locale);
        localStorage.setItem('netconfig-locale', locale);
        this.translatePage();

        // Dispatch event for dynamic content that needs re-rendering
        window.dispatchEvent(new CustomEvent('localeChanged', { detail: { locale } }));

        return true;
    },

    /**
     * Get current locale
     */
    getLocale() {
        return this.currentLocale;
    },

    /**
     * Get list of supported locales
     */
    getSupportedLocales() {
        return [...this.supportedLocales];
    }
};

// Make I18n available globally
window.I18n = I18n;
