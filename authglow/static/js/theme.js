// Theme Management for AuthGlow
(function() {
    'use strict';

    // Get saved theme or default to light
    const getTheme = () => {
        return localStorage.getItem('authglow-theme') || 'light';
    };

    // Set theme
    const setTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('authglow-theme', theme);
        updateThemeToggle(theme);
    };

    // Update theme toggle button
    const updateThemeToggle = (theme) => {
        const toggle = document.querySelector('.theme-toggle');
        if (toggle) {
            toggle.innerHTML = theme === 'dark' ? '☀️' : '🌙';
            toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
        }
    };

    // Toggle theme
    const toggleTheme = () => {
        const currentTheme = getTheme();
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    };

    // Initialize theme on page load
    const initTheme = () => {
        const theme = getTheme();
        setTheme(theme);

        // Create theme toggle button if it doesn't exist
        if (!document.querySelector('.theme-toggle')) {
            const toggle = document.createElement('button');
            toggle.className = 'theme-toggle';
            toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
            toggle.onclick = toggleTheme;
            document.body.appendChild(toggle);
        } else {
            document.querySelector('.theme-toggle').onclick = toggleTheme;
        }

        updateThemeToggle(theme);
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTheme);
    } else {
        initTheme();
    }

    // Export for use in other scripts
    window.AuthGlowTheme = {
        get: getTheme,
        set: setTheme,
        toggle: toggleTheme
    };
})();
