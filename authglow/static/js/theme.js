// Theme Management for AuthGlow
(function() {
    'use strict';

    const setTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('authglow-theme', theme);
        updateThemeToggle(theme);
    };

    const updateThemeToggle = (theme) => {
        const toggle = document.querySelector('.theme-toggle');
        if (toggle) {
            toggle.innerHTML = theme === 'dark' ? '☀️' : '🌙';
            toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
        }
    };

    const toggleTheme = () => {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    };

    // This function creates and initializes the theme toggle button
    const initThemeToggle = () => {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';

        // Create theme toggle button if it doesn't exist
        if (!document.querySelector('.theme-toggle')) {
            const toggle = document.createElement('button');
            toggle.className = 'theme-toggle';
            document.body.appendChild(toggle);
        }
        
        const toggleButton = document.querySelector('.theme-toggle');
        toggleButton.onclick = toggleTheme;
        updateThemeToggle(currentTheme);
    };

    // Initialize the toggle button when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initThemeToggle);
    } else {
        initThemeToggle();
    }

    // Export for use in other scripts
    window.AuthGlowTheme = {
        set: setTheme,
        toggle: toggleTheme
    };
})();