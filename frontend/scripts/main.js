// Wait for the entire HTML document to be loaded
document.addEventListener("DOMContentLoaded", function() {

    // --- 1. DASHBOARD PAGE LOGIC (SIDEBAR) ---
    
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar');

    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            document.body.classList.toggle('sidebar-collapsed');
        });
    }

    // --- 2. LOGIN PAGE (ROLE TOGGLE) ---
    const roleToggles = document.querySelectorAll('.toggle-btn');
    if (roleToggles.length > 0) {
        roleToggles.forEach(toggle => {
            toggle.addEventListener('click', () => {
                roleToggles.forEach(t => t.classList.remove('active'));
                toggle.classList.add('active');
            });
        });
    }

});