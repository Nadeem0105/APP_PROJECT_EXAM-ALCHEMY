document.addEventListener("DOMContentLoaded", function() {

    // --- Sidebar Toggle ---
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');

    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            document.body.classList.toggle('sidebar-collapsed');
        });
    }

    // --- Login Page Role Toggle ---
    const roleToggles = document.querySelectorAll('.toggle-btn');
    if (roleToggles.length > 0) {
        roleToggles.forEach(toggle => {
            toggle.addEventListener('click', () => {
                // Remove active class from all
                roleToggles.forEach(t => t.classList.remove('active'));
                // Add active class to clicked one
                toggle.classList.add('active');
                
                const role = toggle.dataset.role;
                console.log("Selected role:", role);
                // You can change the form action or fields based on the role here
            });
        });
    }

    // --- Placeholder for API calls to Spring Boot ---

    // Example: Function to handle paper generation
    async function generatePaper(settings) {
        // 1. Show loading animation
        console.log("Generating paper...", settings);
        
        // 2. Prepare API request
        const requestOptions = {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                // 'Authorization': 'Bearer YOUR_AUTH_TOKEN' // If you use security
            },
            body: JSON.stringify(settings)
        };

        try {
            // 3. Call your Spring Boot API
            const response = await fetch('/api/v1/papers/generate', requestOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            // 4. Get the generated paper data (e.g., in JSON format)
            const paperData = await response.json();
            
            // 5. Hide loading animation and display the data
            console.log("Paper generated:", paperData);
            // displayPaperPreview(paperData); // A function you would write
            
        } catch (error) {
            // 6. Handle errors
            console.error("Failed to generate paper:", error);
            // ShowErrorModal("Could not generate paper. Please try again.");
        }
    }
    
    // Example of hooking it to a button (if it existed)
    // const genButton = document.getElementById('generate-btn');
    // if (genButton) {
    //     genButton.addEventListener('click', () => {
    //         const settings = {
    //             totalMarks: 100,
    //             difficulty: { easy: 30, medium: 50, hard: 20 },
    //             type: 'MCQ'
    //         };
    //         generatePaper(settings);
    //     });
    // }

});