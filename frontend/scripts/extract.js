document.addEventListener("DOMContentLoaded", function() {

    const extractButton = document.getElementById('extract-button');
    const extractButtonContent = document.getElementById('extract-button-content');
    const extractingIndicator = document.getElementById('extracting-indicator');
    const resultsPlaceholder = document.getElementById('results-placeholder');
    const resultsContent = document.getElementById('results-content');
    const pdfUploadInput = document.getElementById('pdf-upload');

    let isExtracting = false;
    let fileSelected = false;

    // Check if a file is selected
    pdfUploadInput.addEventListener('change', () => {
        fileSelected = pdfUploadInput.files.length > 0;
    });

    // Handle extraction button click
    extractButton.addEventListener('click', () => {
        if (isExtracting || !fileSelected) {
             if (!fileSelected) {
                 alert("Please select a PDF file first.");
             }
            return;
        }

        isExtracting = true;
        
        // Show loading state
        extractButtonContent.classList.add('hidden');
        extractingIndicator.classList.remove('hidden');
        extractButton.disabled = true;

        // Hide placeholder, keep results hidden for now
        resultsPlaceholder.classList.add('hidden');
        resultsContent.classList.add('hidden');

        // --- Simulate AI Extraction (Replace with actual API call) ---
        console.log("Simulating AI extraction...");
        setTimeout(() => {
            console.log("Extraction complete!");

            // Hide loading state
            extractButtonContent.classList.remove('hidden');
            extractingIndicator.classList.add('hidden');
            extractButton.disabled = false;
            isExtracting = false;

            // Show results
            resultsContent.classList.remove('hidden');
            resultsContent.classList.add('animate-fade-in'); // Add fade-in animation

            // TODO: Populate resultsContent with actual extracted questions 
            // from your backend API response. The current content is just placeholder.

        }, 3000); // Simulate 3 seconds processing time
        // --- End Simulation ---
    });

});
