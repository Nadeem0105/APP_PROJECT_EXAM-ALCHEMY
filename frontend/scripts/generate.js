document.addEventListener("DOMContentLoaded", function() {

    // --- Element Selectors ---
    const easySlider = document.getElementById('easy-slider');
    const easyValueDisplay = document.getElementById('easy-value');
    const mediumSlider = document.getElementById('medium-slider');
    const mediumValueDisplay = document.getElementById('medium-value');
    const hardSlider = document.getElementById('hard-slider');
    const hardValueDisplay = document.getElementById('hard-value');

    const generateButton = document.getElementById('generate-button');
    const generateButtonContent = document.getElementById('generate-button-content');
    const generatingIndicator = document.getElementById('generating-indicator');
    
    const previewPlaceholder = document.getElementById('preview-placeholder');
    const previewContent = document.getElementById('preview-content');

    let isLoading = false;

    // --- Slider Value Update Logic ---
    function updateSliderValue(slider, display) {
        display.textContent = `${slider.value}%`;
    }

    easySlider.addEventListener('input', () => updateSliderValue(easySlider, easyValueDisplay));
    mediumSlider.addEventListener('input', () => updateSliderValue(mediumSlider, mediumValueDisplay));
    hardSlider.addEventListener('input', () => updateSliderValue(hardSlider, hardValueDisplay));

    // --- Generate Button Click Logic ---
    generateButton.addEventListener('click', () => {
        if (isLoading) return;

        isLoading = true;

        // Show loading state
        generateButtonContent.classList.add('hidden');
        generatingIndicator.classList.remove('hidden');
        generateButton.disabled = true;

        // Hide placeholder, keep preview hidden for now
        previewPlaceholder.classList.add('hidden');
        previewContent.classList.add('hidden');

        // --- Simulate AI Generation (Replace with actual API call) ---
        console.log("Simulating paper generation...");
        setTimeout(() => {
            console.log("Generation complete!");

            // Hide loading state
            generateButtonContent.classList.remove('hidden');
            generatingIndicator.classList.add('hidden');
            generateButton.disabled = false;
            isLoading = false;

            // Show preview content
            previewContent.classList.remove('hidden');
            previewContent.classList.add('animate-fade-in');

            // TODO: Populate previewContent with actual generated paper data 
            // from your backend API response. The current content is just placeholder.

        }, 2000); // Simulate 2 seconds processing time
        // --- End Simulation ---
    });

});
