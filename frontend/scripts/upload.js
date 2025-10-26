document.addEventListener("DOMContentLoaded", function() {

    const fileUploadInput = document.getElementById('question-file-upload');
    const processButton = document.getElementById('process-button');
    const previewSection = document.getElementById('preview-section');

    // Enable button and show preview when a file is selected
    fileUploadInput.addEventListener('change', () => {
        const fileSelected = fileUploadInput.files.length > 0;
        
        processButton.disabled = !fileSelected;

        if (fileSelected) {
            previewSection.classList.remove('hidden');
            // TODO: Add logic here to actually read the file (CSV, XLSX, JSON) 
            // and populate the table with the real data.
            // The current table content is just static placeholders.
            console.log("File selected:", fileUploadInput.files[0].name); 
        } else {
            previewSection.classList.add('hidden');
        }
    });

    // TODO: Add event listener to processButton to handle the actual upload
    // processButton.addEventListener('click', () => { ... });

});
