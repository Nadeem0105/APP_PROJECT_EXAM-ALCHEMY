document.addEventListener("DOMContentLoaded", function() {

    // --- Test Data (Replace with data fetched from backend later) ---
    const questions = [
        {
            id: 1,
            question: "What is the derivative of x²?",
            options: ["2x", "x", "2x²", "x²"],
            correct: "2x", // Store correct answer if needed for review
            selected: null // Store user's selection
        },
        {
            id: 2,
            question: "Solve: 2x + 5 = 15",
            options: ["5", "10", "7.5", "20"],
            correct: "5",
            selected: null
        },
        {
            id: 3,
            question: "What is the square root of 144?",
            options: ["10", "11", "12", "13"],
            correct: "12",
            selected: null
        },
        {
            id: 4,
            question: "What is 7 * 8?",
            options: ["49", "54", "56", "64"],
            correct: "56",
            selected: null
        },
        {
            id: 5,
            question: "Simplify: 3(x + 2)",
            options: ["3x + 2", "3x + 6", "x + 6", "3x + 5"],
            correct: "3x + 6",
            selected: null
        },
    ];
    const totalQuestions = questions.length;

    // --- State Variables ---
    let currentQuestionIndex = 0; // 0-based index
    let submitted = false;

    // --- DOM Elements ---
    const testView = document.getElementById('test-view');
    const resultsView = document.getElementById('results-view');
    
    const questionCounter = document.getElementById('question-counter');
    const progressBar = document.getElementById('progress-bar');
    const questionNumber = document.getElementById('question-number');
    const questionText = document.getElementById('question-text');
    const optionsContainer = document.getElementById('options-container');
    
    const prevButton = document.getElementById('prev-button');
    const nextButton = document.getElementById('next-button');
    const submitButton = document.getElementById('submit-button');

    // --- Functions ---

    function displayQuestion(index) {
        if (index < 0 || index >= totalQuestions) return;

        const question = questions[index];
        currentQuestionIndex = index;

        // Update progress
        const progressPercent = ((index + 1) / totalQuestions) * 100;
        progressBar.style.width = `${progressPercent}%`;
        questionCounter.textContent = `Question ${index + 1} of ${totalQuestions}`;

        // Update question details
        questionNumber.textContent = `Question ${index + 1}`;
        questionText.textContent = question.question;

        // Update options
        optionsContainer.innerHTML = ''; // Clear previous options
        question.options.forEach((option, optionIndex) => {
            const optionId = `q${index}-option${optionIndex}`;
            
            const optionDiv = document.createElement('div');
            optionDiv.className = 'option-item';
            
            const radioInput = document.createElement('input');
            radioInput.type = 'radio';
            radioInput.id = optionId;
            radioInput.name = `question-${index}`;
            radioInput.value = option;
            radioInput.checked = (question.selected === option); // Restore selection
            radioInput.addEventListener('change', () => {
                questions[currentQuestionIndex].selected = option; // Store selection
            });

            const label = document.createElement('label');
            label.htmlFor = optionId;
            label.textContent = option;

            optionDiv.appendChild(radioInput);
            optionDiv.appendChild(label);
            optionsContainer.appendChild(optionDiv);
        });

        // Update button states
        prevButton.disabled = (index === 0);
        nextButton.style.display = (index === totalQuestions - 1) ? 'none' : 'block';
        submitButton.style.display = (index === totalQuestions - 1) ? 'block' : 'none';
    }

    function showResults() {
        submitted = true;
        testView.style.display = 'none';
        resultsView.style.display = 'block';

        // TODO: Calculate score based on stored selections vs correct answers
        // For now, using placeholder values from the HTML
    }

    // --- Event Listeners ---
    prevButton.addEventListener('click', () => {
        displayQuestion(currentQuestionIndex - 1);
    });

    nextButton.addEventListener('click', () => {
        displayQuestion(currentQuestionIndex + 1);
    });

    submitButton.addEventListener('click', () => {
        // Optional: Confirmation dialog
        // if (confirm("Are you sure you want to submit the test?")) {
            showResults();
        // }
    });

    // --- Initial Load ---
    displayQuestion(0);

    // TODO: Add Timer Logic
});
