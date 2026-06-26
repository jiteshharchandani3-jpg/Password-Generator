/**
 * Password Generator Application
 * Modern, secure password generator with customizable options
 * Uses crypto.getRandomValues() for cryptographically secure randomness
 */

// ============================================
// State Management
// ============================================
const state = {
    currentPassword: '',
    passwordHistory: [],
    isDarkTheme: true,
    maxHistoryLength: 5
};

// ============================================
// DOM Elements
// ============================================
const elements = {
    // Input elements
    lengthSlider: document.getElementById('lengthSlider'),
    uppercase: document.getElementById('uppercase'),
    lowercase: document.getElementById('lowercase'),
    numbers: document.getElementById('numbers'),
    symbols: document.getElementById('symbols'),
    excludeSimilar: document.getElementById('excludeSimilar'),
    generateTypeRadios: document.querySelectorAll('input[name="generateType"]'),
    
    // Display elements
    passwordDisplay: document.getElementById('passwordDisplay'),
    lengthDisplay: document.getElementById('lengthDisplay'),
    strengthText: document.getElementById('strengthText'),
    strengthBar: document.getElementById('strengthBar'),
    entropyText: document.getElementById('entropyText'),
    errorMessage: document.getElementById('errorMessage'),
    
    // Buttons
    generateBtn: document.getElementById('generateBtn'),
    regenerateBtn: document.getElementById('regenerateBtn'),
    copyBtn: document.getElementById('copyBtn'),
    togglePassword: document.getElementById('togglePassword'),
    themeToggle: document.querySelector('.theme-toggle'),
    clearHistoryBtn: document.getElementById('clearHistoryBtn'),
    
    // Notifications
    toast: document.getElementById('toast'),
    
    // History
    historyList: document.getElementById('historyList')
};

// ============================================
// Character Sets
// ============================================
const charSets = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-={}[]<>?/',
    
    // For pronounceable passwords
    consonants: 'bcdfghjklmnprstvwxyz',
    vowels: 'aeiou',
    
    // Characters to exclude when similar characters option is selected
    similarChars: 'ilLo0O1',
};

// ============================================
// Initialize Application
// ============================================
function init() {
    // Load theme preference
    loadTheme();
    
    // Load password history from localStorage
    loadHistory();
    
    // Attach event listeners
    attachEventListeners();
    
    // Set initial slider display
    updateLengthDisplay();
    
    // Generate initial password
    generatePassword();
}

// ============================================
// Event Listeners
// ============================================
function attachEventListeners() {
    // Length slider
    elements.lengthSlider.addEventListener('input', updateLengthDisplay);
    
    // Generate buttons
    elements.generateBtn.addEventListener('click', generatePassword);
    elements.regenerateBtn.addEventListener('click', generatePassword);
    
    // Copy button
    elements.copyBtn.addEventListener('click', copyPassword);
    
    // Password toggle
    elements.togglePassword.addEventListener('click', togglePasswordVisibility);
    
    // Theme toggle
    elements.themeToggle.addEventListener('click', toggleTheme);
    
    // Clear history
    elements.clearHistoryBtn.addEventListener('click', clearHistory);
    
    // Update password strength on input changes
    elements.lengthSlider.addEventListener('change', generatePassword);
    elements.uppercase.addEventListener('change', generatePassword);
    elements.lowercase.addEventListener('change', generatePassword);
    elements.numbers.addEventListener('change', generatePassword);
    elements.symbols.addEventListener('change', generatePassword);
    elements.excludeSimilar.addEventListener('change', generatePassword);
    elements.generateTypeRadios.forEach(radio => {
        radio.addEventListener('change', generatePassword);
    });
    
    // Keyboard accessibility
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey || e.metaKey) {
            if (e.key === 'g' || e.key === 'G') {
                e.preventDefault();
                generatePassword();
            }
            if (e.key === 'c' || e.key === 'C') {
                e.preventDefault();
                copyPassword();
            }
        }
    });
}

// ============================================
// Password Generation Functions
// ============================================

/**
 * Main password generation function
 * Validates options and generates password based on selected type
 */
function generatePassword() {
    clearError();
    
    // Validate that at least one character set is selected
    const hasUppercase = elements.uppercase.checked;
    const hasLowercase = elements.lowercase.checked;
    const hasNumbers = elements.numbers.checked;
    const hasSymbols = elements.symbols.checked;
    
    if (!hasUppercase && !hasLowercase && !hasNumbers && !hasSymbols) {
        showError('Please select at least one character type');
        return;
    }
    
    const length = parseInt(elements.lengthSlider.value);
    const generateType = document.querySelector('input[name="generateType"]:checked').value;
    
    let password = '';
    
    switch (generateType) {
        case 'pronounceable':
            password = generatePronounceable(length);
            break;
        case 'pin':
            password = generatePIN(length);
            break;
        default:
            password = generateRandom(length, {
                uppercase: hasUppercase,
                lowercase: hasLowercase,
                numbers: hasNumbers,
                symbols: hasSymbols
            });
    }
    
    state.currentPassword = password;
    elements.passwordDisplay.value = password;
    
    // Update strength indicator and entropy
    updateStrengthIndicator(password, length);
    
    // Update history
    addToHistory(password);
}

/**
 * Generate random password with selected character sets
 * Uses crypto.getRandomValues() for secure randomness
 * @param {number} length - Password length
 * @param {object} options - Character set options
 * @returns {string} Generated password
 */
function generateRandom(length, options) {
    let charset = '';
    
    if (options.uppercase) charset += charSets.uppercase;
    if (options.lowercase) charset += charSets.lowercase;
    if (options.numbers) charset += charSets.numbers;
    if (options.symbols) charset += charSets.symbols;
    
    // Remove similar characters if option is selected
    if (elements.excludeSimilar.checked) {
        charset = charset.split('').filter(char => !charSets.similarChars.includes(char)).join('');
    }
    
    if (charset.length === 0) {
        showError('No valid characters available with current options');
        return '';
    }
    
    let password = '';
    
    // Ensure at least one character from each selected set (if multiple selected)
    const selectedSets = [];
    if (options.uppercase) selectedSets.push(charSets.uppercase);
    if (options.lowercase) selectedSets.push(charSets.lowercase);
    if (options.numbers) selectedSets.push(charSets.numbers);
    if (options.symbols) selectedSets.push(charSets.symbols);
    
    // Add at least one char from each set
    for (let set of selectedSets) {
        if (elements.excludeSimilar.checked) {
            set = set.split('').filter(char => !charSets.similarChars.includes(char)).join('');
        }
        if (set.length > 0) {
            password += getRandomCharacter(set);
        }
    }
    
    // Fill remaining length with random characters
    for (let i = password.length; i < length; i++) {
        password += getRandomCharacter(charset);
    }
    
    // Shuffle password using Fisher-Yates algorithm
    password = shuffleString(password);
    
    return password;
}

/**
 * Generate pronounceable password (consonant-vowel pattern)
 * @param {number} length - Password length
 * @returns {string} Generated pronounceable password
 */
function generatePronounceable(length) {
    let password = '';
    let useConsonant = Math.random() > 0.5;
    
    for (let i = 0; i < length; i++) {
        if (useConsonant) {
            password += getRandomCharacter(charSets.consonants);
        } else {
            password += getRandomCharacter(charSets.vowels);
        }
        useConsonant = !useConsonant;
    }
    
    // Capitalize some letters for randomness
    if (elements.uppercase.checked) {
        const randomIndices = [];
        for (let i = 0; i < Math.ceil(length / 3); i++) {
            randomIndices.push(getRandomIndex(length));
        }
        password = password.split('').map((char, index) => 
            randomIndices.includes(index) ? char.toUpperCase() : char
        ).join('');
    }
    
    return password;
}

/**
 * Generate PIN (numeric only)
 * @param {number} length - PIN length
 * @returns {string} Generated PIN
 */
function generatePIN(length) {
    let pin = '';
    for (let i = 0; i < length; i++) {
        pin += getRandomCharacter(charSets.numbers);
    }
    return pin;
}

/**
 * Get random character from string using crypto API
 * Ensures cryptographically secure randomness
 * @param {string} str - String to pick from
 * @returns {string} Random character
 */
function getRandomCharacter(str) {
    if (!str || str.length === 0) return '';
    
    const randomIndex = getRandomIndex(str.length);
    return str[randomIndex];
}

/**
 * Get cryptographically secure random index
 * @param {number} max - Maximum value (exclusive)
 * @returns {number} Random index
 */
function getRandomIndex(max) {
    const randomBuffer = new Uint32Array(1);
    crypto.getRandomValues(randomBuffer);
    return randomBuffer[0] % max;
}

/**
 * Shuffle string using Fisher-Yates algorithm
 * @param {string} str - String to shuffle
 * @returns {string} Shuffled string
 */
function shuffleString(str) {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
        const j = getRandomIndex(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
}

// ============================================
// Password Strength & Entropy Calculation
// ============================================

/**
 * Calculate password strength and update UI
 * @param {string} password - Password to analyze
 * @param {number} length - Password length
 */
function updateStrengthIndicator(password, length) {
    const strength = calculateStrength(password, length);
    const entropy = calculateEntropy(password, length);
    
    // Update strength text and bar
    elements.strengthText.textContent = strength.level;
    elements.strengthBar.style.width = strength.percentage + '%';
    elements.strengthBar.style.background = strength.gradient;
    
    // Update entropy text
    elements.entropyText.textContent = `Entropy: ${entropy.toFixed(2)} bits`;
}

/**
 * Calculate password strength based on various factors
 * @param {string} password - Password to analyze
 * @param {number} length - Password length
 * @returns {object} Strength information
 */
function calculateStrength(password, length) {
    let score = 0;
    const maxScore = 100;
    
    // Length scoring
    if (length >= 32) score += 30;
    else if (length >= 16) score += 25;
    else if (length >= 12) score += 20;
    else if (length >= 8) score += 15;
    else score += 10;
    
    // Character variety scoring
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSymbols = /[!@#$%^&*()_+\-=\[\]{}\\|;:'",.<>/?]/.test(password);
    
    if (hasUpper) score += 15;
    if (hasLower) score += 15;
    if (hasNumbers) score += 15;
    if (hasSymbols) score += 25;
    
    // Entropy bonus
    const entropy = calculateEntropy(password, length);
    if (entropy >= 64) score += 10;
    
    // Cap score
    score = Math.min(score, maxScore);
    
    // Determine level and gradient
    let level, gradient, percentage;
    
    if (score < 25) {
        level = 'Weak';
        gradient = 'linear-gradient(90deg, #ef4444 0%, #ef4444 100%)';
        percentage = 25;
    } else if (score < 50) {
        level = 'Medium';
        gradient = 'linear-gradient(90deg, #f59e0b 0%, #f59e0b 100%)';
        percentage = 50;
    } else if (score < 75) {
        level = 'Strong';
        gradient = 'linear-gradient(90deg, #3b82f6 0%, #3b82f6 100%)';
        percentage = 75;
    } else {
        level = 'Very Strong';
        gradient = 'linear-gradient(90deg, #10b981 0%, #10b981 100%)';
        percentage = 100;
    }
    
    return { level, gradient, percentage, score };
}

/**
 * Calculate password entropy
 * Entropy = log2(character_space ^ length)
 * @param {string} password - Password to analyze
 * @param {number} length - Password length
 * @returns {number} Entropy in bits
 */
function calculateEntropy(password, length) {
    let charSpace = 0;
    
    // Count possible characters based on detected types
    if (/[a-z]/.test(password)) charSpace += 26;
    if (/[A-Z]/.test(password)) charSpace += 26;
    if (/[0-9]/.test(password)) charSpace += 10;
    if (/[!@#$%^&*()_+\-=\[\]{}\\|;:'",.<>/?]/.test(password)) charSpace += 32;
    
    // If no characters detected, use basic estimate
    if (charSpace === 0) charSpace = 26;
    
    // Entropy = log2(charSpace ^ length)
    const entropy = length * Math.log2(charSpace);
    
    return entropy;
}

// ============================================
// UI Update Functions
// ============================================

/**
 * Update length display when slider changes
 */
function updateLengthDisplay() {
    const length = elements.lengthSlider.value;
    elements.lengthDisplay.textContent = length;
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility() {
    const isPassword = elements.passwordDisplay.type === 'password';
    elements.passwordDisplay.type = isPassword ? 'text' : 'password';
    
    // Update icon visual feedback
    elements.togglePassword.classList.toggle('active');
}

// ============================================
// Copy to Clipboard
// ============================================

/**
 * Copy password to clipboard with toast notification
 */
function copyPassword() {
    if (!state.currentPassword) {
        showError('Please generate a password first');
        return;
    }
    
    // Use modern Clipboard API
    navigator.clipboard.writeText(state.currentPassword).then(() => {
        // Visual feedback on button
        elements.copyBtn.classList.add('copied');
        elements.copyBtn.textContent = '✓ Copied!';
        
        // Show toast
        showToast('Password copied to clipboard!');
        
        // Reset button after delay
        setTimeout(() => {
            elements.copyBtn.classList.remove('copied');
            elements.copyBtn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg> Copy';
        }, 2000);
    }).catch(() => {
        showError('Failed to copy password. Please try again.');
    });
}

// ============================================
// Notifications
// ============================================

/**
 * Show toast notification
 * @param {string} message - Message to display
 * @param {number} duration - Duration in milliseconds
 */
function showToast(message, duration = 3000) {
    elements.toast.textContent = message;
    elements.toast.classList.add('show');
    
    setTimeout(() => {
        elements.toast.classList.remove('show');
    }, duration);
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showError(message) {
    elements.errorMessage.textContent = message;
    elements.errorMessage.classList.add('show');
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        elements.errorMessage.classList.remove('show');
    }, 5000);
}

/**
 * Clear error message
 */
function clearError() {
    elements.errorMessage.classList.remove('show');
    elements.errorMessage.textContent = '';
}

// ============================================
// Password History Management
// ============================================

/**
 * Add password to history
 * @param {string} password - Password to add
 */
function addToHistory(password) {
    // Avoid duplicates - remove if already exists
    state.passwordHistory = state.passwordHistory.filter(p => p !== password);
    
    // Add to beginning
    state.passwordHistory.unshift(password);
    
    // Limit history length
    if (state.passwordHistory.length > state.maxHistoryLength) {
        state.passwordHistory = state.passwordHistory.slice(0, state.maxHistoryLength);
    }
    
    // Save to localStorage
    saveHistory();
    
    // Update UI
    renderHistory();
}

/**
 * Render password history
 */
function renderHistory() {
    if (state.passwordHistory.length === 0) {
        elements.historyList.innerHTML = '<li class="history-placeholder">No passwords generated yet</li>';
        return;
    }
    
    elements.historyList.innerHTML = state.passwordHistory.map((password, index) => `
        <li class="history-item">
            <span class="history-password" data-index="${index}">${password}</span>
            <button class="history-copy-btn" data-password="${password}" title="Copy password">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                    <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                </svg>
            </button>
        </li>
    `).join('');
    
    // Attach event listeners to history items
    document.querySelectorAll('.history-password').forEach(el => {
        el.addEventListener('click', function() {
            const password = this.textContent;
            elements.passwordDisplay.value = password;
            state.currentPassword = password;
        });
    });
    
    document.querySelectorAll('.history-copy-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const password = this.dataset.password;
            navigator.clipboard.writeText(password).then(() => {
                showToast('Password copied from history!');
            });
        });
    });
}

/**
 * Clear password history
 */
function clearHistory() {
    if (state.passwordHistory.length === 0) return;
    
    if (confirm('Are you sure you want to clear all password history?')) {
        state.passwordHistory = [];
        saveHistory();
        renderHistory();
        showToast('Password history cleared');
    }
}

/**
 * Save history to localStorage
 */
function saveHistory() {
    try {
        localStorage.setItem('passwordHistory', JSON.stringify(state.passwordHistory));
    } catch (e) {
        console.warn('Failed to save history to localStorage', e);
    }
}

/**
 * Load history from localStorage
 */
function loadHistory() {
    try {
        const saved = localStorage.getItem('passwordHistory');
        if (saved) {
            state.passwordHistory = JSON.parse(saved);
            renderHistory();
        }
    } catch (e) {
        console.warn('Failed to load history from localStorage', e);
        state.passwordHistory = [];
    }
}

// ============================================
// Theme Management
// ============================================

/**
 * Toggle between dark and light theme
 */
function toggleTheme() {
    state.isDarkTheme = !state.isDarkTheme;
    
    if (state.isDarkTheme) {
        document.body.classList.remove('light-theme');
    } else {
        document.body.classList.add('light-theme');
    }
    
    // Save preference
    localStorage.setItem('theme', state.isDarkTheme ? 'dark' : 'light');
}

/**
 * Load theme preference from localStorage
 */
function loadTheme() {
    const saved = localStorage.getItem('theme');
    
    if (saved === 'light') {
        state.isDarkTheme = false;
        document.body.classList.add('light-theme');
    } else {
        // Default to dark theme or system preference
        state.isDarkTheme = true;
        document.body.classList.remove('light-theme');
    }
}

// ============================================
// Initialize on DOM Ready
// ============================================
document.addEventListener('DOMContentLoaded', init);

/**
 * Fallback initialization if DOM is already loaded
 */
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
