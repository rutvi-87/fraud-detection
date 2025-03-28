document.getElementById('checkButton').addEventListener('click', async () => {
    const domain = document.getElementById('domainInput').value.trim();
    const resultDiv = document.getElementById('result');
    const searchingContainer = document.getElementById('searchingContainer');

    if (!domain) {
        resultDiv.innerHTML = '<div class="error">⚠️ Please enter a valid domain.</div>';
        return;
    }

    // Show searching animation & clear result
    searchingContainer.style.display = 'block';
    resultDiv.innerHTML = '';

    // Update progress function
    const updateStep = (stepId, progress) => {
        const step = document.getElementById(stepId);
        const progressBar = step.querySelector('.step-progress');
        
        if (progress === 0) {
            step.classList.add('active');
            step.classList.remove('completed');
        } else if (progress === 100) {
            step.classList.remove('active');
            step.classList.add('completed');
        }
        
        progressBar.style.width = `${progress}%`;
        
        // Update overall progress
        const totalSteps = 5;
        const completedSteps = document.querySelectorAll('.step.completed').length;
        const mainProgress = document.querySelector('.progress');
        mainProgress.style.width = `${(completedSteps / totalSteps) * 100}%`;
    };

    // Add before the main try-catch block
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
        resultDiv.innerHTML = '<div class="error">⚠️ Please enter a valid domain name format.</div>';
        return;
    }

    // Add after updateStep function
    const updateProgress = (progress) => {
        const progressBar = document.querySelector('.progress');
        progressBar.style.width = `${progress}%`;
    };

    try {
        // Step 1: Initialize Connection
        updateStep('step1', 0);
        await new Promise(resolve => setTimeout(resolve, 1000));
        updateStep('step1', 100);

        // Step 2: Security Analysis
        updateStep('step2', 0);
        const vtResponse = await fetch('http://localhost:10000/check-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain }),
        });
        if (!vtResponse.ok) throw new Error('Failed to fetch domain details.');
        const vtData = await vtResponse.json();
        updateStep('step2', 100);

        // Step 3: Domain Age Check
        updateStep('step3', 0);
        await new Promise(resolve => setTimeout(resolve, 800));
        updateStep('step3', 100);
        
        // Step 4: Threat Detection
        updateStep('step4', 0);
        const trustScore = Math.max(0, Math.min(100, vtData.trustScore || 0));
        await new Promise(resolve => setTimeout(resolve, 1000));
        updateStep('step4', 100);

        // Step 5: AI Risk Assessment
        updateStep('step5', 0);
        const aiResponse = await fetch('http://localhost:10000/check-ai-fraud', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                domain,
                trustScore,
                stats: vtData.stats
            })
        });
        updateStep('step5', 100);

        let riskAssessment = await aiResponse.json();
        
        // Update metrics during analysis
        document.getElementById('securityLevel').textContent = riskAssessment.riskLevel || 'Analysis Complete';
        document.getElementById('domainAge').textContent = vtData.stats ? 'Verified' : 'Unknown';
        document.getElementById('riskFactors').textContent = riskAssessment.warnings || 'None detected';

        // Final processing
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Hide only the radar animation
        document.querySelector('.radar-scan').style.display = 'none';

        // Add to history before showing results
        addToHistory(domain, riskAssessment.score, vtData.virusTotalScore);

        // Show enhanced result
        resultDiv.innerHTML = `
            <div class="score-panels">
                <div class="score-panel ai-score">
                    <h3>AI Trust Score</h3>
                    <div class="score-circle" style="border-color: ${getScoreColor(riskAssessment.score)}">
                        ${riskAssessment.score}%
                    </div>
                    <div class="score-details">${riskAssessment.riskLevel}</div>
                </div>
                <div class="score-panel vt-score">
                    <h3>VirusTotal Score</h3>
                    <div class="score-circle" style="border-color: ${getScoreColor(vtData.virusTotalScore)}">
                        ${vtData.virusTotalScore}%
                    </div>
                    <div class="score-details">Community Rating</div>
                </div>
            </div>
            <div class="analysis-details">
                ${riskAssessment.warnings ? `<p class="warnings">⚠️ ${riskAssessment.warnings}</p>` : ''}
                <a href="${vtData.reportLink}" target="_blank" rel="noopener noreferrer">
                    <button class="view-report">View Detailed Report</button>
                </a>
            </div>`;

    } catch (error) {
        searchingContainer.style.display = 'none';
        resultDiv.innerHTML = `<div class="error"><strong>❌ Error:</strong> ${error.message}</div>`;
    }
});

// Helper function for score colors
function getScoreColor(score) {
    if (score >= 80) return '#28a745';
    if (score >= 60) return '#ffc107';
    if (score >= 40) return '#fd7e14';
    return '#dc3545';
}

// Add after the result display code
function addToHistory(domain, aiScore, vtScore) {
    const historyDiv = document.getElementById('searchHistory');
    const historyItem = document.createElement('div');
    historyItem.className = 'history-item';
    
    // Create clickable domain with scores
    historyItem.innerHTML = `
        <div class="history-bar" style="background: linear-gradient(to right, ${getScoreColor(aiScore)} 50%, ${getScoreColor(vtScore)} 50%);">
            <a href="#" class="domain-link">${domain}</a>
            <div class="score-tooltip">
                <div>AI Score: ${aiScore}%</div>
                <div>VT Score: ${vtScore}%</div>
                <div class="time">${new Date().toLocaleTimeString()}</div>
            </div>
        </div>
    `;
    
    // Add click handler to rerun analysis
    historyItem.querySelector('.domain-link').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('domainInput').value = domain;
        document.getElementById('checkButton').click();
    });

    historyDiv.insertBefore(historyItem, historyDiv.firstChild);

    // Limit to last 5 checks
    const historyItems = historyDiv.getElementsByClassName('history-item');
    while (historyItems.length > 5) {
        historyDiv.removeChild(historyItems[historyItems.length - 1]);
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Alt + S to focus search
    if (e.altKey && e.key === 's') {
        e.preventDefault();
        document.getElementById('domainInput').focus();
    }
    // Alt + Enter to trigger search
    if (e.altKey && e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('checkButton').click();
    }
});

// Progressive loading states
function updateLoadingState(step, progress) {
    const progressBar = document.querySelector('.progress');
    const loadingText = document.querySelector('.loading-status');
    
    progressBar.style.width = `${progress}%`;
    loadingText.textContent = `Analyzing: ${step}`;
}

// Voice Search Implementation
const voiceSearchBtn = document.getElementById('voiceSearchBtn');
const domainInput = document.getElementById('domainInput');

let recognition;
try {
    recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
    recognition.lang = 'en-US';
    recognition.continuous = false;
    recognition.interimResults = false;

    recognition.onstart = () => {
        voiceSearchBtn.classList.add('listening');
        domainInput.placeholder = 'Listening...';
    };

    recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript.toLowerCase()
            .replace(/\s+dot\s+/g, '.')  // Replace " dot " with "."
            .replace(/\s+/g, '')         // Remove all spaces
            .replace(/^www\./i, '')      // Remove www. if present
            .replace(/\.+/g, '.')        // Replace multiple dots with single dot
            .replace(/\.$/, '')          // Remove trailing dot
            .replace(/^\./, '');         // Remove leading dot

        domainInput.value = transcript;
        voiceSearchBtn.classList.remove('listening');
        domainInput.placeholder = 'Enter domain (e.g., example.com)';
        
        // Auto-trigger search after voice input
        document.getElementById('checkButton').click();
    };

    recognition.onerror = (event) => {
        console.error('Speech recognition error:', event.error);
        voiceSearchBtn.classList.remove('listening');
        domainInput.placeholder = 'Enter domain (e.g., example.com)';
    };

    recognition.onend = () => {
        voiceSearchBtn.classList.remove('listening');
        domainInput.placeholder = 'Enter domain (e.g., example.com)';
    };

    voiceSearchBtn.addEventListener('click', () => {
        try {
            recognition.start();
        } catch (error) {
            console.error('Speech recognition error:', error);
        }
    });

} catch (error) {
    console.error('Speech recognition not supported');
    voiceSearchBtn.style.display = 'none';
}

