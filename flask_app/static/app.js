// Global state
let uploadedFiles = [];
let pipelineRunning = false;
let statusCheckInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
});

function setupEventListeners() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const runBtn = document.getElementById('runPipelineBtn');

    // Click to upload
    dropZone.addEventListener('click', () => fileInput.click());

    // File input change
    fileInput.addEventListener('change', handleFileSelect);

    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        handleFileSelect({ target: { files: e.dataTransfer.files } });
    });

    // Run pipeline button
    runBtn.addEventListener('click', runPipeline);
}

async function handleFileSelect(event) {
    const files = event.target.files;
    if (files.length === 0) return;

    const formData = new FormData();
    for (let file of files) {
        formData.append('files', file);
    }

    try {
        showMessage('Uploading files...', 'info');
        
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            uploadedFiles = data.files;
            displayFileList(data.files);
            document.getElementById('runPipelineBtn').disabled = false;
            showMessage(data.message, 'success');
        } else {
            showMessage('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showMessage('Upload failed: ' + error.message, 'error');
    }
}

function displayFileList(files) {
    const fileList = document.getElementById('fileList');
    fileList.innerHTML = '<h3 style="margin-bottom: 15px;">Uploaded Files:</h3>';

    files.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <div class="file-info">
                <span class="file-icon">📄</span>
                <div>
                    <strong>${file.name}</strong>
                    <div style="font-size: 0.9rem; color: #666;">
                        ${formatFileSize(file.size)}
                    </div>
                </div>
            </div>
            <span style="color: #28a745;">✓</span>
        `;
        fileList.appendChild(fileItem);
    });
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

async function runPipeline() {
    if (pipelineRunning) return;

    pipelineRunning = true;
    document.getElementById('runPipelineBtn').disabled = true;

    // Get configuration
    const config = {
        algorithm: document.getElementById('algorithm').value,
        contamination: parseFloat(document.getElementById('contamination').value),
        gemini_api_key: document.getElementById('geminiKey').value
    };

    // Show progress section
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';

    try {
        // Start pipeline
        const response = await fetch('/api/run_pipeline', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });

        // Start status polling
        statusCheckInterval = setInterval(checkStatus, 1000);

        const data = await response.json();

        if (response.ok) {
            // Pipeline completed successfully
            clearInterval(statusCheckInterval);
            await displayResults();
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        clearInterval(statusCheckInterval);
        showMessage('Pipeline failed: ' + error.message, 'error');
        pipelineRunning = false;
        document.getElementById('uploadSection').style.display = 'block';
        document.getElementById('progressSection').style.display = 'none';
    }
}

async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        // Update progress bar
        document.getElementById('progressBar').style.width = data.progress + '%';
        document.getElementById('progressBar').textContent = data.progress + '%';
        document.getElementById('statusMessage').textContent = data.message;

        if (data.status === 'completed') {
            clearInterval(statusCheckInterval);
            await displayResults();
        } else if (data.status === 'error') {
            clearInterval(statusCheckInterval);
            showMessage('Error: ' + data.error, 'error');
            pipelineRunning = false;
        }
    } catch (error) {
        console.error('Status check failed:', error);
    }
}

async function displayResults() {
    try {
        const response = await fetch('/api/results');
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        // Hide progress, show results
        document.getElementById('progressSection').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'block';

        // Display statistics
        displayStatistics(data.summary);

        // Display charts in summary tab
        displayCharts(data.all_anomalies || data.top_anomalies, data.summary);

        // Display detailed anomalies
        displayDetailedAnomalies(data.all_anomalies || data.top_anomalies);

        // Load XAI data
        await loadFeatureImportance();
        populateAnomalySelector(data.top_anomalies);

        // Load Gemini AI analysis
        await loadGeminiAnalysis();

        pipelineRunning = false;
    } catch (error) {
        showMessage('Failed to load results: ' + error.message, 'error');
    }
}

function displayStatistics(summary) {
    const statsGrid = document.getElementById('statsGrid');
    statsGrid.innerHTML = `
        <div class="stat-card">
            <h3>${summary.total_events}</h3>
            <p>Total Events</p>
        </div>
        <div class="stat-card">
            <h3>${summary.anomaly_count}</h3>
            <p>Anomalies Detected</p>
        </div>
        <div class="stat-card">
            <h3>${summary.anomaly_percentage}%</h3>
            <p>Anomaly Rate</p>
        </div>
        <div class="stat-card">
            <h3>${summary.high_risk_count}</h3>
            <p>High Risk Events</p>
        </div>
    `;
}

function displayAnomalies(anomalies) {
    const tbody = document.getElementById('anomaliesTableBody');
    tbody.innerHTML = '';

    anomalies.forEach(anomaly => {
        const row = document.createElement('tr');
        
        let riskClass = 'risk-low';
        let riskLabel = 'LOW';
        if (anomaly.score > 0.8) {
            riskClass = 'risk-high';
            riskLabel = 'HIGH';
        } else if (anomaly.score > 0.5) {
            riskClass = 'risk-medium';
            riskLabel = 'MEDIUM';
        }

        row.innerHTML = `
            <td><span class="risk-badge ${riskClass}">${riskLabel}</span></td>
            <td>${anomaly.event_id || 'N/A'}</td>
            <td>${(anomaly.score * 100).toFixed(1)}%</td>
            <td>${anomaly.timestamp}</td>
            <td>${anomaly.computer}</td>
            <td>${anomaly.user}</td>
            <td>
                <button class="btn btn-primary" style="padding: 5px 15px; font-size: 0.9rem;" 
                        onclick="explainAnomalyById(${anomaly.index})">
                    Explain
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function displayDetailedAnomalies(anomalies) {
    const tbody = document.getElementById('detailedAnomaliesBody');
    
    if (!anomalies || anomalies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: #888;">No anomalies to display</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    
    anomalies.forEach(anomaly => {
        const row = document.createElement('tr');
        
        let riskClass = 'risk-low';
        let riskLabel = 'LOW';
        if (anomaly.score > 0.8) {
            riskClass = 'risk-high';
            riskLabel = 'CRITICAL';
        } else if (anomaly.score > 0.5) {
            riskClass = 'risk-medium';
            riskLabel = 'MEDIUM';
        }

        row.innerHTML = `
            <td><span class="risk-badge ${riskClass}">${riskLabel}</span></td>
            <td>${anomaly.event_id || 'N/A'}</td>
            <td>${(anomaly.score * 100).toFixed(1)}%</td>
            <td>${anomaly.timestamp}</td>
            <td>${anomaly.computer}</td>
            <td>${anomaly.user}</td>
            <td>${anomaly.index}</td>
            <td>
                <button class="btn btn-primary" style="padding: 5px 15px; font-size: 0.9rem;" 
                        onclick="explainAnomalyById(${anomaly.index})">
                    Explain
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function loadGeminiAnalysis() {
    try {
        const response = await fetch('/api/gemini/analysis');
        const data = await response.json();

        if (!response.ok) {
            document.getElementById('geminiContent').innerHTML = `
                <div style="padding: 20px; text-align: center; color: #9ca3af;">
                    <p>⚠️ Gemini AI analysis unavailable</p>
                    <p style="font-size: 0.9rem; margin-top: 10px;">${data.error || 'Configure API key in .env file'}</p>
                </div>
            `;
            return;
        }

        displayGeminiAnalysis(data);
    } catch (error) {
        console.error('Failed to load Gemini analysis:', error);
        document.getElementById('geminiContent').innerHTML = `
            <div style="padding: 20px; text-align: center; color: #9ca3af;">
                <p>⚠️ Failed to load Gemini analysis</p>
                <p style="font-size: 0.9rem; margin-top: 10px;">${error.message}</p>
            </div>
        `;
    }
}

function formatMarkdownText(text) {
    if (!text) return '';
    
    // Convert markdown-style formatting to HTML
    let formatted = text;
    
    // Bold text: **text** or __text__
    formatted = formatted.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/__(.+?)__/g, '<strong>$1</strong>');
    
    // Italic text: *text* or _text_
    formatted = formatted.replace(/\*(.+?)\*/g, '<em>$1</em>');
    formatted = formatted.replace(/_(.+?)_/g, '<em>$1</em>');
    
    // Convert bullet points (- item or * item)
    formatted = formatted.replace(/^[\-\*]\s+(.+)$/gm, '<li>$1</li>');
    
    // Wrap consecutive list items in <ul>
    formatted = formatted.replace(/(<li>.*<\/li>\n?)+/g, function(match) {
        return '<ul style="margin: 10px 0; padding-left: 25px; line-height: 1.8;">' + match + '</ul>';
    });
    
    // Convert numbered lists (1. item, 2. item)
    formatted = formatted.replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>');
    
    // Wrap consecutive numbered items in <ol>
    formatted = formatted.replace(/(<li>.*<\/li>\n?)+/g, function(match) {
        if (!match.includes('<ul')) {
            return '<ol style="margin: 10px 0; padding-left: 25px; line-height: 1.8;">' + match + '</ol>';
        }
        return match;
    });
    
    // Convert line breaks to paragraphs
    formatted = formatted.split('\n\n').map(para => {
        if (para.trim() && !para.includes('<ul') && !para.includes('<ol') && !para.includes('<li>')) {
            return '<p style="margin-bottom: 15px; line-height: 1.6;">' + para.trim() + '</p>';
        }
        return para;
    }).join('\n');
    
    // Convert single line breaks to <br>
    formatted = formatted.replace(/\n/g, '<br>');
    
    return formatted;
}

function displayGeminiAnalysis(data) {
    const container = document.getElementById('geminiContent');
    
    let html = '<div class="gemini-analysis">';
    
    if (data.overview) {
        html += `
            <div class="analysis-section">
                <h4>📊 Overview</h4>
                <div class="analysis-content">${formatMarkdownText(data.overview)}</div>
            </div>
        `;
    }
    
    if (data.patterns) {
        html += `
            <div class="analysis-section">
                <h4>🎯 Attack Patterns</h4>
                <div class="analysis-content">${formatMarkdownText(data.patterns)}</div>
            </div>
        `;
    }
    
    if (data.threat_assessment) {
        html += `
            <div class="analysis-section">
                <h4>⚠️ Threat Assessment</h4>
                <div class="analysis-content">${formatMarkdownText(data.threat_assessment)}</div>
            </div>
        `;
    }
    
    if (data.key_takeaways) {
        html += `
            <div class="analysis-section">
                <h4>💡 Key Takeaways</h4>
                <div class="analysis-content">${formatMarkdownText(data.key_takeaways)}</div>
            </div>
        `;
    }
    
    if (data.recommendations) {
        html += `
            <div class="analysis-section">
                <h4>🛡️ Recommendations</h4>
                <div class="analysis-content">${formatMarkdownText(data.recommendations)}</div>
            </div>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

async function loadFeatureImportance() {
    try {
        const response = await fetch('/api/xai/feature_importance');
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        displayFeatureImportance(data);
    } catch (error) {
        console.error('Failed to load feature importance:', error);
    }
}

function displayFeatureImportance(data) {
    const container = document.getElementById('featureImportanceChart');
    
    // Take top 15 features
    const topN = 15;
    const features = data.features.slice(0, topN);
    const importance = data.importance.slice(0, topN);

    let html = '';
    
    const maxImportance = Math.max(...importance);
    
    features.forEach((feature, index) => {
        const imp = importance[index];
        const percentage = (imp / maxImportance) * 100;
        // Use grayscale gradient for dark theme
        const brightness = 100 + (percentage * 1.5);
        const color = `hsl(0, 0%, ${Math.min(brightness, 80)}%)`;
        
        html += `
            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <strong style="color: #e0e0e0;">${feature}</strong>
                    <span style="color: #9ca3af;">${imp.toFixed(4)}</span>
                </div>
                <div style="background: #1a1a1a; height: 25px; border-radius: 5px; overflow: hidden; border: 1px solid #333;">
                    <div style="width: ${percentage}%; height: 100%; background: ${color}; 
                                transition: width 0.5s;"></div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function populateAnomalySelector(anomalies) {
    const selector = document.getElementById('anomalySelector');
    selector.innerHTML = '<option value="">-- Select an anomaly --</option>';

    anomalies.forEach(anomaly => {
        const option = document.createElement('option');
        option.value = anomaly.index;
        option.textContent = `Index ${anomaly.index} | EventID ${anomaly.event_id} | Score: ${(anomaly.score * 100).toFixed(1)}%`;
        selector.appendChild(option);
    });
}

async function explainAnomaly() {
    const selector = document.getElementById('anomalySelector');
    const idx = selector.value;

    if (!idx) {
        document.getElementById('explanationContent').innerHTML = '';
        return;
    }

    await explainAnomalyById(parseInt(idx));
}

async function explainAnomalyById(idx) {
    try {
        // Switch to XAI tab
        switchTab('xai');
        
        // Set selector value
        document.getElementById('anomalySelector').value = idx;

        const response = await fetch(`/api/xai/explain/${idx}`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        displayExplanation(data);
    } catch (error) {
        showMessage('Failed to generate explanation: ' + error.message, 'error');
    }
}

function displayExplanation(data) {
    const container = document.getElementById('explanationContent');
    const explanation = data.explanation;
    const event = data.event;

    let html = `
        <div class="explanation-card">
            <h4 style="margin-bottom: 20px; color: #fff;">📊 Event Details</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px;">
                <div style="color: #e0e0e0;">
                    <strong style="color: #9ca3af;">Event ID:</strong> ${event.EventID || 'N/A'}
                </div>
                <div style="color: #e0e0e0;">
                    <strong style="color: #9ca3af;">Anomaly Score:</strong> ${((event.AnomalyScoreNormalized || 0) * 100).toFixed(1)}%
                </div>
                <div style="color: #e0e0e0;">
                    <strong style="color: #9ca3af;">Computer:</strong> ${event.Computer || 'N/A'}
                </div>
                <div style="color: #e0e0e0;">
                    <strong style="color: #9ca3af;">User:</strong> ${event.User || 'N/A'}
                </div>
            </div>

            <h4 style="margin-bottom: 15px; color: #fff;">🎯 Top Contributing Features</h4>
            <p style="color: #9ca3af; margin-bottom: 20px;">
                Features that pushed this event towards being classified as anomalous
            </p>
    `;

    explanation.top_features.slice(0, 8).forEach((feat, index) => {
        const color = feat.contribution === 'increases' ? '#ef4444' : '#10b981';
        const icon = feat.contribution === 'increases' ? '🔴' : '🟢';
        const absShap = Math.abs(feat.shap_value);
        const maxShap = Math.max(...explanation.top_features.map(f => Math.abs(f.shap_value)));
        const barWidth = (absShap / maxShap) * 100;
        const featureClass = feat.contribution === 'increases' ? 'positive' : 'negative';

        html += `
            <div class="feature-item ${featureClass}" style="margin-bottom: 15px; padding: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <strong style="color: #e0e0e0;">${icon} ${index + 1}. ${feat.feature}</strong>
                    <span style="color: ${color}; font-weight: 600;">
                        ${feat.contribution.toUpperCase()}
                    </span>
                </div>
                <div style="margin-bottom: 8px;">
                    <span style="color: #9ca3af;">Feature Value:</span> 
                    <code style="background: #1a1a1a; padding: 2px 8px; border-radius: 4px; color: #e0e0e0;">
                        ${feat.value.toFixed(4)}
                    </code>
                </div>
                <div style="margin-bottom: 8px;">
                    <span style="color: #9ca3af;">SHAP Value:</span> 
                    <code style="background: #1a1a1a; padding: 2px 8px; border-radius: 4px; color: #e0e0e0;">
                        ${feat.shap_value.toFixed(4)}
                    </code>
                </div>
                <div style="background: #1a1a1a; height: 20px; border-radius: 5px; overflow: hidden;">
                    <div style="width: ${barWidth}%; height: 100%; background: ${color}; 
                                transition: width 0.5s;"></div>
                </div>
            </div>
        `;
    });

    html += `
            <div style="background: #0d0d0d; padding: 20px; border-radius: 8px; margin-top: 30px; 
                        border-left: 4px solid #555; border: 1px solid #333;">
                <h4 style="margin-bottom: 10px; color: #fff;">📝 Natural Language Explanation</h4>
                <p style="white-space: pre-line; line-height: 1.6; color: #cbd5e0;">
                    ${explanation.explanation_text}
                </p>
            </div>

            <div style="margin-top: 20px; padding: 15px; background: #0d0d0d; border-radius: 8px; 
                        border-left: 4px solid #555; border: 1px solid #333;">
                <h4 style="margin-bottom: 10px; color: #fff;">🧮 How to Interpret SHAP Values</h4>
                <ul style="margin-left: 20px; line-height: 1.8; color: #cbd5e0;">
                    <li><strong style="color: #ef4444;">🔴 Positive SHAP:</strong> Feature pushes prediction towards anomaly</li>
                    <li><strong style="color: #10b981;">🟢 Negative SHAP:</strong> Feature pushes prediction towards normal</li>
                    <li><strong>Magnitude:</strong> Larger absolute value = stronger impact</li>
                </ul>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

function switchTab(tabName) {
    // Remove active class from all tabs
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

    // Add active class to selected tab
    const tabs = {
        'summary': 0,
        'anomalies': 1,
        'xai': 2,
        'gemini': 3
    };
    
    document.querySelectorAll('.tab')[tabs[tabName]].classList.add('active');
    document.getElementById(tabName + 'Tab').classList.add('active');
}

async function downloadResults() {
    try {
        window.location.href = '/api/download/results';
    } catch (error) {
        showMessage('Download failed: ' + error.message, 'error');
    }
}

async function startNew() {
    if (!confirm('Are you sure you want to start a new analysis? Current results will be cleared.')) {
        return;
    }

    try {
        const response = await fetch('/api/reset', {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            // Reset UI
            uploadedFiles = [];
            document.getElementById('fileList').innerHTML = '';
            document.getElementById('fileInput').value = '';
            document.getElementById('runPipelineBtn').disabled = true;
            document.getElementById('uploadSection').style.display = 'block';
            document.getElementById('progressSection').style.display = 'none';
            document.getElementById('resultsSection').style.display = 'none';
            document.getElementById('errorSection').innerHTML = '';
            
            showMessage('Ready for new analysis', 'success');
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        showMessage('Reset failed: ' + error.message, 'error');
    }
}

function showMessage(message, type) {
    const errorSection = document.getElementById('errorSection');
    const className = type === 'error' ? 'error-message' : 'success-message';
    
    errorSection.innerHTML = `
        <div class="${className}">
            ${message}
        </div>
    `;

    // Auto-hide success messages after 5 seconds
    if (type === 'success') {
        setTimeout(() => {
            errorSection.innerHTML = '';
        }, 5000);
    }
}

// Chart instances storage
let chartInstances = {};

// Destroy existing charts before creating new ones
function destroyChart(chartId) {
    if (chartInstances[chartId]) {
        chartInstances[chartId].destroy();
        delete chartInstances[chartId];
    }
}

// Main function to display all charts
function displayCharts(anomalies, summary) {
    if (!anomalies || anomalies.length === 0) return;

    // Destroy existing charts
    Object.keys(chartInstances).forEach(id => destroyChart(id));

    // Create all charts
    createRiskPieChart(anomalies);
    createAnomalyDoughnutChart(summary);
    createComputerBarChart(anomalies);
    createUserBarChart(anomalies);
    createEventIdBarChart(anomalies);
    createTimelineChart(anomalies);
    createScoreHistogramChart(anomalies);
}

// 1. Risk Distribution Pie Chart
function createRiskPieChart(anomalies) {
    const ctx = document.getElementById('riskPieChart');
    if (!ctx) return;

    // Count risk levels
    let critical = 0, high = 0, medium = 0, low = 0;
    anomalies.forEach(a => {
        if (a.score > 0.8) critical++;
        else if (a.score > 0.6) high++;
        else if (a.score > 0.4) medium++;
        else low++;
    });

    destroyChart('riskPieChart');
    chartInstances['riskPieChart'] = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical (>80%)', 'High (60-80%)', 'Medium (40-60%)', 'Low (<40%)'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: ['#ef4444', '#f59e0b', '#eab308', '#10b981'],
                borderColor: '#000',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e0e0e0', padding: 15, font: { size: 12 } }
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1
                }
            }
        }
    });
}

// 2. Anomaly vs Normal Doughnut Chart
function createAnomalyDoughnutChart(summary) {
    const ctx = document.getElementById('anomalyDoughnutChart');
    if (!ctx) return;

    const normalEvents = summary.total_events - summary.anomaly_count;

    destroyChart('anomalyDoughnutChart');
    chartInstances['anomalyDoughnutChart'] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Anomalies', 'Normal Events'],
            datasets: [{
                data: [summary.anomaly_count, normalEvents],
                backgroundColor: ['#ef4444', '#10b981'],
                borderColor: '#000',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e0e0e0', padding: 15, font: { size: 12 } }
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// 3. Top Affected Computers Bar Chart
function createComputerBarChart(anomalies) {
    const ctx = document.getElementById('computerBarChart');
    if (!ctx) return;

    // Count anomalies per computer
    const computerCounts = {};
    anomalies.forEach(a => {
        const computer = a.computer || 'Unknown';
        computerCounts[computer] = (computerCounts[computer] || 0) + 1;
    });

    // Get top 10
    const sorted = Object.entries(computerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    destroyChart('computerBarChart');
    chartInstances['computerBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0]),
            datasets: [{
                label: 'Anomaly Count',
                data: sorted.map(s => s[1]),
                backgroundColor: '#ef4444',
                borderColor: '#dc2626',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' }
                },
                y: {
                    ticks: { color: '#e0e0e0' },
                    grid: { display: false }
                }
            }
        }
    });
}

// 4. Top Affected Users Bar Chart
function createUserBarChart(anomalies) {
    const ctx = document.getElementById('userBarChart');
    if (!ctx) return;

    // Count anomalies per user
    const userCounts = {};
    anomalies.forEach(a => {
        const user = a.user || 'Unknown';
        userCounts[user] = (userCounts[user] || 0) + 1;
    });

    // Get top 10
    const sorted = Object.entries(userCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    destroyChart('userBarChart');
    chartInstances['userBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0]),
            datasets: [{
                label: 'Anomaly Count',
                data: sorted.map(s => s[1]),
                backgroundColor: '#f59e0b',
                borderColor: '#d97706',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' }
                },
                y: {
                    ticks: { color: '#e0e0e0' },
                    grid: { display: false }
                }
            }
        }
    });
}

// 5. Event ID Distribution Bar Chart
function createEventIdBarChart(anomalies) {
    const ctx = document.getElementById('eventIdBarChart');
    if (!ctx) return;

    // Count anomalies per event ID
    const eventIdCounts = {};
    anomalies.forEach(a => {
        const eventId = a.event_id || 'Unknown';
        eventIdCounts[eventId] = (eventIdCounts[eventId] || 0) + 1;
    });

    // Get top 10
    const sorted = Object.entries(eventIdCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    destroyChart('eventIdBarChart');
    chartInstances['eventIdBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => `Event ${s[0]}`),
            datasets: [{
                label: 'Anomaly Count',
                data: sorted.map(s => s[1]),
                backgroundColor: '#8b5cf6',
                borderColor: '#7c3aed',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: { color: '#e0e0e0', maxRotation: 45, minRotation: 45 },
                    grid: { display: false }
                },
                y: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' }
                }
            }
        }
    });
}

// 6. Anomaly Timeline Chart
function createTimelineChart(anomalies) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    // Group by hour
    const hourCounts = {};
    anomalies.forEach(a => {
        if (a.timestamp) {
            const date = new Date(a.timestamp);
            const hour = date.getHours();
            hourCounts[hour] = (hourCounts[hour] || 0) + 1;
        }
    });

    // Create array for all 24 hours
    const hours = Array.from({length: 24}, (_, i) => i);
    const counts = hours.map(h => hourCounts[h] || 0);

    destroyChart('timelineChart');
    chartInstances['timelineChart'] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: hours.map(h => `${h}:00`),
            datasets: [{
                label: 'Anomalies per Hour',
                data: counts,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#e0e0e0', font: { size: 12 } }
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: { color: '#9ca3af', maxRotation: 45, minRotation: 45 },
                    grid: { color: '#333' }
                },
                y: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' }
                }
            }
        }
    });
}

// 7. Anomaly Score Distribution Histogram
function createScoreHistogramChart(anomalies) {
    const ctx = document.getElementById('scoreHistogramChart');
    if (!ctx) return;

    // Create bins for scores (0-0.1, 0.1-0.2, ..., 0.9-1.0)
    const bins = Array(10).fill(0);
    anomalies.forEach(a => {
        const binIndex = Math.min(Math.floor(a.score * 10), 9);
        bins[binIndex]++;
    });

    const labels = bins.map((_, i) => `${(i * 10)}-${(i + 1) * 10}%`);

    destroyChart('scoreHistogramChart');
    chartInstances['scoreHistogramChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Anomalies',
                data: bins,
                backgroundColor: '#10b981',
                borderColor: '#059669',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: { color: '#e0e0e0', font: { size: 12 } }
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: { color: '#e0e0e0' },
                    grid: { display: false },
                    title: {
                        display: true,
                        text: 'Anomaly Score Range',
                        color: '#9ca3af'
                    }
                },
                y: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Count',
                        color: '#9ca3af'
                    }
                }
            }
        }
    });
}
