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
        populateAnomalySelector(data.all_anomalies || data.top_anomalies);

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
        
        // Get score value with proper handling
        const score = anomaly.score !== undefined ? anomaly.score : 0;
        
        // Calculate risk level based on score (matching summary chart thresholds)
        let riskClass = 'risk-low';
        let riskLabel = 'LOW';
        if (score > 0.8) {
            riskClass = 'risk-critical';
            riskLabel = 'CRITICAL';
        } else if (score > 0.6) {
            riskClass = 'risk-high';
            riskLabel = 'HIGH';
        } else if (score > 0.4) {
            riskClass = 'risk-medium';
            riskLabel = 'MEDIUM';
        }

        row.innerHTML = `
            <td><span class="risk-badge ${riskClass}">${riskLabel}</span></td>
            <td>${anomaly.event_id || 'N/A'}</td>
            <td>${(score * 100).toFixed(1)}%</td>
            <td>${anomaly.timestamp || 'N/A'}</td>
            <td>${anomaly.computer || 'N/A'}</td>
            <td>${anomaly.user || 'N/A'}</td>
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
    
    // Debug: Log first anomaly to see data structure
    if (anomalies.length > 0) {
        console.log('Sample anomaly data:', anomalies[0]);
    }
    
    anomalies.forEach(anomaly => {
        const row = document.createElement('tr');
        
        // Get score value - handle both 'score' and potential other field names
        const score = anomaly.score !== undefined ? anomaly.score : 0;
        
        // Calculate risk level based on score (matching summary chart thresholds)
        let riskClass = 'risk-low';
        let riskLabel = 'LOW';
        if (score > 0.8) {
            riskClass = 'risk-critical';
            riskLabel = 'CRITICAL';
        } else if (score > 0.6) {
            riskClass = 'risk-high';
            riskLabel = 'HIGH';
        } else if (score > 0.4) {
            riskClass = 'risk-medium';
            riskLabel = 'MEDIUM';
        }

        row.innerHTML = `
            <td><span class="risk-badge ${riskClass}">${riskLabel}</span></td>
            <td>${anomaly.event_id || 'N/A'}</td>
            <td>${(score * 100).toFixed(1)}%</td>
            <td>${anomaly.timestamp || 'N/A'}</td>
            <td>${anomaly.computer || 'N/A'}</td>
            <td>${anomaly.user || 'N/A'}</td>
            <td>${anomaly.index !== undefined ? anomaly.index : 'N/A'}</td>
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
async function displayCharts(anomalies, summary) {
    if (!anomalies || anomalies.length === 0) return;

    // Destroy existing charts
    Object.keys(chartInstances).forEach(id => destroyChart(id));

    // Create all charts
    createRiskPieChart(anomalies);
    createAnomalyDoughnutChart(summary);
    createComputerBarChart(anomalies);
    createEventIdBarChart(anomalies);
    createTimelineChart(anomalies);
    createScoreHistogramChart(anomalies);
    
    // Load and display cluster/MITRE charts if available
    await loadClusterMitreCharts();
}

// 1. Risk Distribution Pie Chart
function createRiskPieChart(anomalies) {
    const ctx = document.getElementById('riskPieChart');
    if (!ctx) return;

    // Count risk levels based on anomaly scores
    let critical = 0, high = 0, medium = 0, low = 0;
    anomalies.forEach(a => {
        const score = a.score || 0;
        if (score > 0.8) critical++;
        else if (score > 0.6) high++;
        else if (score > 0.4) medium++;
        else low++;
    });

    destroyChart('riskPieChart');
    chartInstances['riskPieChart'] = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical (>80%)', 'High (60-80%)', 'Medium (40-60%)', 'Low (<40%)'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: ['#8B0000', '#ef4444', '#f59e0b', '#10b981'],
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
                title: {
                    display: false
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
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} anomalies (${percentage}%)`;
                        }
                    }
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

    // Get top 10 computers with most anomalies
    const sorted = Object.entries(computerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    if (sorted.length === 0) return;

    destroyChart('computerBarChart');
    chartInstances['computerBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0]),
            datasets: [{
                label: 'Number of Anomalies',
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
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `Anomalies: ${context.parsed.x}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Number of Anomalies',
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                },
                y: {
                    ticks: { 
                        color: '#e0e0e0',
                        font: { size: 11 }
                    },
                    grid: { display: false },
                    title: {
                        display: true,
                        text: 'Computer Name',
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                }
            }
        }
    });
}

// 4. Event ID Distribution Bar Chart
function createEventIdBarChart(anomalies) {
    const ctx = document.getElementById('eventIdBarChart');
    if (!ctx) return;

    // Count anomalies per event ID
    const eventIdCounts = {};
    anomalies.forEach(a => {
        const eventId = a.event_id || 'Unknown';
        eventIdCounts[eventId] = (eventIdCounts[eventId] || 0) + 1;
    });

    // Get top 10 most frequent event IDs
    const sorted = Object.entries(eventIdCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    if (sorted.length === 0) return;

    destroyChart('eventIdBarChart');
    chartInstances['eventIdBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => `Event ${s[0]}`),
            datasets: [{
                label: 'Number of Anomalies',
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
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `Anomalies: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { 
                        color: '#e0e0e0', 
                        maxRotation: 45, 
                        minRotation: 45,
                        font: { size: 11 }
                    },
                    grid: { display: false },
                    title: {
                        display: true,
                        text: 'Event ID',
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                },
                y: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Number of Anomalies',
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                }
            }
        }
    });
}

// 5. Anomaly Timeline Chart
function createTimelineChart(anomalies) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    // Group anomalies by hour of day and detect timezone
    const hourCounts = {};
    let hasTimestamps = false;
    let detectedTimezone = null;
    let timezoneOffsetMinutes = null;
    let firstTimestamp = null;
    
    anomalies.forEach(a => {
        if (a.timestamp && a.timestamp !== 'N/A') {
            try {
                const timestampStr = a.timestamp;
                
                // Store first timestamp for timezone detection
                if (!firstTimestamp) {
                    firstTimestamp = timestampStr;
                }
                
                // Try to extract timezone from ISO string (e.g., "2024-01-15T10:30:00+05:30" or "2024-01-15T10:30:00Z")
                if (!detectedTimezone) {
                    // Check for timezone offset pattern (e.g., +05:30, -08:00, Z)
                    const tzMatch = timestampStr.match(/([+-]\d{2}:\d{2}|Z)$/);
                    if (tzMatch) {
                        if (tzMatch[1] === 'Z') {
                            detectedTimezone = 'UTC';
                            timezoneOffsetMinutes = 0;
                        } else {
                            detectedTimezone = `UTC${tzMatch[1]}`;
                            // Parse offset to minutes
                            const [hours, minutes] = tzMatch[1].split(':');
                            const hourVal = parseInt(hours);
                            const minVal = parseInt(minutes);
                            timezoneOffsetMinutes = hourVal * 60 + (hourVal < 0 ? -minVal : minVal);
                        }
                    }
                }
                
                // Parse the date in UTC
                const date = new Date(timestampStr);
                if (!isNaN(date.getTime())) {
                    let hour;
                    
                    if (timezoneOffsetMinutes !== null) {
                        // Calculate hour in the original timezone
                        // Get UTC time and add the timezone offset
                        const utcHours = date.getUTCHours();
                        const utcMinutes = date.getUTCMinutes();
                        
                        // Convert to minutes since midnight UTC
                        const utcTotalMinutes = utcHours * 60 + utcMinutes;
                        
                        // Add timezone offset to get local time
                        const localTotalMinutes = utcTotalMinutes + timezoneOffsetMinutes;
                        
                        // Handle day wraparound
                        const adjustedMinutes = ((localTotalMinutes % 1440) + 1440) % 1440;
                        hour = Math.floor(adjustedMinutes / 60);
                    } else {
                        // Fallback: use the hour from Date object (browser's interpretation)
                        hour = date.getHours();
                        
                        // Try to detect timezone from the Date object
                        const offset = -date.getTimezoneOffset(); // Minutes
                        const hours = Math.floor(Math.abs(offset) / 60);
                        const minutes = Math.abs(offset) % 60;
                        const sign = offset >= 0 ? '+' : '-';
                        detectedTimezone = `UTC${sign}${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
                        timezoneOffsetMinutes = offset;
                    }
                    
                    hourCounts[hour] = (hourCounts[hour] || 0) + 1;
                    hasTimestamps = true;
                }
            } catch (e) {
                console.error('Error parsing timestamp:', a.timestamp, e);
            }
        }
    });

    // If no valid timestamps, show message
    if (!hasTimestamps) {
        console.log('No valid timestamps found for timeline chart');
        return;
    }

    // Default to UTC if no timezone detected
    if (!detectedTimezone) {
        detectedTimezone = 'UTC';
        timezoneOffsetMinutes = 0;
    }

    console.log('Detected timezone:', detectedTimezone);
    console.log('Timezone offset (minutes):', timezoneOffsetMinutes);
    console.log('First timestamp:', firstTimestamp);
    console.log('Hour distribution:', hourCounts);

    // Create array for all 24 hours
    const hours = Array.from({length: 24}, (_, i) => i);
    const counts = hours.map(h => hourCounts[h] || 0);

    destroyChart('timelineChart');
    chartInstances['timelineChart'] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: hours.map(h => `${h.toString().padStart(2, '0')}:00`),
            datasets: [{
                label: `Anomalies (${detectedTimezone})`,
                data: counts,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#e0e0e0', font: { size: 12 } }
                },
                title: {
                    display: true,
                    text: `Timezone: ${detectedTimezone}`,
                    color: '#9ca3af',
                    font: { size: 11 },
                    padding: { bottom: 10 },
                    align: 'end'
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `Anomalies: ${context.parsed.y}`;
                        },
                        afterLabel: function(context) {
                            return `Timezone: ${detectedTimezone}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { 
                        color: '#9ca3af', 
                        maxRotation: 45, 
                        minRotation: 45,
                        font: { size: 10 }
                    },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: `Hour of Day (${detectedTimezone})`,
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                },
                y: {
                    ticks: { 
                        color: '#9ca3af',
                        stepSize: 1
                    },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Number of Anomalies',
                        color: '#9ca3af',
                        font: { size: 12 }
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

// 6. Anomaly Score Distribution Histogram
function createScoreHistogramChart(anomalies) {
    const ctx = document.getElementById('scoreHistogramChart');
    if (!ctx) return;

    // Create bins for scores (0-0.1, 0.1-0.2, ..., 0.9-1.0)
    const bins = Array(10).fill(0);
    anomalies.forEach(a => {
        const score = a.score || 0;
        const binIndex = Math.min(Math.floor(score * 10), 9);
        bins[binIndex]++;
    });

    const labels = bins.map((_, i) => `${(i * 10)}-${(i + 1) * 10}%`);

    // Color bins based on severity
    const backgroundColors = bins.map((_, i) => {
        if (i >= 8) return '#8B0000'; // Critical (80-100%)
        if (i >= 6) return '#ef4444'; // High (60-80%)
        if (i >= 4) return '#f59e0b'; // Medium (40-60%)
        return '#10b981'; // Low (0-40%)
    });

    destroyChart('scoreHistogramChart');
    chartInstances['scoreHistogramChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Anomalies',
                data: bins,
                backgroundColor: backgroundColors,
                borderColor: backgroundColors.map(c => c),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#e0e0e0', font: { size: 12 } }
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `Anomalies: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { 
                        color: '#e0e0e0',
                        font: { size: 11 }
                    },
                    grid: { display: false },
                    title: {
                        display: true,
                        text: 'Anomaly Score Range (%)',
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                },
                y: {
                    ticks: { 
                        color: '#9ca3af',
                        stepSize: 1
                    },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Number of Anomalies',
                        color: '#9ca3af',
                        font: { size: 12 }
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

// Load cluster and MITRE stage data and create charts
async function loadClusterMitreCharts() {
    try {
        const response = await fetch('/api/visualization/cluster_mitre');
        const data = await response.json();

        if (!response.ok) {
            console.error('Failed to load cluster/MITRE data:', data.error);
            return;
        }

        // Show/hide containers based on data availability
        if (data.has_clusters) {
            document.getElementById('clusterChartContainer').style.display = 'block';
            createClusterBarChart(data.cluster_distribution);
        } else {
            document.getElementById('clusterChartContainer').style.display = 'none';
        }

        if (data.has_mitre) {
            document.getElementById('mitreChartContainer').style.display = 'block';
            createMitreBarChart(data.mitre_distribution);
        } else {
            document.getElementById('mitreChartContainer').style.display = 'none';
        }

        // Adjust grid layout if only one chart is available
        const row = document.getElementById('clusterMitreRow');
        if (data.has_clusters && !data.has_mitre) {
            row.style.gridTemplateColumns = '1fr';
        } else if (!data.has_clusters && data.has_mitre) {
            row.style.gridTemplateColumns = '1fr';
        } else if (data.has_clusters && data.has_mitre) {
            row.style.gridTemplateColumns = '1fr 1fr';
        }
    } catch (error) {
        console.error('Error loading cluster/MITRE charts:', error);
    }
}

// 7. Cluster Distribution Bar Chart
function createClusterBarChart(clusterData) {
    const ctx = document.getElementById('clusterBarChart');
    if (!ctx || !clusterData || Object.keys(clusterData).length === 0) return;

    const labels = Object.keys(clusterData);
    const values = Object.values(clusterData);

    destroyChart('clusterBarChart');
    chartInstances['clusterBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Anomalies',
                data: values,
                backgroundColor: '#3b82f6',
                borderColor: '#2563eb',
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
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `Anomalies: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { 
                        color: '#e0e0e0', 
                        maxRotation: 45, 
                        minRotation: 45,
                        font: { size: 11 }
                    },
                    grid: { display: false },
                    title: {
                        display: true,
                        text: 'Cluster Label',
                        color: '#9ca3af',
                        font: { size: 12 }
                    }
                },
                y: {
                    ticks: { 
                        color: '#9ca3af',
                        stepSize: 1
                    },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Number of Anomalies',
                        color: '#9ca3af',
                        font: { size: 12 }
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

// 9. MITRE ATT&CK Stages Bar Chart
function createMitreBarChart(mitreData) {
    const ctx = document.getElementById('mitreBarChart');
    if (!ctx || !mitreData || Object.keys(mitreData).length === 0) return;

    // Sort stages by their stage number
    const stageOrder = [
        'Stage 1: Initial Access',
        'Stage 2: Execution',
        'Stage 2: Credential Access',
        'Stage 3: Persistence',
        'Stage 3: Privilege Escalation',
        'Stage 3: Defense Evasion',
        'Stage 4: Discovery',
        'Stage 4: Lateral Movement',
        'Stage 5: Collection',
        'Stage 5: Command & Control',
        'Stage 6: Exfiltration',
        'Stage 7: Impact'
    ];

    const sortedEntries = Object.entries(mitreData).sort((a, b) => {
        const indexA = stageOrder.indexOf(a[0]);
        const indexB = stageOrder.indexOf(b[0]);
        if (indexA === -1 && indexB === -1) return 0;
        if (indexA === -1) return 1;
        if (indexB === -1) return -1;
        return indexA - indexB;
    });

    const labels = sortedEntries.map(e => e[0]);
    const values = sortedEntries.map(e => e[1]);

    // Color by stage severity (early stages are more critical)
    const colors = labels.map(label => {
        if (label.includes('Stage 1') || label.includes('Stage 2')) {
            return '#ef4444'; // Red for early stages
        } else if (label.includes('Stage 3') || label.includes('Stage 4')) {
            return '#f59e0b'; // Orange for mid stages
        } else {
            return '#3b82f6'; // Blue for later stages
        }
    });

    destroyChart('mitreBarChart');
    chartInstances['mitreBarChart'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Anomalies',
                data: values,
                backgroundColor: colors,
                borderColor: colors.map(c => c),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y', // Horizontal bar chart
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#333',
                    borderWidth: 1,
                    callbacks: {
                        title: function(context) {
                            return context[0].label;
                        },
                        label: function(context) {
                            return `Anomalies: ${context.parsed.x}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: '#333' },
                    title: {
                        display: true,
                        text: 'Number of Anomalies',
                        color: '#9ca3af'
                    }
                },
                y: {
                    ticks: { 
                        color: '#e0e0e0',
                        font: { size: 11 }
                    },
                    grid: { display: false }
                }
            }
        }
    });
}
