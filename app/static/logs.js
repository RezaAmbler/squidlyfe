/**
 * Live Log Viewer - Frontend JavaScript
 * Handles polling, UI controls, and log display
 */

class LogViewer {
    constructor() {
        this.isRunning = false;
        this.cursor = null;
        this.pollInterval = 2000; // 2 seconds
        this.pollTimer = null;
        this.currentFile = 'access';
        this.maxLines = 100;
        this.autoScroll = true;
        this.filterText = '';

        // DOM elements
        this.logContainer = document.getElementById('log-lines');
        this.startBtn = document.getElementById('start-log-viewer');
        this.stopBtn = document.getElementById('stop-log-viewer');
        this.fileSelect = document.getElementById('log-file-select');
        this.linesInput = document.getElementById('log-lines-count');
        this.autoScrollCheckbox = document.getElementById('auto-scroll');
        this.filterInput = document.getElementById('log-filter');
        this.statusIndicator = document.getElementById('log-status');

        this.initEventListeners();
    }

    initEventListeners() {
        // Start button
        this.startBtn.addEventListener('click', () => this.start());

        // Stop button
        this.stopBtn.addEventListener('click', () => this.stop());

        // File selection change
        this.fileSelect.addEventListener('change', (e) => {
            this.currentFile = e.target.value;
            this.restart();
        });

        // Lines count change
        this.linesInput.addEventListener('change', (e) => {
            let value = parseInt(e.target.value);
            value = Math.min(Math.max(1, value), 500); // Clamp 1-500
            this.maxLines = value;
            this.linesInput.value = value;
            this.restart();
        });

        // Auto-scroll toggle
        this.autoScrollCheckbox.addEventListener('change', (e) => {
            this.autoScroll = e.target.checked;
        });

        // Filter input (debounced)
        let filterTimeout;
        this.filterInput.addEventListener('input', (e) => {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(() => {
                this.filterText = e.target.value.toLowerCase();
                this.applyFilter();
            }, 300);
        });
    }

    start() {
        if (this.isRunning) return;

        this.isRunning = true;
        this.cursor = null; // Reset cursor for initial load
        this.updateUIState();
        this.showStatus('Starting...', 'info');

        // Initial fetch
        this.fetchLogs();

        // Start polling
        this.pollTimer = setInterval(() => this.fetchLogs(), this.pollInterval);
    }

    stop() {
        if (!this.isRunning) return;

        this.isRunning = false;
        this.updateUIState();
        this.showStatus('Stopped', 'secondary');

        // Clear polling timer
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    restart() {
        if (this.isRunning) {
            this.stop();
            setTimeout(() => this.start(), 100);
        }
    }

    updateUIState() {
        this.startBtn.disabled = this.isRunning;
        this.stopBtn.disabled = !this.isRunning;
        this.fileSelect.disabled = this.isRunning;
        this.linesInput.disabled = this.isRunning;

        if (this.isRunning) {
            this.startBtn.classList.remove('btn-success');
            this.startBtn.classList.add('btn-secondary');
            this.stopBtn.classList.remove('btn-secondary');
            this.stopBtn.classList.add('btn-danger');
        } else {
            this.startBtn.classList.remove('btn-secondary');
            this.startBtn.classList.add('btn-success');
            this.stopBtn.classList.remove('btn-danger');
            this.stopBtn.classList.add('btn-secondary');
        }
    }

    async fetchLogs() {
        try {
            // Build query parameters
            const params = new URLSearchParams({
                file: this.currentFile,
                lines: this.maxLines.toString()
            });

            if (this.cursor !== null) {
                params.append('cursor', this.cursor.toString());
            }

            // Fetch logs
            const response = await fetch(`/api/logs?${params.toString()}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            const data = await response.json();

            // Handle error in response
            if (data.error) {
                this.showStatus(`Error: ${data.error}`, 'danger');
                this.stop();
                return;
            }

            // Update cursor
            this.cursor = data.cursor;

            // Display logs
            if (data.lines && data.lines.length > 0) {
                this.appendLogs(data.lines);
                this.showStatus(`Running (${this.currentFile} log)`, 'success');
            } else if (this.cursor === null || this.cursor === 0) {
                // Initial load with no lines
                this.showStatus('No log entries yet', 'info');
            } else {
                // Polling with no new lines
                this.showStatus(`Running (${this.currentFile} log)`, 'success');
            }

        } catch (error) {
            console.error('Error fetching logs:', error);
            this.showStatus(`Error: ${error.message}`, 'danger');
            this.stop();
        }
    }

    appendLogs(lines) {
        // If this is the initial load (cursor was null), clear container
        if (this.logContainer.getAttribute('data-initialized') !== 'true') {
            this.logContainer.innerHTML = '';
            this.logContainer.setAttribute('data-initialized', 'true');
        }

        const fragment = document.createDocumentFragment();

        lines.forEach(line => {
            const div = document.createElement('div');
            div.className = 'log-line';
            div.textContent = line;
            div.setAttribute('data-raw', line.toLowerCase());
            fragment.appendChild(div);
        });

        this.logContainer.appendChild(fragment);

        // Apply filter to new lines
        if (this.filterText) {
            this.applyFilter();
        }

        // Trim to max lines (keep only last maxLines * 2 for performance)
        const allLines = this.logContainer.querySelectorAll('.log-line');
        if (allLines.length > this.maxLines * 2) {
            const removeCount = allLines.length - this.maxLines * 2;
            for (let i = 0; i < removeCount; i++) {
                allLines[i].remove();
            }
        }

        // Auto-scroll to bottom
        if (this.autoScroll) {
            this.logContainer.scrollTop = this.logContainer.scrollHeight;
        }
    }

    applyFilter() {
        const lines = this.logContainer.querySelectorAll('.log-line');

        if (!this.filterText) {
            // Show all lines
            lines.forEach(line => {
                line.style.display = '';
                line.classList.remove('filtered-match');
            });
        } else {
            // Filter lines
            lines.forEach(line => {
                const text = line.getAttribute('data-raw') || line.textContent.toLowerCase();
                if (text.includes(this.filterText)) {
                    line.style.display = '';
                    line.classList.add('filtered-match');
                } else {
                    line.style.display = 'none';
                    line.classList.remove('filtered-match');
                }
            });
        }
    }

    showStatus(message, type) {
        this.statusIndicator.textContent = message;
        this.statusIndicator.className = `badge bg-${type}`;
    }

    clearLogs() {
        this.logContainer.innerHTML = '<div class="text-muted">Logs will appear here...</div>';
        this.logContainer.setAttribute('data-initialized', 'false');
        this.cursor = null;
    }
}

// Initialize log viewer when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the logging page with log viewer
    if (document.getElementById('log-viewer-container')) {
        window.logViewer = new LogViewer();
    }
});
