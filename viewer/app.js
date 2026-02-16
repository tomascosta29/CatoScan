/**
 * CatoScan Viewer - Application Logic
 * Vanilla JavaScript, no external dependencies
 */

(function() {
    'use strict';

    // ============================================
    // State Management
    // ============================================
    const state = {
        data: null,
        filteredChecks: [],
        filters: {
            status: 'all',
            severity: 'all',
            search: ''
        }
    };

    // ============================================
    // DOM Elements
    // ============================================
    const elements = {
        // File inputs
        fileInput: document.getElementById('file-input'),
        fileInputEmpty: document.getElementById('file-input-empty'),
        
        // Views
        emptyState: document.getElementById('empty-state'),
        dashboard: document.getElementById('dashboard'),
        
        // Report header
        reportHostname: document.getElementById('report-hostname'),
        reportTimestamp: document.querySelector('#report-timestamp .meta-value'),
        reportEnvironment: document.querySelector('#report-environment .meta-value'),
        reportPrivileged: document.querySelector('#report-privileged .meta-value'),
        
        // Summary cards
        summaryTotal: document.getElementById('summary-total'),
        summaryPassed: document.getElementById('summary-passed'),
        summaryFailed: document.getElementById('summary-failed'),
        summarySkipped: document.getElementById('summary-skipped'),
        
        // Severity chart
        severityChart: document.getElementById('severity-chart'),
        
        // Filters
        searchInput: document.getElementById('search-input'),
        statusFilter: document.getElementById('status-filter'),
        severityFilter: document.getElementById('severity-filter'),
        resetFilters: document.getElementById('reset-filters'),
        filteredCount: document.getElementById('filtered-count'),
        totalCount: document.getElementById('total-count'),
        
        // Checks list
        checksList: document.getElementById('checks-list'),
        
        // Export
        exportBtn: document.getElementById('export-btn'),
        
        // Modal
        shortcutsModal: document.getElementById('shortcuts-modal'),
        modalClose: document.getElementById('modal-close')
    };

    // ============================================
    // Utility Functions
    // ============================================
    
    /**
     * Format date string for display
     */
    function formatDate(dateString) {
        if (!dateString) return 'Unknown';
        try {
            const date = new Date(dateString);
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (e) {
            return dateString;
        }
    }

    /**
     * Get status display info
     */
    function getStatusInfo(passed, skipped) {
        if (skipped) {
            return { text: '⊘', class: 'skipped', label: 'Skipped' };
        }
        if (passed) {
            return { text: '✓', class: 'passed', label: 'Passed' };
        }
        return { text: '✗', class: 'failed', label: 'Failed' };
    }

    /**
     * Get severity class
     */
    function getSeverityClass(severity) {
        const normalized = (severity || '').toLowerCase();
        switch (normalized) {
            case 'critical': return 'critical';
            case 'high': return 'high';
            case 'medium': return 'medium';
            case 'low': return 'low';
            default: return 'low';
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    /**
     * Format JSON for display
     */
    function formatJson(obj) {
        if (obj === null || obj === undefined) return 'N/A';
        if (typeof obj !== 'object') return String(obj);
        try {
            return JSON.stringify(obj, null, 2);
        } catch (e) {
            return String(obj);
        }
    }

    // ============================================
    // Validation
    // ============================================
    
    /**
     * Validate JSON structure matches expected schema
     */
    function validateData(data) {
        if (!data || typeof data !== 'object') {
            throw new Error('Invalid JSON: Expected an object');
        }
        
        // Check required sections
        if (!data.metadata || typeof data.metadata !== 'object') {
            throw new Error('Invalid JSON: Missing "metadata" section');
        }
        
        if (!data.summary || typeof data.summary !== 'object') {
            throw new Error('Invalid JSON: Missing "summary" section');
        }
        
        if (!Array.isArray(data.checks)) {
            throw new Error('Invalid JSON: "checks" should be an array');
        }
        
        // Validate check items
        data.checks.forEach((check, index) => {
            if (!check.id) {
                throw new Error(`Invalid JSON: Check at index ${index} missing "id"`);
            }
            if (!check.name) {
                throw new Error(`Invalid JSON: Check "${check.id}" missing "name"`);
            }
        });
        
        return true;
    }

    // ============================================
    // Rendering
    // ============================================
    
    /**
     * Render report header
     */
    function renderHeader(metadata) {
        elements.reportHostname.textContent = escapeHtml(metadata.hostname || 'Unknown Host');
        elements.reportTimestamp.textContent = formatDate(metadata.timestamp);
        elements.reportEnvironment.textContent = escapeHtml(
            (metadata.environment || 'unknown').charAt(0).toUpperCase() + 
            (metadata.environment || 'unknown').slice(1)
        );
        elements.reportPrivileged.textContent = metadata.privileged ? 'Privileged' : 'Unprivileged';
    }

    /**
     * Render summary cards
     */
    function renderSummary(summary) {
        elements.summaryTotal.textContent = summary.total_checks || 0;
        elements.summaryPassed.textContent = summary.passed || 0;
        elements.summaryFailed.textContent = summary.failed || 0;
        elements.summarySkipped.textContent = summary.skipped || 0;
    }

    /**
     * Render severity breakdown chart
     */
    function renderSeverityChart(bySeverity) {
        elements.severityChart.innerHTML = '';
        
        if (!bySeverity) return;
        
        const severities = [
            { key: 'CRITICAL', class: 'critical' },
            { key: 'HIGH', class: 'high' },
            { key: 'MEDIUM', class: 'medium' },
            { key: 'LOW', class: 'low' }
        ];
        
        const total = state.data?.summary?.total_checks || 1;
        
        severities.forEach(sev => {
            const data = bySeverity[sev.key];
            if (!data || data.total === 0) return;
            
            const percentage = (data.total / total) * 100;
            const bar = document.createElement('div');
            bar.className = `severity-bar severity-bar-${sev.class}`;
            bar.style.flex = data.total;
            bar.style.width = `${percentage}%`;
            bar.title = `${sev.key}: ${data.total} checks (${Math.round(percentage)}%)`;
            bar.textContent = data.total > 2 ? data.total : '';
            
            elements.severityChart.appendChild(bar);
        });
    }

    /**
     * Render a single check item
     */
    function renderCheckItem(check) {
        const status = getStatusInfo(check.passed, check.skipped);
        const severityClass = getSeverityClass(check.severity);
        
        const item = document.createElement('div');
        item.className = 'check-item';
        item.dataset.id = check.id;
        
        const hasRemediation = check.remediation && !check.passed && !check.skipped;
        const hasDetails = check.details && Object.keys(check.details).length > 0;
        
        item.innerHTML = `
            <div class="check-header">
                <div class="check-status ${status.class}">${status.text}</div>
                <div class="check-info">
                    <div class="check-name">${escapeHtml(check.name)}</div>
                    <div class="check-id">${escapeHtml(check.id)}</div>
                </div>
                <div class="check-severity ${severityClass}">${escapeHtml(check.severity || 'LOW')}</div>
                <div class="check-expand">▼</div>
            </div>
            <div class="check-details">
                <div class="detail-row">
                    <div class="detail-label">Message</div>
                    <div class="detail-value message ${status.class}">${escapeHtml(check.message || 'No message')}</div>
                </div>
                ${hasRemediation ? `
                <div class="detail-row">
                    <div class="detail-label">Remediation</div>
                    <div class="detail-value remediation">${escapeHtml(check.remediation)}</div>
                </div>
                ` : ''}
                ${hasDetails ? `
                <div class="detail-row">
                    <div class="detail-label">Details</div>
                    <pre class="detail-value details">${escapeHtml(formatJson(check.details))}</pre>
                </div>
                ` : ''}
            </div>
        `;
        
        // Add click handler for expansion
        const header = item.querySelector('.check-header');
        header.addEventListener('click', () => {
            item.classList.toggle('expanded');
        });
        
        return item;
    }

    /**
     * Render checks list
     */
    function renderChecksList(checks) {
        elements.checksList.innerHTML = '';
        
        if (checks.length === 0) {
            elements.checksList.innerHTML = `
                <div class="no-results">
                    <div class="no-results-icon">🔍</div>
                    <h3>No checks match your filters</h3>
                    <p>Try adjusting your search or filter criteria</p>
                </div>
            `;
            return;
        }
        
        // Use DocumentFragment for better performance
        const fragment = document.createDocumentFragment();
        checks.forEach(check => {
            fragment.appendChild(renderCheckItem(check));
        });
        elements.checksList.appendChild(fragment);
    }

    /**
     * Update results count display
     */
    function updateResultsCount() {
        elements.filteredCount.textContent = state.filteredChecks.length;
        elements.totalCount.textContent = state.data?.checks?.length || 0;
    }

    // ============================================
    // Filtering
    // ============================================
    
    /**
     * Apply filters to checks
     */
    function applyFilters() {
        if (!state.data || !state.data.checks) return;
        
        const { status, severity, search } = state.filters;
        const searchLower = search.toLowerCase();
        
        state.filteredChecks = state.data.checks.filter(check => {
            // Status filter
            if (status !== 'all') {
                if (status === 'passed' && !check.passed) return false;
                if (status === 'failed' && (check.passed || check.skipped)) return false;
                if (status === 'skipped' && !check.skipped) return false;
            }
            
            // Severity filter
            if (severity !== 'all') {
                const checkSeverity = (check.severity || 'LOW').toUpperCase();
                if (checkSeverity !== severity) return false;
            }
            
            // Search filter
            if (searchLower) {
                const nameMatch = (check.name || '').toLowerCase().includes(searchLower);
                const idMatch = (check.id || '').toLowerCase().includes(searchLower);
                if (!nameMatch && !idMatch) return false;
            }
            
            return true;
        });
        
        renderChecksList(state.filteredChecks);
        updateResultsCount();
    }

    // ============================================
    // File Loading
    // ============================================
    
    /**
     * Load and parse JSON file
     */
    function loadFile(file) {
        if (!file) return;
        
        if (!file.name.endsWith('.json')) {
            alert('Please select a JSON file');
            return;
        }
        
        const reader = new FileReader();
        
        reader.onload = (e) => {
            try {
                const data = JSON.parse(e.target.result);
                validateData(data);
                
                state.data = data;
                state.filteredChecks = data.checks || [];
                
                // Reset filters
                state.filters = { status: 'all', severity: 'all', search: '' };
                elements.searchInput.value = '';
                elements.statusFilter.value = 'all';
                elements.severityFilter.value = 'all';
                
                // Render dashboard
                renderHeader(data.metadata);
                renderSummary(data.summary);
                renderSeverityChart(data.summary?.by_severity);
                renderChecksList(state.filteredChecks);
                updateResultsCount();
                
                // Show dashboard, hide empty state
                elements.emptyState.classList.add('hidden');
                elements.dashboard.classList.remove('hidden');
                elements.exportBtn.disabled = false;
                
            } catch (err) {
                alert(`Error loading file: ${err.message}`);
                console.error('File load error:', err);
            }
        };
        
        reader.onerror = () => {
            alert('Error reading file');
        };
        
        reader.readAsText(file);
    }

    // ============================================
    // Export
    // ============================================
    
    /**
     * Export filtered results as JSON
     */
    function exportResults() {
        if (!state.data) return;
        
        const exportData = {
            metadata: state.data.metadata,
            summary: {
                ...state.data.summary,
                total_checks: state.filteredChecks.length,
                passed: state.filteredChecks.filter(c => c.passed && !c.skipped).length,
                failed: state.filteredChecks.filter(c => !c.passed && !c.skipped).length,
                skipped: state.filteredChecks.filter(c => c.skipped).length
            },
            checks: state.filteredChecks,
            export_info: {
                exported_at: new Date().toISOString(),
                filters_applied: state.filters
            }
        };
        
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `catoscan-export-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ============================================
    // Modal
    // ============================================
    
    function showModal() {
        elements.shortcutsModal.classList.remove('hidden');
    }
    
    function hideModal() {
        elements.shortcutsModal.classList.add('hidden');
    }

    // ============================================
    // Event Handlers
    // ============================================
    
    function initEventListeners() {
        // File inputs
        elements.fileInput.addEventListener('change', (e) => loadFile(e.target.files[0]));
        elements.fileInputEmpty.addEventListener('change', (e) => loadFile(e.target.files[0]));
        
        // Filters
        elements.searchInput.addEventListener('input', (e) => {
            state.filters.search = e.target.value;
            applyFilters();
        });
        
        elements.statusFilter.addEventListener('change', (e) => {
            state.filters.status = e.target.value;
            applyFilters();
        });
        
        elements.severityFilter.addEventListener('change', (e) => {
            state.filters.severity = e.target.value;
            applyFilters();
        });
        
        elements.resetFilters.addEventListener('click', () => {
            state.filters = { status: 'all', severity: 'all', search: '' };
            elements.searchInput.value = '';
            elements.statusFilter.value = 'all';
            elements.severityFilter.value = 'all';
            applyFilters();
            elements.searchInput.focus();
        });
        
        // Export
        elements.exportBtn.addEventListener('click', exportResults);
        
        // Modal
        elements.modalClose.addEventListener('click', hideModal);
        elements.shortcutsModal.addEventListener('click', (e) => {
            if (e.target === elements.shortcutsModal) hideModal();
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+O - Open file
            if (e.ctrlKey && e.key === 'o') {
                e.preventDefault();
                elements.fileInput.click();
            }
            
            // Ctrl+F - Focus search
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                elements.searchInput.focus();
                elements.searchInput.select();
            }
            
            // Escape - Close modal / Clear search
            if (e.key === 'Escape') {
                if (!elements.shortcutsModal.classList.contains('hidden')) {
                    hideModal();
                } else if (document.activeElement === elements.searchInput) {
                    elements.searchInput.value = '';
                    elements.searchInput.blur();
                    state.filters.search = '';
                    applyFilters();
                }
            }
            
            // ? - Show shortcuts
            if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
                const tagName = document.activeElement?.tagName;
                if (tagName !== 'INPUT' && tagName !== 'SELECT' && tagName !== 'TEXTAREA') {
                    e.preventDefault();
                    showModal();
                }
            }
        });
        
        // Drag and drop
        document.addEventListener('dragover', (e) => {
            e.preventDefault();
            document.body.classList.add('drag-over');
        });
        
        document.addEventListener('dragleave', (e) => {
            if (e.target === document.body) {
                document.body.classList.remove('drag-over');
            }
        });
        
        document.addEventListener('drop', (e) => {
            e.preventDefault();
            document.body.classList.remove('drag-over');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                loadFile(files[0]);
            }
        });
    }

    // ============================================
    // Initialization
    // ============================================
    
    function init() {
        initEventListeners();
        console.log('CatoScan Viewer initialized');
    }
    
    // Start the app when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
