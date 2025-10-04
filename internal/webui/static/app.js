(() => {
        const form = document.getElementById('start-form');
        const targetInput = document.getElementById('target');
        const scanInput = document.getElementById('scan');
        const statusPhase = document.getElementById('status-phase');
        const statusPercent = document.getElementById('status-percent');
        const statusMessage = document.getElementById('status-message');
        const resultsEl = document.getElementById('results');
        const startError = document.getElementById('start-error');
        const consoleEl = document.getElementById('console');
        const progressBar = document.getElementById('progress-bar');
        const lanCard = document.getElementById('lan-card');
        const lanDest = document.getElementById('lan-dest');
        const lanAvg = document.getElementById('lan-avg');
        const lanP95 = document.getElementById('lan-p95');
        const lanJitter = document.getElementById('lan-jitter');
        const wanCard = document.getElementById('wan-card');
        const wanDest = document.getElementById('wan-dest');
        const wanAvg = document.getElementById('wan-avg');
        const wanP95 = document.getElementById('wan-p95');
        const wanJitter = document.getElementById('wan-jitter');
        const devicesCard = document.getElementById('devices-card');
        const devicesBody = document.getElementById('devices-body');
        const vendorCard = document.getElementById('vendor-card');
        const vendorMessage = document.getElementById('vendor-message');
        const vendorSummaryList = document.getElementById('vendor-summary');
        const vendorFindingsList = document.getElementById('vendor-findings');
        const vendorOpenBtn = document.getElementById('vendor-open');
        const vendorModal = document.getElementById('vendor-modal');
        const vendorModalText = document.getElementById('vendor-modal-text');
        const vendorForm = document.getElementById('vendor-form');
        const vendorError = document.getElementById('vendor-error');
        const vendorCancel = document.getElementById('vendor-cancel');
        const vendorFortiSection = document.getElementById('vendor-forti');
        const vendorCiscoSection = document.getElementById('vendor-cisco');
        const fortiHostInput = document.getElementById('forti-host');
        const fortiUserInput = document.getElementById('forti-user');
        const fortiPassInput = document.getElementById('forti-pass');
        const ciscoHostInput = document.getElementById('cisco-host');
        const ciscoUserInput = document.getElementById('cisco-user');
        const ciscoPassInput = document.getElementById('cisco-pass');
        const ciscoSecretInput = document.getElementById('cisco-secret');
        const ciscoPortInput = document.getElementById('cisco-port');
        const bundleBtn = document.getElementById('download-bundle');
        const historyList = document.getElementById('history-list');
        const historyEmpty = document.getElementById('history-empty');
        const historyCompare = document.getElementById('history-compare');
        const compareLabel = document.getElementById('compare-label');
        const clearCompareBtn = document.getElementById('clear-compare');
        const compareCard = document.getElementById('compare-card');
        const compareSummary = document.getElementById('compare-summary');
        const compareGwLoss = document.getElementById('compare-gw-loss');
        const compareGwRtt = document.getElementById('compare-gw-rtt');
        const compareGwJitter = document.getElementById('compare-gw-jitter');
        const compareWanLoss = document.getElementById('compare-wan-loss');
        const compareWanRtt = document.getElementById('compare-wan-rtt');
        const compareWanJitter = document.getElementById('compare-wan-jitter');
        const compareMtu = document.getElementById('compare-mtu');
        const troubleshooterLanBtn = document.getElementById('troubleshooter-lan');
        const troubleshooterWanBtn = document.getElementById('troubleshooter-wan');
        const troubleshooterBody = document.getElementById('troubleshooter-body');
        const troubleshooterTitle = document.getElementById('troubleshooter-title');
        const troubleshooterIntro = document.getElementById('troubleshooter-intro');
        const troubleshooterChecklist = document.getElementById('troubleshooter-checklist');
        const troubleshooterStatus = document.getElementById('troubleshooter-status');
        const troubleshooterError = document.getElementById('troubleshooter-error');

        const PHASE_LABELS = {
                idle: 'Idle',
                starting: 'Starting',
                netinfo: 'Network info',
                'l2-scan': 'Layer-2 scan',
                gateway: 'Gateway checks',
                dns: 'DNS lookups',
                wan: 'WAN ping',
                traceroute: 'Traceroute',
                mtu: 'MTU probe',
                'python-packs': 'Vendor packs',
                snmp: 'SNMP',
                finalizing: 'Finalizing',
                finished: 'Finished',
                error: 'Error',
        };

        const consoleCard = consoleEl ? consoleEl.closest('.card') : null;
        const highlightableCards = [lanCard, wanCard, devicesCard, compareCard, consoleCard].filter(Boolean);
        const troubleshooterButtons = [troubleshooterLanBtn, troubleshooterWanBtn].filter(Boolean);

        const TROUBLESHOOTER_DEFAULT_STATUS = 'Pick a guided path above to run a focused check.';
        const TROUBLESHOOTER_MODES = {
                lan: {
                        title: 'LAN health checklist',
                        intro: 'Focus on gateway reachability and conditions inside your local network.',
                        checklist: [
                                'Review LAN performance for RTT, 95th percentile, and jitter spikes against the default gateway.',
                                'Watch the console for packet loss or ARP failures while gateway tests run.',
                                'Check Discovered Devices for duplicate IP/MAC addresses or unexpected hardware.',
                        ],
                        scan: true,
                        statusMessage: 'Running LAN-focused diagnostics… (extra gateway pings and local discovery).',
                        completeMessage: 'LAN-focused diagnostics finished. Review the highlighted panels below.',
                },
                wan: {
                        title: 'WAN reachability checklist',
                        intro: 'Zero in on Internet latency, DNS resolution, and upstream routing.',
                        checklist: [
                                'Inspect WAN performance for latency, packet loss, and jitter toward your Internet target.',
                                'Follow the console output for DNS lookups and traceroute hops to spot upstream issues.',
                                'Use the Comparison panel to contrast this run with a previous healthy baseline.',
                        ],
                        scan: false,
                        statusMessage: 'Running WAN-focused diagnostics… (external reachability and DNS checks).',
                        completeMessage: 'WAN-focused diagnostics finished. Review the highlighted WAN insights.',
                },
        };

        let eventSource = null;
        let lastVendorSuggestions = [];
        let vendorPromptShown = false;
        let displayedResults = null;
        let displayedRunId = null;
        let latestRunId = null;
        let compareResults = null;
        let compareRunId = null;
        let historyEntries = [];
        const historyCache = new Map();
        let activeTroubleshooterMode = null;
        let troubleshooterPendingRun = false;

        const MINUS = '\u2212';

        function ensureStream() {
                if (eventSource) {
                        return;
                }
                eventSource = new EventSource('/api/stream');
                eventSource.addEventListener('phase', handlePhaseEvent);
                eventSource.addEventListener('step', handleStepEvent);
                eventSource.addEventListener('done', handleDoneEvent);
                eventSource.onerror = () => {
                        // Let EventSource reconnect automatically.
                };
        }

        async function updateStatus() {
                try {
                        const resp = await fetch('/api/status');
                        if (!resp.ok) {
                                throw new Error('Status request failed');
                        }
                        const data = await resp.json();
                        applyPhase(data.phase || 'idle');
                        setProgress(data.percent ?? 0);
                        if (data.message) {
                                statusMessage.textContent = data.message;
                        }
                } catch (err) {
                        console.error(err);
                }
        }

        async function loadResults() {
                try {
                        const resp = await fetch('/api/results');
                        if (resp.status === 204) {
                                applyRunData(null, { message: '(Results not available yet)', allowBundle: false });
                                await refreshHistory();
                                return;
                        }
                        if (!resp.ok) {
                                throw new Error('Results request failed');
                        }
                        const data = await resp.json();
                        const runId = typeof data.history_id === 'string' && data.history_id.trim() !== '' ? data.history_id.trim() : null;
                        if (runId) {
                                historyCache.set(runId, data);
                                latestRunId = runId;
                        }
                        applyRunData(data, { runId, allowBundle: !runId || runId === latestRunId });
                        await refreshHistory();
                } catch (err) {
                        console.error(err);
                        applyRunData(null, { message: '(Unable to load results)', allowBundle: false });
                }
        }

        function applyRunData(data, { runId = null, message = '', allowBundle } = {}) {
                displayedResults = data || null;
                displayedRunId = runId || null;
                if (resultsEl) {
                        if (data) {
                                resultsEl.textContent = JSON.stringify(data, null, 2);
                        } else if (message) {
                                resultsEl.textContent = message;
                        } else {
                                resultsEl.textContent = '(Results not available yet)';
                        }
                }
                populatePerformanceCards(data);
                populateDevicesTable(data && Array.isArray(data.discovered) ? data.discovered : null);
                populateVendorCard(data);
                if (typeof allowBundle === 'boolean') {
                        setBundleAvailability(allowBundle);
                } else if (runId) {
                        setBundleAvailability(runId === latestRunId);
                } else {
                        setBundleAvailability(!!data);
                }
                updateCompareCard();
                updateHistorySelection();
        }

        async function refreshHistory() {
                if (!historyList) {
                        return;
                }
                try {
                        const resp = await fetch('/api/history');
                        if (!resp.ok) {
                                throw new Error('History request failed');
                        }
                        const data = await resp.json();
                        if (Array.isArray(data)) {
                                historyEntries = data;
                        } else {
                                historyEntries = [];
                        }
                        renderHistory(historyEntries);
                } catch (err) {
                        console.error(err);
                }
        }

        function renderHistory(entries) {
                if (!historyList) {
                        return;
                }
                historyList.innerHTML = '';
                const list = Array.isArray(entries) ? entries.filter((entry) => entry && entry.id) : [];
                if (historyEmpty) {
                        historyEmpty.hidden = list.length > 0;
                }
                if (list.length === 0) {
                        updateHistorySelection();
                        return;
                }
                const fragment = document.createDocumentFragment();
                for (const entry of list) {
                        const li = document.createElement('li');
                        li.className = 'history-item';
                        li.dataset.runId = entry.id;

                        const selectBtn = document.createElement('button');
                        selectBtn.type = 'button';
                        selectBtn.className = 'history-select';
                        selectBtn.dataset.action = 'select-run';
                        selectBtn.dataset.runId = entry.id;

                        const timeSpan = document.createElement('span');
                        timeSpan.className = 'history-run-time';
                        timeSpan.textContent = formatHistoryTime(entry.when);
                        selectBtn.appendChild(timeSpan);

                        const targetSpan = document.createElement('span');
                        targetSpan.className = 'history-run-target';
                        targetSpan.textContent = entry.target && entry.target.trim() !== '' ? entry.target : '(unknown target)';
                        selectBtn.appendChild(targetSpan);

                        if (entry.classification && entry.classification.trim() !== '') {
                                const classificationSpan = document.createElement('span');
                                classificationSpan.className = 'history-run-classification';
                                classificationSpan.textContent = entry.classification.trim();
                                selectBtn.appendChild(classificationSpan);
                        }

                        li.appendChild(selectBtn);

                        const compareBtn = document.createElement('button');
                        compareBtn.type = 'button';
                        compareBtn.className = 'history-compare-btn';
                        compareBtn.dataset.action = 'compare-run';
                        compareBtn.dataset.runId = entry.id;
                        compareBtn.textContent = 'Compare';
                        li.appendChild(compareBtn);

                        fragment.appendChild(li);
                }
                historyList.appendChild(fragment);
                updateHistorySelection();
        }

        function updateHistorySelection() {
                if (historyEmpty) {
                        const hasEntries = Array.isArray(historyEntries) && historyEntries.length > 0;
                        historyEmpty.hidden = hasEntries;
                }
                if (historyList) {
                        const items = historyList.querySelectorAll('.history-item');
                        items.forEach((item) => {
                                const runId = item.dataset.runId || '';
                                const isActive = displayedRunId && runId === displayedRunId;
                                const isCompare = compareRunId && runId === compareRunId;
                                item.classList.toggle('is-active', Boolean(isActive));
                                item.classList.toggle('is-compare', Boolean(isCompare));
                                const compareBtn = item.querySelector('.history-compare-btn');
                                if (compareBtn) {
                                        compareBtn.textContent = isCompare ? 'Selected' : 'Compare';
                                }
                        });
                }
                if (historyCompare && compareLabel) {
                        if (compareRunId) {
                                historyCompare.hidden = false;
                                compareLabel.textContent = formatHistoryLabel(compareRunId, compareResults);
                        } else {
                                historyCompare.hidden = true;
                                compareLabel.textContent = '';
                        }
                }
        }

        function formatHistoryTime(value) {
                if (!value) {
                        return 'Unknown time';
                }
                const date = new Date(value);
                if (Number.isNaN(date.getTime())) {
                        return String(value);
                }
                const now = new Date();
                const options = { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
                if (date.getFullYear() !== now.getFullYear()) {
                        options.year = 'numeric';
                }
                return new Intl.DateTimeFormat(undefined, options).format(date);
        }

        function formatHistoryLabel(runId, result) {
                const trimmed = typeof runId === 'string' ? runId.trim() : '';
                if (trimmed) {
                        const fromList = Array.isArray(historyEntries)
                                ? historyEntries.find((entry) => entry && entry.id === trimmed)
                                : null;
                        if (fromList && fromList.when) {
                                return formatHistoryTime(fromList.when);
                        }
                        const cached = historyCache.get(trimmed) || result;
                        if (cached && cached.when) {
                                return formatHistoryTime(cached.when);
                        }
                        return trimmed;
                }
                if (result && result.when) {
                        return formatHistoryTime(result.when);
                }
                return 'Current run';
        }

        async function loadHistoryRun(runId) {
                const trimmed = typeof runId === 'string' ? runId.trim() : '';
                if (trimmed === '') {
                        return null;
                }
                if (historyCache.has(trimmed)) {
                        return historyCache.get(trimmed);
                }
                const resp = await fetch(`/api/run/${encodeURIComponent(trimmed)}`);
                if (resp.status === 404) {
                        await refreshHistory();
                        return null;
                }
                if (!resp.ok) {
                        throw new Error('Run request failed');
                }
                const data = await resp.json();
                historyCache.set(trimmed, data);
                return data;
        }

        async function selectHistoryRun(runId) {
                const trimmed = typeof runId === 'string' ? runId.trim() : '';
                if (trimmed === '') {
                        return;
                }
                try {
                        const data = await loadHistoryRun(trimmed);
                        if (!data) {
                                if (resultsEl) {
                                        resultsEl.textContent = '(Run not found)';
                                }
                                updateCompareCard();
                                updateHistorySelection();
                                return;
                        }
                        historyCache.set(trimmed, data);
                        applyRunData(data, { runId: trimmed, allowBundle: trimmed === latestRunId });
                } catch (err) {
                        console.error(err);
                        if (resultsEl) {
                                resultsEl.textContent = '(Unable to load run)';
                        }
                        updateCompareCard();
                        updateHistorySelection();
                }
        }

        async function toggleCompare(runId) {
                const trimmed = typeof runId === 'string' ? runId.trim() : '';
                if (trimmed === '') {
                        return;
                }
                if (compareRunId === trimmed) {
                        setCompareResults(null, null);
                        return;
                }
                try {
                        const data = await loadHistoryRun(trimmed);
                        if (!data) {
                                setCompareResults(null, null);
                                return;
                        }
                        historyCache.set(trimmed, data);
                        setCompareResults(data, trimmed);
                } catch (err) {
                        console.error(err);
                }
        }

        function setCompareResults(data, runId) {
                if (data && runId) {
                        compareRunId = runId;
                        compareResults = data;
                        historyCache.set(runId, data);
                } else {
                        compareRunId = null;
                        compareResults = null;
                }
                updateCompareCard();
                updateHistorySelection();
        }

        function updateCompareCard() {
                if (!compareCard) {
                        if (historyCompare && compareLabel) {
                                if (compareRunId) {
                                        historyCompare.hidden = false;
                                        compareLabel.textContent = formatHistoryLabel(compareRunId, compareResults);
                                } else {
                                        historyCompare.hidden = true;
                                        compareLabel.textContent = '';
                                }
                        }
                        return;
                }
                if (!displayedResults || !compareResults || !compareRunId) {
                        compareCard.hidden = true;
                        if (historyCompare && compareLabel) {
                                if (compareRunId) {
                                        historyCompare.hidden = false;
                                        compareLabel.textContent = formatHistoryLabel(compareRunId, compareResults);
                                } else {
                                        historyCompare.hidden = true;
                                        compareLabel.textContent = '';
                                }
                        }
                        return;
                }
                compareCard.hidden = false;
                if (compareSummary) {
                        const primaryLabel = formatHistoryLabel(displayedRunId, displayedResults);
                        const secondaryLabel = formatHistoryLabel(compareRunId, compareResults);
                        compareSummary.textContent = `${primaryLabel} vs ${secondaryLabel}`;
                }
                setLossDelta(compareGwLoss, displayedResults ? displayedResults.gw_ping : null, compareResults ? compareResults.gw_ping : null);
                setMsDelta(compareGwRtt, displayedResults ? displayedResults.gw_ping : null, compareResults ? compareResults.gw_ping : null, 'avg_ms');
                setMsDelta(compareGwJitter, displayedResults ? displayedResults.gw_ping : null, compareResults ? compareResults.gw_ping : null, 'jitter_ms');
                setLossDelta(compareWanLoss, displayedResults ? displayedResults.wan_ping : null, compareResults ? compareResults.wan_ping : null);
                setMsDelta(compareWanRtt, displayedResults ? displayedResults.wan_ping : null, compareResults ? compareResults.wan_ping : null, 'avg_ms');
                setMsDelta(compareWanJitter, displayedResults ? displayedResults.wan_ping : null, compareResults ? compareResults.wan_ping : null, 'jitter_ms');
                setMtuDelta(compareMtu, displayedResults ? displayedResults.mtu : null, compareResults ? compareResults.mtu : null);
                if (historyCompare && compareLabel) {
                        historyCompare.hidden = false;
                        compareLabel.textContent = formatHistoryLabel(compareRunId, compareResults);
                }
        }

        function setLossDelta(element, primaryPing, referencePing) {
                if (!element) {
                        return;
                }
                const primary = getLossPercent(primaryPing);
                const reference = getLossPercent(referencePing);
                element.textContent = formatDelta(primary, reference, formatPercentValue, formatPercentDelta);
        }

        function setMsDelta(element, primaryPing, referencePing, key) {
                if (!element) {
                        return;
                }
                const primary = getPingMetric(primaryPing, key);
                const reference = getPingMetric(referencePing, key);
                element.textContent = formatDelta(primary, reference, formatMsValue, formatMsDelta);
        }

        function setMtuDelta(element, primaryMtu, referenceMtu) {
                if (!element) {
                        return;
                }
                const primary = extractMtuValue(primaryMtu);
                const reference = extractMtuValue(referenceMtu);
                if (!Number.isFinite(primary)) {
                        element.textContent = '—';
                        return;
                }
                const baseText = `${Math.round(primary)} bytes`;
                if (!Number.isFinite(reference)) {
                        element.textContent = `${baseText} (Δ n/a)`;
                        return;
                }
                const delta = primary - reference;
                if (delta === 0) {
                        element.textContent = `${baseText} (Δ 0 bytes)`;
                        return;
                }
                const sign = delta > 0 ? '+' : MINUS;
                element.textContent = `${baseText} (Δ ${sign}${Math.abs(delta)} bytes)`;
        }

        function getLossPercent(ping) {
                if (!ping || typeof ping.loss !== 'number') {
                        return Number.NaN;
                }
                const percent = ping.loss * 100;
                return Number.isFinite(percent) ? percent : Number.NaN;
        }

        function getPingMetric(ping, key) {
                if (!ping || typeof ping[key] !== 'number') {
                        return Number.NaN;
                }
                const value = ping[key];
                return Number.isFinite(value) ? value : Number.NaN;
        }

        function extractMtuValue(mtu) {
                if (!mtu || typeof mtu.path_mtu !== 'number') {
                        return Number.NaN;
                }
                const value = mtu.path_mtu;
                if (!Number.isFinite(value) || value <= 0) {
                        return Number.NaN;
                }
                return value;
        }

        function formatDelta(current, reference, formatValue, formatDiff) {
                if (!Number.isFinite(current)) {
                        return '—';
                }
                const baseText = formatValue(current);
                if (!Number.isFinite(reference)) {
                        return `${baseText} (Δ n/a)`;
                }
                return `${baseText} (Δ ${formatDiff(current - reference)})`;
        }

        function formatPercentValue(value) {
                if (!Number.isFinite(value)) {
                        return '—';
                }
                const decimals = Math.abs(value) >= 10 ? 0 : 1;
                return `${value.toFixed(decimals)}%`;
        }

        function formatPercentDelta(delta) {
                if (!Number.isFinite(delta)) {
                        return 'n/a';
                }
                if (delta === 0) {
                        return '0%';
                }
                const decimals = Math.abs(delta) >= 10 ? 0 : 1;
                const sign = delta > 0 ? '+' : MINUS;
                return `${sign}${Math.abs(delta).toFixed(decimals)}%`;
        }

        function formatMsValue(value) {
                if (!Number.isFinite(value)) {
                        return '—';
                }
                const decimals = Math.abs(value) >= 10 ? 0 : 1;
                return `${value.toFixed(decimals)} ms`;
        }

        function formatMsDelta(delta) {
                if (!Number.isFinite(delta)) {
                        return 'n/a';
                }
                if (delta === 0) {
                        return '0 ms';
                }
                const decimals = Math.abs(delta) >= 10 ? 0 : 1;
                const sign = delta > 0 ? '+' : MINUS;
                return `${sign}${Math.abs(delta).toFixed(decimals)} ms`;
        }

        function setTroubleshooterStatus(message) {
                if (!troubleshooterStatus) {
                        return;
                }
                troubleshooterStatus.textContent = message || '';
        }

        function populateTroubleshooterChecklist(items) {
                if (!troubleshooterChecklist) {
                        return;
                }
                troubleshooterChecklist.innerHTML = '';
                if (!Array.isArray(items) || items.length === 0) {
                        return;
                }
                for (const item of items) {
                        if (typeof item !== 'string' || item.trim() === '') {
                                continue;
                        }
                        const entry = document.createElement('li');
                        entry.textContent = item.trim();
                        troubleshooterChecklist.appendChild(entry);
                }
        }

        function setTroubleshooterActiveButton(mode) {
                for (const btn of troubleshooterButtons) {
                        if (!btn) {
                                continue;
                        }
                        const isActive = btn.dataset && btn.dataset.mode === mode;
                        btn.classList.toggle('is-active', Boolean(isActive));
                }
        }

        function setFocusHighlights(mode) {
                for (const card of highlightableCards) {
                        card.classList.remove('card-focus');
                }
                if (!mode) {
                        return;
                }
                const targets = mode === 'lan'
                        ? [lanCard, devicesCard, consoleCard]
                        : mode === 'wan'
                                ? [wanCard, compareCard, consoleCard]
                                : [];
                for (const card of targets) {
                        if (card) {
                                card.classList.add('card-focus');
                        }
                }
        }

        function setTroubleshooterBusy(busy) {
                for (const btn of troubleshooterButtons) {
                        if (!btn) {
                                continue;
                        }
                        btn.disabled = Boolean(busy);
                }
        }

        function handleTroubleshooterCompletion(status) {
                if (!troubleshooterPendingRun) {
                        setTroubleshooterBusy(false);
                        return;
                }
                const config = activeTroubleshooterMode ? TROUBLESHOOTER_MODES[activeTroubleshooterMode] : null;
                if (config) {
                        if (status === 'finished') {
                                setTroubleshooterStatus(config.completeMessage || 'Focused diagnostics finished.');
                        } else if (status === 'error') {
                                setTroubleshooterStatus('Focused diagnostics failed. Review the console for details.');
                        } else {
                                setTroubleshooterStatus(config.statusMessage || TROUBLESHOOTER_DEFAULT_STATUS);
                        }
                        setFocusHighlights(activeTroubleshooterMode);
                } else {
                        setTroubleshooterStatus(TROUBLESHOOTER_DEFAULT_STATUS);
                }
                setTroubleshooterBusy(false);
                troubleshooterPendingRun = false;
        }

        async function startRun(payload = {}, options = {}) {
                const {
                        errorElement = startError,
                        statusOverride = null,
                        conflictMessage = 'A run is already in progress.',
                        failureMessage = 'Unable to start diagnostics.',
                        unexpectedMessage = 'Unexpected error starting diagnostics.',
                } = options;

                if (errorElement) {
                        errorElement.hidden = true;
                        errorElement.textContent = '';
                }

                const requestTarget = typeof payload.target === 'string'
                        ? payload.target.trim()
                        : (targetInput ? targetInput.value.trim() : '');
                const requestScan = typeof payload.scan === 'boolean'
                        ? payload.scan
                        : Boolean(scanInput && scanInput.checked);
                const request = { target: requestTarget, scan: requestScan };

                try {
                        const resp = await fetch('/api/start', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(request),
                        });
                        if (resp.status === 409) {
                                if (errorElement) {
                                        errorElement.textContent = conflictMessage;
                                        errorElement.hidden = false;
                                }
                                return false;
                        }
                        if (!resp.ok) {
                                if (errorElement) {
                                        errorElement.textContent = failureMessage;
                                        errorElement.hidden = false;
                                }
                                return false;
                        }
                        if (resultsEl) {
                                resultsEl.textContent = '(Working…)';
                        }
                        statusMessage.textContent = statusOverride || 'Starting diagnostics…';
                        applyPhase('starting');
                        setProgress(5);
                        clearDevicesTable();
                        setBundleAvailability(false);
                        return true;
                } catch (err) {
                        console.error(err);
                        if (errorElement) {
                                errorElement.textContent = unexpectedMessage;
                                errorElement.hidden = false;
                        }
                        return false;
                }
        }

        form.addEventListener('submit', async (event) => {
                event.preventDefault();
                const payload = {
                        target: targetInput ? targetInput.value.trim() : '',
                        scan: Boolean(scanInput && scanInput.checked),
                };
                await startRun(payload, { errorElement: startError });
        });

        async function triggerTroubleshooter(mode) {
                const config = TROUBLESHOOTER_MODES[mode];
                if (!config) {
                        return;
                }
                activeTroubleshooterMode = mode;
                troubleshooterPendingRun = false;
                if (troubleshooterBody) {
                        troubleshooterBody.hidden = false;
                }
                if (troubleshooterError) {
                        troubleshooterError.hidden = true;
                        troubleshooterError.textContent = '';
                }
                if (troubleshooterTitle) {
                        troubleshooterTitle.textContent = config.title || '';
                }
                if (troubleshooterIntro) {
                        troubleshooterIntro.textContent = config.intro || '';
                }
                populateTroubleshooterChecklist(config.checklist || []);
                setTroubleshooterActiveButton(mode);
                setFocusHighlights(mode);
                const statusText = config.statusMessage || 'Running focused diagnostics…';
                setTroubleshooterStatus(statusText);
                setTroubleshooterBusy(true);

                const payload = {};
                if (typeof config.scan === 'boolean') {
                        payload.scan = config.scan;
                        if (scanInput) {
                                scanInput.checked = config.scan;
                        }
                }
                if (targetInput) {
                        const trimmed = targetInput.value.trim();
                        targetInput.value = trimmed;
                        payload.target = trimmed;
                }

                const success = await startRun(payload, {
                        errorElement: troubleshooterError,
                        statusOverride: statusText,
                        conflictMessage: 'Please wait for the current run to finish before starting another troubleshooter pass.',
                        failureMessage: 'Unable to start focused diagnostics.',
                        unexpectedMessage: 'Unexpected error starting focused diagnostics.',
                });

                if (success) {
                        troubleshooterPendingRun = true;
                } else {
                        setTroubleshooterBusy(false);
                        if (!troubleshooterError || troubleshooterError.hidden) {
                                setTroubleshooterStatus('Unable to start focused diagnostics. Try again shortly.');
                        }
                }
        }

        if (troubleshooterLanBtn) {
                troubleshooterLanBtn.addEventListener('click', () => triggerTroubleshooter('lan'));
        }
        if (troubleshooterWanBtn) {
                troubleshooterWanBtn.addEventListener('click', () => triggerTroubleshooter('wan'));
        }

        setTroubleshooterStatus(TROUBLESHOOTER_DEFAULT_STATUS);
        populateTroubleshooterChecklist([]);
        setFocusHighlights(null);

        function applyPhase(phase) {
                const label = PHASE_LABELS[phase] || phase || 'unknown';
                statusPhase.textContent = label;
        }

        function setProgress(value) {
                const percent = Number.isFinite(value) ? value : 0;
                const clamped = Math.max(0, Math.min(100, percent));
                const display = Math.round(clamped * 10) / 10;
                statusPercent.textContent = `${display}%`;
                if (progressBar) {
                        progressBar.style.width = `${clamped}%`;
                }
        }

        function clearConsole() {
                if (!consoleEl) {
                        return;
                }
                consoleEl.innerHTML = '';
                const empty = document.createElement('div');
                empty.className = 'console-empty';
                empty.textContent = 'No activity yet.';
                consoleEl.appendChild(empty);
        }

        function appendConsole(msg) {
                if (!consoleEl || !msg) {
                        return;
                }
                const first = consoleEl.firstElementChild;
                if (first && first.classList.contains('console-empty')) {
                        consoleEl.innerHTML = '';
                }
                const line = document.createElement('div');
                line.className = 'console-line';
                line.textContent = msg;
                consoleEl.appendChild(line);
                consoleEl.scrollTop = consoleEl.scrollHeight;
        }

        function parseEventData(raw) {
                try {
                        return JSON.parse(raw);
                } catch (err) {
                        console.error('Unable to parse event payload', err);
                        return null;
                }
        }

        function handlePhaseEvent(event) {
                const data = parseEventData(event.data);
                if (!data) {
                        return;
                }
                if (data.reset) {
                        clearConsole();
                        resetVendorState();
                        setBundleAvailability(false);
                }
                if (data.name) {
                        applyPhase(data.name);
                }
                if (typeof data.percent === 'number') {
                        setProgress(data.percent);
                }
                if (typeof data.message === 'string') {
                        statusMessage.textContent = data.message;
                }
        }

        function handleStepEvent(event) {
                const data = parseEventData(event.data);
                if (!data || typeof data.msg !== 'string') {
                        return;
                }
                appendConsole(data.msg);
                statusMessage.textContent = data.msg;
        }

        async function handleDoneEvent(event) {
                const data = parseEventData(event.data);
                if (!data) {
                        return;
                }
                if (data.message) {
                        statusMessage.textContent = data.message;
                }
                if (data.status === 'finished') {
                        await loadResults();
                } else if (data.status === 'error') {
                        resultsEl.textContent = '(Run failed)';
                        populatePerformanceCards(null);
                        populateDevicesTable(null);
                        setBundleAvailability(false);
                }
                handleTroubleshooterCompletion(data.status);
        }

        function setBundleAvailability(available) {
                if (!bundleBtn) {
                        return;
                }
                if (available) {
                        bundleBtn.hidden = false;
                        bundleBtn.disabled = false;
                } else {
                        bundleBtn.hidden = true;
                        bundleBtn.disabled = false;
                }
        }

        function parseBundleFilename(disposition) {
                if (typeof disposition !== 'string' || disposition.trim() === '') {
                        return '';
                }
                const utfMatch = disposition.match(/filename\*=UTF-8''([^;]+)/i);
                if (utfMatch && utfMatch[1]) {
                        try {
                                return decodeURIComponent(utfMatch[1]);
                        } catch (err) {
                                console.error('Unable to decode filename', err);
                        }
                }
                const simpleMatch = disposition.match(/filename="?([^";]+)"?/i);
                if (simpleMatch && simpleMatch[1]) {
                        return simpleMatch[1];
                }
                return '';
        }

        async function downloadBundle() {
                if (!bundleBtn) {
                        return;
                }
                bundleBtn.disabled = true;
                try {
                        const resp = await fetch('/api/bundle');
                        if (resp.status === 204) {
                                setBundleAvailability(false);
                                return;
                        }
                        if (!resp.ok) {
                                throw new Error('Bundle request failed');
                        }
                        const blob = await resp.blob();
                        const url = URL.createObjectURL(blob);
                        const disposition = resp.headers.get('Content-Disposition');
                        const filename = parseBundleFilename(disposition) || 'vne-evidence.zip';
                        const link = document.createElement('a');
                        link.href = url;
                        link.download = filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        setTimeout(() => URL.revokeObjectURL(url), 1000);
                } catch (err) {
                        console.error(err);
                } finally {
                        bundleBtn.disabled = false;
                }
        }

        function formatMs(value) {
                if (!Number.isFinite(value) || value < 0) {
                        return '—';
                }
                const decimals = value >= 10 ? 0 : 1;
                return `${value.toFixed(decimals)} ms`;
        }

        function populatePerformanceCards(data) {
                if (lanCard) {
                        if (!data || !data.has_gateway) {
                                lanCard.hidden = true;
                        } else {
                                updatePerformanceCard(
                                        lanCard,
                                        lanDest,
                                        lanAvg,
                                        lanP95,
                                        lanJitter,
                                        data.gw_ping,
                                        data.gw_jitter_ms,
                                        data.gateway_used || '(unknown)'
                                );
                        }
                }
                if (wanCard) {
                        updatePerformanceCard(
                                wanCard,
                                wanDest,
                                wanAvg,
                                wanP95,
                                wanJitter,
                                data ? data.wan_ping : null,
                                data ? data.wan_jitter_ms : undefined,
                                data && data.target_host ? data.target_host : '(unknown)'
                        );
                }
        }

        function clearDevicesTable() {
                if (!devicesCard) {
                        return;
                }
                devicesCard.hidden = true;
                if (devicesBody) {
                        devicesBody.innerHTML = '';
                }
        }

        function populateDevicesTable(hosts) {
                if (!devicesCard || !devicesBody) {
                        return;
                }
                devicesBody.innerHTML = '';
                const list = Array.isArray(hosts) ? hosts.filter(Boolean) : [];
                if (list.length === 0) {
                        devicesCard.hidden = true;
                        return;
                }
                const sorted = [...list].sort((a, b) => {
                        const ifaceA = (a.if_name || '').toLowerCase();
                        const ifaceB = (b.if_name || '').toLowerCase();
                        if (ifaceA !== ifaceB) {
                                return ifaceA.localeCompare(ifaceB);
                        }
                        const ipA = a.ip || '';
                        const ipB = b.ip || '';
                        return ipA.localeCompare(ipB, undefined, { numeric: true });
                });
                for (const host of sorted) {
                        const row = document.createElement('tr');
                        const ifaceCell = document.createElement('td');
                        ifaceCell.textContent = host.if_name || '—';
                        row.appendChild(ifaceCell);

                        const ipCell = document.createElement('td');
                        ipCell.textContent = host.ip || '—';
                        ipCell.classList.add('mono');
                        row.appendChild(ipCell);

                        const macCell = document.createElement('td');
                        const macText = typeof host.mac === 'string' ? host.mac.toUpperCase() : '—';
                        macCell.textContent = macText || '—';
                        macCell.classList.add('mono');
                        row.appendChild(macCell);

                        const vendorCell = document.createElement('td');
                        vendorCell.textContent = host.vendor || '—';
                        row.appendChild(vendorCell);

                        devicesBody.appendChild(row);
                }
                devicesCard.hidden = false;
        }

        function populateVendorCard(data) {
                if (!vendorCard || !vendorMessage) {
                        return;
                }
                const suggestions = Array.isArray(data && data.vendor_suggestions) ? data.vendor_suggestions : [];
                const summaries = Array.isArray(data && data.vendor_summaries) ? data.vendor_summaries : [];
                const findings = Array.isArray(data && data.vendor_findings) ? data.vendor_findings : [];
                lastVendorSuggestions = suggestions;

                renderFindingList(vendorSummaryList, summaries);
                renderFindingList(vendorFindingsList, findings);

                if (suggestions.length === 0 && summaries.length === 0 && findings.length === 0) {
                        vendorCard.hidden = true;
                        if (vendorOpenBtn) {
                                vendorOpenBtn.hidden = true;
                        }
                        vendorMessage.textContent = '';
                        return;
                }

                vendorCard.hidden = false;
                const vendorListText = formatVendorList(suggestions);
                if (summaries.length === 0 && findings.length === 0) {
                        vendorMessage.textContent = vendorListText
                                ? `Detected ${vendorListText} device${suggestions.length > 1 ? 's' : ''}. Provide credentials to run vendor checks.`
                                : '';
                        if (vendorOpenBtn) {
                                vendorOpenBtn.hidden = false;
                                vendorOpenBtn.textContent = 'Provide credentials';
                        }
                        if (!vendorPromptShown && suggestions.length > 0) {
                                vendorPromptShown = true;
                                openVendorModal(suggestions);
                        }
                } else {
                        vendorMessage.textContent = vendorListText ? `Vendor checks available for ${vendorListText}.` : 'Vendor checks complete.';
                        if (vendorOpenBtn) {
                                vendorOpenBtn.hidden = suggestions.length === 0;
                                vendorOpenBtn.textContent = 'Run again';
                        }
                        vendorPromptShown = true;
                }
        }

        function renderFindingList(container, items) {
                if (!container) {
                        return;
                }
                container.innerHTML = '';
                if (!Array.isArray(items) || items.length === 0) {
                        container.hidden = true;
                        return;
                }
                for (const item of items) {
                        if (!item) {
                                continue;
                        }
                        const li = document.createElement('li');
                        const severity = typeof item.severity === 'string' && item.severity.trim() !== '' ? item.severity.trim().toUpperCase() : '';
                        const message = typeof item.message === 'string' ? item.message : '';
                        if (severity) {
                                const strong = document.createElement('strong');
                                strong.textContent = severity;
                                li.appendChild(strong);
                                if (message) {
                                        li.appendChild(document.createTextNode(` — ${message}`));
                                }
                        } else {
                                li.textContent = message || '(no details)';
                        }
                        container.appendChild(li);
                }
                container.hidden = false;
        }

        function formatVendorName(key) {
                switch (key) {
                case 'fortigate':
                        return 'Fortinet';
                case 'cisco_ios':
                        return 'Cisco';
                default:
                        return key || 'Unknown vendor';
                }
        }

        function formatVendorList(list) {
                if (!Array.isArray(list) || list.length === 0) {
                        return '';
                }
                const names = list.map(formatVendorName);
                if (names.length === 1) {
                        return names[0];
                }
                if (names.length === 2) {
                        return `${names[0]} and ${names[1]}`;
                }
                const tail = names.pop();
                return `${names.join(', ')}, and ${tail}`;
        }

        function openVendorModal(suggestions) {
                if (!vendorModal || !Array.isArray(suggestions) || suggestions.length === 0) {
                        return;
                }
                const names = formatVendorList(suggestions);
                if (vendorModalText) {
                        vendorModalText.textContent = names
                                ? `Detected ${names} device${suggestions.length > 1 ? 's' : ''}. Provide credentials to run vendor checks.`
                                : 'Provide credentials to run vendor checks.';
                }
                clearVendorError();
                const showForti = suggestions.includes('fortigate');
                const showCisco = suggestions.includes('cisco_ios');
                if (vendorFortiSection) {
                        vendorFortiSection.hidden = !showForti;
                }
                if (vendorCiscoSection) {
                        vendorCiscoSection.hidden = !showCisco;
                }
                if (!showForti) {
                        if (fortiHostInput) fortiHostInput.value = '';
                        if (fortiUserInput) fortiUserInput.value = '';
                        if (fortiPassInput) fortiPassInput.value = '';
                }
                if (!showCisco) {
                        if (ciscoHostInput) ciscoHostInput.value = '';
                        if (ciscoUserInput) ciscoUserInput.value = '';
                        if (ciscoPassInput) ciscoPassInput.value = '';
                        if (ciscoSecretInput) ciscoSecretInput.value = '';
                        if (ciscoPortInput) ciscoPortInput.value = '';
                }
                vendorModal.hidden = false;
        }

        function closeVendorModal() {
                if (!vendorModal) {
                        return;
                }
                vendorModal.hidden = true;
        }

        function showVendorError(message) {
                if (!vendorError) {
                        return;
                }
                vendorError.textContent = message || 'Unable to start vendor checks.';
                vendorError.hidden = false;
        }

        function clearVendorError() {
                if (!vendorError) {
                        return;
                }
                vendorError.hidden = true;
                vendorError.textContent = '';
        }

        function resetVendorState() {
                lastVendorSuggestions = [];
                vendorPromptShown = false;
                if (vendorCard) {
                        vendorCard.hidden = true;
                }
                if (vendorMessage) {
                        vendorMessage.textContent = '';
                }
                if (vendorSummaryList) {
                        vendorSummaryList.innerHTML = '';
                        vendorSummaryList.hidden = true;
                }
                if (vendorFindingsList) {
                        vendorFindingsList.innerHTML = '';
                        vendorFindingsList.hidden = true;
                }
                if (vendorOpenBtn) {
                        vendorOpenBtn.hidden = true;
                }
                closeVendorModal();
                clearVendorError();
                if (fortiHostInput) fortiHostInput.value = '';
                if (fortiUserInput) fortiUserInput.value = '';
                if (fortiPassInput) fortiPassInput.value = '';
                if (ciscoHostInput) ciscoHostInput.value = '';
                if (ciscoUserInput) ciscoUserInput.value = '';
                if (ciscoPassInput) ciscoPassInput.value = '';
                if (ciscoSecretInput) ciscoSecretInput.value = '';
                if (ciscoPortInput) ciscoPortInput.value = '';
        }

        function updatePerformanceCard(card, destEl, avgEl, p95El, jitterEl, ping, fallbackJitter, destination) {
                if (!card) {
                        return;
                }
                if (!ping || typeof ping !== 'object') {
                        card.hidden = true;
                        return;
                }
                card.hidden = false;
                if (destEl) {
                        destEl.textContent = destination || '(unknown)';
                }
                if (avgEl) {
                        avgEl.textContent = formatMs(ping.avg_ms);
                }
                if (p95El) {
                        p95El.textContent = formatMs(ping.p95_ms);
                }
                const jitterValue = Number.isFinite(ping.jitter_ms) ? ping.jitter_ms : fallbackJitter;
                if (jitterEl) {
                        jitterEl.textContent = formatMs(jitterValue);
                }
        }

        if (bundleBtn) {
                bundleBtn.addEventListener('click', () => {
                        downloadBundle();
                });
        }

        if (vendorOpenBtn) {
                vendorOpenBtn.addEventListener('click', () => {
                        if (lastVendorSuggestions.length > 0) {
                                openVendorModal(lastVendorSuggestions);
                        }
                });
        }

        if (vendorCancel) {
                vendorCancel.addEventListener('click', () => {
                        closeVendorModal();
                });
        }

        if (vendorModal) {
                vendorModal.addEventListener('click', (event) => {
                        if (event.target && event.target.dataset && event.target.dataset.action === 'close') {
                                closeVendorModal();
                        }
                });
        }

        if (vendorForm) {
                vendorForm.addEventListener('submit', async (event) => {
                        event.preventDefault();
                        clearVendorError();
                        if (!Array.isArray(lastVendorSuggestions) || lastVendorSuggestions.length === 0) {
                                showVendorError('Vendor checks are not available right now.');
                                return;
                        }
                        const payload = {};
                        let hasPayload = false;
                        if (lastVendorSuggestions.includes('fortigate')) {
                                const host = fortiHostInput ? fortiHostInput.value.trim() : '';
                                const user = fortiUserInput ? fortiUserInput.value.trim() : '';
                                const pass = fortiPassInput ? fortiPassInput.value.trim() : '';
                                if (host || user || pass) {
                                        if (!host || !user || !pass) {
                                                showVendorError('Please complete Fortinet host, username, and password.');
                                                return;
                                        }
                                        payload.forti_host = host;
                                        payload.forti_user = user;
                                        payload.forti_pass = pass;
                                        hasPayload = true;
                                }
                        }
                        if (lastVendorSuggestions.includes('cisco_ios')) {
                                const host = ciscoHostInput ? ciscoHostInput.value.trim() : '';
                                const user = ciscoUserInput ? ciscoUserInput.value.trim() : '';
                                const pass = ciscoPassInput ? ciscoPassInput.value.trim() : '';
                                const secret = ciscoSecretInput ? ciscoSecretInput.value.trim() : '';
                                const portRaw = ciscoPortInput ? ciscoPortInput.value.trim() : '';
                                if (host || user || pass || secret || portRaw) {
                                        if (!host || !user || !pass) {
                                                showVendorError('Please complete Cisco host, username, and password.');
                                                return;
                                        }
                                        payload.cisco_host = host;
                                        payload.cisco_user = user;
                                        payload.cisco_pass = pass;
                                        if (secret) {
                                                payload.cisco_secret = secret;
                                        }
                                        if (portRaw) {
                                                const port = Number.parseInt(portRaw, 10);
                                                if (!Number.isFinite(port) || port <= 0 || port > 65535) {
                                                        showVendorError('Cisco SSH port must be between 1 and 65535.');
                                                        return;
                                                }
                                                payload.cisco_port = port;
                                        }
                                        hasPayload = true;
                                }
                        }
                        if (!hasPayload) {
                                showVendorError('Provide credentials for at least one vendor pack.');
                                return;
                        }
                        try {
                                const resp = await fetch('/api/vendor', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify(payload),
                                });
                                if (!resp.ok) {
                                        const text = await resp.text();
                                        showVendorError(text || 'Unable to start vendor checks.');
                                        return;
                                }
                                closeVendorModal();
                        } catch (err) {
                                console.error(err);
                                showVendorError('Unexpected error starting vendor checks.');
                        }
                });
        }

        if (historyList) {
                historyList.addEventListener('click', async (event) => {
                        const element = event.target instanceof Element ? event.target : null;
                        if (!element) {
                                return;
                        }
                        const selectBtn = element.closest('[data-action="select-run"]');
                        if (selectBtn) {
                                event.preventDefault();
                                const runId = selectBtn.dataset.runId;
                                if (runId) {
                                        await selectHistoryRun(runId);
                                }
                                return;
                        }
                        const compareBtn = element.closest('[data-action="compare-run"]');
                        if (compareBtn) {
                                event.preventDefault();
                                const runId = compareBtn.dataset.runId;
                                if (runId) {
                                        await toggleCompare(runId);
                                }
                        }
                });
        }

        if (clearCompareBtn) {
                clearCompareBtn.addEventListener('click', () => {
                        setCompareResults(null, null);
                });
        }

        ensureStream();
        updateStatus();
        loadResults();
        setBundleAvailability(false);
})();
