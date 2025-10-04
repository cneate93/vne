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

        let eventSource = null;
        let lastVendorSuggestions = [];
        let vendorPromptShown = false;

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
                                resultsEl.textContent = '(Results not available yet)';
                                populatePerformanceCards(null);
                                populateDevicesTable(null);
                                populateVendorCard(null);
                                setBundleAvailability(false);
                                return;
                        }
                        if (!resp.ok) {
                                resultsEl.textContent = '(Results not available yet)';
                                populateDevicesTable(null);
                                populateVendorCard(null);
                                setBundleAvailability(false);
                                return;
                        }
                        const data = await resp.json();
                        resultsEl.textContent = JSON.stringify(data, null, 2);
                        populatePerformanceCards(data);
                        populateDevicesTable(data && Array.isArray(data.discovered) ? data.discovered : null);
                        populateVendorCard(data);
                        setBundleAvailability(true);
                } catch (err) {
                        console.error(err);
                        resultsEl.textContent = '(Unable to load results)';
                        populatePerformanceCards(null);
                        populateDevicesTable(null);
                        populateVendorCard(null);
                        setBundleAvailability(false);
                }
        }

        form.addEventListener('submit', async (event) => {
                event.preventDefault();
                startError.hidden = true;
                startError.textContent = '';

                const payload = {
                        target: targetInput.value.trim(),
                        scan: scanInput.checked,
                };

                try {
                        const resp = await fetch('/api/start', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(payload),
                        });
                        if (resp.status === 409) {
                                startError.textContent = 'A run is already in progress.';
                                startError.hidden = false;
                                return;
                        }
                        if (!resp.ok) {
                                startError.textContent = 'Unable to start diagnostics.';
                                startError.hidden = false;
                                return;
                        }
                        resultsEl.textContent = '(Working…)';
                        statusMessage.textContent = 'Starting diagnostics…';
                        applyPhase('starting');
                        setProgress(5);
                        clearDevicesTable();
                        setBundleAvailability(false);
                } catch (err) {
                        console.error(err);
                        startError.textContent = 'Unexpected error starting diagnostics.';
                        startError.hidden = false;
                }
        });

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

        ensureStream();
        updateStatus();
        setBundleAvailability(false);
})();
