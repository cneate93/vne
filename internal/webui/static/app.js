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
                                return;
                        }
                        if (!resp.ok) {
                                resultsEl.textContent = '(Results not available yet)';
                                return;
                        }
                        const data = await resp.json();
                        resultsEl.textContent = JSON.stringify(data, null, 2);
                        populatePerformanceCards(data);
                } catch (err) {
                        console.error(err);
                        resultsEl.textContent = '(Unable to load results)';
                        populatePerformanceCards(null);
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

        ensureStream();
        updateStatus();
})();
