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
                        if (!resp.ok) {
                                resultsEl.textContent = '(Results not available yet)';
                                return;
                        }
                        const data = await resp.json();
                        resultsEl.textContent = JSON.stringify(data, null, 2);
                } catch (err) {
                        console.error(err);
                        resultsEl.textContent = '(Unable to load results)';
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
                }
        }

        ensureStream();
        updateStatus();
})();
