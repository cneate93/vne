(() => {
        const form = document.getElementById('start-form');
        const targetInput = document.getElementById('target');
        const scanInput = document.getElementById('scan');
        const statusPhase = document.getElementById('status-phase');
        const statusPercent = document.getElementById('status-percent');
        const statusMessage = document.getElementById('status-message');
        const resultsEl = document.getElementById('results');
        const startError = document.getElementById('start-error');

        let pollTimer = null;

        async function updateStatus() {
                try {
                        const resp = await fetch('/api/status');
                        if (!resp.ok) {
                                throw new Error('Status request failed');
                        }
                        const data = await resp.json();
                        statusPhase.textContent = data.phase || 'unknown';
                        statusPercent.textContent = `${Math.round((data.percent ?? 0) * 10) / 10}%`;
                        statusMessage.textContent = data.message || '';

                        if (data.phase === 'finished') {
                                clearInterval(pollTimer);
                                pollTimer = null;
                                await loadResults();
                        } else if (data.phase === 'error') {
                                clearInterval(pollTimer);
                                pollTimer = null;
                                resultsEl.textContent = '(Run failed)';
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
                        statusPhase.textContent = 'running';
                        statusPercent.textContent = '5%';
                        statusMessage.textContent = 'Starting diagnostics…';
                        if (pollTimer) {
                                clearInterval(pollTimer);
                        }
                        pollTimer = setInterval(updateStatus, 1500);
                        await updateStatus();
                } catch (err) {
                        console.error(err);
                        startError.textContent = 'Unexpected error starting diagnostics.';
                        startError.hidden = false;
                }
        });

        updateStatus();
})();
