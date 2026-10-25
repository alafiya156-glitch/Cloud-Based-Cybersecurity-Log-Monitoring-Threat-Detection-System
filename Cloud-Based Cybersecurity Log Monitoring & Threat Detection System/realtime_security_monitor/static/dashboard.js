
'use strict';

let loginChart = null;
let eventChart = null;
let refreshInProgress = false;

function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function showStatus(message) {
    const detail = document.getElementById('status-detail');
    if (detail) detail.textContent = message;
}

function initializeCharts() {
    if (typeof window.Chart === 'undefined') {
        console.error('Chart.js did not load. Check your internet connection.');
        showStatus('Chart library unavailable. Statistics will still be loaded.');
        return;
    }

    Chart.defaults.color = '#a5aec9';
    Chart.defaults.font.family = 'DM Sans, sans-serif';

    const loginCanvas = document.getElementById('loginChart');
    const eventCanvas = document.getElementById('eventChart');

    if (loginCanvas && !loginChart) {
        loginChart = new Chart(loginCanvas, {
            type: 'bar',
            data: {
                labels: ['Successful logins', 'Failed logins'],
                datasets: [{
                    label: 'Login count',
                    data: [0, 0],
                    backgroundColor: [
                        'rgba(52, 211, 153, 0.85)',
                        'rgba(251, 113, 133, 0.85)'
                    ],
                    borderColor: ['#34d399', '#fb7185'],
                    borderWidth: 1,
                    borderRadius: 8,
                    maxBarThickness: 85
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 350 },
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        border: { display: false }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 },
                        grid: {
                            color: 'rgba(165, 174, 201, 0.12)'
                        },
                        border: { display: false }
                    }
                }
            }
        });
    }

    if (eventCanvas && !eventChart) {
        eventChart = new Chart(eventCanvas, {
            type: 'doughnut',
            data: {
                labels: ['Successful logins', 'Failed logins', 'Other events'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#34d399', '#fb7185', '#a78bfa'],
                    borderColor: '#191c3a',
                    borderWidth: 4,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 18,
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    }
                }
            }
        });
    }
}

async function getJSON(url) {
    const response = await fetch(url, {
        cache: 'no-store',
        headers: { Accept: 'application/json' }
    });

    if (!response.ok) {
        throw new Error(`${url} returned HTTP ${response.status}`);
    }

    const contentType = response.headers.get('content-type') || '';

    if (!contentType.includes('application/json')) {
        throw new Error(`${url} did not return JSON. Check the Flask route.`);
    }

    return response.json();
}

function updateSecurityStatus(summary) {
    const banner = document.getElementById('status-banner');
    const title = document.getElementById('security-status');
    const detail = document.getElementById('status-detail');
    const symbol = document.getElementById('status-symbol');

    if (!banner || !title || !detail || !symbol) return;

    banner.classList.remove('danger', 'warning', 'healthy');

    if (Number(summary.open_alerts) > 0) {
        banner.classList.add('danger');
        title.textContent = 'THREAT DETECTED';
        detail.textContent =
            `${summary.open_alerts} open alert(s) require review.`;
        symbol.textContent = '!';
    } else if (summary.monitoring_active) {
        banner.classList.add('healthy');
        title.textContent = 'MONITORING ACTIVE';
        detail.textContent =
            'Events are being recorded and no open alerts remain.';
        symbol.textContent = '✓';
    } else {
        banner.classList.add('warning');
        title.textContent = 'MONITORING INACTIVE';
        detail.textContent =
            'No recent events detected. Check your monitoring collector.';
        symbol.textContent = '!';
    }
}

function updateRecentEvents(events) {
    const tbody = document.getElementById('recent-events');
    if (!tbody) return;

    if (!Array.isArray(events) || events.length === 0) {
        tbody.innerHTML =
            '<tr><td colspan="6" class="empty">No security events recorded yet.</td></tr>';
        return;
    }

    tbody.innerHTML = events.map(event => {
        const suspicious =
            event.suspicious === true ||
            event.suspicious === 1 ||
            event.suspicious === '1';

        return `
            <tr>
                <td>${esc(event.timestamp)}</td>
                <td>${esc(event.source)}</td>
                <td>${esc(event.event_type)}</td>
                <td>${esc(event.username)}</td>
                <td>${esc(event.source_ip)}</td>
                <td>
                    ${suspicious
                        ? '<span class="badge high">Suspicious</span>'
                        : '<span class="badge neutral">Recorded</span>'}
                </td>
            </tr>
        `;
    }).join('');
}

function updateCharts(summary, events) {
    if (loginChart) {
        loginChart.data.datasets[0].data = [
            Number(summary.successful_logins) || 0,
            Number(summary.failed_logins) || 0
        ];
        loginChart.update();
    }

    if (eventChart) {
        let successful = 0;
        let failed = 0;
        let other = 0;

        events.forEach(event => {
            const type = String(event.event_type || '').toLowerCase();

            if (type.includes('success')) {
                successful++;
            } else if (type.includes('fail')) {
                failed++;
            } else {
                other++;
            }
        });

        eventChart.data.datasets[0].data = [
            successful,
            failed,
            other
        ];

        eventChart.update();
    }
}

async function refreshDashboard() {
    if (refreshInProgress) return;
    refreshInProgress = true;

    try {
        const [summary, events] = await Promise.all([
            getJSON('/api/summary'),
            getJSON('/api/events?limit=8')
        ]);

        document.getElementById('total-events').textContent =
            summary.total_events ?? 0;

        document.getElementById('successful-logins').textContent =
            summary.successful_logins ?? 0;

        document.getElementById('failed-logins').textContent =
            summary.failed_logins ?? 0;

        document.getElementById('open-alerts').textContent =
            summary.open_alerts ?? 0;

        updateSecurityStatus(summary);
        updateRecentEvents(events);
        updateCharts(summary, events);

    } catch (error) {
        console.error('Dashboard update failed:', error);
        showStatus(`Dashboard data error: ${error.message}`);
    } finally {
        refreshInProgress = false;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    refreshDashboard();
    window.setInterval(refreshDashboard, 5000);
});
