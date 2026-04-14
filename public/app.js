// Define showSection in global scope
function showSection(sectionId) {
    console.log('Navigating to:', sectionId);
    
    // Hide all sections
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => section.classList.remove('active'));
    
    // Remove active class from all nav links
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => link.classList.remove('active'));
    
    // Show the target section
    const targetSection = document.getElementById(sectionId + '-section');
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    // Find and activate the corresponding nav link
    navLinks.forEach(link => {
        if (link.getAttribute('onclick') && link.getAttribute('onclick').includes("'" + sectionId + "'")) {
            link.classList.add('active');
        }
    });
    
    // Section-specific actions
    switch(sectionId) {
        case 'ids':
            setTimeout(() => {
                if (window.ensureCharts) window.ensureCharts();
                if (window.refreshEndpointProtectorData) window.refreshEndpointProtectorData();
                if (window.socket) {
                    window.socket.emit('endpoint-protector:get-overview');
                    window.socket.emit('endpoint-protector:get-agents');
                    window.socket.emit('endpoint-protector:get-alerts');
                }
            }, 100);
            break;
        case 'virustotal':
            if (typeof lastVirusTotalResult !== 'undefined') lastVirusTotalResult = null;
            const vtResults = document.getElementById('virustotal-results');
            if (vtResults) {
                vtResults.innerHTML = '<div class="text-center py-5"><i class="fas fa-virus fa-2x text-muted mb-2"></i><div class="text-muted">VirusTotal scan results will appear here...</div></div>';
            }
            break;
        case 'crypto':
            const cryptoInput = document.getElementById('crypto-input');
            const cryptoOutput = document.getElementById('crypto-output');
            if (cryptoInput) cryptoInput.value = '';
            if (cryptoOutput) cryptoOutput.value = '';
            break;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const scanTypeSelect = document.getElementById('scan-type');
    const customCommandDiv = document.getElementById('custom-command-div');
    
    // Handle scan type selection
    scanTypeSelect.addEventListener('change', function() {
        if (this.value === 'custom') {
            customCommandDiv.style.display = 'block';
        } else {
            customCommandDiv.style.display = 'none';
        }
    });
    
    // Form elements
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
    const fileScanForm = document.getElementById('file-scan-form');
    const urlScanForm = document.getElementById('url-scan-form');
    const hashScanForm = document.getElementById('hash-scan-form');
    const outputContainer = document.getElementById('output-container');
    const cryptoResult = document.getElementById('crypto-result');
    const vtResults = document.getElementById('vt-results');
    const scanStatus = document.getElementById('scan-status');
    const scanProgress = document.getElementById('scan-progress');

    // IDS elements
    const idsStartBtn = document.getElementById('ids-start-btn');
    const idsStopBtn = document.getElementById('ids-stop-btn');
    const idsRefreshBtn = document.getElementById('ids-refresh-btn');
    const idsStatusBadge = document.getElementById('ids-status-badge');
    const threatsContainer = document.getElementById('threats-container');
    const idsLogs = document.getElementById('ids-logs');
    const endpointTotals = {
        total: document.getElementById('endpoint-total'),
        online: document.getElementById('endpoint-online'),
        offline: document.getElementById('endpoint-offline'),
        critical: document.getElementById('endpoint-critical'),
        score: document.getElementById('endpoint-risk-score')
    };
    const endpointGrid = document.getElementById('endpoint-agents-grid');
    const endpointAlertsTimeline = document.getElementById('endpoint-alerts');
    const endpointSearchInput = document.getElementById('endpoint-search');
    const endpointStatusFilter = document.getElementById('endpoint-status-filter');
    const endpointVisibleCount = document.getElementById('endpoint-visible-count');
    const endpointSyncStatus = document.getElementById('endpoint-sync-status');

    let socket = io();

    // Make socket available globally
    window.socket = socket;
    
    socket.on('connect', () => {
        console.log('[Frontend] Connected to backend');
        // Initialize charts only when Endpoint Protector section is visible (avoids 0px canvas sizing)
        if (document.getElementById('ids-section')?.classList.contains('active')) {
            ensureCharts();
        }
        // Request initial data
        socket.emit('endpoint-protector:get-overview');
        socket.emit('endpoint-protector:get-agents');
        socket.emit('endpoint-protector:get-alerts');
        // Also fetch via REST API as fallback
        refreshEndpointProtectorData();
    });

    socket.on('disconnect', () => {
        console.log('[Frontend] Disconnected from backend');
    });

    socket.on('connect_error', (error) => {
        console.error('[Frontend] Connection error:', error);
        showNotification('Connection to backend lost. Retrying...', 'warning');
    });
    let supportedAlgorithms = [];
    let idsThreats = [];
    let endpointAgents = new Map();
    let endpointAlerts = [];
    let endpointOverview = null;
    let lastEndpointRefreshErrorTs = 0;
    let idsLive = false;
    let notificationContainer = null;
    
    // Metrics history for graphs
    let metricsHistory = {
        cpu: [],
        memory: [],
        network: {
            bytesSent: [],
            bytesRecv: [],
            timestamps: []
        }
    };
    // Keep charts compact and performant
    const MAX_HISTORY_POINTS = 30;
    
    // Chart instances
    let cpuChart = null;
    let memoryChart = null;
    let networkChart = null;
    
    // Windows Event Log events
    let windowsEvents = [];
    const winEventsFromEl = document.getElementById('win-events-from');
    const winEventsToEl = document.getElementById('win-events-to');
    const winEventsIdEl = document.getElementById('win-events-id');
    const winEventsHostEl = document.getElementById('win-events-host');
    const winEventsCountEl = document.getElementById('windows-events-count');
    const winEventsFilteredCountEl = document.getElementById('windows-events-filtered-count');
    const notificationVariants = {
        success: { icon: 'fa-circle-check', tone: 'success' },
        error: { icon: 'fa-circle-xmark', tone: 'danger' },
        danger: { icon: 'fa-circle-xmark', tone: 'danger' },
        warning: { icon: 'fa-triangle-exclamation', tone: 'warning' },
        info: { icon: 'fa-circle-info', tone: 'info' }
    };

    function parseDateInput(value) {
        // Input type="date" returns YYYY-MM-DD in local time.
        if (!value) return null;
        const d = new Date(value + 'T00:00:00');
        return Number.isNaN(d.getTime()) ? null : d;
    }

    function getWindowsEventsFilters() {
        const from = parseDateInput(winEventsFromEl?.value);
        const to = parseDateInput(winEventsToEl?.value);
        // Make "to" inclusive end of day
        const toEnd = to ? new Date(to.getTime() + (24 * 60 * 60 * 1000) - 1) : null;
        const eventIdRaw = (winEventsIdEl?.value || '').trim();
        const eventId = eventIdRaw ? eventIdRaw : null;
        const hostRaw = (winEventsHostEl?.value || '').trim();
        const host = hostRaw ? hostRaw.toLowerCase() : null;
        return { from, to: toEnd, eventId, host };
    }

    function getEventAgentMeta(ev) {
        const agentId = ev.agentId || ev.details?.agentId;
        const agent = agentId ? endpointAgents.get(agentId) : null;
        const ip =
            agent?.ipAddress
            || agent?.telemetry?.ipAddress
            || agent?.telemetry?.network?.primaryIp
            || agent?.telemetry?.network?.external_ip
            || '';

        // Try multiple keys for username depending on agent payload / legacy naming
        const users = agent?.telemetry?.users || {};
        const username =
            users.current_console_user
            || users.currentConsoleUser
            || users.username
            || agent?.owner
            || '';

        return {
            agentId: agentId || '',
            hostname: ev.hostname || agent?.hostname || '',
            ipAddress: ip || '',
            username: username || ''
        };
    }

    function getFilteredWindowsEvents() {
        const { from, to, eventId, host } = getWindowsEventsFilters();
        return windowsEvents.filter(ev => {
            const ts = ev.timestamp || ev.details?.timestamp;
            const dt = ts ? new Date(ts) : null;
            if (from && (!dt || dt < from)) return false;
            if (to && (!dt || dt > to)) return false;
            if (eventId) {
                const id = String(ev.event_id || ev.details?.event_id || ev.details?.eventId || ev.details?.Id || '');
                if (!id.includes(eventId)) return false;
            }
            if (host) {
                const meta = getEventAgentMeta(ev);
                const hay = [
                    meta.hostname,
                    meta.agentId,
                    meta.ipAddress
                ].filter(Boolean).join(' ').toLowerCase();
                if (!hay.includes(host)) return false;
            }
            return true;
        });
    }

    function resetWindowsEventFilters() {
        if (winEventsFromEl) winEventsFromEl.value = '';
        if (winEventsToEl) winEventsToEl.value = '';
        if (winEventsIdEl) winEventsIdEl.value = '';
        if (winEventsHostEl) winEventsHostEl.value = '';
        renderWindowsEvents();
    }

    function clearWindowsEvents() {
        windowsEvents = [];
        renderWindowsEvents();
        showNotification('Windows Event Log cleared (dashboard only).', 'info');
    }

    function showResult(type, message) {
        const resultDiv = document.createElement('div');
        resultDiv.className = `alert alert-${type}`;
        resultDiv.textContent = message;
        return resultDiv;
    }

    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }



    // Endpoint Mission Control filtering
    if (endpointSearchInput) {
        endpointSearchInput.addEventListener('input', () => renderEndpointAgents());
    }
    if (endpointStatusFilter) {
        endpointStatusFilter.addEventListener('change', () => renderEndpointAgents());
    }

    function clearOutput() {
        outputContainer.innerHTML = '';
    }
    window.clearOutput = clearOutput;

    function downloadReport() {
        const content = outputContainer.textContent || 'No scan data available';
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan-report-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    function appendOutput(message, type) {
        const para = document.createElement('p');
        para.className = type;
        para.textContent = message;
        outputContainer.appendChild(para);
        outputContainer.scrollTop = outputContainer.scrollHeight;
    }

    let scanStartTime = null;
    let progressInterval = null;
    let currentScanProcess = null;
    let portDistributionChart = null;
    let servicesOverviewChart = null;
    let currentScanAnalysis = null;
    let currentScanInfo = null;
    let pastScans = [];

    const vulnerabilityDatabase = {
        'ssh': {
            name: 'SSH (Secure Shell)',
            port: '22',
            risk: 'MEDIUM',
            description: 'SSH service is running on this port, allowing secure remote access.',
            damages: [
                'Potential brute-force attacks if weak credentials are used',
                'If not properly configured, could allow unauthorized access',
                'Key exchange vulnerabilities could be exploited'
            ],
            recommendations: [
                'Use strong, complex passwords or key-based authentication',
                'Disable root login via SSH',
                'Use SSH key pairs instead of passwords',
                'Implement fail2ban to block brute-force attempts',
                'Keep SSH software updated'
            ]
        },
        'http': {
            name: 'HTTP (Hypertext Transfer Protocol)',
            port: '80',
            risk: 'HIGH',
            description: 'Unencrypted web traffic is running on this port.',
            damages: [
                'Data transmitted can be intercepted (man-in-the-middle)',
                'Session hijacking possible',
                'Credential theft via packet capture'
            ],
            recommendations: [
                'Redirect all HTTP to HTTPS',
                'Implement HSTS (HTTP Strict Transport Security)',
                'Use TLS 1.2 or higher',
                'Obtain and install SSL/TLS certificates'
            ]
        },
        'https': {
            name: 'HTTPS (HTTP Secure)',
            port: '443',
            risk: 'LOW',
            description: 'Encrypted web traffic is running on this port.',
            damages: [
                'SSL/TLS vulnerabilities could be exploited if outdated',
                'Certificate issues could affect security'
            ],
            recommendations: [
                'Use TLS 1.3 if possible',
                'Disable older SSL/TLS versions',
                'Regular certificate renewal',
                'Implement certificate pinning'
            ]
        },
        'ftp': {
            name: 'FTP (File Transfer Protocol)',
            port: '21',
            risk: 'HIGH',
            description: 'FTP service is running, which transmits data in clear text.',
            damages: [
                'All credentials and files can be intercepted',
                'Anonymous access may be enabled',
                'Bounce attacks possible'
            ],
            recommendations: [
                'Disable FTP and use SFTP or SCP instead',
                'If FTP required, implement TLS encryption',
                'Disable anonymous access',
                'Use strong authentication'
            ]
        },
        'telnet': {
            name: 'Telnet',
            port: '23',
            risk: 'CRITICAL',
            description: 'Telnet transmits everything in clear text including passwords.',
            damages: [
                'Complete credential compromise',
                'Session hijacking',
                'All data including sensitive info visible to attackers'
            ],
            recommendations: [
                'Disable Telnet immediately',
                'Replace with SSH for remote access',
                'If legacy systems require Telnet, isolate on separate network'
            ]
        },
        'smtp': {
            name: 'SMTP (Simple Mail Transfer Protocol)',
            port: '25',
            risk: 'MEDIUM',
            description: 'Mail server is running, often used for spam or reconnaissance.',
            damages: [
                'Open relay can be exploited for spam',
                'User enumeration possible',
                'Email spoofing potential'
            ],
            recommendations: [
                'Restrict relay access',
                'Implement SPF, DKIM, and DMARC',
                'Use SMTP authentication',
                'Configure proper firewall rules'
            ]
        },
        'dns': {
            name: 'DNS (Domain Name System)',
            port: '53',
            risk: 'MEDIUM',
            description: 'DNS service is running, critical for network navigation.',
            damages: [
                'DNS poisoning/cache snooping',
                'Amplification attacks possible',
                'Zone transfers may leak network information'
            ],
            recommendations: [
                'Disable zone transfers',
                'Implement DNSSEC',
                'Restrict queries to authorized IPs',
                'Monitor for unusual DNS traffic'
            ]
        },
        'msrpc': {
            name: 'Microsoft RPC',
            port: '135',
            risk: 'HIGH',
            description: 'Windows RPC endpoint mapper is accessible.',
            damages: [
                'Information disclosure',
                'Remote code execution vulnerabilities',
                'Lateral movement potential'
            ],
            recommendations: [
                'Block port 135 at firewall',
                'Enable Windows Firewall',
                'Apply latest Microsoft patches',
                'Disable RPC services if not needed'
            ]
        },
        'netbios': {
            name: 'NetBIOS',
            port: '139',
            risk: 'HIGH',
            description: 'NetBIOS name service is running, legacy Windows networking.',
            damages: [
                'Network enumeration and reconnaissance',
                'SMB relay attacks',
                'Potential unauthorized file sharing access'
            ],
            recommendations: [
                'Disable NetBIOS over TCP/IP',
                'Block ports 137-139 at firewall',
                'Disable file sharing if not needed'
            ]
        },
        'smb': {
            name: 'SMB (Server Message Block)',
            port: '445',
            risk: 'CRITICAL',
            description: 'SMB file sharing protocol is exposed to the network.',
            damages: [
                'EternalBlue and similar exploits possible',
                'Ransomware delivery vector',
                'Lateral movement through file shares',
                'Credential theft via SMB relay'
            ],
            recommendations: [
                'Block port 445 at external firewall',
                'Apply MS17-010 and subsequent patches',
                'Disable SMBv1',
                'Enable SMB signing',
                'Use network segmentation'
            ]
        },
        'rdp': {
            name: 'RDP (Remote Desktop Protocol)',
            port: '3389',
            risk: 'CRITICAL',
            description: 'Remote Desktop is accessible, common attack vector.',
            damages: [
                'BlueKeep vulnerabilities',
                'Brute-force attacks',
                'Ransomware delivery via RDP',
                'Lateral movement capability'
            ],
            recommendations: [
                'Enable Network Level Authentication (NLA)',
                'Use strong passwords',
                'Implement account lockout policies',
                'Restrict RDP access via firewall',
                'Use VPN for remote access instead of direct RDP exposure'
            ]
        },
        'mysql': {
            name: 'MySQL Database',
            port: '3306',
            risk: 'HIGH',
            description: 'MySQL database server is accessible.',
            damages: [
                'SQL injection if web app vulnerable',
                'Data breach potential',
                'Unauthorized database access'
            ],
            recommendations: [
                'Bind MySQL to localhost only',
                'Use strong root password',
                'Implement proper firewall rules',
                'Enable SSL/TLS for MySQL connections',
                'Regular security audits'
            ]
        },
        'postgresql': {
            name: 'PostgreSQL Database',
            port: '5432',
            risk: 'HIGH',
            description: 'PostgreSQL database server is accessible.',
            damages: [
                'Data breach potential',
                'SQL injection attacks',
                'Unauthorized database access'
            ],
            recommendations: [
                'Configure pg_hba.conf for limited access',
                'Use SSL connections',
                'Implement row-level security',
                'Regular security updates'
            ]
        },
        'mongodb': {
            name: 'MongoDB',
            port: '27017',
            risk: 'HIGH',
            description: 'MongoDB NoSQL database is accessible.',
            damages: [
                'Data exfiltration if no authentication',
                'NoSQL injection attacks',
                'Unauthorized access to collections'
            ],
            recommendations: [
                'Enable authentication',
                'Use TLS/SSL encryption',
                'Restrict network access',
                'Disable HTTP interface in production'
            ]
        },
        'redis': {
            name: 'Redis',
            port: '6379',
            risk: 'CRITICAL',
            description: 'Redis server is accessible without authentication.',
            damages: [
                'Complete data exposure',
                'Server takeover possible',
                'Data deletion/modification risk'
            ],
            recommendations: [
                'Enable Redis authentication',
                'Bind to localhost only',
                'Use TLS encryption',
                'Disable危险 commands in production'
            ]
        },
        'vnc': {
            name: 'VNC (Virtual Network Computing)',
            port: '5900',
            risk: 'HIGH',
            description: 'VNC remote desktop service is accessible.',
            damages: [
                'Remote code execution',
                'Screen capture/keystroke logging',
                'Lateral movement capability'
            ],
            recommendations: [
                'Disable VNC if not needed',
                'Use strong password',
                'Implement VPN access',
                'Keep VNC software updated'
            ]
        }
    };

    function validateTargetInput(target) {
        const feedback = document.getElementById('target-validation-feedback');
        const suggestion = document.getElementById('target-validation-suggestion');
        const input = document.getElementById('target-input');

        if (!target || target.trim() === '') {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            feedback.textContent = 'Target cannot be empty. Please enter an IP address, domain, or URL.';
            suggestion.classList.add('d-none');
            return false;
        }

        const trimmedTarget = target.trim();

        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv4Match = trimmedTarget.match(ipv4Regex);

        if (ipv4Match) {
            const parts = trimmedTarget.split('.').map(Number);
            if (parts[0] === 0 || parts[0] === 127 || parts[3] === 0 || parts[3] === 255) {
                input.classList.remove('is-valid');
                input.classList.add('is-invalid');
                feedback.textContent = 'Invalid IP address range.';
                suggestion.innerHTML = 'Suggestions: Use a valid host IP (e.g., 192.168.1.1). Avoid loopback (127.x.x.x), broadcast (255.255.255.255), and network addresses.';
                suggestion.classList.remove('d-none');
                return false;
            }
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            feedback.textContent = '';
            suggestion.classList.add('d-none');
            return true;
        }

        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$/;
        if (ipv6Regex.test(trimmedTarget)) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            feedback.textContent = '';
            suggestion.classList.add('d-none');
            return true;
        }

        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        const urlRegex = /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/;

        if (domainRegex.test(trimmedTarget)) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            feedback.textContent = '';
            suggestion.classList.add('d-none');
            return true;
        }

        if (urlRegex.test(trimmedTarget)) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            feedback.textContent = '';
            suggestion.classList.add('d-none');
            return true;
        }

        input.classList.remove('is-valid');
        input.classList.add('is-invalid');

        let errorMsg = 'Invalid format. Please enter a valid:';
        let suggestions = [];

        if (/\d+\.\d+\.\d+\.\d+/.test(trimmedTarget)) {
            errorMsg = 'IP address format is incorrect.';
            suggestions.push('Example valid IP: 192.168.1.1');
        } else if (/[a-zA-Z]/.test(trimmedTarget) && !trimmedTarget.includes('.')) {
            errorMsg = 'Domain name appears incomplete.';
            suggestions.push('Example valid domain: example.com');
        } else if (trimmedTarget.includes('://')) {
            errorMsg = 'URL format is incorrect.';
            suggestions.push('Example valid URL: https://example.com');
        } else {
            suggestions.push('Valid IP: 192.168.1.1');
            suggestions.push('Valid domain: example.com');
            suggestions.push('Valid URL: https://example.com');
        }

        feedback.textContent = errorMsg;
        suggestion.innerHTML = 'Suggestions:<br>' + suggestions.map(s => '• ' + s).join('<br>');
        suggestion.classList.remove('d-none');

        return false;
    }

    function showScanDashboard(analysis) {
        const dashboard = document.getElementById('scan-dashboard');
        if (!dashboard) return;

        dashboard.style.display = 'block';

        const hostsFound = analysis.hostsFound || (analysis.summary ? (analysis.summary.match(/\d+ host/i) ? parseInt(analysis.summary.match(/\d+ host/i)[0]) : 0) : 0);
        const portsOpen = analysis.portsOpen || (analysis.services ? analysis.services.length : 0);
        const servicesCount = analysis.services ? analysis.services.length : 0;
        const vulnerabilitiesList = analysis.vulnerabilities || [];

        document.getElementById('dash-hosts-count').textContent = hostsFound;
        document.getElementById('dash-ports-count').textContent = portsOpen;
        document.getElementById('dash-services-count').textContent = servicesCount;
        document.getElementById('dash-vulns-count').textContent = vulnerabilitiesList.length;

        if (analysis.services) {
            renderPortDistributionChart(analysis.services);
            renderServicesOverviewChart(analysis.services);
        }
        renderServicesDetails(analysis.services || []);
        renderVulnerabilityDetails(vulnerabilitiesList);
    }

    function renderServicesDetails(services) {
        const container = document.getElementById('services-details');
        if (!container) return;

        if (!services || services.length === 0) {
            container.innerHTML = '<div class="col-12 text-center text-muted">No services detected.</div>';
            return;
        }

        container.innerHTML = services.slice(0, 12).map(svc => {
            const vulnKey = Object.keys(vulnerabilityDatabase).find(key =>
                svc.service.toLowerCase().includes(key)
            );
            const vulnInfo = vulnKey ? vulnerabilityDatabase[vulnKey] : null;
            const riskColor = vulnInfo ? (vulnInfo.risk === 'CRITICAL' ? 'danger' : vulnInfo.risk === 'HIGH' ? 'warning' : 'info') : 'secondary';
            const riskBadge = vulnInfo ? `<span class="badge bg-${riskColor} ms-2">${vulnInfo.risk}</span>` : '';

            return `
                <div class="col-md-4 mb-2">
                    <div class="card h-100 border-${riskColor}" style="border-width: 2px;">
                        <div class="card-body py-2 px-3">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <span class="badge bg-primary me-2">${svc.port}/${svc.protocol}</span>
                                    <strong class="text-white">${svc.service}</strong>
                                    ${riskBadge}
                                </div>
                            </div>
                            <small class="text-muted">${svc.version || 'Service info unavailable'}</small>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        if (services.length > 12) {
            container.innerHTML += `<div class="col-12 text-center text-muted mt-2">... and ${services.length - 12} more services</div>`;
        }
    }

    function renderPortDistributionChart(services) {
        const ctx = document.getElementById('portDistributionChart');
        if (!ctx) return;

        if (portDistributionChart) {
            portDistributionChart.destroy();
        }

        const portCounts = {};
        services.forEach(svc => {
            const port = svc.port.split('/')[0];
            const serviceName = svc.service.toLowerCase();
            if (portCounts[serviceName]) {
                portCounts[serviceName]++;
            } else {
                portCounts[serviceName] = 1;
            }
        });

        const labels = Object.keys(portCounts);
        const data = Object.values(portCounts);

        const colors = [
            '#00ff41', '#00d4ff', '#ff6b35', '#9d00ff', '#ffd23f',
            '#ff3366', '#00cc99', '#3366ff', '#ff9900', '#66ff00'
        ];

        portDistributionChart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors.slice(0, labels.length),
                    borderColor: '#1a1f3a',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#b8c5d6',
                            font: { size: 11 }
                        }
                    }
                }
            }
        });
    }

    function renderServicesOverviewChart(services) {
        const ctx = document.getElementById('servicesOverviewChart');
        if (!ctx) return;

        if (servicesOverviewChart) {
            servicesOverviewChart.destroy();
        }

        const portRanges = {
            'Well-Known (0-1023)': 0,
            'Registered (1024-49151)': 0,
            'Dynamic (49152+)': 0
        };

        services.forEach(svc => {
            const port = parseInt(svc.port.split('/')[0]);
            if (port <= 1023) {
                portRanges['Well-Known (0-1023)']++;
            } else if (port <= 49151) {
                portRanges['Registered (1024-49151)']++;
            } else {
                portRanges['Dynamic (49152+)']++;
            }
        });

        servicesOverviewChart = new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: Object.keys(portRanges),
                datasets: [{
                    label: 'Services',
                    data: Object.values(portRanges),
                    backgroundColor: ['#00ff41', '#00d4ff', '#ff6b35'],
                    borderColor: ['#00ff41', '#00d4ff', '#ff6b35'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#b8c5d6' },
                        grid: { color: 'rgba(0, 255, 65, 0.1)' }
                    },
                    x: {
                        ticks: { color: '#b8c5d6' },
                        grid: { color: 'rgba(0, 255, 65, 0.1)' }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    function renderVulnerabilityDetails(vulnerabilities) {
        const container = document.getElementById('vulnerability-details');
        if (!container) return;

        if (!vulnerabilities || vulnerabilities.length === 0) {
            container.innerHTML = '<div class="col-12 text-center text-muted py-3"><i class="fas fa-check-circle fa-2x mb-2 text-success"></i><p>No significant security considerations identified.</p></div>';
            return;
        }

        container.innerHTML = vulnerabilities.map((vuln, index) => {
            const vulnKey = Object.keys(vulnerabilityDatabase).find(key =>
                vuln.toLowerCase().includes(key)
            );
            const vulnInfo = vulnKey ? vulnerabilityDatabase[vulnKey] : null;

            if (!vulnInfo) {
                return `
                    <div class="col-md-6 mb-2">
                        <div class="card border-warning h-100 bg-dark shadow-sm">
                            <div class="card-header bg-warning text-dark py-1">
                                <h6 class="mb-0 small fw-bold"><i class="fas fa-exclamation-triangle me-2"></i>Note #${index + 1}</h6>
                            </div>
                            <div class="card-body py-2">
                                <p class="card-text small mb-0">${vuln}</p>
                            </div>
                        </div>
                    </div>
                `;
            }

            const riskClass = vulnInfo.risk === 'CRITICAL' ? 'danger' : vulnInfo.risk === 'HIGH' ? 'warning' : 'info';
            const riskIcon = vulnInfo.risk === 'CRITICAL' ? 'fa-skull-crossbones' : vulnInfo.risk === 'HIGH' ? 'fa-exclamation-circle' : 'fa-info-circle';

            return `
                <div class="col-lg-6 mb-3">
                    <div class="card border-${riskClass} h-100 bg-dark shadow-sm">
                        <div class="card-header bg-${riskClass} ${riskClass === 'warning' ? 'text-dark' : 'text-white'} py-1">
                            <h6 class="mb-0 small fw-bold">
                                <i class="fas ${riskIcon} me-2"></i>
                                ${vulnInfo.name}
                                <span class="badge bg-dark ms-2 text-white">${vulnInfo.risk} RISK</span>
                            </h6>
                        </div>
                        <div class="card-body py-2 px-3">
                            <p class="card-text small mb-2 text-info"><strong>Description:</strong> ${vulnInfo.description}</p>

                            <div class="mb-2">
                                <strong class="small text-danger d-block mb-1">Potential Damages:</strong>
                                <ul class="ps-3 mb-0">
                                    ${vulnInfo.damages.map(d => `<li class="x-small text-light">${d}</li>`).join('')}
                                </ul>
                            </div>

                            <div>
                                <strong class="small text-success d-block mb-1">Recommendations:</strong>
                                <ul class="ps-3 mb-0">
                                    ${vulnInfo.recommendations.map(r => `<li class="x-small text-light">${r}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function resetScanForm() {
        const form = document.getElementById('scan-form');
        if (form) form.reset();

        const targetInput = document.getElementById('target-input');
        if (targetInput) {
            targetInput.classList.remove('is-valid', 'is-invalid');
        }

        const feedback = document.getElementById('target-validation-feedback');
        const suggestion = document.getElementById('target-validation-suggestion');
        if (feedback) feedback.textContent = '';
        if (suggestion) suggestion.classList.add('d-none');

        clearOutput();

        const scanStatus = document.getElementById('scan-status');
        if (scanStatus) scanStatus.textContent = 'Ready to scan';

        const scanProgress = document.getElementById('scan-progress');
        if (scanProgress) {
            scanProgress.style.width = '0%';
            scanProgress.textContent = '';
            scanProgress.classList.remove('bg-success', 'bg-danger');
        }

        const dashboard = document.getElementById('scan-dashboard');
        if (dashboard) dashboard.style.display = 'none';

        const stopBtn = document.getElementById('stop-scan-btn');
        if (stopBtn) stopBtn.disabled = true;

        const startBtn = document.getElementById('start-scan-btn');
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        }

        showNotification('Scan form has been reset', 'info');
    }

    function populatePastScanSelector() {
        const selector = document.getElementById('past-scan-selector');
        if (!selector) return;

        selector.innerHTML = '<option value="">-- Current Scan Results --</option>';

        pastScans.forEach((scan, index) => {
            const date = new Date(scan.timestamp).toLocaleString();
            const label = `${scan.target} (${date})`;
            selector.innerHTML += `<option value="${index}">${label}</option>`;
        });
    }

    function updateScanInfoDisplay() {
        const infoDiv = document.getElementById('current-scan-info');
        if (!infoDiv || !currentScanInfo) return;

        const date = new Date(currentScanInfo.timestamp).toLocaleString();
        let html = `<strong>Current:</strong> ${currentScanInfo.target} | ${date}`;
        if (currentScanInfo.reportGenerated && currentScanInfo.reportFilename) {
            html += ` | <span class="text-success"><i class="fas fa-file-pdf me-1"></i>${currentScanInfo.reportFilename}</span>`;
        }
        infoDiv.innerHTML = html;
    }

    function loadSelectedScan() {
        const selector = document.getElementById('past-scan-selector');
        if (!selector || !selector.value) {
            showNotification('Please select a scan to load', 'warning');
            return;
        }

        const index = parseInt(selector.value);
        if (isNaN(index) || index < 0 || index >= pastScans.length) {
            showNotification('Invalid scan selection', 'error');
            return;
        }

        const selectedScan = pastScans[index];
        if (selectedScan && selectedScan.analysis) {
            currentScanAnalysis = selectedScan.analysis;
            currentScanInfo = {
                id: selectedScan.id,
                target: selectedScan.target,
                timestamp: selectedScan.timestamp,
                reportGenerated: selectedScan.reportGenerated,
                reportFilename: selectedScan.reportFilename
            };

            showScanDashboard(selectedScan.analysis);
            updateScanInfoDisplay();
            showNotification(`Loaded scan results for: ${selectedScan.target}`, 'success');
        }
    }

    function showCurrentScan() {
        if (currentScanAnalysis) {
            showScanDashboard(currentScanAnalysis);
            updateScanInfoDisplay();
            showNotification('Showing current scan results', 'info');
        } else {
            showNotification('No current scan results available', 'warning');
        }
    }

    async function loadPastScansFromServer() {
        try {
            const response = await fetch('/api/history/scans');
            if (response.ok) {
                const scans = await response.json();
                scans.forEach(scan => {
                    if (scan.analysis && !pastScans.find(p => p.id === scan.id)) {
                        pastScans.push({
                            id: scan.id,
                            target: scan.target,
                            timestamp: scan.startTime,
                            analysis: scan.analysis,
                            reportGenerated: scan.reportGenerated,
                            reportFilename: scan.reportId ? `scan-report-${scan.id}.pdf` : null
                        });
                    }
                });
                if (pastScans.length > 0) {
                    populatePastScanSelector();
                }
            }
        } catch (error) {
            console.error('Error loading past scans:', error);
        }
    }

    function stopScan() {
        if (socket) {
            socket.emit('stop-scan');
            
            stopProgressAnimation();

            const scanStatus = document.getElementById('scan-status');
            if (scanStatus) scanStatus.textContent = 'Scan stopped by user';

            const stopBtn = document.getElementById('stop-scan-btn');
            if (stopBtn) stopBtn.disabled = true;

            const startBtn = document.getElementById('start-scan-btn');
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
            }

            appendOutput('Scan stopped by user.', 'warning');
            showNotification('Scan has been stopped', 'warning');
        }
    }
    
    socket.on('scan-progress', data => {
        console.log('[Frontend] Received scan-progress:', data);
        
        // Update scan status with timestamp
        if (data.status && scanStatus) {
            const timestamp = new Date().toLocaleTimeString();
            scanStatus.innerHTML = `<span class="text-primary fw-bold">${data.status}</span> <small class="text-muted ms-2">${timestamp}</small>`;
            
            // Real-time progress calculation
            if (data.status.includes('Starting')) {
                scanStartTime = Date.now();
                startProgressAnimation();
                updateProgress(5, 'Initializing...');
            } else if (data.status.includes('Scanning') || data.status.includes('Running')) {
                // Update progress based on time elapsed and scan activity
                updateProgressBasedOnActivity(data);
            } else if (data.status === 'Completed') {
                stopProgressAnimation();
                updateProgress(100, 'Scan Successful');
                if (scanProgress) {
                    scanProgress.classList.remove('bg-primary');
                    scanProgress.classList.add('bg-success');
                }
            } else if (data.status === 'Failed' || data.status === 'Stopped') {
                stopProgressAnimation();
                updateProgress(data.status === 'Stopped' ? 50 : 0, data.status);
                if (scanProgress) {
                    scanProgress.classList.remove('bg-primary');
                    scanProgress.classList.add(data.status === 'Stopped' ? 'bg-warning' : 'bg-danger');
                }
            }
        }
        
        // Use explicit progress if provided
        if (data.progress !== undefined && scanProgress) {
            updateProgress(data.progress);
        }
        
        if (data.message && data.message.text) {
            appendOutput(data.message.text, data.message.type || 'info');
        }
        
        // Show report generation notification
        if (data.reportGenerated && data.reportFilename) {
            showNotification(`Professional report generated: ${data.reportFilename}`, 'success');
        }

        if (data.status === 'Completed' && data.analysis) {
            currentScanAnalysis = data.analysis;
            currentScanInfo = {
                id: data.scanId,
                target: document.getElementById('target-input')?.value || 'Unknown',
                timestamp: new Date().toISOString(),
                reportGenerated: data.reportGenerated,
                reportFilename: data.reportFilename
            };

            pastScans.unshift({
                id: data.scanId,
                target: currentScanInfo.target,
                timestamp: currentScanInfo.timestamp,
                analysis: data.analysis,
                reportGenerated: data.reportGenerated,
                reportFilename: data.reportFilename
            });

            if (pastScans.length > 20) {
                pastScans = pastScans.slice(0, 20);
            }

            populatePastScanSelector();
            showScanDashboard(data.analysis);
            updateScanInfoDisplay();

            const stopBtn = document.getElementById('stop-scan-btn');
            if (stopBtn) stopBtn.disabled = true;

            const startBtn = document.getElementById('start-scan-btn');
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
            }
        }
    });

    socket.on('endpoint-protector:overview', (data) => {
        endpointOverview = data;
        renderEndpointOverview();
    });

    socket.on('endpoint-protector:agents', (agents = []) => {
        if (!Array.isArray(agents)) {
            console.warn('[Frontend] Invalid agents data received:', agents);
            return;
        }
        // Filter out invalid agents
        const validAgents = agents.filter(agent => agent && agent.agentId);
        endpointAgents = new Map(validAgents.map(agent => [agent.agentId, agent]));
        renderEndpointAgents();
        renderEndpointOverview();
        console.log(`[Frontend] Received ${validAgents.length} agents`);
    });

    socket.on('endpoint-protector:telemetry', (agent) => {
        if (!agent || !agent.agentId) {
            console.warn('[Frontend] Invalid telemetry data received:', agent);
            return;
        }
        endpointAgents.set(agent.agentId, agent);
        renderEndpointAgents();
        renderEndpointOverview();
        updateCharts(agent); // Update graphs with new telemetry
        console.log(`[Frontend] Telemetry update from agent: ${agent.agentId}`);
    });

    socket.on('endpoint-protector:agent-status', (agent) => {
        if (!agent || !agent.agentId) return;
        endpointAgents.set(agent.agentId, agent);
        renderEndpointAgents();
        renderEndpointOverview();
        socket.emit('endpoint-protector:get-overview');
    });

    socket.on('endpoint-protector:alerts', (alerts = []) => {
        endpointAlerts = alerts;
        renderEndpointAlerts();
    });

    socket.on('endpoint-protector:alert', (alert) => {
        if (!alert) return;
        
        // Check if it's a Windows Event Log event
        const alertType = (alert.alertType || alert.type || '').toUpperCase();
        if (alertType.includes('WINDOWS_EVENT') || alertType === 'WINDOWS_EVENT_ERROR' || alertType === 'WINDOWS_EVENT_WARNING') {
            windowsEvents.unshift(alert);
            if (windowsEvents.length > 100) {
                windowsEvents = windowsEvents.slice(0, 100);
            }
            renderWindowsEvents();
        } else {
            endpointAlerts.unshift(alert);
            if (endpointAlerts.length > 100) {
                endpointAlerts = endpointAlerts.slice(0, 100);
            }
            renderEndpointAlerts();
        }

        const severity = (alert.severity || 'info').toUpperCase();
        const severityToType = {
            CRITICAL: 'danger',
            HIGH: 'warning',
            MEDIUM: 'info',
            LOW: 'secondary',
            INFO: 'info'
        };
        
        // Filter out routine Windows events to prevent notification spam
        // Only show notifications for important events (CRITICAL, HIGH severity)
        // or non-Windows events
        const alertCategory = (alert.alertType || alert.type || '').toUpperCase();
        const isWindowsEvent = alertCategory.includes('WINDOWS_EVENT');
        const isImportantSeverity = ['CRITICAL', 'HIGH'].includes(severity);
        
        if (!isWindowsEvent || isImportantSeverity) {
            showNotification(`[${alert.hostname || alert.agentId}] ${alert.message}`, severityToType[severity] || 'info');
        }
    });

    // Re-render windows events whenever filters change
    if (winEventsFromEl) winEventsFromEl.addEventListener('change', () => renderWindowsEvents());
    if (winEventsToEl) winEventsToEl.addEventListener('change', () => renderWindowsEvents());
    if (winEventsIdEl) winEventsIdEl.addEventListener('input', () => renderWindowsEvents());
    if (winEventsHostEl) winEventsHostEl.addEventListener('input', () => renderWindowsEvents());

    socket.on('endpoint-protector:agent-registered', (agent) => {
        if (!agent || !agent.agentId) return;
        endpointAgents.set(agent.agentId, agent);
        renderEndpointAgents();
        renderEndpointOverview();
        socket.emit('endpoint-protector:get-overview');
        showNotification(`New agent connected: ${agent.hostname || agent.agentId}`, 'success');
    });
    
    function startProgressAnimation() {
        progressInterval = setInterval(() => {
            updateProgressBasedOnTime();
        }, 2000); // Update every 2 seconds
    }
    
    function updateProgressBasedOnTime() {
        if (!scanStartTime) return;
        
        const elapsed = Date.now() - scanStartTime;
        const estimatedDuration = 120000; // 2 minutes estimated scan time
        let progress = Math.min((elapsed / estimatedDuration) * 85, 85); // Max 85% based on time
        
        updateProgress(progress);
    }
    
    function updateProgressBasedOnActivity(data) {
        if (!scanStartTime) return;
        
        const elapsed = Date.now() - scanStartTime;
        let progress = 0;
        
        // Calculate progress based on scan activity
        if (data.message && data.message.text) {
            const text = data.message.text.toLowerCase();
            if (text.includes('starting nmap') || text.includes('initiating')) {
                progress = 10;
            } else if (text.includes('discovered') || text.includes('scanning')) {
                progress = Math.min(30 + (elapsed / 1000) * 2, 70);
            } else if (text.includes('host') && text.includes('up')) {
                progress = 75;
            } else if (text.includes('scan report')) {
                progress = 90;
            }
        }
        
        // Ensure progress moves forward
        const currentProgress = parseFloat(scanProgress.style.width) || 0;
        if (progress > currentProgress) {
            updateProgress(progress);
        }
    }
    
    function updateProgress(percentage, statusText) {
        if (!scanProgress) return;
        
        percentage = Math.max(0, Math.min(100, percentage));
        scanProgress.style.width = `${percentage}%`;
        scanProgress.textContent = `${Math.round(percentage)}%`;
        scanProgress.setAttribute('aria-valuenow', Math.round(percentage));
        
        // Update status text if provided
        if (statusText && scanStatus) {
            const timestamp = new Date().toLocaleTimeString();
            scanStatus.innerHTML = `<span class="text-primary fw-bold">${statusText}</span> <small class="text-muted ms-2">${timestamp}</small>`;
        }
        
        // Add visual feedback
        if (percentage > 0 && percentage < 100) {
            scanProgress.classList.remove('bg-success', 'bg-danger');
            scanProgress.classList.add('progress-bar-animated', 'progress-bar-striped');
        }
    }
    
    function stopProgressAnimation() {
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        scanProgress.classList.remove('progress-bar-animated', 'progress-bar-striped');
        scanStartTime = null;
    }
    
    function showNotification(message, type = 'info') {
        if (!notificationContainer) {
            notificationContainer = document.createElement('div');
            notificationContainer.id = 'notification-container';
            notificationContainer.className = 'notification-container';
            document.body.appendChild(notificationContainer);
        }

        const variant = notificationVariants[type] || notificationVariants.info;
        const notification = document.createElement('div');
        notification.className = `notification-toast border-start border-3 border-${variant.tone}`;
        notification.innerHTML = `
            <div class="d-flex align-items-start gap-2">
                <span class="notification-icon text-${variant.tone}">
                    <i class="fas ${variant.icon}"></i>
                </span>
                <div class="flex-grow-1 text-white">
                    ${message}
                </div>
                <button type="button" class="btn btn-sm btn-link text-muted p-0">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        const closeBtn = notification.querySelector('button');
        closeBtn.addEventListener('click', () => notification.remove());

        notificationContainer.appendChild(notification);

        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    window.refreshEndpointProtectorData = refreshEndpointProtectorData;
    async function refreshEndpointProtectorData() {
        try {
            if (endpointSyncStatus) endpointSyncStatus.textContent = 'Syncing...';
            const results = await Promise.allSettled([
                fetch('/api/endpoint-protector/overview'),
                fetch('/api/endpoint-protector/agents'),
                fetch('/api/endpoint-protector/alerts')
            ]);

            const [overviewRes, agentsRes, alertsRes] = results.map(r => r.status === 'fulfilled' ? r.value : null);

            // Only update pieces that succeeded; never hard-fail the whole refresh
            if (overviewRes && overviewRes.ok) {
                endpointOverview = await overviewRes.json();
            }

            let agents = null;
            if (agentsRes && agentsRes.ok) {
                agents = await agentsRes.json();
            }

            let alerts = null;
            if (alertsRes && alertsRes.ok) {
                alerts = await alertsRes.json();
            }

            // Filter out any invalid agents
            if (Array.isArray(agents)) {
                const validAgents = agents.filter(agent => agent && agent.agentId);
                endpointAgents = new Map(validAgents.map(agent => [agent.agentId, agent]));
            }
            
            // Filter out demo/fake alerts
            if (Array.isArray(alerts)) {
                endpointAlerts = alerts.filter(alert => {
                    if (!alert || !alert.timestamp || !alert.agentId) return false;
                    const msg = (alert.message || '').toLowerCase();
                    return !msg.includes('demo') && !msg.includes('test') && !msg.includes('sample');
                });
            }

            renderEndpointOverview();
            renderEndpointAgents();
            renderEndpointAlerts();
            if (document.getElementById('ids-section')?.classList.contains('active')) {
                ensureCharts();
            }
            if (endpointSyncStatus) endpointSyncStatus.textContent = 'Synced';
            
            console.log(`[Frontend] Endpoint Protector refresh complete`);
        } catch (error) {
            console.error('[Frontend] Error refreshing Endpoint Protector data:', error);
            // Avoid spamming toasts if backend is temporarily unavailable
            const now = Date.now();
            // Only warn if we have NO data at all (socket may still be working)
            const hasAnyData = endpointAgents.size > 0 || (endpointOverview && endpointOverview.total > 0);
            if (!hasAnyData && (now - lastEndpointRefreshErrorTs > 15000)) {
                lastEndpointRefreshErrorTs = now;
                showNotification('Endpoint data refresh failed (REST unavailable). Live socket updates will continue automatically.', 'warning');
            }
            if (endpointSyncStatus) endpointSyncStatus.textContent = 'Error';
        }
    }

    function renderEndpointOverview() {
        if (!endpointTotals.total) return;
        
        // Always compute from live agent data to avoid stale health score
        const agents = Array.from(endpointAgents.values());
        const total = agents.length;
        const online = agents.filter(a => (a.status || 'OFFLINE') !== 'OFFLINE').length;
        const critical = agents.filter(a => (a.riskScore || 0) >= 70).length;
        const avgRisk = total > 0 ? Math.round(agents.reduce((sum, a) => sum + (a.riskScore || 0), 0) / total) : 0;

        // Preserve lastUpdated from backend if present, otherwise now
        const lastUpdated = endpointOverview?.lastUpdated || new Date().toISOString();

        const overview = {
            total,
            online,
            offline: total - online,
            critical,
            avgRisk,
            lastUpdated
        };

        endpointTotals.total.textContent = overview.total || 0;
        endpointTotals.online.textContent = overview.online || 0;
        endpointTotals.offline.textContent = overview.offline || 0;
        endpointTotals.critical.textContent = overview.critical || 0;
        endpointTotals.score.textContent = `${overview.avgRisk || 0}%`;
        
        // Update threat statistics from alerts
        updateThreatStatistics();
        
        // Update health status display
        const healthStatusEl = document.getElementById('health-status');
        if (healthStatusEl) {
            const online = overview.online || 0;
            healthStatusEl.textContent = online > 0 ? 'Connected' : 'Waiting for agent';
            healthStatusEl.className = `badge ${online > 0 ? 'bg-success' : 'bg-warning'} ms-2`;
        }

        const statusBadge = document.getElementById('ids-status-badge');
        if (statusBadge) {
            const online = overview.online || 0;
            statusBadge.textContent = online > 0 ? 'ACTIVE' : 'IDLE';
            statusBadge.className = `badge ${online > 0 ? 'bg-success' : 'bg-secondary'}`;
        }
        
        const uptimeEl = document.getElementById('health-uptime');
        if (uptimeEl) {
            uptimeEl.textContent = overview.lastUpdated ? formatRelativeTime(overview.lastUpdated) : 'Just now';
        }
    }

    function updateThreatStatistics() {
        // Calculate threat statistics from endpoint alerts
        const now = Date.now();
        const last24h = now - (24 * 60 * 60 * 1000);
        
        const allAlerts = [...endpointAlerts, ...windowsEvents];
        const alerts24h = allAlerts.filter(alert => {
            const alertTime = new Date(alert.timestamp || alert.details?.timestamp || 0).getTime();
            return alertTime > last24h;
        });
        
        const severityDist = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0
        };
        
        alerts24h.forEach(alert => {
            const severity = (alert.severity || 'INFO').toUpperCase();
            if (severityDist.hasOwnProperty(severity)) {
                severityDist[severity]++;
            } else if (severity === 'WARNING' || severity.includes('ERROR')) {
                severityDist.HIGH++;
            } else {
                severityDist.MEDIUM++;
            }
        });
        
        const stats = {
            total_threats: allAlerts.length,
            threats_24h: alerts24h.length,
            severity_distribution: severityDist
        };
        
        document.getElementById('stats-total').textContent = stats.total_threats || 0;
        document.getElementById('stats-24h').textContent = stats.threats_24h || 0;
        document.getElementById('stats-critical').textContent = severityDist.CRITICAL || 0;
        document.getElementById('stats-high').textContent = severityDist.HIGH || 0;
        document.getElementById('stats-medium').textContent = severityDist.MEDIUM || 0;
    }

    function renderEndpointAgents() {
        if (!endpointGrid) return;
        const agents = Array.from(endpointAgents.values());
        const search = (endpointSearchInput?.value || '').trim().toLowerCase();
        const statusFilter = (endpointStatusFilter?.value || 'ALL').toUpperCase();

        const filteredAgents = agents.filter(agent => {
            if (!agent) return false;
            const status = (agent.status || 'OFFLINE').toUpperCase();
            if (statusFilter !== 'ALL' && status !== statusFilter) return false;

            if (!search) return true;
            const haystack = [
                agent.hostname,
                agent.agentId,
                agent.ipAddress,
                agent.platform
            ].filter(Boolean).join(' ').toLowerCase();
            return haystack.includes(search);
        });

        if (endpointVisibleCount) {
            endpointVisibleCount.textContent = `${filteredAgents.length} visible`;
        }
        const normalizePercent = (value = 0) => {
            const num = typeof value === 'number' ? value : parseFloat(value);
            if (Number.isNaN(num)) return 0;
            return Math.min(Math.max(num, 0), 100);
        };

        if (filteredAgents.length === 0) {
            endpointGrid.innerHTML = `
                <div class="text-center py-5">
                    <i class="fas fa-server fa-3x text-muted mb-3"></i>
                    <div class="text-muted mb-2">${agents.length === 0 ? 'No endpoint agents connected' : 'No endpoints match your filters'}</div>
                    <small class="text-muted d-block">Start the Python endpoint agent to see it here:</small>
                    <code class="d-block mt-2 p-2 bg-dark rounded">py enterprise_endpoint_agent.py</code>
                </div>
            `;
            return;
        }

        endpointGrid.innerHTML = filteredAgents.map(agent => {
            const status = (agent.status || 'OFFLINE').toUpperCase();
            const statusClass = status === 'OFFLINE' ? 'offline' : status === 'DEGRADED' ? 'degraded' : 'online';
            const cpu = agent.telemetry?.cpu?.usage ?? 0;
            const memory = agent.telemetry?.memory?.utilization ?? 0;
            const normalizedCpu = normalizePercent(cpu);
            const normalizedMemory = normalizePercent(memory);
            const lastSeen = formatRelativeTime(agent.lastSeen);
            const telemetry = agent.telemetry || {};
            const cpuData = telemetry.cpu || {};
            const memData = telemetry.memory || {};
            const processes = telemetry.processes || [];
            const network = telemetry.network || {};
            const integrity = telemetry.integrity || {};
            const liveProcesses = processes.slice(0, 5);
            
            // Format memory values
            const memTotal = memData.total ? formatBytes(memData.total) : 'N/A';
            const memUsed = memData.used ? formatBytes(memData.used) : 'N/A';
            const memFree = memData.free ? formatBytes(memData.free) : 'N/A';
            
            const suspiciousCount = processes.filter(p => p.suspicious).length;
            
            // Network interfaces
            const networkInterfaces = network.interfaces || [];
            const ifaceAddresses = networkInterfaces.flatMap(iface => iface.addresses || []).filter(Boolean);
            const primaryIp = agent.ipAddress || network.primaryIp || ifaceAddresses[0] || 'N/A';
            const additionalIps = ifaceAddresses.filter(addr => addr !== primaryIp);

            return `
                <div class="endpoint-card mb-3 border rounded p-3 shadow-sm" data-agent-id="${agent.agentId}">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div class="flex-grow-1">
                            <div class="d-flex align-items-center mb-1">
                                <h6 class="fw-bold mb-0 me-2">${agent.hostname || agent.agentId}</h6>
                                <span class="badge bg-${status === 'ONLINE' ? 'success' : status === 'DEGRADED' ? 'warning' : 'secondary'}">${status}</span>
                            </div>
                            <small class="text-muted d-block">${agent.platform || 'Unknown OS'}</small>
                            <small class="text-muted d-block">IP: ${primaryIp}${additionalIps.length ? ` <span class="text-secondary">(+${additionalIps.length} more)</span>` : ''}</small>
                            ${agent.tags && agent.tags.length > 0 ? `<div class="mt-1">${agent.tags.map(tag => `<span class="badge bg-info me-1">${tag}</span>`).join('')}</div>` : ''}
                        </div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                <i class="fas fa-cog"></i>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><a class="dropdown-item" href="#" onclick="viewAgentDetails('${agent.agentId}'); return false;"><i class="fas fa-info-circle me-2"></i>View Details</a></li>
                                <li><a class="dropdown-item" href="#" onclick="refreshEndpointProtectorData(); return false;"><i class="fas fa-sync me-2"></i>Refresh Dashboard Data</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item text-warning" href="#" onclick="sendAgentCommand('${agent.agentId}', 'restart'); return false;"><i class="fas fa-redo me-2"></i>Restart Agent</a></li>
                                <li><a class="dropdown-item text-danger" href="#" onclick="sendAgentCommand('${agent.agentId}', 'stop'); return false;"><i class="fas fa-stop me-2"></i>Stop Monitoring</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><h6 class="dropdown-header">USB Control</h6></li>
                                <li><a class="dropdown-item text-danger" href="#" onclick="blockUSBDevice('${agent.agentId}'); return false;"><i class="fas fa-ban me-2"></i>Block USB Devices</a></li>
                                <li><a class="dropdown-item text-success" href="#" onclick="unblockUSBDevice('${agent.agentId}'); return false;"><i class="fas fa-check me-2"></i>Unblock USB Devices</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><h6 class="dropdown-header">Network Control</h6></li>
                                <li><a class="dropdown-item text-warning" href="#" onclick="blockNetworkInterface('${agent.agentId}'); return false;"><i class="fas fa-network-wired me-2"></i>Block Network Interface</a></li>
                                <li><a class="dropdown-item text-success" href="#" onclick="unblockNetworkInterface('${agent.agentId}'); return false;"><i class="fas fa-network-wired me-2"></i>Unblock Network Interface</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><h6 class="dropdown-header">User Control</h6></li>
                                <li><a class="dropdown-item text-danger" href="#" onclick="blockUser('${agent.agentId}'); return false;"><i class="fas fa-user-slash me-2"></i>Block User</a></li>
                                <li><a class="dropdown-item text-success" href="#" onclick="unblockUser('${agent.agentId}'); return false;"><i class="fas fa-user-check me-2"></i>Unblock User</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><h6 class="dropdown-header">Process Control</h6></li>
                                <li><a class="dropdown-item text-danger" href="#" onclick="terminateProcess('${agent.agentId}'); return false;"><i class="fas fa-skull me-2"></i>Terminate Process</a></li>
                            </ul>
                        </div>
                    </div>
                    
                    <!-- Real-time Telemetry -->
                    <div class="row mb-2">
                        <div class="col-6">
                            <div class="mb-2 p-2 rounded" style="background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.15);">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <small style="color: #adb5bd !important; font-weight: 500;">CPU</small>
                                    <strong style="color: ${normalizedCpu > 80 ? '#dc3545' : normalizedCpu > 60 ? '#ffc107' : '#0dcaf0'} !important; font-size: 1.1em;">${normalizedCpu.toFixed(1)}%</strong>
                                </div>
                                <div class="progress mt-1" style="height: 10px; background: rgba(0, 0, 0, 0.4); border-radius: 5px;">
                                    <div class="progress-bar bg-${normalizedCpu > 80 ? 'danger' : normalizedCpu > 60 ? 'warning' : 'info'}" 
                                         style="width: ${normalizedCpu}%; border-radius: 5px;"></div>
                                </div>
                                ${cpuData.cores ? `<small style="color: #adb5bd !important; font-size: 0.7rem; margin-top: 4px; display: block;">${cpuData.cores} cores</small>` : ''}
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="mb-2 p-2 rounded" style="background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.15);">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <small style="color: #adb5bd !important; font-weight: 500;">Memory</small>
                                    <strong style="color: ${normalizedMemory > 80 ? '#dc3545' : normalizedMemory > 60 ? '#ffc107' : '#198754'} !important; font-size: 1.1em;">${normalizedMemory.toFixed(1)}%</strong>
                                </div>
                                <div class="progress mt-1" style="height: 10px; background: rgba(0, 0, 0, 0.4); border-radius: 5px;">
                                    <div class="progress-bar bg-${normalizedMemory > 80 ? 'danger' : normalizedMemory > 60 ? 'warning' : 'success'}" 
                                         style="width: ${normalizedMemory}%; border-radius: 5px;"></div>
                                </div>
                                <small style="color: #adb5bd !important; font-size: 0.7rem; margin-top: 4px; display: block;">${memUsed} / ${memTotal}</small>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Additional Metrics -->
                    <div class="row mb-2">
                        <div class="col-4 text-center">
                            <div class="small text-light" style="color: #adb5bd !important;">Risk Score</div>
                            <div class="h5 mb-0" style="color: ${agent.riskScore >= 70 ? '#dc3545' : agent.riskScore >= 40 ? '#ffc107' : '#198754'} !important;">${agent.riskScore || 0}%</div>
                        </div>
                        <div class="col-4 text-center">
                            <div class="small text-light" style="color: #adb5bd !important;">Processes</div>
                            <div class="h5 mb-0 text-light" style="color: #ffffff !important;">${processes.length}</div>
                            ${suspiciousCount > 0 ? `<small class="text-danger" style="color: #dc3545 !important;">${suspiciousCount} suspicious</small>` : ''}
                        </div>
                        <div class="col-4 text-center">
                            <div class="small text-light" style="color: #adb5bd !important;">Alerts</div>
                            <div class="h5 mb-0" style="color: ${integrity.alerts > 0 ? '#dc3545' : '#198754'} !important;">${integrity.alerts || 0}</div>
                        </div>
                    </div>
                    
                    ${liveProcesses.length > 0 ? `
                    <div class="mt-2 pt-2" style="border-top: 1px solid rgba(255, 255, 255, 0.1);">
                        <small class="d-block mb-2" style="color: #adb5bd !important; font-weight: 600;">Live Processes</small>
                        ${liveProcesses.map(proc => {
                            const procCpu = normalizePercent(proc.cpu || proc.cpuPct || 0);
                            return `
                                <div class="d-flex justify-content-between align-items-center mb-1 small">
                                    <span class="text-truncate" style="max-width: 55%; color: #fff;" title="${proc.name}">${proc.name || 'Unknown'}</span>
                                    <div class="d-flex align-items-center gap-2">
                                        <span class="badge bg-dark text-${procCpu > 80 ? 'danger' : procCpu > 60 ? 'warning' : 'info'} border border-${procCpu > 80 ? 'danger' : procCpu > 60 ? 'warning' : 'info'}">
                                            ${procCpu.toFixed(1)}%
                                        </span>
                                        ${proc.suspicious ? '<span class="badge bg-danger">Suspicious</span>' : ''}
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                    ` : `<small class="text-muted d-block mt-2">No live process data</small>`}
                    
                    <!-- Footer -->
                    <div class="d-flex justify-content-between align-items-center mt-2 pt-2" style="border-top: 1px solid rgba(255, 255, 255, 0.1);">
                        <small class="text-light" style="color: #adb5bd !important;">
                            <i class="fas fa-clock me-1"></i>Last seen: ${lastSeen}
                        </small>
                        <small class="text-light" style="color: #adb5bd !important;">
                            <i class="fas fa-user me-1"></i>${agent.owner || 'Unknown'}
                        </small>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderEndpointAlerts() {
        if (!endpointAlertsTimeline) return;

        // Filter out any demo/fake data - only show real alerts with valid timestamps
        const realAlerts = endpointAlerts.filter(alert => {
            // Must have valid timestamp and agentId
            if (!alert.timestamp || !alert.agentId) return false;
            // Must have a message
            if (!alert.message && !alert.alertType && !alert.type) return false;
            // Reject demo/test data patterns
            const msg = (alert.message || '').toLowerCase();
            if (msg.includes('demo') || msg.includes('test') || msg.includes('sample') || msg.includes('placeholder')) {
                return false;
            }
            return true;
        });

        if (realAlerts.length === 0) {
            endpointAlertsTimeline.innerHTML = '<div class="text-center py-4"><i class="fas fa-inbox fa-2x text-muted mb-2"></i><div class="text-muted">No telemetry events yet. Events will appear here when agents send data.</div></div>';
            return;
        }

        // Professional formatting for rich alert types - limit to 50 most recent
        endpointAlertsTimeline.innerHTML = realAlerts.slice(0, 50).map(alert => {
            let icon = 'fa-info-circle', color = 'info', message = escapeHtml(alert.message || '');
            let contextInfo = '';
            const alertType = (alert.alertType || alert.type || '').toUpperCase();
            
            switch (alertType) {
                case 'FILE_MODIFIED':
                    icon = 'fa-file-pen'; color = 'primary';
                    const filePath = escapeHtml(alert.file || (alert.details && alert.details.file) || 'Unknown file');
                    message = `File modified: <code class="text-primary">${filePath}</code>`;
                    break;
                case 'FILE_DELETED':
                    icon = 'fa-file-circle-minus'; color = 'danger';
                    const deletedFile = escapeHtml(alert.file || (alert.details && alert.details.file) || 'Unknown file');
                    message = `File deleted: <code class="text-danger">${deletedFile}</code>`;
                    break;
                case 'USB_CONNECTED':
                    icon = 'fa-usb'; color = 'success';
                    const vendor = escapeHtml(alert.details && alert.details.vendor ? alert.details.vendor : '');
                    const product = escapeHtml(alert.details && alert.details.product ? alert.details.product : '');
                    message = `USB device connected${vendor ? `: <strong>${vendor} ${product}</strong>` : ''}`;
                    if (alert.details && Object.keys(alert.details).length > 0) {
                        contextInfo = Object.entries(alert.details)
                            .filter(([k]) => k !== 'vendor' && k !== 'product')
                            .map(([k, v]) => `<span class="badge bg-secondary me-1">${escapeHtml(k)}: ${escapeHtml(v)}</span>`)
                            .join('');
                    }
                    break;
                case 'USB_DISCONNECTED':
                    icon = 'fa-usb'; color = 'secondary';
                    const disVendor = escapeHtml(alert.details && alert.details.vendor ? alert.details.vendor : '');
                    const disProduct = escapeHtml(alert.details && alert.details.product ? alert.details.product : '');
                    message = `USB device disconnected${disVendor ? `: <strong>${disVendor} ${disProduct}</strong>` : ''}`;
                    break;
                case 'RESOURCE':
                    icon = 'fa-exclamation-triangle'; color = 'warning';
                    break;
                case 'PROCESS':
                    icon = 'fa-microchip'; color = 'danger';
                    break;
                default:
                    if (!message) {
                        message = escapeHtml(alert.description || 'Security event detected');
                    }
            }
            
            const severity = (alert.severity || 'INFO').toUpperCase();
            const severityColors = {
                'CRITICAL': 'danger',
                'HIGH': 'warning',
                'MEDIUM': 'info',
                'LOW': 'secondary',
                'INFO': 'info'
            };
            const severityColor = severityColors[severity] || 'info';
            
            const hostname = escapeHtml(alert.hostname || alert.agentId || 'Unknown Agent');

            return `
              <div class="timeline-entry mb-3 p-3 bg-dark border-start border-${severityColor} border-3 rounded shadow-sm">
                <div class="d-flex justify-content-between align-items-start mb-2">
                  <div class="flex-grow-1">
                    <div class="d-flex align-items-center mb-1">
                      <i class="fas ${icon} me-2 text-${severityColor}"></i>
                      <strong class="text-white">${hostname}</strong>
                    </div>
                    <div class="text-light mb-1">${message}</div>
                    ${contextInfo ? `<div class="mt-2">${contextInfo}</div>` : ''}
                  </div>
                  <span class="badge bg-${severityColor} ms-2">${severity.replace(/_/g, ' ')}</span>
                </div>
                <div class="d-flex justify-content-between align-items-center">
                  <small class="text-muted"><i class="fas fa-clock me-1"></i>${formatRelativeTime(alert.timestamp)}</small>
                  ${alert.agentId ? `<small class="text-muted"><code>${escapeHtml(alert.agentId.substring(0, 12))}...</code></small>` : ''}
                </div>
              </div>
            `;
        }).join('');
    }

    function formatRelativeTime(timestamp) {
        if (!timestamp) return 'Unknown';
        const now = new Date();
        const past = new Date(timestamp);
        const diffMs = now - past;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);

        if (diffMins < 1) return 'just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        return past.toLocaleDateString();
    }

    function renderWindowsEvents() {
        const container = document.getElementById('windows-events-container');
        if (!container) return;

        if (winEventsCountEl) winEventsCountEl.textContent = String(windowsEvents.length);

        const filtered = getFilteredWindowsEvents();
        if (winEventsFilteredCountEl) winEventsFilteredCountEl.textContent = `${filtered.length} shown`;
        
        if (filtered.length === 0) {
            container.innerHTML = '<div class="text-center py-5"><i class="fas fa-windows fa-2x text-muted mb-2"></i><div class="text-muted">No Windows Event Log events yet</div></div>';
            return;
        }
        
        container.innerHTML = filtered.slice(0, 50).map(event => {
            const meta = getEventAgentMeta(event);
            const eventType = (event.event_type || event.alertType || event.details?.event_type || 'INFO').toUpperCase();
            const severity = (event.severity || event.event_type || 'INFO').toUpperCase();
            const icon = eventType === 'ERROR' ? 'fa-exclamation-circle' : 'fa-exclamation-triangle';
            const color = eventType === 'ERROR' ? 'danger' : 'warning';
            const message = escapeHtml(event.message || event.details?.message || 'Windows Event');
            const source = escapeHtml(event.source || event.details?.source || 'Unknown');
            const logType = escapeHtml(event.log_type || event.details?.log_type || 'System');
            const eventId = escapeHtml(event.event_id || event.details?.event_id || '');
            const hostname = escapeHtml(meta.hostname || 'N/A');
            const ipAddress = escapeHtml(meta.ipAddress || 'N/A');
            const agentId = escapeHtml((meta.agentId || '').toString().slice(0, 12));
            const username = escapeHtml(meta.username || 'N/A');
            
            return `
                <div class="timeline-entry mb-3 p-3 bg-dark border-start border-${color} border-3 rounded shadow-sm">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div class="flex-grow-1">
                            <div class="d-flex align-items-center mb-1">
                                <i class="fas ${icon} me-2 text-${color}"></i>
                                <strong class="text-white">${logType} - ${source}</strong>
                            </div>
                            <div class="text-muted small mb-1">
                                <span class="badge bg-secondary me-1">Host: ${hostname}</span>
                                <span class="badge bg-secondary me-1">IP: ${ipAddress}</span>
                                <span class="badge bg-secondary me-1">Agent: ${agentId}${meta.agentId && meta.agentId.length > 12 ? '…' : ''}</span>
                                <span class="badge bg-secondary">User: ${username}</span>
                            </div>
                            <div class="text-light mb-1">${message.substring(0, 300)}</div>
                        </div>
                        <span class="badge bg-${color} ms-2">${severity}</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center">
                        <small class="text-muted"><i class="fas fa-clock me-1"></i>${formatRelativeTime(event.timestamp || event.details?.timestamp)}</small>
                        ${eventId ? `<small class="text-muted">Event ID: ${eventId}</small>` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }

    function refreshWindowsEvents() {
        socket.emit('endpoint-protector:get-alerts');
        renderWindowsEvents();
    }

    function downloadWindowsEventsPdf(filteredOnly) {
        const items = filteredOnly ? getFilteredWindowsEvents() : windowsEvents;
        if (!items || items.length === 0) {
            showNotification('No Windows events to export.', 'warning');
            return;
        }
        if (!window.jspdf || !window.jspdf.jsPDF) {
            showNotification('PDF exporter not available (jsPDF not loaded).', 'error');
            return;
        }

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ unit: 'mm', format: 'a4' });

        const filters = getWindowsEventsFilters();
        const filterTextParts = [];
        if (filters.from) filterTextParts.push(`From: ${filters.from.toLocaleDateString()}`);
        if (filters.to) filterTextParts.push(`To: ${new Date(filters.to.getTime()).toLocaleDateString()}`);
        if (filters.eventId) filterTextParts.push(`EventId contains: ${filters.eventId}`);
        if (filters.host) filterTextParts.push(`Host contains: ${filters.host}`);
        const filterText = filterTextParts.length ? filterTextParts.join(' | ') : 'No filters';

        const pageWidth = doc.internal.pageSize.getWidth();
        let y = 14;

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(14);
        doc.text('Windows Event Log Report', 14, y);
        y += 7;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.text(`Generated: ${new Date().toLocaleString()}`, 14, y);
        y += 5;
        doc.text(`Scope: ${filteredOnly ? 'Filtered' : 'All'} | Count: ${items.length}`, 14, y);
        y += 5;
        doc.text(`Filters: ${filterText}`, 14, y, { maxWidth: pageWidth - 28 });
        y += 8;

        doc.setDrawColor(90);
        doc.line(14, y, pageWidth - 14, y);
        y += 6;

        const addLine = (text) => {
            const lines = doc.splitTextToSize(text, pageWidth - 28);
            for (const line of lines) {
                if (y > 285) {
                    doc.addPage();
                    y = 14;
                }
                doc.text(line, 14, y);
                y += 5;
            }
        };

        items.forEach((ev, idx) => {
            const meta = getEventAgentMeta(ev);
            const ts = ev.timestamp || ev.details?.timestamp || '';
            const dt = ts ? new Date(ts) : null;
            const when = dt && !Number.isNaN(dt.getTime()) ? dt.toLocaleString() : 'Unknown time';
            const logType = ev.log_type || ev.details?.log_type || 'System';
            const source = ev.source || ev.details?.source || 'Unknown';
            const eventId = ev.event_id || ev.details?.event_id || '';
            const level = (ev.event_type || ev.details?.event_type || ev.severity || 'INFO');
            const message = (ev.message || ev.details?.message || '').toString();

            doc.setFont('helvetica', 'bold');
            addLine(`${idx + 1}. [${level}] ${when}`);
            doc.setFont('helvetica', 'normal');
            addLine(`Host: ${meta.hostname || 'N/A'} | IP: ${meta.ipAddress || 'N/A'} | Agent: ${meta.agentId || 'N/A'} | User: ${meta.username || 'N/A'}`);
            addLine(`Log: ${logType} | Source: ${source} | Event ID: ${eventId || 'N/A'}`);
            addLine(`Message: ${message.substring(0, 1200)}`);
            y += 3;
        });

        const safe = (s) => String(s).replace(/[^a-z0-9_-]+/gi, '_').slice(0, 80);
        const fileName = `windows_events_${filteredOnly ? 'filtered' : 'all'}_${safe(new Date().toISOString())}.pdf`;
        doc.save(fileName);
    }

    // Make ensureCharts available globally
    window.ensureCharts = ensureCharts;

    function ensureCharts() {
        // Chart.js might not be loaded yet
        if (typeof Chart === 'undefined') return;

        const cpuCanvas = document.getElementById('cpuUsageChart');
        const memCanvas = document.getElementById('memoryUsageChart');
        const netCanvas = document.getElementById('networkTrafficChart');
        if (!cpuCanvas || !memCanvas || !netCanvas) return;

        // Create charts once; resize when section becomes visible
        if (!cpuChart || !memoryChart || !networkChart) {
            try { cpuChart?.destroy?.(); } catch (_) {}
            try { memoryChart?.destroy?.(); } catch (_) {}
            try { networkChart?.destroy?.(); } catch (_) {}
            cpuChart = null; memoryChart = null; networkChart = null;
            initCharts();
        }

        setTimeout(() => {
            try { cpuChart?.resize?.(); } catch (_) {}
            try { memoryChart?.resize?.(); } catch (_) {}
            try { networkChart?.resize?.(); } catch (_) {}

            // Seed with latest telemetry if available
            const agents = Array.from(endpointAgents.values());
            if (agents.length > 0) {
                updateCharts(agents[0]);
            }
        }, 50);
    }

    // Initialize charts
    function initCharts() {
        const cpuCtx = document.getElementById('cpuUsageChart');
        const memoryCtx = document.getElementById('memoryUsageChart');
        const networkCtx = document.getElementById('networkTrafficChart');
        
        if (cpuCtx) {
            cpuChart = new Chart(cpuCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'CPU Usage %',
                        data: [],
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            ticks: {
                                callback: function(value) {
                                    return value + '%';
                                }
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
        
        if (memoryCtx) {
            memoryChart = new Chart(memoryCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Memory Usage %',
                        data: [],
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.2)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            ticks: {
                                callback: function(value) {
                                    return value + '%';
                                }
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
        
        if (networkCtx) {
            networkChart = new Chart(networkCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Sent (MB)',
                        data: [],
                        borderColor: 'rgb(54, 162, 235)',
                        backgroundColor: 'rgba(54, 162, 235, 0.2)',
                        tension: 0.4,
                        fill: true
                    }, {
                        label: 'Received (MB)',
                        data: [],
                        borderColor: 'rgb(255, 159, 64)',
                        backgroundColor: 'rgba(255, 159, 64, 0.2)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    return value.toFixed(2) + ' MB';
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    function updateCharts(agent) {
        if (!agent || !agent.telemetry) return;

        if (document.getElementById('ids-section')?.classList.contains('active')) {
            if (!cpuChart || !memoryChart || !networkChart) {
                ensureCharts();
            }
        }
        
        const telemetry = agent.telemetry;
        const timestamp = new Date().toLocaleTimeString();
        
        // Update CPU chart
        if (cpuChart && telemetry.cpu && telemetry.cpu.usage !== undefined) {
            const cpuUsage = Math.min(Math.max(parseFloat(telemetry.cpu.usage) || 0, 0), 100);
            cpuChart.data.labels.push(timestamp);
            cpuChart.data.datasets[0].data.push(cpuUsage);
            
            if (cpuChart.data.labels.length > MAX_HISTORY_POINTS) {
                cpuChart.data.labels.shift();
                cpuChart.data.datasets[0].data.shift();
            }
            cpuChart.update('none');
        }
        
        // Update Memory chart
        if (memoryChart && telemetry.memory && telemetry.memory.utilization !== undefined) {
            const memUsage = Math.min(Math.max(parseFloat(telemetry.memory.utilization) || 0, 0), 100);
            memoryChart.data.labels.push(timestamp);
            memoryChart.data.datasets[0].data.push(memUsage);
            
            if (memoryChart.data.labels.length > MAX_HISTORY_POINTS) {
                memoryChart.data.labels.shift();
                memoryChart.data.datasets[0].data.shift();
            }
            memoryChart.update('none');
        }
        
        // Update Network chart
        if (networkChart && telemetry.network && telemetry.network.network_traffic) {
            const traffic = telemetry.network.network_traffic;
            let totalSent = 0;
            let totalRecv = 0;
            
            Object.values(traffic).forEach(ifaceStats => {
                if (ifaceStats.bytes_sent) totalSent += ifaceStats.bytes_sent;
                if (ifaceStats.bytes_recv) totalRecv += ifaceStats.bytes_recv;
            });
            
            const sentMB = totalSent / (1024 * 1024);
            const recvMB = totalRecv / (1024 * 1024);
            
            networkChart.data.labels.push(timestamp);
            networkChart.data.datasets[0].data.push(sentMB);
            networkChart.data.datasets[1].data.push(recvMB);
            
            if (networkChart.data.labels.length > MAX_HISTORY_POINTS) {
                networkChart.data.labels.shift();
                networkChart.data.datasets[0].data.shift();
                networkChart.data.datasets[1].data.shift();
            }
            networkChart.update('none');
        }
    }

    if (scanForm) {
        scanForm.addEventListener('submit', event => {
            event.preventDefault();
            const target = document.getElementById('target-input')?.value || '';

            if (!validateTargetInput(target)) {
                showNotification('Please enter a valid target address', 'warning');
                return;
            }

            const scanType = document.getElementById('scan-type')?.value || '';
            const customCommand = document.getElementById('custom-command')?.value?.trim() || '';
            const nseScripts = document.getElementById('nse-scripts')?.value || '';
            const pentesterName = document.getElementById('pentester-name')?.value?.trim() || 'Security Analyst';

            let command = scanType === 'custom' ? customCommand : scanType;
            if (nseScripts) {
                command += ` ${nseScripts}`;
            }

            const stopBtn = document.getElementById('stop-scan-btn');
            if (stopBtn) stopBtn.disabled = false;

            const startBtn = document.getElementById('start-scan-btn');
            if (startBtn) {
                startBtn.disabled = true;
                startBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scanning...';
            }

            // Immediately clear and show intent on frontend
            clearOutput();
            appendOutput(`[FRONTEND] Initiating scan for: ${target}`, 'info');
            appendOutput(`[FRONTEND] Command: nmap ${command}`, 'info');
            
            console.log('[Frontend] Emitting start-scan:', { target, command, pentester: pentesterName });
            socket.emit('start-scan', { target, command, pentester: pentesterName });
            
            if (scanStatus) {
                scanStatus.innerHTML = '<i class="fas fa-satellite-dish fa-spin me-1"></i>Waiting for backend response...';
            }
            if (scanProgress) {
                scanProgress.style.width = '0%';
                scanProgress.textContent = '0%';
            }
        });
    }

    // Add a global function for testing socket connectivity
    window.testSocket = () => {
        console.log('[Frontend] Manual socket test emit');
        socket.emit('test-connection', { timestamp: Date.now() });
        appendOutput('[FRONTEND] Manual socket test emitted', 'info');
    };

    const targetInput = document.getElementById('target-input');
    if (targetInput) {
        targetInput.addEventListener('blur', function() {
            const value = this.value.trim();
            if (value) {
                validateTargetInput(value);
            }
        });

        targetInput.addEventListener('input', function() {
            this.classList.remove('is-valid', 'is-invalid');
            const feedback = document.getElementById('target-validation-feedback');
            const suggestion = document.getElementById('target-validation-suggestion');
            if (feedback) feedback.textContent = '';
            if (suggestion) suggestion.classList.add('d-none');
        });
    }

    const loadScanBtn = document.getElementById('load-scan-btn');
    if (loadScanBtn) loadScanBtn.addEventListener('click', loadSelectedScan);

    const showCurrentBtn = document.getElementById('show-current-btn');
    if (showCurrentBtn) showCurrentBtn.addEventListener('click', showCurrentScan);

    const resetScanBtn = document.getElementById('reset-scan-btn');
    if (resetScanBtn) {
        resetScanBtn.addEventListener('click', resetScanForm);
    }

    const stopScanBtn = document.getElementById('stop-scan-btn');
    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', stopScan);
    }


    // Store last VirusTotal result for PDF generation
    let lastVirusTotalResult = null;

    function displayVirusTotalResult(data, scanType) {
        vtResults.innerHTML = '';
        
        if (data && data.data && data.data.attributes) {
            const attrs = data.data.attributes;
            const stats = attrs.last_analysis_stats;
            const results = attrs.last_analysis_results || {};
            const total = Object.values(stats).reduce((a, b) => a + b, 0);
            
            let statusClass = 'success';
            let statusText = 'Clean';
            let statusIcon = 'fa-check-circle';
            
            if (stats.malicious > 0) {
                statusClass = 'danger';
                statusText = 'Malicious';
                statusIcon = 'fa-exclamation-triangle';
            } else if (stats.suspicious > 0) {
                statusClass = 'warning';
                statusText = 'Suspicious';
                statusIcon = 'fa-exclamation-circle';
            }
            
            const scanDate = attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toLocaleString() : new Date().toLocaleString();
            const resourceId = data.data.id || 'N/A';
            
            const resultCard = document.createElement('div');
            resultCard.innerHTML = `
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-${statusClass} text-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas ${statusIcon} me-2"></i>
                            VirusTotal Analysis: ${statusText}
                        </h5>
                        <div class="text-end">
                            <div class="h6 mb-0">${stats.malicious}/${total} detections</div>
                            <small>Security vendors flagged this ${scanType}</small>
                        </div>
                    </div>
                    <div class="card-body">
                        <!-- Quick Stats Row -->
                        <div class="row mb-4">
                            <div class="col-lg-8">
                                <div class="row text-center">
                                    <div class="col-3">
                                        <div class="border rounded p-2">
                                            <div class="h4 text-danger mb-1">${stats.malicious}</div>
                                            <small class="text-muted">Malicious</small>
                                        </div>
                                    </div>
                                    <div class="col-3">
                                        <div class="border rounded p-2">
                                            <div class="h4 text-warning mb-1">${stats.suspicious}</div>
                                            <small class="text-muted">Suspicious</small>
                                        </div>
                                    </div>
                                    <div class="col-3">
                                        <div class="border rounded p-2">
                                            <div class="h4 text-success mb-1">${stats.harmless}</div>
                                            <small class="text-muted">Clean</small>
                                        </div>
                                    </div>
                                    <div class="col-3">
                                        <div class="border rounded p-2">
                                            <div class="h4 text-secondary mb-1">${stats.undetected}</div>
                                            <small class="text-muted">Undetected</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-lg-4">
                                <div class="text-center">
                                    <div class="position-relative d-inline-block">
                                        <svg width="120" height="120" viewBox="0 0 42 42" class="donut">
                                            <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#e9ecef" stroke-width="3"></circle>
                                            <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="${statusClass === 'danger' ? '#dc3545' : statusClass === 'warning' ? '#ffc107' : '#28a745'}" stroke-width="3" stroke-dasharray="${((stats.malicious + stats.suspicious) / total * 100)} ${(100 - (stats.malicious + stats.suspicious) / total * 100)}" stroke-dashoffset="25"></circle>
                                        </svg>
                                        <div class="position-absolute top-50 start-50 translate-middle">
                                            <div class="h6 mb-0">${Math.round(((stats.malicious + stats.suspicious) / total) * 100)}%</div>
                                            <small class="text-muted">Risk</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- File/URL Details -->
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <h6 class="fw-bold text-primary mb-3"><i class="fas fa-info-circle me-2"></i>Basic Properties</h6>
                                <table class="table table-sm table-borderless">
                                    <tbody>
                                        ${scanType === 'file' ? `
                                            <tr><td class="text-muted">SHA256:</td><td><code class="small">${attrs.sha256 || resourceId}</code></td></tr>
                                            <tr><td class="text-muted">MD5:</td><td><code class="small">${attrs.md5 || 'N/A'}</code></td></tr>
                                            <tr><td class="text-muted">SHA1:</td><td><code class="small">${attrs.sha1 || 'N/A'}</code></td></tr>
                                            <tr><td class="text-muted">File size:</td><td>${formatFileSize(attrs.size)}</td></tr>
                                            <tr><td class="text-muted">File type:</td><td>${attrs.type_description || attrs.magic || 'Unknown'}</td></tr>
                                        ` : `
                                            <tr><td class="text-muted">URL:</td><td><code class="small text-break">${attrs.url || 'N/A'}</code></td></tr>
                                            <tr><td class="text-muted">Domain:</td><td>${extractDomain(attrs.url)}</td></tr>
                                        `}
                                        <tr><td class="text-muted">First seen:</td><td>${attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toLocaleString() : 'N/A'}</td></tr>
                                        <tr><td class="text-muted">Last analysis:</td><td>${scanDate}</td></tr>
                                    </tbody>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <h6 class="fw-bold text-primary mb-3"><i class="fas fa-chart-line me-2"></i>Threat Assessment</h6>
                                <div class="mb-3">
                                    <div class="d-flex justify-content-between mb-1">
                                        <small>Risk Level:</small>
                                        <small>${attrs.risk_level || calculateRiskLevel(stats)}</small>
                                    </div>
                                    <div class="progress" style="height: 8px;">
                                        <div class="progress-bar bg-${getRiskColor(attrs.risk_level || calculateRiskLevel(stats))}" 
                                             style="width: ${getRiskPercentage(attrs.risk_level || calculateRiskLevel(stats))}%"></div>
                                    </div>
                                </div>
                                <div class="mb-2">
                                    <small class="text-muted">Reputation Score:</small> 
                                    <span class="badge bg-${getReputationColor(attrs.reputation_score)}">${attrs.reputation_score || 'N/A'}/100</span>
                                </div>
                                <div class="mb-2">
                                    <small class="text-muted">Community Score:</small> 
                                    <span class="text-${attrs.reputation_score > 60 ? 'success' : attrs.reputation_score > 30 ? 'warning' : 'danger'}">
                                        ${attrs.reputation_score > 60 ? 'Trusted' : attrs.reputation_score > 30 ? 'Neutral' : 'Untrusted'}
                                    </span>
                                </div>
                                ${attrs.permalink ? `
                                <div class="mt-3">
                                    <a href="${attrs.permalink}" target="_blank" class="btn btn-outline-primary btn-sm">
                                        <i class="fas fa-external-link-alt"></i> View on VirusTotal
                                    </a>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                        
                        <!-- Detection Results -->
                        <div class="mb-4">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                                <h6 class="fw-bold text-primary mb-0"><i class="fas fa-shield-alt me-2"></i>Security Vendor Analysis</h6>
                            <div class="btn-group btn-group-sm vt-filter-group" role="group">
                                    <button type="button" class="btn btn-outline-secondary active" onclick="filterResults('all')" data-filter="all">All</button>
                                    <button type="button" class="btn btn-outline-danger" onclick="filterResults('malicious')" data-filter="malicious">Malicious</button>
                                    <button type="button" class="btn btn-outline-warning" onclick="filterResults('suspicious')" data-filter="suspicious">Suspicious</button>
                                    <button type="button" class="btn btn-outline-success" onclick="filterResults('clean')" data-filter="clean">Clean</button>
                                </div>
                            </div>
                            <div class="detection-results vt-detection-results" style="max-height: 400px; overflow-y: auto;">
                                ${generateDetectionResults(results)}
                            </div>
                        </div>
                        
                        <!-- Action Buttons -->
                        <div class="d-flex flex-wrap gap-2 vt-action-bar">
                            <button class="btn btn-primary" onclick="downloadVirusTotalPDF()">
                                <i class="fas fa-download"></i> Download PDF Report
                            </button>
                            <button class="btn btn-outline-secondary" onclick="viewRawVirusTotalData()">
                                <i class="fas fa-code"></i> View Raw Data
                            </button>
                            <button class="btn btn-outline-info" onclick="showDetailedAnalysis()">
                                <i class="fas fa-microscope"></i> Detailed Analysis
                            </button>
                            ${attrs.permalink ? `
                            <a href="${attrs.permalink}" target="_blank" class="btn btn-outline-primary">
                                <i class="fas fa-external-link-alt"></i> VirusTotal Report
                            </a>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
            vtResults.appendChild(resultCard);
            
            // Store the result for PDF generation
            lastVirusTotalResult = {
                data: data.data,
                scanType: scanType,
                scanDate: scanDate,
                stats: stats
            };
        } else {
            const resultCard = document.createElement('div');
            resultCard.innerHTML = `
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-info-circle me-2"></i>
                            VirusTotal Scan Complete
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <p class="mb-0">Analysis completed but detailed results are not available.</p>
                        </div>
                        <div class="bg-light p-3 rounded">
                            <h6 class="fw-bold">Raw Response:</h6>
                            <pre class="mb-0" style="font-size: 12px; max-height: 200px; overflow-y: auto;">${JSON.stringify(data, null, 2)}</pre>
                        </div>
                        <div class="mt-3">
                            <button class="btn btn-primary" onclick="downloadVirusTotalPDF()">
                                <i class="fas fa-download"></i> Download PDF Report
                            </button>
                        </div>
                    </div>
                </div>
            `;
            vtResults.appendChild(resultCard);
            
            // Store the result for PDF generation
            lastVirusTotalResult = {
                data: data,
                scanType: scanType,
                scanDate: new Date().toLocaleString(),
                stats: null
            };
        }
    }

    fileScanForm.addEventListener('submit', event => {
        event.preventDefault();
        const file = fileScanForm['file-upload'].files[0];
        if (file) {
            vtResults.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">Scanning file...</p></div>';
            
            const formData = new FormData();
            formData.append('file', file);
            fetch('/api/virustotal/file', {
                method: 'POST',
                body: formData,
            })
                .then(response => response.json())
                .then(data => {
                    displayVirusTotalResult(data, 'file');
                })
                .catch(error => {
                    vtResults.innerHTML = '';
                    vtResults.appendChild(showResult('danger', 'File scan failed: ' + error.message));
                });
        }
    });

    urlScanForm.addEventListener('submit', event => {
        event.preventDefault();
        const url = urlScanForm['url-input'].value;
        
        vtResults.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">Scanning URL...</p></div>';

        fetch('/api/virustotal/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        })
            .then(response => response.json())
            .then(data => {
                displayVirusTotalResult(data, 'url');
            })
            .catch(error => {
                vtResults.innerHTML = '';
                vtResults.appendChild(showResult('danger', 'URL scan failed: ' + error.message));
            });
    });

    hashScanForm.addEventListener('submit', event => {
        event.preventDefault();
        const hash = hashScanForm['hash-input'].value;
        
        vtResults.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">Checking hash...</p></div>';

        fetch('/api/virustotal/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash }),
        })
            .then(response => response.json())
            .then(data => {
                displayVirusTotalResult(data, 'hash');
            })
            .catch(error => {
                vtResults.innerHTML = '';
                vtResults.appendChild(showResult('danger', 'Hash scan failed: ' + error.message));
            });
    });
    // Load history on page load
    loadHistory();
    loadReports();
    loadPastScansFromServer();

    const reportFilterPentester = document.getElementById('report-filter-pentester');
    const reportFilterScanType = document.getElementById('report-filter-scan-type');
    const reportFilterDate = document.getElementById('report-filter-date');
    const reportFilterMonth = document.getElementById('report-filter-month');
    const reportFilterResetBtn = document.getElementById('report-filter-reset-btn');
    const reportDownloadFilteredBtn = document.getElementById('report-download-filtered-btn');

    if (reportFilterPentester) reportFilterPentester.addEventListener('change', applyReportFilters);
    if (reportFilterScanType) reportFilterScanType.addEventListener('change', applyReportFilters);
    if (reportFilterDate) reportFilterDate.addEventListener('change', applyReportFilters);
    if (reportFilterMonth) reportFilterMonth.addEventListener('change', applyReportFilters);
    if (reportFilterResetBtn) reportFilterResetBtn.addEventListener('click', resetReportFilters);
    if (reportDownloadFilteredBtn) reportDownloadFilteredBtn.addEventListener('click', downloadFilteredReports);

    // Auto-refresh every 30 seconds
    setInterval(() => {
        const activeSection = document.querySelector('.section.active');
        if (activeSection) {
            const sectionId = activeSection.id.replace('-section', '');
            if (sectionId === 'history') {
                loadHistory();
            } else if (sectionId === 'reports') {
                loadReports();
            }
        }
    }, 30000);

    async function loadHistory() {
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            updateHistoryTable(history.scans);
        } catch (error) {
            console.error('Error loading history:', error);
        }
    }

    async function loadReports() {
        try {
            const response = await fetch('/api/reports');
            const reports = await response.json();
            updateReportsSection(reports);
        } catch (error) {
            console.error('Error loading reports:', error);
        }
    }

    function updateHistoryTable(scans) {
        const historyTable = document.getElementById('history-table');
        if (!historyTable) return;

        if (scans.length === 0) {
            historyTable.innerHTML = '<tr><td colspan="5" class="text-muted text-center">No scan history available</td></tr>';
            return;
        }

        historyTable.innerHTML = scans.map(scan => {
            const statusClass = scan.status === 'Completed' ? 'success' : 
                               scan.status === 'Failed' ? 'error' : 'warning';
            const startTime = new Date(scan.startTime).toLocaleString();
            
            return `
                <tr>
                    <td>${startTime}</td>
                    <td><span class="terminal-text">${scan.target}</span></td>
                    <td><code>${scan.scanType}</code></td>
                    <td><span class="status-indicator ${statusClass}"></span>${scan.status}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="viewScanDetails('${scan.id}')">
                            <i class="fas fa-eye"></i> Details
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteScan('${scan.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function updateReportsSection(reports) {
        const reportsList = document.getElementById('reports-list');
        if (!reportsList) return;

        if (reports.length === 0) {
            reportsList.innerHTML = '<div class="text-muted">No reports generated yet.</div>';
            return;
        }

        reportsList.innerHTML = reports.map(report => {
            const created = new Date(report.created).toLocaleString();
            const sizeKB = Math.round(report.size / 1024);
            const reportType = report.type || report.format || 'Unknown';
            const target = report.target || 'Unknown Target';

            let iconClass = 'fa-file-alt';
            if (reportType.toLowerCase() === 'pdf') {
                iconClass = 'fa-file-pdf text-danger';
            } else if (reportType.toLowerCase() === 'html') {
                iconClass = 'fa-file-code text-primary';
            } else if (reportType.toLowerCase() === 'txt') {
                iconClass = 'fa-file-text text-secondary';
            }

            return `
                <div class="card mb-3 shadow-sm report-card" data-pentester="${report.pentester || ''}" data-scan-type="${report.scanType || ''}" data-created="${report.created || ''}">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <h6 class="card-title mb-1">
                                    <i class="fas ${iconClass} me-2"></i> ${report.filename}
                                </h6>
                                <p class="card-text mb-2">
                                    <small class="text-muted">
                                        Target: <span class="terminal-text">${target}</span> |
                                        Format: <span class="badge bg-secondary">${reportType}</span> |
                                        Scan: <span class="badge bg-primary">${report.scanType || 'Network Scan'}</span> |
                                        Size: <strong>${sizeKB} KB</strong><br>
                                        Created: ${created}
                                    </small>
                                </p>
                                <p class="card-text mb-0">
                                    <small class="text-info"><i class="fas fa-user-shield"></i> By: <strong>${report.pentester || 'Security Analyst'}</strong></small>
                                </p>
                            </div>
                            <div class="col-md-4 text-end">
                                <button class="btn btn-primary btn-sm me-1" onclick="viewReport('${report.filename}')" title="View Report">
                                    <i class="fas fa-eye"></i> View
                                </button>
                                <button class="btn btn-success btn-sm" onclick="downloadReportFile('${report.filename}')" title="Download Report">
                                    <i class="fas fa-download"></i> Download
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        populateReportFilters(reports);
    }

    function populateReportFilters(reports) {
        const pentesterSelect = document.getElementById('report-filter-pentester');
        const scanTypeSelect = document.getElementById('report-filter-scan-type');

        if (!pentesterSelect || !scanTypeSelect) return;

        // Get unique pentesters and scan types from the reports data
        const pentesters = [...new Set(reports.map(r => r.pentester).filter(p => p && p !== ''))];
        const scanTypes = [...new Set(reports.map(r => r.scanType).filter(s => s && s !== ''))];

        // Store current selections to restore them if they still exist
        const currentPentester = pentesterSelect.value;
        const currentScanType = scanTypeSelect.value;

        pentesterSelect.innerHTML = '<option value="">All pentesters</option>';
        pentesters.sort().forEach(p => {
            const selected = (p === currentPentester) ? 'selected' : '';
            pentesterSelect.innerHTML += `<option value="${p}" ${selected}>${p}</option>`;
        });

        scanTypeSelect.innerHTML = '<option value="">All scan types</option>';
        scanTypes.sort().forEach(s => {
            const selected = (s === currentScanType) ? 'selected' : '';
            scanTypeSelect.innerHTML += `<option value="${s}" ${selected}>${s}</option>`;
        });
    }

    function applyReportFilters() {
        const pentesterFilter = document.getElementById('report-filter-pentester')?.value || '';
        const scanTypeFilter = document.getElementById('report-filter-scan-type')?.value || '';
        const dateFilter = document.getElementById('report-filter-date')?.value || '';
        const monthFilter = document.getElementById('report-filter-month')?.value || '';

        const reportCards = document.querySelectorAll('.report-card');
        let visibleCount = 0;

        reportCards.forEach(card => {
            const cardPentester = card.getAttribute('data-pentester') || '';
            const cardScanType = card.getAttribute('data-scan-type') || '';
            const cardCreated = card.getAttribute('data-created') || '';

            let show = true;

            if (pentesterFilter && cardPentester !== pentesterFilter) {
                show = false;
            }

            if (scanTypeFilter && cardScanType !== scanTypeFilter) {
                show = false;
            }

            if (dateFilter) {
                const filterDate = new Date(dateFilter).toDateString();
                const cardDate = new Date(cardCreated).toDateString();
                if (filterDate !== cardDate) {
                    show = false;
                }
            }

            if (monthFilter) {
                const cardMonth = new Date(cardCreated).getMonth() + 1;
                if (parseInt(monthFilter) !== cardMonth) {
                    show = false;
                }
            }

            card.style.display = show ? '' : 'none';
            if (show) visibleCount++;
        });

        const filteredCountEl = document.getElementById('reports-filtered-count');
        if (filteredCountEl) {
            filteredCountEl.textContent = `${visibleCount} shown`;
        }
    }

    function resetReportFilters() {
        const pentesterSelect = document.getElementById('report-filter-pentester');
        const scanTypeSelect = document.getElementById('report-filter-scan-type');
        const dateFilter = document.getElementById('report-filter-date');
        const monthFilter = document.getElementById('report-filter-month');

        if (pentesterSelect) pentesterSelect.value = '';
        if (scanTypeSelect) scanTypeSelect.value = '';
        if (dateFilter) dateFilter.value = '';
        if (monthFilter) monthFilter.value = '';

        document.querySelectorAll('.report-card').forEach(card => {
            card.style.display = '';
        });

        const filteredCountEl = document.getElementById('reports-filtered-count');
        if (filteredCountEl) {
            const totalCards = document.querySelectorAll('.report-card').length;
            filteredCountEl.textContent = `${totalCards} shown`;
        }

        showNotification('Report filters have been reset', 'info');
    }

    function downloadFilteredReports() {
        const visibleCards = document.querySelectorAll('.report-card:not([style*="display: none"])');
        const visibleReports = [];

        visibleCards.forEach(card => {
            const filename = card.querySelector('.card-title')?.textContent?.trim() || '';
            if (filename) {
                visibleReports.push(filename);
            }
        });

        if (visibleReports.length === 0) {
            showNotification('No reports to download', 'warning');
            return;
        }

        if (visibleReports.length === 1) {
            downloadReportFile(visibleReports[0]);
        } else {
            showNotification(`Downloading ${visibleReports.length} reports...`, 'info');
            visibleReports.forEach((filename, index) => {
                setTimeout(() => {
                    downloadReportFile(filename);
                }, index * 500);
            });
        }
    }

    async function viewReport(filename) {
        try {
            window.open(`/api/reports/${filename}`, '_blank');
        } catch (error) {
            console.error('Error viewing report:', error);
            alert('Error opening report');
        }
    }

    async function downloadReportFile(filename) {
        try {
            const link = document.createElement('a');
            link.href = `/api/reports/${filename}`;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (error) {
            console.error('Error downloading report:', error);
            alert('Error downloading report');
        }
    }

    async function deleteScan(scanId) {
        if (!confirm('Are you sure you want to delete this scan record?')) {
            return;
        }

        try {
            const response = await fetch(`/api/history/scans/${scanId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                loadHistory(); // Refresh the history table
            } else {
                alert('Error deleting scan record');
            }
        } catch (error) {
            console.error('Error deleting scan:', error);
            alert('Error deleting scan record');
        }
    }

    function viewScanDetails(scanId) {
        // You can implement a modal or detailed view here
        console.log('View details for scan:', scanId);
        alert(`Scan details view for ${scanId} - This could open a detailed modal!`);
    }

    // Enhanced download report function
    function downloadReport() {
        const content = outputContainer.textContent || 'No scan data available';
        const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `quick-scan-${timestamp}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    // VirusTotal PDF download function
    async function downloadVirusTotalPDF() {
        if (!lastVirusTotalResult) {
            alert('No VirusTotal scan results available to download');
            return;
        }

        try {
            const response = await fetch('/api/virustotal/generate-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(lastVirusTotalResult)
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `virustotal-report-${Date.now()}.pdf`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                showNotification('VirusTotal PDF report downloaded successfully!', 'success');
            } else {
                throw new Error('Failed to generate PDF report');
            }
        } catch (error) {
            console.error('Error downloading VirusTotal PDF:', error);
            alert('Error generating PDF report: ' + error.message);
        }
    }

    // View raw VirusTotal data function
    function viewRawVirusTotalData() {
        if (!lastVirusTotalResult) {
            alert('No VirusTotal scan results available');
            return;
        }

        const modalHtml = `
            <div class="modal fade" id="rawDataModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Raw VirusTotal Data</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="bg-dark text-light p-3 rounded" style="max-height: 500px; overflow-y: auto;">
                                <pre style="color: #00ff00; font-size: 12px;">${JSON.stringify(lastVirusTotalResult.data, null, 2)}</pre>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-primary" onclick="copyRawData()">Copy to Clipboard</button>
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Remove any existing modal
        const existingModal = document.getElementById('rawDataModal');
        if (existingModal) {
            existingModal.remove();
        }

        // Add modal to DOM
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('rawDataModal'));
        modal.show();
    }

    // Copy raw data to clipboard
    function copyRawData() {
        if (!lastVirusTotalResult) return;
        
        const data = JSON.stringify(lastVirusTotalResult.data, null, 2);
        navigator.clipboard.writeText(data).then(() => {
            showNotification('Raw data copied to clipboard!', 'success');
        }).catch(() => {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = data;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            showNotification('Raw data copied to clipboard!', 'success');
        });
    }

    // ============ IDS/THREAT HUNTER FUNCTIONALITY ============
    
    // Load supported algorithms and setup crypto forms
    async function loadSupportedAlgorithms() {
        try {
            const response = await fetch('/api/crypto/algorithms');
            supportedAlgorithms = await response.json();
            updateAlgorithmOptions();
        } catch (error) {
            console.error('Error loading supported algorithms:', error);
        }
    }
    
    function updateAlgorithmOptions() {
        const encryptSelect = document.getElementById('encrypt-algorithm');
        const decryptSelect = document.getElementById('decrypt-algorithm');
        
        if (encryptSelect && decryptSelect && supportedAlgorithms.length > 0) {
            const options = supportedAlgorithms.map(alg => 
                `<option value="${alg.name}">${alg.displayName} - ${alg.description}</option>`
            ).join('');
            
            encryptSelect.innerHTML = options;
            decryptSelect.innerHTML = options;
        }
    }
    
    // Enhanced encryption with backend API
    if (encryptForm) {
        encryptForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const algorithm = encryptForm['encrypt-algorithm'].value;
            const key = encryptForm['encrypt-key'].value;
            const text = encryptForm['plaintext'].value;
            
            if (!text || !key) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('warning', 'Please enter both text and key'));
                return;
            }
            
            try {
                const response = await fetch('/api/crypto/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ algorithm, text, key })
                });
                
                const result = await response.json();
                if (response.ok) {
                    cryptoResult.innerHTML = '';
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'alert alert-success';
                    resultDiv.innerHTML = `
                        <h6><i class="fas fa-lock me-2"></i>Encryption Result (${result.algorithm.toUpperCase()})</h6>
                        <div class="mb-2">
                            <label class="form-label small">Encrypted Data:</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="encrypt-result" value="${result.encrypted}" readonly>
                                <button class="btn btn-outline-secondary" onclick="copyToClipboard('encrypt-result')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        <div class="mb-2">
                            <label class="form-label small">IV (Initialization Vector):</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="encrypt-iv" value="${result.iv}" readonly>
                                <button class="btn btn-outline-secondary" onclick="copyToClipboard('encrypt-iv')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        ${result.authTag ? `
                        <div class="mb-2">
                            <label class="form-label small">Auth Tag (GCM):</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="encrypt-authtag" value="${result.authTag}" readonly>
                                <button class="btn btn-outline-secondary" onclick="copyToClipboard('encrypt-authtag')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        ` : ''}
                        <small class="text-muted">
                            <i class="fas fa-info-circle me-1"></i>
                            Save both the encrypted data and IV for decryption
                        </small>
                    `;
                    cryptoResult.appendChild(resultDiv);
                } else {
                    cryptoResult.innerHTML = '';
                    cryptoResult.appendChild(showResult('danger', `Encryption failed: ${result.error}`));
                }
            } catch (error) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('danger', 'Encryption failed: ' + error.message));
            }
        });
    }
    
    // Enhanced decryption with backend API
    if (decryptForm) {
        decryptForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const algorithm = decryptForm['decrypt-algorithm'].value;
            const key = decryptForm['decrypt-key'].value;
            const ciphertextInput = decryptForm['ciphertext'].value;
            
            if (!ciphertextInput || !key) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('warning', 'Please enter both ciphertext and key'));
                return;
            }
            
            let encryptedData;
            try {
                // Try to parse as JSON first (full encryption object)
                encryptedData = JSON.parse(ciphertextInput);
            } catch (e) {
                // If not JSON, treat as plain encrypted string
                encryptedData = ciphertextInput;
            }
            
            try {
                const response = await fetch('/api/crypto/decrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ algorithm, encryptedData, key })
                });
                
                const result = await response.json();
                if (response.ok) {
                    cryptoResult.innerHTML = '';
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'alert alert-info';
                    resultDiv.innerHTML = `
                        <h6><i class="fas fa-unlock me-2"></i>Decryption Result</h6>
                        <div class="input-group">
                            <input type="text" class="form-control" id="decrypt-result" value="${result.decrypted}" readonly>
                            <button class="btn btn-outline-secondary" onclick="copyToClipboard('decrypt-result')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <small class="text-muted mt-2 d-block">
                            <i class="fas fa-check-circle me-1 text-success"></i>
                            Successfully decrypted using ${algorithm.toUpperCase()}
                        </small>
                    `;
                    cryptoResult.appendChild(resultDiv);
                } else {
                    cryptoResult.innerHTML = '';
                    cryptoResult.appendChild(showResult('danger', `Decryption failed: ${result.error}`));
                }
            } catch (error) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('danger', 'Decryption failed: ' + error.message));
            }
        });
    }


    
    // IDS Control Functions
    async function startIDSMonitoring() {
        try {
            const response = await fetch('/api/ids/start', { method: 'POST' });
            const result = await response.json();
            
            if (result.success) {
                idsLive = true;
                idsStatusBadge.textContent = 'RUNNING';
                idsStatusBadge.className = 'badge bg-success';
                idsStartBtn.style.display = 'none';
                idsStopBtn.style.display = 'block';
                showNotification('IDS monitoring started successfully', 'success');
                refreshIDSData();
            } else {
                showNotification('Failed to start IDS: ' + result.message, 'error');
            }
        } catch (error) {
            console.error('Error starting IDS:', error);
            showNotification('Error starting IDS monitoring', 'error');
        }
    }
    
    async function stopIDSMonitoring() {
        try {
            const response = await fetch('/api/ids/stop', { method: 'POST' });
            const result = await response.json();
            
            if (result.success) {
                idsLive = false;
                idsStatusBadge.textContent = 'STOPPED';
                idsStatusBadge.className = 'badge bg-secondary';
                idsStartBtn.style.display = 'block';
                idsStopBtn.style.display = 'none';
                showNotification('IDS monitoring stopped', 'info');
            } else {
                showNotification('Failed to stop IDS: ' + result.message, 'error');
            }
        } catch (error) {
            console.error('Error stopping IDS:', error);
            showNotification('Error stopping IDS monitoring', 'error');
        }
    }
    
    async function refreshIDSData() {
        try {
            // Get system health
            const healthResponse = await fetch('/api/ids/status');
            const health = await healthResponse.json();
            updateSystemHealth(health);
            
            // Get statistics
            const statsResponse = await fetch('/api/ids/statistics');
            const stats = await statsResponse.json();
            updateThreatStatistics(stats);
            
            // Get recent threats
            const threatsResponse = await fetch('/api/ids/threats?limit=20');
            const threats = await threatsResponse.json();
            updateThreatsDisplay(threats);
            
            // Always refresh endpoint data when refreshing IDS data
            await refreshEndpointProtectorData();
        } catch (error) {
            console.error('[Frontend] Error refreshing IDS data:', error);
            showNotification('Failed to refresh data', 'error');
        }
    }
    
    function updateSystemHealth(health) {
        // Update connection status
        const healthStatusEl = document.getElementById('health-status');
        if (healthStatusEl) {
            healthStatusEl.textContent = 'Connected';
            healthStatusEl.className = 'badge bg-success';
        }
        
        // Update last update time
        const uptimeEl = document.getElementById('health-uptime');
        if (uptimeEl) {
            uptimeEl.textContent = new Date().toLocaleTimeString();
        }
        
        // Update endpoint counts if available
        if (endpointOverview) {
            const totalEl = document.getElementById('endpoint-total');
            const onlineEl = document.getElementById('endpoint-online');
            if (totalEl) totalEl.textContent = endpointOverview.total || 0;
            if (onlineEl) onlineEl.textContent = endpointOverview.online || 0;
        }
    }
    
    function updateThreatStatistics(stats) {
        document.getElementById('stats-total').textContent = stats.total_threats || 0;
        document.getElementById('stats-24h').textContent = stats.threats_24h || 0;
        
        const severityDist = stats.severity_distribution || {};
        document.getElementById('stats-critical').textContent = severityDist.CRITICAL || 0;
        document.getElementById('stats-high').textContent = severityDist.HIGH || 0;
        document.getElementById('stats-medium').textContent = severityDist.MEDIUM || 0;
    }
    
    function updateThreatsDisplay(threats) {
        if (!threatsContainer) return;
        
        if (threats.length === 0) {
            threatsContainer.innerHTML = '<div class="text-muted text-center">No threats detected</div>';
            return;
        }
        
        const threatsHtml = threats.map(threat => {
            const severityClass = getSeverityClass(threat.severity);
            const timeAgo = getTimeAgo(threat.detected_at);
            const statusBadge = getStatusBadge(threat.status || 'ACTIVE');
            
            return `
                <div class="card mb-2 border-${severityClass}">
                    <div class="card-header bg-light py-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-0 text-${severityClass}">
                                    <i class="fas fa-exclamation-triangle me-1"></i>
                                    ${threat.severity} - ${threat.type.toUpperCase()}
                                    ${statusBadge}
                                </h6>
                            </div>
                            <div class="btn-group" role="group">
                                <button type="button" class="btn btn-sm btn-outline-info" 
                                        onclick="viewThreatDetails('${threat.id}')" title="View Details">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                                <button type="button" class="btn btn-sm btn-outline-success" 
                                        onclick="markAsValidThreat('${threat.id}')" title="Mark as Valid Threat">
                                    <i class="fas fa-check-circle"></i>
                                </button>
                                <button type="button" class="btn btn-sm btn-outline-warning" 
                                        onclick="markAsFalsePositive('${threat.id}')" title="Mark as False Positive">
                                    <i class="fas fa-times-circle"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="card-body py-2">
                        <p class="mb-2">${threat.description}</p>
                        <div class="row text-muted small">
                            <div class="col-md-4">
                                <strong>Source:</strong> ${threat.source}
                            </div>
                            <div class="col-md-4">
                                <strong>Time:</strong> ${timeAgo}
                            </div>
                            <div class="col-md-4">
                                <strong>ID:</strong> ${threat.id.substr(0, 12)}...
                            </div>
                        </div>
                        ${threat.details ? `
                        <div class="mt-2">
                            <button class="btn btn-sm btn-outline-secondary" type="button" 
                                    data-bs-toggle="collapse" data-bs-target="#details-${threat.id.substr(0, 8)}"
                                    aria-expanded="false">
                                <i class="fas fa-chevron-down"></i> Show Technical Details
                            </button>
                            <div class="collapse mt-2" id="details-${threat.id.substr(0, 8)}">
                                <div class="card card-body bg-light small">
                                    <pre class="mb-0">${JSON.stringify(threat.details, null, 2)}</pre>
                                </div>
                            </div>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');
        
        threatsContainer.innerHTML = threatsHtml;
    }
    
    function getStatusBadge(status) {
        switch (status) {
            case 'ACTIVE': return '<span class="badge bg-danger ms-2">ACTIVE</span>';
            case 'RESOLVED': return '<span class="badge bg-success ms-2">RESOLVED</span>';
            case 'FALSE_POSITIVE': return '<span class="badge bg-warning text-dark ms-2">FALSE POSITIVE</span>';
            case 'VALID_THREAT': return '<span class="badge bg-danger ms-2">CONFIRMED THREAT</span>';
            default: return '<span class="badge bg-secondary ms-2">UNKNOWN</span>';
        }
    }
    
    async function viewThreatDetails(threatId) {
        try {
            const response = await fetch(`/api/ids/threats?limit=100`);
            const threats = await response.json();
            const threat = threats.find(t => t.id === threatId);
            
            if (!threat) {
                showNotification('Threat not found', 'error');
                return;
            }
            
            const modalHtml = `
                <div class="modal fade" id="threatDetailsModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">
                                    <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                    Threat Analysis - ${threat.severity}
                                </h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <strong>Threat ID:</strong><br>
                                        <code>${threat.id}</code>
                                    </div>
                                    <div class="col-md-6">
                                        <strong>Detection Time:</strong><br>
                                        ${new Date(threat.detected_at).toLocaleString()}
                                    </div>
                                </div>
                                
                                <div class="row mb-3">
                                    <div class="col-md-4">
                                        <strong>Severity:</strong><br>
                                        <span class="badge bg-${getSeverityClass(threat.severity)} text-white">
                                            ${threat.severity}
                                        </span>
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Type:</strong><br>
                                        <span class="badge bg-info text-white">${threat.type}</span>
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Source:</strong><br>
                                        ${threat.source}
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <strong>Description:</strong><br>
                                    <div class="alert alert-info">${threat.description}</div>
                                </div>
                                
                                ${threat.details ? `
                                <div class="mb-3">
                                    <strong>Technical Details:</strong>
                                    <div class="bg-light p-3 rounded" style="max-height: 300px; overflow-y: auto;">
                                        <pre class="mb-0 small">${JSON.stringify(threat.details, null, 2)}</pre>
                                    </div>
                                </div>
                                ` : ''}
                                
                                <div class="mb-3">
                                    <strong>Analysis & Recommendations:</strong>
                                    <div class="card">
                                        <div class="card-body">
                                            <h6>Risk Assessment:</h6>
                                            <p>${getAnalysisRecommendation(threat)}</p>
                                            
                                            <h6>Next Steps:</h6>
                                            <ul>
                                                ${getActionItems(threat).map(item => `<li>${item}</li>`).join('')}
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <strong>Verification Status:</strong><br>
                                    <div class="btn-group" role="group">
                                        <button type="button" class="btn btn-success" 
                                                onclick="markAsValidThreat('${threat.id}'); bootstrap.Modal.getInstance(document.getElementById('threatDetailsModal')).hide();">
                                            <i class="fas fa-check-circle"></i> Confirm as Valid Threat
                                        </button>
                                        <button type="button" class="btn btn-warning" 
                                                onclick="markAsFalsePositive('${threat.id}'); bootstrap.Modal.getInstance(document.getElementById('threatDetailsModal')).hide();">
                                            <i class="fas fa-times-circle"></i> Mark as False Positive
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal
            const existingModal = document.getElementById('threatDetailsModal');
            if (existingModal) existingModal.remove();
            
            // Add modal to DOM and show
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            const modal = new bootstrap.Modal(document.getElementById('threatDetailsModal'));
            modal.show();
            
        } catch (error) {
            console.error('Error loading threat details:', error);
            showNotification('Error loading threat details', 'error');
        }
    }
    
    function getAnalysisRecommendation(threat) {
        switch (threat.severity) {
            case 'CRITICAL':
                return 'This is a critical threat that requires immediate attention. Potential for significant system compromise or data breach.';
            case 'HIGH':
                return 'High-priority threat that should be investigated promptly. May indicate ongoing attack or system vulnerability.';
            case 'MEDIUM':
                return 'Medium-level threat requiring analysis. Could be part of reconnaissance or early attack phase.';
            default:
                return 'Low-level threat that should be monitored. May be benign but worth tracking for patterns.';
        }
    }
    
    function getActionItems(threat) {
        const baseActions = ['Review system logs for related activities', 'Check network traffic patterns', 'Verify system integrity'];
        
        switch (threat.type) {
            case 'network':
                return [...baseActions, 'Analyze network connections', 'Check firewall rules', 'Review network segmentation'];
            case 'process':
                return [...baseActions, 'Investigate process origins', 'Check process signatures', 'Review system startup items'];
            case 'file':
                return [...baseActions, 'Scan files with antivirus', 'Check file permissions', 'Review recent file changes'];
            default:
                return [...baseActions, 'Conduct deeper investigation', 'Consult security team'];
        }
    }
    
    async function markAsValidThreat(threatId) {
        await updateThreatStatus(threatId, 'VALID_THREAT', 'Confirmed as valid threat by security analyst');
    }
    
    async function markAsFalsePositive(threatId) {
        await updateThreatStatus(threatId, 'FALSE_POSITIVE', 'Marked as false positive by security analyst');
    }
    
    function getSeverityClass(severity) {
        switch (severity) {
            case 'CRITICAL': return 'danger';
            case 'HIGH': return 'warning';
            case 'MEDIUM': return 'info';
            default: return 'secondary';
        }
    }
    
    function getTimeAgo(timestamp) {
        const now = new Date();
        const past = new Date(timestamp);
        const diffMs = now - past;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        
        if (diffMins < 1) return 'just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        return past.toLocaleDateString();
    }
    
    function formatUptime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        if (hours > 0) return `${hours}h ${minutes}m`;
        if (minutes > 0) return `${minutes}m ${secs}s`;
        return `${secs}s`;
    }
    
    async function updateThreatStatus(threatId, status, resolution = 'Manually resolved by user') {
        try {
            const response = await fetch(`/api/ids/threats/${threatId}/update`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status, resolution })
            });
            
            if (response.ok) {
                showNotification('Threat status updated', 'success');
                refreshIDSData(); // Refresh the display
            } else {
                showNotification('Failed to update threat status', 'error');
            }
        } catch (error) {
            console.error('Error updating threat status:', error);
            showNotification('Error updating threat status', 'error');
        }
    }
    
    async function generateIDSReport() {
        try {
            // Show modal for report options
            showReportOptionsModal();
        } catch (error) {
            console.error('Error generating IDS report:', error);
            showNotification('Error generating IDS report', 'error');
        }
    }
    
    function showReportOptionsModal() {
        const modalHtml = `
            <div class="modal fade" id="reportOptionsModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-file-alt me-2"></i>
                                Generate IDS Security Report
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <form id="reportOptionsForm">
                                <div class="mb-3">
                                    <label for="reportFormat" class="form-label">Report Format</label>
                                    <select class="form-select" id="reportFormat" required>
                                        <option value="pdf">PDF - Professional Report</option>
                                        <option value="html">HTML - Web Report</option>
                                        <option value="txt">TXT - Plain Text</option>
                                        <option value="json">JSON - Raw Data</option>
                                    </select>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="auditorName" class="form-label">Security Analyst/Auditor Name</label>
                                    <input type="text" class="form-control" id="auditorName" 
                                           placeholder="Enter your name" value="Security Analyst">
                                </div>
                                
                                <div class="mb-3">
                                    <label for="organizationName" class="form-label">Organization</label>
                                    <input type="text" class="form-control" id="organizationName" 
                                           placeholder="Organization name (optional)">
                                </div>
                                
                                <div class="mb-3">
                                    <label for="reportTimeframe" class="form-label">Report Timeframe</label>
                                    <select class="form-select" id="reportTimeframe">
                                        <option value="24h">Last 24 Hours</option>
                                        <option value="7d">Last 7 Days</option>
                                        <option value="30d">Last 30 Days</option>
                                        <option value="all">All Available Data</option>
                                    </select>
                                </div>
                                
                                <div class="mb-3">
                                    <label class="form-label">Include Sections</label>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="includeSummary" checked>
                                        <label class="form-check-label" for="includeSummary">Executive Summary</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="includeThreats" checked>
                                        <label class="form-check-label" for="includeThreats">Threat Analysis</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="includeStatistics" checked>
                                        <label class="form-check-label" for="includeStatistics">Security Statistics</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="includeRecommendations" checked>
                                        <label class="form-check-label" for="includeRecommendations">Recommendations</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="includeLogs">
                                        <label class="form-check-label" for="includeLogs">System Logs</label>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="reportNotes" class="form-label">Additional Notes</label>
                                    <textarea class="form-control" id="reportNotes" rows="3" 
                                              placeholder="Any additional notes or observations..."></textarea>
                                </div>
                            </form>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" onclick="generateCustomReport()">Generate Report</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal
        const existingModal = document.getElementById('reportOptionsModal');
        if (existingModal) existingModal.remove();
        
        // Add modal to DOM and show
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('reportOptionsModal'));
        modal.show();
    }
    
    async function generateCustomReport() {
        const form = document.getElementById('reportOptionsForm');
        const formData = new FormData(form);
        
        const reportOptions = {
            format: document.getElementById('reportFormat').value,
            auditorName: document.getElementById('auditorName').value || 'Security Analyst',
            organizationName: document.getElementById('organizationName').value,
            timeframe: document.getElementById('reportTimeframe').value,
            notes: document.getElementById('reportNotes').value,
            includeSections: {
                summary: document.getElementById('includeSummary').checked,
                threats: document.getElementById('includeThreats').checked,
                statistics: document.getElementById('includeStatistics').checked,
                recommendations: document.getElementById('includeRecommendations').checked,
                logs: document.getElementById('includeLogs').checked
            },
            timestamp: new Date().toISOString()
        };
        
        try {
            // Show loading notification
            showNotification('Generating professional report...', 'info');
            
            const response = await fetch('/api/ids/generate-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reportOptions)
            });
            
            if (response.ok) {
                const contentType = response.headers.get('content-type');
                
                if (contentType && contentType.includes('application/json')) {
                    // JSON response with filename
                    const result = await response.json();
                    showNotification(`Professional report generated: ${result.filename}`, 'success');
                    
                    // Optionally download the file
                    if (result.downloadUrl) {
                        const link = document.createElement('a');
                        link.href = result.downloadUrl;
                        link.download = result.filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                    }
                } else {
                    // Direct file download
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    
                    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
                    let filename = `ids-security-report-${timestamp}`;
                    
                    switch (reportOptions.format) {
                        case 'pdf': filename += '.pdf'; break;
                        case 'html': filename += '.html'; break;
                        case 'txt': filename += '.txt'; break;
                        default: filename += '.json'; break;
                    }
                    
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    
                    showNotification(`Professional ${reportOptions.format.toUpperCase()} report downloaded successfully!`, 'success');
                }
                
                // Close the modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('reportOptionsModal'));
                if (modal) modal.hide();
                
                // Refresh reports list
                loadReports();
                
            } else {
                const error = await response.json();
                throw new Error(error.message || 'Failed to generate report');
            }
        } catch (error) {
            console.error('Error generating custom report:', error);
            showNotification('Error generating report: ' + error.message, 'error');
        }
    }
    
    function clearThreats() {
        if (threatsContainer) {
            threatsContainer.innerHTML = '<div class="text-muted text-center">No threats detected</div>';
        }
    }
    
    function clearLogs() {
        if (idsLogs) {
            idsLogs.innerHTML = '<div class="text-muted">IDS logs will appear here...</div>';
        }
    }
    
    function addLogEntry(logEntry) {
        if (!idsLogs) return;
        
        const logDiv = document.createElement('div');
        const levelClass = logEntry.level === 'ERROR' ? 'text-danger' : 
                          logEntry.level === 'WARN' ? 'text-warning' : 'text-info';
        
        logDiv.innerHTML = `
            <div class="border-bottom pb-1 mb-1">
                <small class="${levelClass}">
                    [${new Date(logEntry.timestamp).toLocaleTimeString()}] 
                    <strong>${logEntry.level}</strong>: ${logEntry.message}
                </small>
            </div>
        `;
        
        if (idsLogs.firstChild && idsLogs.firstChild.className === 'text-muted') {
            idsLogs.innerHTML = '';
        }
        
        idsLogs.insertBefore(logDiv, idsLogs.firstChild);
        
        // Keep only last 50 log entries
        while (idsLogs.children.length > 50) {
            idsLogs.removeChild(idsLogs.lastChild);
        }
    }
    
    // WebSocket event handlers for IDS
    socket.on('ids-threat', (threat) => {
        idsThreats.unshift(threat);
        if (idsThreats.length > 100) idsThreats = idsThreats.slice(0, 100);
        
        if (document.querySelector('.section.active')?.id === 'ids-section') {
            updateThreatsDisplay(idsThreats.slice(0, 20));
        }
        
        showNotification(`New ${threat.severity} threat detected: ${threat.description}`, 'warning');
    });
    
    socket.on('ids-alert', (alert) => {
        showNotification(`Security Alert: ${alert.message}`, 'danger');
        addLogEntry({
            timestamp: alert.timestamp,
            level: 'ALERT',
            message: alert.message
        });
    });
    
    socket.on('ids-log', (logEntry) => {
        addLogEntry(logEntry);
    });
    
    // Event listeners for IDS controls
    if (idsStartBtn) {
        idsStartBtn.addEventListener('click', startIDSMonitoring);
    }
    
    if (idsStopBtn) {
        idsStopBtn.addEventListener('click', stopIDSMonitoring);
    }
    
    if (idsRefreshBtn) {
        idsRefreshBtn.addEventListener('click', async () => {
            idsRefreshBtn.disabled = true;
            const originalHtml = idsRefreshBtn.innerHTML;
            idsRefreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Refreshing...';
            try {
                await refreshEndpointProtectorData();
                socket.emit('endpoint-protector:get-overview');
                socket.emit('endpoint-protector:get-agents');
                socket.emit('endpoint-protector:get-alerts');
                showNotification('Endpoint data refreshed', 'success');
            } catch (error) {
                console.error('[Frontend] Refresh error:', error);
                showNotification('Failed to refresh data', 'error');
            } finally {
                idsRefreshBtn.disabled = false;
                idsRefreshBtn.innerHTML = originalHtml;
            }
        });
    }
    
    // Initialize data on page load
    loadSupportedAlgorithms();
    refreshIDSData();
    
    // Auto-refresh IDS data every 30 seconds
    setInterval(() => {
        if (document.querySelector('.section.active')?.id === 'ids-section') {
            refreshIDSData();
        }
    }, 30000);
    
    // ============ VIRUSTOTAL HELPER FUNCTIONS ============
    
    function formatFileSize(bytes) {
        if (!bytes || bytes === 0) return 'Unknown';
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }
    
    function extractDomain(url) {
        if (!url) return 'N/A';
        try {
            return new URL(url).hostname;
        } catch {
            return 'Invalid URL';
        }
    }
    
    function calculateRiskLevel(stats) {
        const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0 } = stats;
        const total = malicious + suspicious + harmless + undetected;
        
        if (total === 0) return 'UNKNOWN';
        
        const threatRatio = (malicious + suspicious) / total;
        
        if (threatRatio > 0.3) return 'VERY_HIGH';
        if (threatRatio > 0.15) return 'HIGH';
        if (threatRatio > 0.05) return 'MEDIUM';
        if (threatRatio > 0) return 'LOW';
        return 'VERY_LOW';
    }
    
    function getRiskColor(riskLevel) {
        switch (riskLevel) {
            case 'VERY_HIGH': return 'danger';
            case 'HIGH': return 'danger';
            case 'MEDIUM': return 'warning';
            case 'LOW': return 'info';
            default: return 'success';
        }
    }
    
    function getRiskPercentage(riskLevel) {
        switch (riskLevel) {
            case 'VERY_HIGH': return 100;
            case 'HIGH': return 80;
            case 'MEDIUM': return 60;
            case 'LOW': return 40;
            default: return 20;
        }
    }
    
    function getReputationColor(score) {
        if (!score) return 'secondary';
        if (score >= 80) return 'success';
        if (score >= 60) return 'info';
        if (score >= 40) return 'warning';
        return 'danger';
    }
    
    function generateDetectionResults(results) {
        if (!results || Object.keys(results).length === 0) {
            return '<div class="text-muted text-center p-3">No individual engine results available</div>';
        }
        
        const engines = Object.entries(results);
        
        return engines.map(([engineName, result]) => {
            let statusClass = 'secondary';
            let statusIcon = 'fa-question';
            let statusText = 'Unknown';
            let threatName = '';
            
            if (result.category) {
                switch (result.category.toLowerCase()) {
                    case 'malicious':
                        statusClass = 'danger';
                        statusIcon = 'fa-virus';
                        statusText = 'Malicious';
                        threatName = result.result || 'Threat detected';
                        break;
                    case 'suspicious':
                        statusClass = 'warning';
                        statusIcon = 'fa-exclamation-triangle';
                        statusText = 'Suspicious';
                        threatName = result.result || 'Suspicious activity';
                        break;
                    case 'harmless':
                    case 'clean':
                        statusClass = 'success';
                        statusIcon = 'fa-shield-alt';
                        statusText = 'Clean';
                        break;
                    case 'undetected':
                        statusClass = 'secondary';
                        statusIcon = 'fa-eye-slash';
                        statusText = 'Undetected';
                        break;
                    default:
                        statusClass = 'secondary';
                        statusIcon = 'fa-question';
                        statusText = result.category;
                }
            }
            
            return `
                <div class="detection-result border rounded p-2 mb-2" data-category="${result.category || 'unknown'}">
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center">
                            <i class="fas ${statusIcon} text-${statusClass} me-2"></i>
                            <strong>${engineName}</strong>
                        </div>
                        <div class="text-end">
                            <span class="badge bg-${statusClass} me-2">${statusText}</span>
                            ${threatName ? `<small class="text-muted">${threatName}</small>` : ''}
                        </div>
                    </div>
                    ${result.version ? `<small class="text-muted">Version: ${result.version}</small>` : ''}
                    ${result.update ? `<small class="text-muted ms-2">Updated: ${result.update}</small>` : ''}
                </div>
            `;
        }).join('');
    }
    
    function filterResults(category) {
        // Update button states
        document.querySelectorAll('[data-filter]').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-filter="${category}"]`).classList.add('active');
        
        // Filter detection results
        document.querySelectorAll('.detection-result').forEach(result => {
            const resultCategory = result.dataset.category;
            
            if (category === 'all') {
                result.style.display = 'block';
            } else {
                const shouldShow = 
                    (category === 'malicious' && resultCategory === 'malicious') ||
                    (category === 'suspicious' && resultCategory === 'suspicious') ||
                    (category === 'clean' && (resultCategory === 'harmless' || resultCategory === 'clean'));
                
                result.style.display = shouldShow ? 'block' : 'none';
            }
        });
    }
    
    function showDetailedAnalysis() {
        if (!lastVirusTotalResult) {
            alert('No VirusTotal scan results available');
            return;
        }
        
        const data = lastVirusTotalResult.data;
        const attrs = data.attributes || {};
        
        const modalHtml = `
            <div class="modal fade" id="detailedAnalysisModal" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-microscope me-2"></i>
                                Detailed VirusTotal Analysis
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                            <!-- File Information -->
                            <div class="row mb-4">
                                <div class="col-md-6">
                                    <h6 class="fw-bold text-primary">File Properties</h6>
                                    <table class="table table-sm">
                                        <tbody>
                                            <tr><td>SHA256:</td><td><code class="small">${attrs.sha256 || 'N/A'}</code></td></tr>
                                            <tr><td>MD5:</td><td><code class="small">${attrs.md5 || 'N/A'}</code></td></tr>
                                            <tr><td>SHA1:</td><td><code class="small">${attrs.sha1 || 'N/A'}</code></td></tr>
                                            <tr><td>File Type:</td><td>${attrs.type_description || 'Unknown'}</td></tr>
                                            <tr><td>File Size:</td><td>${formatFileSize(attrs.size)}</td></tr>
                                            <tr><td>Magic:</td><td><code>${attrs.magic || 'N/A'}</code></td></tr>
                                        </tbody>
                                    </table>
                                </div>
                                <div class="col-md-6">
                                    <h6 class="fw-bold text-primary">Submission Details</h6>
                                    <table class="table table-sm">
                                        <tbody>
                                            <tr><td>First Seen:</td><td>${attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toLocaleString() : 'N/A'}</td></tr>
                                            <tr><td>Last Analysis:</td><td>${attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toLocaleString() : 'N/A'}</td></tr>
                                            <tr><td>Times Submitted:</td><td>${attrs.times_submitted || 'N/A'}</td></tr>
                                            <tr><td>Unique Sources:</td><td>${attrs.unique_sources || 'N/A'}</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <!-- Enhanced Threat Intelligence -->
                            ${attrs.threat_classification ? `
                            <div class="mb-4">
                                <h6 class="fw-bold text-primary">Threat Intelligence</h6>
                                <div class="alert alert-info">
                                    <div class="row">
                                        <div class="col-md-4">
                                            <strong>Threat Classification:</strong><br>
                                            <span class="badge bg-${getRiskColor(attrs.threat_classification)}">${attrs.threat_classification}</span>
                                        </div>
                                        <div class="col-md-4">
                                            <strong>Reputation Score:</strong><br>
                                            <span class="badge bg-${getReputationColor(attrs.reputation_score)}">${attrs.reputation_score || 'N/A'}/100</span>
                                        </div>
                                        <div class="col-md-4">
                                            <strong>Risk Level:</strong><br>
                                            <span class="badge bg-${getRiskColor(attrs.risk_level)}">${attrs.risk_level || 'N/A'}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            ` : ''}
                            
                            <!-- YARA Rules -->
                            ${attrs.yara_matches && attrs.yara_matches.length > 0 ? `
                            <div class="mb-4">
                                <h6 class="fw-bold text-primary">YARA Rule Matches</h6>
                                <div class="bg-light p-3 rounded">
                                    ${attrs.yara_matches.map(match => `
                                        <div class="border-bottom pb-2 mb-2">
                                            <strong>${match.rule_name || 'Unknown Rule'}</strong>
                                            ${match.description ? `<br><small class="text-muted">${match.description}</small>` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                            ` : ''}
                            
                            <!-- Behavioral Analysis -->
                            ${attrs.behavioral_analysis ? `
                            <div class="mb-4">
                                <h6 class="fw-bold text-primary">Behavioral Analysis</h6>
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="card">
                                            <div class="card-header">Network Activity</div>
                                            <div class="card-body small">
                                                ${attrs.behavioral_analysis.network_activity || 'No data available'}
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="card">
                                            <div class="card-header">File System Activity</div>
                                            <div class="card-body small">
                                                ${attrs.behavioral_analysis.file_system_activity || 'No data available'}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            ` : ''}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal
        const existingModal = document.getElementById('detailedAnalysisModal');
        if (existingModal) existingModal.remove();
        
        // Add modal to DOM and show
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('detailedAnalysisModal'));
        modal.show();
    }

    // Device Control Functions
    async function sendAgentCommand(agentId, command, params = {}) {
        try {
            const response = await fetch(`/api/endpoint-protector/agents/${agentId}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command, params })
            });
            
            const result = await response.json();
            if (response.ok) {
                showNotification(`Command "${command}" sent to agent ${agentId}`, 'success');
                // Refresh agent data after command
                setTimeout(() => {
                    refreshEndpointProtectorData();
                }, 1000);
            } else {
                // Enhanced error handling with user-friendly messages
                let errorMessage = result.error || 'Unknown error';
                if (result.showInDashboard) {
                    // Show detailed error in dashboard
                    errorMessage = result.details ? `${result.error}: ${result.details}` : result.error;
                }
                showNotification(`Failed to send command: ${errorMessage}`, 'error');
                
                // Don't mark agent as offline for connection issues
                if (!errorMessage.includes('offline') && !errorMessage.includes('unavailable')) {
                    // Refresh data to get current agent status
                    refreshEndpointProtectorData();
                }
            }
        } catch (error) {
            console.error('Error sending agent command:', error);
            showNotification('Network error sending command to agent. Check connection.', 'error');
        }
    }
    
    // Enhanced command functions with parameters
    async function blockUSBDevice(agentId) {
        if (confirm('Are you sure you want to block USB devices on this agent?')) {
            await sendAgentCommand(agentId, 'block_usb');
        }
    }
    
    async function unblockUSBDevice(agentId) {
        await sendAgentCommand(agentId, 'unblock_usb');
    }
    
    async function blockNetworkInterface(agentId, interfaceName) {
        if (!interfaceName) {
            interfaceName = prompt('Enter network interface name to block:');
            if (!interfaceName) return;
        }
        if (confirm(`Are you sure you want to block network interface "${interfaceName}"?`)) {
            await sendAgentCommand(agentId, 'block_network', { interface: interfaceName });
        }
    }
    
    async function unblockNetworkInterface(agentId, interfaceName) {
        if (!interfaceName) {
            interfaceName = prompt('Enter network interface name to unblock:');
            if (!interfaceName) return;
        }
        await sendAgentCommand(agentId, 'unblock_network', { interface: interfaceName });
    }
    
    async function blockUser(agentId, username) {
        if (!username) {
            username = prompt('Enter username to block:');
            if (!username) return;
        }
        if (confirm(`Are you sure you want to block user "${username}"?`)) {
            await sendAgentCommand(agentId, 'block_user', { username: username });
        }
    }
    
    async function unblockUser(agentId, username) {
        if (!username) {
            username = prompt('Enter username to unblock:');
            if (!username) return;
        }
        await sendAgentCommand(agentId, 'unblock_user', { username: username });
    }
    
    async function terminateProcess(agentId, pid, processName) {
        if (!pid && !processName) {
            const input = prompt('Enter process PID or name to terminate:');
            if (!input) return;
            if (/^\d+$/.test(input)) {
                pid = parseInt(input);
            } else {
                processName = input;
            }
        }
        if (confirm(`Are you sure you want to terminate ${pid ? `process ${pid}` : `process "${processName}"`}?`)) {
            await sendAgentCommand(agentId, 'terminate_process', { pid, process_name: processName });
        }
    }
    
    async function viewAgentDetails(agentId) {
        const agent = endpointAgents.get(agentId);
        if (!agent) {
            showNotification('Agent not found', 'error');
            return;
        }
        
        const telemetry = agent.telemetry || {};
        const cpu = telemetry.cpu || {};
        const mem = telemetry.memory || {};
        const processes = telemetry.processes || [];
        const network = telemetry.network || {};
        
        const modalHtml = `
            <div class="modal fade" id="agentDetailsModal" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-desktop me-2"></i>
                                Agent Details: ${agent.hostname || agent.agentId}
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                            <!-- Agent Information -->
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <h6 class="fw-bold">Agent Information</h6>
                                    <table class="table table-sm">
                                        <tr><td><strong>Agent ID:</strong></td><td><code>${agent.agentId}</code></td></tr>
                                        <tr><td><strong>Hostname:</strong></td><td>${agent.hostname || 'N/A'}</td></tr>
                                        <tr><td><strong>Platform:</strong></td><td>${agent.platform || 'N/A'}</td></tr>
                                        <tr><td><strong>IP Address:</strong></td><td>${agent.ipAddress || 'N/A'}</td></tr>
                                        <tr><td><strong>Version:</strong></td><td>${agent.version || 'N/A'}</td></tr>
                                        <tr><td><strong>Status:</strong></td><td><span class="badge bg-${agent.status === 'ONLINE' ? 'success' : 'secondary'}">${agent.status || 'OFFLINE'}</span></td></tr>
                                        <tr><td><strong>Owner:</strong></td><td>${agent.owner || 'N/A'}</td></tr>
                                        <tr><td><strong>Tags:</strong></td><td>${agent.tags && agent.tags.length > 0 ? agent.tags.map(t => `<span class="badge bg-info me-1">${t}</span>`).join('') : 'None'}</td></tr>
                                        <tr><td><strong>Registered:</strong></td><td>${new Date(agent.registeredAt).toLocaleString()}</td></tr>
                                        <tr><td><strong>Last Seen:</strong></td><td>${formatRelativeTime(agent.lastSeen)}</td></tr>
                                        <tr><td><strong>Risk Score:</strong></td><td><span class="badge bg-${agent.riskScore >= 70 ? 'danger' : agent.riskScore >= 40 ? 'warning' : 'success'}">${agent.riskScore || 0}%</span></td></tr>
                                    </table>
                                </div>
                                <div class="col-md-6">
                                    <h6 class="fw-bold">System Resources</h6>
                                    <div class="mb-3">
                                        <div class="d-flex justify-content-between mb-1">
                                            <span>CPU Usage</span>
                                            <strong>${cpu.usage || 0}%</strong>
                                        </div>
                                        <div class="progress" style="height: 20px;">
                                            <div class="progress-bar bg-${cpu.usage > 80 ? 'danger' : cpu.usage > 60 ? 'warning' : 'info'}" 
                                                 style="width: ${cpu.usage || 0}%">${cpu.usage || 0}%</div>
                                        </div>
                                        <small class="text-muted">Cores: ${cpu.cores || 'N/A'} | Model: ${cpu.model || 'N/A'}</small>
                                    </div>
                                    <div class="mb-3">
                                        <div class="d-flex justify-content-between mb-1">
                                            <span>Memory Usage</span>
                                            <strong>${mem.utilization || 0}%</strong>
                                        </div>
                                        <div class="progress" style="height: 20px;">
                                            <div class="progress-bar bg-${mem.utilization > 80 ? 'danger' : mem.utilization > 60 ? 'warning' : 'success'}" 
                                                 style="width: ${mem.utilization || 0}%">${mem.utilization || 0}%</div>
                                        </div>
                                        <small class="text-muted">
                                            Used: ${formatBytes(mem.used || 0)} | 
                                            Free: ${formatBytes(mem.free || 0)} | 
                                            Total: ${formatBytes(mem.total || 0)}
                                        </small>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Network Interfaces -->
                            ${network.interfaces && network.interfaces.length > 0 ? `
                            <div class="mb-3">
                                <h6 class="fw-bold">Network Interfaces</h6>
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>Interface</th>
                                                <th>IP Addresses</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${network.interfaces.map(iface => `
                                                <tr>
                                                    <td><code>${iface.name}</code></td>
                                                    <td>${(iface.addresses || []).join(', ') || 'N/A'}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            ` : ''}
                            
                            <!-- Processes -->
                            ${processes.length > 0 ? `
                            <div class="mb-3">
                                <h6 class="fw-bold">Running Processes (Top ${processes.length})</h6>
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th>PID</th>
                                                <th>Name</th>
                                                <th>CPU %</th>
                                                <th>Memory (MB)</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${processes.map(proc => `
                                                <tr class="${proc.suspicious ? 'table-danger' : ''}">
                                                    <td>${proc.pid || 'N/A'}</td>
                                                    <td><code>${proc.name || 'N/A'}</code></td>
                                                    <td>${proc.cpu || 0}%</td>
                                                    <td>${proc.memoryMB || 0}</td>
                                                    <td>${proc.suspicious ? '<span class="badge bg-danger">Suspicious</span>' : '<span class="badge bg-success">Normal</span>'}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            ` : ''}
                            
                            <!-- Telemetry Timestamp -->
                            <div class="text-muted small">
                                <i class="fas fa-clock me-1"></i>
                                Last telemetry update: ${telemetry.timestamp ? new Date(telemetry.timestamp).toLocaleString() : 'Never'}
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" onclick="refreshEndpointProtectorData(); bootstrap.Modal.getInstance(document.getElementById('agentDetailsModal')).hide();">
                                <i class="fas fa-sync me-1"></i>Refresh Data
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal
        const existingModal = document.getElementById('agentDetailsModal');
        if (existingModal) existingModal.remove();
        
        // Add modal to DOM and show
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('agentDetailsModal'));
        modal.show();
    }
    
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Auto-refresh endpoint data every 5 seconds when viewing Endpoint Protector section
    setInterval(() => {
        const activeSection = document.querySelector('.section.active');
        if (activeSection && activeSection.id === 'ids-section') {
            // Request fresh data via socket
            socket.emit('endpoint-protector:get-overview');
            socket.emit('endpoint-protector:get-agents');
            socket.emit('endpoint-protector:get-alerts');
        }
    }, 5000);

    // Make functions global for onclick handlers
    window.showSection = showSection;
    window.clearOutput = clearOutput;
    window.downloadReport = downloadReport;
    window.viewReport = viewReport;
    window.downloadReportFile = downloadReportFile;
    window.deleteScan = deleteScan;
    window.viewScanDetails = viewScanDetails;
    window.downloadVirusTotalPDF = downloadVirusTotalPDF;
    window.viewRawVirusTotalData = viewRawVirusTotalData;
    window.copyRawData = copyRawData;
    window.updateThreatStatus = updateThreatStatus;
    window.generateIDSReport = generateIDSReport;
    window.generateCustomReport = generateCustomReport;
    window.clearThreats = clearThreats;
    window.clearLogs = clearLogs;
    window.viewThreatDetails = viewThreatDetails;
    window.markAsValidThreat = markAsValidThreat;
    window.markAsFalsePositive = markAsFalsePositive;
    window.filterResults = filterResults;
    window.showDetailedAnalysis = showDetailedAnalysis;
    window.refreshEndpointProtectorData = refreshEndpointProtectorData;
    window.refreshWindowsEvents = refreshWindowsEvents;
    window.resetWindowsEventFilters = resetWindowsEventFilters;
    window.clearWindowsEvents = clearWindowsEvents;
    window.downloadWindowsEventsPdf = downloadWindowsEventsPdf;
    window.sendAgentCommand = sendAgentCommand;
    window.viewAgentDetails = viewAgentDetails;
    window.blockUSBDevice = blockUSBDevice;
    window.unblockUSBDevice = unblockUSBDevice;
    window.blockNetworkInterface = blockNetworkInterface;
    window.unblockNetworkInterface = unblockNetworkInterface;
    window.blockUser = blockUser;
    window.unblockUser = unblockUser;
    window.terminateProcess = terminateProcess;
    
    // ============ CRYPTO UTILITY BUTTON HANDLERS ============
    
    // Encoding/Decoding Form Handler
    const encodingForm = document.getElementById('encoding-form');
    const encodingTypeSelect = document.getElementById('encoding-type');
    const shiftInputDiv = document.getElementById('shift-input-div');
    const decodeBtn = document.getElementById('decode-btn');
    const hashBtn = document.getElementById('hash-btn');
    const generateKeyBtn = document.getElementById('generate-key-btn');
    
    // Show/hide shift input for Caesar cipher
    if (encodingTypeSelect && shiftInputDiv) {
        encodingTypeSelect.addEventListener('change', function() {
            if (this.value === 'caesar') {
                shiftInputDiv.style.display = 'block';
            } else {
                shiftInputDiv.style.display = 'none';
            }
        });
    }
    
    // Encoding form submit handler
    if (encodingForm) {
        encodingForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const encodingType = encodingForm['encoding-type'].value;
            const text = encodingForm['encode-text'].value;
            const shift = encodingForm['shift-input'] ? encodingForm['shift-input'].value : 3;
            
            if (!text) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('warning', 'Please enter text to encode'));
                return;
            }
            
            try {
                const endpoint = `/api/crypto/encode/${encodingType}`;
                const body = { text };
                if (encodingType === 'caesar') {
                    body.shift = parseInt(shift) || 3;
                }
                
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                
                const result = await response.json();
                if (response.ok) {
                    cryptoResult.innerHTML = '';
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'alert alert-success';
                    resultDiv.innerHTML = `
                        <h6><i class="fas fa-arrow-up me-2"></i>Encoded (${encodingType.toUpperCase()})</h6>
                        <div class="input-group">
                            <input type="text" class="form-control" id="encoded-result" value="${result.encoded}" readonly>
                            <button class="btn btn-outline-secondary" onclick="copyToClipboard('encoded-result')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    `;
                    cryptoResult.appendChild(resultDiv);
                } else {
                    cryptoResult.innerHTML = '';
                    cryptoResult.appendChild(showResult('danger', `Encoding failed: ${result.error}`));
                }
            } catch (error) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('danger', 'Encoding failed: ' + error.message));
            }
        });
    }
    
    // Decode button handler
    if (decodeBtn) {
        decodeBtn.addEventListener('click', async () => {
            const encodingType = document.getElementById('encoding-type').value;
            const text = document.getElementById('encode-text').value;
            const shift = document.getElementById('shift-input') ? document.getElementById('shift-input').value : 3;
            
            if (!text) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('warning', 'Please enter text to decode'));
                return;
            }
            
            try {
                const endpoint = `/api/crypto/decode/${encodingType}`;
                const body = { text };
                if (encodingType === 'caesar') {
                    body.shift = parseInt(shift) || 3;
                }
                
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                
                const result = await response.json();
                if (response.ok) {
                    cryptoResult.innerHTML = '';
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'alert alert-info';
                    resultDiv.innerHTML = `
                        <h6><i class="fas fa-arrow-down me-2"></i>Decoded (${encodingType.toUpperCase()})</h6>
                        <div class="input-group">
                            <input type="text" class="form-control" id="decoded-result" value="${result.decoded}" readonly>
                            <button class="btn btn-outline-secondary" onclick="copyToClipboard('decoded-result')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    `;
                    cryptoResult.appendChild(resultDiv);
                } else {
                    cryptoResult.innerHTML = '';
                    cryptoResult.appendChild(showResult('danger', `Decoding failed: ${result.error}`));
                }
            } catch (error) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('danger', 'Decoding failed: ' + error.message));
            }
        });
    }
    
    // Hash button handler
    if (hashBtn) {
        hashBtn.addEventListener('click', async () => {
            const text = document.getElementById('hash-text').value;
            const algorithm = document.getElementById('hash-algorithm').value;
            
            if (!text) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('warning', 'Please enter text to hash'));
                return;
            }
            
            try {
                const response = await fetch('/api/crypto/hash', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text, algorithm })
                });
                
                const result = await response.json();
                if (response.ok) {
                    cryptoResult.innerHTML = '';
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'alert alert-warning';
                    resultDiv.innerHTML = `
                        <h6><i class="fas fa-fingerprint me-2"></i>Hash (${result.algorithm.toUpperCase()})</h6>
                        <div class="input-group">
                            <input type="text" class="form-control" id="hash-result" value="${result.hash}" readonly>
                            <button class="btn btn-outline-secondary" onclick="copyToClipboard('hash-result')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <small class="text-muted mt-2 d-block">Input text: "${text}"</small>
                    `;
                    cryptoResult.appendChild(resultDiv);
                } else {
                    cryptoResult.innerHTML = '';
                    cryptoResult.appendChild(showResult('danger', `Hashing failed: ${result.error}`));
                }
            } catch (error) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('danger', 'Hashing failed: ' + error.message));
            }
        });
    }
    
    // Generate Key button handler
    if (generateKeyBtn) {
        generateKeyBtn.addEventListener('click', async () => {
            const keyLength = document.getElementById('key-length').value || 32;
            
            try {
                const response = await fetch('/api/crypto/generate-key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ length: parseInt(keyLength) })
                });
                
                const result = await response.json();
                if (response.ok) {
                    cryptoResult.innerHTML = '';
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'alert alert-success';
                    resultDiv.innerHTML = `
                        <h6><i class="fas fa-key me-2"></i>Random Key Generated</h6>
                        <div class="input-group mb-2">
                            <input type="text" class="form-control" id="key-result" value="${result.key}" readonly>
                            <button class="btn btn-outline-secondary" onclick="copyToClipboard('key-result')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <small class="text-muted">
                            <i class="fas fa-info-circle me-1"></i>
                            Length: ${result.length} bytes (${result.key.length} hex characters)
                        </small>
                        <br>
                        <small class="text-warning">
                            <i class="fas fa-exclamation-triangle me-1"></i>
                            Keep this key secure! It's cryptographically random.
                        </small>
                    `;
                    cryptoResult.appendChild(resultDiv);
                    
                    // Also generate an IV for convenience
                    const ivResponse = await fetch('/api/crypto/generate-iv', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ length: 16 })
                    });
                    
                    if (ivResponse.ok) {
                        const ivResult = await ivResponse.json();
                        const ivDiv = document.createElement('div');
                        ivDiv.className = 'alert alert-info mt-2';
                        ivDiv.innerHTML = `
                            <h6><i class="fas fa-shield-alt me-2"></i>Initialization Vector (IV)</h6>
                            <div class="input-group">
                                <input type="text" class="form-control" id="iv-result" value="${ivResult.iv}" readonly>
                                <button class="btn btn-outline-secondary" onclick="copyToClipboard('iv-result')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                            <small class="text-muted">
                                <i class="fas fa-info-circle me-1"></i>
                                Use this IV with block ciphers like AES-CBC
                            </small>
                        `;
                        cryptoResult.appendChild(ivDiv);
                    }
                } else {
                    cryptoResult.innerHTML = '';
                    cryptoResult.appendChild(showResult('danger', `Key generation failed: ${result.error}`));
                }
            } catch (error) {
                cryptoResult.innerHTML = '';
                cryptoResult.appendChild(showResult('danger', 'Key generation failed: ' + error.message));
            }
        });
    }
    
    // Copy to clipboard function
    window.copyToClipboard = function(elementId) {
        const element = document.getElementById(elementId);
        if (element) {
            element.select();
            element.setSelectionRange(0, 99999); // For mobile devices
            
            navigator.clipboard.writeText(element.value).then(() => {
                showNotification('Copied to clipboard!', 'success');
            }).catch(() => {
                // Fallback for older browsers
                document.execCommand('copy');
                showNotification('Copied to clipboard!', 'success');
            });
        }
    };

    // Expose functions to global scope
    window.downloadReport = downloadReport;
    if (typeof viewAgentDetails !== 'undefined') window.viewAgentDetails = viewAgentDetails;
    if (typeof sendAgentCommand !== 'undefined') window.sendAgentCommand = sendAgentCommand;
    if (typeof blockUSBDevice !== 'undefined') window.blockUSBDevice = blockUSBDevice;
    if (typeof unblockUSBDevice !== 'undefined') window.unblockUSBDevice = unblockUSBDevice;
    if (typeof blockNetworkInterface !== 'undefined') window.blockNetworkInterface = blockNetworkInterface;
    if (typeof unblockNetworkInterface !== 'undefined') window.unblockNetworkInterface = unblockNetworkInterface;
    if (typeof blockUser !== 'undefined') window.blockUser = blockUser;
    if (typeof unblockUser !== 'undefined') window.unblockUser = unblockUser;
    if (typeof terminateProcess !== 'undefined') window.terminateProcess = terminateProcess;
    if (typeof refreshWindowsEvents !== 'undefined') window.refreshWindowsEvents = refreshWindowsEvents;
    if (typeof resetWindowsEventFilters !== 'undefined') window.resetWindowsEventFilters = resetWindowsEventFilters;
    if (typeof clearWindowsEvents !== 'undefined') window.clearWindowsEvents = clearWindowsEvents;
    if (typeof downloadWindowsEventsPdf !== 'undefined') window.downloadWindowsEventsPdf = downloadWindowsEventsPdf;
    if (typeof viewScanDetails !== 'undefined') window.viewScanDetails = viewScanDetails;
    if (typeof deleteScan !== 'undefined') window.deleteScan = deleteScan;
    if (typeof viewReport !== 'undefined') window.viewReport = viewReport;
    if (typeof downloadReportFile !== 'undefined') window.downloadReportFile = downloadReportFile;
    if (typeof downloadVirusTotalPDF !== 'undefined') window.downloadVirusTotalPDF = downloadVirusTotalPDF;
    if (typeof viewRawVirusTotalData !== 'undefined') window.viewRawVirusTotalData = viewRawVirusTotalData;
    if (typeof viewThreatDetails !== 'undefined') window.viewThreatDetails = viewThreatDetails;
    if (typeof markAsValidThreat !== 'undefined') window.markAsValidThreat = markAsValidThreat;
    if (typeof markAsFalsePositive !== 'undefined') window.markAsFalsePositive = markAsFalsePositive;
    if (typeof showDetailedAnalysis !== 'undefined') window.showDetailedAnalysis = showDetailedAnalysis;
    if (typeof filterResults !== 'undefined') window.filterResults = filterResults;
    if (typeof copyRawData !== 'undefined') window.copyRawData = copyRawData;
});
